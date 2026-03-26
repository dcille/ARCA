"""CLI → SDK Transpiler: Converts Azure CLI commands into Python SDK evaluation scripts.

When a user creates a custom control with a cli_command, this module can
generate the equivalent Python SDK evaluation_script. This gives the user
the best of both worlds:

  1. Write the check as a familiar CLI command (easy to prototype)
  2. Auto-generate the SDK script for production execution (fast, reliable)

The generated script follows the same contract as hand-written evaluators:
  - Receives: credential, subscription_id, tenant_id, clients
  - Must set: results = [{"status": "PASS"|"FAIL", "resource_id": ..., ...}]

Usage:
    from cli_to_sdk_transpiler import CLIToSDKTranspiler

    transpiler = CLIToSDKTranspiler()

    cli = 'az storage account list --subscription {subscription_id} --query "[?enableHttpsTrafficOnly==`false`]" -o json'
    script = transpiler.transpile(cli, pass_condition="empty")

    print(script)
    # Output: a complete Python evaluation_script using StorageManagementClient

Limitations:
    - Covers the most common az CLI resource types (storage, network, keyvault, etc.)
    - Complex --query (JMESPath) filters are converted to Python equivalents
    - Unsupported commands get a best-effort template with TODOs
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# CLI command parser
# ─────────────────────────────────────────────────────────────────

@dataclass
class ParsedCLICommand:
    """Structured representation of an Azure CLI command."""
    service: str           # e.g., "storage", "network", "keyvault"
    resource_type: str     # e.g., "account", "nsg", "vaults"
    action: str            # e.g., "list", "show"
    subscription: str      # {subscription_id} or literal
    resource_group: str    # optional
    query: str             # JMESPath --query filter
    raw_command: str       # Original CLI string


def parse_cli_command(cmd: str) -> Optional[ParsedCLICommand]:
    """Parse an Azure CLI command string into structured components."""
    cmd = cmd.strip()
    if not cmd.startswith("az "):
        return None

    parts = cmd.split()
    if len(parts) < 3:
        return None

    # az <service> <resource_type> <action> [flags]
    # or az <service> <action> [flags]  (e.g., "az keyvault list")
    service = parts[1]

    # Detect the action and resource type
    # Common patterns:
    #   az storage account list
    #   az network nsg list
    #   az keyvault list
    #   az sql server list
    #   az security secure-score-controls list
    action_keywords = {"list", "show", "get"}
    resource_type = ""
    action = ""

    for i, p in enumerate(parts[2:], start=2):
        if p.startswith("-"):
            break
        if p in action_keywords:
            action = p
            break
        resource_type += (" " + p if resource_type else p)

    if not action:
        action = "list"  # Default assumption

    # Extract flags
    subscription = ""
    resource_group = ""
    query = ""

    i = 0
    while i < len(parts):
        if parts[i] in ("--subscription", "-s") and i + 1 < len(parts):
            subscription = parts[i + 1]
            i += 2
        elif parts[i] in ("--resource-group", "-g") and i + 1 < len(parts):
            resource_group = parts[i + 1]
            i += 2
        elif parts[i] == "--query" and i + 1 < len(parts):
            # Query might be quoted and span multiple parts
            q_parts = []
            i += 1
            if parts[i].startswith('"') or parts[i].startswith("'"):
                quote = parts[i][0]
                combined = parts[i]
                while not combined.endswith(quote) and i + 1 < len(parts):
                    i += 1
                    combined += " " + parts[i]
                q_parts.append(combined.strip("'\""))
            else:
                q_parts.append(parts[i])
            query = " ".join(q_parts)
            i += 1
        else:
            i += 1

    return ParsedCLICommand(
        service=service,
        resource_type=resource_type.strip(),
        action=action,
        subscription=subscription,
        resource_group=resource_group,
        query=query,
        raw_command=cmd,
    )


# ─────────────────────────────────────────────────────────────────
# SDK mapping: CLI service → Python SDK client + method
# ─────────────────────────────────────────────────────────────────

# Maps (service, resource_type) → (SDK import, client class, list method, attribute path)
SDK_MAP = {
    ("storage", "account"): {
        "import": "from azure.mgmt.storage import StorageManagementClient",
        "client": "StorageManagementClient(credential, subscription_id)",
        "client_var": "storage",
        "list_method": "storage.storage_accounts.list()",
        "id_attr": "acct.id",
        "name_attr": "acct.name",
        "iter_var": "acct",
    },
    ("network", "nsg"): {
        "import": "from azure.mgmt.network import NetworkManagementClient",
        "client": "NetworkManagementClient(credential, subscription_id)",
        "client_var": "net",
        "list_method": "net.network_security_groups.list_all()",
        "id_attr": "nsg.id",
        "name_attr": "nsg.name",
        "iter_var": "nsg",
    },
    ("network", "vnet"): {
        "import": "from azure.mgmt.network import NetworkManagementClient",
        "client": "NetworkManagementClient(credential, subscription_id)",
        "client_var": "net",
        "list_method": "net.virtual_networks.list_all()",
        "id_attr": "vnet.id",
        "name_attr": "vnet.name",
        "iter_var": "vnet",
    },
    ("network", "public-ip"): {
        "import": "from azure.mgmt.network import NetworkManagementClient",
        "client": "NetworkManagementClient(credential, subscription_id)",
        "client_var": "net",
        "list_method": "net.public_ip_addresses.list_all()",
        "id_attr": "pip.id",
        "name_attr": "pip.name",
        "iter_var": "pip",
    },
    ("network", "application-gateway"): {
        "import": "from azure.mgmt.network import NetworkManagementClient",
        "client": "NetworkManagementClient(credential, subscription_id)",
        "client_var": "net",
        "list_method": "net.application_gateways.list_all()",
        "id_attr": "agw.id",
        "name_attr": "agw.name",
        "iter_var": "agw",
    },
    ("keyvault", ""): {
        "import": "from azure.mgmt.keyvault import KeyVaultManagementClient",
        "client": "KeyVaultManagementClient(credential, subscription_id)",
        "client_var": "kv",
        "list_method": "kv.vaults.list()",
        "id_attr": "vault.id",
        "name_attr": "vault.name",
        "iter_var": "vault",
    },
    ("sql", "server"): {
        "import": "from azure.mgmt.sql import SqlManagementClient",
        "client": "SqlManagementClient(credential, subscription_id)",
        "client_var": "sql",
        "list_method": "sql.servers.list()",
        "id_attr": "server.id",
        "name_attr": "server.name",
        "iter_var": "server",
    },
    ("webapp", ""): {
        "import": "from azure.mgmt.web import WebSiteManagementClient",
        "client": "WebSiteManagementClient(credential, subscription_id)",
        "client_var": "web",
        "list_method": "web.web_apps.list()",
        "id_attr": "app.id",
        "name_attr": "app.name",
        "iter_var": "app",
    },
    ("vm", ""): {
        "import": "from azure.mgmt.compute import ComputeManagementClient",
        "client": "ComputeManagementClient(credential, subscription_id)",
        "client_var": "compute",
        "list_method": "compute.virtual_machines.list_all()",
        "id_attr": "vm.id",
        "name_attr": "vm.name",
        "iter_var": "vm",
    },
    ("cosmosdb", ""): {
        "import": "from azure.mgmt.cosmosdb import CosmosDBManagementClient",
        "client": "CosmosDBManagementClient(credential, subscription_id)",
        "client_var": "cosmos",
        "list_method": "cosmos.database_accounts.list()",
        "id_attr": "acct.id",
        "name_attr": "acct.name",
        "iter_var": "acct",
    },
}


# ─────────────────────────────────────────────────────────────────
# JMESPath → Python filter converter
# ─────────────────────────────────────────────────────────────────

def _jmespath_to_python_filter(query: str, iter_var: str) -> tuple[str, str]:
    """Convert a JMESPath filter to a Python condition.

    Returns: (condition_str, description_str)

    Examples:
        "[?enableHttpsTrafficOnly==`false`]"
        → ("not acct.enable_https_traffic_only", "HTTPS not enforced")

        "[?allowBlobPublicAccess!=`false`]"
        → ("acct.allow_blob_public_access is not False", "blob public access enabled")

        "[?properties.enablePurgeProtection!=`true`]"
        → ("not (vault.properties and vault.properties.enable_purge_protection)", ...)
    """
    if not query:
        return ("True", "all resources")

    # Extract the filter expression from [?...]
    match = re.search(r'\[\?\s*(.+?)\s*\]', query)
    if not match:
        return ("True  # TODO: manually convert query: " + query, query)

    expr = match.group(1)

    # Convert common patterns
    # Pattern: field==`value` or field=='value'
    eq_match = re.match(r"(\w[\w.]*)\s*==\s*[`']([^`']+)[`']", expr)
    if eq_match:
        field, value = eq_match.groups()
        py_field = _cli_field_to_python(field, iter_var)
        py_value = _cli_value_to_python(value)
        return (f"{py_field} == {py_value}", f"{field} is {value}")

    # Pattern: field!=`value` or field!='value'
    neq_match = re.match(r"(\w[\w.]*)\s*!=\s*[`']([^`']+)[`']", expr)
    if neq_match:
        field, value = neq_match.groups()
        py_field = _cli_field_to_python(field, iter_var)
        py_value = _cli_value_to_python(value)
        return (f"{py_field} != {py_value}", f"{field} is not {value}")

    # Pattern: !field (boolean negation)
    neg_match = re.match(r"!\s*(\w[\w.]*)", expr)
    if neg_match:
        field = neg_match.group(1)
        py_field = _cli_field_to_python(field, iter_var)
        return (f"not {py_field}", f"{field} is falsy")

    # Complex or unrecognized → return as comment
    return (f"True  # TODO: convert JMESPath filter: {expr}", expr)


def _cli_field_to_python(field: str, iter_var: str) -> str:
    """Convert a CLI field path to Python attribute access.

    CLI uses camelCase, Python SDK uses snake_case.
    """
    # Handle nested paths like "properties.enablePurgeProtection"
    parts = field.split(".")

    # Convert each part from camelCase to snake_case
    py_parts = []
    for part in parts:
        # camelCase → snake_case
        snake = re.sub(r'(?<!^)(?=[A-Z])', '_', part).lower()
        py_parts.append(snake)

    return f"{iter_var}.{'.'.join(py_parts)}"


def _cli_value_to_python(value: str) -> str:
    """Convert a JMESPath literal to Python."""
    if value.lower() == "true":
        return "True"
    elif value.lower() == "false":
        return "False"
    elif value.lower() == "null":
        return "None"
    elif value.isdigit():
        return value
    else:
        return f'"{value}"'


# ─────────────────────────────────────────────────────────────────
# Main transpiler
# ─────────────────────────────────────────────────────────────────

class CLIToSDKTranspiler:
    """Converts Azure CLI commands to Python SDK evaluation scripts."""

    def transpile(
        self,
        cli_command: str,
        pass_condition: str = "empty",
        control_title: str = "",
    ) -> str:
        """Convert a CLI command to a Python evaluation script.

        Args:
            cli_command: The Azure CLI command string
            pass_condition: How to determine PASS/FAIL ("empty", "not_empty", etc.)
            control_title: Optional title for the comment header

        Returns:
            Python source code string ready to use as evaluation_script
        """
        parsed = parse_cli_command(cli_command)
        if not parsed:
            return self._fallback_template(cli_command, control_title)

        # Find SDK mapping
        sdk_info = self._find_sdk_mapping(parsed)
        if not sdk_info:
            return self._fallback_template(cli_command, control_title)

        # Convert JMESPath query to Python filter
        py_condition, desc = _jmespath_to_python_filter(
            parsed.query, sdk_info["iter_var"]
        )

        # Determine PASS/FAIL logic based on pass_condition
        if pass_condition == "empty":
            # PASS when filter finds NO non-compliant resources
            # The CLI query selects BAD resources, so we FAIL on match
            fail_condition = py_condition
            pass_label = "compliant"
            fail_label = f"non-compliant ({desc})"
        elif pass_condition == "not_empty":
            # PASS when filter FINDS compliant resources
            fail_condition = f"not ({py_condition})"
            pass_label = f"matches ({desc})"
            fail_label = "does not match"
        else:
            fail_condition = py_condition
            pass_label = "compliant"
            fail_label = f"non-compliant ({desc})"

        # Generate the script
        var = sdk_info["iter_var"]
        header = f"# Auto-generated from CLI: {cli_command[:100]}"
        if control_title:
            header = f"# {control_title}\n{header}"

        script = f"""{header}
{sdk_info['import']}

{sdk_info['client_var']} = {sdk_info['client']}
resources = list({sdk_info['list_method']})

results = []
for {var} in resources:
    is_non_compliant = {fail_condition}
    results.append({{
        "status": "FAIL" if is_non_compliant else "PASS",
        "resource_id": {sdk_info['id_attr']},
        "resource_name": {sdk_info['name_attr']},
        "status_extended": f"{var.title()} {{{sdk_info['name_attr']}}}: {{'non-compliant: {desc}' if is_non_compliant else 'compliant'}}",
    }})
"""
        return script.strip()

    def transpile_with_metadata(
        self,
        cli_command: str,
        pass_condition: str = "empty",
        control_title: str = "",
    ) -> dict:
        """Transpile and return metadata about the conversion.

        Returns dict with:
          - script: The generated Python code
          - sdk_import: The SDK package needed
          - confidence: "high" | "medium" | "low"
          - notes: Any caveats
        """
        parsed = parse_cli_command(cli_command)
        script = self.transpile(cli_command, pass_condition, control_title)

        if not parsed:
            return {
                "script": script,
                "sdk_import": None,
                "confidence": "low",
                "notes": "Could not parse CLI command. Generated a fallback template.",
            }

        sdk_info = self._find_sdk_mapping(parsed)
        if not sdk_info:
            return {
                "script": script,
                "sdk_import": None,
                "confidence": "low",
                "notes": f"No SDK mapping for 'az {parsed.service} {parsed.resource_type}'. Generated fallback.",
            }

        has_query = bool(parsed.query)
        has_todo = "TODO" in script

        if has_todo:
            confidence = "medium"
            notes = "SDK mapping found, but JMESPath filter needs manual review."
        elif has_query:
            confidence = "high"
            notes = "Full conversion including query filter."
        else:
            confidence = "high"
            notes = "Clean conversion, no filter needed."

        return {
            "script": script,
            "sdk_import": sdk_info["import"].split("import ")[-1],
            "confidence": confidence,
            "notes": notes,
        }

    def _find_sdk_mapping(self, parsed: ParsedCLICommand) -> Optional[dict]:
        """Find the SDK mapping for a parsed CLI command."""
        # Try exact match first
        key = (parsed.service, parsed.resource_type)
        if key in SDK_MAP:
            return SDK_MAP[key]

        # Try service-only match
        key = (parsed.service, "")
        if key in SDK_MAP:
            return SDK_MAP[key]

        # Try partial matches
        for (svc, rtype), info in SDK_MAP.items():
            if svc == parsed.service:
                return info

        return None

    def _fallback_template(self, cli_command: str, title: str = "") -> str:
        """Generate a fallback template when SDK mapping is not available."""
        header = f"# {title}\n" if title else ""
        return f"""{header}# TODO: Auto-conversion not available for this CLI command.
# Original CLI: {cli_command[:200]}
#
# Manual conversion needed. Use this template:
#
# from azure.mgmt.XXX import XXXManagementClient
# client = XXXManagementClient(credential, subscription_id)
# resources = list(client.xxx.list())
#
# results = []
# for r in resources:
#     is_compliant = True  # TODO: implement check logic
#     results.append({{
#         "status": "PASS" if is_compliant else "FAIL",
#         "resource_id": r.id,
#         "resource_name": r.name,
#         "status_extended": f"Resource {{r.name}}: compliant={{is_compliant}}",
#     }})

import subprocess, json

proc = subprocess.run(
    {repr(cli_command.replace('{subscription_id}', '" + subscription_id + "').replace('{tenant_id}', '" + tenant_id + "'))},
    shell=True, capture_output=True, text=True, timeout=60
)
data = json.loads(proc.stdout) if proc.stdout.strip() else []

results = []
if isinstance(data, list):
    if len(data) == 0:
        results.append({{
            "status": "PASS",
            "resource_id": f"/subscriptions/{{subscription_id}}",
            "status_extended": "No non-compliant resources found.",
        }})
    else:
        for item in data:
            results.append({{
                "status": "FAIL",
                "resource_id": item.get("id", str(item)[:100]),
                "resource_name": item.get("name", ""),
                "status_extended": f"Non-compliant: {{item.get('name', item)}}",
            }})
""".strip()


# ─────────────────────────────────────────────────────────────────
# API endpoint for transpilation
# ─────────────────────────────────────────────────────────────────

def create_transpiler_router():
    """FastAPI router for CLI → SDK transpilation.

    Wire into your API:
        from cli_to_sdk_transpiler import create_transpiler_router
        app.include_router(create_transpiler_router(), prefix="/api/v1")
    """
    from fastapi import APIRouter
    from pydantic import BaseModel

    router = APIRouter(tags=["transpiler"])

    class TranspileRequest(BaseModel):
        cli_command: str
        pass_condition: str = "empty"
        control_title: str = ""

    class TranspileResponse(BaseModel):
        evaluation_script: str
        sdk_import: Optional[str]
        confidence: str
        notes: str

    @router.post("/transpile/cli-to-sdk", response_model=TranspileResponse)
    async def transpile_cli(body: TranspileRequest):
        """Convert an Azure CLI command to a Python SDK evaluation script.

        The generated script can be used directly as evaluation_script
        in a custom control.

        Confidence levels:
          - high: Full conversion including filter logic
          - medium: SDK found but JMESPath filter needs manual review
          - low: No SDK mapping, generated subprocess fallback
        """
        transpiler = CLIToSDKTranspiler()
        result = transpiler.transpile_with_metadata(
            cli_command=body.cli_command,
            pass_condition=body.pass_condition,
            control_title=body.control_title,
        )
        return TranspileResponse(
            evaluation_script=result["script"],
            sdk_import=result["sdk_import"],
            confidence=result["confidence"],
            notes=result["notes"],
        )

    return router
