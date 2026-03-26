"""API models for custom framework controls with executable evaluation logic.

Extends the existing custom framework/control models to support:
  - cli_command: Azure CLI command to run
  - evaluation_script: Python code that evaluates the control
  - pass_condition: How to interpret CLI output

These fields are optional — controls without them are treated as MANUAL.
"""

from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class PassCondition(str, Enum):
    """How to determine PASS/FAIL from CLI command output."""
    EMPTY = "empty"              # PASS if output is [] (no bad resources)
    NOT_EMPTY = "not_empty"      # PASS if output has results
    EXIT_CODE = "exit_code"      # PASS if exit code == 0


class CustomControlCreate(BaseModel):
    """Request body for creating a custom control with evaluation logic.

    This is the API contract — what the user sends when creating a new control
    within their custom framework.
    """
    control_id: str = Field(..., description="Unique ID, e.g., 'NET-001'")
    title: str = Field(..., description="Human-readable title")
    description: str = Field("", description="What this control checks")
    severity: str = Field("medium", description="low | medium | high | critical")
    service: str = Field("general", description="Service area: networking, storage, identity, etc.")
    remediation: str = Field("", description="How to fix if FAIL")

    # ── Evaluation logic ──
    cli_command: Optional[str] = Field(
        None,
        description="Azure CLI command. Use {subscription_id} and {tenant_id} as placeholders.",
        json_schema_extra={
            "examples": [
                "az network nsg list --subscription {subscription_id} --query \"[?securityRules[?access=='Allow' && direction=='Inbound' && sourceAddressPrefix=='*' && destinationPortRange=='22']]\" -o json",
                "az storage account list --subscription {subscription_id} --query \"[?enableHttpsTrafficOnly==`false`]\" -o json",
                "az keyvault list --subscription {subscription_id} --query \"[?properties.enablePurgeProtection!=`true`]\" -o json",
            ]
        },
    )

    pass_condition: Optional[str] = Field(
        "empty",
        description="How to determine PASS/FAIL: 'empty' (default), 'not_empty', 'exit_code', 'contains:X', 'equals:X'",
    )

    evaluation_script: Optional[str] = Field(
        None,
        description="Python code that evaluates the control. Must set a 'results' list variable.",
        json_schema_extra={
            "examples": [
                """# Check all storage accounts for HTTPS-only
from azure.mgmt.storage import StorageManagementClient
storage = StorageManagementClient(credential, subscription_id)
accounts = list(storage.storage_accounts.list())

results = []
for acct in accounts:
    results.append({
        "status": "PASS" if acct.enable_https_traffic_only else "FAIL",
        "resource_id": acct.id,
        "resource_name": acct.name,
        "status_extended": f"HTTPS only = {acct.enable_https_traffic_only}",
    })
""",
            ]
        },
    )

    class Config:
        json_schema_extra = {
            "example": {
                "control_id": "CUSTOM-STORAGE-001",
                "title": "Ensure all storage accounts use HTTPS",
                "severity": "high",
                "service": "storage",
                "remediation": "Enable 'Secure transfer required' on each storage account.",
                "cli_command": 'az storage account list --subscription {subscription_id} --query "[?enableHttpsTrafficOnly==`false`]" -o json',
                "pass_condition": "empty",
            }
        }


class CustomControlResponse(BaseModel):
    """Response when a custom control is created."""
    control_id: str
    title: str
    severity: str
    evaluation_type: str  # "python_script" | "cli_command" | "manual"
    created: bool = True


# ═════════════════════════════════════════════════════════════════
# EXAMPLE CONTROLS — Ready to use as templates
# ═════════════════════════════════════════════════════════════════

EXAMPLE_CONTROLS_CLI = [
    {
        "control_id": "CUSTOM-NET-001",
        "title": "Ensure no NSGs allow unrestricted SSH from Internet",
        "severity": "critical",
        "service": "networking",
        "remediation": "Remove or restrict inbound rules allowing 0.0.0.0/0 on port 22.",
        "cli_command": 'az network nsg list --subscription {subscription_id} --query "[].{name:name, rules:securityRules[?access==\'Allow\' && direction==\'Inbound\' && sourceAddressPrefix==\'*\' && (destinationPortRange==\'22\' || destinationPortRange==\'*\')]}" --query "[?length(rules) > `0`]" -o json',
        "pass_condition": "empty",
    },
    {
        "control_id": "CUSTOM-STORAGE-001",
        "title": "Ensure no storage accounts allow public blob access",
        "severity": "high",
        "service": "storage",
        "remediation": "Set allowBlobPublicAccess to false on each storage account.",
        "cli_command": 'az storage account list --subscription {subscription_id} --query "[?allowBlobPublicAccess!=`false`].{name:name, id:id, publicAccess:allowBlobPublicAccess}" -o json',
        "pass_condition": "empty",
    },
    {
        "control_id": "CUSTOM-KV-001",
        "title": "Ensure Key Vaults have purge protection enabled",
        "severity": "high",
        "service": "security",
        "remediation": "Enable purge protection on each Key Vault (cannot be reversed).",
        "cli_command": 'az keyvault list --subscription {subscription_id} --query "[?properties.enablePurgeProtection!=`true`].{name:name, id:id}" -o json',
        "pass_condition": "empty",
    },
    {
        "control_id": "CUSTOM-DB-001",
        "title": "Ensure SQL Servers require TLS 1.2+",
        "severity": "high",
        "service": "database",
        "remediation": "Set minimalTlsVersion to '1.2' on each SQL Server.",
        "cli_command": "az sql server list --subscription {subscription_id} --query \"[?minimalTlsVersion!='1.2'].{name:name, id:id, tls:minimalTlsVersion}\" -o json",
        "pass_condition": "empty",
    },
    {
        "control_id": "CUSTOM-DEFENDER-001",
        "title": "Ensure Defender for Cloud secure score is above threshold",
        "severity": "medium",
        "service": "security",
        "remediation": "Review and remediate Defender for Cloud recommendations to improve secure score.",
        "cli_command": 'az security secure-score-controls list --subscription {subscription_id} --query "[?score.percentage < `0.7`].{name:displayName, score:score.percentage}" -o json',
        "pass_condition": "empty",
    },
]


EXAMPLE_CONTROLS_PYTHON = [
    {
        "control_id": "CUSTOM-NET-002",
        "title": "Ensure all subnets (except system) have NSGs attached",
        "severity": "high",
        "service": "networking",
        "remediation": "Associate a Network Security Group with each user subnet.",
        "evaluation_script": """
# Check that all non-system subnets have NSGs
from azure.mgmt.network import NetworkManagementClient
net = NetworkManagementClient(credential, subscription_id)

EXEMPT = {"GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet",
          "AzureFirewallManagementSubnet", "RouteServerSubnet"}

results = []
for vnet in net.virtual_networks.list_all():
    for subnet in (vnet.subnets or []):
        if subnet.name in EXEMPT:
            continue
        has_nsg = subnet.network_security_group is not None
        results.append({
            "status": "PASS" if has_nsg else "FAIL",
            "resource_id": subnet.id,
            "resource_name": f"{vnet.name}/{subnet.name}",
            "status_extended": f"Subnet {subnet.name}: NSG = {'yes' if has_nsg else 'MISSING'}",
        })
""",
    },
    {
        "control_id": "CUSTOM-IAM-001",
        "title": "Ensure no subscription has more than 3 Owners",
        "severity": "critical",
        "service": "identity",
        "remediation": "Remove excess Owner role assignments. Use PIM for just-in-time elevation.",
        "evaluation_script": """
# Count Owner role assignments at subscription scope
from azure.mgmt.authorization import AuthorizationManagementClient
auth = AuthorizationManagementClient(credential, subscription_id)

OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
assignments = list(auth.role_assignments.list_for_scope(
    scope=f"/subscriptions/{subscription_id}"))
owners = [a for a in assignments
          if a.role_definition_id and a.role_definition_id.endswith(f"/{OWNER_ROLE_ID}")]

status = "PASS" if len(owners) <= 3 else "FAIL"
results = [{
    "status": status,
    "resource_id": f"/subscriptions/{subscription_id}",
    "status_extended": f"Subscription owners: {len(owners)} (max recommended: 3)",
}]
""",
    },
    {
        "control_id": "CUSTOM-LOG-001",
        "title": "Ensure all Key Vaults have diagnostic settings enabled",
        "severity": "high",
        "service": "monitoring",
        "remediation": "Configure diagnostic settings on each Key Vault to send logs to Log Analytics.",
        "evaluation_script": """
# Check diagnostic settings on all Key Vaults
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient

kv = KeyVaultManagementClient(credential, subscription_id)
mon = MonitorManagementClient(credential, subscription_id)

results = []
for vault in kv.vaults.list():
    try:
        diag = list(mon.diagnostic_settings.list(resource_uri=vault.id))
        has_diag = len(diag) > 0
        results.append({
            "status": "PASS" if has_diag else "FAIL",
            "resource_id": vault.id,
            "resource_name": vault.name,
            "status_extended": f"Key Vault {vault.name}: diagnostic settings = {len(diag)}",
        })
    except Exception as e:
        results.append({
            "status": "ERROR",
            "resource_id": vault.id,
            "resource_name": vault.name,
            "status_extended": f"Error checking {vault.name}: {e}",
        })
""",
    },
    {
        "control_id": "CUSTOM-STORAGE-002",
        "title": "Ensure storage account keys have been rotated in last 90 days",
        "severity": "high",
        "service": "storage",
        "remediation": "Rotate storage account access keys. Configure automatic key rotation.",
        "evaluation_script": """
# Check storage account key age
from azure.mgmt.storage import StorageManagementClient
from datetime import datetime, timezone

storage = StorageManagementClient(credential, subscription_id)

results = []
for acct in storage.storage_accounts.list():
    rg = acct.id.split("/")[4]  # Extract resource group from ID
    try:
        keys = storage.storage_accounts.list_keys(rg, acct.name)
        for key in keys.keys:
            ct = getattr(key, "creation_time", None)
            if ct:
                age_days = (datetime.now(timezone.utc) - ct).days
                results.append({
                    "status": "PASS" if age_days <= 90 else "FAIL",
                    "resource_id": acct.id,
                    "resource_name": f"{acct.name}/{key.key_name}",
                    "status_extended": f"Key {key.key_name} age: {age_days} days (max: 90)",
                })
    except Exception:
        pass
""",
    },
]


# ─────────────────────────────────────────────────────────────────
# API Router extension
# ─────────────────────────────────────────────────────────────────

def create_custom_controls_router():
    """Creates a FastAPI router for custom control CRUD with evaluation logic.

    Wire this into your existing API:
        from custom_control_models import create_custom_controls_router
        app.include_router(create_custom_controls_router(), prefix="/api/v1")
    """
    from fastapi import APIRouter, HTTPException

    router = APIRouter(tags=["custom-controls"])

    @router.post("/frameworks/{framework_id}/controls", response_model=CustomControlResponse)
    async def create_control(framework_id: str, body: CustomControlCreate):
        """Create a new custom control with optional evaluation logic.

        The control can include:
        - cli_command: An Azure CLI command to execute during scans
        - evaluation_script: Python code that evaluates the control
        - Both (Python takes priority during execution)
        - Neither (control will be MANUAL)
        """
        # Determine evaluation type
        if body.evaluation_script:
            eval_type = "python_script"
        elif body.cli_command:
            eval_type = "cli_command"
        else:
            eval_type = "manual"

        # Validate Python script syntax (don't execute, just compile)
        if body.evaluation_script:
            try:
                compile(body.evaluation_script, f"<control:{body.control_id}>", "exec")
            except SyntaxError as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Python script has syntax error at line {e.lineno}: {e.msg}",
                )

        # Validate CLI command (basic checks)
        if body.cli_command:
            cmd = body.cli_command.strip()
            if not cmd.startswith("az "):
                raise HTTPException(
                    status_code=422,
                    detail="CLI command must start with 'az ' (Azure CLI).",
                )
            # Check for dangerous commands
            dangerous = ["delete", "remove", "purge", "update", "create", "set"]
            cmd_parts = cmd.split()
            if len(cmd_parts) > 2 and cmd_parts[2] in dangerous:
                raise HTTPException(
                    status_code=422,
                    detail=f"CLI command contains destructive operation '{cmd_parts[2]}'. "
                           "Only read operations (list, show, get) are allowed.",
                )

        # TODO: Save to your database here
        # db_control = CustomControlDB(
        #     framework_id=framework_id,
        #     control_id=body.control_id,
        #     ...
        # )
        # db.add(db_control)

        return CustomControlResponse(
            control_id=body.control_id,
            title=body.title,
            severity=body.severity,
            evaluation_type=eval_type,
        )

    @router.post("/frameworks/{framework_id}/controls/{control_id}/test")
    async def test_control(framework_id: str, control_id: str):
        """Dry-run a custom control's evaluation logic.

        Useful for testing before adding to a framework.
        Returns the evaluation results without saving them as scan results.
        """
        # TODO: Load control from DB
        # control = db.get_control(framework_id, control_id)
        # executor = CustomControlExecutor(credential, subscription_id, tenant_id)
        # results = executor.execute(control)
        # return {"results": results, "count": len(results)}
        raise HTTPException(status_code=501, detail="Implement with your DB layer")

    @router.get("/custom-controls/examples")
    async def get_example_controls():
        """Get example custom controls with CLI and Python evaluation logic."""
        return {
            "cli_examples": EXAMPLE_CONTROLS_CLI,
            "python_examples": EXAMPLE_CONTROLS_PYTHON,
            "usage": (
                "Copy any example and POST to /frameworks/{id}/controls. "
                "CLI controls use Azure CLI commands with {subscription_id} placeholders. "
                "Python controls use Azure SDK with credential/subscription_id variables."
            ),
        }

    return router
