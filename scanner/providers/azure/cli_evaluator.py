"""CLI-based CIS control evaluator for Azure.

Executes Azure CLI (az) commands defined in CIS controls one by one,
evaluates output against expected conditions, and generates PASS/FAIL findings.

This engine enables the CSPM to evaluate controls that have detection_commands
defined but are not yet covered by the SDK-based scanner checks.
"""
import json
import logging
import re
import subprocess
import time
from typing import Optional

from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)

# Timeout for individual CLI commands (seconds)
CLI_COMMAND_TIMEOUT = 60
# Timeout for resource discovery commands
DISCOVERY_TIMEOUT = 120


class AzureCLIEvaluator:
    """Evaluates CIS controls by executing Azure CLI detection commands.

    Authenticates with az CLI using service principal credentials,
    then iterates through control definitions executing detection commands
    and evaluating results to produce PASS/FAIL findings.
    """

    def __init__(self, credentials: dict):
        self.subscription_id = credentials.get("subscription_id", "")
        self.tenant_id = credentials.get("tenant_id", "")
        self.client_id = credentials.get("client_id", "")
        self.client_secret = credentials.get("client_secret", "")
        self._authenticated = False
        self._resource_cache: dict[str, list] = {}

    # ── Authentication ──────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """Login to az CLI using service principal."""
        try:
            result = subprocess.run(
                [
                    "az", "login", "--service-principal",
                    "-u", self.client_id,
                    "-p", self.client_secret,
                    "--tenant", self.tenant_id,
                    "--output", "none",
                ],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                logger.error(f"az login failed: {result.stderr}")
                return False

            result = subprocess.run(
                ["az", "account", "set", "-s", self.subscription_id, "--output", "none"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logger.error(f"az account set failed: {result.stderr}")
                return False

            self._authenticated = True
            logger.info("Azure CLI authentication successful")
            return True
        except FileNotFoundError:
            logger.error("az CLI not found — install Azure CLI to enable CLI-based control evaluation")
            return False
        except Exception as e:
            logger.error(f"az CLI authentication failed: {e}")
            return False

    # ── Command Execution ───────────────────────────────────────────────

    def run_command(self, command: str, timeout: int = CLI_COMMAND_TIMEOUT) -> dict:
        """Execute an az CLI command and return parsed result.

        Returns:
            dict with keys: success (bool), data (parsed JSON or raw text),
                            raw (raw stdout), error (stderr if failed)
        """
        if not self._authenticated:
            return {"success": False, "data": None, "raw": "", "error": "Not authenticated"}

        # Ensure JSON output for parseable results
        cmd = command.strip()
        if "--output" not in cmd and "-o " not in cmd:
            cmd += " --output json"

        try:
            result = subprocess.run(
                cmd, shell=True,
                capture_output=True, text=True, timeout=timeout,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "data": None,
                    "raw": result.stdout,
                    "error": result.stderr.strip(),
                }

            # Try to parse as JSON
            raw = result.stdout.strip()
            try:
                data = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                data = raw

            return {"success": True, "data": data, "raw": raw, "error": ""}

        except subprocess.TimeoutExpired:
            return {"success": False, "data": None, "raw": "", "error": f"Command timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "data": None, "raw": "", "error": str(e)}

    # ── Resource Discovery ──────────────────────────────────────────────

    def discover_resources(self, resource_type: str) -> list[dict]:
        """Discover Azure resources of a given type for placeholder resolution.

        Caches results to avoid repeated API calls.
        """
        if resource_type in self._resource_cache:
            return self._resource_cache[resource_type]

        discovery_commands = {
            "resource_groups": "az group list",
            "storage_accounts": "az storage account list",
            "sql_servers": "az sql server list",
            "key_vaults": "az keyvault list",
            "vms": "az vm list",
            "web_apps": "az webapp list",
            "nsgs": "az network nsg list",
            "vnets": "az network vnet list",
            "databricks_workspaces": "az databricks workspace list",
            "aks_clusters": "az aks list",
            "postgresql_servers": "az postgres flexible-server list",
            "cosmosdb_accounts": "az cosmosdb list",
            "acr_registries": "az acr list",
            "app_gateways": "az network application-gateway list",
            "public_ips": "az network public-ip list",
            "disks": "az disk list",
            "log_analytics_workspaces": "az monitor log-analytics workspace list",
            "activity_log_alerts": "az monitor activity-log alert list",
            "diagnostic_settings": "az monitor diagnostic-settings subscription list",
        }

        cmd = discovery_commands.get(resource_type)
        if not cmd:
            return []

        result = self.run_command(cmd, timeout=DISCOVERY_TIMEOUT)
        resources = result["data"] if result["success"] and isinstance(result["data"], list) else []
        self._resource_cache[resource_type] = resources
        return resources

    # ── Placeholder Resolution ──────────────────────────────────────────

    def resolve_placeholders(self, command: str, resource: dict) -> str:
        """Replace <placeholder> tokens in a command with actual resource values."""
        replacements = {
            "<resource-group-name>": resource.get("resourceGroup", ""),
            "<resource-group>": resource.get("resourceGroup", ""),
            "<subscription-id>": self.subscription_id,
        }

        # Resource-type-specific replacements
        name = resource.get("name", "")
        rid = resource.get("id", "")

        # Generic name patterns
        for pattern in [
            "<name>", "<storage-account-name>", "<server-name>",
            "<keyvault-name>", "<vault-name>", "<vm-name>",
            "<webapp-name>", "<app-name>", "<nsg-name>",
            "<vnet-name>", "<workspace-name>",
            "<databricks-workspace-name>", "<cluster-name>",
            "<registry-name>", "<gateway-name>",
            "<databricks-resource-id>",
        ]:
            replacements[pattern] = rid if "resource-id" in pattern else name

        resolved = command
        for placeholder, value in replacements.items():
            resolved = resolved.replace(placeholder, value)

        return resolved

    # ── Control Evaluation ──────────────────────────────────────────────

    def evaluate_control(self, control_def: dict) -> list[dict]:
        """Evaluate a single CIS control using its CLI commands.

        Args:
            control_def: A control evaluation definition dict with keys:
                - cis_id: CIS control ID
                - check_ids: List of check_ids to produce
                - title: Control title
                - service: Service area
                - severity: Severity level
                - cis_level: L1 or L2
                - evaluation_type: "subscription" or "per_resource"
                - resource_type: (for per_resource) type key for discovery
                - commands: List of az CLI commands to execute
                - evaluate: callable(results) -> (status, detail)

        Returns:
            List of CheckResult dicts.
        """
        cis_id = control_def["cis_id"]
        check_ids = control_def["check_ids"]
        title = control_def["title"]
        service = control_def.get("service", "general")
        severity = control_def.get("severity", "medium")
        cis_level = control_def.get("cis_level", "L1")
        eval_type = control_def.get("evaluation_type", "subscription")
        commands = control_def.get("commands", [])
        evaluate_fn = control_def.get("evaluate")
        CIS5 = ["CIS-Azure-5.0", "MCSB-Azure-1.0"]

        results = []

        try:
            if eval_type == "subscription":
                # Run commands at subscription level
                cmd_results = []
                for cmd in commands:
                    cmd_results.append(self.run_command(cmd))

                if evaluate_fn:
                    status, detail = evaluate_fn(cmd_results)
                else:
                    # Default: PASS if all commands succeed
                    status = "PASS" if all(r["success"] for r in cmd_results) else "FAIL"
                    detail = "; ".join(r.get("error", "") for r in cmd_results if r.get("error"))

                for check_id in check_ids:
                    results.append(CheckResult(
                        check_id=check_id,
                        check_title=f"{title} (CIS {cis_id})",
                        service=service,
                        severity=severity,
                        status=status,
                        resource_id=self.subscription_id,
                        status_extended=f"CIS {cis_id} [{cis_level}] — {detail}",
                        remediation=control_def.get("remediation", f"Refer to CIS Azure Benchmark v5.0, control {cis_id}."),
                        compliance_frameworks=CIS5,
                        assessment_type="automated",
                        cis_control_id=cis_id,
                        cis_level=cis_level,
                    ).to_dict())

            elif eval_type == "per_resource":
                resource_type = control_def.get("resource_type", "")
                resources = self.discover_resources(resource_type)

                if not resources:
                    # No resources of this type — emit PASS (nothing to evaluate)
                    for check_id in check_ids:
                        results.append(CheckResult(
                            check_id=check_id,
                            check_title=f"{title} (CIS {cis_id})",
                            service=service,
                            severity=severity,
                            status="PASS",
                            resource_id=self.subscription_id,
                            status_extended=f"CIS {cis_id} [{cis_level}] — No {resource_type} resources found.",
                            compliance_frameworks=CIS5,
                            assessment_type="automated",
                            cis_control_id=cis_id,
                            cis_level=cis_level,
                        ).to_dict())
                else:
                    for resource in resources:
                        cmd_results = []
                        for cmd_template in commands:
                            resolved_cmd = self.resolve_placeholders(cmd_template, resource)
                            # Skip if unresolved placeholders remain
                            if "<" in resolved_cmd and ">" in resolved_cmd:
                                logger.debug(f"Skipping command with unresolved placeholders: {resolved_cmd}")
                                continue
                            cmd_results.append(self.run_command(resolved_cmd))

                        if not cmd_results:
                            continue

                        if evaluate_fn:
                            status, detail = evaluate_fn(cmd_results, resource)
                        else:
                            status = "PASS" if all(r["success"] for r in cmd_results) else "FAIL"
                            detail = resource.get("name", "unknown")

                        for check_id in check_ids:
                            results.append(CheckResult(
                                check_id=check_id,
                                check_title=f"{title} (CIS {cis_id})",
                                service=service,
                                severity=severity,
                                status=status,
                                resource_id=resource.get("id", ""),
                                resource_name=resource.get("name", ""),
                                status_extended=f"CIS {cis_id} [{cis_level}] — {detail}",
                                remediation=control_def.get("remediation", f"Refer to CIS Azure Benchmark v5.0, control {cis_id}."),
                                compliance_frameworks=CIS5,
                                assessment_type="automated",
                                cis_control_id=cis_id,
                                cis_level=cis_level,
                            ).to_dict())

        except Exception as e:
            logger.warning(f"CLI evaluation failed for CIS {cis_id}: {e}")
            # Emit error result so the control shows as evaluated
            for check_id in check_ids:
                results.append(CheckResult(
                    check_id=check_id,
                    check_title=f"{title} (CIS {cis_id})",
                    service=service,
                    severity=severity,
                    status="FAIL",
                    resource_id=self.subscription_id,
                    status_extended=f"CIS {cis_id} [{cis_level}] — Evaluation error: {e}",
                    compliance_frameworks=CIS5,
                    assessment_type="automated",
                    cis_control_id=cis_id,
                    cis_level=cis_level,
                ).to_dict())

        return results

    # ── Batch Evaluation ────────────────────────────────────────────────

    def evaluate_controls(self, control_defs: list[dict], covered_check_ids: set[str] | None = None) -> list[dict]:
        """Evaluate multiple CIS controls, skipping already-covered ones.

        Args:
            control_defs: List of control evaluation definitions.
            covered_check_ids: Set of check_ids already produced by SDK checks.

        Returns:
            List of CheckResult dicts for all evaluated controls.
        """
        if not self.authenticate():
            logger.error("CLI evaluation skipped — authentication failed")
            return []

        covered = covered_check_ids or set()
        all_results = []
        total = len(control_defs)

        for i, control_def in enumerate(control_defs, 1):
            check_ids = control_def.get("check_ids", [])

            # Skip if all check_ids are already covered
            if check_ids and all(cid in covered for cid in check_ids):
                logger.debug(f"Skipping CIS {control_def['cis_id']} — already covered by SDK checks")
                continue

            # Filter to only uncovered check_ids
            uncovered_ids = [cid for cid in check_ids if cid not in covered]
            eval_def = {**control_def, "check_ids": uncovered_ids}

            logger.info(f"[{i}/{total}] Evaluating CIS {control_def['cis_id']}: {control_def['title']}")
            results = self.evaluate_control(eval_def)
            all_results.extend(results)

            # Small delay to avoid throttling
            if i % 10 == 0:
                time.sleep(1)

        logger.info(f"CLI evaluation complete: {len(all_results)} findings from {total} controls")
        return all_results

    # ── Cleanup ─────────────────────────────────────────────────────────

    def logout(self):
        """Logout from az CLI."""
        try:
            subprocess.run(["az", "logout"], capture_output=True, timeout=10)
        except Exception:
            pass
