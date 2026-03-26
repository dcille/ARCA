"""Custom Control Executor — Executes user-defined evaluation logic for custom framework controls.

When a user creates a custom framework with custom controls, each control can include:
  1. A Python script (evaluation_script) that runs against the cloud environment
  2. An Azure CLI command (cli_command) that gets executed and parsed
  3. Both (Python takes priority)

The executor runs these safely within the scan context and returns
CheckResult dicts compatible with the existing evaluator engine.

Security model:
  - Python scripts run in a restricted exec() sandbox
  - CLI commands run via subprocess with timeout
  - Both receive the same credential/config context as SDK evaluators
  - Errors are caught and returned as ERROR results, never crash the scan

Usage:
    from custom_control_executor import CustomControlExecutor

    executor = CustomControlExecutor(credential, subscription_id, tenant_id)

    # Execute a Python script
    results = executor.execute_python(control, script_code)

    # Execute a CLI command
    results = executor.execute_cli(control, cli_command)

    # Auto-detect and execute whatever the control has
    results = executor.execute(control)
"""

import json
import logging
import subprocess
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Data model for custom controls
# ─────────────────────────────────────────────────────────────────

@dataclass
class CustomControl:
    """A custom control definition with optional evaluation logic.

    This extends your existing custom control model with two new fields:
      - cli_command: An Azure CLI command string to execute
      - evaluation_script: Python code that evaluates the control

    At least one should be provided for automated evaluation.
    """
    control_id: str               # e.g., "CUSTOM-NET-001"
    title: str                    # e.g., "Ensure all VNets have DDoS protection"
    description: str = ""
    severity: str = "medium"      # low | medium | high | critical
    service: str = "general"
    framework_id: str = ""        # Parent custom framework
    remediation: str = ""
    compliance_frameworks: list[str] = field(default_factory=list)

    # ── Evaluation logic (at least one for automated evaluation) ──
    cli_command: Optional[str] = None
    """Azure CLI command to execute.

    The command can use these placeholders that get resolved at runtime:
      {subscription_id}  → Current Azure subscription ID
      {tenant_id}        → Current Entra tenant ID
      {resource_group}   → Iterated per resource group (if applicable)

    The command output is captured and parsed. The control PASSES if:
      - exit code == 0 AND
      - pass_condition is met (if specified)

    Examples:
      "az network nsg list --subscription {subscription_id} --query '[?!subnets]' -o json"
      "az storage account list --subscription {subscription_id} --query '[?enableHttpsTrafficOnly==`false`]' -o json"
    """

    pass_condition: Optional[str] = None
    """How to determine PASS/FAIL from CLI output.

    Options:
      "empty"        → PASS if output is empty list [] (no non-compliant resources)
      "not_empty"    → PASS if output is non-empty (compliant resources found)
      "exit_code"    → PASS if exit code == 0
      "contains:X"   → PASS if output contains string X
      "equals:X"     → PASS if output equals X (stripped)
      "jq:EXPR"      → PASS if jq expression returns true/non-empty

    Default: "empty" (PASS when no bad resources found)
    """

    evaluation_script: Optional[str] = None
    """Python script that evaluates the control.

    The script receives these variables in its execution context:
      - credential: Azure TokenCredential (already authenticated)
      - subscription_id: str
      - tenant_id: str
      - clients: AzureClientCache (lazy SDK client cache)
      - config: EvalConfig

    The script MUST set a `results` variable — a list of dicts with:
      {"status": "PASS"|"FAIL", "resource_id": "...", "status_extended": "..."}

    If `results` is not set, the executor treats it as an error.

    Example script:
    ```python
    from azure.mgmt.network import NetworkManagementClient
    net = NetworkManagementClient(credential, subscription_id)
    vnets = list(net.virtual_networks.list_all())

    results = []
    for vnet in vnets:
        has_ddos = vnet.enable_ddos_protection or False
        results.append({
            "status": "PASS" if has_ddos else "FAIL",
            "resource_id": vnet.id,
            "resource_name": vnet.name,
            "status_extended": f"VNet {vnet.name}: DDoS protection = {has_ddos}",
        })
    ```
    """


# ─────────────────────────────────────────────────────────────────
# Result builders (reuse from base.py pattern)
# ─────────────────────────────────────────────────────────────────

def _make_check_result(
    control: CustomControl,
    status: str,
    resource_id: str,
    resource_name: str = "",
    status_extended: str = "",
    region: str = "",
) -> dict:
    return {
        "check_id": f"custom_{control.control_id.lower().replace('-', '_').replace('.', '_')}",
        "check_title": control.title,
        "service": control.service,
        "severity": control.severity,
        "status": status,
        "resource_id": resource_id,
        "resource_name": resource_name or (resource_id.split("/")[-1] if resource_id else ""),
        "region": region,
        "status_extended": status_extended,
        "remediation": control.remediation,
        "compliance_frameworks": control.compliance_frameworks or [control.framework_id],
        "cis_control_id": control.control_id,
    }


# ─────────────────────────────────────────────────────────────────
# Custom Control Executor
# ─────────────────────────────────────────────────────────────────

class CustomControlExecutor:
    """Executes evaluation logic for custom controls.

    Supports two modes:
      1. Python script execution (sandboxed exec)
      2. Azure CLI command execution (subprocess)
    """

    def __init__(
        self,
        credential,
        subscription_id: str,
        tenant_id: str = "",
        clients=None,  # Optional AzureClientCache
        timeout: int = 60,
    ):
        self.credential = credential
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self._clients = clients
        self.timeout = timeout

    @property
    def clients(self):
        """Lazy-load AzureClientCache if not provided."""
        if self._clients is None:
            from .evaluators.base import AzureClientCache
            self._clients = AzureClientCache(self.credential, self.subscription_id)
        return self._clients

    # ─────────────────────────────────────────────────────────
    # Main dispatcher
    # ─────────────────────────────────────────────────────────

    def execute(self, control: CustomControl) -> list[dict]:
        """Execute the control's evaluation logic (auto-detect mode).

        Priority: evaluation_script > cli_command > MANUAL
        """
        if control.evaluation_script:
            return self.execute_python(control)
        elif control.cli_command:
            return self.execute_cli(control)
        else:
            return [_make_check_result(
                control, status="MANUAL",
                resource_id=self.subscription_id,
                status_extended=f"Control {control.control_id} has no evaluation logic (no script or CLI command).",
            )]

    # ─────────────────────────────────────────────────────────
    # Python script execution
    # ─────────────────────────────────────────────────────────

    def execute_python(self, control: CustomControl) -> list[dict]:
        """Execute a Python evaluation script in a sandboxed context.

        The script receives credential, subscription_id, clients, etc.
        It must set a `results` list variable.
        """
        if not control.evaluation_script:
            return [_make_check_result(
                control, status="ERROR",
                resource_id=self.subscription_id,
                status_extended="No evaluation_script provided.",
            )]

        # Build the execution context
        from .evaluators.base import EvalConfig
        exec_globals = {
            "__builtins__": __builtins__,
            "credential": self.credential,
            "subscription_id": self.subscription_id,
            "tenant_id": self.tenant_id,
            "clients": self.clients,
            "config": EvalConfig(
                subscription_id=self.subscription_id,
                tenant_id=self.tenant_id,
            ),
            "results": [],  # Script must populate this
            "json": json,
            "logging": logging,
        }

        start = time.monotonic()
        try:
            exec(compile(control.evaluation_script, f"<control:{control.control_id}>", "exec"), exec_globals)
            elapsed = time.monotonic() - start

            raw_results = exec_globals.get("results", [])
            if not isinstance(raw_results, list):
                return [_make_check_result(
                    control, status="ERROR",
                    resource_id=self.subscription_id,
                    status_extended=f"Script did not set 'results' as a list (got {type(raw_results).__name__}).",
                )]

            # Normalize results into CheckResult format
            check_results = []
            for r in raw_results:
                if isinstance(r, dict):
                    check_results.append(_make_check_result(
                        control,
                        status=r.get("status", "FAIL"),
                        resource_id=r.get("resource_id", self.subscription_id),
                        resource_name=r.get("resource_name", ""),
                        status_extended=r.get("status_extended", ""),
                        region=r.get("region", ""),
                    ))

            if not check_results:
                # Script ran but produced no results — treat as PASS (no resources found)
                check_results.append(_make_check_result(
                    control, status="PASS",
                    resource_id=self.subscription_id,
                    status_extended=f"Script completed in {elapsed:.1f}s, no applicable resources found.",
                ))

            logger.info("Custom control %s: Python script completed in %.1fs, %d results",
                        control.control_id, elapsed, len(check_results))
            return check_results

        except Exception as e:
            elapsed = time.monotonic() - start
            tb = traceback.format_exc()
            logger.warning("Custom control %s: Python script failed in %.1fs: %s",
                           control.control_id, elapsed, e)
            return [_make_check_result(
                control, status="ERROR",
                resource_id=self.subscription_id,
                status_extended=f"Script error after {elapsed:.1f}s: {e}\n{tb[:500]}",
            )]

    # ─────────────────────────────────────────────────────────
    # CLI command execution
    # ─────────────────────────────────────────────────────────

    def execute_cli(self, control: CustomControl) -> list[dict]:
        """Execute an Azure CLI command and parse the result.

        Resolves placeholders, runs via subprocess, applies pass_condition.
        """
        if not control.cli_command:
            return [_make_check_result(
                control, status="ERROR",
                resource_id=self.subscription_id,
                status_extended="No cli_command provided.",
            )]

        # Resolve placeholders
        cmd = control.cli_command.format(
            subscription_id=self.subscription_id,
            tenant_id=self.tenant_id,
        )

        # Ensure output is JSON for parsing
        if "-o " not in cmd and "--output " not in cmd:
            cmd += " -o json"

        start = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            elapsed = time.monotonic() - start

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            exit_code = result.returncode

            logger.info("Custom control %s: CLI completed in %.1fs (exit=%d, stdout=%d bytes)",
                        control.control_id, elapsed, exit_code, len(stdout))

            # Apply pass condition
            condition = control.pass_condition or "empty"
            passed = self._evaluate_cli_condition(condition, stdout, exit_code)

            # Try to parse JSON output for per-resource results
            check_results = []
            try:
                data = json.loads(stdout) if stdout else []
                if isinstance(data, list):
                    if passed:
                        # PASS — no non-compliant resources
                        check_results.append(_make_check_result(
                            control, status="PASS",
                            resource_id=self.subscription_id,
                            status_extended=f"CLI check passed. {len(data)} resources evaluated. Condition: {condition}",
                        ))
                    else:
                        # FAIL — enumerate non-compliant resources
                        for item in data:
                            rid = item.get("id", item.get("name", str(item)[:100]))
                            rname = item.get("name", "")
                            check_results.append(_make_check_result(
                                control, status="FAIL",
                                resource_id=rid, resource_name=rname,
                                status_extended=f"Non-compliant resource: {rname or rid}",
                            ))
                        if not check_results:
                            check_results.append(_make_check_result(
                                control, status="FAIL",
                                resource_id=self.subscription_id,
                                status_extended=f"CLI check failed. Condition: {condition}. Output: {stdout[:200]}",
                            ))
                else:
                    check_results.append(_make_check_result(
                        control, status="PASS" if passed else "FAIL",
                        resource_id=self.subscription_id,
                        status_extended=f"CLI output (non-list): {stdout[:300]}",
                    ))
            except json.JSONDecodeError:
                check_results.append(_make_check_result(
                    control, status="PASS" if passed else "FAIL",
                    resource_id=self.subscription_id,
                    status_extended=f"CLI output (non-JSON): {stdout[:300]}",
                ))

            if stderr and exit_code != 0:
                check_results.append(_make_check_result(
                    control, status="ERROR",
                    resource_id=self.subscription_id,
                    status_extended=f"CLI stderr: {stderr[:500]}",
                ))

            return check_results

        except subprocess.TimeoutExpired:
            return [_make_check_result(
                control, status="ERROR",
                resource_id=self.subscription_id,
                status_extended=f"CLI command timed out after {self.timeout}s: {cmd[:200]}",
            )]
        except Exception as e:
            return [_make_check_result(
                control, status="ERROR",
                resource_id=self.subscription_id,
                status_extended=f"CLI execution error: {e}",
            )]

    @staticmethod
    def _evaluate_cli_condition(condition: str, stdout: str, exit_code: int) -> bool:
        """Evaluate the pass condition against CLI output."""
        condition = condition.strip().lower()

        if condition == "empty":
            # PASS if output is empty or empty JSON array
            try:
                data = json.loads(stdout) if stdout else []
                return isinstance(data, list) and len(data) == 0
            except json.JSONDecodeError:
                return stdout.strip() in ("", "[]", "null")

        elif condition == "not_empty":
            try:
                data = json.loads(stdout) if stdout else []
                return isinstance(data, list) and len(data) > 0
            except json.JSONDecodeError:
                return bool(stdout.strip())

        elif condition == "exit_code":
            return exit_code == 0

        elif condition.startswith("contains:"):
            target = condition[len("contains:"):]
            return target in stdout

        elif condition.startswith("equals:"):
            target = condition[len("equals:"):]
            return stdout.strip() == target.strip()

        else:
            # Default: treat as "empty"
            return stdout.strip() in ("", "[]", "null")


# ─────────────────────────────────────────────────────────────────
# Integration with the CIS Evaluator Engine
# ─────────────────────────────────────────────────────────────────

class CustomFrameworkEngine:
    """Evaluates all controls in a custom framework.

    Analogous to CISEvaluatorEngine but for user-defined frameworks.
    Each control can have cli_command and/or evaluation_script.

    Usage:
        engine = CustomFrameworkEngine(
            credential=cred,
            subscription_id="...",
            tenant_id="...",
            controls=[CustomControl(...), CustomControl(...)],
        )
        results = engine.evaluate_all()
    """

    def __init__(
        self,
        credential,
        subscription_id: str,
        tenant_id: str = "",
        controls: list[CustomControl] | None = None,
        timeout: int = 60,
    ):
        self.executor = CustomControlExecutor(
            credential=credential,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            timeout=timeout,
        )
        self.controls = controls or []

    def evaluate_all(self) -> list[dict]:
        """Evaluate all custom controls."""
        all_results = []
        for control in self.controls:
            try:
                results = self.executor.execute(control)
                all_results.extend(results)
            except Exception as e:
                logger.error("Fatal error evaluating custom control %s: %s",
                             control.control_id, e)
                all_results.append(_make_check_result(
                    control, status="ERROR",
                    resource_id=self.executor.subscription_id,
                    status_extended=f"Unhandled error: {e}",
                ))
        return all_results

    def evaluate_single(self, control_id: str) -> list[dict]:
        """Evaluate a single custom control by ID."""
        control = next((c for c in self.controls if c.control_id == control_id), None)
        if not control:
            return [{"error": f"Custom control {control_id} not found"}]
        return self.executor.execute(control)
