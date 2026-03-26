"""Base evaluator infrastructure for CIS control evaluation.

Every CIS evaluator function receives a credential, subscription_id,
and optional config, and returns a list of CheckResult dicts.

The evaluator handles resource enumeration internally — it lists all
applicable resources and evaluates each one, returning per-resource
PASS/FAIL results.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────

@dataclass
class EvalConfig:
    """Runtime configuration passed to every evaluator."""
    subscription_id: str
    tenant_id: Optional[str] = None
    # Limits (for large environments)
    max_resources_per_check: int = 500
    timeout_seconds: int = 60
    # Optional filters
    resource_groups: Optional[list[str]] = None  # Restrict to specific RGs
    regions: Optional[list[str]] = None


# ─────────────────────────────────────────────────────────────────
# Result builder helpers
# ─────────────────────────────────────────────────────────────────

def make_result(
    *,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    status: str,             # PASS | FAIL | MANUAL | ERROR
    resource_id: str,
    resource_name: str = "",
    status_extended: str = "",
    remediation: str = "",
    region: str = "",
    compliance_frameworks: Optional[list[str]] = None,
) -> dict:
    """Build a CheckResult dict compatible with the existing scanner output.

    This is the contract between evaluators and the scan engine.
    """
    return {
        "check_id": check_id,
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": status,
        "resource_id": resource_id,
        "resource_name": resource_name or resource_id.split("/")[-1] if resource_id else "",
        "region": region,
        "status_extended": status_extended,
        "remediation": remediation,
        "compliance_frameworks": compliance_frameworks or ["CIS-Azure-5.0", "MCSB-Azure-1.0"],
        "cis_control_id": cis_id,
    }


def make_error_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    subscription_id: str,
    error: str,
) -> dict:
    """Build an ERROR result when the evaluator fails (e.g., missing permissions)."""
    return make_result(
        cis_id=cis_id,
        check_id=check_id,
        title=title,
        service=service,
        severity=severity,
        status="ERROR",
        resource_id=subscription_id,
        status_extended=f"Evaluation failed: {error}",
        remediation="Check that the service principal has the required permissions.",
    )


def make_manual_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    subscription_id: str,
    reason: str,
) -> dict:
    """Build a MANUAL result for controls that cannot be automated."""
    return make_result(
        cis_id=cis_id,
        check_id=check_id,
        title=title,
        service=service,
        severity=severity,
        status="MANUAL",
        resource_id=subscription_id,
        status_extended=f"Manual verification required: {reason}",
        remediation=f"Refer to CIS Azure Benchmark v5.0.0, control {cis_id}.",
    )


# ─────────────────────────────────────────────────────────────────
# SDK client caching
# ─────────────────────────────────────────────────────────────────

class AzureClientCache:
    """Lazy-loading cache for Azure SDK management clients.

    Avoids creating a new client for every evaluator function.
    One instance is created per scan run and shared across evaluators.
    """

    def __init__(self, credential, subscription_id: str):
        self._credential = credential
        self._subscription_id = subscription_id
        self._cache: dict[str, Any] = {}

    def _get_or_create(self, key: str, factory: Callable) -> Any:
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]

    @property
    def network(self):
        from azure.mgmt.network import NetworkManagementClient
        return self._get_or_create(
            "network",
            lambda: NetworkManagementClient(self._credential, self._subscription_id),
        )

    @property
    def storage(self):
        from azure.mgmt.storage import StorageManagementClient
        return self._get_or_create(
            "storage",
            lambda: StorageManagementClient(self._credential, self._subscription_id),
        )

    @property
    def compute(self):
        from azure.mgmt.compute import ComputeManagementClient
        return self._get_or_create(
            "compute",
            lambda: ComputeManagementClient(self._credential, self._subscription_id),
        )

    @property
    def monitor(self):
        from azure.mgmt.monitor import MonitorManagementClient
        return self._get_or_create(
            "monitor",
            lambda: MonitorManagementClient(self._credential, self._subscription_id),
        )

    @property
    def keyvault_mgmt(self):
        from azure.mgmt.keyvault import KeyVaultManagementClient
        return self._get_or_create(
            "keyvault_mgmt",
            lambda: KeyVaultManagementClient(self._credential, self._subscription_id),
        )

    @property
    def sql(self):
        from azure.mgmt.sql import SqlManagementClient
        return self._get_or_create(
            "sql",
            lambda: SqlManagementClient(self._credential, self._subscription_id),
        )

    @property
    def web(self):
        from azure.mgmt.web import WebSiteManagementClient
        return self._get_or_create(
            "web",
            lambda: WebSiteManagementClient(self._credential, self._subscription_id),
        )

    @property
    def authorization(self):
        from azure.mgmt.authorization import AuthorizationManagementClient
        return self._get_or_create(
            "authorization",
            lambda: AuthorizationManagementClient(self._credential, self._subscription_id),
        )

    @property
    def security(self):
        from azure.mgmt.security import SecurityCenter
        return self._get_or_create(
            "security",
            lambda: SecurityCenter(self._credential, self._subscription_id, ""),
        )

    @property
    def resource(self):
        from azure.mgmt.resource import ResourceManagementClient
        return self._get_or_create(
            "resource",
            lambda: ResourceManagementClient(self._credential, self._subscription_id),
        )

    @property
    def subscription_id(self):
        return self._subscription_id

    @property
    def credential(self):
        return self._credential

    def graph_token(self) -> str:
        """Get a Graph API access token for Entra ID checks."""
        token = self._credential.get_token("https://graph.microsoft.com/.default")
        return token.token

    def graph_get(self, path: str, beta: bool = False) -> dict | None:
        """Make a GET request to Microsoft Graph API."""
        import requests
        base = "https://graph.microsoft.com/beta" if beta else "https://graph.microsoft.com/v1.0"
        headers = {"Authorization": f"Bearer {self.graph_token()}"}
        resp = requests.get(f"{base}{path}", headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Graph API %s returned %d: %s", path, resp.status_code, resp.text[:200])
        return None


# ─────────────────────────────────────────────────────────────────
# Evaluator type alias
# ─────────────────────────────────────────────────────────────────

# Signature for all evaluator functions:
#   def evaluate_cis_X_Y_Z(clients: AzureClientCache, config: EvalConfig) -> list[dict]
EvaluatorFn = Callable[[AzureClientCache, EvalConfig], list[dict]]


def safe_evaluate(
    evaluator: EvaluatorFn,
    clients: AzureClientCache,
    config: EvalConfig,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
) -> list[dict]:
    """Run an evaluator with error handling — never let one check crash the scan.

    If the evaluator returns an empty list (no resources found to evaluate),
    emit a PASS result so the control doesn't show as "Not Evaluated".
    """
    try:
        results = evaluator(clients, config)
        if not results:
            # No resources found — emit PASS (nothing to flag as non-compliant)
            return [make_result(
                cis_id=cis_id,
                check_id=check_id,
                title=title,
                service=service,
                severity=severity,
                status="PASS",
                resource_id=config.subscription_id,
                resource_name="(no applicable resources)",
                status_extended=(
                    f"No applicable resources found for {cis_id} in subscription "
                    f"{config.subscription_id}. Control passes by default."
                ),
                remediation="",
            )]
        return results
    except Exception as e:
        logger.warning("Evaluator %s failed: %s", cis_id, e)
        return [make_error_result(
            cis_id=cis_id,
            check_id=check_id,
            title=title,
            service=service,
            severity=severity,
            subscription_id=config.subscription_id,
            error=str(e),
        )]
