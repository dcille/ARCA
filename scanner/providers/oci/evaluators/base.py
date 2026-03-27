"""Base evaluator infrastructure for OCI CIS v3.1.0 control evaluation.

Every CIS evaluator function receives an OCIClientCache and EvalConfig,
and returns a list of CheckResult dicts.

Mirrors the AWS/Azure/GCP evaluator pattern but uses the OCI Python SDK.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------

@dataclass
class EvalConfig:
    """Runtime configuration passed to every evaluator."""
    tenancy_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["us-ashburn-1"])
    max_resources_per_check: int = 500
    timeout_seconds: int = 60


# -----------------------------------------------------------------
# Result builder helpers
# -----------------------------------------------------------------

def make_result(
    *,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    status: str,             # PASS | FAIL | MANUAL | ERROR | N/A
    resource_id: str,
    resource_name: str = "",
    status_extended: str = "",
    remediation: str = "",
    region: str = "",
    compliance_frameworks: Optional[list[str]] = None,
) -> dict:
    """Build a CheckResult dict compatible with the existing scanner output."""
    return {
        "check_id": check_id,
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": status,
        "resource_id": resource_id,
        "resource_name": resource_name or (resource_id.split("/")[-1] if resource_id else ""),
        "region": region,
        "status_extended": status_extended,
        "remediation": remediation,
        "compliance_frameworks": compliance_frameworks or ["CIS-OCI-3.1"],
        "cis_control_id": cis_id,
    }


def make_manual_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    tenancy_id: str,
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
        resource_id=tenancy_id,
        status_extended=f"Manual verification required: {reason}",
        remediation=f"Refer to CIS OCI Foundations Benchmark v3.1.0, control {cis_id}.",
    )


def make_error_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    tenancy_id: str,
    error: str,
) -> dict:
    """Build an ERROR result when the evaluator fails."""
    return make_result(
        cis_id=cis_id,
        check_id=check_id,
        title=title,
        service=service,
        severity=severity,
        status="ERROR",
        resource_id=tenancy_id,
        status_extended=f"Evaluation failed: {error}",
        remediation="Check that the OCI credentials have the required IAM permissions.",
    )


# -----------------------------------------------------------------
# SDK client caching
# -----------------------------------------------------------------

class OCIClientCache:
    """Lazy-loading cache for OCI SDK clients.

    Avoids creating a new client for every evaluator function.
    One instance is created per scan run and shared across evaluators.
    """

    def __init__(self, oci_config: dict, tenancy_id: str):
        self._config = oci_config
        self._tenancy_id = tenancy_id
        self._cache: dict[str, Any] = {}

    def _get_or_create(self, key: str, factory: Callable) -> Any:
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]

    @property
    def tenancy_id(self):
        return self._tenancy_id

    @property
    def config(self):
        return self._config

    # --- Identity / IAM ---

    @property
    def identity(self):
        import oci
        return self._get_or_create(
            "identity",
            lambda: oci.identity.IdentityClient(self._config),
        )

    # --- Networking ---

    @property
    def virtual_network(self):
        import oci
        return self._get_or_create(
            "virtual_network",
            lambda: oci.core.VirtualNetworkClient(self._config),
        )

    # --- Compute ---

    @property
    def compute(self):
        import oci
        return self._get_or_create(
            "compute",
            lambda: oci.core.ComputeClient(self._config),
        )

    # --- Block Storage ---

    @property
    def block_storage(self):
        import oci
        return self._get_or_create(
            "block_storage",
            lambda: oci.core.BlockstorageClient(self._config),
        )

    # --- Object Storage ---

    @property
    def object_storage(self):
        import oci
        return self._get_or_create(
            "object_storage",
            lambda: oci.object_storage.ObjectStorageClient(self._config),
        )

    # --- File Storage ---

    @property
    def file_storage(self):
        import oci
        return self._get_or_create(
            "file_storage",
            lambda: oci.file_storage.FileStorageClient(self._config),
        )

    # --- Audit ---

    @property
    def audit(self):
        import oci
        return self._get_or_create(
            "audit",
            lambda: oci.audit.AuditClient(self._config),
        )

    # --- Logging ---

    @property
    def logging(self):
        import oci
        return self._get_or_create(
            "logging",
            lambda: oci.logging.LoggingManagementClient(self._config),
        )

    # --- Events ---

    @property
    def events(self):
        import oci
        return self._get_or_create(
            "events",
            lambda: oci.events.EventsClient(self._config),
        )

    # --- Cloud Guard ---

    @property
    def cloud_guard(self):
        import oci
        return self._get_or_create(
            "cloud_guard",
            lambda: oci.cloud_guard.CloudGuardClient(self._config),
        )

    # --- Notifications ---

    @property
    def notifications(self):
        import oci
        return self._get_or_create(
            "notifications",
            lambda: oci.ons.NotificationControlPlaneClient(self._config),
        )

    # --- KMS Vault ---

    @property
    def kms_vault(self):
        import oci
        return self._get_or_create(
            "kms_vault",
            lambda: oci.key_management.KmsVaultClient(self._config),
        )

    def kms_management(self, endpoint: str):
        """Create a KMS management client for a specific vault endpoint."""
        import oci
        key = f"kms_mgmt:{endpoint}"
        return self._get_or_create(
            key,
            lambda: oci.key_management.KmsManagementClient(self._config, service_endpoint=endpoint),
        )

    # --- Helpers ---

    def list_compartments(self) -> list:
        """List all active compartments including root tenancy."""
        compartments = self.identity.list_compartments(
            self._tenancy_id, compartment_id_in_subtree=True
        ).data
        return [self._tenancy_id] + [
            c.id for c in compartments if c.lifecycle_state == "ACTIVE"
        ]


# -----------------------------------------------------------------
# Evaluator type alias
# -----------------------------------------------------------------

EvaluatorFn = Callable[[OCIClientCache, EvalConfig], list[dict]]


def safe_evaluate(
    evaluator: EvaluatorFn,
    clients: OCIClientCache,
    config: EvalConfig,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
) -> list[dict]:
    """Run an evaluator with error handling -- never let one check crash the scan."""
    try:
        return evaluator(clients, config)
    except Exception as e:
        logger.warning("Evaluator %s failed: %s", cis_id, e)
        return [make_error_result(
            cis_id=cis_id,
            check_id=check_id,
            title=title,
            service=service,
            severity=severity,
            tenancy_id=config.tenancy_id,
            error=str(e),
        )]
