"""Base evaluator infrastructure for GCP CIS v4.0.0 control evaluation.

Every CIS evaluator function receives a GCPClientCache and EvalConfig,
and returns a list of CheckResult dicts.

Mirrors the Azure/AWS evaluator pattern but uses Google Cloud SDK clients.
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
    project_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["us-central1"])
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
    status: str,             # PASS | FAIL | MANUAL | ERROR
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
        "compliance_frameworks": compliance_frameworks or ["CIS-GCP-4.0"],
        "cis_control_id": cis_id,
    }


def make_manual_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    project_id: str,
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
        resource_id=project_id,
        status_extended=f"Manual verification required: {reason}",
        remediation=f"Refer to CIS GCP Foundation Benchmark v4.0.0, control {cis_id}.",
    )


def make_error_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    project_id: str,
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
        resource_id=project_id,
        status_extended=f"Evaluation failed: {error}",
        remediation="Check that the service account has the required permissions.",
    )


# -----------------------------------------------------------------
# SDK client caching
# -----------------------------------------------------------------

class GCPClientCache:
    """Lazy-loading cache for Google Cloud SDK clients.

    Avoids creating a new client for every evaluator function.
    One instance is created per scan run and shared across evaluators.
    """

    def __init__(self, credentials, project_id: str):
        self._credentials = credentials
        self._project_id = project_id
        self._cache: dict[str, Any] = {}

    def _get_or_create(self, key: str, factory: Callable) -> Any:
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]

    @property
    def project_id(self):
        return self._project_id

    @property
    def credentials(self):
        return self._credentials

    # --- Resource Manager ---

    @property
    def resource_manager(self):
        from google.cloud import resourcemanager_v3
        return self._get_or_create(
            "resource_manager",
            lambda: resourcemanager_v3.ProjectsClient(credentials=self._credentials),
        )

    # --- IAM Admin ---

    @property
    def iam_admin(self):
        from google.cloud.iam_admin_v1 import IAMClient
        return self._get_or_create(
            "iam_admin",
            lambda: IAMClient(credentials=self._credentials),
        )

    # --- Compute ---

    @property
    def compute_instances(self):
        from google.cloud.compute_v1 import InstancesClient
        return self._get_or_create(
            "compute_instances",
            lambda: InstancesClient(credentials=self._credentials),
        )

    @property
    def compute_firewalls(self):
        from google.cloud.compute_v1 import FirewallsClient
        return self._get_or_create(
            "compute_firewalls",
            lambda: FirewallsClient(credentials=self._credentials),
        )

    @property
    def compute_networks(self):
        from google.cloud.compute_v1 import NetworksClient
        return self._get_or_create(
            "compute_networks",
            lambda: NetworksClient(credentials=self._credentials),
        )

    @property
    def compute_subnetworks(self):
        from google.cloud.compute_v1 import SubnetworksClient
        return self._get_or_create(
            "compute_subnetworks",
            lambda: SubnetworksClient(credentials=self._credentials),
        )

    @property
    def compute_projects(self):
        from google.cloud.compute_v1 import ProjectsClient
        return self._get_or_create(
            "compute_projects",
            lambda: ProjectsClient(credentials=self._credentials),
        )

    @property
    def compute_disks(self):
        from google.cloud.compute_v1 import DisksClient
        return self._get_or_create(
            "compute_disks",
            lambda: DisksClient(credentials=self._credentials),
        )

    # --- Storage ---

    @property
    def storage(self):
        from google.cloud import storage
        return self._get_or_create(
            "storage",
            lambda: storage.Client(credentials=self._credentials, project=self._project_id),
        )

    # --- KMS ---

    @property
    def kms(self):
        from google.cloud import kms
        return self._get_or_create(
            "kms",
            lambda: kms.KeyManagementServiceClient(credentials=self._credentials),
        )

    # --- Logging ---

    @property
    def logging_client(self):
        from google.cloud import logging as gcp_logging
        return self._get_or_create(
            "logging",
            lambda: gcp_logging.Client(credentials=self._credentials, project=self._project_id),
        )

    @property
    def logging_metrics(self):
        from google.cloud.logging_v2 import MetricsServiceV2Client
        return self._get_or_create(
            "logging_metrics",
            lambda: MetricsServiceV2Client(credentials=self._credentials),
        )

    # --- BigQuery ---

    @property
    def bigquery(self):
        from google.cloud import bigquery
        return self._get_or_create(
            "bigquery",
            lambda: bigquery.Client(credentials=self._credentials, project=self._project_id),
        )

    # --- GKE ---

    @property
    def container(self):
        from google.cloud import container_v1
        return self._get_or_create(
            "container",
            lambda: container_v1.ClusterManagerClient(credentials=self._credentials),
        )

    # --- Discovery-based clients (REST) ---

    def discovery_client(self, service_name: str, version: str = "v1") -> Any:
        """Build a googleapiclient.discovery service client."""
        key = f"discovery:{service_name}:{version}"
        if key not in self._cache:
            from googleapiclient.discovery import build
            self._cache[key] = build(
                service_name, version,
                credentials=self._credentials,
                cache_discovery=False,
            )
        return self._cache[key]

    @property
    def sqladmin(self):
        return self.discovery_client("sqladmin", "v1beta4")

    @property
    def dns(self):
        return self.discovery_client("dns", "v1")

    @property
    def dataproc(self):
        return self.discovery_client("dataproc", "v1")

    @property
    def crm_v1(self):
        """Cloud Resource Manager v1 (for getIamPolicy)."""
        return self.discovery_client("cloudresourcemanager", "v1")

    @property
    def essentialcontacts(self):
        return self.discovery_client("essentialcontacts", "v1")


# -----------------------------------------------------------------
# Evaluator type alias
# -----------------------------------------------------------------

EvaluatorFn = Callable[[GCPClientCache, EvalConfig], list[dict]]


def safe_evaluate(
    evaluator: EvaluatorFn,
    clients: GCPClientCache,
    config: EvalConfig,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
) -> list[dict]:
    """Run an evaluator with error handling — never let one check crash the scan."""
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
            project_id=config.project_id,
            error=str(e),
        )]
