"""Base evaluator infrastructure for GCP CIS control evaluation."""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)


@dataclass
class EvalConfig:
    project_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["us-central1"])
    max_resources_per_check: int = 500
    timeout_seconds: int = 60


def make_result(*, cis_id, check_id, title, service, severity, status,
    resource_id, resource_name="", status_extended="", remediation="",
    region="", compliance_frameworks=None):
    return {
        "check_id": check_id, "check_title": title, "service": service,
        "severity": severity, "status": status, "resource_id": resource_id,
        "resource_name": resource_name or (resource_id.split("/")[-1] if resource_id else ""),
        "region": region, "status_extended": status_extended,
        "remediation": remediation,
        "compliance_frameworks": compliance_frameworks or ["CIS-GCP-4.0"],
        "cis_control_id": cis_id,
    }


def make_manual_result(cis_id, check_id, title, service, severity, project_id, reason):
    return make_result(cis_id=cis_id, check_id=check_id, title=title,
        service=service, severity=severity, status="MANUAL",
        resource_id=f"projects/{project_id}",
        status_extended=f"Manual verification required: {reason}",
        remediation=f"Refer to CIS GCP Foundation Benchmark v4.0.0, control {cis_id}.")


def make_error_result(cis_id, check_id, title, service, severity, project_id, error):
    return make_result(cis_id=cis_id, check_id=check_id, title=title,
        service=service, severity=severity, status="ERROR",
        resource_id=f"projects/{project_id}",
        status_extended=f"Evaluation failed: {error}",
        remediation="Check service account permissions.")


class GCPClientCache:
    """Lazy-loading cache for GCP SDK clients."""
    def __init__(self, credentials, project_id: str):
        self._credentials = credentials
        self._project_id = project_id
        self._cache: dict[str, Any] = {}

    @property
    def project_id(self):
        return self._project_id

    @property
    def credentials(self):
        return self._credentials

    def _get(self, key, factory):
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]

    def api_service(self, service_name: str, version: str = "v1"):
        """Get a googleapiclient discovery service."""
        key = f"api:{service_name}:{version}"
        def factory():
            from googleapiclient.discovery import build
            return build(service_name, version, credentials=self._credentials)
        return self._get(key, factory)

    @property
    def iam_client(self):
        def factory():
            from google.cloud import iam_admin_v1
            return iam_admin_v1.IAMClient(credentials=self._credentials)
        return self._get("iam_client", factory)

    @property
    def compute_instances(self):
        def factory():
            from google.cloud import compute_v1
            return compute_v1.InstancesClient(credentials=self._credentials)
        return self._get("compute_instances", factory)

    @property
    def compute_firewalls(self):
        def factory():
            from google.cloud import compute_v1
            return compute_v1.FirewallsClient(credentials=self._credentials)
        return self._get("compute_firewalls", factory)

    @property
    def compute_networks(self):
        def factory():
            from google.cloud import compute_v1
            return compute_v1.NetworksClient(credentials=self._credentials)
        return self._get("compute_networks", factory)

    @property
    def compute_subnets(self):
        def factory():
            from google.cloud import compute_v1
            return compute_v1.SubnetworksClient(credentials=self._credentials)
        return self._get("compute_subnets", factory)

    @property
    def storage_client(self):
        def factory():
            from google.cloud import storage
            return storage.Client(credentials=self._credentials, project=self._project_id)
        return self._get("storage_client", factory)

    @property
    def logging_client(self):
        def factory():
            from google.cloud import logging as gcp_logging
            return gcp_logging.Client(credentials=self._credentials, project=self._project_id)
        return self._get("logging_client", factory)

    @property
    def kms_client(self):
        def factory():
            from google.cloud import kms
            return kms.KeyManagementServiceClient(credentials=self._credentials)
        return self._get("kms_client", factory)

    @property
    def container_client(self):
        def factory():
            from google.cloud import container_v1
            return container_v1.ClusterManagerClient(credentials=self._credentials)
        return self._get("container_client", factory)

    @property
    def bigquery_client(self):
        def factory():
            from google.cloud import bigquery
            return bigquery.Client(credentials=self._credentials, project=self._project_id)
        return self._get("bigquery_client", factory)

    def crm_policy(self):
        """Get project IAM policy via Cloud Resource Manager v1."""
        svc = self.api_service("cloudresourcemanager", "v1")
        return svc.projects().getIamPolicy(
            resource=self._project_id,
            body={"options": {"requestedPolicyVersion": 3}}
        ).execute()


EvaluatorFn = Callable[["GCPClientCache", EvalConfig], list[dict]]


def safe_evaluate(evaluator, clients, config, cis_id, check_id, title, service, severity):
    try:
        return evaluator(clients, config)
    except Exception as e:
        logger.warning("Evaluator %s failed: %s", cis_id, e)
        return [make_error_result(cis_id, check_id, title, service, severity, config.project_id, str(e))]
