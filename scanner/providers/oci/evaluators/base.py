"""OCI CIS Evaluator Base — client cache, helpers, result builders.

Uses the official ``oci`` Python SDK for all API calls.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class EvalConfig:
    """Runtime parameters for an OCI CIS evaluation run."""
    config: dict
    tenancy_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["us-ashburn-1"])
    compartment_ids: list[str] = field(default_factory=list)


class OCIClientCache:
    """Lazy-create OCI SDK clients and cache them."""

    def __init__(self, config: dict):
        self._config = config
        self._clients: dict[str, Any] = {}

    def _get(self, key, factory):
        if key not in self._clients:
            self._clients[key] = factory(self._config)
        return self._clients[key]

    @property
    def identity(self):
        import oci; return self._get("identity", oci.identity.IdentityClient)

    @property
    def audit(self):
        import oci; return self._get("audit", oci.audit.AuditClient)

    @property
    def vcn(self):
        import oci; return self._get("vcn", oci.core.VirtualNetworkClient)

    @property
    def compute(self):
        import oci; return self._get("compute", oci.core.ComputeClient)

    @property
    def blockstorage(self):
        import oci; return self._get("blockstorage", oci.core.BlockstorageClient)

    @property
    def object_storage(self):
        import oci; return self._get("object_storage", oci.object_storage.ObjectStorageClient)

    @property
    def database(self):
        import oci; return self._get("database", oci.database.DatabaseClient)

    @property
    def kms_vault(self):
        import oci; return self._get("kms_vault", oci.key_management.KmsVaultClient)

    @property
    def logging_mgmt(self):
        import oci; return self._get("logging_mgmt", oci.logging.LoggingManagementClient)

    @property
    def events(self):
        import oci; return self._get("events", oci.events.EventsClient)

    @property
    def cloud_guard(self):
        import oci; return self._get("cloud_guard", oci.cloud_guard.CloudGuardClient)

    @property
    def ons(self):
        import oci; return self._get("ons", oci.ons.NotificationControlPlaneClient)

    @property
    def file_storage(self):
        import oci; return self._get("file_storage", oci.file_storage.FileStorageClient)

    @property
    def resource_search(self):
        import oci; return self._get("resource_search", oci.resource_search.ResourceSearchClient)

    def kms_management(self, endpoint: str):
        import oci
        key = f"kms_mgmt_{endpoint}"
        if key not in self._clients:
            self._clients[key] = oci.key_management.KmsManagementClient(
                self._config, service_endpoint=endpoint)
        return self._clients[key]


# ── Compartment helpers ──

def list_all_compartments(clients: OCIClientCache, tenancy_id: str) -> list[str]:
    """Return tenancy + all active child compartment OCIDs."""
    try:
        comps = clients.identity.list_compartments(
            tenancy_id, compartment_id_in_subtree=True).data
        return [tenancy_id] + [c.id for c in comps if c.lifecycle_state == "ACTIVE"]
    except Exception as e:
        logger.warning(f"Failed to list compartments: {e}")
        return [tenancy_id]


# ── Date helpers ──

def days_since(dt: Optional[datetime]) -> int:
    if dt is None:
        return 9999
    return (datetime.now(timezone.utc) - dt).days


# ── Result builders ──

def make_result(cis_id, title, resource_id, resource_name, passed,
                detail="", severity="medium", service="OCI", remediation=""):
    return {
        "check_id": f"oci_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": "PASS" if passed else "FAIL",
        "resource_id": resource_id,
        "resource_name": resource_name,
        "status_extended": detail,
        "remediation": remediation,
        "compliance_frameworks": ["CIS-OCI-3.1"],
        "cis_control_id": cis_id,
    }


def make_manual_result(cis_id, title, service="OCI", severity="medium"):
    return {
        "check_id": f"oci_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": "MANUAL",
        "resource_id": "oci-tenancy",
        "resource_name": "Manual verification required",
        "status_extended": f"CIS {cis_id}: Requires manual verification via OCI Console",
        "remediation": f"Refer to CIS OCI Foundations Benchmark v3.1.0, control {cis_id}",
        "compliance_frameworks": ["CIS-OCI-3.1"],
        "cis_control_id": cis_id,
    }


def safe_evaluate(fn, clients, cfg):
    try:
        return fn(clients, cfg)
    except Exception as e:
        logger.error(f"Evaluator {fn.__name__} failed: {e}")
        return []
