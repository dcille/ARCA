"""CIS OCI v3.1 Section 5 — Storage (6 controls) + Section 6 — Asset Management (2 controls).

Section 5 - All Automated:
  5.1.1 No public buckets
  5.1.2 Buckets encrypted with CMK
  5.1.3 Bucket versioning enabled
  5.2.1 Block volumes encrypted with CMK
  5.2.2 Boot volumes encrypted with CMK
  5.3.1 File Storage Systems encrypted with CMK
Section 6 - All Automated:
  6.1 At least one compartment exists
  6.2 No resources in root compartment
"""
from __future__ import annotations
from .base import (OCIClientCache, EvalConfig, make_result, logger)


# ═════════════════════════════════════════════════════════════════
# Section 5.1 — Object Storage
# ═════════════════════════════════════════════════════════════════

def evaluate_5_1_1(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """5.1.1 — No Object Storage buckets are publicly visible."""
    results = []
    try:
        namespace = clients.object_storage.get_namespace().data
        for cid in cfg.compartment_ids:
            try:
                buckets = clients.object_storage.list_buckets(namespace, cid).data
                for bs in buckets:
                    bucket = clients.object_storage.get_bucket(namespace, bs.name).data
                    is_public = bucket.public_access_type != "NoPublicAccess"
                    results.append(make_result("5.1.1",
                        "No Object Storage buckets are publicly visible",
                        bucket.name, bucket.name, not is_public,
                        f"Bucket '{bucket.name}' access type: {bucket.public_access_type}",
                        severity="critical", service="ObjectStorage",
                        remediation="Set bucket public access type to 'NoPublicAccess'"))
            except Exception as e:
                logger.warning(f"Bucket public check compartment {cid}: {e}")
    except Exception as e:
        logger.warning(f"Object Storage namespace: {e}")
    return results


def evaluate_5_1_2(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """5.1.2 — Buckets encrypted with Customer Managed Key (CMK)."""
    results = []
    try:
        namespace = clients.object_storage.get_namespace().data
        for cid in cfg.compartment_ids:
            try:
                buckets = clients.object_storage.list_buckets(namespace, cid).data
                for bs in buckets:
                    bucket = clients.object_storage.get_bucket(namespace, bs.name).data
                    has_cmk = bool(getattr(bucket, 'kms_key_id', None))
                    results.append(make_result("5.1.2",
                        "Object Storage Buckets are encrypted with a Customer Managed Key (CMK)",
                        bucket.name, bucket.name, has_cmk,
                        severity="high", service="ObjectStorage",
                        remediation="Enable encryption with a customer-managed key in OCI Vault"))
            except Exception as e:
                logger.warning(f"Bucket CMK check compartment {cid}: {e}")
    except Exception as e:
        logger.warning(f"Object Storage namespace: {e}")
    return results


def evaluate_5_1_3(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """5.1.3 — Versioning enabled for Object Storage Buckets."""
    results = []
    try:
        namespace = clients.object_storage.get_namespace().data
        for cid in cfg.compartment_ids:
            try:
                buckets = clients.object_storage.list_buckets(namespace, cid).data
                for bs in buckets:
                    bucket = clients.object_storage.get_bucket(namespace, bs.name).data
                    versioned = getattr(bucket, 'versioning', '') == "Enabled"
                    results.append(make_result("5.1.3",
                        "Versioning is enabled for Object Storage Buckets",
                        bucket.name, bucket.name, versioned,
                        severity="medium", service="ObjectStorage",
                        remediation="Enable versioning on the Object Storage bucket"))
            except Exception as e:
                logger.warning(f"Bucket versioning check compartment {cid}: {e}")
    except Exception as e:
        logger.warning(f"Object Storage namespace: {e}")
    return results


# ═════════════════════════════════════════════════════════════════
# Section 5.2 — Block Volumes
# ═════════════════════════════════════════════════════════════════

def evaluate_5_2_1(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """5.2.1 — Block Volumes encrypted with CMK."""
    results = []
    for cid in cfg.compartment_ids:
        try:
            volumes = clients.blockstorage.list_volumes(cid).data
            for vol in volumes:
                if vol.lifecycle_state != "AVAILABLE":
                    continue
                has_cmk = bool(getattr(vol, 'kms_key_id', None))
                results.append(make_result("5.2.1",
                    "Block Volumes are encrypted with Customer Managed Keys (CMK)",
                    vol.id, vol.display_name, has_cmk,
                    severity="high", service="Storage",
                    remediation="Enable encryption with a customer-managed key in OCI Vault"))
        except Exception as e:
            logger.warning(f"Block volume CMK check compartment {cid}: {e}")
    return results


def evaluate_5_2_2(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """5.2.2 — Boot volumes encrypted with CMK."""
    results = []
    try:
        ads = clients.identity.list_availability_domains(cfg.tenancy_id).data
    except Exception:
        ads = []
    for cid in cfg.compartment_ids:
        for ad in ads:
            try:
                bvs = clients.blockstorage.list_boot_volumes(
                    compartment_id=cid, availability_domain=ad.name).data
                for bv in bvs:
                    if bv.lifecycle_state != "AVAILABLE":
                        continue
                    has_cmk = bool(getattr(bv, 'kms_key_id', None))
                    results.append(make_result("5.2.2",
                        "Boot volumes are encrypted with Customer Managed Key (CMK)",
                        bv.id, bv.display_name, has_cmk,
                        severity="high", service="Storage",
                        remediation="Enable encryption with a customer-managed key in OCI Vault"))
            except Exception as e:
                logger.warning(f"Boot volume CMK check compartment {cid}, AD {ad.name}: {e}")
    return results


# ═════════════════════════════════════════════════════════════════
# Section 5.3 — File Storage Service
# ═════════════════════════════════════════════════════════════════

def evaluate_5_3_1(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """5.3.1 — File Storage Systems encrypted with CMK."""
    results = []
    try:
        ads = clients.identity.list_availability_domains(cfg.tenancy_id).data
    except Exception:
        ads = []
    for cid in cfg.compartment_ids:
        for ad in ads:
            try:
                file_systems = clients.file_storage.list_file_systems(
                    cid, availability_domain=ad.name).data
                for fs in file_systems:
                    if fs.lifecycle_state != "ACTIVE":
                        continue
                    has_cmk = bool(getattr(fs, 'kms_key_id', None))
                    results.append(make_result("5.3.1",
                        "File Storage Systems are encrypted with Customer Managed Keys (CMK)",
                        fs.id, fs.display_name, has_cmk,
                        severity="high", service="FileStorage",
                        remediation="Enable encryption with a customer-managed key in OCI Vault"))
            except Exception as e:
                logger.warning(f"File Storage CMK check compartment {cid}, AD {ad.name}: {e}")
    return results


# ═════════════════════════════════════════════════════════════════
# Section 6 — Asset Management
# ═════════════════════════════════════════════════════════════════

def evaluate_6_1(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """6.1 — At least one compartment in tenancy to store cloud resources."""
    try:
        comps = clients.identity.list_compartments(cfg.tenancy_id).data
        active = [c for c in comps if c.lifecycle_state == "ACTIVE"]
        return [make_result("6.1",
            "Create at least one compartment in your tenancy to store cloud resources",
            cfg.tenancy_id, "Compartments", len(active) > 0,
            f"{len(active)} active compartment(s) found",
            severity="medium", service="AssetManagement",
            remediation="Create at least one compartment under the root to organize resources")]
    except Exception as e:
        logger.warning(f"Compartment check: {e}")
        return []


def evaluate_6_2(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """6.2 — No resources are created in the root compartment."""
    results = []
    try:
        import oci
        search_client = clients.resource_search
        query = f"query all resources where compartmentId = '{cfg.tenancy_id}'"
        search_details = oci.resource_search.models.StructuredSearchDetails(
            query=query, type="Structured")
        resp = search_client.search_resources(search_details).data
        items = getattr(resp, 'items', []) or []
        # Filter out identity resources that must be in root
        non_identity = [i for i in items if getattr(i, 'resource_type', '') not in
                       ('Compartment', 'User', 'Group', 'Policy', 'TagNamespace',
                        'TagDefault', 'DynamicGroup', 'IdentityProvider')]
        passed = len(non_identity) == 0
        results.append(make_result("6.2",
            "Ensure no resources are created in the root compartment",
            cfg.tenancy_id, "Root Compartment", passed,
            f"{len(non_identity)} non-identity resource(s) found in root compartment",
            severity="medium", service="AssetManagement",
            remediation="Move all resources out of the root compartment into child compartments"))
    except Exception as e:
        logger.warning(f"Root compartment resource check: {e}")
        results.append(make_result("6.2",
            "Ensure no resources are created in the root compartment",
            cfg.tenancy_id, "Root Compartment", False,
            f"Could not verify: {e}", severity="medium", service="AssetManagement"))
    return results


SECTION_5_EVALUATORS = {
    "5.1.1": evaluate_5_1_1, "5.1.2": evaluate_5_1_2, "5.1.3": evaluate_5_1_3,
    "5.2.1": evaluate_5_2_1, "5.2.2": evaluate_5_2_2,
    "5.3.1": evaluate_5_3_1,
}

SECTION_6_EVALUATORS = {
    "6.1": evaluate_6_1, "6.2": evaluate_6_2,
}
