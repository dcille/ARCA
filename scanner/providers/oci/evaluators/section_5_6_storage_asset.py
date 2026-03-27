"""CIS OCI v3.1 Sections 5 & 6: Storage + Asset Management -- 8 controls.

Coverage:
  5.1.1 No Object Storage buckets publicly visible          automated
  5.1.2 Object Storage Buckets encrypted with CMK           automated
  5.1.3 Versioning enabled for Object Storage Buckets       automated
  5.2.1 Block Volumes encrypted with CMK                    automated
  5.2.2 Boot Volumes encrypted with CMK                     automated
  5.3.1 File Storage Systems encrypted with CMK             automated
  6.1   At least one compartment exists                     automated
  6.2   No resources created in root compartment            automated
"""

import logging

from .base import OCIClientCache, EvalConfig, make_result

logger = logging.getLogger(__name__)
FW = ["CIS-OCI-3.1"]


# ═══════════════════════════════════════════════════════════════
# 5.1.1 -- No Object Storage buckets publicly visible
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_1_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        namespace = c.object_storage.get_namespace().data
    except Exception:
        return [make_result(
            cis_id="5.1.1", check_id="oci_cis_5_1_1",
            title="Ensure no Object Storage buckets are publicly visible",
            service="storage", severity="critical", status="ERROR",
            resource_id=cfg.tenancy_id,
            status_extended="Could not retrieve Object Storage namespace",
            compliance_frameworks=FW,
        )]

    for cid in c.list_compartments():
        try:
            buckets = c.object_storage.list_buckets(namespace, cid).data
            for bs in buckets:
                bucket = c.object_storage.get_bucket(namespace, bs.name).data
                is_public = bucket.public_access_type != "NoPublicAccess"
                results.append(make_result(
                    cis_id="5.1.1", check_id="oci_cis_5_1_1",
                    title="Ensure no Object Storage buckets are publicly visible",
                    service="storage", severity="critical",
                    status="FAIL" if is_public else "PASS",
                    resource_id=bucket.name, resource_name=bucket.name,
                    status_extended=f"Bucket '{bucket.name}' public access: {bucket.public_access_type}",
                    remediation="Set bucket public access type to 'NoPublicAccess'.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 5.1.1 compartment %s: %s", cid, e)

    return results or [make_result(
        cis_id="5.1.1", check_id="oci_cis_5_1_1",
        title="Ensure no Object Storage buckets are publicly visible",
        service="storage", severity="critical", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No buckets found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 5.1.2 -- Object Storage Buckets encrypted with CMK
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_1_2(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        namespace = c.object_storage.get_namespace().data
    except Exception:
        return [make_result(
            cis_id="5.1.2", check_id="oci_cis_5_1_2",
            title="Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)",
            service="storage", severity="high", status="ERROR",
            resource_id=cfg.tenancy_id,
            status_extended="Could not retrieve Object Storage namespace",
            compliance_frameworks=FW,
        )]

    for cid in c.list_compartments():
        try:
            buckets = c.object_storage.list_buckets(namespace, cid).data
            for bs in buckets:
                bucket = c.object_storage.get_bucket(namespace, bs.name).data
                has_cmk = bucket.kms_key_id is not None and bucket.kms_key_id != ""
                results.append(make_result(
                    cis_id="5.1.2", check_id="oci_cis_5_1_2",
                    title="Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)",
                    service="storage", severity="high",
                    status="PASS" if has_cmk else "FAIL",
                    resource_id=bucket.name, resource_name=bucket.name,
                    status_extended=f"Bucket '{bucket.name}': CMK {'configured' if has_cmk else 'not configured'}",
                    remediation="Enable encryption with a customer-managed key in OCI Vault.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 5.1.2 compartment %s: %s", cid, e)

    return results or [make_result(
        cis_id="5.1.2", check_id="oci_cis_5_1_2",
        title="Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)",
        service="storage", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No buckets found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 5.1.3 -- Versioning enabled for Object Storage Buckets
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_1_3(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        namespace = c.object_storage.get_namespace().data
    except Exception:
        return [make_result(
            cis_id="5.1.3", check_id="oci_cis_5_1_3",
            title="Ensure Versioning is Enabled for Object Storage Buckets",
            service="storage", severity="medium", status="ERROR",
            resource_id=cfg.tenancy_id,
            status_extended="Could not retrieve Object Storage namespace",
            compliance_frameworks=FW,
        )]

    for cid in c.list_compartments():
        try:
            buckets = c.object_storage.list_buckets(namespace, cid).data
            for bs in buckets:
                bucket = c.object_storage.get_bucket(namespace, bs.name).data
                versioning = getattr(bucket, "versioning", None)
                is_versioned = versioning == "Enabled"
                results.append(make_result(
                    cis_id="5.1.3", check_id="oci_cis_5_1_3",
                    title="Ensure Versioning is Enabled for Object Storage Buckets",
                    service="storage", severity="medium",
                    status="PASS" if is_versioned else "FAIL",
                    resource_id=bucket.name, resource_name=bucket.name,
                    status_extended=f"Bucket '{bucket.name}': versioning {'enabled' if is_versioned else 'not enabled'}",
                    remediation="Enable versioning on the Object Storage bucket.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 5.1.3 compartment %s: %s", cid, e)

    return results or [make_result(
        cis_id="5.1.3", check_id="oci_cis_5_1_3",
        title="Ensure Versioning is Enabled for Object Storage Buckets",
        service="storage", severity="medium", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No buckets found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 5.2.1 -- Block Volumes encrypted with CMK
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_2_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            volumes = c.block_storage.list_volumes(cid).data
            for vol in volumes:
                if vol.lifecycle_state != "AVAILABLE":
                    continue
                has_cmk = vol.kms_key_id is not None and vol.kms_key_id != ""
                results.append(make_result(
                    cis_id="5.2.1", check_id="oci_cis_5_2_1",
                    title="Ensure Block Volumes are encrypted with Customer Managed Keys (CMK)",
                    service="storage", severity="high",
                    status="PASS" if has_cmk else "FAIL",
                    resource_id=vol.id, resource_name=vol.display_name,
                    status_extended=f"Volume '{vol.display_name}': CMK {'configured' if has_cmk else 'not configured'}",
                    remediation="Enable encryption with a customer-managed key in OCI Vault.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 5.2.1 compartment %s: %s", cid, e)

    return results or [make_result(
        cis_id="5.2.1", check_id="oci_cis_5_2_1",
        title="Ensure Block Volumes are encrypted with Customer Managed Keys (CMK)",
        service="storage", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No block volumes found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 5.2.2 -- Boot Volumes encrypted with CMK
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_2_2(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    ads = c.identity.list_availability_domains(cfg.tenancy_id).data
    for cid in c.list_compartments():
        for ad in ads:
            try:
                boot_volumes = c.block_storage.list_boot_volumes(
                    compartment_id=cid, availability_domain=ad.name
                ).data
                for bv in boot_volumes:
                    if bv.lifecycle_state != "AVAILABLE":
                        continue
                    has_cmk = bv.kms_key_id is not None and bv.kms_key_id != ""
                    results.append(make_result(
                        cis_id="5.2.2", check_id="oci_cis_5_2_2",
                        title="Ensure boot volumes are encrypted with Customer Managed Key (CMK)",
                        service="storage", severity="high",
                        status="PASS" if has_cmk else "FAIL",
                        resource_id=bv.id, resource_name=bv.display_name,
                        status_extended=f"Boot volume '{bv.display_name}': CMK {'configured' if has_cmk else 'not configured'}",
                        remediation="Enable encryption with a customer-managed key in OCI Vault.",
                        compliance_frameworks=FW,
                    ))
            except Exception as e:
                logger.warning("CIS 5.2.2 compartment %s AD %s: %s", cid, ad.name, e)

    return results or [make_result(
        cis_id="5.2.2", check_id="oci_cis_5_2_2",
        title="Ensure boot volumes are encrypted with Customer Managed Key (CMK)",
        service="storage", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No boot volumes found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 5.3.1 -- File Storage Systems encrypted with CMK
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_3_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    ads = c.identity.list_availability_domains(cfg.tenancy_id).data
    for cid in c.list_compartments():
        for ad in ads:
            try:
                file_systems = c.file_storage.list_file_systems(
                    cid, availability_domain=ad.name
                ).data
                for fs in file_systems:
                    if fs.lifecycle_state != "ACTIVE":
                        continue
                    has_cmk = getattr(fs, "kms_key_id", None) is not None
                    results.append(make_result(
                        cis_id="5.3.1", check_id="oci_cis_5_3_1",
                        title="Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)",
                        service="storage", severity="high",
                        status="PASS" if has_cmk else "FAIL",
                        resource_id=fs.id, resource_name=fs.display_name,
                        status_extended=f"File system '{fs.display_name}': CMK {'configured' if has_cmk else 'not configured'}",
                        remediation="Enable encryption with a customer-managed key in OCI Vault.",
                        compliance_frameworks=FW,
                    ))
            except Exception as e:
                logger.warning("CIS 5.3.1 compartment %s AD %s: %s", cid, ad.name, e)

    return results or [make_result(
        cis_id="5.3.1", check_id="oci_cis_5_3_1",
        title="Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)",
        service="storage", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No file storage systems found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 6.1 -- At least one compartment exists
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_6_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    compartments = c.identity.list_compartments(cfg.tenancy_id).data
    active = [comp for comp in compartments if comp.lifecycle_state == "ACTIVE"]
    status = "PASS" if active else "FAIL"
    return [make_result(
        cis_id="6.1", check_id="oci_cis_6_1",
        title="Create at least one compartment in your tenancy to store cloud resources",
        service="asset_management", severity="critical", status=status,
        resource_id=cfg.tenancy_id,
        status_extended=f"{len(active)} active compartment(s) found (excluding root)",
        remediation="Create at least one compartment to organize and isolate resources.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 6.2 -- No resources created in root compartment
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_6_2(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """Check that no compute instances exist in the root compartment."""
    root_resources = []
    try:
        instances = c.compute.list_instances(cfg.tenancy_id).data
        root_resources.extend([i for i in instances if i.lifecycle_state == "RUNNING"])
    except Exception:
        pass
    try:
        vcns = c.virtual_network.list_vcns(cfg.tenancy_id).data
        root_resources.extend(vcns)
    except Exception:
        pass

    status = "FAIL" if root_resources else "PASS"
    return [make_result(
        cis_id="6.2", check_id="oci_cis_6_2",
        title="Ensure no resources are created in the root compartment",
        service="asset_management", severity="critical", status=status,
        resource_id=cfg.tenancy_id,
        status_extended=(
            f"{len(root_resources)} resource(s) found in root compartment"
            if root_resources else "No compute instances or VCNs found in root compartment"
        ),
        remediation="Move resources from root compartment to child compartments.",
        compliance_frameworks=FW,
    )]
