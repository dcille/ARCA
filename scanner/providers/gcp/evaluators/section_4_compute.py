"""CIS GCP v4.0 Section 4: Virtual Machines — 12 controls.

Coverage:
  4.1  No default service account         automated
  4.2  No full API access scope           automated
  4.3  Block project-wide SSH keys        automated
  4.4  OS Login enabled                   automated
  4.5  Serial port access disabled        automated
  4.6  IP forwarding disabled             automated
  4.7  VM disks encrypted with CMEK       automated
  4.8  Shielded VM enabled                automated
  4.9  No public IP on instances          automated
  4.10 App Engine enforces HTTPS          manual
  4.11 Confidential Computing enabled     automated
  4.12 Latest OS updates installed        manual
"""

import logging

from .base import GCPClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]


# -----------------------------------------------------------------
# Helper: iterate all instances across all zones
# -----------------------------------------------------------------

def _iter_instances(c: GCPClientCache, cfg: EvalConfig):
    """Yield (instance, zone_name, resource_id) for all compute instances."""
    try:
        for zone, resp in c.compute_instances.aggregated_list(project=cfg.project_id):
            for inst in (resp.instances or []):
                zn = zone.split("/")[-1]
                rid = f"projects/{cfg.project_id}/zones/{zn}/instances/{inst.name}"
                yield inst, zn, rid
    except Exception as e:
        logger.warning("Could not list instances: %s", e)


# ═══════════════════════════════════════════════════════════════
# 4.1 — Ensure instances do not use the default service account
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        default_sa = any(
            sa.email.endswith("-compute@developer.gserviceaccount.com")
            for sa in (inst.service_accounts or [])
        )
        results.append(make_result(
            cis_id="4.1", check_id="gcp_cis_4_1",
            title="Ensure That Instances Are Not Configured To Use Default Service Accounts",
            service="compute", severity="high",
            status="FAIL" if default_sa else "PASS",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': default SA={default_sa}",
            remediation="Use a custom service account with minimum permissions.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.1", check_id="gcp_cis_4_1",
            title="Ensure That Instances Are Not Configured To Use Default Service Accounts",
            service="compute", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.2 — Ensure instances do not use default SA with full API access
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        full_access = any(
            "https://www.googleapis.com/auth/cloud-platform" in (sa.scopes or [])
            for sa in (inst.service_accounts or [])
        )
        results.append(make_result(
            cis_id="4.2", check_id="gcp_cis_4_2",
            title="Ensure That Instances Are Not Configured To Use Default Service Accounts With Full Access to All Cloud APIs",
            service="compute", severity="high",
            status="FAIL" if full_access else "PASS",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': full API scope={full_access}",
            remediation="Use minimum necessary API scopes instead of cloud-platform.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.2", check_id="gcp_cis_4_2",
            title="Ensure That Instances Are Not Configured To Use Default Service Accounts With Full Access to All Cloud APIs",
            service="compute", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.3 — Ensure "Block Project-Wide SSH Keys" is enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        blocked = any(
            i.key == "block-project-ssh-keys" and i.value.lower() == "true"
            for i in (inst.metadata.items or []) if inst.metadata
        )
        results.append(make_result(
            cis_id="4.3", check_id="gcp_cis_4_3",
            title="Ensure 'Block Project-Wide SSH Keys' Is Enabled for VM Instances",
            service="compute", severity="medium",
            status="PASS" if blocked else "FAIL",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': block project SSH keys={blocked}",
            remediation="Set metadata block-project-ssh-keys=true on the instance.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.3", check_id="gcp_cis_4_3",
            title="Ensure 'Block Project-Wide SSH Keys' Is Enabled for VM Instances",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.4 — Ensure OS Login is enabled for instances
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []

    # Check project-level metadata first
    project_oslogin = False
    try:
        project = c.compute_projects.get(request={"project": cfg.project_id})
        if project.common_instance_metadata:
            project_oslogin = any(
                i.key == "enable-oslogin" and i.value.lower() == "true"
                for i in (project.common_instance_metadata.items or [])
            )
    except Exception:
        pass

    for inst, zn, rid in _iter_instances(c, cfg):
        instance_oslogin = any(
            i.key == "enable-oslogin" and i.value.lower() == "true"
            for i in (inst.metadata.items or []) if inst.metadata
        )
        enabled = instance_oslogin or project_oslogin
        results.append(make_result(
            cis_id="4.4", check_id="gcp_cis_4_4",
            title="Ensure Oslogin Is Enabled for a Project",
            service="compute", severity="medium",
            status="PASS" if enabled else "FAIL",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': OS Login={enabled}",
            remediation="Enable OS Login: gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.4", check_id="gcp_cis_4_4",
            title="Ensure Oslogin Is Enabled for a Project",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.5 — Ensure serial port access is disabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        serial_enabled = any(
            i.key == "serial-port-enable" and i.value.lower() == "true"
            for i in (inst.metadata.items or []) if inst.metadata
        )
        results.append(make_result(
            cis_id="4.5", check_id="gcp_cis_4_5",
            title="Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
            service="compute", severity="medium",
            status="FAIL" if serial_enabled else "PASS",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': serial port={serial_enabled}",
            remediation="Disable serial port access on the instance.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.5", check_id="gcp_cis_4_5",
            title="Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.6 — Ensure IP forwarding is not enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        fwd = inst.can_ip_forward
        results.append(make_result(
            cis_id="4.6", check_id="gcp_cis_4_6",
            title="Ensure That IP Forwarding Is Not Enabled on Instances",
            service="compute", severity="medium",
            status="FAIL" if fwd else "PASS",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': IP forwarding={fwd}",
            remediation="Disable IP forwarding unless needed for routing appliances.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.6", check_id="gcp_cis_4_6",
            title="Ensure That IP Forwarding Is Not Enabled on Instances",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.7 — Ensure VM disks are encrypted with CSEK/CMEK
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        all_cmek = all(
            (d.disk_encryption_key and d.disk_encryption_key.kms_key_name)
            for d in (inst.disks or [])
        )
        results.append(make_result(
            cis_id="4.7", check_id="gcp_cis_4_7",
            title="Ensure VM Disks Are Encrypted With Customer-Supplied Encryption Keys (CSEK)",
            service="compute", severity="medium",
            status="PASS" if all_cmek else "FAIL",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': all disks CMEK={all_cmek}",
            remediation="Use CMEK or CSEK for disk encryption.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.7", check_id="gcp_cis_4_7",
            title="Ensure VM Disks Are Encrypted With Customer-Supplied Encryption Keys (CSEK)",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.8 — Ensure Shielded VM is enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_8(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        sc = inst.shielded_instance_config
        shielded = (
            sc and sc.enable_secure_boot and sc.enable_vtpm
            and sc.enable_integrity_monitoring
        ) if sc else False
        results.append(make_result(
            cis_id="4.8", check_id="gcp_cis_4_8",
            title="Ensure Compute Instances Are Launched With Shielded VM Enabled",
            service="compute", severity="medium",
            status="PASS" if shielded else "FAIL",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': Shielded VM={shielded}",
            remediation="Enable Secure Boot, vTPM, and Integrity Monitoring.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.8", check_id="gcp_cis_4_8",
            title="Ensure Compute Instances Are Launched With Shielded VM Enabled",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.9 — Ensure instances do not have public IP addresses
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_9(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        ext_ip = any(
            ac.nat_i_p
            for ni in (inst.network_interfaces or [])
            for ac in (ni.access_configs or [])
        )
        results.append(make_result(
            cis_id="4.9", check_id="gcp_cis_4_9",
            title="Ensure That Compute Instances Do Not Have Public IP Addresses",
            service="compute", severity="medium",
            status="FAIL" if ext_ip else "PASS",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': external IP={ext_ip}",
            remediation="Remove external IPs; use IAP or Cloud NAT for outbound access.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.9", check_id="gcp_cis_4_9",
            title="Ensure That Compute Instances Do Not Have Public IP Addresses",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.10 — Ensure App Engine applications enforce HTTPS (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_10(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.10", "gcp_cis_4_10",
        "Ensure That App Engine Applications Enforce HTTPS Connections",
        "compute", "high", cfg.project_id,
        "Requires verifying App Engine dispatch.yaml and handler settings for HTTPS enforcement.")]


# ═══════════════════════════════════════════════════════════════
# 4.11 — Ensure Confidential Computing is enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_11(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        cc = inst.confidential_instance_config
        enabled = cc and cc.enable_confidential_compute if cc else False
        results.append(make_result(
            cis_id="4.11", check_id="gcp_cis_4_11",
            title="Ensure That Compute Instances Have Confidential Computing Enabled",
            service="compute", severity="low",
            status="PASS" if enabled else "FAIL",
            resource_id=rid, resource_name=inst.name, region=zn,
            status_extended=f"Instance '{inst.name}': Confidential Computing={enabled}",
            remediation="Enable Confidential Computing on the instance.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="4.11", check_id="gcp_cis_4_11",
            title="Ensure That Compute Instances Have Confidential Computing Enabled",
            service="compute", severity="low", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.12 — Ensure latest OS updates are installed (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_12(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.12", "gcp_cis_4_12",
        "Ensure the Latest OS Patches Are Installed on All Instances",
        "compute", "medium", cfg.project_id,
        "Requires OS-level verification or OS Patch Management review.")]
