"""CIS GCP v4.0 Section 4: Virtual Machines — 12 controls.

Coverage:
  4.1  Ensure instances don't use default SA     automated
  4.2  Ensure instances don't use default SA with full access  automated
  4.3  Ensure 'Block Project-Wide SSH Keys' enabled  automated
  4.4  Ensure OS Login is enabled                  automated
  4.5  Ensure 'Enable Connecting to Serial Ports' disabled  automated
  4.6  Ensure IP forwarding not enabled on instances  automated
  4.7  Ensure VM disks are encrypted with CMEK     automated
  4.8  Ensure Compute instances are launched with Shielded VM  automated
  4.9  Ensure that Compute instances do not have public IP  automated
  4.10 Ensure App Engine applications enforce HTTPS  manual
  4.11 Ensure Compute instances have Confidential Computing  automated
  4.12 Ensure that all GCE VMs use a custom metadata server  manual
"""

import logging

from .base import GCPClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]

_DEFAULT_SA_SUFFIXES = (
    "-compute@developer.gserviceaccount.com",
    "@appspot.gserviceaccount.com",
)


def _iter_instances(c: GCPClientCache, cfg: EvalConfig):
    """Yield all instances across all zones."""
    try:
        agg = c.compute_instances.aggregated_list(request={"project": cfg.project_id})
        for zone_key, scoped in agg:
            for instance in getattr(scoped, "instances", []) or []:
                yield instance
    except Exception as e:
        logger.warning("Error listing instances: %s", e)


# ═══════════════════════════════════════════════════════════════
# 4.1 — Instances don't use default SA
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        sa_list = list(inst.service_accounts) if inst.service_accounts else []
        uses_default = any(
            any(sa.email.endswith(suffix) for suffix in _DEFAULT_SA_SUFFIXES)
            for sa in sa_list
        )
        results.append(make_result(
            cis_id="4.1", check_id="gcp_cis_4_1",
            title="Ensure That Instances Are Not Configured To Use Default Service Accounts",
            service="compute", severity="medium",
            status="FAIL" if uses_default else "PASS",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=(
                f"Instance '{inst.name}' uses default service account"
                if uses_default else f"Instance '{inst.name}' uses custom service account"
            ),
            remediation="Create and assign a custom service account to the instance.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.1", check_id="gcp_cis_4_1",
            title="Ensure Instances Don't Use Default Service Accounts",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.2 — Instances don't use default SA with full API access
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        sa_list = list(inst.service_accounts) if inst.service_accounts else []
        has_full_access = False
        for sa in sa_list:
            if any(sa.email.endswith(s) for s in _DEFAULT_SA_SUFFIXES):
                scopes = list(sa.scopes) if sa.scopes else []
                if "https://www.googleapis.com/auth/cloud-platform" in scopes:
                    has_full_access = True
                    break
        results.append(make_result(
            cis_id="4.2", check_id="gcp_cis_4_2",
            title="Ensure That Instances Are Not Configured To Use Default SA With Full Access to Cloud APIs",
            service="compute", severity="high",
            status="FAIL" if has_full_access else "PASS",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=(
                f"Instance '{inst.name}' default SA has full cloud-platform scope"
                if has_full_access else f"Instance '{inst.name}' OK"
            ),
            remediation="Remove cloud-platform scope; use least-privilege scopes.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.2", check_id="gcp_cis_4_2",
            title="Ensure Default SA Not Used With Full Access",
            service="compute", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.3 — Block project-wide SSH keys enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        metadata_items = {
            item.key: item.value
            for item in (inst.metadata.items_ if inst.metadata and inst.metadata.items_ else [])
        }
        block_keys = metadata_items.get("block-project-ssh-keys", "").lower() == "true"
        results.append(make_result(
            cis_id="4.3", check_id="gcp_cis_4_3",
            title="Ensure 'Block Project-Wide SSH Keys' Is Enabled for VM Instances",
            service="compute", severity="medium",
            status="PASS" if block_keys else "FAIL",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=f"Instance '{inst.name}': block-project-ssh-keys={block_keys}",
            remediation="Set block-project-ssh-keys=TRUE in instance metadata.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.3", check_id="gcp_cis_4_3",
            title="Ensure Block Project-Wide SSH Keys Enabled",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.4 — OS Login enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        project_info = c.compute_projects.get(request={"project": cfg.project_id})
        project_metadata = {
            item.key: item.value
            for item in (project_info.common_instance_metadata.items_
                         if project_info.common_instance_metadata
                         and project_info.common_instance_metadata.items_ else [])
        }
        os_login = project_metadata.get("enable-oslogin", "").lower() == "true"
    except Exception:
        os_login = False

    return [make_result(
        cis_id="4.4", check_id="gcp_cis_4_4",
        title="Ensure OS Login Is Enabled for a Project",
        service="compute", severity="medium",
        status="PASS" if os_login else "FAIL",
        resource_id=cfg.project_id,
        status_extended=f"Project enable-oslogin={os_login}",
        remediation="Enable OS Login: gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 4.5 — Serial port access disabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        metadata_items = {
            item.key: item.value
            for item in (inst.metadata.items_ if inst.metadata and inst.metadata.items_ else [])
        }
        serial = metadata_items.get("serial-port-enable", "").lower() == "true"
        results.append(make_result(
            cis_id="4.5", check_id="gcp_cis_4_5",
            title="Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
            service="compute", severity="medium",
            status="FAIL" if serial else "PASS",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=f"Instance '{inst.name}': serial-port-enable={serial}",
            remediation="Disable serial port: set serial-port-enable=false in instance metadata.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.5", check_id="gcp_cis_4_5",
            title="Ensure Serial Ports Disabled",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.6 — IP forwarding disabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        fwd = getattr(inst, "can_ip_forward", False)
        results.append(make_result(
            cis_id="4.6", check_id="gcp_cis_4_6",
            title="Ensure That IP Forwarding Is Not Enabled on Instances",
            service="compute", severity="medium",
            status="FAIL" if fwd else "PASS",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=f"Instance '{inst.name}': canIpForward={fwd}",
            remediation="Disable IP forwarding unless required for NAT/routing.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.6", check_id="gcp_cis_4_6",
            title="Ensure IP Forwarding Disabled",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.7 — VM disks encrypted with CMEK
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        disks = list(inst.disks) if inst.disks else []
        all_cmek = True
        for disk in disks:
            enc = getattr(disk, "disk_encryption_key", None)
            if not enc or not getattr(enc, "kms_key_name", None):
                all_cmek = False
                break
        results.append(make_result(
            cis_id="4.7", check_id="gcp_cis_4_7",
            title="Ensure VM Disks Are Encrypted With Customer-Managed Encryption Keys (CMEK)",
            service="compute", severity="medium",
            status="PASS" if all_cmek else "FAIL",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=(
                f"Instance '{inst.name}': all disks CMEK encrypted"
                if all_cmek else f"Instance '{inst.name}': not all disks use CMEK"
            ),
            remediation="Re-create disks with CMEK encryption using Cloud KMS keys.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.7", check_id="gcp_cis_4_7",
            title="Ensure VM Disks Use CMEK",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.8 — Shielded VM enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_8(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        shielded = getattr(inst, "shielded_instance_config", None)
        vtpm = shielded and getattr(shielded, "enable_vtpm", False)
        integrity = shielded and getattr(shielded, "enable_integrity_monitoring", False)
        ok = vtpm and integrity
        results.append(make_result(
            cis_id="4.8", check_id="gcp_cis_4_8",
            title="Ensure Compute Instances Are Launched With Shielded VM Enabled",
            service="compute", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=f"Instance '{inst.name}': vTPM={vtpm}, integrityMonitoring={integrity}",
            remediation="Enable Shielded VM features (vTPM and integrity monitoring).",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.8", check_id="gcp_cis_4_8",
            title="Ensure Shielded VM Enabled",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.9 — No public IP on instances
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_9(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        has_public = False
        for iface in (inst.network_interfaces or []):
            for ac in (iface.access_configs or []):
                if getattr(ac, "nat_i_p", None):
                    has_public = True
                    break
        results.append(make_result(
            cis_id="4.9", check_id="gcp_cis_4_9",
            title="Ensure That Compute Instances Do Not Have Public IP Addresses",
            service="compute", severity="high",
            status="FAIL" if has_public else "PASS",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=(
                f"Instance '{inst.name}' has a public IP"
                if has_public else f"Instance '{inst.name}' has no public IP"
            ),
            remediation="Remove external IP; use IAP or Cloud NAT for egress.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.9", check_id="gcp_cis_4_9",
            title="Ensure No Public IP on Instances",
            service="compute", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.10 — App Engine HTTPS enforcement (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_10(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.10", "gcp_cis_4_10",
        "Ensure That App Engine Applications Enforce HTTPS Connections",
        "compute", "medium", cfg.project_id,
        "Verify App Engine app.yaml has 'secure: always' for all handlers.")]


# ═══════════════════════════════════════════════════════════════
# 4.11 — Confidential Computing enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_11(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _iter_instances(c, cfg):
        cc = getattr(inst, "confidential_instance_config", None)
        enabled = cc and getattr(cc, "enable_confidential_compute", False)
        results.append(make_result(
            cis_id="4.11", check_id="gcp_cis_4_11",
            title="Ensure That Compute Instances Have Confidential Computing Enabled",
            service="compute", severity="medium",
            status="PASS" if enabled else "FAIL",
            resource_id=inst.self_link or inst.name,
            resource_name=inst.name,
            region=getattr(inst, "zone", "").split("/")[-1],
            status_extended=f"Instance '{inst.name}': confidential computing={enabled}",
            remediation="Enable Confidential Computing (requires N2D machine type).",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="4.11", check_id="gcp_cis_4_11",
            title="Ensure Confidential Computing Enabled",
            service="compute", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No compute instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 4.12 — Custom metadata server (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_12(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.12", "gcp_cis_4_12",
        "Ensure That All GCE VMs Use A Custom Metadata Server",
        "compute", "medium", cfg.project_id,
        "Requires verifying instance metadata server configuration and organization policies.")]
