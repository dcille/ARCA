"""CIS GCP v4.0 Section 4: Virtual Machines — 12 controls."""
import logging
from .base import GCPClientCache, EvalConfig, make_result, make_manual_result
logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]

def _iter_instances(c, cfg):
    """Yield (instance, zone_name, resource_id) for all instances."""
    try:
        for zone, resp in c.compute_instances.aggregated_list(project=cfg.project_id):
            for inst in (resp.instances or []):
                zn = zone.split("/")[-1]
                rid = f"projects/{cfg.project_id}/zones/{zn}/instances/{inst.name}"
                yield inst, zn, rid
    except Exception as e:
        logger.warning("Could not list instances: %s", e)

def evaluate_cis_4_1(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        default = any(sa.email.endswith("-compute@developer.gserviceaccount.com") for sa in (inst.service_accounts or []))
        results.append(make_result(cis_id="4.1",check_id="gcp_cis_4_1",title="Ensure instances do not use default service account",service="compute",severity="high",status="FAIL" if default else "PASS",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: default SA = {default}",remediation="Use a custom SA with minimum permissions.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_2(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        full = any("https://www.googleapis.com/auth/cloud-platform" in (sa.scopes or []) for sa in (inst.service_accounts or []))
        results.append(make_result(cis_id="4.2",check_id="gcp_cis_4_2",title="Ensure instances do not use default SA with full API access",service="compute",severity="high",status="FAIL" if full else "PASS",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: full API scope = {full}",remediation="Use minimum necessary API scopes.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_3(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        blocked = any(i.key=="block-project-ssh-keys" and i.value.lower()=="true" for i in (inst.metadata.items or []) if inst.metadata)
        results.append(make_result(cis_id="4.3",check_id="gcp_cis_4_3",title="Ensure Block Project-Wide SSH Keys is enabled",service="compute",severity="medium",status="PASS" if blocked else "FAIL",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: block project SSH = {blocked}",remediation="Set block-project-ssh-keys to true.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_4(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        oslogin = any(i.key=="enable-oslogin" and i.value.lower()=="true" for i in (inst.metadata.items or []) if inst.metadata)
        results.append(make_result(cis_id="4.4",check_id="gcp_cis_4_4",title="Ensure OS Login is enabled",service="compute",severity="medium",status="PASS" if oslogin else "FAIL",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: OS Login = {oslogin}",remediation="Enable OS Login for centralized SSH management.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_5(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        serial = any(i.key=="serial-port-enable" and i.value.lower()=="true" for i in (inst.metadata.items or []) if inst.metadata)
        results.append(make_result(cis_id="4.5",check_id="gcp_cis_4_5",title="Ensure Enable Connecting to Serial Ports is not enabled",service="compute",severity="medium",status="FAIL" if serial else "PASS",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: serial port = {serial}",remediation="Disable serial port access.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_6(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        fwd = inst.can_ip_forward
        results.append(make_result(cis_id="4.6",check_id="gcp_cis_4_6",title="Ensure IP forwarding is not enabled on instances",service="compute",severity="medium",status="FAIL" if fwd else "PASS",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: IP forwarding = {fwd}",remediation="Disable IP forwarding unless needed for routing.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_7(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        all_cmek = all((d.disk_encryption_key and d.disk_encryption_key.kms_key_name) for d in (inst.disks or []))
        results.append(make_result(cis_id="4.7",check_id="gcp_cis_4_7",title="Ensure VM disks are encrypted with CSEK/CMEK",service="compute",severity="medium",status="PASS" if all_cmek else "FAIL",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: all disks CMEK = {all_cmek}",remediation="Use CMEK for disk encryption.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_8(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        sc = inst.shielded_instance_config
        shielded = sc and sc.enable_secure_boot and sc.enable_vtpm and sc.enable_integrity_monitoring if sc else False
        results.append(make_result(cis_id="4.8",check_id="gcp_cis_4_8",title="Ensure Shielded VM is enabled",service="compute",severity="medium",status="PASS" if shielded else "FAIL",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: Shielded VM = {shielded}",remediation="Enable Secure Boot, vTPM, and Integrity Monitoring.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_9(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        ext_ip = any(ac.nat_i_p for ni in (inst.network_interfaces or []) for ac in (ni.access_configs or []))
        results.append(make_result(cis_id="4.9",check_id="gcp_cis_4_9",title="Ensure instances do not have public IP addresses",service="compute",severity="medium",status="FAIL" if ext_ip else "PASS",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: external IP = {ext_ip}",remediation="Remove external IPs; use IAP or Cloud NAT.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_10(c, cfg):
    return [make_manual_result("4.10","gcp_cis_4_10","Ensure App Engine applications enforce HTTPS","compute","high",cfg.project_id,"Requires verifying App Engine dispatch.yaml and handler settings.")]

def evaluate_cis_4_11(c, cfg):
    results = []
    for inst, zn, rid in _iter_instances(c, cfg):
        cc = inst.confidential_instance_config
        enabled = cc and cc.enable_confidential_compute if cc else False
        results.append(make_result(cis_id="4.11",check_id="gcp_cis_4_11",title="Ensure Confidential Computing is enabled",service="compute",severity="low",status="PASS" if enabled else "FAIL",resource_id=rid,resource_name=inst.name,region=zn,status_extended=f"Instance {inst.name}: Confidential Computing = {enabled}",remediation="Enable Confidential Computing.",compliance_frameworks=FW))
    return results

def evaluate_cis_4_12(c, cfg):
    return [make_manual_result("4.12","gcp_cis_4_12","Ensure latest OS updates are installed","compute","medium",cfg.project_id,"Requires OS-level verification or OS Patch Management review.")]
