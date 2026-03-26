"""CIS GCP v4.0 Section 3: Networking — 10 controls."""
import logging
from .base import GCPClientCache, EvalConfig, make_result, make_manual_result
logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]

def evaluate_cis_3_1(c, cfg):
    try:
        has_default = any(n.name == "default" for n in c.compute_networks.list(project=cfg.project_id))
        return [make_result(cis_id="3.1",check_id="gcp_cis_3_1",title="Ensure default network does not exist",service="networking",severity="medium",status="FAIL" if has_default else "PASS",resource_id=f"projects/{cfg.project_id}",status_extended=f"Default network exists: {has_default}",remediation="Delete the default network and create custom VPCs.",compliance_frameworks=FW)]
    except Exception:
        return []

def evaluate_cis_3_2(c, cfg):
    try:
        legacy = any(hasattr(n,'i_pv4_range') and n.i_pv4_range for n in c.compute_networks.list(project=cfg.project_id))
        return [make_result(cis_id="3.2",check_id="gcp_cis_3_2",title="Ensure legacy networks do not exist",service="networking",severity="medium",status="FAIL" if legacy else "PASS",resource_id=f"projects/{cfg.project_id}",status_extended=f"Legacy network found: {legacy}",remediation="Delete legacy networks; use VPC networks.",compliance_frameworks=FW)]
    except Exception:
        return []

def evaluate_cis_3_3(c, cfg):
    results = []
    try:
        svc = c.api_service("dns","v1")
        zones = svc.managedZones().list(project=cfg.project_id).execute()
        for z in zones.get("managedZones",[]):
            if z.get("visibility","public") != "public": continue
            on = z.get("dnssecConfig",{}).get("state","off") == "on"
            results.append(make_result(cis_id="3.3",check_id="gcp_cis_3_3",title="Ensure DNSSEC is enabled for Cloud DNS",service="networking",severity="medium",status="PASS" if on else "FAIL",resource_id=z.get("id",z.get("name","")),resource_name=z.get("name",""),status_extended=f"Zone {z['name']}: DNSSEC = {on}",remediation="Enable DNSSEC on public zones.",compliance_frameworks=FW))
    except Exception: pass
    return results

def _check_dnssec_algo(c, cfg, cis_id, key_type):
    results = []
    try:
        svc = c.api_service("dns","v1")
        zones = svc.managedZones().list(project=cfg.project_id).execute()
        for z in zones.get("managedZones",[]):
            if z.get("visibility","public") != "public": continue
            specs = z.get("dnssecConfig",{}).get("defaultKeySpecs",[])
            for spec in specs:
                if spec.get("keyType") == key_type and spec.get("algorithm") == "RSASHA1":
                    results.append(make_result(cis_id=cis_id,check_id=f"gcp_cis_{cis_id.replace('.','_')}",title=f"Ensure RSASHA1 is not used for {key_type}",service="networking",severity="high",status="FAIL",resource_id=z.get("id",""),resource_name=z.get("name",""),status_extended=f"Zone {z['name']} uses RSASHA1 for {key_type}",remediation="Use RSASHA256+ or ECDSAP256SHA256.",compliance_frameworks=FW))
    except Exception: pass
    return results

def evaluate_cis_3_4(c, cfg): return _check_dnssec_algo(c, cfg, "3.4", "keySigning")
def evaluate_cis_3_5(c, cfg): return _check_dnssec_algo(c, cfg, "3.5", "zoneSigning")

def _check_firewall_port(c, cfg, cis_id, port, name):
    results = []
    try:
        for fw in c.compute_firewalls.list(project=cfg.project_id):
            if fw.direction != "INGRESS": continue
            if "0.0.0.0/0" not in (fw.source_ranges or []): continue
            for allowed in (fw.allowed or []):
                if str(port) in (allowed.ports or []) or not allowed.ports:
                    results.append(make_result(cis_id=cis_id,check_id=f"gcp_cis_{cis_id.replace('.','_')}",title=f"Ensure {name} access is restricted from Internet",service="networking",severity="critical",status="FAIL",resource_id=fw.self_link or fw.name,resource_name=fw.name,status_extended=f"Firewall {fw.name} allows 0.0.0.0/0 on port {port}",remediation=f"Restrict port {port} to specific CIDRs.",compliance_frameworks=FW))
    except Exception: pass
    return results

def evaluate_cis_3_6(c, cfg): return _check_firewall_port(c, cfg, "3.6", 22, "SSH")
def evaluate_cis_3_7(c, cfg): return _check_firewall_port(c, cfg, "3.7", 3389, "RDP")

def evaluate_cis_3_8(c, cfg):
    results = []
    try:
        for region, resp in c.compute_subnets.aggregated_list(project=cfg.project_id):
            for sub in (resp.subnetworks or []):
                flow = sub.log_config and sub.log_config.enable
                results.append(make_result(cis_id="3.8",check_id="gcp_cis_3_8",title="Ensure VPC Flow Logs is enabled for every subnet",service="networking",severity="medium",status="PASS" if flow else "FAIL",resource_id=sub.self_link or sub.name,resource_name=sub.name,status_extended=f"Subnet {sub.name}: flow logs = {flow}",remediation="Enable VPC Flow Logs on all subnets.",compliance_frameworks=FW))
    except Exception: pass
    return results

def evaluate_cis_3_9(c, cfg):
    return [make_manual_result("3.9","gcp_cis_3_9","Ensure no HTTPS/SSL proxy LBs permit weak SSL policies","networking","high",cfg.project_id,"Requires reviewing SSL policies on HTTPS/SSL proxy load balancers.")]

def evaluate_cis_3_10(c, cfg):
    return [make_manual_result("3.10","gcp_cis_3_10","Use Identity Aware Proxy to ensure only authorized traffic","networking","medium",cfg.project_id,"Requires verifying IAP configuration on relevant backends.")]
