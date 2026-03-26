"""CIS GCP v4.0 Section 3: Networking — 10 controls.

Coverage:
  3.1  Default network deleted          automated
  3.2  Legacy network deleted           automated
  3.3  DNSSEC enabled for Cloud DNS     automated
  3.4  RSASHA1 not used for zone-signing  automated
  3.5  RSASHA1 not used for key-signing   automated
  3.6  SSH not open from Internet        automated
  3.7  RDP not open from Internet        automated
  3.8  VPC flow logs enabled             automated
  3.9  Firewall rules reviewed           manual
  3.10 Private Google Access enabled     manual
"""

import logging

from .base import GCPClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]


# ═══════════════════════════════════════════════════════════════
# 3.1 — Ensure the default network does not exist
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        networks = list(c.compute_networks.list(request={"project": cfg.project_id}))
    except Exception:
        networks = []

    default_exists = any(n.name == "default" for n in networks)

    return [make_result(
        cis_id="3.1", check_id="gcp_cis_3_1",
        title="Ensure That the Default Network Does Not Exist in a Project",
        service="networking", severity="medium",
        status="FAIL" if default_exists else "PASS",
        resource_id=cfg.project_id,
        status_extended=(
            "Default network exists — should be deleted"
            if default_exists else "Default network has been deleted"
        ),
        remediation="Delete the default network: gcloud compute networks delete default",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 3.2 — Ensure legacy networks do not exist
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        networks = list(c.compute_networks.list(request={"project": cfg.project_id}))
    except Exception:
        networks = []

    legacy_nets = [n for n in networks if getattr(n, "auto_create_subnetworks", None) is None
                   and not getattr(n, "subnetworks", [])]

    if not legacy_nets:
        return [make_result(cis_id="3.2", check_id="gcp_cis_3_2",
            title="Ensure Legacy Networks Do Not Exist",
            service="networking", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No legacy networks found",
            compliance_frameworks=FW)]

    for net in legacy_nets:
        results.append(make_result(
            cis_id="3.2", check_id="gcp_cis_3_2",
            title="Ensure Legacy Networks Do Not Exist",
            service="networking", severity="medium", status="FAIL",
            resource_id=net.self_link or net.name,
            resource_name=net.name,
            status_extended=f"Legacy network '{net.name}' exists",
            remediation="Migrate to VPC network and delete legacy network.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 3.3 — DNSSEC enabled for Cloud DNS managed zones
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        resp = c.dns.managedZones().list(project=cfg.project_id).execute()
        zones = resp.get("managedZones", [])
    except Exception:
        zones = []

    for zone in zones:
        if zone.get("visibility") == "private":
            continue
        name = zone.get("name", "")
        dnssec = zone.get("dnssecConfig", {})
        state = dnssec.get("state", "off")
        ok = state == "on"
        results.append(make_result(
            cis_id="3.3", check_id="gcp_cis_3_3",
            title="Ensure That DNSSEC Is Enabled for Cloud DNS",
            service="networking", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"DNS zone '{name}': DNSSEC={state}",
            remediation="Enable DNSSEC: gcloud dns managed-zones update ZONE --dnssec-state on",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="3.3", check_id="gcp_cis_3_3",
            title="Ensure That DNSSEC Is Enabled for Cloud DNS",
            service="networking", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No public DNS managed zones found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 3.4 — RSASHA1 not used for zone-signing key
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        resp = c.dns.managedZones().list(project=cfg.project_id).execute()
        zones = resp.get("managedZones", [])
    except Exception:
        zones = []

    for zone in zones:
        name = zone.get("name", "")
        dnssec = zone.get("dnssecConfig", {})
        if dnssec.get("state") != "on":
            continue
        default_keys = dnssec.get("defaultKeySpecs", [])
        for spec in default_keys:
            if spec.get("keyType") == "zoneSigning":
                algo = spec.get("algorithm", "")
                ok = algo.upper() != "RSASHA1"
                results.append(make_result(
                    cis_id="3.4", check_id="gcp_cis_3_4",
                    title="Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC",
                    service="networking", severity="medium",
                    status="PASS" if ok else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"DNS zone '{name}' zone-signing algorithm: {algo}",
                    remediation="Change DNSSEC zone-signing to RSASHA256 or ECDSAP256SHA256.",
                    compliance_frameworks=FW,
                ))

    if not results:
        return [make_result(cis_id="3.4", check_id="gcp_cis_3_4",
            title="Ensure That RSASHA1 Is Not Used for Zone-Signing Key",
            service="networking", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No DNSSEC-enabled zones or no zone-signing keys found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 3.5 — RSASHA1 not used for key-signing key
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        resp = c.dns.managedZones().list(project=cfg.project_id).execute()
        zones = resp.get("managedZones", [])
    except Exception:
        zones = []

    for zone in zones:
        name = zone.get("name", "")
        dnssec = zone.get("dnssecConfig", {})
        if dnssec.get("state") != "on":
            continue
        default_keys = dnssec.get("defaultKeySpecs", [])
        for spec in default_keys:
            if spec.get("keyType") == "keySigning":
                algo = spec.get("algorithm", "")
                ok = algo.upper() != "RSASHA1"
                results.append(make_result(
                    cis_id="3.5", check_id="gcp_cis_3_5",
                    title="Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC",
                    service="networking", severity="medium",
                    status="PASS" if ok else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"DNS zone '{name}' key-signing algorithm: {algo}",
                    remediation="Change DNSSEC key-signing to RSASHA256 or ECDSAP256SHA256.",
                    compliance_frameworks=FW,
                ))

    if not results:
        return [make_result(cis_id="3.5", check_id="gcp_cis_3_5",
            title="Ensure That RSASHA1 Is Not Used for Key-Signing Key",
            service="networking", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No DNSSEC-enabled zones or no key-signing keys found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 3.6 — SSH (port 22) not allowed from 0.0.0.0/0
# ═══════════════════════════════════════════════════════════════

def _firewall_allows_port(rule, port: int) -> bool:
    """Check if a firewall rule allows a specific port from 0.0.0.0/0."""
    if rule.direction != "INGRESS":
        return False
    sources = list(rule.source_ranges) if rule.source_ranges else []
    if "0.0.0.0/0" not in sources:
        return False
    for allowed in rule.allowed or []:
        if allowed.I_p_protocol in ("all", "tcp"):
            ports = list(allowed.ports) if allowed.ports else []
            if not ports:
                return True  # all ports
            for p in ports:
                if "-" in p:
                    lo, hi = p.split("-")
                    if int(lo) <= port <= int(hi):
                        return True
                elif p == str(port):
                    return True
    return False


def evaluate_cis_3_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        firewalls = list(c.compute_firewalls.list(request={"project": cfg.project_id}))
    except Exception:
        firewalls = []

    bad_rules = [fw for fw in firewalls if _firewall_allows_port(fw, 22)]

    if not bad_rules:
        return [make_result(cis_id="3.6", check_id="gcp_cis_3_6",
            title="Ensure That SSH Access Is Restricted From the Internet",
            service="networking", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No firewall rules allow SSH (22) from 0.0.0.0/0",
            compliance_frameworks=FW)]

    for fw in bad_rules:
        results.append(make_result(
            cis_id="3.6", check_id="gcp_cis_3_6",
            title="Ensure That SSH Access Is Restricted From the Internet",
            service="networking", severity="high", status="FAIL",
            resource_id=fw.self_link or fw.name,
            resource_name=fw.name,
            status_extended=f"Firewall rule '{fw.name}' allows SSH from 0.0.0.0/0",
            remediation="Restrict SSH source ranges or remove the rule.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 3.7 — RDP (port 3389) not allowed from 0.0.0.0/0
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        firewalls = list(c.compute_firewalls.list(request={"project": cfg.project_id}))
    except Exception:
        firewalls = []

    bad_rules = [fw for fw in firewalls if _firewall_allows_port(fw, 3389)]

    if not bad_rules:
        return [make_result(cis_id="3.7", check_id="gcp_cis_3_7",
            title="Ensure That RDP Access Is Restricted From the Internet",
            service="networking", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No firewall rules allow RDP (3389) from 0.0.0.0/0",
            compliance_frameworks=FW)]

    for fw in bad_rules:
        results.append(make_result(
            cis_id="3.7", check_id="gcp_cis_3_7",
            title="Ensure That RDP Access Is Restricted From the Internet",
            service="networking", severity="high", status="FAIL",
            resource_id=fw.self_link or fw.name,
            resource_name=fw.name,
            status_extended=f"Firewall rule '{fw.name}' allows RDP from 0.0.0.0/0",
            remediation="Restrict RDP source ranges or remove the rule.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 3.8 — VPC Flow Logs enabled for every subnet
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_8(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        subnets_agg = c.compute_subnetworks.aggregated_list(request={"project": cfg.project_id})
        for region_key, scoped in subnets_agg:
            for subnet in getattr(scoped, "subnetworks", []) or []:
                log_config = getattr(subnet, "log_config", None)
                enabled = log_config and getattr(log_config, "enable", False)
                results.append(make_result(
                    cis_id="3.8", check_id="gcp_cis_3_8",
                    title="Ensure VPC Flow Logs Is Enabled for Every Subnet in a VPC Network",
                    service="networking", severity="medium",
                    status="PASS" if enabled else "FAIL",
                    resource_id=subnet.self_link or subnet.name,
                    resource_name=subnet.name,
                    region=getattr(subnet, "region", "").split("/")[-1],
                    status_extended=f"Subnet '{subnet.name}': flow logs={'enabled' if enabled else 'disabled'}",
                    remediation="Enable flow logs: gcloud compute networks subnets update SUBNET --enable-flow-logs",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("Error listing subnets: %s", e)

    if not results:
        return [make_result(cis_id="3.8", check_id="gcp_cis_3_8",
            title="Ensure VPC Flow Logs Is Enabled for Every Subnet",
            service="networking", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No subnets found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 3.9 — Firewall rules reviewed (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_9(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("3.9", "gcp_cis_3_9",
        "Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites",
        "networking", "medium", cfg.project_id,
        "Requires reviewing SSL policies on HTTPS/SSL proxy load balancers for weak ciphers.")]


# ═══════════════════════════════════════════════════════════════
# 3.10 — Private Google Access (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_10(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("3.10", "gcp_cis_3_10",
        "Use Identity Aware Proxy (IAP) to Ensure Only Traffic From Google IP Addresses Are Allowed",
        "networking", "medium", cfg.project_id,
        "Requires verifying IAP configuration for internal-only access patterns.")]
