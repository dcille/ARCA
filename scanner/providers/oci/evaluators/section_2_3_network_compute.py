"""CIS OCI v3.1 Section 2 — Networking (8 controls) + Section 3 — Compute (3 controls).

Section 2 Automated: 2.1, 2.2, 2.3, 2.4, 2.5
Section 2 Manual:    2.6, 2.7, 2.8
Section 3 Automated: 3.1, 3.2, 3.3
"""
from __future__ import annotations
from .base import (OCIClientCache, EvalConfig, make_result, make_manual_result, logger)


# ═════════════════════════════════════════════════════════════════
# Section 2: Networking
# ═════════════════════════════════════════════════════════════════

def _check_security_list_port(clients, cfg, port, cis_id, title):
    """Check that no security list allows 0.0.0.0/0 ingress on *port*."""
    results = []
    for cid in cfg.compartment_ids:
        try:
            sls = clients.vcn.list_security_lists(cid).data
            for sl in sls:
                for rule in (sl.ingress_security_rules or []):
                    src = getattr(rule, 'source', '')
                    if src != '0.0.0.0/0':
                        continue
                    tcp = getattr(rule, 'tcp_options', None)
                    if tcp:
                        dst = getattr(tcp, 'destination_port_range', None)
                        if dst and getattr(dst, 'min', 0) <= port <= getattr(dst, 'max', 0):
                            results.append(make_result(cis_id, title,
                                sl.id, sl.display_name, False,
                                f"Security list '{sl.display_name}' allows 0.0.0.0/0 on port {port}",
                                severity="high", service="Networking",
                                remediation=f"Restrict port {port} to specific CIDR ranges"))
        except Exception as e:
            logger.warning(f"SL check {cis_id} compartment {cid}: {e}")
    if not results:
        results.append(make_result(cis_id, title,
            cfg.tenancy_id, "All Security Lists", True,
            f"No security lists allow unrestricted access on port {port}",
            severity="high", service="Networking"))
    return results


def evaluate_2_1(clients, cfg):
    return _check_security_list_port(clients, cfg, 22, "2.1",
        "No security lists allow ingress from 0.0.0.0/0 to port 22")

def evaluate_2_2(clients, cfg):
    return _check_security_list_port(clients, cfg, 3389, "2.2",
        "No security lists allow ingress from 0.0.0.0/0 to port 3389")


def _check_nsg_port(clients, cfg, port, cis_id, title):
    """Check that no NSG allows 0.0.0.0/0 ingress on *port*."""
    results = []
    for cid in cfg.compartment_ids:
        try:
            nsgs = clients.vcn.list_network_security_groups(cid).data
            for nsg in nsgs:
                rules = clients.vcn.list_network_security_group_security_rules(
                    nsg.id, direction="INGRESS").data
                for rule in rules:
                    src = getattr(rule, 'source', '')
                    if src != '0.0.0.0/0':
                        continue
                    tcp = getattr(rule, 'tcp_options', None)
                    if tcp:
                        dst = getattr(tcp, 'destination_port_range', None)
                        if dst and getattr(dst, 'min', 0) <= port <= getattr(dst, 'max', 0):
                            results.append(make_result(cis_id, title,
                                nsg.id, nsg.display_name, False,
                                f"NSG '{nsg.display_name}' allows 0.0.0.0/0 on port {port}",
                                severity="high", service="Networking",
                                remediation=f"Restrict port {port} to specific CIDR ranges in NSG rules"))
        except Exception as e:
            logger.warning(f"NSG check {cis_id} compartment {cid}: {e}")
    if not results:
        results.append(make_result(cis_id, title,
            cfg.tenancy_id, "All NSGs", True,
            f"No NSGs allow unrestricted access on port {port}",
            severity="high", service="Networking"))
    return results


def evaluate_2_3(clients, cfg):
    return _check_nsg_port(clients, cfg, 22, "2.3",
        "No network security groups allow ingress from 0.0.0.0/0 to port 22")

def evaluate_2_4(clients, cfg):
    return _check_nsg_port(clients, cfg, 3389, "2.4",
        "No network security groups allow ingress from 0.0.0.0/0 to port 3389")


# ── 2.5 Default security list restricts all traffic except ICMP (Automated) ──

def evaluate_2_5(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in cfg.compartment_ids:
        try:
            sls = clients.vcn.list_security_lists(cid).data
            for sl in sls:
                if "Default Security List" not in (sl.display_name or ""):
                    continue
                has_unrestricted = False
                for rule in (sl.ingress_security_rules or []):
                    if getattr(rule, 'source', '') == '0.0.0.0/0':
                        if getattr(rule, 'protocol', '') != '1':  # 1 = ICMP
                            has_unrestricted = True
                            break
                results.append(make_result("2.5",
                    "Default security list of every VCN restricts all traffic except ICMP",
                    sl.id, sl.display_name, not has_unrestricted,
                    severity="high", service="Networking",
                    remediation="Modify default security list to restrict all ingress except ICMP within VCN"))
        except Exception as e:
            logger.warning(f"Default SL check compartment {cid}: {e}")
    return results


# ── 2.6, 2.7, 2.8 — Manual controls ──

def evaluate_2_6(clients, cfg):
    return [make_manual_result("2.6",
        "Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources",
        service="Networking", severity="medium")]

def evaluate_2_7(clients, cfg):
    return [make_manual_result("2.7",
        "Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within VCN",
        service="Networking", severity="medium")]

def evaluate_2_8(clients, cfg):
    return [make_manual_result("2.8",
        "Ensure Oracle Autonomous Shared Databases access is restricted or deployed within VCN",
        service="Networking", severity="medium")]


# ═════════════════════════════════════════════════════════════════
# Section 3: Compute
# ═════════════════════════════════════════════════════════════════

# ── 3.1 Legacy IMDS v1 endpoint disabled (Automated) ──

def evaluate_3_1(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in cfg.compartment_ids:
        try:
            instances = clients.compute.list_instances(cid).data
            for inst in instances:
                if inst.lifecycle_state != "RUNNING":
                    continue
                opts = getattr(inst, 'instance_options', None)
                v1_disabled = opts and getattr(opts, 'are_legacy_imds_endpoints_disabled', False)
                results.append(make_result("3.1",
                    "Compute Instance Legacy Metadata service endpoint is disabled",
                    inst.id, inst.display_name, v1_disabled,
                    f"Instance '{inst.display_name}': legacy IMDS {'disabled' if v1_disabled else 'ENABLED'}",
                    severity="high", service="Compute",
                    remediation="Disable legacy IMDS v1 endpoints to prevent SSRF attacks"))
        except Exception as e:
            logger.warning(f"Compute IMDS check compartment {cid}: {e}")
    return results


# ── 3.2 Secure Boot enabled (Automated) ──

def evaluate_3_2(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in cfg.compartment_ids:
        try:
            instances = clients.compute.list_instances(cid).data
            for inst in instances:
                if inst.lifecycle_state != "RUNNING":
                    continue
                lo = getattr(inst, 'launch_options', None)
                secure_boot = lo and getattr(lo, 'is_secure_boot_enabled', False)
                results.append(make_result("3.2",
                    "Secure Boot is enabled on Compute Instance",
                    inst.id, inst.display_name, secure_boot,
                    severity="medium", service="Compute",
                    remediation="Enable Secure Boot in instance launch options"))
        except Exception as e:
            logger.warning(f"Secure boot check compartment {cid}: {e}")
    return results


# ── 3.3 In-transit encryption enabled (Automated) ──

def evaluate_3_3(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in cfg.compartment_ids:
        try:
            instances = clients.compute.list_instances(cid).data
            for inst in instances:
                if inst.lifecycle_state != "RUNNING":
                    continue
                lo = getattr(inst, 'launch_options', None)
                transit_enc = lo and getattr(lo, 'is_pv_encryption_in_transit_enabled', False)
                results.append(make_result("3.3",
                    "In-transit Encryption is enabled on Compute Instance",
                    inst.id, inst.display_name, transit_enc,
                    severity="medium", service="Compute",
                    remediation="Enable in-transit encryption for boot/block volumes"))
        except Exception as e:
            logger.warning(f"Transit encryption check compartment {cid}: {e}")
    return results


SECTION_2_EVALUATORS = {
    "2.1": evaluate_2_1, "2.2": evaluate_2_2, "2.3": evaluate_2_3,
    "2.4": evaluate_2_4, "2.5": evaluate_2_5, "2.6": evaluate_2_6,
    "2.7": evaluate_2_7, "2.8": evaluate_2_8,
}

SECTION_3_EVALUATORS = {
    "3.1": evaluate_3_1, "3.2": evaluate_3_2, "3.3": evaluate_3_3,
}
