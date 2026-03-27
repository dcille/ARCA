"""CIS OCI v3.1 Sections 2 & 3: Networking + Compute -- 11 controls.

Coverage:
  2.1  No SL ingress 0.0.0.0/0 to port 22               automated
  2.2  No SL ingress 0.0.0.0/0 to port 3389              automated
  2.3  No NSG ingress 0.0.0.0/0 to port 22               automated
  2.4  No NSG ingress 0.0.0.0/0 to port 3389             automated
  2.5  Default SL restricts all except ICMP within VCN    automated
  2.6  OIC access restricted                              MANUAL
  2.7  OAC access restricted                              MANUAL
  2.8  ADB access restricted                              MANUAL
  3.1  Legacy IMDS endpoint disabled                      automated
  3.2  Secure Boot enabled                                automated
  3.3  In-transit encryption enabled                      automated
"""

import logging

from .base import OCIClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-OCI-3.1"]


# ═══════════════════════════════════════════════════════════════
# Helper: check security list rules for open port from 0.0.0.0/0
# ═══════════════════════════════════════════════════════════════

def _sl_has_open_port(security_list, port: int) -> bool:
    """Return True if any ingress rule allows 0.0.0.0/0 to the given port."""
    for rule in (security_list.ingress_security_rules or []):
        source = getattr(rule, "source", "")
        if source != "0.0.0.0/0":
            continue
        tcp_opts = getattr(rule, "tcp_options", None)
        if tcp_opts:
            dst = getattr(tcp_opts, "destination_port_range", None)
            if dst and getattr(dst, "min", 0) <= port <= getattr(dst, "max", 0):
                return True
        elif getattr(rule, "protocol", "") == "all":
            return True
    return False


# ═══════════════════════════════════════════════════════════════
# 2.1 -- No SL ingress 0.0.0.0/0 to port 22
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for sl in c.virtual_network.list_security_lists(cid).data:
                if _sl_has_open_port(sl, 22):
                    results.append(make_result(
                        cis_id="2.1", check_id="oci_cis_2_1",
                        title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
                        service="networking", severity="critical", status="FAIL",
                        resource_id=sl.id, resource_name=sl.display_name,
                        status_extended=f"Security list '{sl.display_name}' allows 0.0.0.0/0 on port 22",
                        remediation="Restrict SSH (port 22) to specific CIDR ranges.",
                        compliance_frameworks=FW,
                    ))
                else:
                    results.append(make_result(
                        cis_id="2.1", check_id="oci_cis_2_1",
                        title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
                        service="networking", severity="critical", status="PASS",
                        resource_id=sl.id, resource_name=sl.display_name,
                        status_extended=f"Security list '{sl.display_name}' does not allow 0.0.0.0/0 on port 22",
                        compliance_frameworks=FW,
                    ))
        except Exception as e:
            logger.warning("CIS 2.1 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="2.1", check_id="oci_cis_2_1",
        title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
        service="networking", severity="critical", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No security lists found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.2 -- No SL ingress 0.0.0.0/0 to port 3389
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_2(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for sl in c.virtual_network.list_security_lists(cid).data:
                if _sl_has_open_port(sl, 3389):
                    results.append(make_result(
                        cis_id="2.2", check_id="oci_cis_2_2",
                        title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
                        service="networking", severity="critical", status="FAIL",
                        resource_id=sl.id, resource_name=sl.display_name,
                        status_extended=f"Security list '{sl.display_name}' allows 0.0.0.0/0 on port 3389",
                        remediation="Restrict RDP (port 3389) to specific CIDR ranges.",
                        compliance_frameworks=FW,
                    ))
                else:
                    results.append(make_result(
                        cis_id="2.2", check_id="oci_cis_2_2",
                        title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
                        service="networking", severity="critical", status="PASS",
                        resource_id=sl.id, resource_name=sl.display_name,
                        status_extended=f"Security list '{sl.display_name}' does not allow 0.0.0.0/0 on port 3389",
                        compliance_frameworks=FW,
                    ))
        except Exception as e:
            logger.warning("CIS 2.2 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="2.2", check_id="oci_cis_2_2",
        title="Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
        service="networking", severity="critical", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No security lists found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# Helper: check NSG rules for open port from 0.0.0.0/0
# ═══════════════════════════════════════════════════════════════

def _nsg_has_open_port(c: OCIClientCache, nsg_id: str, port: int) -> bool:
    rules = c.virtual_network.list_network_security_group_security_rules(
        nsg_id, direction="INGRESS"
    ).data
    for rule in rules:
        if getattr(rule, "source", "") != "0.0.0.0/0":
            continue
        tcp_opts = getattr(rule, "tcp_options", None)
        if tcp_opts:
            dst = getattr(tcp_opts, "destination_port_range", None)
            if dst and getattr(dst, "min", 0) <= port <= getattr(dst, "max", 0):
                return True
        elif getattr(rule, "protocol", "") == "all":
            return True
    return False


# ═══════════════════════════════════════════════════════════════
# 2.3 -- No NSG ingress 0.0.0.0/0 to port 22
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_3(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for nsg in c.virtual_network.list_network_security_groups(cid).data:
                has_open = _nsg_has_open_port(c, nsg.id, 22)
                results.append(make_result(
                    cis_id="2.3", check_id="oci_cis_2_3",
                    title="Ensure no network security groups allow ingress from 0.0.0.0/0 to port 22",
                    service="networking", severity="critical",
                    status="FAIL" if has_open else "PASS",
                    resource_id=nsg.id, resource_name=nsg.display_name,
                    status_extended=f"NSG '{nsg.display_name}' {'allows' if has_open else 'does not allow'} 0.0.0.0/0 on port 22",
                    remediation="Restrict SSH (port 22) to specific CIDR ranges in NSG rules.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 2.3 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="2.3", check_id="oci_cis_2_3",
        title="Ensure no network security groups allow ingress from 0.0.0.0/0 to port 22",
        service="networking", severity="critical", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No NSGs found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.4 -- No NSG ingress 0.0.0.0/0 to port 3389
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_4(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for nsg in c.virtual_network.list_network_security_groups(cid).data:
                has_open = _nsg_has_open_port(c, nsg.id, 3389)
                results.append(make_result(
                    cis_id="2.4", check_id="oci_cis_2_4",
                    title="Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389",
                    service="networking", severity="critical",
                    status="FAIL" if has_open else "PASS",
                    resource_id=nsg.id, resource_name=nsg.display_name,
                    status_extended=f"NSG '{nsg.display_name}' {'allows' if has_open else 'does not allow'} 0.0.0.0/0 on port 3389",
                    remediation="Restrict RDP (port 3389) to specific CIDR ranges in NSG rules.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 2.4 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="2.4", check_id="oci_cis_2_4",
        title="Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389",
        service="networking", severity="critical", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No NSGs found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.5 -- Default SL restricts all except ICMP within VCN
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_5(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for sl in c.virtual_network.list_security_lists(cid).data:
                if "Default Security List" not in (sl.display_name or ""):
                    continue
                has_unrestricted = False
                for rule in (sl.ingress_security_rules or []):
                    if getattr(rule, "source", "") == "0.0.0.0/0":
                        # Protocol 1 = ICMP -- allowed
                        if getattr(rule, "protocol", "") != "1":
                            has_unrestricted = True
                            break
                results.append(make_result(
                    cis_id="2.5", check_id="oci_cis_2_5",
                    title="Ensure the default security list of every VCN restricts all traffic except ICMP within VCN",
                    service="networking", severity="critical",
                    status="FAIL" if has_unrestricted else "PASS",
                    resource_id=sl.id, resource_name=sl.display_name,
                    status_extended=(
                        f"Default SL '{sl.display_name}' has unrestricted non-ICMP ingress from 0.0.0.0/0"
                        if has_unrestricted else
                        f"Default SL '{sl.display_name}' properly restricts ingress"
                    ),
                    remediation="Modify default security list to restrict all ingress except ICMP within VCN CIDR.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 2.5 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="2.5", check_id="oci_cis_2_5",
        title="Ensure the default security list of every VCN restricts all traffic except ICMP within VCN",
        service="networking", severity="critical", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No default security lists found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.6 -- OIC access restricted (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_6(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.6", "oci_cis_2_6",
        "Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources",
        "networking", "medium", cfg.tenancy_id,
        "Verify OIC instances have network access restricted to specific IPs via OCI Console.")]


# ═══════════════════════════════════════════════════════════════
# 2.7 -- OAC access restricted (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_7(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.7", "oci_cis_2_7",
        "Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network",
        "networking", "medium", cfg.tenancy_id,
        "Verify OAC instances are in a VCN or have IP allowlists configured via OCI Console.")]


# ═══════════════════════════════════════════════════════════════
# 2.8 -- ADB access restricted (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_8(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.8", "oci_cis_2_8",
        "Ensure Oracle Autonomous Shared Databases (ADB) access is restricted to allowed sources or deployed within a Virtual Cloud Network",
        "networking", "high", cfg.tenancy_id,
        "Verify ADB instances are in a VCN or have ACL network restrictions configured.")]


# ═══════════════════════════════════════════════════════════════
# 3.1 -- Legacy IMDS endpoint disabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for instance in c.compute.list_instances(cid).data:
                if instance.lifecycle_state != "RUNNING":
                    continue
                inst_opts = getattr(instance, "instance_options", None)
                legacy_disabled = False
                if inst_opts:
                    legacy_disabled = getattr(inst_opts, "are_legacy_imds_endpoints_disabled", False)
                results.append(make_result(
                    cis_id="3.1", check_id="oci_cis_3_1",
                    title="Ensure Compute Instance Legacy Metadata service endpoint is disabled",
                    service="compute", severity="medium",
                    status="PASS" if legacy_disabled else "FAIL",
                    resource_id=instance.id, resource_name=instance.display_name,
                    status_extended=f"Instance '{instance.display_name}': legacy IMDS {'disabled' if legacy_disabled else 'enabled'}",
                    remediation="Disable legacy IMDS endpoints to prevent SSRF attacks.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 3.1 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="3.1", check_id="oci_cis_3_1",
        title="Ensure Compute Instance Legacy Metadata service endpoint is disabled",
        service="compute", severity="medium", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No running instances found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 3.2 -- Secure Boot enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_2(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for instance in c.compute.list_instances(cid).data:
                if instance.lifecycle_state != "RUNNING":
                    continue
                launch_opts = getattr(instance, "launch_options", None)
                secure_boot = False
                if launch_opts:
                    secure_boot = getattr(launch_opts, "is_secure_boot_enabled", False)
                results.append(make_result(
                    cis_id="3.2", check_id="oci_cis_3_2",
                    title="Ensure Secure Boot is enabled on Compute Instance",
                    service="compute", severity="critical",
                    status="PASS" if secure_boot else "FAIL",
                    resource_id=instance.id, resource_name=instance.display_name,
                    status_extended=f"Instance '{instance.display_name}': Secure Boot {'enabled' if secure_boot else 'disabled'}",
                    remediation="Enable Secure Boot in instance launch options.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 3.2 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="3.2", check_id="oci_cis_3_2",
        title="Ensure Secure Boot is enabled on Compute Instance",
        service="compute", severity="critical", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No running instances found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 3.3 -- In-transit encryption enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_3_3(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            for instance in c.compute.list_instances(cid).data:
                if instance.lifecycle_state != "RUNNING":
                    continue
                launch_opts = getattr(instance, "launch_options", None)
                transit_enc = False
                if launch_opts:
                    transit_enc = getattr(launch_opts, "is_pv_encryption_in_transit_enabled", False)
                results.append(make_result(
                    cis_id="3.3", check_id="oci_cis_3_3",
                    title="Ensure In-transit Encryption is enabled on Compute Instance",
                    service="compute", severity="high",
                    status="PASS" if transit_enc else "FAIL",
                    resource_id=instance.id, resource_name=instance.display_name,
                    status_extended=f"Instance '{instance.display_name}': in-transit encryption {'enabled' if transit_enc else 'disabled'}",
                    remediation="Enable in-transit encryption for boot and block volumes.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 3.3 compartment %s: %s", cid, e)
    return results or [make_result(
        cis_id="3.3", check_id="oci_cis_3_3",
        title="Ensure In-transit Encryption is enabled on Compute Instance",
        service="compute", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No running instances found",
        compliance_frameworks=FW,
    )]
