"""CIS Azure v5.0 Section 7: Networking evaluators.

Each function evaluates ONE CIS control across ALL applicable resources.
Returns list[dict] of per-resource CheckResult dicts.

Coverage:
  7.1  RDP restricted           ✓ automated
  7.2  SSH restricted            ✓ automated
  7.3  UDP restricted            ✓ automated
  7.4  HTTP(S) restricted        ✓ automated
  7.5  NSG flow log retention    ✓ automated
  7.6  Network Watcher enabled   ✓ automated
  7.7  Public IPs reviewed       ✓ automated
  7.8  VNet flow log retention   ✓ automated
  7.9  VPN AAD auth              ✓ automated (partial - needs VPN gateways)
  7.10 WAF on AppGW              ✓ automated
  7.11 Subnets have NSGs         ✓ automated
  7.12 AppGW TLS 1.2             ✓ automated
  7.13 AppGW HTTP/2              ✓ automated
  7.14 WAF body inspection       ✓ automated
  7.15 WAF bot protection        ✓ automated
  7.16 Network Security Perimeter  manual (L2, org-specific)
"""

import logging
from .base import AzureClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)

CIS = "CIS-Azure-5.0"
FW = [CIS, "MCSB-Azure-1.0"]


# ─────────────────────────────────────────────────────────────────
# Helper: Check NSG rules for unrestricted inbound access
# ─────────────────────────────────────────────────────────────────

def _nsg_has_unrestricted_inbound(nsg, port: int | str, protocol: str = "Tcp") -> list[str]:
    """Return list of rule names that allow unrestricted inbound on given port/protocol."""
    bad_rules = []
    for rule in nsg.security_rules or []:
        if rule.direction != "Inbound" or rule.access != "Allow":
            continue
        if rule.source_address_prefix not in ("*", "0.0.0.0/0", "Internet", "Any"):
            continue
        if protocol != "*" and rule.protocol not in (protocol, "*"):
            continue

        dest = rule.destination_port_range or ""
        dest_ranges = rule.destination_port_ranges or []

        # Check single port or wildcard
        if isinstance(port, int):
            port_str = str(port)
            if dest == port_str or dest == "*":
                bad_rules.append(rule.name)
                continue
            # Check ranges
            for r in ([dest] + list(dest_ranges)):
                if "-" in r:
                    try:
                        lo, hi = r.split("-")
                        if int(lo) <= port <= int(hi):
                            bad_rules.append(rule.name)
                            break
                    except ValueError:
                        pass
        elif port == "*":
            if dest == "*":
                bad_rules.append(rule.name)

    return bad_rules


# ═════════════════════════════════════════════════════════════════
# CIS 7.1 — Ensure RDP access from the Internet is restricted
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    nsgs = list(clients.network.network_security_groups.list_all())

    if not nsgs:
        results.append(make_result(
            cis_id="7.1", check_id="azure_cis_7_1",
            title="Ensure RDP access from the Internet is restricted",
            service="networking", severity="high", status="PASS",
            resource_id=config.subscription_id,
            status_extended="No NSGs found in subscription",
            compliance_frameworks=FW,
        ))
        return results

    for nsg in nsgs:
        bad_rules = _nsg_has_unrestricted_inbound(nsg, 3389, "Tcp")
        results.append(make_result(
            cis_id="7.1", check_id="azure_cis_7_1",
            title="Ensure RDP access from the Internet is restricted",
            service="networking", severity="high",
            status="FAIL" if bad_rules else "PASS",
            resource_id=nsg.id, resource_name=nsg.name,
            region=nsg.location,
            status_extended=(
                f"NSG {nsg.name}: Rules allowing unrestricted RDP (3389): {', '.join(bad_rules)}"
                if bad_rules else f"NSG {nsg.name}: No unrestricted RDP access"
            ),
            remediation="Remove or restrict inbound rules allowing 0.0.0.0/0 on port 3389. Use Azure Bastion or VPN for remote access.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.2 — Ensure SSH access from the Internet is restricted
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_2(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    nsgs = list(clients.network.network_security_groups.list_all())
    for nsg in nsgs:
        bad_rules = _nsg_has_unrestricted_inbound(nsg, 22, "Tcp")
        results.append(make_result(
            cis_id="7.2", check_id="azure_cis_7_2",
            title="Ensure SSH access from the Internet is restricted",
            service="networking", severity="high",
            status="FAIL" if bad_rules else "PASS",
            resource_id=nsg.id, resource_name=nsg.name,
            region=nsg.location,
            status_extended=(
                f"NSG {nsg.name}: Rules allowing unrestricted SSH (22): {', '.join(bad_rules)}"
                if bad_rules else f"NSG {nsg.name}: No unrestricted SSH access"
            ),
            remediation="Remove or restrict inbound rules allowing 0.0.0.0/0 on port 22.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.3 — Ensure UDP access from the Internet is restricted
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_3(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    # UDP amplification ports: DNS(53), NTP(123), SNMP(161), LDAP(389), SSDP(1900)
    vuln_ports = [53, 123, 161, 389, 1900]
    nsgs = list(clients.network.network_security_groups.list_all())

    for nsg in nsgs:
        all_bad_rules = set()
        for port in vuln_ports:
            all_bad_rules.update(_nsg_has_unrestricted_inbound(nsg, port, "Udp"))
        # Also check for wildcard UDP
        all_bad_rules.update(_nsg_has_unrestricted_inbound(nsg, "*", "Udp"))

        results.append(make_result(
            cis_id="7.3", check_id="azure_cis_7_3",
            title="Ensure UDP access from the Internet is restricted",
            service="networking", severity="high",
            status="FAIL" if all_bad_rules else "PASS",
            resource_id=nsg.id, resource_name=nsg.name,
            region=nsg.location,
            status_extended=(
                f"NSG {nsg.name}: Rules allowing unrestricted UDP: {', '.join(sorted(all_bad_rules))}"
                if all_bad_rules else f"NSG {nsg.name}: No unrestricted UDP access"
            ),
            remediation="Restrict inbound UDP access on ports 53, 123, 161, 389, 1900 to specific IPs.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.4 — Ensure HTTP(S) access from the Internet is restricted
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_4(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    nsgs = list(clients.network.network_security_groups.list_all())
    for nsg in nsgs:
        bad_80 = _nsg_has_unrestricted_inbound(nsg, 80, "Tcp")
        bad_443 = _nsg_has_unrestricted_inbound(nsg, 443, "Tcp")
        all_bad = set(bad_80 + bad_443)
        results.append(make_result(
            cis_id="7.4", check_id="azure_cis_7_4",
            title="Ensure HTTP(S) access from the Internet is restricted",
            service="networking", severity="high",
            status="FAIL" if all_bad else "PASS",
            resource_id=nsg.id, resource_name=nsg.name,
            region=nsg.location,
            status_extended=(
                f"NSG {nsg.name}: Unrestricted HTTP/S rules: {', '.join(sorted(all_bad))}"
                if all_bad else f"NSG {nsg.name}: HTTP/S properly restricted"
            ),
            remediation="Restrict inbound HTTP (80) and HTTPS (443) to known IPs. Use Application Gateway or Front Door for public web apps.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.5 — NSG flow log retention ≥ 90 days
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_5(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    watchers = list(clients.network.network_watchers.list_all())

    if not watchers:
        results.append(make_result(
            cis_id="7.5", check_id="azure_cis_7_5",
            title="Ensure NSG flow log retention ≥ 90 days",
            service="networking", severity="high",
            status="FAIL",
            resource_id=config.subscription_id,
            status_extended="No Network Watchers found — flow logs cannot be configured",
            remediation="Enable Network Watcher and configure NSG flow logs with ≥ 90 day retention.",
            compliance_frameworks=FW,
        ))
        return results

    for watcher in watchers:
        rg = watcher.id.split("/")[4]
        try:
            flow_logs = list(clients.network.flow_logs.list(rg, watcher.name))
            if not flow_logs:
                results.append(make_result(
                    cis_id="7.5", check_id="azure_cis_7_5",
                    title="Ensure NSG flow log retention ≥ 90 days",
                    service="networking", severity="high", status="FAIL",
                    resource_id=watcher.id, resource_name=watcher.name,
                    region=watcher.location,
                    status_extended=f"No flow logs configured in watcher {watcher.name}",
                    remediation="Configure NSG flow logs with ≥ 90 day retention.",
                    compliance_frameworks=FW,
                ))
                continue

            for fl in flow_logs:
                rp = fl.retention_policy
                days = rp.days if rp and rp.enabled else 0
                # 0 days = retained indefinitely (PASS)
                ok = days == 0 or days >= 90
                results.append(make_result(
                    cis_id="7.5", check_id="azure_cis_7_5",
                    title="Ensure NSG flow log retention ≥ 90 days",
                    service="networking", severity="high",
                    status="PASS" if ok else "FAIL",
                    resource_id=fl.id, resource_name=fl.name,
                    region=watcher.location,
                    status_extended=f"Flow log {fl.name}: retention = {days} days (0 = indefinite)",
                    remediation="Set flow log retention to 0 (indefinite) or ≥ 90 days.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("Failed to list flow logs for %s: %s", watcher.name, e)

    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.6 — Network Watcher enabled in all regions
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_6(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    watchers = list(clients.network.network_watchers.list_all())
    watcher_regions = {w.location.lower().replace(" ", "") for w in watchers}

    # Get regions with resources
    try:
        vnets = list(clients.network.virtual_networks.list_all())
        active_regions = {v.location.lower().replace(" ", "") for v in vnets}
    except Exception:
        active_regions = set()

    if not active_regions:
        results.append(make_result(
            cis_id="7.6", check_id="azure_cis_7_6",
            title="Ensure Network Watcher is enabled for all regions in use",
            service="networking", severity="medium",
            status="PASS" if watchers else "FAIL",
            resource_id=config.subscription_id,
            status_extended=f"Network Watchers: {len(watchers)}",
            remediation="Enable Network Watcher in all active regions.",
            compliance_frameworks=FW,
        ))
        return results

    missing = active_regions - watcher_regions
    results.append(make_result(
        cis_id="7.6", check_id="azure_cis_7_6",
        title="Ensure Network Watcher is enabled for all regions in use",
        service="networking", severity="medium",
        status="FAIL" if missing else "PASS",
        resource_id=config.subscription_id,
        status_extended=(
            f"Regions with VNets but no Network Watcher: {', '.join(sorted(missing))}"
            if missing else f"All {len(active_regions)} active regions have Network Watcher"
        ),
        remediation="Enable Network Watcher in the missing regions.",
        compliance_frameworks=FW,
    ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.7 — Public IP addresses evaluated periodically
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_7(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    pips = list(clients.network.public_ip_addresses.list_all())

    for pip in pips:
        associated = pip.ip_configuration is not None
        results.append(make_result(
            cis_id="7.7", check_id="azure_cis_7_7",
            title="Ensure Public IP addresses are evaluated periodically",
            service="networking", severity="medium",
            status="PASS" if associated else "FAIL",
            resource_id=pip.id, resource_name=pip.name,
            region=pip.location,
            status_extended=(
                f"Public IP {pip.name}: {'Associated' if associated else 'UNASSOCIATED — may be unnecessary'} "
                f"(IP: {pip.ip_address or 'dynamic'})"
            ),
            remediation="Review and remove unassociated public IPs. Ensure all public IPs are intentional.",
            compliance_frameworks=FW,
        ))

    if not pips:
        results.append(make_result(
            cis_id="7.7", check_id="azure_cis_7_7",
            title="Ensure Public IP addresses are evaluated periodically",
            service="networking", severity="medium", status="PASS",
            resource_id=config.subscription_id,
            status_extended="No public IP addresses found.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.8 — VNet flow log retention ≥ 90 days
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_8(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    watchers = list(clients.network.network_watchers.list_all())
    found_vnet_logs = False

    for watcher in watchers:
        rg = watcher.id.split("/")[4]
        try:
            flow_logs = list(clients.network.flow_logs.list(rg, watcher.name))
            for fl in flow_logs:
                target = fl.target_resource_id or ""
                if "virtualnetwork" not in target.lower() and "virtualNetwork" not in target:
                    continue
                found_vnet_logs = True
                rp = fl.retention_policy
                days = rp.days if rp and rp.enabled else 0
                ok = days == 0 or days >= 90
                results.append(make_result(
                    cis_id="7.8", check_id="azure_cis_7_8",
                    title="Ensure VNet flow log retention ≥ 90 days",
                    service="networking", severity="high",
                    status="PASS" if ok else "FAIL",
                    resource_id=fl.id, resource_name=fl.name,
                    region=watcher.location,
                    status_extended=f"VNet flow log {fl.name}: retention = {days} days",
                    remediation="Set VNet flow log retention to 0 (indefinite) or ≥ 90 days.",
                    compliance_frameworks=FW,
                ))
        except Exception:
            pass

    if not found_vnet_logs:
        results.append(make_result(
            cis_id="7.8", check_id="azure_cis_7_8",
            title="Ensure VNet flow log retention ≥ 90 days",
            service="networking", severity="high", status="FAIL",
            resource_id=config.subscription_id,
            status_extended="No VNet flow logs configured.",
            remediation="Configure VNet flow logs with ≥ 90 day retention.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.10 — WAF enabled on Application Gateway
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_10(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    try:
        agws = list(clients.network.application_gateways.list_all())
    except Exception:
        return results

    for agw in agws:
        sku = agw.sku
        is_waf = sku and "WAF" in (sku.tier or "")
        results.append(make_result(
            cis_id="7.10", check_id="azure_cis_7_10",
            title="Ensure WAF is enabled on Azure Application Gateway",
            service="networking", severity="high",
            status="PASS" if is_waf else "FAIL",
            resource_id=agw.id, resource_name=agw.name,
            region=agw.location,
            status_extended=f"AppGW {agw.name}: SKU tier = {sku.tier if sku else 'unknown'}",
            remediation="Upgrade Application Gateway to WAF_v2 tier.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.11 — Subnets associated with NSGs
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_11(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    EXEMPT_SUBNETS = {"GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet",
                      "AzureFirewallManagementSubnet", "RouteServerSubnet"}

    vnets = list(clients.network.virtual_networks.list_all())
    for vnet in vnets:
        for subnet in vnet.subnets or []:
            if subnet.name in EXEMPT_SUBNETS:
                continue
            has_nsg = subnet.network_security_group is not None
            results.append(make_result(
                cis_id="7.11", check_id="azure_cis_7_11",
                title="Ensure subnets are associated with network security groups",
                service="networking", severity="high",
                status="PASS" if has_nsg else "FAIL",
                resource_id=subnet.id, resource_name=subnet.name,
                region=vnet.location,
                status_extended=f"Subnet {subnet.name} in VNet {vnet.name}: NSG = {'yes' if has_nsg else 'NONE'}",
                remediation="Associate a Network Security Group with this subnet.",
                compliance_frameworks=FW,
            ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.12 — AppGW SSL policy min TLS 1.2
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_12(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    try:
        agws = list(clients.network.application_gateways.list_all())
    except Exception:
        return results

    for agw in agws:
        ssl = agw.ssl_policy
        min_tls = ssl.min_protocol_version if ssl else None
        ok = min_tls in ("TLSv1_2", "TLSv1_3") if min_tls else False
        results.append(make_result(
            cis_id="7.12", check_id="azure_cis_7_12",
            title="Ensure AppGW SSL policy min protocol is TLS 1.2+",
            service="networking", severity="high",
            status="PASS" if ok else "FAIL",
            resource_id=agw.id, resource_name=agw.name,
            region=agw.location,
            status_extended=f"AppGW {agw.name}: min TLS = {min_tls or 'not set (defaults vary)'}",
            remediation="Set SSL policy minimum protocol version to TLSv1_2 or TLSv1_3.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.13 — AppGW HTTP/2 enabled
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_13(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    try:
        agws = list(clients.network.application_gateways.list_all())
    except Exception:
        return results

    for agw in agws:
        http2 = getattr(agw, "enable_http2", False) or False
        results.append(make_result(
            cis_id="7.13", check_id="azure_cis_7_13",
            title="Ensure HTTP/2 is enabled on Application Gateway",
            service="networking", severity="medium",
            status="PASS" if http2 else "FAIL",
            resource_id=agw.id, resource_name=agw.name,
            region=agw.location,
            status_extended=f"AppGW {agw.name}: HTTP/2 = {http2}",
            remediation="Enable HTTP/2 on the Application Gateway for improved performance.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.14 — WAF request body inspection
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_14(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    try:
        agws = list(clients.network.application_gateways.list_all())
    except Exception:
        return results

    for agw in agws:
        waf = agw.web_application_firewall_configuration
        if not waf:
            # Not a WAF-tier gateway — skip (covered by 7.10)
            continue
        body_check = getattr(waf, "request_body_check", False) or False
        results.append(make_result(
            cis_id="7.14", check_id="azure_cis_7_14",
            title="Ensure WAF request body inspection is enabled",
            service="networking", severity="high",
            status="PASS" if body_check else "FAIL",
            resource_id=agw.id, resource_name=agw.name,
            region=agw.location,
            status_extended=f"AppGW {agw.name}: WAF body inspection = {body_check}",
            remediation="Enable request body inspection in the WAF configuration.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.15 — WAF bot protection
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_15(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    try:
        # Check WAF policies for bot manager rule set
        waf_policies = list(clients.network.web_application_firewall_policies.list_all())
    except Exception:
        return results

    for pol in waf_policies:
        managed_rules = pol.managed_rules
        has_bot = False
        if managed_rules and managed_rules.managed_rule_sets:
            has_bot = any(
                "bot" in (rs.rule_set_type or "").lower()
                for rs in managed_rules.managed_rule_sets
            )
        results.append(make_result(
            cis_id="7.15", check_id="azure_cis_7_15",
            title="Ensure bot protection is enabled in WAF policy",
            service="networking", severity="high",
            status="PASS" if has_bot else "FAIL",
            resource_id=pol.id, resource_name=pol.name,
            region=pol.location,
            status_extended=f"WAF policy {pol.name}: BotManagerRuleSet = {has_bot}",
            remediation="Add Microsoft_BotManagerRuleSet to the WAF policy managed rules.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.9 — VPN Gateway AAD authentication
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_9(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    try:
        # List VPN gateways (virtual network gateways of type Vpn)
        vngs = list(clients.network.virtual_network_gateways.list_all()) if hasattr(
            clients.network, 'virtual_network_gateways'
        ) else []
    except Exception:
        return results

    for gw in vngs:
        if gw.gateway_type != "Vpn":
            continue
        vpn_cfg = gw.vpn_client_configuration
        if not vpn_cfg:
            # No P2S configured — not applicable
            continue

        auth_types = vpn_cfg.vpn_authentication_types or []
        aad_only = auth_types == ["AAD"] if auth_types else False

        results.append(make_result(
            cis_id="7.9", check_id="azure_cis_7_9",
            title="Ensure VPN Gateway uses Azure AD authentication only",
            service="networking", severity="medium",
            status="PASS" if aad_only else "FAIL",
            resource_id=gw.id, resource_name=gw.name,
            region=gw.location,
            status_extended=f"VPN Gateway {gw.name}: auth types = {auth_types or 'none/default'}",
            remediation="Configure VPN Gateway P2S to use only Azure Active Directory authentication.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 7.16 — Network Security Perimeter (MANUAL)
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_7_16(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="7.16", check_id="azure_cis_7_16",
        title="Ensure Azure Network Security Perimeter is used for PaaS resources",
        service="networking", severity="critical",
        subscription_id=config.subscription_id,
        reason="NSP resource association depends on organizational PaaS resource inventory. Requires manual review of perimeter profiles.",
    )]
