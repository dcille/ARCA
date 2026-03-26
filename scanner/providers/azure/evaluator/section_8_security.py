"""CIS Azure v5.0 Section 8: Security Services evaluators.

38 controls: 8.1.x (Defender for Cloud), 8.2.x (Defender for IoT),
             8.3.x (Key Vault), 8.4.1 (Bastion), 8.5 (DDoS).
"""

import logging
from .base import AzureClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Azure-5.0", "MCSB-Azure-1.0"]


# ═══════════════════════════════════════════════════════════════
# Helper: Check Defender pricing tier
# ═══════════════════════════════════════════════════════════════

def _check_defender_plan(c, cfg, cis_id, check_id, title, plan_name, severity="high"):
    """Check if a specific Defender plan is on Standard tier."""
    try:
        pricing = c.security.pricings.get(plan_name)
        enabled = pricing.pricing_tier == "Standard"
        return [make_result(cis_id=cis_id, check_id=check_id, title=title,
            service="security", severity=severity,
            status="PASS" if enabled else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Defender {plan_name}: {pricing.pricing_tier}",
            remediation=f"Enable Microsoft Defender for {plan_name} (Standard tier).",
            compliance_frameworks=FW)]
    except Exception as e:
        return [make_result(cis_id=cis_id, check_id=check_id, title=title,
            service="security", severity=severity, status="ERROR",
            resource_id=cfg.subscription_id,
            status_extended=f"Could not query Defender pricing for {plan_name}: {e}",
            compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 8.1.1.1 — Defender CSPM
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_8_1_1_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.1.1", "azure_cis_8_1_1_1",
        "Ensure Defender CSPM is set to On", "CloudPosture")

# 8.1.2.1 — Defender for APIs
def evaluate_cis_8_1_2_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.2.1", "azure_cis_8_1_2_1",
        "Ensure Defender for APIs is set to On", "Api")

# 8.1.3.1 — Defender for Servers
def evaluate_cis_8_1_3_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.3.1", "azure_cis_8_1_3_1",
        "Ensure Defender for Servers is set to On", "VirtualMachines")

# 8.1.3.2 — Vulnerability assessment component (MANUAL)
def evaluate_cis_8_1_3_2(c, cfg):
    return [make_manual_result(cis_id="8.1.3.2", check_id="azure_cis_8_1_3_2",
        title="Ensure vulnerability assessment for machines is On",
        service="security", severity="high", subscription_id=cfg.subscription_id,
        reason="Requires checking Defender for Cloud > Environment Settings > Settings & monitoring for the VA component.")]

# 8.1.3.3 — Endpoint protection component
def evaluate_cis_8_1_3_3(c, cfg):
    """Check WDATP (MDE) integration setting."""
    try:
        settings = list(c.security.settings.list())
        wdatp = next((s for s in settings if s.name == "WDATP"), None)
        enabled = wdatp and getattr(wdatp, "enabled", False)
        return [make_result(cis_id="8.1.3.3", check_id="azure_cis_8_1_3_3",
            title="Ensure endpoint protection component is On",
            service="security", severity="high",
            status="PASS" if enabled else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"WDATP (Defender for Endpoint) integration: {enabled}",
            remediation="Enable endpoint protection in Defender for Cloud Settings & monitoring.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="8.1.3.3", check_id="azure_cis_8_1_3_3",
            title="Ensure endpoint protection component is On",
            service="security", severity="high", status="ERROR",
            resource_id=cfg.subscription_id,
            status_extended="Could not query security settings.",
            compliance_frameworks=FW)]

# 8.1.3.4 — Agentless scanning (MANUAL)
def evaluate_cis_8_1_3_4(c, cfg):
    return [make_manual_result(cis_id="8.1.3.4", check_id="azure_cis_8_1_3_4",
        title="Ensure agentless scanning for machines is On",
        service="security", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires checking Settings & monitoring in Defender for Cloud for the agentless scanning component.")]

# 8.1.3.5 — File Integrity Monitoring (MANUAL)
def evaluate_cis_8_1_3_5(c, cfg):
    return [make_manual_result(cis_id="8.1.3.5", check_id="azure_cis_8_1_3_5",
        title="Ensure File Integrity Monitoring is On",
        service="security", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires checking Settings & monitoring in Defender for Cloud for the FIM component.")]

# 8.1.4.1 — Defender for Containers
def evaluate_cis_8_1_4_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.4.1", "azure_cis_8_1_4_1",
        "Ensure Defender for Containers is set to On", "Containers")

# 8.1.5.1 — Defender for Storage
def evaluate_cis_8_1_5_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.5.1", "azure_cis_8_1_5_1",
        "Ensure Defender for Storage is set to On", "StorageAccounts")

# 8.1.5.2 — ATP alerts monitored (MANUAL)
def evaluate_cis_8_1_5_2(c, cfg):
    return [make_manual_result(cis_id="8.1.5.2", check_id="azure_cis_8_1_5_2",
        title="Ensure Advanced Threat Protection alerts for Storage are monitored",
        service="security", severity="high", subscription_id=cfg.subscription_id,
        reason="Requires verifying continuous export and SIEM integration for storage security alerts.")]

# 8.1.6.1 — Defender for App Services
def evaluate_cis_8_1_6_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.6.1", "azure_cis_8_1_6_1",
        "Ensure Defender for App Services is set to On", "AppServices")

# 8.1.7.1 — Defender for Cosmos DB
def evaluate_cis_8_1_7_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.7.1", "azure_cis_8_1_7_1",
        "Ensure Defender for Azure Cosmos DB is set to On", "CosmosDbs")

# 8.1.7.2 — Defender for Open-Source Relational DBs
def evaluate_cis_8_1_7_2(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.7.2", "azure_cis_8_1_7_2",
        "Ensure Defender for Open-Source Relational Databases is On",
        "OpenSourceRelationalDatabases")

# 8.1.7.3 — Defender for Azure SQL Databases
def evaluate_cis_8_1_7_3(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.7.3", "azure_cis_8_1_7_3",
        "Ensure Defender for Azure SQL Databases is On", "SqlServers")

# 8.1.7.4 — Defender for SQL Servers on Machines
def evaluate_cis_8_1_7_4(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.7.4", "azure_cis_8_1_7_4",
        "Ensure Defender for SQL Servers on Machines is On", "SqlServerVirtualMachines")

# 8.1.8.1 — Defender for Key Vault
def evaluate_cis_8_1_8_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.8.1", "azure_cis_8_1_8_1",
        "Ensure Defender for Key Vault is set to On", "KeyVaults")

# 8.1.9.1 — Defender for Resource Manager
def evaluate_cis_8_1_9_1(c, cfg):
    return _check_defender_plan(c, cfg, "8.1.9.1", "azure_cis_8_1_9_1",
        "Ensure Defender for Resource Manager is set to On", "Arm")

# 8.1.10 — VM OS updates
def evaluate_cis_8_1_10(c, cfg):
    """Check that Defender recommends no system updates."""
    return [make_result(cis_id="8.1.10", check_id="azure_cis_8_1_10",
        title="Ensure Defender checks VM OS for updates",
        service="security", severity="high", status="MANUAL",
        resource_id=cfg.subscription_id,
        status_extended="Verify no 'System updates should be installed' recommendations exist in Defender for Cloud.",
        remediation="Apply pending system updates or use Azure Update Management.",
        compliance_frameworks=FW)]

# 8.1.11 — MCSB policies not disabled (MANUAL)
def evaluate_cis_8_1_11(c, cfg):
    return [make_manual_result(cis_id="8.1.11", check_id="azure_cis_8_1_11",
        title="Ensure MCSB policies are not set to Disabled",
        service="security", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires reviewing all policies in the MCSB initiative for Disabled effect.")]


# 8.1.12 — Email notifications to owners
def evaluate_cis_8_1_12(c, cfg):
    try:
        contacts = list(c.security.security_contacts.list())
        owners_notified = any(
            getattr(c_obj, "notifications_by_role", None) and
            "Owner" in str(getattr(c_obj.notifications_by_role, "roles", []))
            for c_obj in contacts
        )
        return [make_result(cis_id="8.1.12", check_id="azure_cis_8_1_12",
            title="Ensure 'All users with the following roles' is set to Owner",
            service="security", severity="medium",
            status="PASS" if owners_notified else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Owner role email notifications: {owners_notified}",
            remediation="Set email notifications to include Owner role in Defender for Cloud.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="8.1.12", check_id="azure_cis_8_1_12",
            title="Ensure 'All users with the following roles' is set to Owner",
            service="security", severity="medium", status="ERROR",
            resource_id=cfg.subscription_id, status_extended="Could not query security contacts.",
            compliance_frameworks=FW)]


# 8.1.13 — Additional email addresses configured
def evaluate_cis_8_1_13(c, cfg):
    try:
        contacts = list(c.security.security_contacts.list())
        has_email = any(getattr(co, "emails", None) for co in contacts)
        return [make_result(cis_id="8.1.13", check_id="azure_cis_8_1_13",
            title="Ensure additional email addresses are configured",
            service="security", severity="high",
            status="PASS" if has_email else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Security contact email configured: {has_email}",
            remediation="Add security team email addresses in Defender for Cloud email notifications.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="8.1.13", check_id="azure_cis_8_1_13",
            title="Ensure additional email addresses are configured",
            service="security", severity="high", status="ERROR",
            resource_id=cfg.subscription_id, status_extended="Could not query security contacts.",
            compliance_frameworks=FW)]


# 8.1.14 — Notify about high severity alerts
def evaluate_cis_8_1_14(c, cfg):
    try:
        contacts = list(c.security.security_contacts.list())
        notif_on = any(
            getattr(co, "alert_notifications", None) and
            getattr(co.alert_notifications, "state", "") == "On"
            for co in contacts
        )
        return [make_result(cis_id="8.1.14", check_id="azure_cis_8_1_14",
            title="Ensure 'Notify about alerts with high severity' is enabled",
            service="security", severity="medium",
            status="PASS" if notif_on else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Alert email notifications: {'On' if notif_on else 'Off'}",
            remediation="Enable email notifications for high severity alerts in Defender for Cloud.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="8.1.14", check_id="azure_cis_8_1_14",
            title="Ensure 'Notify about alerts with high severity' is enabled",
            service="security", severity="medium", status="ERROR",
            resource_id=cfg.subscription_id, status_extended="Could not query.",
            compliance_frameworks=FW)]


# 8.1.15 — Notify about attack paths
def evaluate_cis_8_1_15(c, cfg):
    return [make_result(cis_id="8.1.15", check_id="azure_cis_8_1_15",
        title="Ensure 'Notify about attack paths with risk level' is enabled",
        service="security", severity="medium", status="MANUAL",
        resource_id=cfg.subscription_id,
        status_extended="Check Defender for Cloud > Email notifications for attack path notifications.",
        remediation="Enable attack path email notifications in Defender for Cloud.",
        compliance_frameworks=FW)]

# 8.1.16 — EASM (MANUAL)
def evaluate_cis_8_1_16(c, cfg):
    return [make_manual_result(cis_id="8.1.16", check_id="azure_cis_8_1_16",
        title="Ensure Microsoft Defender EASM is enabled",
        service="security", severity="high", subscription_id=cfg.subscription_id,
        reason="EASM is a separate Azure resource. Check Azure Portal for Defender EASM workspaces.")]

# 8.2.1 — Defender for IoT (MANUAL)
def evaluate_cis_8_2_1(c, cfg):
    return [make_manual_result(cis_id="8.2.1", check_id="azure_cis_8_2_1",
        title="Ensure Defender for IoT Hub is set to On",
        service="security", severity="high", subscription_id=cfg.subscription_id,
        reason="Requires IoT Hub resource and checking Defender for IoT within the IoT Hub blade.")]


# ═══════════════════════════════════════════════════════════════
# 8.3.x — Key Vault
# ═══════════════════════════════════════════════════════════════

def _iter_vaults(c):
    try:
        return list(c.keyvault_mgmt.vaults.list())
    except Exception:
        return []


def _kv_data_client(c, vault_name, client_type):
    """Create a Key Vault data-plane client."""
    url = f"https://{vault_name}.vault.azure.net"
    if client_type == "keys":
        from azure.keyvault.keys import KeyClient
        return KeyClient(vault_url=url, credential=c.credential)
    elif client_type == "secrets":
        from azure.keyvault.secrets import SecretClient
        return SecretClient(vault_url=url, credential=c.credential)
    elif client_type == "certificates":
        from azure.keyvault.certificates import CertificateClient
        return CertificateClient(vault_url=url, credential=c.credential)


# 8.3.1 — Key expiration (RBAC vaults)
def evaluate_cis_8_3_1(c, cfg):
    results = []
    for v in _iter_vaults(c):
        if not (v.properties and v.properties.enable_rbac_authorization):
            continue
        try:
            kc = _kv_data_client(c, v.name, "keys")
            for key in kc.list_properties_of_keys():
                if not key.enabled:
                    continue
                has_exp = key.expires_on is not None
                results.append(make_result(cis_id="8.3.1", check_id="azure_cis_8_3_1",
                    title="Ensure key expiration is set (RBAC vaults)",
                    service="security", severity="medium",
                    status="PASS" if has_exp else "FAIL",
                    resource_id=f"{v.id}/keys/{key.name}", resource_name=key.name,
                    status_extended=f"Key {key.name} in {v.name}: expires = {key.expires_on or 'NEVER'}",
                    remediation="Set an expiration date on all Key Vault keys.",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results


# 8.3.2 — Key expiration (non-RBAC vaults)
def evaluate_cis_8_3_2(c, cfg):
    results = []
    for v in _iter_vaults(c):
        if v.properties and v.properties.enable_rbac_authorization:
            continue
        try:
            kc = _kv_data_client(c, v.name, "keys")
            for key in kc.list_properties_of_keys():
                if not key.enabled:
                    continue
                has_exp = key.expires_on is not None
                results.append(make_result(cis_id="8.3.2", check_id="azure_cis_8_3_2",
                    title="Ensure key expiration is set (non-RBAC vaults)",
                    service="security", severity="medium",
                    status="PASS" if has_exp else "FAIL",
                    resource_id=f"{v.id}/keys/{key.name}", resource_name=key.name,
                    status_extended=f"Key {key.name} in {v.name}: expires = {key.expires_on or 'NEVER'}",
                    remediation="Set an expiration date on all Key Vault keys.",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results


# 8.3.3 / 8.3.4 — Secret expiration (RBAC / non-RBAC)
def _check_secret_expiration(c, cfg, cis_id, check_id, title, rbac_filter):
    results = []
    for v in _iter_vaults(c):
        is_rbac = v.properties and v.properties.enable_rbac_authorization
        if rbac_filter and not is_rbac:
            continue
        if not rbac_filter and is_rbac:
            continue
        try:
            sc = _kv_data_client(c, v.name, "secrets")
            for sec in sc.list_properties_of_secrets():
                if not sec.enabled:
                    continue
                has_exp = sec.expires_on is not None
                results.append(make_result(cis_id=cis_id, check_id=check_id, title=title,
                    service="security", severity="medium",
                    status="PASS" if has_exp else "FAIL",
                    resource_id=f"{v.id}/secrets/{sec.name}", resource_name=sec.name,
                    status_extended=f"Secret {sec.name} in {v.name}: expires = {sec.expires_on or 'NEVER'}",
                    remediation="Set an expiration date on all Key Vault secrets.",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results

def evaluate_cis_8_3_3(c, cfg):
    return _check_secret_expiration(c, cfg, "8.3.3", "azure_cis_8_3_3",
        "Ensure secret expiration is set (RBAC vaults)", rbac_filter=True)

def evaluate_cis_8_3_4(c, cfg):
    return _check_secret_expiration(c, cfg, "8.3.4", "azure_cis_8_3_4",
        "Ensure secret expiration is set (non-RBAC vaults)", rbac_filter=False)


# 8.3.5 — Purge protection
def evaluate_cis_8_3_5(c, cfg):
    results = []
    for v in _iter_vaults(c):
        purge = v.properties and v.properties.enable_purge_protection
        results.append(make_result(cis_id="8.3.5", check_id="azure_cis_8_3_5",
            title="Ensure purge protection is enabled",
            service="security", severity="high",
            status="PASS" if purge else "FAIL",
            resource_id=v.id, resource_name=v.name,
            status_extended=f"Key Vault {v.name}: purge protection = {purge}",
            remediation="Enable purge protection for the Key Vault. Note: cannot be disabled once enabled.",
            compliance_frameworks=FW))
    return results


# 8.3.6 — RBAC authorization
def evaluate_cis_8_3_6(c, cfg):
    results = []
    for v in _iter_vaults(c):
        rbac = v.properties and v.properties.enable_rbac_authorization
        results.append(make_result(cis_id="8.3.6", check_id="azure_cis_8_3_6",
            title="Ensure RBAC for Key Vault is enabled",
            service="security", severity="high",
            status="PASS" if rbac else "FAIL",
            resource_id=v.id, resource_name=v.name,
            status_extended=f"Key Vault {v.name}: RBAC authorization = {rbac}",
            remediation="Switch Key Vault to Azure RBAC permission model.",
            compliance_frameworks=FW))
    return results


# 8.3.7 — Public network access disabled
def evaluate_cis_8_3_7(c, cfg):
    results = []
    for v in _iter_vaults(c):
        pna = getattr(v.properties, "public_network_access", None)
        disabled = pna == "Disabled"
        results.append(make_result(cis_id="8.3.7", check_id="azure_cis_8_3_7",
            title="Ensure public network access is disabled for Key Vault",
            service="security", severity="high",
            status="PASS" if disabled else "FAIL",
            resource_id=v.id, resource_name=v.name,
            status_extended=f"Key Vault {v.name}: publicNetworkAccess = {pna or 'Enabled'}",
            remediation="Disable public network access and use private endpoints.",
            compliance_frameworks=FW))
    return results


# 8.3.8 — Private endpoints for Key Vault
def evaluate_cis_8_3_8(c, cfg):
    results = []
    for v in _iter_vaults(c):
        pe = getattr(v.properties, "private_endpoint_connections", None) or []
        approved = [p for p in pe
                    if getattr(getattr(p, "private_link_service_connection_state", None), "status", "") == "Approved"]
        results.append(make_result(cis_id="8.3.8", check_id="azure_cis_8_3_8",
            title="Ensure private endpoints are used for Key Vault",
            service="security", severity="high",
            status="PASS" if approved else "FAIL",
            resource_id=v.id, resource_name=v.name,
            status_extended=f"Key Vault {v.name}: approved private endpoints = {len(approved)}",
            remediation="Configure private endpoints for the Key Vault.",
            compliance_frameworks=FW))
    return results


# 8.3.9 — Automatic key rotation
def evaluate_cis_8_3_9(c, cfg):
    results = []
    for v in _iter_vaults(c):
        try:
            kc = _kv_data_client(c, v.name, "keys")
            for key in kc.list_properties_of_keys():
                try:
                    policy = kc.get_key_rotation_policy(key.name)
                    has_rotate = any(
                        a.action.value == "Rotate" if hasattr(a.action, "value") else str(a.action) == "Rotate"
                        for a in (policy.lifetime_actions or [])
                    ) if policy else False
                    results.append(make_result(cis_id="8.3.9", check_id="azure_cis_8_3_9",
                        title="Ensure automatic key rotation is enabled",
                        service="security", severity="high",
                        status="PASS" if has_rotate else "FAIL",
                        resource_id=f"{v.id}/keys/{key.name}", resource_name=key.name,
                        status_extended=f"Key {key.name} in {v.name}: auto-rotate = {has_rotate}",
                        remediation="Configure a rotation policy with a Rotate action for the key.",
                        compliance_frameworks=FW))
                except Exception:
                    pass
        except Exception:
            pass
    return results


# 8.3.10 — Managed HSM (MANUAL)
def evaluate_cis_8_3_10(c, cfg):
    return [make_manual_result(cis_id="8.3.10", check_id="azure_cis_8_3_10",
        title="Ensure Azure Key Vault Managed HSM is used when required",
        service="security", severity="medium", subscription_id=cfg.subscription_id,
        reason="Managed HSM is required only for FIPS 140-2 Level 3 compliance. Requires organizational assessment.")]


# 8.3.11 — Certificate validity ≤ 12 months
def evaluate_cis_8_3_11(c, cfg):
    results = []
    for v in _iter_vaults(c):
        try:
            cc = _kv_data_client(c, v.name, "certificates")
            for cert in cc.list_properties_of_certificates():
                try:
                    policy = cc.get_certificate_policy(cert.name)
                    months = policy.validity_in_months if policy else None
                    ok = months is not None and months <= 12
                    results.append(make_result(cis_id="8.3.11", check_id="azure_cis_8_3_11",
                        title="Ensure certificate validity ≤ 12 months",
                        service="security", severity="medium",
                        status="PASS" if ok else "FAIL",
                        resource_id=f"{v.id}/certificates/{cert.name}", resource_name=cert.name,
                        status_extended=f"Certificate {cert.name} in {v.name}: validity = {months} months",
                        remediation="Set certificate validity to 12 months or less.",
                        compliance_frameworks=FW))
                except Exception:
                    pass
        except Exception:
            pass
    return results


# ═══════════════════════════════════════════════════════════════
# 8.4.1 — Azure Bastion Host
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_8_4_1(c, cfg):
    try:
        bastions = list(c.network.bastion_hosts.list())
        return [make_result(cis_id="8.4.1", check_id="azure_cis_8_4_1",
            title="Ensure an Azure Bastion Host exists",
            service="security", severity="high",
            status="PASS" if bastions else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Azure Bastion hosts: {len(bastions)}",
            remediation="Deploy Azure Bastion for secure RDP/SSH access without public IPs.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="8.4.1", check_id="azure_cis_8_4_1",
            title="Ensure an Azure Bastion Host exists",
            service="security", severity="high", status="ERROR",
            resource_id=cfg.subscription_id,
            status_extended="Could not query Bastion hosts.",
            compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 8.5 — DDoS Network Protection
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_8_5(c, cfg):
    try:
        vnets = list(c.network.virtual_networks.list_all())
        protected = [v for v in vnets if v.enable_ddos_protection]
        return [make_result(cis_id="8.5", check_id="azure_cis_8_5",
            title="Ensure Azure DDoS Network Protection is enabled",
            service="security", severity="medium",
            status="PASS" if protected else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"VNets with DDoS protection: {len(protected)}/{len(vnets)}",
            remediation="Enable DDoS Network Protection on virtual networks.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="8.5", check_id="azure_cis_8_5",
            title="Ensure Azure DDoS Network Protection is enabled",
            service="security", severity="medium", status="ERROR",
            resource_id=cfg.subscription_id, status_extended="Could not query VNets.",
            compliance_frameworks=FW)]
