"""CIS Azure v5.0 Section 9: Storage evaluators.

Coverage:
  9.1.1 Soft delete for file shares                   ✓
  9.1.2 SMB protocol version 3.1.1                    ✓
  9.1.3 SMB channel encryption AES-256-GCM            ✓
  9.2.1 Soft delete for blobs                         ✓
  9.2.2 Soft delete for containers                    ✓
  9.2.3 Blob versioning enabled                       ✓
  9.3.1.1 Key rotation reminders enabled              ✓
  9.3.1.2 Keys periodically regenerated               ✓
  9.3.1.3 Shared key access disabled                  ✓
  9.3.2.1 Private endpoints for storage               ✓
  9.3.2.2 Public network access disabled              ✓
  9.3.2.3 Default network rule set to deny            ✓
  9.3.3.1 Default Entra authorization in portal       ✓
  9.3.4   Secure transfer required (HTTPS)            ✓
  9.3.5   Trusted Azure services bypass               ✓
  9.3.6   Minimum TLS 1.2                             ✓
  9.3.7   Cross-tenant replication disabled            ✓
  9.3.8   Blob anonymous access disabled              ✓
  9.3.9   Delete locks on storage accounts            manual (org-specific)
  9.3.10  ReadOnly locks considered                   manual (org-specific)
  9.3.11  Geo-redundant storage                       ✓
"""

import logging
from datetime import datetime, timezone
from .base import AzureClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Azure-5.0", "MCSB-Azure-1.0"]


def _rg_from_id(resource_id: str) -> str:
    """Extract resource group name from an Azure resource ID."""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""


# ═════════════════════════════════════════════════════════════════
# CIS 9.1.1 — Soft delete for Azure File Shares
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_1_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        rg = _rg_from_id(acct.id)
        try:
            file_services = list(clients.storage.file_services.list(rg, acct.name))
            for fs in file_services:
                policy = fs.share_delete_retention_policy
                enabled = policy and policy.enabled
                days = policy.days if policy and policy.enabled else 0
                results.append(make_result(
                    cis_id="9.1.1", check_id="azure_cis_9_1_1",
                    title="Ensure soft delete for Azure File Shares is enabled",
                    service="storage", severity="medium",
                    status="PASS" if enabled else "FAIL",
                    resource_id=acct.id, resource_name=acct.name,
                    region=acct.location,
                    status_extended=f"Storage {acct.name}: file share soft delete = {enabled} ({days} days)",
                    remediation="Enable soft delete for file shares with 7-365 day retention.",
                    compliance_frameworks=FW,
                ))
        except Exception:
            pass
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.2.1 — Soft delete for blobs
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_2_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        rg = _rg_from_id(acct.id)
        try:
            props = clients.storage.blob_services.get_service_properties(rg, acct.name)
            policy = props.delete_retention_policy
            enabled = policy and policy.enabled
            days = policy.days if enabled else 0
            results.append(make_result(
                cis_id="9.2.1", check_id="azure_cis_9_2_1",
                title="Ensure soft delete for blobs is enabled",
                service="storage", severity="high",
                status="PASS" if enabled else "FAIL",
                resource_id=acct.id, resource_name=acct.name,
                region=acct.location,
                status_extended=f"Storage {acct.name}: blob soft delete = {enabled} ({days} days)",
                remediation="Enable soft delete for blobs with appropriate retention.",
                compliance_frameworks=FW,
            ))
        except Exception:
            pass
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.2.2 — Soft delete for containers
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_2_2(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        rg = _rg_from_id(acct.id)
        try:
            props = clients.storage.blob_services.get_service_properties(rg, acct.name)
            policy = props.container_delete_retention_policy
            enabled = policy and policy.enabled
            results.append(make_result(
                cis_id="9.2.2", check_id="azure_cis_9_2_2",
                title="Ensure soft delete for containers is enabled",
                service="storage", severity="high",
                status="PASS" if enabled else "FAIL",
                resource_id=acct.id, resource_name=acct.name,
                region=acct.location,
                status_extended=f"Storage {acct.name}: container soft delete = {enabled}",
                remediation="Enable soft delete for containers with appropriate retention.",
                compliance_frameworks=FW,
            ))
        except Exception:
            pass
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.2.3 — Blob versioning enabled
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_2_3(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        rg = _rg_from_id(acct.id)
        try:
            props = clients.storage.blob_services.get_service_properties(rg, acct.name)
            versioning = props.is_versioning_enabled or False
            results.append(make_result(
                cis_id="9.2.3", check_id="azure_cis_9_2_3",
                title="Ensure blob versioning is enabled",
                service="storage", severity="high",
                status="PASS" if versioning else "FAIL",
                resource_id=acct.id, resource_name=acct.name,
                region=acct.location,
                status_extended=f"Storage {acct.name}: versioning = {versioning}",
                remediation="Enable blob versioning for data recovery.",
                compliance_frameworks=FW,
            ))
        except Exception:
            pass
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.1.3 — Shared key access disabled
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_1_3(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        shared_key = acct.allow_shared_key_access
        # None = not set = defaults to True (allow)
        disabled = shared_key is False
        results.append(make_result(
            cis_id="9.3.1.3", check_id="azure_cis_9_3_1_3",
            title="Ensure shared key access is disabled",
            service="storage", severity="high",
            status="PASS" if disabled else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: allowSharedKeyAccess = {shared_key}",
            remediation="Set allowSharedKeyAccess to false. Use Entra ID (Azure AD) for authentication.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.2.2 — Public network access disabled
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_2_2(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        pna = acct.public_network_access
        disabled = pna == "Disabled"
        results.append(make_result(
            cis_id="9.3.2.2", check_id="azure_cis_9_3_2_2",
            title="Ensure public network access is disabled for storage accounts",
            service="storage", severity="critical",
            status="PASS" if disabled else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: publicNetworkAccess = {pna or 'Enabled (default)'}",
            remediation="Set publicNetworkAccess to Disabled. Use private endpoints.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.2.3 — Default network rule = deny
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_2_3(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        rules = acct.network_rule_set
        default_action = rules.default_action if rules else "Allow"
        deny = default_action == "Deny"
        results.append(make_result(
            cis_id="9.3.2.3", check_id="azure_cis_9_3_2_3",
            title="Ensure default network access rule is set to deny",
            service="storage", severity="medium",
            status="PASS" if deny else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: defaultAction = {default_action}",
            remediation="Set storage account network default action to Deny.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.4 — Secure transfer required (HTTPS)
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_4(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        https = acct.enable_https_traffic_only
        results.append(make_result(
            cis_id="9.3.4", check_id="azure_cis_9_3_4",
            title="Ensure secure transfer required is enabled",
            service="storage", severity="high",
            status="PASS" if https else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: HTTPS only = {https}",
            remediation="Enable 'Secure transfer required' for the storage account.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.6 — Minimum TLS 1.2
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_6(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        min_tls = acct.minimum_tls_version
        ok = min_tls in ("TLS1_2", "TLS1_3")
        results.append(make_result(
            cis_id="9.3.6", check_id="azure_cis_9_3_6",
            title="Ensure minimum TLS version is 1.2",
            service="storage", severity="high",
            status="PASS" if ok else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: minimumTlsVersion = {min_tls or 'not set'}",
            remediation="Set minimum TLS version to TLS1_2.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.7 — Cross-tenant replication disabled
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_7(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        cross_tenant = acct.allow_cross_tenant_replication
        disabled = cross_tenant is False
        results.append(make_result(
            cis_id="9.3.7", check_id="azure_cis_9_3_7",
            title="Ensure cross-tenant replication is disabled",
            service="storage", severity="medium",
            status="PASS" if disabled else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: allowCrossTenantReplication = {cross_tenant}",
            remediation="Set allowCrossTenantReplication to false.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.8 — Blob anonymous access disabled
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_8(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        public = acct.allow_blob_public_access
        disabled = public is False
        results.append(make_result(
            cis_id="9.3.8", check_id="azure_cis_9_3_8",
            title="Ensure blob anonymous access is disabled",
            service="storage", severity="critical",
            status="PASS" if disabled else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: allowBlobPublicAccess = {public}",
            remediation="Set allowBlobPublicAccess to false.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.5 — Trusted Azure services bypass
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_5(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    for acct in accounts:
        rules = acct.network_rule_set
        bypass = rules.bypass if rules else "AzureServices"
        trusted = "AzureServices" in (bypass or "")
        results.append(make_result(
            cis_id="9.3.5", check_id="azure_cis_9_3_5",
            title="Ensure trusted Azure services can access storage account",
            service="storage", severity="high",
            status="PASS" if trusted else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: bypass = {bypass}",
            remediation="Set network rule bypass to include AzureServices.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.11 — Geo-redundant storage
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_11(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    accounts = list(clients.storage.storage_accounts.list())

    grs_skus = {"Standard_GRS", "Standard_RAGRS", "Standard_GZRS", "Standard_RAGZRS"}

    for acct in accounts:
        sku = acct.sku.name if acct.sku else "unknown"
        is_grs = sku in grs_skus
        results.append(make_result(
            cis_id="9.3.11", check_id="azure_cis_9_3_11",
            title="Ensure redundancy is set to geo-redundant storage",
            service="storage", severity="medium",
            status="PASS" if is_grs else "FAIL",
            resource_id=acct.id, resource_name=acct.name,
            region=acct.location,
            status_extended=f"Storage {acct.name}: SKU = {sku}",
            remediation="Set storage redundancy to GRS, RA-GRS, GZRS, or RA-GZRS.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.9 / 9.3.10 — Resource locks (MANUAL)
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_9(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="9.3.9", check_id="azure_cis_9_3_9",
        title="Ensure Azure RM Delete locks are applied to storage accounts",
        service="storage", severity="medium",
        subscription_id=config.subscription_id,
        reason="Resource lock requirements depend on organizational policy. Requires manual review.",
    )]

def evaluate_cis_9_3_10(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="9.3.10", check_id="azure_cis_9_3_10",
        title="Ensure Azure RM ReadOnly locks are considered for storage accounts",
        service="storage", severity="high",
        subscription_id=config.subscription_id,
        reason="ReadOnly lock requirements depend on organizational policy. Requires manual review.",
    )]


# ═════════════════════════════════════════════════════════════════
# CIS 9.1.2 — SMB protocol version 3.1.1
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_1_2(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for acct in list(clients.storage.storage_accounts.list()):
        rg = _rg_from_id(acct.id)
        try:
            file_services = list(clients.storage.file_services.list(rg, acct.name))
            for fs in file_services:
                smb = getattr(getattr(fs, "protocol_settings", None), "smb", None)
                versions = getattr(smb, "versions", None) if smb else None
                ok = versions and versions == "SMB3.1.1;"
                results.append(make_result(
                    cis_id="9.1.2", check_id="azure_cis_9_1_2",
                    title="Ensure SMB protocol version is set to SMB 3.1.1+",
                    service="storage", severity="medium",
                    status="PASS" if ok else "FAIL",
                    resource_id=acct.id, resource_name=acct.name, region=acct.location,
                    status_extended=f"Storage {acct.name}: SMB versions = {versions or 'all (default)'}",
                    remediation="Set SMB protocol version to SMB3.1.1 only.",
                    compliance_frameworks=FW,
                ))
        except Exception:
            pass
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.1.3 — SMB channel encryption AES-256-GCM
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_1_3(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for acct in list(clients.storage.storage_accounts.list()):
        rg = _rg_from_id(acct.id)
        try:
            file_services = list(clients.storage.file_services.list(rg, acct.name))
            for fs in file_services:
                smb = getattr(getattr(fs, "protocol_settings", None), "smb", None)
                enc = getattr(smb, "channel_encryption", None) if smb else None
                ok = enc and enc == "AES-256-GCM;"
                results.append(make_result(
                    cis_id="9.1.3", check_id="azure_cis_9_1_3",
                    title="Ensure SMB channel encryption is AES-256-GCM+",
                    service="storage", severity="high",
                    status="PASS" if ok else "FAIL",
                    resource_id=acct.id, resource_name=acct.name, region=acct.location,
                    status_extended=f"Storage {acct.name}: SMB encryption = {enc or 'all (default)'}",
                    remediation="Set SMB channel encryption to AES-256-GCM only.",
                    compliance_frameworks=FW,
                ))
        except Exception:
            pass
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.1.1 — Key rotation reminders enabled
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_1_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for acct in list(clients.storage.storage_accounts.list()):
        key_policy = getattr(acct, "key_policy", None)
        expiry_days = getattr(key_policy, "key_expiration_period_in_days", None) if key_policy else None
        ok = expiry_days is not None and expiry_days > 0
        results.append(make_result(
            cis_id="9.3.1.1", check_id="azure_cis_9_3_1_1",
            title="Ensure key rotation reminders are enabled",
            service="storage", severity="high",
            status="PASS" if ok else "FAIL",
            resource_id=acct.id, resource_name=acct.name, region=acct.location,
            status_extended=f"Storage {acct.name}: key expiration = {expiry_days or 'not set'} days",
            remediation="Set key rotation reminder to 90 days or less.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.1.2 — Keys periodically regenerated
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_1_2(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for acct in list(clients.storage.storage_accounts.list()):
        rg = _rg_from_id(acct.id)
        try:
            keys = clients.storage.storage_accounts.list_keys(rg, acct.name)
            for key in keys.keys:
                ct = getattr(key, "creation_time", None)
                if ct:
                    age = (datetime.now(timezone.utc) - ct).days
                    ok = age <= 90
                else:
                    age = "unknown"
                    ok = False
                results.append(make_result(
                    cis_id="9.3.1.2", check_id="azure_cis_9_3_1_2",
                    title="Ensure storage account keys are periodically regenerated",
                    service="storage", severity="high",
                    status="PASS" if ok else "FAIL",
                    resource_id=acct.id, resource_name=f"{acct.name}/{key.key_name}",
                    region=acct.location,
                    status_extended=f"Storage {acct.name} {key.key_name}: age = {age} days",
                    remediation="Rotate storage account access keys at least every 90 days.",
                    compliance_frameworks=FW,
                ))
        except Exception:
            pass
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.2.1 — Private endpoints for Storage Accounts
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_2_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for acct in list(clients.storage.storage_accounts.list()):
        pe = getattr(acct, "private_endpoint_connections", None) or []
        approved = [p for p in pe
                    if getattr(getattr(p, "private_link_service_connection_state", None),
                               "status", "") == "Approved"]
        results.append(make_result(
            cis_id="9.3.2.1", check_id="azure_cis_9_3_2_1",
            title="Ensure private endpoints are used for storage accounts",
            service="storage", severity="high",
            status="PASS" if approved else "FAIL",
            resource_id=acct.id, resource_name=acct.name, region=acct.location,
            status_extended=f"Storage {acct.name}: approved private endpoints = {len(approved)}",
            remediation="Configure private endpoints for the storage account.",
            compliance_frameworks=FW,
        ))
    return results


# ═════════════════════════════════════════════════════════════════
# CIS 9.3.3.1 — Default to Entra authorization in portal
# ═════════════════════════════════════════════════════════════════

def evaluate_cis_9_3_3_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for acct in list(clients.storage.storage_accounts.list()):
        oauth = getattr(acct, "default_to_o_auth_authentication", None)
        ok = oauth is True
        results.append(make_result(
            cis_id="9.3.3.1", check_id="azure_cis_9_3_3_1",
            title="Ensure default to Entra authorization in portal is enabled",
            service="storage", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=acct.id, resource_name=acct.name, region=acct.location,
            status_extended=f"Storage {acct.name}: defaultToOAuthAuthentication = {oauth}",
            remediation="Enable 'Default to Microsoft Entra authorization in the Azure portal'.",
            compliance_frameworks=FW,
        ))
    return results
