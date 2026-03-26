"""CIS Azure v5.0 Section 6: Management & Governance (Logging/Monitoring) evaluators.

25 controls: 6.1.1.x (diagnostic settings), 6.1.2.x (activity log alerts),
             6.1.3.1 (App Insights), 6.1.4 (resource logging), 6.1.5 (SKUs), 6.2 (locks).
"""

import logging
from .base import AzureClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Azure-5.0", "MCSB-Azure-1.0"]


# ═══════════════════════════════════════════════════════════════
# 6.1.1.x — Diagnostic Settings
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_6_1_1_1(c, cfg):
    """Diagnostic setting exists for subscription activity logs."""
    try:
        diag = list(c.monitor.diagnostic_settings.list(
            resource_uri=f"/subscriptions/{cfg.subscription_id}"))
        return [make_result(cis_id="6.1.1.1", check_id="azure_cis_6_1_1_1",
            title="Ensure a Diagnostic Setting exists for Subscription Activity Logs",
            service="monitoring", severity="medium",
            status="PASS" if diag else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Subscription diagnostic settings: {len(diag)}",
            remediation="Create a diagnostic setting to export activity logs to Log Analytics, Storage, or Event Hub.",
            compliance_frameworks=FW)]
    except Exception as e:
        return [make_result(cis_id="6.1.1.1", check_id="azure_cis_6_1_1_1",
            title="Ensure a Diagnostic Setting exists for Subscription Activity Logs",
            service="monitoring", severity="medium", status="ERROR",
            resource_id=cfg.subscription_id,
            status_extended=f"Error querying diagnostic settings: {e}",
            compliance_frameworks=FW)]


def evaluate_cis_6_1_1_2(c, cfg):
    """Diagnostic Setting captures appropriate categories."""
    try:
        diag = list(c.monitor.diagnostic_settings.list(
            resource_uri=f"/subscriptions/{cfg.subscription_id}"))
        required = {"Administrative", "Alert", "Policy", "Security"}
        for ds in diag:
            enabled_cats = {l.category for l in (ds.logs or []) if l.enabled}
            if required.issubset(enabled_cats):
                return [make_result(cis_id="6.1.1.2", check_id="azure_cis_6_1_1_2",
                    title="Ensure Diagnostic Setting captures appropriate categories",
                    service="monitoring", severity="medium", status="PASS",
                    resource_id=ds.id or cfg.subscription_id, resource_name=ds.name,
                    status_extended=f"Setting '{ds.name}' captures: {', '.join(sorted(enabled_cats))}",
                    compliance_frameworks=FW)]
        return [make_result(cis_id="6.1.1.2", check_id="azure_cis_6_1_1_2",
            title="Ensure Diagnostic Setting captures appropriate categories",
            service="monitoring", severity="medium", status="FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"No diagnostic setting captures all required categories: {required}",
            remediation="Enable Administrative, Alert, Policy, and Security categories in a diagnostic setting.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="6.1.1.2", check_id="azure_cis_6_1_1_2",
            title="Ensure Diagnostic Setting captures appropriate categories",
            service="monitoring", severity="medium", status="ERROR",
            resource_id=cfg.subscription_id, status_extended="Error querying.",
            compliance_frameworks=FW)]


def evaluate_cis_6_1_1_3(c, cfg):
    return [make_manual_result(cis_id="6.1.1.3", check_id="azure_cis_6_1_1_3",
        title="Ensure activity log storage account is encrypted with CMK",
        service="monitoring", severity="high", subscription_id=cfg.subscription_id,
        reason="Requires identifying the storage account used by the diagnostic setting, then checking its encryption key source.")]


def evaluate_cis_6_1_1_4(c, cfg):
    """Key Vault logging enabled."""
    results = []
    try:
        vaults = list(c.keyvault_mgmt.vaults.list())
        for v in vaults:
            try:
                diag = list(c.monitor.diagnostic_settings.list(resource_uri=v.id))
                has_audit = any(
                    any(l.enabled and l.category_group in ("audit", "allLogs") for l in (d.logs or []))
                    for d in diag
                ) if diag else False
                results.append(make_result(cis_id="6.1.1.4", check_id="azure_cis_6_1_1_4",
                    title="Ensure logging for Azure Key Vault is enabled",
                    service="monitoring", severity="high",
                    status="PASS" if has_audit else "FAIL",
                    resource_id=v.id, resource_name=v.name,
                    status_extended=f"Key Vault {v.name}: audit logging = {has_audit}",
                    remediation="Configure diagnostic settings for the Key Vault with audit and allLogs categories.",
                    compliance_frameworks=FW))
            except Exception:
                pass
    except Exception:
        pass
    return results


def evaluate_cis_6_1_1_5(c, cfg):
    return [make_manual_result(cis_id="6.1.1.5", check_id="azure_cis_6_1_1_5",
        title="Ensure NSG flow logs are captured and sent to Log Analytics",
        service="monitoring", severity="high", subscription_id=cfg.subscription_id,
        reason="NSG flow logs being retired Sept 2027. Migrate to VNet flow logs (see 6.1.1.7).")]


def evaluate_cis_6_1_1_6(c, cfg):
    """AppService HTTP logging enabled."""
    results = []
    try:
        apps = list(c.web.web_apps.list())
        for app in apps:
            try:
                diag = list(c.monitor.diagnostic_settings.list(resource_uri=app.id))
                has_http = any(
                    any(l.enabled and "http" in (l.category or "").lower() for l in (d.logs or []))
                    for d in diag
                ) if diag else False
                results.append(make_result(cis_id="6.1.1.6", check_id="azure_cis_6_1_1_6",
                    title="Ensure AppService HTTP logs are enabled",
                    service="monitoring", severity="high",
                    status="PASS" if has_http else "FAIL",
                    resource_id=app.id, resource_name=app.name,
                    status_extended=f"App {app.name}: HTTP logging = {has_http}",
                    remediation="Enable AppServiceHTTPLogs diagnostic category.",
                    compliance_frameworks=FW))
            except Exception:
                pass
    except Exception:
        pass
    return results


def evaluate_cis_6_1_1_7(c, cfg):
    return [make_manual_result(cis_id="6.1.1.7", check_id="azure_cis_6_1_1_7",
        title="Ensure VNet flow logs are captured and sent to Log Analytics",
        service="monitoring", severity="high", subscription_id=cfg.subscription_id,
        reason="Requires checking Network Watcher flow logs targeting VNet resources with traffic analytics enabled.")]

def evaluate_cis_6_1_1_8(c, cfg):
    return [make_manual_result(cis_id="6.1.1.8", check_id="azure_cis_6_1_1_8",
        title="Ensure Entra diagnostic sends Microsoft Graph activity logs",
        service="monitoring", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires checking Entra ID > Monitoring > Diagnostic settings for MicrosoftGraphActivityLogs.")]

def evaluate_cis_6_1_1_9(c, cfg):
    return [make_manual_result(cis_id="6.1.1.9", check_id="azure_cis_6_1_1_9",
        title="Ensure Entra diagnostic sends activity logs to appropriate destination",
        service="monitoring", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires checking Entra ID > Monitoring > Diagnostic settings for all activity log categories.")]

def evaluate_cis_6_1_1_10(c, cfg):
    return [make_manual_result(cis_id="6.1.1.10", check_id="azure_cis_6_1_1_10",
        title="Ensure Intune logs are captured and sent to Log Analytics",
        service="monitoring", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires Intune license and checking Intune > Reports > Diagnostic settings.")]


# ═══════════════════════════════════════════════════════════════
# 6.1.2.x — Activity Log Alerts
# ═══════════════════════════════════════════════════════════════

def _check_activity_alert(c, cfg, cis_id, check_id, title, operation_name):
    """Generic activity log alert checker."""
    try:
        alerts = list(c.monitor.activity_log_alerts.list_by_subscription_id())
        found = False
        for alert in alerts:
            if not alert.enabled:
                continue
            for cond in (alert.condition.all_of if alert.condition else []):
                if getattr(cond, "equals", "") == operation_name:
                    found = True
                    break
            if found:
                break
        return [make_result(cis_id=cis_id, check_id=check_id, title=title,
            service="monitoring", severity="medium",
            status="PASS" if found else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Activity log alert for {operation_name}: {'found' if found else 'NOT found'}",
            remediation=f"Create an activity log alert for the operation: {operation_name}",
            compliance_frameworks=FW)]
    except Exception as e:
        return [make_result(cis_id=cis_id, check_id=check_id, title=title,
            service="monitoring", severity="medium", status="ERROR",
            resource_id=cfg.subscription_id, status_extended=str(e),
            compliance_frameworks=FW)]


def evaluate_cis_6_1_2_1(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.1", "azure_cis_6_1_2_1",
        "Ensure alert exists for Create Policy Assignment",
        "Microsoft.Authorization/policyAssignments/write")

def evaluate_cis_6_1_2_2(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.2", "azure_cis_6_1_2_2",
        "Ensure alert exists for Delete Policy Assignment",
        "Microsoft.Authorization/policyAssignments/delete")

def evaluate_cis_6_1_2_3(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.3", "azure_cis_6_1_2_3",
        "Ensure alert exists for Create/Update NSG",
        "Microsoft.Network/networkSecurityGroups/write")

def evaluate_cis_6_1_2_4(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.4", "azure_cis_6_1_2_4",
        "Ensure alert exists for Delete NSG",
        "Microsoft.Network/networkSecurityGroups/delete")

def evaluate_cis_6_1_2_5(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.5", "azure_cis_6_1_2_5",
        "Ensure alert exists for Create/Update Security Solution",
        "Microsoft.Security/securitySolutions/write")

def evaluate_cis_6_1_2_6(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.6", "azure_cis_6_1_2_6",
        "Ensure alert exists for Delete Security Solution",
        "Microsoft.Security/securitySolutions/delete")

def evaluate_cis_6_1_2_7(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.7", "azure_cis_6_1_2_7",
        "Ensure alert exists for Create/Update SQL Server Firewall Rule",
        "Microsoft.Sql/servers/firewallRules/write")

def evaluate_cis_6_1_2_8(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.8", "azure_cis_6_1_2_8",
        "Ensure alert exists for Delete SQL Server Firewall Rule",
        "Microsoft.Sql/servers/firewallRules/delete")

def evaluate_cis_6_1_2_9(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.9", "azure_cis_6_1_2_9",
        "Ensure alert exists for Create/Update Public IP Address",
        "Microsoft.Network/publicIPAddresses/write")

def evaluate_cis_6_1_2_10(c, cfg):
    return _check_activity_alert(c, cfg, "6.1.2.10", "azure_cis_6_1_2_10",
        "Ensure alert exists for Delete Public IP Address",
        "Microsoft.Network/publicIPAddresses/delete")


def evaluate_cis_6_1_2_11(c, cfg):
    """Alert exists for Service Health."""
    try:
        alerts = list(c.monitor.activity_log_alerts.list_by_subscription_id())
        found = any(
            alert.enabled and any(
                getattr(cond, "equals", "") == "ServiceHealth"
                for cond in (alert.condition.all_of if alert.condition else [])
            )
            for alert in alerts
        )
        return [make_result(cis_id="6.1.2.11", check_id="azure_cis_6_1_2_11",
            title="Ensure alert exists for Service Health",
            service="monitoring", severity="medium",
            status="PASS" if found else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Service Health alert: {'found' if found else 'NOT found'}",
            remediation="Create an activity log alert for Service Health events.",
            compliance_frameworks=FW)]
    except Exception as e:
        return [make_result(cis_id="6.1.2.11", check_id="azure_cis_6_1_2_11",
            title="Ensure alert exists for Service Health",
            service="monitoring", severity="medium", status="ERROR",
            resource_id=cfg.subscription_id, status_extended=str(e),
            compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 6.1.3.1 — Application Insights
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_6_1_3_1(c, cfg):
    """Application Insights configured."""
    try:
        from azure.mgmt.applicationinsights import ApplicationInsightsManagementClient
        ai = c._get_or_create("appinsights",
            lambda: ApplicationInsightsManagementClient(c.credential, cfg.subscription_id))
        components = list(ai.components.list())
        return [make_result(cis_id="6.1.3.1", check_id="azure_cis_6_1_3_1",
            title="Ensure Application Insights are configured",
            service="monitoring", severity="high",
            status="PASS" if components else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Application Insights instances: {len(components)}",
            remediation="Create an Application Insights resource connected to a Log Analytics workspace.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="6.1.3.1", check_id="azure_cis_6_1_3_1",
            title="Ensure Application Insights are configured",
            service="monitoring", severity="high", status="ERROR",
            resource_id=cfg.subscription_id,
            status_extended="Could not query Application Insights (SDK may not be installed).",
            compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 6.1.4, 6.1.5, 6.2 — General governance
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_6_1_4(c, cfg):
    return [make_manual_result(cis_id="6.1.4", check_id="azure_cis_6_1_4",
        title="Ensure Azure Monitor Resource Logging is enabled for all services",
        service="monitoring", severity="high", subscription_id=cfg.subscription_id,
        reason="Requires iterating every resource and checking for diagnostic settings. Org-specific scoping needed.")]

def evaluate_cis_6_1_5(c, cfg):
    return [make_manual_result(cis_id="6.1.5", check_id="azure_cis_6_1_5",
        title="Ensure Basic/Consumption SKU is not used on production artifacts",
        service="general", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires identifying production workloads and verifying their SKU tiers.")]

def evaluate_cis_6_2(c, cfg):
    return [make_manual_result(cis_id="6.2", check_id="azure_cis_6_2",
        title="Ensure Resource Locks are set for mission-critical resources",
        service="general", severity="medium", subscription_id=cfg.subscription_id,
        reason="Identifying mission-critical resources requires organizational context.")]
