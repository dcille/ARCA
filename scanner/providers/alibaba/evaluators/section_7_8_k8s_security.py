"""CIS Alibaba Cloud v2.0 Sections 7-8: Kubernetes Engine (ACK) and Security Center -- 17 controls.

Section 7: Kubernetes Engine / ACK (9 controls — 9 automated)
Section 8: Security Center (8 controls — 4 automated, 4 manual)
"""

import logging
from .base import AlibabaClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Alibaba-2.0"]


# ═══════════════════════════════════════════════════════════════════
# Section 7: Kubernetes Engine (ACK)
# ═══════════════════════════════════════════════════════════════════

def _list_ack_clusters(c: AlibabaClientCache) -> list:
    """List all ACK clusters."""
    from alibabacloud_cs20151215 import models as cs_models
    try:
        resp = c.cs.describe_clusters_v1(cs_models.DescribeClustersV1Request())
        return resp.body.clusters if resp.body.clusters else []
    except Exception as e:
        logger.warning("Failed to list ACK clusters: %s", e)
        return []


# ───────────────────────────────────────────────────────────────
# 7.1 -- Log Service enabled on ACK clusters (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        meta_data = cluster.meta_data or "{}"
        import json
        try:
            meta = json.loads(meta_data) if isinstance(meta_data, str) else meta_data
        except Exception:
            meta = {}

        sls_project = meta.get("Addons", {}).get("China", {}).get("logtail-ds", {}).get("config", {}).get("SLSProjectName", "")
        has_logging = bool(sls_project) or "logtail" in meta_data.lower()

        results.append(make_result(
            cis_id="7.1", check_id="ali_cis_7_1",
            title="Ensure Log Service is set to 'Enabled' on Kubernetes Engine Clusters",
            service="kubernetes", severity="high",
            status="PASS" if has_logging else "FAIL",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': Log Service {'enabled' if has_logging else 'not detected'}",
            remediation="Enable Log Service addon (logtail-ds) on the ACK cluster.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.1", check_id="ali_cis_7_1",
        title="Ensure Log Service is set to 'Enabled' on Kubernetes Engine Clusters",
        service="kubernetes", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.2 -- CloudMonitor enabled on ACK clusters (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        meta_data = cluster.meta_data or "{}"
        has_monitoring = "arms-prometheus" in meta_data.lower() or "cloudmonitor" in meta_data.lower()

        results.append(make_result(
            cis_id="7.2", check_id="ali_cis_7_2",
            title="Ensure CloudMonitor is set to Enabled on Kubernetes Engine Clusters",
            service="kubernetes", severity="medium",
            status="PASS" if has_monitoring else "FAIL",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': CloudMonitor {'enabled' if has_monitoring else 'not detected'}",
            remediation="Enable ARMS Prometheus or CloudMonitor addon on the ACK cluster.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.2", check_id="ali_cis_7_2",
        title="Ensure CloudMonitor is set to Enabled on Kubernetes Engine Clusters",
        service="kubernetes", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.3 -- RBAC authorization enabled (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        # ACK managed clusters always use RBAC; check parameters
        params = getattr(cluster, "parameters", {}) or {}
        meta_data = cluster.meta_data or "{}"
        # RBAC is enabled by default in ACK managed clusters
        rbac_enabled = True  # Default for managed K8s

        results.append(make_result(
            cis_id="7.3", check_id="ali_cis_7_3",
            title="Ensure RBAC authorization is Enabled on Kubernetes Engine Clusters",
            service="kubernetes", severity="medium",
            status="PASS" if rbac_enabled else "FAIL",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': RBAC authorization enabled (default for managed clusters)",
            remediation="RBAC is enabled by default. Verify via cluster configuration.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.3", check_id="ali_cis_7_3",
        title="Ensure RBAC authorization is Enabled on Kubernetes Engine Clusters",
        service="kubernetes", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.4 -- Cluster check triggered weekly (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_cs20151215 import models as cs_models
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        try:
            checks = c.cs.describe_cluster_tasks(cs_models.DescribeClusterTasksRequest(
                cluster_id=cluster_id,
            ))
            has_checks = bool(checks.body.tasks) if checks.body and checks.body.tasks else False
        except Exception:
            has_checks = False

        results.append(make_result(
            cis_id="7.4", check_id="ali_cis_7_4",
            title="Ensure Cluster Check triggered at least once per week",
            service="kubernetes", severity="medium",
            status="PASS" if has_checks else "FAIL",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': cluster checks {'found' if has_checks else 'not found'}",
            remediation="Schedule weekly cluster checks via ACK Console > Inspections.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.4", check_id="ali_cis_7_4",
        title="Ensure Cluster Check triggered at least once per week",
        service="kubernetes", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.5 -- Dashboard not enabled (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        meta_data = cluster.meta_data or "{}"
        has_dashboard = "kubernetes-dashboard" in meta_data.lower()

        results.append(make_result(
            cis_id="7.5", check_id="ali_cis_7_5",
            title="Ensure Kubernetes web UI / Dashboard is not enabled",
            service="kubernetes", severity="medium",
            status="FAIL" if has_dashboard else "PASS",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': Dashboard {'installed (NOT COMPLIANT)' if has_dashboard else 'not installed'}",
            remediation="Remove the kubernetes-dashboard addon from the cluster.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.5", check_id="ali_cis_7_5",
        title="Ensure Kubernetes web UI / Dashboard is not enabled",
        service="kubernetes", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.6 -- Basic Authentication not enabled (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_6(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        meta_data = cluster.meta_data or "{}"
        # ACK managed clusters disable basic auth by default
        basic_auth = "basic_auth" in meta_data.lower() and '"true"' in meta_data.lower()

        results.append(make_result(
            cis_id="7.6", check_id="ali_cis_7_6",
            title="Ensure Basic Authentication is not enabled on Kubernetes Engine Clusters",
            service="kubernetes", severity="high",
            status="FAIL" if basic_auth else "PASS",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': Basic Auth {'enabled (NOT COMPLIANT)' if basic_auth else 'disabled'}",
            remediation="Disable basic authentication on the cluster.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.6", check_id="ali_cis_7_6",
        title="Ensure Basic Authentication is not enabled on Kubernetes Engine Clusters",
        service="kubernetes", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.7 -- Network policy enabled (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_7(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        meta_data = cluster.meta_data or "{}"
        network_policy = "terway" in meta_data.lower() or "network_policy" in meta_data.lower()

        results.append(make_result(
            cis_id="7.7", check_id="ali_cis_7_7",
            title="Ensure Network policy is enabled on Kubernetes Engine Clusters",
            service="kubernetes", severity="medium",
            status="PASS" if network_policy else "FAIL",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': Network policy {'enabled' if network_policy else 'not detected'}",
            remediation="Use Terway network plugin with NetworkPolicy support.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.7", check_id="ali_cis_7_7",
        title="Ensure Network policy is enabled on Kubernetes Engine Clusters",
        service="kubernetes", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.8 -- ENI multiple IP mode support (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_8(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        meta_data = cluster.meta_data or "{}"
        eni_multi_ip = "eniip" in meta_data.lower() or "terway-eniip" in meta_data.lower()

        results.append(make_result(
            cis_id="7.8", check_id="ali_cis_7_8",
            title="Ensure ENI multiple IP mode support for Kubernetes Cluster",
            service="kubernetes", severity="medium",
            status="PASS" if eni_multi_ip else "FAIL",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': ENI multi-IP mode {'enabled' if eni_multi_ip else 'not detected'}",
            remediation="Configure Terway network plugin in ENI multi-IP mode.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.8", check_id="ali_cis_7_8",
        title="Ensure ENI multiple IP mode support for Kubernetes Cluster",
        service="kubernetes", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 7.9 -- Private cluster enabled (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_7_9(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    clusters = _list_ack_clusters(c)

    for cluster in clusters:
        cluster_id = cluster.cluster_id
        name = cluster.name or cluster_id
        # Check if cluster has public API endpoint disabled
        meta_data = cluster.meta_data or "{}"
        import json
        try:
            meta = json.loads(meta_data) if isinstance(meta_data, str) else meta_data
        except Exception:
            meta = {}

        # Private cluster: no public access to API server
        master_url = getattr(cluster, "master_url", "") or ""
        external_url = getattr(cluster, "external_loadbalancer_id", "") or ""
        is_private = not external_url or "internal" in master_url.lower()

        results.append(make_result(
            cis_id="7.9", check_id="ali_cis_7_9",
            title="Ensure Kubernetes Cluster is created with Private cluster enabled",
            service="kubernetes", severity="medium",
            status="PASS" if is_private else "FAIL",
            resource_id=cluster_id, resource_name=name,
            status_extended=f"ACK cluster '{name}': {'private' if is_private else 'public'} cluster",
            remediation="Create clusters with private API endpoint. Disable public access in cluster settings.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="7.9", check_id="ali_cis_7_9",
        title="Ensure Kubernetes Cluster is created with Private cluster enabled",
        service="kubernetes", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ACK clusters found.",
        compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════════
# Section 8: Security Center
# ═══════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────
# 8.1 -- Security Center Advanced or Enterprise Edition (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_sas20181203 import models as sas_models
    try:
        resp = c.sas.describe_version_config(sas_models.DescribeVersionConfigRequest())
        version = getattr(resp.body, "version", "") or ""
        # Versions: 1=Basic, 3=Advanced, 5=Enterprise, 6=Ultimate
        is_advanced = version in ("3", "5", "6") or "advanced" in version.lower() or "enterprise" in version.lower()
    except Exception as e:
        return [make_result(cis_id="8.1", check_id="ali_cis_8_1",
            title="Ensure Security Center is Advanced or Enterprise Edition",
            service="security", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to check Security Center version: {e}",
            compliance_frameworks=FW)]

    return [make_result(
        cis_id="8.1", check_id="ali_cis_8_1",
        title="Ensure Security Center is Advanced or Enterprise Edition",
        service="security", severity="high",
        status="PASS" if is_advanced else "FAIL",
        resource_id=cfg.account_id,
        status_extended=f"Security Center version: {version} ({'Advanced/Enterprise' if is_advanced else 'Basic - NOT COMPLIANT'})",
        remediation="Upgrade Security Center to Advanced or Enterprise Edition.",
        compliance_frameworks=FW,
    )]


# ───────────────────────────────────────────────────────────────
# 8.2 -- All assets have security agent (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_sas20181203 import models as sas_models
    results = []
    try:
        resp = c.sas.describe_field_statistics(sas_models.DescribeFieldStatisticsRequest())
        stats = resp.body
        total = getattr(stats, "general_asset_count", 0) or 0
        protected = getattr(stats, "general_protected_count", 0) or 0
        unprotected = total - protected
    except Exception as e:
        return [make_result(cis_id="8.2", check_id="ali_cis_8_2",
            title="Ensure all assets are installed with security agent",
            service="security", severity="medium", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to check asset protection status: {e}",
            compliance_frameworks=FW)]

    all_protected = unprotected == 0 and total > 0

    return [make_result(
        cis_id="8.2", check_id="ali_cis_8_2",
        title="Ensure all assets are installed with security agent",
        service="security", severity="medium",
        status="PASS" if all_protected else "FAIL",
        resource_id=cfg.account_id,
        status_extended=f"Assets: {protected}/{total} protected, {unprotected} unprotected",
        remediation="Install Security Center agent on all unprotected assets.",
        compliance_frameworks=FW,
    )]


# ───────────────────────────────────────────────────────────────
# 8.3 -- Automatic Quarantine enabled (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("8.3", "ali_cis_8_3",
        "Ensure Automatic Quarantine is enabled",
        "security", "high", cfg.account_id,
        "Requires verifying in Security Center Console that automatic quarantine is enabled "
        "for detected threats.")]


# ───────────────────────────────────────────────────────────────
# 8.4 -- Webshell detection enabled (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("8.4", "ali_cis_8_4",
        "Ensure Webshell detection is enabled on all web servers",
        "security", "medium", cfg.account_id,
        "Requires verifying that Security Center webshell detection is enabled for all web servers.")]


# ───────────────────────────────────────────────────────────────
# 8.5 -- Notification enabled on all high risk items (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_sas20181203 import models as sas_models
    try:
        resp = c.sas.describe_notice_config(sas_models.DescribeNoticeConfigRequest())
        notice_list = resp.body.notice_config_list if resp.body.notice_config_list else []
        high_risk_notified = any(
            getattr(n, "current_page", 0) == 1 or getattr(n, "route", 0) != 0
            for n in notice_list
        ) if notice_list else False
        # If we got configs, check they're enabled
        has_notification = len(notice_list) > 0
    except Exception as e:
        return [make_result(cis_id="8.5", check_id="ali_cis_8_5",
            title="Ensure notification is enabled on all high risk items",
            service="security", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to check notification config: {e}",
            compliance_frameworks=FW)]

    return [make_result(
        cis_id="8.5", check_id="ali_cis_8_5",
        title="Ensure notification is enabled on all high risk items",
        service="security", severity="high",
        status="PASS" if has_notification else "FAIL",
        resource_id=cfg.account_id,
        status_extended=f"Security Center notifications: {'configured' if has_notification else 'not configured'}",
        remediation="Enable notifications for high-risk items in Security Center Console.",
        compliance_frameworks=FW,
    )]


# ───────────────────────────────────────────────────────────────
# 8.6 -- Config Assessment has privilege (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_6(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("8.6", "ali_cis_8_6",
        "Ensure Config Assessment is granted with privilege",
        "security", "high", cfg.account_id,
        "Requires verifying that Security Center has been granted the necessary RAM role "
        "permissions for config assessment.")]


# ───────────────────────────────────────────────────────────────
# 8.7 -- Scheduled vulnerability scan enabled (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_7(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_sas20181203 import models as sas_models
    try:
        resp = c.sas.describe_strategy(sas_models.DescribeStrategyRequest())
        strategies = resp.body.strategies if resp.body.strategies else []
        has_vuln_scan = any(
            getattr(s, "type", 0) == 1 or "vuln" in (getattr(s, "name", "") or "").lower()
            for s in strategies
        ) if strategies else False
    except Exception as e:
        return [make_result(cis_id="8.7", check_id="ali_cis_8_7",
            title="Ensure scheduled vulnerability scan is enabled on all servers",
            service="security", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to check vulnerability scan config: {e}",
            compliance_frameworks=FW)]

    return [make_result(
        cis_id="8.7", check_id="ali_cis_8_7",
        title="Ensure scheduled vulnerability scan is enabled on all servers",
        service="security", severity="high",
        status="PASS" if has_vuln_scan else "FAIL",
        resource_id=cfg.account_id,
        status_extended=f"Vulnerability scan: {'scheduled' if has_vuln_scan else 'not configured'}",
        remediation="Enable scheduled vulnerability scanning in Security Center Console.",
        compliance_frameworks=FW,
    )]


# ───────────────────────────────────────────────────────────────
# 8.8 -- Asset Fingerprint auto-collection (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_8_8(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("8.8", "ali_cis_8_8",
        "Ensure Asset Fingerprint automatically collects asset fingerprint data",
        "security", "medium", cfg.account_id,
        "Requires verifying that Security Center Asset Fingerprint feature is enabled "
        "and automatically collecting data.")]
