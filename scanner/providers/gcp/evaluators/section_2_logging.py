"""CIS GCP v4.0 Section 2: Logging and Monitoring — 16 controls.

Coverage:
  2.1  Cloud Audit Logging configured  automated
  2.2  Log sinks configured            automated
  2.3  Retention policy on log buckets  automated
  2.4  Log metric: project ownership    automated
  2.5  Log metric: audit config changes automated
  2.6  Log metric: custom role changes  automated
  2.7  Log metric: firewall rule changes automated
  2.8  Log metric: route changes        automated
  2.9  Log metric: VPC network changes  automated
  2.10 Log metric: storage IAM changes  automated
  2.11 Log metric: SQL config changes   automated
  2.12 Cloud DNS logging enabled        automated
  2.13 Cloud Asset Inventory enabled    automated
  2.14 Access Approval enabled          manual
  2.15 Load Balancer logging enabled    automated
  2.16 VPC flow logs enabled            automated
"""

import logging

from .base import GCPClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]


# Helper: check if a metric filter exists matching a given filter pattern
def _check_metric_filter(c: GCPClientCache, cfg: EvalConfig, cis_id: str,
                         check_id: str, title: str, filter_pattern: str) -> list[dict]:
    """Check if a log-based metric with the given filter pattern exists."""
    try:
        metrics = list(c.logging_metrics.list_log_metrics(
            request={"parent": f"projects/{cfg.project_id}"}
        ))
    except Exception:
        metrics = []

    found = False
    for metric in metrics:
        if filter_pattern in (metric.filter or ""):
            found = True
            break

    return [make_result(
        cis_id=cis_id, check_id=check_id, title=title,
        service="logging", severity="medium",
        status="PASS" if found else "FAIL",
        resource_id=cfg.project_id,
        status_extended=(
            f"Log metric filter found matching: {filter_pattern[:80]}..."
            if found else f"No log metric filter found for: {filter_pattern[:80]}..."
        ),
        remediation=f"Create a log-based metric with filter: {filter_pattern[:120]}",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.1 — Cloud Audit Logging enabled for all services
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    body = {"options": {"requestedPolicyVersion": 3}}
    policy = c.crm_v1.projects().getIamPolicy(resource=cfg.project_id, body=body).execute()

    audit_configs = policy.get("auditConfigs", [])
    has_all_services = any(
        ac.get("service") == "allServices" for ac in audit_configs
    )

    return [make_result(
        cis_id="2.1", check_id="gcp_cis_2_1",
        title="Ensure Cloud Audit Logging Is Configured Properly",
        service="logging", severity="high",
        status="PASS" if has_all_services else "FAIL",
        resource_id=cfg.project_id,
        status_extended=(
            "Audit logging configured for allServices"
            if has_all_services else "Audit logging NOT configured for allServices"
        ),
        remediation="Enable Data Access audit logs for all services in IAM > Audit Logs.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.2 — Log sinks configured for all log entries
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        sinks = list(c.logging_client.list_sinks())
    except Exception:
        sinks = []

    has_export = any(not getattr(s, "filter_", "") for s in sinks)

    return [make_result(
        cis_id="2.2", check_id="gcp_cis_2_2",
        title="Ensure That Sinks Are Configured for All Log Entries",
        service="logging", severity="medium",
        status="PASS" if has_export else "FAIL",
        resource_id=cfg.project_id,
        status_extended=(
            "A log sink with no filter (exports all) exists"
            if has_export else "No log sink exporting all log entries found"
        ),
        remediation="Create a log sink with an empty filter to export all entries.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.3 — Retention policy on log buckets
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        from google.cloud.logging_v2 import ConfigServiceV2Client
        config_client = ConfigServiceV2Client(credentials=c.credentials)
        buckets = list(config_client.list_buckets(
            request={"parent": f"projects/{cfg.project_id}/locations/-"}
        ))
    except Exception:
        buckets = []

    for bucket in buckets:
        retention = getattr(bucket, "retention_days", 0)
        locked = getattr(bucket, "locked", False)
        ok = retention >= 365 and locked
        results.append(make_result(
            cis_id="2.3", check_id="gcp_cis_2_3",
            title="Ensure That Retention Policies on Log Buckets Are Configured Using Bucket Lock",
            service="logging", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=bucket.name,
            status_extended=f"Bucket {bucket.name}: retention={retention}d, locked={locked}",
            remediation="Set retention >= 365 days and enable Bucket Lock on log buckets.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="2.3", check_id="gcp_cis_2_3",
            title="Ensure Retention Policies on Log Buckets with Bucket Lock",
            service="logging", severity="medium", status="N/A",
            resource_id=cfg.project_id,
            status_extended="No log buckets found. Control not applicable.",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 2.4–2.11 — Log metric filter controls
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.4", "gcp_cis_2_4",
        "Ensure Log Metric Filter and Alerts Exist for Project Ownership Changes",
        'protoPayload.serviceName="cloudresourcemanager.googleapis.com"')

def evaluate_cis_2_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.5", "gcp_cis_2_5",
        "Ensure Log Metric Filter and Alerts Exist for Audit Configuration Changes",
        'protoPayload.methodName="SetIamPolicy"')

def evaluate_cis_2_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.6", "gcp_cis_2_6",
        "Ensure Log Metric Filter and Alerts Exist for Custom Role Changes",
        'resource.type="iam_role"')

def evaluate_cis_2_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.7", "gcp_cis_2_7",
        "Ensure Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes",
        'resource.type="gce_firewall_rule"')

def evaluate_cis_2_8(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.8", "gcp_cis_2_8",
        "Ensure Log Metric Filter and Alerts Exist for VPC Network Route Changes",
        'resource.type="gce_route"')

def evaluate_cis_2_9(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.9", "gcp_cis_2_9",
        "Ensure Log Metric Filter and Alerts Exist for VPC Network Changes",
        'resource.type="gce_network"')

def evaluate_cis_2_10(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.10", "gcp_cis_2_10",
        "Ensure Log Metric Filter and Alerts Exist for Cloud Storage IAM Permission Changes",
        'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"')

def evaluate_cis_2_11(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_metric_filter(c, cfg, "2.11", "gcp_cis_2_11",
        "Ensure Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes",
        'protoPayload.methodName="cloudsql.instances.update"')


# ═══════════════════════════════════════════════════════════════
# 2.12 — Cloud DNS logging enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_12(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        resp = c.dns.managedZones().list(project=cfg.project_id).execute()
        zones = resp.get("managedZones", [])
    except Exception:
        zones = []

    for zone in zones:
        dns_name = zone.get("name", "")
        logging_config = zone.get("cloudLoggingConfig", {})
        enabled = logging_config.get("enableLogging", False)
        results.append(make_result(
            cis_id="2.12", check_id="gcp_cis_2_12",
            title="Ensure That Cloud DNS Logging Is Enabled for All VPC Networks",
            service="logging", severity="medium",
            status="PASS" if enabled else "FAIL",
            resource_id=dns_name, resource_name=dns_name,
            status_extended=f"DNS zone '{dns_name}': logging={'enabled' if enabled else 'disabled'}",
            remediation="Enable Cloud DNS logging: gcloud dns managed-zones update ZONE --log-dns-queries",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="2.12", check_id="gcp_cis_2_12",
            title="Ensure That Cloud DNS Logging Is Enabled for All VPC Networks",
            service="logging", severity="medium", status="N/A",
            resource_id=cfg.project_id,
            status_extended="No DNS managed zones found. Control not applicable.",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 2.13 — Cloud Asset Inventory enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_13(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        svc = c.discovery_client("cloudasset", "v1")
        feed_list = svc.feeds().list(parent=f"projects/{cfg.project_id}").execute()
        feeds = feed_list.get("feeds", [])
        ok = len(feeds) > 0
    except Exception:
        ok = False

    return [make_result(
        cis_id="2.13", check_id="gcp_cis_2_13",
        title="Ensure Cloud Asset Inventory Is Enabled",
        service="logging", severity="medium",
        status="PASS" if ok else "FAIL",
        resource_id=cfg.project_id,
        status_extended=(
            "Cloud Asset Inventory feeds configured"
            if ok else "No Cloud Asset Inventory feeds found"
        ),
        remediation="Enable Cloud Asset Inventory and create feeds for asset monitoring.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 2.14 — Access Approval enabled (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_14(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.14", "gcp_cis_2_14",
        "Ensure Access Approval Is Enabled",
        "logging", "medium", cfg.project_id,
        "Access Approval settings must be verified in the Console under "
        "Security > Access Approval.")]


# ═══════════════════════════════════════════════════════════════
# 2.15 — Load Balancer logging enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_15(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        from google.cloud.compute_v1 import BackendServicesClient
        bs_client = BackendServicesClient(credentials=c.credentials)
        backends = list(bs_client.aggregated_list(request={"project": cfg.project_id}))
    except Exception:
        backends = []

    for scope_key, scope_val in backends:
        for bs in getattr(scope_val, "backend_services", []) or []:
            log_config = getattr(bs, "log_config", None)
            enabled = log_config and getattr(log_config, "enable", False)
            results.append(make_result(
                cis_id="2.15", check_id="gcp_cis_2_15",
                title="Ensure Logging Is Enabled for HTTP(S) Load Balancer",
                service="logging", severity="medium",
                status="PASS" if enabled else "FAIL",
                resource_id=bs.self_link or bs.name,
                resource_name=bs.name,
                status_extended=f"Backend service '{bs.name}': logging={'enabled' if enabled else 'disabled'}",
                remediation="Enable logging on backend service: set logConfig.enable=true.",
                compliance_frameworks=FW,
            ))

    if not results:
        return [make_result(cis_id="2.15", check_id="gcp_cis_2_15",
            title="Ensure Logging Is Enabled for HTTP(S) Load Balancer",
            service="logging", severity="medium", status="N/A",
            resource_id=cfg.project_id,
            status_extended="No backend services found. Control not applicable.",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 2.16 — VPC Flow Logs enabled for every subnet
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_2_16(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        subnets_agg = c.compute_subnetworks.aggregated_list(request={"project": cfg.project_id})
        for region_key, scoped in subnets_agg:
            for subnet in getattr(scoped, "subnetworks", []) or []:
                log_config = getattr(subnet, "log_config", None)
                enabled = log_config and getattr(log_config, "enable", False)
                results.append(make_result(
                    cis_id="2.16", check_id="gcp_cis_2_16",
                    title="Ensure That VPC Flow Logs Is Enabled for Every Subnet in a VPC Network",
                    service="logging", severity="medium",
                    status="PASS" if enabled else "FAIL",
                    resource_id=subnet.self_link or subnet.name,
                    resource_name=subnet.name,
                    region=getattr(subnet, "region", "").split("/")[-1],
                    status_extended=f"Subnet '{subnet.name}': flow logs={'enabled' if enabled else 'disabled'}",
                    remediation="Enable VPC Flow Logs: gcloud compute networks subnets update SUBNET --enable-flow-logs",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("Error listing subnets for flow logs check: %s", e)

    if not results:
        return [make_result(cis_id="2.16", check_id="gcp_cis_2_16",
            title="Ensure That VPC Flow Logs Is Enabled for Every Subnet",
            service="logging", severity="medium", status="N/A",
            resource_id=cfg.project_id,
            status_extended="No subnets found. Control not applicable.",
            compliance_frameworks=FW)]
    return results
