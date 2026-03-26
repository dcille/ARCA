"""CIS GCP v4.0 Section 2: Logging & Monitoring — 16 controls (2.1–2.16)."""
import logging
from .base import GCPClientCache, EvalConfig, make_result, make_manual_result
logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]

def evaluate_cis_2_1(c, cfg):
    try:
        policy = c.crm_policy()
        audit_cfgs = policy.get("auditConfigs",[])
        has_all = any(a.get("service")=="allServices" for a in audit_cfgs)
        return [make_result(cis_id="2.1",check_id="gcp_cis_2_1",title="Ensure Cloud Audit Logging is configured properly",service="logging",severity="high",status="PASS" if has_all else "FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"Data Access audit logs for allServices: {has_all}",remediation="Enable Data Access audit logs for allServices.",compliance_frameworks=FW)]
    except Exception as e:
        return [make_result(cis_id="2.1",check_id="gcp_cis_2_1",title="Ensure Cloud Audit Logging is configured properly",service="logging",severity="high",status="ERROR",resource_id=f"projects/{cfg.project_id}",status_extended=str(e),compliance_frameworks=FW)]

def evaluate_cis_2_2(c, cfg):
    try:
        sinks = list(c.logging_client.list_sinks())
        return [make_result(cis_id="2.2",check_id="gcp_cis_2_2",title="Ensure sinks are configured for all log entries",service="logging",severity="high",status="PASS" if sinks else "FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"Log sinks: {len(sinks)}",remediation="Create a log sink that exports all log entries.",compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="2.2",check_id="gcp_cis_2_2",title="Ensure sinks are configured for all log entries",service="logging",severity="high",status="ERROR",resource_id=f"projects/{cfg.project_id}",compliance_frameworks=FW)]

def evaluate_cis_2_3(c, cfg):
    results = []
    try:
        svc = c.api_service("logging","v2")
        resp = svc.projects().locations().buckets().list(parent=f"projects/{cfg.project_id}/locations/-").execute()
        for b in resp.get("buckets",[]):
            days = b.get("retentionDays",0)
            name = b.get("name","").split("/")[-1]
            results.append(make_result(cis_id="2.3",check_id="gcp_cis_2_3",title="Ensure retention policies on log export buckets",service="logging",severity="medium",status="PASS" if days >= 365 else "FAIL",resource_id=b.get("name",""),resource_name=name,status_extended=f"Log bucket {name}: {days} days retention (requires 365+)",remediation="Set log bucket retention to >= 365 days.",compliance_frameworks=FW))
    except Exception:
        pass
    return results

# 2.4–2.11: Metric filter controls — check CloudWatch-style log metrics
_METRIC_CONTROLS = [
    ("2.4","Ensure log metric filter and alerts for project ownership assignments","roles/owner"),
    ("2.5","Ensure log metric filter and alerts for audit config changes","SetIamPolicy"),
    ("2.6","Ensure log metric filter and alerts for custom role changes","iam_role"),
    ("2.7","Ensure log metric filter and alerts for VPC firewall rule changes","gce_firewall_rule"),
    ("2.8","Ensure log metric filter and alerts for VPC network route changes","gce_route"),
    ("2.9","Ensure log metric filter and alerts for VPC network changes","gce_network"),
    ("2.10","Ensure log metric filter and alerts for Cloud Storage IAM changes","storage.setIamPermissions"),
    ("2.11","Ensure log metric filter and alerts for SQL instance config changes","cloudsql.instances"),
]

def _make_metric_evaluator(cis_id, title, pattern):
    def evaluator(c, cfg):
        try:
            metrics = list(c.logging_client.list_metrics())
            found = any(pattern.lower() in (m.filter_ or "").lower() for m in metrics)
            return [make_result(cis_id=cis_id,check_id=f"gcp_cis_{cis_id.replace('.','_')}",title=title,service="logging",severity="medium",status="PASS" if found else "FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"Metric filter for '{pattern}': {'found' if found else 'not found'}",remediation=f"Create log metric filter containing '{pattern}' and configure alerting.",compliance_frameworks=FW)]
        except Exception:
            return [make_result(cis_id=cis_id,check_id=f"gcp_cis_{cis_id.replace('.','_')}",title=title,service="logging",severity="medium",status="ERROR",resource_id=f"projects/{cfg.project_id}",compliance_frameworks=FW)]
    return evaluator

for _cid, _title, _pat in _METRIC_CONTROLS:
    globals()[f"evaluate_cis_{_cid.replace('.','_')}"] = _make_metric_evaluator(_cid, _title, _pat)

def evaluate_cis_2_12(c, cfg):
    try:
        svc = c.api_service("dns","v1")
        policies = svc.policies().list(project=cfg.project_id).execute()
        enabled = any(p.get("enableLogging") for p in policies.get("policies",[]))
        return [make_result(cis_id="2.12",check_id="gcp_cis_2_12",title="Ensure Cloud DNS logging is enabled for all VPC networks",service="logging",severity="medium",status="PASS" if enabled else "FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"DNS logging via policy: {enabled}",remediation="Enable DNS logging via DNS policies.",compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="2.12",check_id="gcp_cis_2_12",title="Ensure Cloud DNS logging is enabled",service="logging",severity="medium",status="FAIL",resource_id=f"projects/{cfg.project_id}",compliance_frameworks=FW)]

def evaluate_cis_2_13(c, cfg):
    try:
        svc = c.api_service("cloudasset","v1")
        feeds = svc.feeds().list(parent=f"projects/{cfg.project_id}").execute()
        has = len(feeds.get("feeds",[])) > 0
        return [make_result(cis_id="2.13",check_id="gcp_cis_2_13",title="Ensure Cloud Asset Inventory is enabled",service="logging",severity="medium",status="PASS" if has else "FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"Cloud Asset Inventory feeds: {len(feeds.get('feeds',[]))}",remediation="Enable Cloud Asset Inventory.",compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="2.13",check_id="gcp_cis_2_13",title="Ensure Cloud Asset Inventory is enabled",service="logging",severity="medium",status="FAIL",resource_id=f"projects/{cfg.project_id}",compliance_frameworks=FW)]

def evaluate_cis_2_14(c, cfg):
    return [make_manual_result("2.14","gcp_cis_2_14","Ensure Access Transparency is enabled","logging","medium",cfg.project_id,"Access Transparency requires org-level verification.")]

def evaluate_cis_2_15(c, cfg):
    try:
        svc = c.api_service("accessapproval","v1")
        settings = svc.projects().getAccessApprovalSettings(name=f"projects/{cfg.project_id}/accessApprovalSettings").execute()
        enrolled = bool(settings.get("enrolledAncestor") or settings.get("enrolledServices"))
        return [make_result(cis_id="2.15",check_id="gcp_cis_2_15",title="Ensure Access Approval is enabled",service="logging",severity="medium",status="PASS" if enrolled else "FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"Access Approval enrolled: {enrolled}",remediation="Enable Access Approval.",compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="2.15",check_id="gcp_cis_2_15",title="Ensure Access Approval is enabled",service="logging",severity="medium",status="FAIL",resource_id=f"projects/{cfg.project_id}",compliance_frameworks=FW)]

def evaluate_cis_2_16(c, cfg):
    results = []
    try:
        svc = c.api_service("compute","v1")
        resp = svc.backendServices().aggregatedList(project=cfg.project_id).execute()
        for scope, data in resp.get("items",{}).items():
            for bs in data.get("backendServices",[]):
                log_on = bs.get("logConfig",{}).get("enable",False)
                results.append(make_result(cis_id="2.16",check_id="gcp_cis_2_16",title="Ensure logging is enabled for HTTP(S) Load Balancer",service="logging",severity="medium",status="PASS" if log_on else "FAIL",resource_id=bs.get("selfLink",bs.get("name","")),resource_name=bs.get("name",""),status_extended=f"Backend service {bs.get('name','')}: logging = {log_on}",remediation="Enable logging on load balancer backend services.",compliance_frameworks=FW))
    except Exception:
        pass
    return results
