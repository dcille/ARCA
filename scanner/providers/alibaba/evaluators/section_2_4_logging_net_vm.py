"""CIS Alibaba v2.0 Sections 2–4.

Section 2 — Logging and Monitoring (23 controls): 2.1-2.2 automated, 2.3-2.23 manual
Section 3 — Networking (5 controls): all manual
Section 4 — Virtual Machines (6 controls): all manual
"""
from __future__ import annotations
from .base import (AlibabaClientCache, EvalConfig, make_result, make_manual_result, logger)


# ═════════════════════════════════════════════════════════════════
# Section 2: Logging and Monitoring
# ═════════════════════════════════════════════════════════════════

def evaluate_2_1(c: AlibabaClientCache, cfg: EvalConfig):
    """ActionTrail configured to export all log entries."""
    from alibabacloud_actiontrail20200706 import models as m
    trails = c.actiontrail.describe_trails(m.DescribeTrailsRequest()).body.trail_list or []
    multi_region = any(t.trail_region == "All" for t in trails)
    active = any(getattr(t, 'status', '') == "Enable" for t in trails)
    return [make_result("2.1", "ActionTrail configured to export all log entries",
        "actiontrail", "ActionTrail", bool(trails) and active and multi_region,
        f"{len(trails)} trail(s), multi-region: {multi_region}, active: {active}",
        severity="medium", service="Logging",
        remediation="Create an ActionTrail trail covering all regions")]


def evaluate_2_2(c: AlibabaClientCache, cfg: EvalConfig):
    """ActionTrail OSS bucket not publicly accessible."""
    from alibabacloud_actiontrail20200706 import models as m
    import oss2
    results = []
    trails = c.actiontrail.describe_trails(m.DescribeTrailsRequest()).body.trail_list or []
    auth = c.oss_auth()
    for t in trails:
        bucket_name = getattr(t, 'oss_bucket_name', None)
        if not bucket_name: continue
        try:
            loc = getattr(t, 'oss_bucket_location', None) or f"oss-{cfg.regions[0]}"
            bucket = oss2.Bucket(auth, f"https://{loc}.aliyuncs.com", bucket_name)
            acl = bucket.get_bucket_acl()
            is_public = acl.acl in ("public-read", "public-read-write")
        except Exception:
            is_public = False
        results.append(make_result("2.2", "ActionTrail OSS bucket not publicly accessible",
            bucket_name, bucket_name, not is_public,
            severity="critical", service="Logging",
            remediation="Set ActionTrail OSS bucket ACL to private"))
    if not results:
        results.append(make_result("2.2", "ActionTrail OSS bucket not publicly accessible",
            "actiontrail-oss", "ActionTrail OSS", True, "No ActionTrail OSS buckets found",
            severity="critical", service="Logging"))
    return results


# 2.3–2.23: All manual (log monitoring alerts)
_S2_MANUAL = {
    "2.3":  ("Ensure audit logs integrated with Log Service", "Logging", "high"),
    "2.4":  ("Ensure Log Service enabled for Kubernetes", "Logging", "high"),
    "2.5":  ("Ensure virtual network flow log enabled", "Logging", "high"),
    "2.6":  ("Ensure Anti-DDoS log service enabled", "Logging", "medium"),
    "2.7":  ("Ensure WAF log service enabled", "Logging", "high"),
    "2.8":  ("Ensure Cloud Firewall log analysis enabled", "Logging", "high"),
    "2.9":  ("Ensure Security Center log analysis enabled", "Logging", "high"),
    "2.10": ("Ensure alerts for RAM Role changes", "Logging", "medium"),
    "2.11": ("Ensure alerts for Cloud Firewall changes", "Logging", "high"),
    "2.12": ("Ensure alerts for VPC route changes", "Logging", "medium"),
    "2.13": ("Ensure alerts for VPC changes", "Logging", "medium"),
    "2.14": ("Ensure alerts for OSS permission changes", "Logging", "medium"),
    "2.15": ("Ensure alerts for RDS config changes", "Logging", "medium"),
    "2.16": ("Ensure alerts for unauthorized API calls", "Logging", "medium"),
    "2.17": ("Ensure alerts for console sign-in without MFA", "Logging", "high"),
    "2.18": ("Ensure alerts for root account usage", "Logging", "critical"),
    "2.19": ("Ensure alerts for console auth failures", "Logging", "medium"),
    "2.20": ("Ensure alerts for CMK disable/deletion", "Logging", "medium"),
    "2.21": ("Ensure alerts for OSS bucket policy changes", "Logging", "medium"),
    "2.22": ("Ensure alerts for security group changes", "Logging", "high"),
    "2.23": ("Ensure Logstore retention >= 365 days", "Logging", "high"),
}

def _make_manual(cis_id, title, svc, sev):
    def fn(c, cfg): return [make_manual_result(cis_id, title, svc, sev)]
    fn.__name__ = f"evaluate_{cis_id.replace('.', '_')}"
    return fn


# ═════════════════════════════════════════════════════════════════
# Section 3: Networking (all manual)
# ═════════════════════════════════════════════════════════════════

_S3_MANUAL = {
    "3.1": ("Ensure legacy networks do not exist", "Networking", "medium"),
    "3.2": ("Ensure SSH access restricted from internet", "Networking", "critical"),
    "3.3": ("Ensure VPC flow logging enabled in all VPCs", "Networking", "high"),
    "3.4": ("Ensure VPC peering routing tables are least access", "Networking", "medium"),
    "3.5": ("Ensure security groups configured with fine grained rules", "Networking", "high"),
}


# ═════════════════════════════════════════════════════════════════
# Section 4: Virtual Machines (all manual)
# ═════════════════════════════════════════════════════════════════

_S4_MANUAL = {
    "4.1": ("Ensure unattached disks are encrypted", "Compute", "high"),
    "4.2": ("Ensure VM disks are encrypted", "Compute", "high"),
    "4.3": ("Ensure no SG allows 0.0.0.0/0 to port 22", "Compute", "critical"),
    "4.4": ("Ensure no SG allows 0.0.0.0/0 to port 3389", "Compute", "critical"),
    "4.5": ("Ensure latest OS patches applied on all VMs", "Compute", "medium"),
    "4.6": ("Ensure endpoint protection installed on all VMs", "Compute", "medium"),
}


# ── Build evaluator dicts ──

SECTION_2_EVALUATORS = {"2.1": evaluate_2_1, "2.2": evaluate_2_2}
for _cid, (_t, _s, _sv) in _S2_MANUAL.items():
    SECTION_2_EVALUATORS[_cid] = _make_manual(_cid, _t, _s, _sv)

SECTION_3_EVALUATORS = {}
for _cid, (_t, _s, _sv) in _S3_MANUAL.items():
    SECTION_3_EVALUATORS[_cid] = _make_manual(_cid, _t, _s, _sv)

SECTION_4_EVALUATORS = {}
for _cid, (_t, _s, _sv) in _S4_MANUAL.items():
    SECTION_4_EVALUATORS[_cid] = _make_manual(_cid, _t, _s, _sv)
