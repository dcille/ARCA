"""CIS IBM Cloud v2.0 Sections 2–6 (all manual controls).

Section 2 — Storage (COS + Block + File): 15 controls
Section 3 — Logging and Monitoring: 6 controls
Section 4 — IBM Cloud Databases: 3 controls
Section 5 — Cloudant: 1 control
Section 6 — Networking (CIS + VPC): 8 controls
"""
from __future__ import annotations
from .base import make_manual_result

def _m(cis_id, title, svc="IBMCloud", sev="medium"):
    def fn(c, cfg): return [make_manual_result(cis_id, title, svc, sev)]
    fn.__name__ = f"evaluate_{cis_id.replace('.', '_')}"
    return fn

# ═════════ Section 2: Storage ═════════
SECTION_2_EVALUATORS = {
    "2.1.1.1": _m("2.1.1.1","COS encryption with customer managed keys","COS","high"),
    "2.1.1.2": _m("2.1.1.2","COS encryption with BYOK","COS","critical"),
    "2.1.1.3": _m("2.1.1.3","COS encryption with KYOK","COS","critical"),
    "2.1.2":   _m("2.1.2","COS network access restricted to specific IP range","COS","high"),
    "2.1.3":   _m("2.1.3","COS exposed only on private endpoints","COS","medium"),
    "2.1.4":   _m("2.1.4","COS bucket access restricted by IAM and S3 ACL","COS","medium"),
    "2.1.5":   _m("2.1.5","Public access to COS buckets disabled","COS","medium"),
    "2.2.1.1": _m("2.2.1.1","Block Storage VPC encrypted with BYOK","Storage","high"),
    "2.2.1.2": _m("2.2.1.2","Block Storage VPC encrypted with KYOK","Storage","high"),
    "2.2.2.1": _m("2.2.2.1","File Storage VPC encrypted with provider keys","Storage","high"),
    "2.2.2.2": _m("2.2.2.2","File Storage VPC encrypted with BYOK","Storage","high"),
    "2.2.2.3": _m("2.2.2.3","File Storage VPC encrypted with KYOK","Storage","high"),
    "2.2.3":   _m("2.2.3","Boot volumes encrypted with customer managed keys","Storage","high"),
    "2.2.4":   _m("2.2.4","Secondary volumes encrypted with customer managed keys","Storage","high"),
    "2.2.5":   _m("2.2.5","Unattached volumes encrypted with customer managed keys","Storage","high"),
}

# ═════════ Section 3: Logging ═════════
SECTION_3_EVALUATORS = {
    "3.1": _m("3.1","Auditing configured in account","Logging","high"),
    "3.2": _m("3.2","Data retention for audit events","Logging","high"),
    "3.3": _m("3.3","Events collected to identify anomalies","Logging","medium"),
    "3.4": _m("3.4","Alerts defined on custom views","Logging","medium"),
    "3.5": _m("3.5","Account owner login restricted to authorized IPs","Logging","medium"),
    "3.6": _m("3.6","Activity Tracker data encrypted at rest","Logging","high"),
}

# ═════════ Section 4: Databases ═════════
SECTION_4_EVALUATORS = {
    "4.1": _m("4.1","IBM Cloud Databases disk encryption with CMK","Database","high"),
    "4.2": _m("4.2","Database network access on private endpoints only","Database","high"),
    "4.3": _m("4.3","Database incoming connections limited to allowed sources","Database","medium"),
}

# ═════════ Section 5: Cloudant ═════════
SECTION_5_EVALUATORS = {
    "5.1": _m("5.1","IBM Cloudant encryption with customer managed keys","Cloudant","high"),
}

# ═════════ Section 6: Networking ═════════
SECTION_6_EVALUATORS = {
    "6.1.1": _m("6.1.1","TLS 1.2+ for CIS Proxy inbound traffic","Networking","high"),
    "6.1.2": _m("6.1.2","WAF enabled in CIS","Networking","high"),
    "6.1.3": _m("6.1.3","DDoS protection active on CIS","Networking","high"),
    "6.2.1": _m("6.2.1","No VPC ACL allows 0.0.0.0/0 to port 22","Networking","critical"),
    "6.2.2": _m("6.2.2","Default VPC SG restricts all traffic","Networking","critical"),
    "6.2.3": _m("6.2.3","No VPC SG allows 0.0.0.0/0 to port 3389","Networking","critical"),
    "6.2.4": _m("6.2.4","No VPC SG allows 0.0.0.0/0 to port 22","Networking","critical"),
    "6.2.5": _m("6.2.5","No VPC ACL allows 0.0.0.0/0 to port 3389","Networking","critical"),
}
