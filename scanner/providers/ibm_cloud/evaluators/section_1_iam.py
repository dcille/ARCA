"""CIS IBM Cloud v2.0 Section 1 — Identity and Access Management (20 controls).

Automated: 1.2 (API key age), 1.6/1.8 (MFA settings), 1.18 (public access)
Manual: all others (console verification required)
"""
from __future__ import annotations
from .base import (IBMCloudClientCache, EvalConfig, make_result, make_manual_result,
                   days_since, logger)

def _m(cis_id, title, svc="IAM", sev="medium"):
    def fn(c, cfg): return [make_manual_result(cis_id, title, svc, sev)]
    fn.__name__ = f"evaluate_{cis_id.replace('.', '_')}"
    return fn

# ── Automated ──

def evaluate_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    """API keys unused for 180 days detected."""
    results = []
    resp = c.get("https://iam.cloud.ibm.com/v1/apikeys",
                 params={"account_id": cfg.account_id, "pagesize": 100} if cfg.account_id else {"pagesize": 100})
    resp.raise_for_status()
    for key in resp.json().get("apikeys", []):
        age = days_since(key.get("created_at"))
        results.append(make_result("1.2", "API keys unused for 180 days detected and disabled",
            key.get("id",""), key.get("name",""), age <= 180,
            f"API key '{key.get('name','')}' is {age} days old",
            severity="medium", service="IAM",
            remediation="Delete or disable API keys unused for 180+ days"))
    return results

def evaluate_1_6(c: IBMCloudClientCache, cfg: EvalConfig):
    """MFA enabled for all users."""
    if not cfg.account_id: return [make_manual_result("1.6","MFA enabled for all users","IAM","high")]
    resp = c.get(f"https://iam.cloud.ibm.com/v1/accounts/{cfg.account_id}/settings")
    resp.raise_for_status()
    mfa = resp.json().get("mfa", "NONE")
    return [make_result("1.6", "MFA enabled for all users in account",
        cfg.account_id, "Account IAM Settings", mfa != "NONE",
        f"Account MFA: {mfa}", severity="high", service="IAM",
        remediation="Enable MFA at the account level")]

def evaluate_1_18(c: IBMCloudClientCache, cfg: EvalConfig):
    """IAM does not allow public access."""
    if not cfg.account_id: return [make_manual_result("1.18","IAM no public access","IAM","critical")]
    resp = c.get(f"https://iam.cloud.ibm.com/v1/accounts/{cfg.account_id}/settings")
    resp.raise_for_status()
    s = resp.json()
    restricted = s.get("restrict_create_platform_apikey") == "RESTRICTED"
    return [make_result("1.18", "IAM does not allow public access to cloud services",
        cfg.account_id, "Account IAM Settings", restricted,
        severity="critical", service="IAM",
        remediation="Disable public access group in IAM settings")]


SECTION_1_EVALUATORS = {
    "1.1":  _m("1.1","Monitor account owner logins","IAM","medium"),
    "1.2":  evaluate_1_2,
    "1.3":  _m("1.3","API keys rotated every 90 days","IAM","high"),
    "1.4":  _m("1.4","Restrict API key and service ID creation","IAM","medium"),
    "1.5":  _m("1.5","No owner account API key exists","IAM","medium"),
    "1.6":  evaluate_1_6,
    "1.7":  _m("1.7","MFA enabled for account owner and admins","IAM","high"),
    "1.8":  _m("1.8","MFA enabled at account level","IAM","high"),
    "1.9":  _m("1.9","Contact email is valid","IAM","medium"),
    "1.10": _m("1.10","Contact phone number is valid","IAM","medium"),
    "1.11": _m("1.11","Trusted Profiles used instead of ServiceIDs","IAM","medium"),
    "1.12": _m("1.12","Context-Based Restrictions implemented","IAM","medium"),
    "1.13": _m("1.13","External Identity Interactions limited","IAM","medium"),
    "1.14": _m("1.14","IAM policies assigned to access groups/Trusted Profiles","IAM","medium"),
    "1.15": _m("1.15","Support access group created","IAM","medium"),
    "1.16": _m("1.16","Minimal admin privileges","IAM","critical"),
    "1.17": _m("1.17","Minimal Service ID admin privileges","IAM","critical"),
    "1.18": evaluate_1_18,
    "1.19": _m("1.19","Inactive user accounts suspended","IAM","medium"),
    "1.20": _m("1.20","Audit logging for IAM enabled","IAM","high"),
}
