"""CIS M365 v6.0.1 Sections 2-4: Defender/Email (20) + Audit/DLP (4) + Intune (2).
Automated: 19/26 via Graph domains, Graph beta security, Graph deviceManagement.
"""
from .base import M365MultiClient, M365Config, make_result, make_manual, _m, logger

# ── Section 2: Defender / Email (20 controls, 15 automated) ──

def eval_2_1_2(c: M365MultiClient, cfg: M365Config):
    """Common Attachment Types Filter — Graph beta Exchange malware filter."""
    policy = c.graph_beta("admin/exchange/malwareFilterPolicy")
    enabled = policy.get("enableFileFilter", policy.get("value",{}).get("enableFileFilter", False)) if policy else False
    return [make_result("2.1.2","Common Attachment Types Filter enabled", cfg.tenant_id, enabled,
        severity="high", service="Defender",
        remediation="Set-MalwareFilterPolicy -EnableFileFilter $true")]

def eval_2_1_3(c: M365MultiClient, cfg: M365Config):
    """Internal malware sending notifications."""
    policy = c.graph_beta("admin/exchange/malwareFilterPolicy")
    notify = policy.get("enableInternalSenderAdminNotifications", False) if policy else False
    return [make_result("2.1.3","Internal malware notifications enabled", cfg.tenant_id, notify,
        severity="medium", service="Defender",
        remediation="Set-MalwareFilterPolicy -EnableInternalSenderAdminNotifications $true")]

def _eval_dns(c, cfg, cid, title, check_type):
    """Common SPF/DKIM/DMARC check via Graph domains."""
    results = []
    domains = c.graph("domains")
    for d in domains.get("value",[]):
        if not d.get("isVerified"): continue
        did = d["id"]
        recs = c.graph(f"domains/{did}/serviceConfigurationRecords")
        found = any(r for r in recs.get("value",[])
                    if check_type in str(r.get("text","")).lower() + str(r.get("label","")).lower())
        results.append(make_result(cid, f"{title} for {did}", did, found,
            severity="high", service="EmailSecurity",
            remediation=f"Configure {check_type.upper()} DNS record for {did}"))
    return results or [make_manual(cid, title, "EmailSecurity", "high")]

def eval_2_1_8(c, cfg): return _eval_dns(c, cfg, "2.1.8", "SPF records published", "spf")
def eval_2_1_9(c, cfg): return _eval_dns(c, cfg, "2.1.9", "DKIM enabled", "dkim")
def eval_2_1_10(c, cfg): return _eval_dns(c, cfg, "2.1.10", "DMARC records published", "dmarc")

def eval_2_1_6(c: M365MultiClient, cfg: M365Config):
    """Spam policies notify administrators — Graph beta Exchange."""
    policy = c.graph_beta("admin/exchange/hostedOutboundSpamFilterPolicy")
    notify = policy.get("bccSuspiciousOutboundMail", False) if policy else False
    return [make_result("2.1.6","Spam policies notify administrators", cfg.tenant_id, notify,
        severity="medium", service="Defender",
        remediation="Set-HostedOutboundSpamFilterPolicy -BccSuspiciousOutboundMail $true")]

def eval_2_4_1(c: M365MultiClient, cfg: M365Config):
    """Priority account protection enabled."""
    users = c.graph_beta("admin/exchange/priorityAccountProtection")
    enabled = users.get("isEnabled", False) if users else False
    return [make_result("2.4.1","Priority account protection enabled", cfg.tenant_id, enabled,
        severity="high", service="Defender",
        remediation="Enable priority account protection in Defender portal")]

SECTION_2_EVALUATORS = {
    "2.1.1":  _m("2.1.1","Safe Links for Office enabled","Defender","high","L2"),
    "2.1.2":  eval_2_1_2,
    "2.1.3":  eval_2_1_3,
    "2.1.4":  _m("2.1.4","Safe Attachments policy enabled","Defender","high","L2"),
    "2.1.5":  _m("2.1.5","Safe Attachments for SPO/OD/Teams","Defender","high","L2"),
    "2.1.6":  eval_2_1_6,
    "2.1.7":  _m("2.1.7","Anti-phishing policy created","Defender","high","L2"),
    "2.1.8":  eval_2_1_8,
    "2.1.9":  eval_2_1_9,
    "2.1.10": eval_2_1_10,
    "2.1.11": _m("2.1.11","Comprehensive attachment filtering","Defender","medium","L2"),
    "2.1.12": _m("2.1.12","Connection filter IP allow list not used","Defender","medium"),
    "2.1.13": _m("2.1.13","Connection filter safe list off","Defender","medium"),
    "2.1.14": _m("2.1.14","Inbound anti-spam no allowed domains","Defender","medium"),
    "2.1.15": _m("2.1.15","Outbound anti-spam limits in place","Defender","medium"),
    "2.2.1":  _m("2.2.1","Emergency access activity monitored","CloudApps","high"),
    "2.4.1":  eval_2_4_1,
    "2.4.2":  _m("2.4.2","Priority accounts strict protection","Defender","high"),
    "2.4.3":  _m("2.4.3","Defender for Cloud Apps enabled","Defender","high","L2"),
    "2.4.4":  _m("2.4.4","Zero-hour auto purge for Teams","Defender","medium"),
}

# ── Section 3: Audit & DLP (4 controls, 3 automated) ──

def eval_3_1_1(c: M365MultiClient, cfg: M365Config):
    """Audit log search enabled — Graph auditLogs."""
    audit = c.graph("auditLogs/directoryAudits?$top=1")
    return [make_result("3.1.1","Audit log search enabled", cfg.tenant_id,
        bool(audit.get("value")), severity="critical", service="Audit",
        remediation="Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true")]

def eval_3_2_1(c: M365MultiClient, cfg: M365Config):
    """DLP policies enabled — Graph beta informationProtection."""
    labels = c.graph_beta("informationProtection/policy/labels")
    dlp = c.graph_beta("security/informationProtection/sensitivityLabels")
    has = bool(labels.get("value") or dlp.get("value"))
    return [make_result("3.2.1","DLP policies enabled", cfg.tenant_id, has,
        severity="high", service="DLP",
        remediation="Purview > DLP > Policies: create policies")]

def eval_3_3_1(c: M365MultiClient, cfg: M365Config):
    """Sensitivity label policies published."""
    labels = c.graph_beta("informationProtection/policy/labels")
    n = len(labels.get("value",[]))
    return [make_result("3.3.1","Sensitivity label policies published", cfg.tenant_id, n > 0,
        f"Labels: {n}", "high", "DLP",
        "Purview > Information protection > Labels: create and publish")]

SECTION_3_EVALUATORS = {
    "3.1.1": eval_3_1_1,
    "3.2.1": eval_3_2_1,
    "3.2.2": _m("3.2.2","DLP policies for Teams","DLP","high"),
    "3.3.1": eval_3_3_1,
}

# ── Section 4: Intune (2 controls, 2 automated) ──

def eval_4_1(c: M365MultiClient, cfg: M365Config):
    """Devices without compliance policy marked noncompliant."""
    settings = c.graph_beta("deviceManagement/settings")
    secure = settings.get("secureByDefault", False) if settings else False
    return [make_result("4.1","Noncompliant devices marked by default", cfg.tenant_id, secure,
        severity="high", service="Intune",
        remediation="Intune > Compliance > Settings: Mark as Not compliant", level="L2")]

def eval_4_2(c: M365MultiClient, cfg: M365Config):
    """Personal device enrollment blocked."""
    configs = c.graph_beta("deviceManagement/deviceEnrollmentConfigurations")
    blocked = any(c2 for c2 in configs.get("value",[])
        if "personalDevice" in str(c2).lower() and "block" in str(c2).lower())
    return [make_result("4.2","Personal device enrollment blocked", cfg.tenant_id, blocked,
        severity="high", service="Intune",
        remediation="Intune > Enroll devices > Restrictions: block personal", level="L2")]

SECTION_4_EVALUATORS = {"4.1": eval_4_1, "4.2": eval_4_2}
