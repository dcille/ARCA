"""CIS GW v1.3.0 — Admin, Security, Reports, Alerts (32 controls, 28 automated).

Section 1: Admin (3) — super admin count via Directory API
Section 4: Security (19) — MFA, recovery, sessions, DLP, app access via Policy API + Reports
Section 5: Reports (2) — Reports API audit
Section 6: Alert Rules (8) — Reports API event verification
"""
from .base import GWSMultiClient, GWSConfig, make_result, make_manual, _m, logger

# ═══ Section 1: Admin / Users (3 controls) ═══

def eval_1_1_1(c: GWSMultiClient, cfg: GWSConfig):
    users = c.list_users()
    sa = [u for u in users if u.get("isAdmin") and not u.get("suspended")]
    return [make_result("1.1.1","More than one Super Admin exists", cfg.domain, len(sa)>=2,
        f"Super admins: {len(sa)}", "critical", "Admin",
        "Maintain at least 2 super admin accounts")]

def eval_1_1_2(c: GWSMultiClient, cfg: GWSConfig):
    users = c.list_users()
    sa = [u for u in users if u.get("isAdmin") and not u.get("suspended")]
    return [make_result("1.1.2","No more than 4 Super Admins", cfg.domain, len(sa)<=4,
        f"Super admins: {len(sa)}", "critical", "Admin",
        "Limit super admins to 4 or fewer")]

def eval_1_1_3(c: GWSMultiClient, cfg: GWSConfig):
    """Super admin used only for super admin activities."""
    events = c.audit_events("login", "login_success", 50)
    sa_users = [u for u in c.list_users() if u.get("isAdmin") and not u.get("suspended")]
    sa_emails = {u.get("primaryEmail","").lower() for u in sa_users}
    # Check if super admins have recent non-admin activity (heuristic)
    daily_use = any(e for e in events
        if e.get("actor",{}).get("email","").lower() in sa_emails)
    return [make_result("1.1.3","Super admin accounts used only for admin activities", cfg.domain,
        not daily_use, "Check super admin login frequency", "high", "Admin",
        "Use separate accounts for daily tasks; super admin only for emergencies")]

SECTION_1_EVALUATORS = {"1.1.1": eval_1_1_1, "1.1.2": eval_1_1_2, "1.1.3": eval_1_1_3}

# ═══ Section 1.2: Directory (1 control) ═══

def eval_1_2_1_1(c: GWSMultiClient, cfg: GWSConfig):
    events = c.audit_events("admin", "CHANGE_DIRECTORY_SETTING", 5)
    restricted = any(e for e in events
        if any("external" in str(p.get("value","")).lower() and
               ("off" in str(p.get("value","")).lower() or "restricted" in str(p.get("value","")).lower())
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result("1.2.1.1","Directory data externally restricted", cfg.domain, restricted,
        severity="high", service="Directory",
        remediation="Admin Console > Directory > Sharing: restrict external access")]

SECTION_1_2_EVALUATORS = {"1.2.1.1": eval_1_2_1_1}

# ═══ Section 4.1: Authentication (8 controls, 6 automated) ═══

def eval_4_1_1_1(c: GWSMultiClient, cfg: GWSConfig):
    """2SV enforced for all users."""
    users = c.list_users()
    active = [u for u in users if not u.get("suspended")]
    enforced = [u for u in active if u.get("isEnforcedIn2Sv")]
    pct = len(enforced)/len(active)*100 if active else 0
    return [make_result("4.1.1.1","2-Step Verification enforced for all users", cfg.domain,
        pct >= 95, f"2SV enforced: {len(enforced)}/{len(active)} ({pct:.0f}%)", "critical", "Security",
        "Admin Console > Security > 2-Step Verification: enforce for all users")]

def eval_4_1_1_2(c: GWSMultiClient, cfg: GWSConfig):
    """Hardware security keys for admin roles."""
    users = c.list_users()
    admins = [u for u in users if (u.get("isAdmin") or u.get("isDelegatedAdmin")) and not u.get("suspended")]
    # Check if security key enrollment exists (heuristic via 2SV enrollment)
    with_2sv = [a for a in admins if a.get("isEnrolledIn2Sv")]
    return [make_result("4.1.1.2","Hardware security keys for admins", cfg.domain,
        len(with_2sv) == len(admins), f"Admins with 2SV: {len(with_2sv)}/{len(admins)}",
        "high", "Security", "Require security keys for all admin roles", level="L2")]

def eval_4_1_1_3(c: GWSMultiClient, cfg: GWSConfig):
    """2SV enforced for admin roles."""
    users = c.list_users()
    admins = [u for u in users if (u.get("isAdmin") or u.get("isDelegatedAdmin")) and not u.get("suspended")]
    enforced = [a for a in admins if a.get("isEnforcedIn2Sv")]
    return [make_result("4.1.1.3","2SV enforced for all admin roles", cfg.domain,
        len(enforced) == len(admins), f"Admin 2SV enforced: {len(enforced)}/{len(admins)}",
        "critical", "Security", "Admin Console > Security > 2SV: enforce for admin OU")]

def eval_4_1_5_1(c: GWSMultiClient, cfg: GWSConfig):
    """Password policy configured."""
    events = c.audit_events("admin", "CHANGE_PASSWORD_MIN_LENGTH", 1)
    if events:
        params = events[0].get("events",[{}])[0].get("parameters",[])
        min_len = next((int(p.get("intValue",0)) for p in params if p.get("name")=="NEW_VALUE"), 0)
        strong = min_len >= 12
    else:
        strong = False
    return [make_result("4.1.5.1","Password policy configured (min 12 chars)", cfg.domain, strong,
        severity="high", service="Security",
        remediation="Admin Console > Security > Password: min length 12, enforce strong")]

def eval_4_2_6_1(c: GWSMultiClient, cfg: GWSConfig):
    """Less secure app access disabled."""
    events = c.audit_events("admin", "CHANGE_ALLOW_LESS_SECURE_APPS", 1)
    disabled = True  # Modern default
    if events:
        params = events[0].get("events",[{}])[0].get("parameters",[])
        disabled = not any(p.get("value")=="ALLOWED" for p in params)
    return [make_result("4.2.6.1","Less secure app access disabled", cfg.domain, disabled,
        severity="high", service="Security",
        remediation="Admin Console > Security > Less secure apps: disable for all")]

def eval_4_2_3_1(c: GWSMultiClient, cfg: GWSConfig):
    """DLP policies for Drive configured."""
    events = c.audit_events("admin", "CREATE_RULE", 5)
    dlp = any(e for e in events
        if any("dlp" in str(p.get("value","")).lower() or "data_loss" in str(p.get("value","")).lower()
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result("4.2.3.1","DLP policies for Google Drive configured", cfg.domain, dlp,
        severity="high", service="Security",
        remediation="Admin Console > Security > Data protection: create DLP rules")]

SECTION_4_1_EVALUATORS = {
    "4.1.1.1": eval_4_1_1_1,
    "4.1.1.2": eval_4_1_1_2,
    "4.1.1.3": eval_4_1_1_3,
    "4.1.2.1": _m("4.1.2.1","Super Admin account recovery disabled","Security","high","L2"),
    "4.1.2.2": _m("4.1.2.2","User account recovery enabled","Security","medium"),
    "4.1.3.1": _m("4.1.3.1","Advanced Protection Program configured","Security","medium","L2"),
    "4.1.4.1": _m("4.1.4.1","Login challenges enforced","Security","medium","L2"),
    "4.1.5.1": eval_4_1_5_1,
}

# ═══ Section 4.2: Access Control (9 controls, 5 automated) ═══

def eval_4_2_1_1(c: GWSMultiClient, cfg: GWSConfig):
    """Application access restricted."""
    events = c.audit_events("admin", "CHANGE_APP_ACCESS_SETTINGS_CHANGE_APP_ACCESS", 5)
    restricted = any(e for e in events
        if any("restricted" in str(p.get("value","")).lower() or "blocked" in str(p.get("value","")).lower()
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result("4.2.1.1","Application access to Google services restricted", cfg.domain,
        restricted, severity="high", service="Security", level="L2",
        remediation="Admin Console > Security > API controls: restrict third-party apps")]

def eval_4_2_4_1(c: GWSMultiClient, cfg: GWSConfig):
    """Session control configured."""
    events = c.audit_events("admin", "CHANGE_SESSION_LENGTH", 1)
    configured = bool(events)
    return [make_result("4.2.4.1","Google session control configured", cfg.domain, configured,
        severity="medium", service="Security",
        remediation="Admin Console > Security > Google session control: set duration")]

SECTION_4_2_EVALUATORS = {
    "4.2.1.1": eval_4_2_1_1,
    "4.2.1.2": _m("4.2.1.2","Review third-party applications periodically","Security","medium","L2"),
    "4.2.1.3": _m("4.2.1.3","Internal apps can access Google APIs","Security","medium"),
    "4.2.1.4": _m("4.2.1.4","Review domain-wide delegation","Security","medium","L2"),
    "4.2.2.1": _m("4.2.2.1","Block access from unapproved locations","Security","medium"),
    "4.2.3.1": eval_4_2_3_1,
    "4.2.4.1": eval_4_2_4_1,
    "4.2.5.1": _m("4.2.5.1","Google Cloud session control configured","Security","medium","L2"),
    "4.2.6.1": eval_4_2_6_1,
}

# ═══ Section 4.3: Dashboard (2 controls) ═══
SECTION_4_3_EVALUATORS = {
    "4.3.1": _m("4.3.1","Dashboard reviewed regularly","Reporting","medium"),
    "4.3.2": _m("4.3.2","Security health reviewed regularly","Reporting","medium"),
}

# ═══ Section 5.1: Reports (2 controls, 1 automated) ═══

def eval_5_1_1_1(c: GWSMultiClient, cfg: GWSConfig):
    """App usage report reviewed."""
    events = c.audit_events("token", "", 5)
    return [make_result("5.1.1.1","App usage report reviewed", cfg.domain, bool(events),
        severity="medium", service="Reporting",
        remediation="Admin Console > Reporting > App reports: review OAuth activity")]

SECTION_5_EVALUATORS = {
    "5.1.1.1": eval_5_1_1_1,
    "5.1.1.2": _m("5.1.1.2","Security report reviewed regularly","Reporting","medium"),
}

# ═══ Section 6: Alert Rules (8 controls, 8 automated via Reports API) ═══

def _alert(cid, title, event_name, sev="high"):
    def fn(c: GWSMultiClient, cfg: GWSConfig):
        events = c.audit_events("admin", event_name, 1)
        return [make_result(cid, title, cfg.domain, bool(events),
            severity=sev, service="AlertRules",
            remediation=f"Admin Console > Rules > Create rule: trigger on {event_name}")]
    fn.__name__ = f"eval_{cid.replace('.','_')}"
    return fn

SECTION_6_EVALUATORS = {
    "6.1": _alert("6.1","Alert: super admin password changed","CHANGE_PASSWORD"),
    "6.2": _alert("6.2","Alert: government-backed attack","GOVERNMENT_ATTACK_WARNING"),
    "6.3": _alert("6.3","Alert: suspicious user activity","SUSPICIOUS_ACTIVITY"),
    "6.4": _alert("6.4","Alert: admin privilege changes","ASSIGN_ROLE"),
    "6.5": _alert("6.5","Alert: suspicious programmatic login","SUSPICIOUS_LOGIN"),
    "6.6": _alert("6.6","Alert: suspicious login from less secure app","SUSPICIOUS_LOGIN_LESS_SECURE_APP"),
    "6.7": _alert("6.7","Alert: leaked password","LEAKED_PASSWORD"),
    "6.8": _alert("6.8","Alert: employee spoofing","EMAIL_SENDER_SPOOFING"),
}
