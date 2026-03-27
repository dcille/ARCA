"""CIS M365 v6.0.1 Section 1 — Admin Center (15 controls, 12 automated)."""
from .base import M365MultiClient, M365Config, make_result, make_manual, _m, logger

def eval_1_1_1(c: M365MultiClient, cfg: M365Config):
    """Admin accounts cloud-only — Graph directoryRoles + user onPremisesSyncEnabled."""
    admins = c.graph("directoryRoles?$filter=displayName eq 'Global Administrator'&$expand=members")
    synced = []
    for role in admins.get("value", []):
        for m in role.get("members", []):
            u = c.graph(f"users/{m['id']}?$select=userPrincipalName,onPremisesSyncEnabled")
            if u.get("onPremisesSyncEnabled"): synced.append(u.get("userPrincipalName",""))
    return [make_result("1.1.1","Admin accounts are cloud-only", cfg.tenant_id, not synced,
        f"Synced admins: {len(synced)}", "critical", "AdminCenter",
        "Create dedicated cloud-only admin accounts")]

def eval_1_1_3(c: M365MultiClient, cfg: M365Config):
    """2-4 global admins — Graph directoryRoles member count."""
    ga = c.graph("directoryRoles?$filter=displayName eq 'Global Administrator'&$expand=members")
    n = sum(len(r.get("members",[])) for r in ga.get("value",[]))
    return [make_result("1.1.3","Between 2-4 global admins", cfg.tenant_id, 2<=n<=4,
        f"Global admins: {n}", "high", "AdminCenter", "Maintain 2-4 global admins")]

def eval_1_1_4(c: M365MultiClient, cfg: M365Config):
    """Admin accounts use reduced-footprint licenses — check assignedLicenses."""
    admins = c.graph("directoryRoles?$filter=displayName eq 'Global Administrator'&$expand=members")
    over_licensed = []
    for role in admins.get("value",[]):
        for m in role.get("members",[]):
            u = c.graph(f"users/{m['id']}?$select=userPrincipalName,assignedLicenses")
            if len(u.get("assignedLicenses",[])) > 2: over_licensed.append(u.get("userPrincipalName",""))
    return [make_result("1.1.4","Admin accounts use reduced-footprint licenses", cfg.tenant_id,
        not over_licensed, f"Over-licensed admins: {len(over_licensed)}", "high", "AdminCenter",
        "Remove unnecessary licenses from admin accounts")]

def eval_1_2_1(c: M365MultiClient, cfg: M365Config):
    """Only managed/approved public groups — Graph groups filter."""
    groups = c.graph("groups?$filter=groupTypes/any(g:g eq 'Unified') and visibility eq 'Public'&$count=true&$top=1",
                     ver="beta")
    count = groups.get("@odata.count", len(groups.get("value",[])))
    return [make_result("1.2.1","Only managed/approved public groups", cfg.tenant_id, count == 0,
        f"Public groups: {count}", "medium", "AdminCenter",
        "Review and convert public groups to private", level="L2")]

def eval_1_2_2(c: M365MultiClient, cfg: M365Config):
    """Shared mailbox sign-in blocked — check accountEnabled for shared mailboxes."""
    users = c.graph("users?$select=id,displayName,accountEnabled,mailboxSettings&$top=999")
    shared_enabled = [u for u in users.get("value",[])
                      if "shared" in u.get("displayName","").lower() and u.get("accountEnabled")]
    return [make_result("1.2.2","Shared mailbox sign-in blocked", cfg.tenant_id, not shared_enabled,
        f"Shared mailboxes with sign-in: {len(shared_enabled)}", "high", "AdminCenter",
        "Block sign-in: Set-MsolUser -BlockCredential $true")]

def eval_1_3_1(c: M365MultiClient, cfg: M365Config):
    """Password expiration set to never expire."""
    domains = c.graph("domains")
    verified = [d for d in domains.get("value",[]) if d.get("isVerified")]
    never_exp = all(d.get("passwordValidityPeriodInDays",0) in (0, 2147483647) for d in verified) if verified else False
    return [make_result("1.3.1","Password expiration set to never expire", cfg.tenant_id, never_exp,
        severity="medium", service="AdminCenter",
        remediation="Set-MsolPasswordPolicy -DomainName domain -ValidityPeriod 2147483647")]

def eval_1_3_2(c: M365MultiClient, cfg: M365Config):
    """Idle session timeout ≤3h — CA policy with signInFrequency."""
    pols = c.graph("identity/conditionalAccess/policies")
    has_timeout = any(p for p in pols.get("value",[])
        if p.get("state")=="enabled" and
        p.get("sessionControls",{}).get("signInFrequency",{}).get("isEnabled"))
    return [make_result("1.3.2","Idle session timeout ≤3h for unmanaged devices", cfg.tenant_id,
        has_timeout, severity="high", service="AdminCenter",
        remediation="Create CA policy with sign-in frequency ≤3h", level="L2")]

def eval_1_3_3(c: M365MultiClient, cfg: M365Config):
    """External calendar sharing not available — Graph beta org settings."""
    settings = c.graph_beta("admin/exchange/organizationConfig")
    sharing = settings.get("externalSharingPolicy", settings.get("value",{}).get("externalSharingPolicy",""))
    disabled = sharing.lower() in ("none","disabled","") if sharing else True
    return [make_result("1.3.3","External calendar sharing not available", cfg.tenant_id, disabled,
        f"Calendar sharing: {sharing or 'could not determine'}", "medium", "AdminCenter",
        "Set-SharingPolicy -Enabled $false", level="L2")]

def eval_1_3_4(c: M365MultiClient, cfg: M365Config):
    """User owned apps and services restricted — Graph beta org settings."""
    settings = c.graph_beta("admin/microsoft365/settings")
    restricted = not settings.get("isUserAppsAndServicesEnabled", True) if settings else False
    return [make_result("1.3.4","User owned apps and services restricted", cfg.tenant_id, restricted,
        severity="medium", service="AdminCenter",
        remediation="Admin center > Org settings > User owned apps: Off")]

def eval_1_3_5(c: M365MultiClient, cfg: M365Config):
    """Internal phishing protection for Forms enabled."""
    settings = c.graph_beta("admin/forms/settings")
    protected = settings.get("isInternalPhishingProtectionEnabled", False) if settings else False
    return [make_result("1.3.5","Internal phishing protection for Forms", cfg.tenant_id, protected,
        severity="medium", service="AdminCenter",
        remediation="Admin center > Org settings > Forms: enable phishing protection")]

def eval_1_3_6(c: M365MultiClient, cfg: M365Config):
    """Customer lockbox enabled."""
    org = c.graph("organization")
    orgs = org.get("value",[])
    lockbox = orgs[0].get("customerLockboxEnabled", False) if orgs else False
    return [make_result("1.3.6","Customer lockbox enabled", cfg.tenant_id, lockbox,
        severity="high", service="AdminCenter",
        remediation="Admin center > Org settings > Security & privacy > Customer Lockbox: On", level="L2")]

SECTION_1_EVALUATORS = {
    "1.1.1": eval_1_1_1,
    "1.1.2": _m("1.1.2","Two emergency access accounts defined","AdminCenter","critical"),
    "1.1.3": eval_1_1_3,
    "1.1.4": eval_1_1_4,
    "1.2.1": eval_1_2_1,
    "1.2.2": eval_1_2_2,
    "1.3.1": eval_1_3_1,
    "1.3.2": eval_1_3_2,
    "1.3.3": eval_1_3_3,
    "1.3.4": eval_1_3_4,
    "1.3.5": eval_1_3_5,
    "1.3.6": eval_1_3_6,
    "1.3.7": _m("1.3.7","Third-party storage services restricted","AdminCenter","medium","L2"),
    "1.3.8": _m("1.3.8","Sways cannot be shared externally","AdminCenter","medium","L2"),
    "1.3.9": _m("1.3.9","Shared bookings pages restricted","AdminCenter","medium"),
}
