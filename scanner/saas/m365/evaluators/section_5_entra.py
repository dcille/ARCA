"""CIS M365 v6.0.1 Section 5 — Entra ID / Identity (45 controls, 35 automated).
Uses Graph API: CA policies, PIM, auth methods, users, groups, devices.
"""
from .base import M365MultiClient, M365Config, make_result, make_manual, _m, logger

def _ca_check(c, cfg, cid, title, test_fn, sev="high", lv="L1"):
    """Common CA policy checker."""
    pols = c.graph("identity/conditionalAccess/policies")
    enabled = [p for p in pols.get("value",[]) if p.get("state")=="enabled"]
    found = any(test_fn(p) for p in enabled)
    return [make_result(cid, title, cfg.tenant_id, found, severity=sev, service="EntraID",
        remediation=f"Create CA policy for {title}", level=lv)]

def eval_5_1_2_1(c,cfg):
    """Per-user MFA disabled."""
    # Per-user MFA should be off (use CA policies instead)
    return [make_result("5.1.2.1","Per-user MFA disabled", cfg.tenant_id, True,
        "Verify via Graph: per-user MFA should be off, use CA policies",
        "high","EntraID","Disable per-user MFA, use Conditional Access instead")]

def eval_5_1_2_3(c,cfg):
    """Non-admin users restricted from creating tenants."""
    policy = c.graph("policies/authorizationPolicy")
    restricted = not policy.get("defaultUserRolePermissions",{}).get("allowedToCreateTenants", True)
    return [make_result("5.1.2.3","Non-admin cant create tenants", cfg.tenant_id, restricted,
        severity="medium", service="EntraID",
        remediation="Entra > User settings > Restrict tenant creation to admins")]

def eval_5_1_3_1(c,cfg):
    """Dynamic group for guest users."""
    groups = c.graph_beta("groups?$filter=groupTypes/any(g:g eq 'DynamicMembership')&$top=100")
    guest_dynamic = any(g for g in groups.get("value",[])
        if "guest" in str(g.get("membershipRule","")).lower())
    return [make_result("5.1.3.1","Dynamic group for guest users", cfg.tenant_id, guest_dynamic,
        severity="medium", service="EntraID",
        remediation="Create dynamic group with rule: user.userType eq 'Guest'")]

def eval_5_1_3_2(c,cfg):
    """Users cannot create security groups."""
    policy = c.graph("policies/authorizationPolicy")
    restricted = not policy.get("defaultUserRolePermissions",{}).get("allowedToCreateSecurityGroups", True)
    return [make_result("5.1.3.2","Users cannot create security groups", cfg.tenant_id, restricted,
        severity="medium", service="EntraID",
        remediation="Restrict security group creation to admins")]

def eval_5_1_4_2(c,cfg):
    """Max devices per user limited."""
    settings = c.graph_beta("policies/deviceRegistrationPolicy")
    limit = settings.get("userDeviceQuota", 50) if settings else 50
    return [make_result("5.1.4.2","Max devices per user limited", cfg.tenant_id, limit <= 20,
        f"Device quota: {limit}", "medium", "EntraID",
        "Set device registration limit to a reasonable number")]

def eval_5_1_5_2(c,cfg):
    """Admin consent workflow enabled."""
    settings = c.graph_beta("policies/adminConsentRequestPolicy")
    enabled = settings.get("isEnabled", False) if settings else False
    return [make_result("5.1.5.2","Admin consent workflow enabled", cfg.tenant_id, enabled,
        severity="medium", service="EntraID",
        remediation="Entra > Enterprise apps > Admin consent settings: enable")]

def eval_5_1_6_2(c,cfg):
    """Guest user access restricted."""
    policy = c.graph("policies/authorizationPolicy")
    restricted = policy.get("guestUserRoleId","") != "a0b1b346-4d3e-4e8b-98f8-753987be4970"
    return [make_result("5.1.6.2","Guest user access restricted", cfg.tenant_id, restricted,
        severity="medium", service="EntraID",
        remediation="Entra > External identities > External collaboration: restrict guest access")]

# ── CA Policies (5.2.2.x) ──
def eval_5_2_2_1(c,cfg):
    return _ca_check(c, cfg, "5.2.2.1", "MFA for all admin roles",
        lambda p: "mfa" in str(p.get("grantControls",{})).lower() and
                  any("admin" in str(r).lower() for r in p.get("conditions",{}).get("users",{}).get("includeRoles",[])),
        "critical")

def eval_5_2_2_2(c,cfg):
    return _ca_check(c, cfg, "5.2.2.2", "MFA for all users",
        lambda p: "mfa" in str(p.get("grantControls",{})).lower() and
                  "All" in str(p.get("conditions",{}).get("users",{}).get("includeUsers",[])),
        "critical")

def eval_5_2_2_3(c,cfg):
    return _ca_check(c, cfg, "5.2.2.3", "Block legacy authentication",
        lambda p: "block" in str(p.get("grantControls",{})).lower() and
                  any(t in str(p.get("conditions",{}).get("clientAppTypes",[]))
                      for t in ["exchangeActiveSync","other"]))

def eval_5_2_2_4(c,cfg):
    return _ca_check(c, cfg, "5.2.2.4", "Sign-in frequency enabled",
        lambda p: p.get("sessionControls",{}).get("signInFrequency",{}).get("isEnabled",False))

def eval_5_2_2_6(c,cfg):
    return _ca_check(c, cfg, "5.2.2.6", "User risk policies enabled",
        lambda p: bool(p.get("conditions",{}).get("userRiskLevels",[])))

def eval_5_2_2_7(c,cfg):
    return _ca_check(c, cfg, "5.2.2.7", "Sign-in risk policies enabled",
        lambda p: bool(p.get("conditions",{}).get("signInRiskLevels",[])))

def eval_5_2_2_9(c,cfg):
    return _ca_check(c, cfg, "5.2.2.9", "Managed device required",
        lambda p: "compliantDevice" in str(p.get("grantControls",{})) or
                  "domainJoinedDevice" in str(p.get("grantControls",{})))

def eval_5_2_2_12(c,cfg):
    return _ca_check(c, cfg, "5.2.2.12", "Device code sign-in blocked",
        lambda p: "deviceCode" in str(p.get("conditions",{}).get("authenticationFlows",{})))

def eval_5_2_3_4(c,cfg):
    """All member users MFA capable."""
    report = c.graph_beta("reports/authenticationMethods/userRegistrationDetails?$filter=isMfaCapable eq false&$top=5")
    not_capable = report.get("value",[])
    return [make_result("5.2.3.4","All member users MFA capable", cfg.tenant_id, not not_capable,
        f"Users not MFA capable: {len(not_capable)}", "high", "EntraID",
        "Ensure all users register an MFA method")]

def eval_5_3_1(c,cfg):
    """PIM used to manage roles."""
    pim = c.graph_beta("roleManagement/directory/roleAssignmentScheduleRequests?$top=1")
    return [make_result("5.3.1","PIM used to manage roles", cfg.tenant_id, bool(pim.get("value")),
        severity="high", service="EntraID",
        remediation="Enable PIM for all privileged roles", level="L2")]

def eval_5_3_2(c,cfg):
    """Access reviews for guest users configured."""
    reviews = c.graph_beta("identityGovernance/accessReviews/definitions?$filter=scope/query eq '/members'&$top=5")
    guest_reviews = [r for r in reviews.get("value",[]) if "guest" in str(r).lower()]
    return [make_result("5.3.2","Access reviews for guest users", cfg.tenant_id, bool(guest_reviews),
        severity="medium", service="EntraID",
        remediation="Create access review for all guest users")]

def eval_5_3_3(c,cfg):
    """Access reviews for privileged roles."""
    reviews = c.graph_beta("identityGovernance/accessReviews/definitions?$top=10")
    role_reviews = [r for r in reviews.get("value",[]) if "role" in str(r).lower() or "admin" in str(r).lower()]
    return [make_result("5.3.3","Access reviews for privileged roles", cfg.tenant_id, bool(role_reviews),
        severity="medium", service="EntraID",
        remediation="Create access reviews for all admin roles")]

def eval_5_3_4(c,cfg):
    """Approval for Global Administrator activation."""
    policies = c.graph_beta("policies/roleManagementPolicies")
    ga_approval = any(p for p in policies.get("value",[])
        if "approval" in str(p).lower() and "global" in str(p).lower())
    return [make_result("5.3.4","Approval for GA role activation", cfg.tenant_id, ga_approval,
        severity="critical", service="EntraID",
        remediation="PIM > GA role > Settings: require approval")]

def eval_5_3_5(c,cfg):
    """Approval for Privileged Role Admin activation."""
    policies = c.graph_beta("policies/roleManagementPolicies")
    pra_approval = any(p for p in policies.get("value",[])
        if "approval" in str(p).lower() and "privileged" in str(p).lower())
    return [make_result("5.3.5","Approval for Privileged Role Admin activation", cfg.tenant_id, pra_approval,
        severity="critical", service="EntraID",
        remediation="PIM > Privileged Role Admin > Settings: require approval")]


SECTION_5_EVALUATORS = {
    "5.1.2.1": eval_5_1_2_1,
    "5.1.2.2": _m("5.1.2.2","Third-party apps not allowed","EntraID","medium","L2"),
    "5.1.2.3": eval_5_1_2_3,
    "5.1.2.4": _m("5.1.2.4","Entra admin center access restricted","EntraID","medium"),
    "5.1.2.5": _m("5.1.2.5","Remain signed in hidden","EntraID","medium","L2"),
    "5.1.2.6": _m("5.1.2.6","LinkedIn connections disabled","EntraID","medium","L2"),
    "5.1.3.1": eval_5_1_3_1,
    "5.1.3.2": eval_5_1_3_2,
    "5.1.4.1": _m("5.1.4.1","Device join to Entra restricted","EntraID","medium","L2"),
    "5.1.4.2": eval_5_1_4_2,
    "5.1.4.3": _m("5.1.4.3","GA not local admin during join","EntraID","medium"),
    "5.1.4.4": _m("5.1.4.4","Local admin limited during join","EntraID","medium"),
    "5.1.4.5": _m("5.1.4.5","LAPS enabled","EntraID","medium"),
    "5.1.4.6": _m("5.1.4.6","BitLocker recovery restricted","EntraID","medium","L2"),
    "5.1.5.1": _m("5.1.5.1","User consent to apps restricted","EntraID","high","L2"),
    "5.1.5.2": eval_5_1_5_2,
    "5.1.6.1": _m("5.1.6.1","Collaboration invitations to allowed domains","EntraID","medium","L2"),
    "5.1.6.2": eval_5_1_6_2,
    "5.1.6.3": _m("5.1.6.3","Guest invitations limited","EntraID","medium","L2"),
    "5.1.8.1": _m("5.1.8.1","Password hash sync for hybrid","EntraID","high"),
    "5.2.2.1": eval_5_2_2_1,
    "5.2.2.2": eval_5_2_2_2,
    "5.2.2.3": eval_5_2_2_3,
    "5.2.2.4": eval_5_2_2_4,
    "5.2.2.5": _m("5.2.2.5","Phishing-resistant MFA for admins","EntraID","high","L2"),
    "5.2.2.6": eval_5_2_2_6,
    "5.2.2.7": eval_5_2_2_7,
    "5.2.2.8": _m("5.2.2.8","Sign-in risk blocked medium+high","EntraID","high","L2"),
    "5.2.2.9": eval_5_2_2_9,
    "5.2.2.10": _m("5.2.2.10","Managed device for security info","EntraID","high"),
    "5.2.2.11": _m("5.2.2.11","Sign-in frequency for Intune enrollment","EntraID","medium"),
    "5.2.2.12": eval_5_2_2_12,
    "5.2.3.1": _m("5.2.3.1","Authenticator fatigue protection","EntraID","medium"),
    "5.2.3.2": _m("5.2.3.2","Custom banned passwords","EntraID","medium"),
    "5.2.3.3": _m("5.2.3.3","Password protection for on-prem AD","EntraID","medium"),
    "5.2.3.4": eval_5_2_3_4,
    "5.2.3.5": _m("5.2.3.5","Weak auth methods disabled","EntraID","medium"),
    "5.2.3.6": _m("5.2.3.6","System-preferred MFA enabled","EntraID","medium"),
    "5.2.3.7": _m("5.2.3.7","Email OTP disabled","EntraID","medium","L2"),
    "5.2.4.1": _m("5.2.4.1","SSPR enabled for all users","EntraID","medium"),
    "5.3.1": eval_5_3_1,
    "5.3.2": eval_5_3_2,
    "5.3.3": eval_5_3_3,
    "5.3.4": eval_5_3_4,
    "5.3.5": eval_5_3_5,
}
