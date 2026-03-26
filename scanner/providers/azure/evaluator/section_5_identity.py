"""CIS Azure v5.0 Section 5: Identity & Access Management (Entra ID) evaluators.

43 controls (5.1.1–5.28). Uses Microsoft Graph API for most checks.
Many are CIS-manual but we still attempt automated evaluation where possible.
"""

import logging
from .base import AzureClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Azure-5.0", "MCSB-Azure-1.0"]


# ═══════════════════════════════════════════════════════════════
# Section 5.1 — Security Defaults / Per-User MFA
# ═══════════════════════════════════════════════════════════════

# 5.1.1 — Security defaults enabled
def evaluate_cis_5_1_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    data = clients.graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
    if not data:
        return [make_result(
            cis_id="5.1.1", check_id="azure_cis_5_1_1",
            title="Ensure security defaults is enabled in Entra ID",
            service="identity", severity="medium", status="ERROR",
            resource_id=config.subscription_id,
            status_extended="Could not query security defaults policy via Graph API.",
            compliance_frameworks=FW,
        )]
    enabled = data.get("isEnabled", False)
    return [make_result(
        cis_id="5.1.1", check_id="azure_cis_5_1_1",
        title="Ensure security defaults is enabled in Entra ID",
        service="identity", severity="medium",
        status="PASS" if enabled else "FAIL",
        resource_id=config.tenant_id or config.subscription_id,
        status_extended=f"Security defaults isEnabled = {enabled}",
        remediation="Enable security defaults in Entra ID > Properties > Manage security defaults.",
        compliance_frameworks=FW,
    )]


# 5.1.2 — MFA enabled for all users
def evaluate_cis_5_1_2(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    # Check via security defaults or Conditional Access
    sd = clients.graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
    if sd and sd.get("isEnabled"):
        return [make_result(
            cis_id="5.1.2", check_id="azure_cis_5_1_2",
            title="Ensure MFA is enabled for all users",
            service="identity", severity="high", status="PASS",
            resource_id=config.tenant_id or config.subscription_id,
            status_extended="Security defaults enabled — MFA required for all users.",
            compliance_frameworks=FW,
        )]
    # Check Conditional Access for MFA policy
    caps = clients.graph_get("/identity/conditionalAccess/policies", beta=True)
    if caps:
        policies = caps.get("value", [])
        mfa_all = any(
            "All" in str(p.get("conditions", {}).get("users", {}).get("includeUsers", []))
            and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
            and p.get("state") == "enabled"
            for p in policies
        )
        return [make_result(
            cis_id="5.1.2", check_id="azure_cis_5_1_2",
            title="Ensure MFA is enabled for all users",
            service="identity", severity="high",
            status="PASS" if mfa_all else "FAIL",
            resource_id=config.tenant_id or config.subscription_id,
            status_extended=f"Conditional Access MFA-for-all policy found: {mfa_all}",
            remediation="Enable MFA via Security Defaults or Conditional Access policy for all users.",
            compliance_frameworks=FW,
        )]
    return [make_result(
        cis_id="5.1.2", check_id="azure_cis_5_1_2",
        title="Ensure MFA is enabled for all users",
        service="identity", severity="high", status="FAIL",
        resource_id=config.tenant_id or config.subscription_id,
        status_extended="Neither Security Defaults nor Conditional Access MFA policy detected.",
        remediation="Enable MFA for all users via Security Defaults or Conditional Access.",
        compliance_frameworks=FW,
    )]


# 5.1.3 — Don't allow remember MFA on devices
def evaluate_cis_5_1_3(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="5.1.3", check_id="azure_cis_5_1_3",
        title="Ensure 'Allow users to remember MFA on devices they trust' is disabled",
        service="identity", severity="high",
        subscription_id=config.subscription_id,
        reason="Per-user MFA service settings are only accessible via the legacy MFA portal, not Graph API.",
    )]


# ═══════════════════════════════════════════════════════════════
# Section 5.2 — Conditional Access (all manual per CIS)
# ═══════════════════════════════════════════════════════════════

def _check_ca_policy(clients, cis_id, check_id, title, severity, condition_fn, remediation):
    """Generic CA policy checker."""
    caps = clients.graph_get("/identity/conditionalAccess/policies", beta=True)
    if not caps:
        return [make_result(
            cis_id=cis_id, check_id=check_id, title=title,
            service="identity", severity=severity, status="ERROR",
            resource_id="tenant",
            status_extended="Could not query Conditional Access policies.",
            compliance_frameworks=FW,
        )]
    policies = caps.get("value", [])
    matching = [p for p in policies if p.get("state") == "enabled" and condition_fn(p)]
    return [make_result(
        cis_id=cis_id, check_id=check_id, title=title,
        service="identity", severity=severity,
        status="PASS" if matching else "FAIL",
        resource_id="tenant",
        status_extended=f"Matching enabled CA policies: {len(matching)}",
        remediation=remediation,
        compliance_frameworks=FW,
    )]


def evaluate_cis_5_2_1(c, cfg):
    """Trusted locations defined."""
    locs = c.graph_get("/identity/conditionalAccess/namedLocations", beta=True)
    if not locs:
        return [make_result(cis_id="5.2.1", check_id="azure_cis_5_2_1",
            title="Ensure trusted locations are defined", service="identity",
            severity="medium", status="FAIL", resource_id="tenant",
            status_extended="No named locations found or could not query.",
            remediation="Define trusted IP-based named locations in Entra ID > Security > Conditional Access > Named locations.",
            compliance_frameworks=FW)]
    trusted = [l for l in locs.get("value", []) if l.get("isTrusted")]
    return [make_result(cis_id="5.2.1", check_id="azure_cis_5_2_1",
        title="Ensure trusted locations are defined", service="identity",
        severity="medium", status="PASS" if trusted else "FAIL",
        resource_id="tenant",
        status_extended=f"Named locations: {len(locs.get('value', []))}, trusted: {len(trusted)}",
        remediation="Define and mark IP ranges as trusted in Named Locations.",
        compliance_frameworks=FW)]


def evaluate_cis_5_2_2(c, cfg):
    """Exclusionary geographic CA policy."""
    return _check_ca_policy(c, "5.2.2", "azure_cis_5_2_2",
        "Ensure exclusionary geographic CA policy is considered", "high",
        lambda p: "block" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
            and p.get("conditions", {}).get("locations", {}).get("includeLocations"),
        "Create a CA policy that blocks access from non-approved geographic locations.")


def evaluate_cis_5_2_3(c, cfg):
    """Device code flow blocked."""
    return _check_ca_policy(c, "5.2.3", "azure_cis_5_2_3",
        "Ensure device code flow is blocked via CA policy", "medium",
        lambda p: "block" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
            and "deviceCode" in str(p.get("conditions", {}).get("authenticationFlows", {})),
        "Create a CA policy that blocks the device code authentication flow.")


def evaluate_cis_5_2_4(c, cfg):
    """MFA CA policy for all users."""
    return _check_ca_policy(c, "5.2.4", "azure_cis_5_2_4",
        "Ensure MFA CA policy exists for all users", "high",
        lambda p: "All" in str(p.get("conditions", {}).get("users", {}).get("includeUsers", []))
            and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower(),
        "Create a CA policy requiring MFA for all users on all cloud apps.")


def evaluate_cis_5_2_5(c, cfg):
    """MFA required for risky sign-ins."""
    return _check_ca_policy(c, "5.2.5", "azure_cis_5_2_5",
        "Ensure MFA is required for risky sign-ins", "high",
        lambda p: p.get("conditions", {}).get("signInRiskLevels")
            and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower(),
        "Create a CA policy requiring MFA for medium/high risk sign-ins.")


def evaluate_cis_5_2_6(c, cfg):
    """MFA for Azure Service Management API."""
    return _check_ca_policy(c, "5.2.6", "azure_cis_5_2_6",
        "Ensure MFA for Windows Azure Service Management API", "high",
        lambda p: "797f4846-ba00-4fd7-ba43-dac1f8f63013" in str(p.get("conditions", {}).get("applications", {}).get("includeApplications", []))
            and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower(),
        "Create a CA policy requiring MFA for Azure Service Management API access.")


def evaluate_cis_5_2_7(c, cfg):
    """MFA for Microsoft Admin Portals."""
    return _check_ca_policy(c, "5.2.7", "azure_cis_5_2_7",
        "Ensure MFA for Microsoft Admin Portals", "high",
        lambda p: "MicrosoftAdminPortals" in str(p.get("conditions", {}).get("applications", {}).get("includeApplications", []))
            and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower(),
        "Create a CA policy requiring MFA for Microsoft Admin Portals.")


def evaluate_cis_5_2_8(c, cfg):
    """Token Protection CA policy."""
    return _check_ca_policy(c, "5.2.8", "azure_cis_5_2_8",
        "Ensure Token Protection CA policy is considered", "medium",
        lambda p: p.get("sessionControls", {}).get("securityTokenProtection", {}).get("isEnabled"),
        "Create a CA policy with token protection for sign-in sessions.")


# ═══════════════════════════════════════════════════════════════
# Section 5.3 — Account Management
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_3_1(c, cfg):
    return [make_manual_result(cis_id="5.3.1", check_id="azure_cis_5_3_1",
        title="Ensure admin accounts are not used for daily operations",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires reviewing sign-in logs to verify admin accounts are not used for routine tasks.")]


def evaluate_cis_5_3_2(c, cfg):
    """Guest users reviewed."""
    data = c.graph_get("/users?$filter=userType eq 'Guest'&$count=true&$top=1",)
    if not data:
        return [make_manual_result(cis_id="5.3.2", check_id="azure_cis_5_3_2",
            title="Ensure guest users are reviewed regularly",
            service="identity", severity="medium", subscription_id=cfg.subscription_id,
            reason="Could not query guest users via Graph API.")]
    guests = data.get("value", [])
    count = data.get("@odata.count", len(guests))
    return [make_result(cis_id="5.3.2", check_id="azure_cis_5_3_2",
        title="Ensure guest users are reviewed regularly",
        service="identity", severity="medium",
        status="PASS" if count == 0 else "MANUAL",
        resource_id="tenant",
        status_extended=f"Guest users found: {count}. Manual review required if > 0.",
        remediation="Review and remove unnecessary guest users. Set up periodic access reviews.",
        compliance_frameworks=FW)]


def evaluate_cis_5_3_3(c, cfg):
    """User Access Administrator role restricted."""
    try:
        ras = list(c.authorization.role_assignments.list_for_scope(
            scope="/", filter="atScope()"))
        ua_admins = [ra for ra in ras if "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" in str(ra.role_definition_id)]
        return [make_result(cis_id="5.3.3", check_id="azure_cis_5_3_3",
            title="Ensure User Access Administrator role usage is restricted",
            service="identity", severity="critical",
            status="PASS" if not ua_admins else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"User Access Administrator assignments at root scope: {len(ua_admins)}",
            remediation="Remove User Access Administrator role assignments at root scope immediately after use.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="5.3.3", check_id="azure_cis_5_3_3",
            title="Ensure User Access Administrator role usage is restricted",
            service="identity", severity="critical", status="PASS",
            resource_id=cfg.subscription_id,
            status_extended="No elevated access detected (could not query root scope — likely no elevation).",
            compliance_frameworks=FW)]


def evaluate_cis_5_3_4(c, cfg):
    return [make_manual_result(cis_id="5.3.4", check_id="azure_cis_5_3_4",
        title="Ensure all privileged role assignments are periodically reviewed",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires manual review of privileged role assignments for appropriateness.")]


def evaluate_cis_5_3_5(c, cfg):
    return [make_manual_result(cis_id="5.3.5", check_id="azure_cis_5_3_5",
        title="Ensure disabled accounts have no read/write/owner permissions",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires cross-referencing disabled Entra ID accounts with Azure RBAC assignments.")]


def evaluate_cis_5_3_6(c, cfg):
    return [make_manual_result(cis_id="5.3.6", check_id="azure_cis_5_3_6",
        title="Ensure Tenant Creator role assignments are periodically reviewed",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires reviewing Tenant Creator role assignments for appropriateness.")]


def evaluate_cis_5_3_7(c, cfg):
    return [make_manual_result(cis_id="5.3.7", check_id="azure_cis_5_3_7",
        title="Ensure all non-privileged role assignments are periodically reviewed",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires manual review of all non-privileged RBAC assignments.")]


# ═══════════════════════════════════════════════════════════════
# Section 5.4–5.28 — Tenant & User Settings
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_5_4(c, cfg):
    """Restrict non-admin users from creating tenants."""
    data = c.graph_get("/policies/authorizationPolicy")
    if not data:
        return [make_result(cis_id="5.4", check_id="azure_cis_5_4",
            title="Ensure non-admin users cannot create tenants",
            service="identity", severity="medium", status="ERROR",
            resource_id="tenant", status_extended="Could not query authorization policy.",
            compliance_frameworks=FW)]
    perms = data.get("defaultUserRolePermissions", {})
    restricted = perms.get("allowedToCreateTenants") is False
    return [make_result(cis_id="5.4", check_id="azure_cis_5_4",
        title="Ensure non-admin users cannot create tenants",
        service="identity", severity="medium",
        status="PASS" if restricted else "FAIL",
        resource_id="tenant",
        status_extended=f"allowedToCreateTenants = {perms.get('allowedToCreateTenants')}",
        remediation="Set 'Restrict non-admin users from creating tenants' to Yes.",
        compliance_frameworks=FW)]


def _graph_auth_policy_check(c, cfg, cis_id, check_id, title, severity, field_path, condition_fn, remediation):
    """Generic check against authorization policy."""
    data = c.graph_get("/policies/authorizationPolicy")
    if not data:
        return [make_result(cis_id=cis_id, check_id=check_id, title=title,
            service="identity", severity=severity, status="ERROR",
            resource_id="tenant", status_extended="Could not query authorization policy.",
            compliance_frameworks=FW)]
    val = data
    for key in field_path.split("."):
        val = val.get(key, {}) if isinstance(val, dict) else None
    ok = condition_fn(val) if val is not None else False
    return [make_result(cis_id=cis_id, check_id=check_id, title=title,
        service="identity", severity=severity,
        status="PASS" if ok else "FAIL",
        resource_id="tenant",
        status_extended=f"{field_path} = {val}",
        remediation=remediation,
        compliance_frameworks=FW)]


def evaluate_cis_5_5(c, cfg):
    return [make_manual_result(cis_id="5.5", check_id="azure_cis_5_5",
        title="Ensure SSPR requires 2 authentication methods",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="SSPR settings accessible only via Azure Portal (Entra ID > Users > Password reset > Authentication methods).")]

def evaluate_cis_5_6(c, cfg):
    return [make_manual_result(cis_id="5.6", check_id="azure_cis_5_6",
        title="Ensure account lockout threshold ≤ 10",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Lockout settings accessible via Entra ID > Security > Authentication methods > Password protection.")]

def evaluate_cis_5_7(c, cfg):
    return [make_manual_result(cis_id="5.7", check_id="azure_cis_5_7",
        title="Ensure account lockout duration ≥ 60 seconds",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Lockout settings accessible via Entra ID > Security > Authentication methods > Password protection.")]

def evaluate_cis_5_8(c, cfg):
    return [make_manual_result(cis_id="5.8", check_id="azure_cis_5_8",
        title="Ensure custom banned password list is enforced",
        service="identity", severity="high", subscription_id=cfg.subscription_id,
        reason="Custom banned passwords accessible via Entra ID > Security > Authentication methods > Password protection.")]

def evaluate_cis_5_9(c, cfg):
    return [make_manual_result(cis_id="5.9", check_id="azure_cis_5_9",
        title="Ensure auth reconfirmation days is not 0",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="SSPR registration settings accessible via Entra ID > Users > Password reset > Registration.")]

def evaluate_cis_5_10(c, cfg):
    return [make_manual_result(cis_id="5.10", check_id="azure_cis_5_10",
        title="Ensure 'Notify users on password resets' is set to Yes",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Password reset notification settings accessible via Entra ID > Users > Password reset > Notifications.")]

def evaluate_cis_5_11(c, cfg):
    return [make_manual_result(cis_id="5.11", check_id="azure_cis_5_11",
        title="Ensure 'Notify all admins when other admins reset their password' is Yes",
        service="identity", severity="critical", subscription_id=cfg.subscription_id,
        reason="Password reset notification settings accessible via Entra ID > Users > Password reset > Notifications.")]


def evaluate_cis_5_12(c, cfg):
    """User consent for applications disabled."""
    data = c.graph_get("/policies/authorizationPolicy")
    if not data:
        return [make_result(cis_id="5.12", check_id="azure_cis_5_12",
            title="Ensure user consent for applications is disabled", service="identity",
            severity="medium", status="ERROR", resource_id="tenant",
            status_extended="Could not query.", compliance_frameworks=FW)]
    policies = data.get("defaultUserRolePermissions", {}).get("permissionGrantPoliciesAssigned", [])
    disabled = len(policies) == 0
    return [make_result(cis_id="5.12", check_id="azure_cis_5_12",
        title="Ensure user consent for applications is disabled",
        service="identity", severity="medium",
        status="PASS" if disabled else "FAIL",
        resource_id="tenant",
        status_extended=f"permissionGrantPoliciesAssigned = {policies}",
        remediation="Set 'User consent for applications' to 'Do not allow user consent'.",
        compliance_frameworks=FW)]


def evaluate_cis_5_13(c, cfg):
    """User consent restricted to verified publishers."""
    data = c.graph_get("/policies/authorizationPolicy")
    if not data:
        return [make_manual_result(cis_id="5.13", check_id="azure_cis_5_13",
            title="Ensure consent is restricted to verified publishers",
            service="identity", severity="medium", subscription_id=cfg.subscription_id,
            reason="Could not query authorization policy.")]
    policies = data.get("defaultUserRolePermissions", {}).get("permissionGrantPoliciesAssigned", [])
    ok = (len(policies) == 0 or
          "ManagePermissionGrantsForSelf.microsoft-user-default-low" in str(policies))
    return [make_result(cis_id="5.13", check_id="azure_cis_5_13",
        title="Ensure consent is restricted to verified publishers",
        service="identity", severity="medium",
        status="PASS" if ok else "FAIL", resource_id="tenant",
        status_extended=f"Consent policies: {policies}",
        remediation="Set to 'Allow user consent for apps from verified publishers, for selected permissions'.",
        compliance_frameworks=FW)]


def evaluate_cis_5_14(c, cfg):
    """Users cannot register applications."""
    data = c.graph_get("/policies/authorizationPolicy")
    if not data:
        return [make_result(cis_id="5.14", check_id="azure_cis_5_14",
            title="Ensure users cannot register applications", service="identity",
            severity="medium", status="ERROR", resource_id="tenant",
            status_extended="Could not query.", compliance_frameworks=FW)]
    restricted = data.get("defaultUserRolePermissions", {}).get("allowedToCreateApps") is False
    return [make_result(cis_id="5.14", check_id="azure_cis_5_14",
        title="Ensure users cannot register applications",
        service="identity", severity="medium",
        status="PASS" if restricted else "FAIL", resource_id="tenant",
        status_extended=f"allowedToCreateApps = {data.get('defaultUserRolePermissions', {}).get('allowedToCreateApps')}",
        remediation="Set 'Users can register applications' to No.",
        compliance_frameworks=FW)]


def evaluate_cis_5_15(c, cfg):
    """Guest user access restricted."""
    data = c.graph_get("/policies/authorizationPolicy")
    if not data:
        return [make_result(cis_id="5.15", check_id="azure_cis_5_15",
            title="Ensure guest user access is restricted", service="identity",
            severity="medium", status="ERROR", resource_id="tenant",
            status_extended="Could not query.", compliance_frameworks=FW)]
    gid = data.get("guestUserRoleId", "")
    most_restrictive = gid == "2af84b1e-32c8-42b7-82bc-daa82404023b"
    return [make_result(cis_id="5.15", check_id="azure_cis_5_15",
        title="Ensure guest user access is restricted",
        service="identity", severity="medium",
        status="PASS" if most_restrictive else "FAIL", resource_id="tenant",
        status_extended=f"guestUserRoleId = {gid} ({'most restrictive' if most_restrictive else 'NOT most restrictive'})",
        remediation="Set guest access to 'restricted to properties and memberships of their own directory objects'.",
        compliance_frameworks=FW)]


def evaluate_cis_5_16(c, cfg):
    """Guest invite restricted."""
    data = c.graph_get("/policies/authorizationPolicy")
    if not data:
        return [make_result(cis_id="5.16", check_id="azure_cis_5_16",
            title="Ensure guest invite is restricted", service="identity",
            severity="medium", status="ERROR", resource_id="tenant",
            status_extended="Could not query.", compliance_frameworks=FW)]
    allow = data.get("allowInvitesFrom", "everyone")
    ok = allow in ("adminsAndGuestInviters", "none")
    return [make_result(cis_id="5.16", check_id="azure_cis_5_16",
        title="Ensure guest invite is restricted to admins",
        service="identity", severity="medium",
        status="PASS" if ok else "FAIL", resource_id="tenant",
        status_extended=f"allowInvitesFrom = {allow}",
        remediation="Set to 'Only users assigned to specific admin roles can invite guest users'.",
        compliance_frameworks=FW)]


def evaluate_cis_5_17(c, cfg):
    return [make_manual_result(cis_id="5.17", check_id="azure_cis_5_17",
        title="Ensure 'Restrict access to Entra admin center' is Yes",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="This setting is only in the Entra portal (Users > User settings > Administration centre).")]

def evaluate_cis_5_18(c, cfg):
    return [make_manual_result(cis_id="5.18", check_id="azure_cis_5_18",
        title="Ensure 'Restrict user ability to access groups in My Groups' is Yes",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Group self-service settings accessible via Entra ID > Groups > General.")]

def evaluate_cis_5_19(c, cfg):
    return [make_manual_result(cis_id="5.19", check_id="azure_cis_5_19",
        title="Ensure users cannot create security groups in Azure portals",
        service="identity", severity="high", subscription_id=cfg.subscription_id,
        reason="Security group creation settings accessible via Entra ID > Groups > General.")]

def evaluate_cis_5_20(c, cfg):
    return [make_manual_result(cis_id="5.20", check_id="azure_cis_5_20",
        title="Ensure 'Owners can manage group membership requests in My Groups' is No",
        service="identity", severity="high", subscription_id=cfg.subscription_id,
        reason="Group self-service settings accessible via Entra ID > Groups > General.")]

def evaluate_cis_5_21(c, cfg):
    return [make_manual_result(cis_id="5.21", check_id="azure_cis_5_21",
        title="Ensure users cannot create M365 groups in Azure portals",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="M365 group creation settings accessible via Entra ID > Groups > General.")]

def evaluate_cis_5_22(c, cfg):
    return [make_manual_result(cis_id="5.22", check_id="azure_cis_5_22",
        title="Ensure MFA required to register/join devices with Entra",
        service="identity", severity="high", subscription_id=cfg.subscription_id,
        reason="Device registration settings accessible via Entra ID > Devices > Device Settings.")]


def evaluate_cis_5_23(c, cfg):
    """No custom subscription admin roles."""
    try:
        roles = list(c.authorization.role_definitions.list(
            scope=f"/subscriptions/{cfg.subscription_id}",
            filter="type eq 'CustomRole'"))
        bad = [r for r in roles if r.permissions and
               any("*" in (p.actions or []) for p in r.permissions)]
        return [make_result(cis_id="5.23", check_id="azure_cis_5_23",
            title="Ensure no custom subscription administrator roles exist",
            service="identity", severity="critical",
            status="PASS" if not bad else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Custom roles with * actions: {len(bad)}",
            remediation="Remove custom roles that grant full subscription administrator permissions.",
            compliance_frameworks=FW)]
    except Exception as e:
        return [make_result(cis_id="5.23", check_id="azure_cis_5_23",
            title="Ensure no custom subscription administrator roles exist",
            service="identity", severity="critical", status="ERROR",
            resource_id=cfg.subscription_id, status_extended=str(e),
            compliance_frameworks=FW)]


def evaluate_cis_5_24(c, cfg):
    return [make_manual_result(cis_id="5.24", check_id="azure_cis_5_24",
        title="Ensure custom role exists for administering resource locks",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Requires reviewing custom roles for Microsoft.Authorization/locks/* permission.")]

def evaluate_cis_5_25(c, cfg):
    return [make_manual_result(cis_id="5.25", check_id="azure_cis_5_25",
        title="Ensure subscription leaving/entering Entra tenant is set to 'Permit no one'",
        service="identity", severity="medium", subscription_id=cfg.subscription_id,
        reason="Subscription transfer policies are only in the Azure Portal > Subscriptions > Manage Policies.")]


def evaluate_cis_5_26(c, cfg):
    """Fewer than 5 global admins."""
    data = c.graph_get("/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members")
    if not data:
        return [make_manual_result(cis_id="5.26", check_id="azure_cis_5_26",
            title="Ensure fewer than 5 global administrators",
            service="identity", severity="critical", subscription_id=cfg.subscription_id,
            reason="Could not query Global Administrator role members.")]
    members = data.get("value", [])
    count = len(members)
    ok = 2 <= count <= 4
    return [make_result(cis_id="5.26", check_id="azure_cis_5_26",
        title="Ensure fewer than 5 global administrators",
        service="identity", severity="critical",
        status="PASS" if ok else "FAIL", resource_id="tenant",
        status_extended=f"Global Administrators: {count} (recommended: 2–4)",
        remediation="Maintain 2–4 global admins. Use PIM for just-in-time elevation.",
        compliance_frameworks=FW)]


def evaluate_cis_5_27(c, cfg):
    """2–3 subscription owners."""
    try:
        ras = list(c.authorization.role_assignments.list_for_scope(
            scope=f"/subscriptions/{cfg.subscription_id}"))
        # Owner role definition ID ends with specific GUID
        owners = [ra for ra in ras if ra.role_definition_id and
                  ra.role_definition_id.endswith("/8e3af657-a8ff-443c-a75c-2fe8c4bcb635")]
        count = len(owners)
        ok = 2 <= count <= 3
        return [make_result(cis_id="5.27", check_id="azure_cis_5_27",
            title="Ensure there are between 2 and 3 subscription owners",
            service="identity", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=cfg.subscription_id,
            status_extended=f"Subscription owners: {count} (recommended: 2–3)",
            remediation="Adjust subscription owner count to between 2 and 3.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_manual_result(cis_id="5.27", check_id="azure_cis_5_27",
            title="Ensure there are between 2 and 3 subscription owners",
            service="identity", severity="medium", subscription_id=cfg.subscription_id,
            reason="Could not enumerate subscription owner role assignments.")]


def evaluate_cis_5_28(c, cfg):
    """Passwordless authentication considered."""
    data = c.graph_get("/policies/authenticationMethodsPolicy", beta=True)
    if not data:
        return [make_manual_result(cis_id="5.28", check_id="azure_cis_5_28",
            title="Ensure passwordless authentication methods are considered",
            service="identity", severity="medium", subscription_id=cfg.subscription_id,
            reason="Could not query authentication methods policy.")]
    configs = data.get("authenticationMethodConfigurations", [])
    passwordless_ids = {"Fido2", "MicrosoftAuthenticator", "WindowsHelloForBusiness"}
    enabled = [m.get("id") for m in configs if m.get("state") == "enabled" and m.get("id") in passwordless_ids]
    return [make_result(cis_id="5.28", check_id="azure_cis_5_28",
        title="Ensure passwordless authentication methods are considered",
        service="identity", severity="medium",
        status="PASS" if enabled else "FAIL", resource_id="tenant",
        status_extended=f"Passwordless methods enabled: {enabled or 'none'}",
        remediation="Enable FIDO2, Microsoft Authenticator, or Windows Hello for Business.",
        compliance_frameworks=FW)]
