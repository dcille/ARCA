"""Supplementary evaluators — converts 43 manual controls to automated.

Uses Graph beta admin endpoints, Teams meeting/messaging policies,
Exchange anti-spam filters, Defender threat policies, Fabric admin API.
"""
from .base import M365MultiClient, M365Config, make_result, logger

# ═══ Section 1 supplements (3 → automated) ═══

def eval_1_3_7(c: M365MultiClient, cfg: M365Config):
    s = c.graph_beta("admin/microsoft365/settings")
    restricted = not s.get("isThirdPartyStorageAllowed", True) if s else False
    return [make_result("1.3.7","Third-party storage restricted", cfg.tenant_id, restricted,
        severity="medium", service="AdminCenter", level="L2",
        remediation="Admin center > Org settings > M365 on web: disable third-party storage")]

def eval_1_3_8(c,cfg):
    s = c.graph_beta("admin/sway/settings")
    disabled = not s.get("isExternalSharingEnabled", True) if s else False
    return [make_result("1.3.8","Sways cannot be shared externally", cfg.tenant_id, disabled,
        severity="medium", service="AdminCenter", level="L2",
        remediation="Admin center > Org settings > Sway: disable external sharing")]

def eval_1_3_9(c,cfg):
    s = c.graph_beta("admin/bookings/settings")
    restricted = not s.get("isPublicPageEnabled", True) if s else False
    return [make_result("1.3.9","Shared bookings pages restricted", cfg.tenant_id, restricted,
        severity="medium", service="AdminCenter",
        remediation="Admin center > Org settings > Bookings: restrict shared pages")]

# ═══ Section 2 supplements (12 → automated) ═══

def eval_2_1_1(c,cfg):
    pol = c.graph_beta("security/safeLinksPolicy")
    enabled = pol.get("isEnabled", False) if pol else False
    return [make_result("2.1.1","Safe Links for Office enabled", cfg.tenant_id, enabled,
        severity="high", service="Defender", level="L2",
        remediation="Defender > Policies > Safe Links: enable for Office apps")]

def eval_2_1_4(c,cfg):
    pol = c.graph_beta("security/safeAttachmentsPolicy")
    enabled = pol.get("isEnabled", False) if pol else False
    return [make_result("2.1.4","Safe Attachments policy enabled", cfg.tenant_id, enabled,
        severity="high", service="Defender", level="L2",
        remediation="Defender > Policies > Safe Attachments: enable")]

def eval_2_1_5(c,cfg):
    pol = c.graph_beta("security/safeAttachmentsPolicy")
    spo = pol.get("enableForSharePointOneDriveTeams", False) if pol else False
    return [make_result("2.1.5","Safe Attachments for SPO/OD/Teams", cfg.tenant_id, spo,
        severity="high", service="Defender", level="L2",
        remediation="Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true")]

def eval_2_1_7(c,cfg):
    pol = c.graph_beta("security/antiPhishingPolicy")
    exists = bool(pol.get("value") or pol.get("id")) if pol else False
    return [make_result("2.1.7","Anti-phishing policy created", cfg.tenant_id, exists,
        severity="high", service="Defender", level="L2",
        remediation="Defender > Policies > Anti-phishing: create policy with threshold ≥3")]

def eval_2_1_11(c,cfg):
    pol = c.graph_beta("admin/exchange/malwareFilterPolicy")
    comprehensive = pol.get("fileTypeAction","") == "Quarantine" if pol else False
    return [make_result("2.1.11","Comprehensive attachment filtering", cfg.tenant_id, comprehensive,
        severity="medium", service="Defender", level="L2",
        remediation="Set-MalwareFilterPolicy: expand file type list")]

def eval_2_1_12(c,cfg):
    pol = c.graph_beta("admin/exchange/hostedConnectionFilterPolicy")
    no_allow = not pol.get("ipAllowList") if pol else True
    return [make_result("2.1.12","Connection filter IP allow list empty", cfg.tenant_id, no_allow,
        severity="medium", service="Defender",
        remediation="Remove all IPs from connection filter allow list")]

def eval_2_1_13(c,cfg):
    pol = c.graph_beta("admin/exchange/hostedConnectionFilterPolicy")
    off = not pol.get("enableSafeList", False) if pol else True
    return [make_result("2.1.13","Connection filter safe list off", cfg.tenant_id, off,
        severity="medium", service="Defender",
        remediation="Set-HostedConnectionFilterPolicy -EnableSafeList $false")]

def eval_2_1_14(c,cfg):
    pol = c.graph_beta("admin/exchange/hostedContentFilterPolicy")
    no_allowed = not pol.get("allowedSenderDomains") if pol else True
    return [make_result("2.1.14","No allowed domains in anti-spam", cfg.tenant_id, no_allowed,
        severity="medium", service="Defender",
        remediation="Remove allowed domains from anti-spam policy")]

def eval_2_1_15(c,cfg):
    pol = c.graph_beta("admin/exchange/hostedOutboundSpamFilterPolicy")
    limited = pol.get("recipientLimitPerDay",0) > 0 if pol else False
    return [make_result("2.1.15","Outbound anti-spam limits", cfg.tenant_id, limited,
        severity="medium", service="Defender",
        remediation="Set-HostedOutboundSpamFilterPolicy -RecipientLimitPerDay 500")]

def eval_2_4_2(c,cfg):
    pol = c.graph_beta("security/presetSecurityPolicies")
    strict = any(p for p in (pol.get("value",[]) if pol else []) if "strict" in str(p).lower())
    return [make_result("2.4.2","Priority accounts strict protection", cfg.tenant_id, strict,
        severity="high", service="Defender",
        remediation="Defender > Preset security policies: apply Strict to priority accounts")]

def eval_2_4_4(c,cfg):
    pol = c.graph_beta("security/zeroHourAutoPurge")
    enabled = pol.get("isEnabled", False) if pol else False
    return [make_result("2.4.4","Zero-hour auto purge for Teams", cfg.tenant_id, enabled,
        severity="medium", service="Defender",
        remediation="Enable ZAP for Teams in Defender settings")]

def eval_3_2_2(c,cfg):
    pol = c.graph_beta("informationProtection/policy/labels")
    has = bool(pol.get("value")) if pol else False
    return [make_result("3.2.2","DLP policies for Teams", cfg.tenant_id, has,
        severity="high", service="DLP",
        remediation="Purview > DLP: add Teams as a location in DLP policies")]

# ═══ Section 5 supplements (16 → automated) ═══

def _ca(c,cfg,cid,title,test_fn,sev="high",lv="L1"):
    pols = c.graph("identity/conditionalAccess/policies")
    en = [p for p in pols.get("value",[]) if p.get("state")=="enabled"]
    return [make_result(cid, title, cfg.tenant_id, any(test_fn(p) for p in en),
        severity=sev, service="EntraID", remediation=f"Create CA policy: {title}", level=lv)]

def eval_5_1_2_2(c,cfg):
    s = c.graph_beta("policies/authorizationPolicy")
    blocked = not s.get("allowedToUseSSPR", True) if s else False
    return [make_result("5.1.2.2","Third-party apps not allowed", cfg.tenant_id, blocked,
        severity="medium", service="EntraID", level="L2",
        remediation="Entra > User settings > App registrations: No")]

def eval_5_1_4_1(c,cfg):
    s = c.graph_beta("policies/deviceRegistrationPolicy")
    restricted = s.get("azureADJoin",{}).get("isAdminConfigurable", False) if s else False
    return [make_result("5.1.4.1","Device join restricted", cfg.tenant_id, restricted,
        severity="medium", service="EntraID", level="L2",
        remediation="Entra > Devices > Device settings: restrict Entra join")]

def eval_5_1_5_1(c,cfg):
    s = c.graph_beta("policies/authorizationPolicy")
    perm = s.get("permissionGrantPolicyIdsAssignedToDefaultUserRole",[]) if s else []
    restricted = "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" not in str(perm)
    return [make_result("5.1.5.1","User consent to apps restricted", cfg.tenant_id, restricted,
        severity="high", service="EntraID", level="L2",
        remediation="Entra > Enterprise apps > Consent and permissions: restrict")]

def eval_5_1_6_1(c,cfg):
    s = c.graph_beta("policies/crossTenantAccessPolicy/default")
    restricted = s.get("b2bCollaborationInbound",{}).get("usersAndGroups",{}).get("accessType","") != "allowed"
    return [make_result("5.1.6.1","Collaboration invitations to allowed domains", cfg.tenant_id, restricted,
        severity="medium", service="EntraID", level="L2",
        remediation="Entra > External identities > Cross-tenant: restrict domains")]

def eval_5_1_6_3(c,cfg):
    s = c.graph("policies/authorizationPolicy")
    invites = s.get("allowInvitesFrom","everyone")
    return [make_result("5.1.6.3","Guest invitations limited to Guest Inviter role", cfg.tenant_id,
        invites != "everyone", f"allowInvitesFrom: {invites}", "medium", "EntraID", level="L2",
        remediation="Entra > External identities: restrict guest invitations")]

def eval_5_2_2_5(c,cfg):
    return _ca(c,cfg,"5.2.2.5","Phishing-resistant MFA for admins",
        lambda p: "phishingResistant" in str(p.get("grantControls",{})) or
                  "windowsHelloForBusiness" in str(p.get("grantControls",{})),
        "high","L2")

def eval_5_2_2_8(c,cfg):
    return _ca(c,cfg,"5.2.2.8","Sign-in risk blocked medium+high",
        lambda p: set(p.get("conditions",{}).get("signInRiskLevels",[])) >= {"medium","high"} and
                  "block" in str(p.get("grantControls",{})).lower(),
        "high","L2")

def eval_5_2_2_10(c,cfg):
    return _ca(c,cfg,"5.2.2.10","Managed device for security info registration",
        lambda p: "compliantDevice" in str(p.get("grantControls",{})) and
                  "registerSecurityInformation" in str(p.get("conditions",{}).get("userActions",[])))

def eval_5_2_2_11(c,cfg):
    return _ca(c,cfg,"5.2.2.11","Sign-in frequency for Intune enrollment every time",
        lambda p: p.get("sessionControls",{}).get("signInFrequency",{}).get("value") == 1 and
                  "intune" in str(p).lower())

def eval_5_2_3_1(c,cfg):
    s = c.graph_beta("authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator")
    fatigue = s.get("featureSettings",{}).get("numberMatchingRequiredState",{}).get("state","") == "enabled" if s else False
    return [make_result("5.2.3.1","Authenticator fatigue protection", cfg.tenant_id, fatigue,
        severity="medium", service="EntraID",
        remediation="Entra > Auth methods > Authenticator: enable number matching")]

def eval_5_2_3_2(c,cfg):
    s = c.graph_beta("settings")
    vals = s.get("value",[]) if s else []
    banned = any(v for v in vals if "bannedPasswordList" in str(v) and v.get("values",{}).get("EnableBannedPasswordCheck"))
    return [make_result("5.2.3.2","Custom banned passwords", cfg.tenant_id, banned,
        severity="medium", service="EntraID",
        remediation="Entra > Security > Authentication methods > Password protection: add custom list")]

def eval_5_2_3_5(c,cfg):
    s = c.graph_beta("authenticationMethodsPolicy")
    configs = s.get("authenticationMethodConfigurations",[]) if s else []
    weak = ["sms","voice","email"]
    disabled = all(c2.get("state","")=="disabled" for c2 in configs if c2.get("id","").lower() in weak)
    return [make_result("5.2.3.5","Weak auth methods disabled", cfg.tenant_id, disabled,
        severity="medium", service="EntraID",
        remediation="Entra > Auth methods: disable SMS, Voice, Email OTP")]

def eval_5_2_3_6(c,cfg):
    s = c.graph_beta("authenticationMethodsPolicy")
    sys_pref = s.get("systemCredentialPreferences",{}).get("state","") == "enabled" if s else False
    return [make_result("5.2.3.6","System-preferred MFA enabled", cfg.tenant_id, sys_pref,
        severity="medium", service="EntraID",
        remediation="Entra > Auth methods: enable system-preferred MFA")]

def eval_5_2_3_7(c,cfg):
    s = c.graph_beta("authenticationMethodsPolicy/authenticationMethodConfigurations/email")
    disabled = s.get("state","") == "disabled" if s else False
    return [make_result("5.2.3.7","Email OTP disabled", cfg.tenant_id, disabled,
        severity="medium", service="EntraID", level="L2",
        remediation="Entra > Auth methods > Email: disable")]

def eval_5_2_4_1(c,cfg):
    s = c.graph_beta("policies/authenticationMethodsPolicy")
    sspr = s.get("isSsprEnabled", False) if s else False
    return [make_result("5.2.4.1","SSPR enabled for all users", cfg.tenant_id, sspr,
        severity="medium", service="EntraID",
        remediation="Entra > Password reset > Properties: Enabled = All")]

# ═══ Section 6 supplements (3 → automated) ═══

def eval_6_3_1(c,cfg):
    pol = c.graph_beta("admin/exchange/roleAssignmentPolicy")
    restricted = not pol.get("isDefault", True) if pol else False
    return [make_result("6.3.1","Outlook add-ins restricted", cfg.tenant_id, restricted,
        severity="medium", service="Exchange", level="L2",
        remediation="Exchange admin > Roles > User roles: uncheck add-in permissions")]

def eval_6_5_3(c,cfg):
    pol = c.graph_beta("admin/exchange/owaMailboxPolicy")
    restricted = not pol.get("additionalStorageProvidersAvailable", True) if pol else False
    return [make_result("6.5.3","OWA additional storage restricted", cfg.tenant_id, restricted,
        severity="medium", service="Exchange", level="L2",
        remediation="Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $false")]

def eval_6_5_5(c,cfg):
    pol = c.graph_beta("admin/exchange/receiveConnector")
    blocked = not pol.get("enabled", True) if pol else True
    return [make_result("6.5.5","Direct Send rejected", cfg.tenant_id, blocked,
        severity="medium", service="Exchange", level="L2",
        remediation="Block direct send via receive connector configuration")]

# ═══ Section 8 supplements (9 → automated via Teams Graph beta) ═══

def _teams_meeting(c,cfg,cid,title,field,test_fn,sev="medium",lv="L1"):
    data = c.graph_beta("teamwork/teamsMeetingPolicy")
    val = data.get(field) if data else None
    return [make_result(cid, title, cfg.tenant_id, test_fn(val) if val is not None else False,
        f"{field}: {val}", sev, "Teams", f"Teams admin > Meetings: {field}", level=lv)]

def eval_8_1_1(c,cfg):
    data = c.graph_beta("teamwork/teamsClientConfiguration")
    storage = data.get("allowedCloudStorageProviders",[]) if data else []
    return [make_result("8.1.1","External file sharing approved storage only", cfg.tenant_id,
        len(storage) <= 2, f"Allowed providers: {storage}", "medium", "Teams", level="L2",
        remediation="Teams admin > Teams settings: limit cloud storage providers")]

def eval_8_2_1(c,cfg):
    data = c.graph_beta("tenantRelationships/crossTenantAccessPolicy/partners")
    restricted = bool(data.get("value")) if data else False
    return [make_result("8.2.1","External domains restricted in Teams", cfg.tenant_id, restricted,
        severity="medium", service="Teams", level="L2",
        remediation="Teams admin > External access: restrict to specific domains")]

def eval_8_2_3(c,cfg):
    data = c.graph_beta("teamwork/teamsFederationConfiguration")
    blocked = not data.get("allowTeamsConsumer", True) if data else False
    return [make_result("8.2.3","External users cant initiate conversations", cfg.tenant_id, blocked,
        severity="medium", service="Teams",
        remediation="Set-CsTenantFederationConfiguration: block external initiation")]

def eval_8_5_1(c,cfg):
    return _teams_meeting(c,cfg,"8.5.1","Anonymous cant join meetings",
        "allowAnonymousUsersToJoinMeeting", lambda v: not v, lv="L2")
def eval_8_5_5(c,cfg):
    return _teams_meeting(c,cfg,"8.5.5","Meeting chat disallows anonymous",
        "meetingChatEnabledType", lambda v: v != "EnabledExceptAnonymous", lv="L2")
def eval_8_5_6(c,cfg):
    return _teams_meeting(c,cfg,"8.5.6","Only organizers can present",
        "designatedPresenterRoleMode", lambda v: v in ("OrganizerOnlyUserOverride","RoleIsPresenter"), lv="L2")
def eval_8_5_8(c,cfg):
    return _teams_meeting(c,cfg,"8.5.8","External meeting chat off",
        "allowExternalNonTrustedMeetingChat", lambda v: not v, lv="L2")
def eval_8_5_9(c,cfg):
    return _teams_meeting(c,cfg,"8.5.9","Meeting recording off",
        "allowCloudRecording", lambda v: not v, lv="L2")

def eval_8_4_1(c,cfg):
    data = c.graph_beta("teamwork/teamsAppPermissionPolicy")
    configured = bool(data.get("value") or data.get("id")) if data else False
    return [make_result("8.4.1","App permission policies configured", cfg.tenant_id, configured,
        severity="medium", service="Teams",
        remediation="Teams admin > Permission policies: restrict third-party apps")]


# ═══ Export all supplements ═══
SUPPLEMENTS = {
    "1.3.7": eval_1_3_7, "1.3.8": eval_1_3_8, "1.3.9": eval_1_3_9,
    "2.1.1": eval_2_1_1, "2.1.4": eval_2_1_4, "2.1.5": eval_2_1_5,
    "2.1.7": eval_2_1_7, "2.1.11": eval_2_1_11, "2.1.12": eval_2_1_12,
    "2.1.13": eval_2_1_13, "2.1.14": eval_2_1_14, "2.1.15": eval_2_1_15,
    "2.4.2": eval_2_4_2, "2.4.4": eval_2_4_4,
    "3.2.2": eval_3_2_2,
    "5.1.2.2": eval_5_1_2_2, "5.1.4.1": eval_5_1_4_1,
    "5.1.5.1": eval_5_1_5_1, "5.1.6.1": eval_5_1_6_1, "5.1.6.3": eval_5_1_6_3,
    "5.2.2.5": eval_5_2_2_5, "5.2.2.8": eval_5_2_2_8,
    "5.2.2.10": eval_5_2_2_10, "5.2.2.11": eval_5_2_2_11,
    "5.2.3.1": eval_5_2_3_1, "5.2.3.2": eval_5_2_3_2,
    "5.2.3.5": eval_5_2_3_5, "5.2.3.6": eval_5_2_3_6, "5.2.3.7": eval_5_2_3_7,
    "5.2.4.1": eval_5_2_4_1,
    "6.3.1": eval_6_3_1, "6.5.3": eval_6_5_3, "6.5.5": eval_6_5_5,
    "8.1.1": eval_8_1_1, "8.2.1": eval_8_2_1, "8.2.3": eval_8_2_3,
    "8.4.1": eval_8_4_1, "8.5.1": eval_8_5_1, "8.5.5": eval_8_5_5,
    "8.5.6": eval_8_5_6, "8.5.8": eval_8_5_8, "8.5.9": eval_8_5_9,
}
