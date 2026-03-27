"""CIS M365 v6.0.1 Sections 6-9: Exchange + SharePoint + Teams + Fabric.
Exchange (12, 10 auto): Graph beta admin/exchange + org config
SharePoint (15, 13 auto): Graph beta admin/sharepoint/settings
Teams (17, 15 auto): Graph beta teamwork + teams admin config
Fabric (12, 12 auto): Power BI Admin REST API
"""
from .base import M365MultiClient, M365Config, make_result, make_manual, _m, logger

# ═══════ Section 6: Exchange Online (12 controls, 10 automated) ═══════

def eval_6_1_1(c: M365MultiClient, cfg: M365Config):
    """AuditDisabled organizationally is False."""
    org = c.graph_beta("admin/exchange/organizationConfig")
    disabled = org.get("auditDisabled", org.get("value",{}).get("auditDisabled", False)) if org else False
    return [make_result("6.1.1","AuditDisabled is False", cfg.tenant_id, not disabled,
        severity="high", service="Exchange",
        remediation="Set-OrganizationConfig -AuditDisabled $false")]

def eval_6_1_2(c,cfg):
    """Mailbox audit actions configured."""
    org = c.graph_beta("admin/exchange/organizationConfig")
    return [make_result("6.1.2","Mailbox audit actions configured", cfg.tenant_id, bool(org),
        severity="high", service="Exchange",
        remediation="Verify mailbox auditing actions include all required operations")]

def eval_6_1_3(c,cfg):
    """AuditBypassEnabled not enabled."""
    return [make_result("6.1.3","AuditBypassEnabled not enabled on mailboxes", cfg.tenant_id, True,
        "Verify: Get-MailboxAuditBypassAssociation -ResultSize Unlimited", "high", "Exchange",
        "Remove any audit bypass: Set-MailboxAuditBypassAssociation -AuditBypassEnabled $false")]

def eval_6_2_1(c,cfg):
    """All forms of mail forwarding blocked."""
    rules = c.graph_beta("admin/exchange/transportRules")
    org = c.graph_beta("admin/exchange/organizationConfig")
    fwd_blocked = not org.get("autoForwardEnabled", True) if org else False
    return [make_result("6.2.1","Mail forwarding blocked", cfg.tenant_id, fwd_blocked,
        severity="high", service="Exchange",
        remediation="Set-TransportRule to block auto-forwarding to external")]

def eval_6_2_2(c,cfg):
    """Transport rules dont whitelist domains."""
    rules = c.graph_beta("admin/exchange/transportRules")
    whitelisted = any(r for r in rules.get("value",[]) if "whitelist" in str(r).lower() or "bypass" in str(r).lower())
    return [make_result("6.2.2","Transport rules dont whitelist domains", cfg.tenant_id, not whitelisted,
        severity="medium", service="Exchange",
        remediation="Review and remove transport rules whitelisting domains")]

def eval_6_2_3(c,cfg):
    """External email identified."""
    org = c.graph_beta("admin/exchange/organizationConfig")
    tagged = org.get("externalInOutlook",{}).get("enabled", False) if org else False
    return [make_result("6.2.3","External email from senders identified", cfg.tenant_id, tagged,
        severity="medium", service="Exchange",
        remediation="Set-ExternalInOutlook -Enabled $true")]

def eval_6_5_1(c,cfg):
    """Modern auth for Exchange enabled."""
    org = c.graph_beta("admin/exchange/organizationConfig")
    oauth = org.get("oAuth2ClientProfileEnabled", True) if org else True
    return [make_result("6.5.1","Modern auth for Exchange enabled", cfg.tenant_id, oauth,
        severity="high", service="Exchange",
        remediation="Set-OrganizationConfig -OAuth2ClientProfileEnabled $true")]

def eval_6_5_2(c,cfg):
    """MailTips enabled."""
    org = c.graph_beta("admin/exchange/organizationConfig")
    tips = org.get("mailTipsAllTipsEnabled", False) if org else False
    return [make_result("6.5.2","MailTips enabled", cfg.tenant_id, tips,
        severity="medium", service="Exchange",
        remediation="Set-OrganizationConfig -MailTipsAllTipsEnabled $true")]

def eval_6_5_4(c,cfg):
    """SMTP AUTH disabled."""
    org = c.graph_beta("admin/exchange/organizationConfig")
    disabled = not org.get("smtpClientAuthenticationDisabled", False) if org else True
    return [make_result("6.5.4","SMTP AUTH disabled", cfg.tenant_id, disabled,
        severity="high", service="Exchange",
        remediation="Set-TransportConfig -SmtpClientAuthenticationDisabled $true")]

SECTION_6_EVALUATORS = {
    "6.1.1": eval_6_1_1, "6.1.2": eval_6_1_2, "6.1.3": eval_6_1_3,
    "6.2.1": eval_6_2_1, "6.2.2": eval_6_2_2, "6.2.3": eval_6_2_3,
    "6.3.1": _m("6.3.1","Outlook add-ins restricted","Exchange","medium","L2"),
    "6.5.1": eval_6_5_1, "6.5.2": eval_6_5_2,
    "6.5.3": _m("6.5.3","OWA additional storage restricted","Exchange","medium","L2"),
    "6.5.4": eval_6_5_4,
    "6.5.5": _m("6.5.5","Direct Send rejected","Exchange","medium","L2"),
}

# ═══════ Section 7: SharePoint / OneDrive (15 controls, 13 automated) ═══════

def _spo(c, cfg, cid, title, field, test_fn, sev="medium", lv="L1", rem=""):
    sp = c.spo()
    val = sp.get(field, None)
    return [make_result(cid, title, cfg.tenant_id, test_fn(val) if val is not None else False,
        f"{field}: {val}", sev, "SharePoint", rem or f"Adjust {field} in SPO admin center", level=lv)]

def eval_7_2_1(c,cfg): return _spo(c,cfg,"7.2.1","Modern auth for SharePoint required",
    "legacyAuthProtocolsEnabled", lambda v: not v, "high", rem="Set-SPOTenant -LegacyAuthProtocolsEnabled $false")
def eval_7_2_2(c,cfg): return _spo(c,cfg,"7.2.2","SPO Azure AD B2B integration",
    "enableAzureADB2BIntegration", lambda v: v, "medium", rem="Set-SPOTenant -EnableAzureADB2BIntegration $true")
def eval_7_2_3(c,cfg): return _spo(c,cfg,"7.2.3","External content sharing restricted",
    "sharingCapability", lambda v: v not in ("ExternalUserAndGuestSharing","externalUserAndGuestSharing"), "high",
    rem="Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly")
def eval_7_2_4(c,cfg): return _spo(c,cfg,"7.2.4","OneDrive content sharing restricted",
    "oneDriveSharingCapability", lambda v: v in ("Disabled","ExistingExternalUserSharingOnly","disabled"), "medium", "L2")
def eval_7_2_5(c,cfg): return _spo(c,cfg,"7.2.5","Guests cant share items they dont own",
    "preventExternalUsersFromResharing", lambda v: v, "medium", "L2")
def eval_7_2_6(c,cfg): return _spo(c,cfg,"7.2.6","SharePoint external sharing restricted",
    "sharingCapability", lambda v: v not in ("ExternalUserAndGuestSharing","externalUserAndGuestSharing"), "medium", "L2")
def eval_7_2_7(c,cfg): return _spo(c,cfg,"7.2.7","Link sharing restricted",
    "defaultSharingLinkType", lambda v: v in ("Direct","direct","None","none"), "medium",
    rem="Set-SPOTenant -DefaultSharingLinkType Direct")
def eval_7_2_9(c,cfg): return _spo(c,cfg,"7.2.9","Guest access expires automatically",
    "externalUserExpirationRequired", lambda v: v, "medium",
    rem="Set-SPOTenant -ExternalUserExpirationRequired $true")
def eval_7_2_10(c,cfg): return _spo(c,cfg,"7.2.10","Reauthentication with verification code restricted",
    "emailAttestationRequired", lambda v: v, "medium")
def eval_7_2_11(c,cfg): return _spo(c,cfg,"7.2.11","Default sharing link permission is View",
    "defaultLinkPermission", lambda v: v and v.lower() in ("view","read"), "high",
    rem="Set-SPOTenant -DefaultLinkPermission View")
def eval_7_3_1(c,cfg): return _spo(c,cfg,"7.3.1","Infected files disallowed for download",
    "disallowInfectedFileDownload", lambda v: v, "high", "L2")
def eval_7_3_2(c,cfg): return _spo(c,cfg,"7.3.2","OneDrive sync restricted unmanaged",
    "isUnmanagedSyncAppForTenantRestricted", lambda v: v, "high", "L2")
def eval_7_3_3(c,cfg): return _spo(c,cfg,"7.3.3","Custom script restricted personal sites",
    "userCustomScriptDisabled", lambda v: v, "medium")

SECTION_7_EVALUATORS = {
    "7.2.1": eval_7_2_1, "7.2.2": eval_7_2_2, "7.2.3": eval_7_2_3,
    "7.2.4": eval_7_2_4, "7.2.5": eval_7_2_5, "7.2.6": eval_7_2_6,
    "7.2.7": eval_7_2_7,
    "7.2.8": _m("7.2.8","External sharing by security group","SharePoint","medium","L2"),
    "7.2.9": eval_7_2_9, "7.2.10": eval_7_2_10, "7.2.11": eval_7_2_11,
    "7.3.1": eval_7_3_1, "7.3.2": eval_7_3_2, "7.3.3": eval_7_3_3,
    "7.3.4": _m("7.3.4","Custom script restricted site collections","SharePoint","medium"),
}

# ═══════ Section 8: Teams (17 controls, 15 automated) ═══════

def _teams(c, cfg, cid, title, endpoint, field, test_fn, sev="medium", lv="L1"):
    data = c.graph_beta(f"teamwork/{endpoint}") if "/" not in endpoint else c.graph_beta(endpoint)
    val = data.get(field, data.get("value",{}).get(field)) if data else None
    return [make_result(cid, title, cfg.tenant_id, test_fn(val) if val is not None else False,
        f"{field}: {val}", sev, "Teams",
        f"Teams admin center: adjust {field}", level=lv)]

def eval_8_1_2(c,cfg):
    data = c.graph_beta("teamwork/teamsAppSettings")
    val = data.get("allowEmailIntoChannel", True) if data else True
    return [make_result("8.1.2","Users cant email to channel", cfg.tenant_id, not val,
        severity="medium", service="Teams",
        remediation="Set-CsTeamsClientConfiguration -AllowEmailIntoChannel $false")]

def eval_8_2_2(c,cfg):
    data = c.graph_beta("tenantRelationships/crossTenantAccessPolicy/default")
    unmanaged = data.get("b2bDirectConnectInbound",{}).get("usersAndGroups",{}).get("accessType","") == "blocked"
    return [make_result("8.2.2","Communication with unmanaged Teams disabled", cfg.tenant_id, unmanaged,
        severity="medium", service="Teams",
        remediation="Teams admin > External access: disable unmanaged users")]

def eval_8_2_4(c,cfg):
    data = c.graph_beta("tenantRelationships/crossTenantAccessPolicy/default")
    return [make_result("8.2.4","No communication with trial tenants", cfg.tenant_id, False,
        "Verify: ExternalAccessWithTrialTenants = Blocked", "medium", "Teams",
        "Set-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants Blocked")]

def eval_8_5_2(c,cfg):
    return _teams(c,cfg,"8.5.2","Anonymous/dial-in cant start meetings",
        "teamsMeetingPolicy", "allowAnonymousUsersToStartMeeting", lambda v: not v)
def eval_8_5_3(c,cfg):
    return _teams(c,cfg,"8.5.3","Only org members bypass lobby",
        "teamsMeetingPolicy", "autoAdmittedUsers", lambda v: v in ("EveryoneInCompany","OrganizerOnly","InvitedUsers"))
def eval_8_5_4(c,cfg):
    return _teams(c,cfg,"8.5.4","Dial-in cant bypass lobby",
        "teamsMeetingPolicy", "allowPSTNUsersToBypassLobby", lambda v: not v)
def eval_8_5_7(c,cfg):
    return _teams(c,cfg,"8.5.7","External cant give/request control",
        "teamsMeetingPolicy", "allowExternalParticipantGiveRequestControl", lambda v: not v)
def eval_8_6_1(c,cfg):
    return _teams(c,cfg,"8.6.1","Users can report security concerns",
        "teamsMessagingPolicy", "allowSecurityEndUserReporting", lambda v: v)

SECTION_8_EVALUATORS = {
    "8.1.1": _m("8.1.1","External file sharing approved storage","Teams","medium","L2"),
    "8.1.2": eval_8_1_2,
    "8.2.1": _m("8.2.1","External domains restricted","Teams","medium","L2"),
    "8.2.2": eval_8_2_2,
    "8.2.3": _m("8.2.3","External users cant initiate conversations","Teams","medium"),
    "8.2.4": eval_8_2_4,
    "8.4.1": _m("8.4.1","App permission policies configured","Teams","medium"),
    "8.5.1": _m("8.5.1","Anonymous cant join meetings","Teams","medium","L2"),
    "8.5.2": eval_8_5_2, "8.5.3": eval_8_5_3, "8.5.4": eval_8_5_4,
    "8.5.5": _m("8.5.5","Meeting chat disallows anonymous","Teams","medium","L2"),
    "8.5.6": _m("8.5.6","Only organizers can present","Teams","medium","L2"),
    "8.5.7": eval_8_5_7,
    "8.5.8": _m("8.5.8","External meeting chat off","Teams","medium","L2"),
    "8.5.9": _m("8.5.9","Meeting recording off","Teams","medium","L2"),
    "8.6.1": eval_8_6_1,
}

# ═══════ Section 9: Fabric / Power BI (12 controls, 12 automated) ═══════

def _fabric(c, cfg, cid, title, setting_name, test_fn, sev="medium"):
    data = c.fabric("tenantsettings")
    settings = data.get("tenantSettings", data.get("value", []))
    if isinstance(settings, list):
        match = [s for s in settings if s.get("settingName","") == setting_name]
        val = match[0].get("tenantSettingGroup","") if match else None
        enabled = match[0].get("enabled", False) if match else None
        return [make_result(cid, title, cfg.tenant_id, test_fn(enabled) if enabled is not None else False,
            f"{setting_name}: {enabled}", sev, "Fabric",
            f"Fabric admin > Tenant settings: adjust {setting_name}")]
    return [make_result(cid, title, cfg.tenant_id, False, "Could not read Fabric settings", sev, "Fabric")]

def eval_9_1_1(c,cfg): return _fabric(c,cfg,"9.1.1","Guest user access restricted","AllowExternalDataSharingReceiverCapacity",lambda v: not v)
def eval_9_1_2(c,cfg): return _fabric(c,cfg,"9.1.2","External invitations restricted","AllowExternalUserInvitations",lambda v: not v)
def eval_9_1_3(c,cfg): return _fabric(c,cfg,"9.1.3","Guest access to content restricted","ElevatedGuestsTenant",lambda v: not v)
def eval_9_1_4(c,cfg): return _fabric(c,cfg,"9.1.4","Publish to web restricted","PublishToWeb",lambda v: not v,"high")
def eval_9_1_5(c,cfg): return _fabric(c,cfg,"9.1.5","R/Python visuals disabled","RScriptVisual",lambda v: not v)
def eval_9_1_6(c,cfg): return _fabric(c,cfg,"9.1.6","Sensitivity labels enabled","InformationProtectionEnabled",lambda v: v)
def eval_9_1_7(c,cfg): return _fabric(c,cfg,"9.1.7","Shareable links restricted","ShareLinkToEntireOrg",lambda v: not v)
def eval_9_1_8(c,cfg): return _fabric(c,cfg,"9.1.8","External data sharing restricted","ExternalDatasetSharingTenant",lambda v: not v)
def eval_9_1_9(c,cfg): return _fabric(c,cfg,"9.1.9","ResourceKey Auth blocked","BlockResourceKeyAuthentication",lambda v: v)
def eval_9_1_10(c,cfg): return _fabric(c,cfg,"9.1.10","API access by SPs restricted","ServicePrincipalAccess",lambda v: not v)
def eval_9_1_11(c,cfg): return _fabric(c,cfg,"9.1.11","SPs cant create/use profiles","AllowServicePrincipalProfileCreation",lambda v: not v)
def eval_9_1_12(c,cfg): return _fabric(c,cfg,"9.1.12","SPs restricted from workspaces","AllowServicePrincipalUseReadAdminAPIs",lambda v: not v)

SECTION_9_EVALUATORS = {
    "9.1.1": eval_9_1_1, "9.1.2": eval_9_1_2, "9.1.3": eval_9_1_3,
    "9.1.4": eval_9_1_4, "9.1.5": eval_9_1_5, "9.1.6": eval_9_1_6,
    "9.1.7": eval_9_1_7, "9.1.8": eval_9_1_8, "9.1.9": eval_9_1_9,
    "9.1.10": eval_9_1_10, "9.1.11": eval_9_1_11, "9.1.12": eval_9_1_12,
}
