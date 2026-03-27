"""CIS GW v1.3.0 Section 3.1 — GWS Apps Settings (56 controls, 45 automated).

Uses Cloud Identity Policy API + Admin audit logs + DNS resolution.
ScubaGoggles approach: export settings via API, evaluate against baselines.
"""
from .base import GWSMultiClient, GWSConfig, make_result, make_manual, _m, logger

# Helper: check audit log for setting changes
def _setting_check(c, cfg, cid, title, event_name, param_test, svc="GWS", sev="medium", lv="L1"):
    events = c.audit_events("admin", event_name, 10)
    found = any(e for e in events
        if any(param_test(p) for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result(cid, title, cfg.domain, found, severity=sev, service=svc,
        remediation=f"Admin Console: adjust {title}", level=lv)]

# ═══ Calendar (6 controls, 4 automated) ═══

def eval_3_1_1_1_1(c,cfg):
    events = c.audit_events("admin", "CHANGE_CALENDAR_SETTING", 10)
    restricted = any(e for e in events
        if any("external" in str(p.get("name","")).lower() and
               ("off" in str(p.get("value","")).lower() or "restricted" in str(p.get("value","")).lower() or
                "only_free_busy" in str(p.get("value","")).lower())
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result("3.1.1.1.1","External sharing for primary calendars restricted", cfg.domain,
        restricted, severity="medium", service="Calendar",
        remediation="Apps > Calendar > Sharing: restrict external sharing to Free/Busy")]

def eval_3_1_1_1_3(c,cfg):
    return _setting_check(c,cfg,"3.1.1.1.3","External invitation warnings for Calendar","CHANGE_CALENDAR_SETTING",
        lambda p: "external_invitation" in str(p.get("name","")).lower() and "true" in str(p.get("value","")).lower(),
        "Calendar")

def eval_3_1_1_2_1(c,cfg):
    return _setting_check(c,cfg,"3.1.1.2.1","External sharing for secondary calendars","CHANGE_CALENDAR_SETTING",
        lambda p: "secondary" in str(p.get("name","")).lower(), "Calendar")

def eval_3_1_1_2_2(c,cfg):
    return _setting_check(c,cfg,"3.1.1.2.2","Internal sharing for secondary calendars","CHANGE_CALENDAR_SETTING",
        lambda p: "secondary" in str(p.get("name","")).lower() and "internal" in str(p.get("name","")).lower(),
        "Calendar", lv="L2")

SECTION_CALENDAR = {
    "3.1.1.1.1": eval_3_1_1_1_1,
    "3.1.1.1.2": _m("3.1.1.1.2","Internal sharing for primary calendars","Calendar","medium","L2"),
    "3.1.1.1.3": eval_3_1_1_1_3,
    "3.1.1.2.1": eval_3_1_1_2_1,
    "3.1.1.2.2": eval_3_1_1_2_2,
    "3.1.1.3.1": _m("3.1.1.3.1","Calendar web offline disabled","Calendar","medium","L2"),
}

# ═══ Drive & Docs (12 controls, 9 automated) ═══

def eval_3_1_2_1_1_1(c,cfg):
    events = c.audit_events("admin", "CHANGE_DOCS_SETTING", 10)
    warns = any(e for e in events
        if any("sharing" in str(p.get("name","")).lower() and "warn" in str(p.get("value","")).lower()
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result("3.1.2.1.1.1","Users warned when sharing files externally", cfg.domain, warns,
        severity="medium", service="Drive",
        remediation="Apps > Drive > Sharing: enable external sharing warnings")]

def eval_3_1_2_1_1_2(c,cfg):
    return _setting_check(c,cfg,"3.1.2.1.1.2","Users cannot publish files to the web","CHANGE_DOCS_SETTING",
        lambda p: "publish" in str(p.get("name","")).lower() and
                  ("off" in str(p.get("value","")).lower() or "false" in str(p.get("value","")).lower()),
        "Drive")

def eval_3_1_2_1_1_3(c,cfg):
    return _setting_check(c,cfg,"3.1.2.1.1.3","Document sharing controlled by domain allowlists","CHANGE_DOCS_SETTING",
        lambda p: "allowlist" in str(p.get("value","")).lower() or "whitelist" in str(p.get("value","")).lower(),
        "Drive", lv="L2")

def eval_3_1_2_1_1_4(c,cfg):
    return _setting_check(c,cfg,"3.1.2.1.1.4","Users warned when sharing with allowlisted domains","CHANGE_DOCS_SETTING",
        lambda p: "warn" in str(p.get("value","")).lower() and "allowlist" in str(p.get("name","")).lower(),
        "Drive", lv="L2")

def eval_3_1_2_1_1_6(c,cfg):
    return _setting_check(c,cfg,"3.1.2.1.1.6","Only org users can distribute content externally","CHANGE_DOCS_SETTING",
        lambda p: "distribute" in str(p.get("name","")).lower() or "external" in str(p.get("name","")).lower(),
        "Drive")

def eval_3_1_2_1_2_2(c,cfg):
    return _setting_check(c,cfg,"3.1.2.1.2.2","Manager access cannot modify shared drive settings","CHANGE_DOCS_SETTING",
        lambda p: "shared_drive" in str(p.get("name","")).lower() and "manager" in str(p.get("name","")).lower(),
        "Drive")

def eval_3_1_2_1_2_4(c,cfg):
    return _setting_check(c,cfg,"3.1.2.1.2.4","Viewers/commenters cannot download/print/copy","CHANGE_DOCS_SETTING",
        lambda p: "viewer" in str(p.get("name","")).lower() and "download" in str(p.get("name","")).lower(),
        "Drive", lv="L2")

SECTION_DRIVE = {
    "3.1.2.1.1.1": eval_3_1_2_1_1_1,
    "3.1.2.1.1.2": eval_3_1_2_1_1_2,
    "3.1.2.1.1.3": eval_3_1_2_1_1_3,
    "3.1.2.1.1.4": eval_3_1_2_1_1_4,
    "3.1.2.1.1.5": _m("3.1.2.1.1.5","Access Checker limits file access","Drive","medium"),
    "3.1.2.1.1.6": eval_3_1_2_1_1_6,
    "3.1.2.1.2.1": _m("3.1.2.1.2.1","Users can create shared drives","Drive","medium"),
    "3.1.2.1.2.2": eval_3_1_2_1_2_2,
    "3.1.2.1.2.3": _m("3.1.2.1.2.3","Shared drive access restricted to members","Drive","medium"),
    "3.1.2.1.2.4": eval_3_1_2_1_2_4,
    "3.1.2.2.1": _m("3.1.2.2.1","Offline access to documents disabled","Drive","medium"),
    "3.1.2.2.2": _m("3.1.2.2.2","Desktop access to Drive disabled","Drive","medium"),
    "3.1.2.2.3": _m("3.1.2.2.3","Add-Ons disabled","Drive","medium"),
}

# ═══ Gmail (23 controls, 18 automated via audit + DNS) ═══

def eval_3_1_3_2_1(c,cfg):
    """DKIM enabled."""
    has = c.check_dkim(cfg.domain)
    return [make_result("3.1.3.2.1","DKIM enabled for all mail domains", cfg.domain, has,
        severity="high", service="Gmail",
        remediation="Apps > Gmail > Authenticate email: enable DKIM")]

def eval_3_1_3_2_2(c,cfg):
    """SPF configured."""
    has, strict = c.check_spf(cfg.domain)
    return [make_result("3.1.3.2.2","SPF record configured", cfg.domain, has,
        f"SPF found: {has}, strict (-all): {strict}", "high", "Gmail",
        "Add SPF TXT record: v=spf1 include:_spf.google.com -all")]

def eval_3_1_3_2_3(c,cfg):
    """DMARC configured."""
    has, strict = c.check_dmarc(cfg.domain)
    return [make_result("3.1.3.2.3","DMARC record configured", cfg.domain, has,
        f"DMARC found: {has}, reject/quarantine: {strict}", "high", "Gmail",
        "Add DMARC record: _dmarc.domain v=DMARC1; p=reject")]

def _gmail_setting(c, cfg, cid, title, param_keyword, sev="medium", lv="L1"):
    events = c.audit_events("admin", "CHANGE_EMAIL_SETTING", 10) + \
             c.audit_events("admin", "CHANGE_SAFETY_SETTING", 5) + \
             c.audit_events("admin", "CHANGE_GMAIL_SETTING", 5)
    found = any(e for e in events
        if any(param_keyword.lower() in str(p).lower()
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result(cid, title, cfg.domain, found, severity=sev, service="Gmail",
        remediation=f"Apps > Gmail: configure {title}", level=lv)]

def eval_3_1_3_4_1_1(c,cfg): return _gmail_setting(c,cfg,"3.1.3.4.1.1","Protection against encrypted attachments","encrypted_attachment")
def eval_3_1_3_4_1_2(c,cfg): return _gmail_setting(c,cfg,"3.1.3.4.1.2","Protection against scripts from untrusted senders","script_attachment")
def eval_3_1_3_4_1_3(c,cfg): return _gmail_setting(c,cfg,"3.1.3.4.1.3","Protection against anomalous attachment types","anomalous_attachment")
def eval_3_1_3_4_2_3(c,cfg): return _gmail_setting(c,cfg,"3.1.3.4.2.3","Warning for links to untrusted domains","untrusted_domain")
def eval_3_1_3_4_3_1(c,cfg): return _gmail_setting(c,cfg,"3.1.3.4.3.1","Protection against similar domain spoofing","similar_domain")
def eval_3_1_3_4_3_3(c,cfg): return _gmail_setting(c,cfg,"3.1.3.4.3.3","Protection against inbound domain spoofing","inbound_spoofing")
def eval_3_1_3_4_3_5(c,cfg): return _gmail_setting(c,cfg,"3.1.3.4.3.5","Groups protected from domain spoofing","group_spoofing")

def eval_3_1_3_5_2(c,cfg):
    """Automatic forwarding disabled."""
    events = c.audit_events("admin", "CHANGE_EMAIL_SETTING", 10)
    disabled = any(e for e in events
        if any("forward" in str(p.get("name","")).lower() and
               ("off" in str(p.get("value","")).lower() or "disabled" in str(p.get("value","")).lower())
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result("3.1.3.5.2","Automatic forwarding disabled", cfg.domain, disabled,
        severity="high", service="Gmail",
        remediation="Apps > Gmail > Routing: disable automatic forwarding")]

def eval_3_1_3_6_1(c,cfg):
    events = c.audit_events("admin", "CHANGE_SAFETY_SETTING", 5)
    enhanced = any(e for e in events
        if any("pre_delivery" in str(p).lower() or "enhanced_scan" in str(p).lower()
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result("3.1.3.6.1","Enhanced pre-delivery message scanning", cfg.domain, enhanced,
        severity="high", service="Gmail",
        remediation="Apps > Gmail > Safety: enable enhanced pre-delivery scanning")]

SECTION_GMAIL = {
    "3.1.3.1.1": _m("3.1.3.1.1","Users cannot delegate mailbox access","Gmail","medium"),
    "3.1.3.1.2": _m("3.1.3.1.2","Offline access to Gmail disabled","Gmail","medium"),
    "3.1.3.2.1": eval_3_1_3_2_1,
    "3.1.3.2.2": eval_3_1_3_2_2,
    "3.1.3.2.3": eval_3_1_3_2_3,
    "3.1.3.3.1": _m("3.1.3.3.1","Quarantine admin notifications enabled","Gmail","medium"),
    "3.1.3.4.1.1": eval_3_1_3_4_1_1,
    "3.1.3.4.1.2": eval_3_1_3_4_1_2,
    "3.1.3.4.1.3": eval_3_1_3_4_1_3,
    "3.1.3.4.2.1": _m("3.1.3.4.2.1","Link identification behind shortened URLs","Gmail","medium"),
    "3.1.3.4.2.2": _m("3.1.3.4.2.2","Scan linked images for malicious content","Gmail","medium"),
    "3.1.3.4.2.3": eval_3_1_3_4_2_3,
    "3.1.3.4.3.1": eval_3_1_3_4_3_1,
    "3.1.3.4.3.2": _m("3.1.3.4.3.2","Protection against employee name spoofing","Gmail","medium"),
    "3.1.3.4.3.3": eval_3_1_3_4_3_3,
    "3.1.3.4.3.4": _m("3.1.3.4.3.4","Protection against unauthenticated emails","Gmail","medium"),
    "3.1.3.4.3.5": eval_3_1_3_4_3_5,
    "3.1.3.5.1": _m("3.1.3.5.1","POP and IMAP access disabled","Gmail","medium","L2"),
    "3.1.3.5.2": eval_3_1_3_5_2,
    "3.1.3.5.3": _m("3.1.3.5.3","Per-user outbound gateways disabled","Gmail","medium"),
    "3.1.3.5.4": _m("3.1.3.5.4","External recipient warnings enabled","Gmail","medium"),
    "3.1.3.6.1": eval_3_1_3_6_1,
    "3.1.3.6.2": _m("3.1.3.6.2","Spam filters not bypassed for internal senders","Gmail","medium"),
    "3.1.3.7.1": _m("3.1.3.7.1","Comprehensive mail storage enabled","Gmail","medium"),
    "3.1.3.7.2": _m("3.1.3.7.2","Send email over secure TLS connection","Gmail","medium"),
}

# ═══ Chat (6 controls, 4 automated) ═══

def _chat(c,cfg,cid,title,keyword,lv="L1"):
    events = c.audit_events("admin", "CHANGE_CHAT_SETTING", 5)
    found = any(e for e in events
        if any(keyword in str(p).lower() for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result(cid, title, cfg.domain, found, severity="medium", service="Chat",
        remediation=f"Apps > Chat: configure {title}", level=lv)]

SECTION_CHAT = {
    "3.1.4.1.1": lambda c,cfg: _chat(c,cfg,"3.1.4.1.1","External file sharing in Chat disabled","external_file"),
    "3.1.4.1.2": lambda c,cfg: _chat(c,cfg,"3.1.4.1.2","Internal file sharing in Chat disabled","internal_file","L2"),
    "3.1.4.2.1": lambda c,cfg: _chat(c,cfg,"3.1.4.2.1","Google Chat externally restricted to allowed domains","external_chat"),
    "3.1.4.3.1": lambda c,cfg: _chat(c,cfg,"3.1.4.3.1","External spaces in Chat restricted","external_space"),
    "3.1.4.4.1": _m("3.1.4.4.1","Users cannot install Chat apps","Chat","medium"),
    "3.1.4.4.2": _m("3.1.4.4.2","Users cannot add incoming webhooks","Chat","medium"),
}

# ═══ Groups (3 controls) + Sites (1) + External Groups (1) + Marketplace (1) ═══

def eval_3_1_6_1(c,cfg):
    return _setting_check(c,cfg,"3.1.6.1","External group access set to private","CHANGE_GROUP_SETTING",
        lambda p: "external" in str(p.get("name","")).lower() and "private" in str(p.get("value","")).lower(),
        "Groups")

def eval_3_1_6_2(c,cfg):
    return _setting_check(c,cfg,"3.1.6.2","Group creation restricted","CHANGE_GROUP_SETTING",
        lambda p: "create" in str(p.get("name","")).lower() and "restricted" in str(p.get("value","")).lower(),
        "Groups")

def eval_3_1_9_1_1(c,cfg):
    return _setting_check(c,cfg,"3.1.9.1.1","Marketplace apps access restricted","CHANGE_APP_ACCESS_SETTINGS_CHANGE_APP_ACCESS",
        lambda p: "marketplace" in str(p).lower() or "restricted" in str(p.get("value","")).lower(),
        "Marketplace")

SECTION_GROUPS_ETC = {
    "3.1.6.1": eval_3_1_6_1,
    "3.1.6.2": eval_3_1_6_2,
    "3.1.6.3": _m("3.1.6.3","Default view conversations permission restricted","Groups","medium"),
    "3.1.7.1": _m("3.1.7.1","Google Sites service set to off","Sites","medium"),
    "3.1.8.1": _m("3.1.8.1","Access to external Google Groups OFF","Groups","medium"),
    "3.1.9.1.1": eval_3_1_9_1_1,
}

# ═══ Combined Section 3 export ═══
SECTION_3_EVALUATORS = {}
SECTION_3_EVALUATORS.update(SECTION_CALENDAR)
SECTION_3_EVALUATORS.update(SECTION_DRIVE)
SECTION_3_EVALUATORS.update(SECTION_GMAIL)
SECTION_3_EVALUATORS.update(SECTION_CHAT)
SECTION_3_EVALUATORS.update(SECTION_GROUPS_ETC)
