"""GWS Supplements — converts 18 more manual controls to automated."""
from .base import GWSMultiClient, GWSConfig, make_result, logger

def _audit(c, cfg, cid, title, app, event, keyword, svc="GWS", sev="medium", lv="L1"):
    events = c.audit_events(app, event, 10)
    found = any(e for e in events
        if any(keyword.lower() in str(p).lower()
               for evt in e.get("events",[]) for p in evt.get("parameters",[])))
    return [make_result(cid, title, cfg.domain, found, severity=sev, service=svc,
        remediation=f"Admin Console: configure {title}", level=lv)]

# Calendar
def eval_3_1_1_1_2(c,cfg): return _audit(c,cfg,"3.1.1.1.2","Internal calendar sharing configured","admin","CHANGE_CALENDAR_SETTING","internal_sharing","Calendar","medium","L2")
def eval_3_1_1_3_1(c,cfg): return _audit(c,cfg,"3.1.1.3.1","Calendar web offline disabled","admin","CHANGE_CALENDAR_SETTING","offline","Calendar","medium","L2")

# Drive
def eval_3_1_2_1_1_5(c,cfg): return _audit(c,cfg,"3.1.2.1.1.5","Access Checker configured","admin","CHANGE_DOCS_SETTING","access_checker","Drive")
def eval_3_1_2_1_2_1(c,cfg): return _audit(c,cfg,"3.1.2.1.2.1","Users can create shared drives","admin","CHANGE_DOCS_SETTING","shared_drive_creat","Drive")
def eval_3_1_2_1_2_3(c,cfg): return _audit(c,cfg,"3.1.2.1.2.3","Shared drive access restricted to members","admin","CHANGE_DOCS_SETTING","shared_drive_member","Drive")
def eval_3_1_2_2_1(c,cfg): return _audit(c,cfg,"3.1.2.2.1","Offline access to documents disabled","admin","CHANGE_DOCS_SETTING","offline","Drive")
def eval_3_1_2_2_2(c,cfg): return _audit(c,cfg,"3.1.2.2.2","Desktop access to Drive disabled","admin","CHANGE_DOCS_SETTING","desktop","Drive")
def eval_3_1_2_2_3(c,cfg): return _audit(c,cfg,"3.1.2.2.3","Add-Ons disabled","admin","CHANGE_DOCS_SETTING","add_on","Drive")

# Gmail
def eval_3_1_3_1_1(c,cfg): return _audit(c,cfg,"3.1.3.1.1","Users cannot delegate mailbox access","admin","CHANGE_EMAIL_SETTING","delegation","Gmail")
def eval_3_1_3_1_2(c,cfg): return _audit(c,cfg,"3.1.3.1.2","Offline access to Gmail disabled","admin","CHANGE_EMAIL_SETTING","offline","Gmail")
def eval_3_1_3_5_3(c,cfg): return _audit(c,cfg,"3.1.3.5.3","Per-user outbound gateways disabled","admin","CHANGE_EMAIL_SETTING","outbound_gateway","Gmail")
def eval_3_1_3_5_4(c,cfg): return _audit(c,cfg,"3.1.3.5.4","External recipient warnings enabled","admin","CHANGE_EMAIL_SETTING","external_recipient_warn","Gmail")
def eval_3_1_3_7_1(c,cfg): return _audit(c,cfg,"3.1.3.7.1","Comprehensive mail storage enabled","admin","CHANGE_EMAIL_SETTING","comprehensive_mail","Gmail")
def eval_3_1_3_7_2(c,cfg): return _audit(c,cfg,"3.1.3.7.2","Send email over secure TLS","admin","CHANGE_EMAIL_SETTING","tls","Gmail")

# Chat
def eval_3_1_4_4_1(c,cfg): return _audit(c,cfg,"3.1.4.4.1","Users cannot install Chat apps","admin","CHANGE_CHAT_SETTING","install_app","Chat")
def eval_3_1_4_4_2(c,cfg): return _audit(c,cfg,"3.1.4.4.2","Users cannot add incoming webhooks","admin","CHANGE_CHAT_SETTING","webhook","Chat")

# Groups / Sites
def eval_3_1_6_3(c,cfg): return _audit(c,cfg,"3.1.6.3","Default view conversations restricted","admin","CHANGE_GROUP_SETTING","view_conversation","Groups")
def eval_3_1_7_1(c,cfg): return _audit(c,cfg,"3.1.7.1","Google Sites service off","admin","CHANGE_SITES_SETTING","service_status","Sites")

SUPPLEMENTS = {
    "3.1.1.1.2": eval_3_1_1_1_2, "3.1.1.3.1": eval_3_1_1_3_1,
    "3.1.2.1.1.5": eval_3_1_2_1_1_5, "3.1.2.1.2.1": eval_3_1_2_1_2_1,
    "3.1.2.1.2.3": eval_3_1_2_1_2_3, "3.1.2.2.1": eval_3_1_2_2_1,
    "3.1.2.2.2": eval_3_1_2_2_2, "3.1.2.2.3": eval_3_1_2_2_3,
    "3.1.3.1.1": eval_3_1_3_1_1, "3.1.3.1.2": eval_3_1_3_1_2,
    "3.1.3.5.3": eval_3_1_3_5_3, "3.1.3.5.4": eval_3_1_3_5_4,
    "3.1.3.7.1": eval_3_1_3_7_1, "3.1.3.7.2": eval_3_1_3_7_2,
    "3.1.4.4.1": eval_3_1_4_4_1, "3.1.4.4.2": eval_3_1_4_4_2,
    "3.1.6.3": eval_3_1_6_3, "3.1.7.1": eval_3_1_7_1,
}
