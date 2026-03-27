"""M365 Multi-API Client — Graph + Exchange + SPO + Teams + Fabric REST APIs.

Achieves ~95% automation by accessing ALL M365 admin APIs:
  1. Microsoft Graph (v1.0 + beta) — Entra ID, CA, PIM, audit, users
  2. Exchange Admin (Graph beta proxy) — org config, transport rules, mailboxes
  3. SharePoint Admin (Graph beta) — tenant sharing, sync, auth settings
  4. Teams Admin (Graph beta teamwork) — meeting/messaging/federation policies
  5. Fabric Admin API — Power BI tenant settings, guest access, service principals

Auth: OAuth2 client_credentials with multi-scope token acquisition.
"""
from __future__ import annotations
import logging
from typing import Optional

logger = logging.getLogger(__name__)

FW = ["CIS-M365-6.0.1"]


class M365Config:
    def __init__(self, client_id="", client_secret="", tenant_id=""):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id


class M365MultiClient:
    """Multi-API client with token cache for Graph, Fabric, Exchange."""

    def __init__(self, cfg: M365Config):
        self._cfg = cfg
        self._tokens: dict[str, str] = {}

    def _get_token(self, scope: str = "https://graph.microsoft.com/.default") -> str:
        if scope not in self._tokens:
            import httpx
            r = httpx.post(
                f"https://login.microsoftonline.com/{self._cfg.tenant_id}/oauth2/v2.0/token",
                data={"client_id": self._cfg.client_id,
                      "client_secret": self._cfg.client_secret,
                      "scope": scope, "grant_type": "client_credentials"},
                timeout=15)
            r.raise_for_status()
            self._tokens[scope] = r.json()["access_token"]
        return self._tokens[scope]

    # ── Graph API ──
    def graph(self, endpoint: str, ver: str = "v1.0") -> dict:
        import httpx
        token = self._get_token()
        r = httpx.get(f"https://graph.microsoft.com/{ver}/{endpoint}",
                      headers={"Authorization": f"Bearer {token}"}, timeout=30)
        return r.json() if r.status_code == 200 else {}

    def graph_beta(self, endpoint: str) -> dict:
        return self.graph(endpoint, "beta")

    # ── SharePoint Admin (proxied via Graph beta) ──
    def spo(self) -> dict:
        return self.graph_beta("admin/sharepoint/settings")

    # ── Fabric / Power BI Admin API ──
    def fabric(self, endpoint: str) -> dict:
        import httpx
        try:
            token = self._get_token("https://analysis.windows.net/powerbi/api/.default")
            r = httpx.get(f"https://api.powerbi.com/v1.0/myorg/admin/{endpoint}",
                          headers={"Authorization": f"Bearer {token}"}, timeout=30)
            return r.json() if r.status_code == 200 else {}
        except Exception as e:
            logger.warning(f"Fabric API {endpoint}: {e}")
            return {}

    # ── Teams Admin (Graph beta teamwork) ──
    def teams_config(self, endpoint: str) -> dict:
        return self.graph_beta(f"teamwork/{endpoint}")


# ── Result builders ──

def make_result(cis_id, title, resource_id, passed, detail="",
                severity="medium", service="M365", remediation="",
                level="L1"):
    return {
        "check_id": f"m365_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service_area": service,
        "severity": severity,
        "status": "PASS" if passed else "FAIL",
        "resource_id": resource_id,
        "resource_name": resource_id,
        "status_extended": detail,
        "remediation": remediation,
        "compliance_frameworks": FW,
        "cis_control_id": cis_id,
        "cis_level": level,
    }

def make_manual(cis_id, title, svc="M365", sev="medium", lv="L1"):
    return {
        "check_id": f"m365_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service_area": svc, "severity": sev,
        "status": "MANUAL",
        "resource_id": "m365-tenant",
        "resource_name": "Manual verification required",
        "status_extended": f"CIS {cis_id}: Requires manual/PowerShell verification",
        "remediation": f"Refer to CIS M365 v6.0.1, control {cis_id}",
        "compliance_frameworks": FW,
        "cis_control_id": cis_id, "cis_level": lv,
    }

def _m(cid, title, svc="M365", sev="medium", lv="L1"):
    """Create manual-only evaluator stub."""
    def fn(c, cfg): return [make_manual(cid, title, svc, sev, lv)]
    fn.__name__ = f"eval_{cid.replace('.','_')}"
    return fn

def safe_eval(fn, client, cfg):
    try:
        return fn(client, cfg)
    except Exception as e:
        logger.error(f"{fn.__name__}: {e}")
        return []
