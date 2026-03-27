"""Google Workspace Multi-API Client — Admin SDK + Cloud Identity Policy API + DNS.

APIs used (following ScubaGoggles/CISA approach):
  1. Admin SDK Directory (admin/directory_v1) — users, roles, domains, org units
  2. Admin SDK Reports (admin/reports_v1) — audit logs, alert rule activity
  3. Cloud Identity Policy API (cloudidentity.googleapis.com) — GWS app settings
     (Gmail, Calendar, Drive, Chat, Groups, Sites, Meet, Classroom)
  4. Groups Settings API (groupssettings/v1) — group sharing settings
  5. DNS resolution (dnspython) — SPF, DKIM, DMARC

Auth: Service account with domain-wide delegation + subject impersonation.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)
FW = ["CIS-GW-1.3.0"]


class GWSConfig:
    def __init__(self, service_account_key: dict = None, admin_email: str = "",
                 domain: str = "", customer_id: str = "my_customer"):
        self.sa_key = service_account_key or {}
        self.admin_email = admin_email
        self.domain = domain
        self.customer_id = customer_id


class GWSMultiClient:
    """Multi-API client using google-api-python-client + service account delegation."""

    SCOPES = [
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/apps.groups.settings",
        "https://www.googleapis.com/auth/cloud-identity.policies.readonly",
        "https://www.googleapis.com/auth/cloud-platform",
    ]

    def __init__(self, cfg: GWSConfig):
        self._cfg = cfg
        self._services: dict[str, Any] = {}
        self._headers: Optional[dict] = None

    def _get_creds(self):
        from google.oauth2 import service_account
        creds = service_account.Credentials.from_service_account_info(
            self._cfg.sa_key, scopes=self.SCOPES)
        return creds.with_subject(self._cfg.admin_email)

    def _build(self, api: str, version: str):
        key = f"{api}_{version}"
        if key not in self._services:
            from googleapiclient.discovery import build
            self._services[key] = build(api, version, credentials=self._get_creds())
        return self._services[key]

    @property
    def directory(self):
        return self._build("admin", "directory_v1")

    @property
    def reports(self):
        return self._build("admin", "reports_v1")

    # ── Directory helpers ──
    def list_users(self, max_results=500) -> list[dict]:
        users = []
        req = self.directory.users().list(domain=self._cfg.domain, maxResults=max_results)
        while req:
            resp = req.execute()
            users.extend(resp.get("users", []))
            req = self.directory.users().list_next(req, resp)
        return users

    def list_domains(self) -> list[dict]:
        return self.directory.domains().list(customer=self._cfg.customer_id).execute().get("domains", [])

    # ── Reports / Audit helpers ──
    def audit_events(self, app: str, event_name: str, max_results: int = 5) -> list[dict]:
        try:
            resp = self.reports.activities().list(
                userKey="all", applicationName=app,
                eventName=event_name, maxResults=max_results
            ).execute()
            return resp.get("items", [])
        except Exception:
            return []

    # ── Cloud Identity Policy API (REST) ──
    def policy_get(self, setting_path: str) -> dict:
        """Read GWS setting via Cloud Identity Policy API.
        setting_path examples:
          'gmail' → gmail settings
          'calendar' → calendar settings
          'drive_and_docs' → drive settings
          'chat' → chat settings
          'groups_for_business' → groups settings
          'sites' → sites settings
        """
        import httpx
        try:
            creds = self._get_creds()
            import google.auth.transport.requests
            creds.refresh(google.auth.transport.requests.Request())
            token = creds.token
            # Cloud Identity Policy API endpoint
            url = (f"https://cloudidentity.googleapis.com/v1beta1/"
                   f"customers/{self._cfg.customer_id}/policies")
            r = httpx.get(url, headers={"Authorization": f"Bearer {token}"},
                         params={"filter": f"setting.type='{setting_path}'"}, timeout=30)
            return r.json() if r.status_code == 200 else {}
        except Exception as e:
            logger.debug(f"Policy API {setting_path}: {e}")
            return {}

    # ── DNS resolution ──
    def dns_txt(self, name: str) -> list[str]:
        try:
            import dns.resolver
            return [str(r) for r in dns.resolver.resolve(name, "TXT")]
        except Exception:
            return []

    def check_spf(self, domain: str) -> tuple[bool, bool]:
        """Returns (has_spf, is_strict)."""
        records = self.dns_txt(domain)
        spf = [r for r in records if "v=spf1" in r]
        return bool(spf), any("-all" in r for r in spf)

    def check_dkim(self, domain: str, selector: str = "google") -> bool:
        return bool(self.dns_txt(f"{selector}._domainkey.{domain}"))

    def check_dmarc(self, domain: str) -> tuple[bool, bool]:
        """Returns (has_dmarc, is_reject_or_quarantine)."""
        records = self.dns_txt(f"_dmarc.{domain}")
        dmarc = [r for r in records if "v=DMARC1" in r]
        strict = any("p=reject" in r or "p=quarantine" in r for r in dmarc)
        return bool(dmarc), strict


# ── Result builders ──

def make_result(cis_id, title, resource_id, passed, detail="",
                severity="medium", service="GWS", remediation="", level="L1"):
    return {
        "check_id": f"gws_cis_{cis_id.replace('.', '_')}",
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

def make_manual(cis_id, title, svc="GWS", sev="medium", lv="L1"):
    return {
        "check_id": f"gws_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service_area": svc, "severity": sev,
        "status": "MANUAL",
        "resource_id": "gws-domain",
        "resource_name": "Manual verification required",
        "status_extended": f"CIS {cis_id}: Requires Admin Console verification",
        "remediation": f"Refer to CIS Google Workspace v1.3.0, control {cis_id}",
        "compliance_frameworks": FW,
        "cis_control_id": cis_id, "cis_level": lv,
    }

def _m(cid, title, svc="GWS", sev="medium", lv="L1"):
    def fn(c, cfg): return [make_manual(cid, title, svc, sev, lv)]
    fn.__name__ = f"eval_{cid.replace('.','_')}"
    return fn

def safe_eval(fn, client, cfg):
    try:
        return fn(client, cfg)
    except Exception as e:
        logger.error(f"{fn.__name__}: {e}")
        return []
