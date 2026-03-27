"""Alibaba Cloud CIS Evaluator Base — client cache, helpers, result builders.

Uses alibabacloud SDKs (Tea OpenAPI) for all API calls.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class EvalConfig:
    access_key_id: str = ""
    access_key_secret: str = ""
    regions: list[str] = field(default_factory=lambda: ["cn-hangzhou"])


class AlibabaClientCache:
    """Lazy-create Alibaba Cloud SDK clients and cache them."""

    def __init__(self, cfg: EvalConfig):
        self._cfg = cfg
        self._clients: dict[str, Any] = {}

    def _make_config(self, endpoint: str):
        from alibabacloud_tea_openapi.models import Config
        return Config(
            access_key_id=self._cfg.access_key_id,
            access_key_secret=self._cfg.access_key_secret,
            endpoint=endpoint,
        )

    def _region_config(self, service: str, region: str):
        from alibabacloud_tea_openapi.models import Config
        return Config(
            access_key_id=self._cfg.access_key_id,
            access_key_secret=self._cfg.access_key_secret,
            region_id=region,
            endpoint=f"{service}.{region}.aliyuncs.com",
        )

    @property
    def ram(self):
        if "ram" not in self._clients:
            from alibabacloud_ram20150501.client import Client
            self._clients["ram"] = Client(self._make_config("ram.aliyuncs.com"))
        return self._clients["ram"]

    @property
    def actiontrail(self):
        if "actiontrail" not in self._clients:
            from alibabacloud_actiontrail20200706.client import Client
            self._clients["actiontrail"] = Client(
                self._make_config("actiontrail.cn-hangzhou.aliyuncs.com"))
        return self._clients["actiontrail"]

    def ecs(self, region: str):
        key = f"ecs_{region}"
        if key not in self._clients:
            from alibabacloud_ecs20140526.client import Client
            self._clients[key] = Client(self._region_config("ecs", region))
        return self._clients[key]

    def rds(self, region: str):
        key = f"rds_{region}"
        if key not in self._clients:
            from alibabacloud_rds20140815.client import Client
            self._clients[key] = Client(self._region_config("rds", region))
        return self._clients[key]

    def vpc(self, region: str):
        key = f"vpc_{region}"
        if key not in self._clients:
            from alibabacloud_vpc20160428.client import Client
            self._clients[key] = Client(self._region_config("vpc", region))
        return self._clients[key]

    def kms(self, region: str):
        key = f"kms_{region}"
        if key not in self._clients:
            from alibabacloud_kms20160120.client import Client
            self._clients[key] = Client(self._region_config("kms", region))
        return self._clients[key]

    def oss_auth(self):
        import oss2
        return oss2.Auth(self._cfg.access_key_id, self._cfg.access_key_secret)

    def cs(self):
        if "cs" not in self._clients:
            from alibabacloud_cs20151215.client import Client
            self._clients["cs"] = Client(self._make_config("cs.aliyuncs.com"))
        return self._clients["cs"]

    def sas(self):
        if "sas" not in self._clients:
            from alibabacloud_sas20181203.client import Client
            self._clients["sas"] = Client(self._make_config("tds.aliyuncs.com"))
        return self._clients["sas"]


# ── Date helpers ──

def days_since(dt_str: Optional[str]) -> int:
    if not dt_str:
        return 9999
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return 9999


# ── Result builders ──

def make_result(cis_id, title, resource_id, resource_name, passed,
                detail="", severity="medium", service="Alibaba", remediation=""):
    return {
        "check_id": f"ali_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": "PASS" if passed else "FAIL",
        "resource_id": resource_id,
        "resource_name": resource_name,
        "status_extended": detail,
        "remediation": remediation,
        "compliance_frameworks": ["CIS-Alibaba-2.0"],
        "cis_control_id": cis_id,
    }


def make_manual_result(cis_id, title, service="Alibaba", severity="medium"):
    return {
        "check_id": f"ali_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": "MANUAL",
        "resource_id": "alibaba-account",
        "resource_name": "Manual verification required",
        "status_extended": f"CIS {cis_id}: Requires manual verification via Alibaba Console",
        "remediation": f"Refer to CIS Alibaba Cloud Foundation Benchmark v2.0.0, control {cis_id}",
        "compliance_frameworks": ["CIS-Alibaba-2.0"],
        "cis_control_id": cis_id,
    }


def safe_evaluate(fn, clients, cfg):
    try:
        return fn(clients, cfg)
    except Exception as e:
        logger.error(f"Evaluator {fn.__name__} failed: {e}")
        return []
