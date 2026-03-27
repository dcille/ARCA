"""Google Workspace CIS Evaluator Engine — 89 controls, ~77% automated.

Multi-API: Admin SDK Directory + Reports + Cloud Identity Policy + DNS.

Usage:
    from scanner.saas.google_workspace.gws_cis_evaluator_engine import GWSCISEvaluatorEngine
    engine = GWSCISEvaluatorEngine(sa_key_dict, admin_email, domain)
    results = engine.evaluate_all()
"""
from __future__ import annotations
import logging
from .evaluators import EVALUATOR_REGISTRY
from .evaluators.base import GWSMultiClient, GWSConfig, safe_eval

logger = logging.getLogger(__name__)

class GWSCISEvaluatorEngine:
    SECTION_MAP = {
        "1":"Admin / Users","3":"GWS Apps (Calendar/Drive/Gmail/Chat/Groups)",
        "4":"Security & Access Control","5":"Reports","6":"Alert Rules",
    }
    def __init__(self, service_account_key: dict, admin_email: str, domain: str,
                 customer_id: str = "my_customer"):
        self.cfg = GWSConfig(service_account_key, admin_email, domain, customer_id)
        self.clients = GWSMultiClient(self.cfg)

    def evaluate_all(self) -> list[dict]:
        return [r for cid in sorted(EVALUATOR_REGISTRY, key=self._sort_key)
                for r in safe_eval(EVALUATOR_REGISTRY[cid], self.clients, self.cfg)]

    def evaluate_section(self, section: str) -> list[dict]:
        return [r for cid, fn in EVALUATOR_REGISTRY.items()
                if cid.startswith(section)
                for r in safe_eval(fn, self.clients, self.cfg)]

    def evaluate_single(self, cis_id: str) -> list[dict]:
        fn = EVALUATOR_REGISTRY.get(cis_id)
        if not fn: raise KeyError(f"Unknown CIS ID: {cis_id}")
        return safe_eval(fn, self.clients, self.cfg)

    def coverage_report(self) -> dict:
        import inspect
        by_sec = {}; auto = manual = 0
        for cid, fn in EVALUATOR_REGISTRY.items():
            sec = cid.split(".")[0]
            by_sec.setdefault(sec, {"total":0,"automated":0,"manual":0})
            by_sec[sec]["total"] += 1
            if inspect.getsource(fn).strip().startswith("def fn(c, cfg): return [make_manual"):
                by_sec[sec]["manual"] += 1; manual += 1
            else:
                by_sec[sec]["automated"] += 1; auto += 1
        return {"benchmark":"CIS Google Workspace v1.3.0",
                "total_controls":len(EVALUATOR_REGISTRY),"automated":auto,"manual":manual,
                "automation_pct":round(auto/len(EVALUATOR_REGISTRY)*100,1),
                "sections":{s:{"name":self.SECTION_MAP.get(s,""),...c} for s,c in sorted(by_sec.items())}}

    @staticmethod
    def _sort_key(cid): return [int(p) for p in cid.split(".")]
