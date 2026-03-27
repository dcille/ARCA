"""M365 CIS Evaluator Engine — 142 controls, ~93% automated.

Multi-API: Graph v1.0/beta + Fabric Admin + Exchange beta + SPO beta + Teams beta.

Usage:
    from scanner.saas.m365.m365_cis_evaluator_engine import M365CISEvaluatorEngine
    engine = M365CISEvaluatorEngine(client_id, client_secret, tenant_id)
    results = engine.evaluate_all()
"""
from __future__ import annotations
import logging
from .evaluators import EVALUATOR_REGISTRY
from .evaluators.base import M365MultiClient, M365Config, safe_eval

logger = logging.getLogger(__name__)

class M365CISEvaluatorEngine:
    SECTION_MAP = {
        "1":"Admin Center","2":"Defender / Email","3":"Audit & DLP","4":"Intune",
        "5":"Entra ID","6":"Exchange Online","7":"SharePoint/OneDrive",
        "8":"Teams","9":"Fabric / Power BI",
    }

    def __init__(self, client_id: str, client_secret: str, tenant_id: str):
        self.cfg = M365Config(client_id, client_secret, tenant_id)
        self.clients = M365MultiClient(self.cfg)

    def evaluate_all(self) -> list[dict]:
        results = []
        for cis_id in sorted(EVALUATOR_REGISTRY, key=self._sort_key):
            results.extend(safe_eval(EVALUATOR_REGISTRY[cis_id], self.clients, self.cfg))
        return results

    def evaluate_section(self, section: str) -> list[dict]:
        return [r for cid, fn in EVALUATOR_REGISTRY.items()
                if cid.split(".")[0] == section
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
        return {
            "benchmark":"CIS Microsoft 365 Foundations v6.0.1",
            "total_controls":len(EVALUATOR_REGISTRY),
            "automated":auto,"manual":manual,
            "automation_pct":round(auto/len(EVALUATOR_REGISTRY)*100,1),
            "sections":{s:{"name":self.SECTION_MAP.get(s,""), **c} for s,c in sorted(by_sec.items())},
        }

    @staticmethod
    def _sort_key(cid): return [int(p) for p in cid.split(".")]
