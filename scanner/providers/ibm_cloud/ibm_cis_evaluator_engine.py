"""IBM Cloud CIS Evaluator Engine — orchestrates 73 CIS IBM Cloud v2.0 controls.

Usage:
    from scanner.providers.ibm_cloud.ibm_cis_evaluator_engine import IBMCloudCISEvaluatorEngine
    engine = IBMCloudCISEvaluatorEngine(api_key, account_id)
    results = engine.evaluate_all()
"""
from __future__ import annotations
import logging
from typing import Optional
from .evaluators import EVALUATOR_REGISTRY
from .evaluators.base import IBMCloudClientCache, EvalConfig, safe_evaluate

logger = logging.getLogger(__name__)

class IBMCloudCISEvaluatorEngine:
    SECTION_MAP = {
        "1": "Identity and Access Management",
        "2": "Storage",
        "3": "Logging and Monitoring",
        "4": "IBM Cloud Databases",
        "5": "Cloudant",
        "6": "Networking",
        "7": "Containers (IKS)",
        "8": "Security and Compliance",
        "9": "PowerVS",
    }

    def __init__(self, api_key: str, account_id: str = "",
                 regions: Optional[list[str]] = None):
        self.cfg = EvalConfig(api_key=api_key, account_id=account_id,
                              regions=regions or ["us-south"])
        self.clients = IBMCloudClientCache(self.cfg)

    def evaluate_all(self) -> list[dict]:
        results = []
        for cis_id in sorted(EVALUATOR_REGISTRY, key=self._sort_key):
            results.extend(safe_evaluate(EVALUATOR_REGISTRY[cis_id], self.clients, self.cfg))
        return results

    def evaluate_section(self, section: str) -> list[dict]:
        results = []
        for cis_id, fn in EVALUATOR_REGISTRY.items():
            if cis_id.split(".")[0] == section:
                results.extend(safe_evaluate(fn, self.clients, self.cfg))
        return results

    def evaluate_single(self, cis_id: str) -> list[dict]:
        fn = EVALUATOR_REGISTRY.get(cis_id)
        if not fn: raise KeyError(f"Unknown CIS ID: {cis_id}")
        return safe_evaluate(fn, self.clients, self.cfg)

    def coverage_report(self) -> dict:
        import inspect
        by_section = {}
        auto = manual = 0
        for cis_id, fn in EVALUATOR_REGISTRY.items():
            sec = cis_id.split(".")[0]
            by_section.setdefault(sec, {"total": 0, "automated": 0, "manual": 0})
            by_section[sec]["total"] += 1
            if "make_manual_result" in inspect.getsource(fn):
                by_section[sec]["manual"] += 1; manual += 1
            else:
                by_section[sec]["automated"] += 1; auto += 1
        return {
            "benchmark": "CIS IBM Cloud Foundations v2.0.0",
            "total_controls": len(EVALUATOR_REGISTRY),
            "automated": auto, "manual": manual, "coverage_pct": 100.0,
            "sections": {s: {"name": self.SECTION_MAP.get(s, f"Section {s}"), **c}
                         for s, c in sorted(by_section.items())},
        }

    @staticmethod
    def _sort_key(cis_id: str) -> list[int]:
        return [int(p) for p in cis_id.split(".")]
