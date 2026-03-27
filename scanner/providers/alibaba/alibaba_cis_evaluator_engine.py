"""Alibaba Cloud CIS Evaluator Engine — orchestrates 85 CIS Alibaba v2.0 controls.

Usage:
    from scanner.providers.alibaba.alibaba_cis_evaluator_engine import AlibabaCISEvaluatorEngine

    engine = AlibabaCISEvaluatorEngine(access_key_id, access_key_secret)
    results = engine.evaluate_all()
"""
from __future__ import annotations
import logging
from typing import Optional

from .evaluators import EVALUATOR_REGISTRY
from .evaluators.base import AlibabaClientCache, EvalConfig, safe_evaluate

logger = logging.getLogger(__name__)


class AlibabaCISEvaluatorEngine:
    """Run CIS Alibaba Cloud Foundation Benchmark v2.0 evaluations."""

    SECTION_MAP = {
        "1": "Identity and Access Management",
        "2": "Logging and Monitoring",
        "3": "Networking",
        "4": "Virtual Machines",
        "5": "Storage",
        "6": "Relational Database Services",
        "7": "Kubernetes Engine",
        "8": "Security Center",
    }

    def __init__(self, access_key_id: str, access_key_secret: str,
                 regions: Optional[list[str]] = None):
        self.cfg = EvalConfig(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            regions=regions or ["cn-hangzhou"],
        )
        self.clients = AlibabaClientCache(self.cfg)
        logger.info(f"AlibabaCISEvaluatorEngine: {len(EVALUATOR_REGISTRY)} controls registered")

    def evaluate_all(self) -> list[dict]:
        results = []
        for cis_id in sorted(EVALUATOR_REGISTRY, key=self._sort_key):
            results.extend(safe_evaluate(EVALUATOR_REGISTRY[cis_id], self.clients, self.cfg))
        logger.info(f"evaluate_all: {len(results)} results")
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
        total = len(EVALUATOR_REGISTRY)
        by_section = {}
        auto = manual = 0
        for cis_id, fn in EVALUATOR_REGISTRY.items():
            sec = cis_id.split(".")[0]
            by_section.setdefault(sec, {"total": 0, "automated": 0, "manual": 0})
            by_section[sec]["total"] += 1
            src = inspect.getsource(fn)
            if "make_manual_result" in src:
                by_section[sec]["manual"] += 1; manual += 1
            else:
                by_section[sec]["automated"] += 1; auto += 1
        return {
            "benchmark": "CIS Alibaba Cloud Foundation v2.0.0",
            "total_controls": total, "automated": auto, "manual": manual,
            "coverage_pct": 100.0,
            "sections": {s: {"name": self.SECTION_MAP.get(s, f"Section {s}"), **c}
                         for s, c in sorted(by_section.items())},
        }

    @staticmethod
    def _sort_key(cis_id: str) -> list[int]:
        return [int(p) for p in cis_id.split(".")]
