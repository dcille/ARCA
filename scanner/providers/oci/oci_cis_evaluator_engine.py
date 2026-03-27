"""OCI CIS Evaluator Engine — orchestrates 54 CIS OCI v3.1 controls.

Usage:
    from scanner.providers.oci.oci_cis_evaluator_engine import OCICISEvaluatorEngine

    engine = OCICISEvaluatorEngine(oci_config, tenancy_id)
    results = engine.evaluate_all()
    report  = engine.coverage_report()
"""
from __future__ import annotations

import logging
from typing import Optional

from .evaluators import EVALUATOR_REGISTRY
from .evaluators.base import (
    OCIClientCache, EvalConfig, safe_evaluate, list_all_compartments,
)

logger = logging.getLogger(__name__)


class OCICISEvaluatorEngine:
    """Run CIS OCI Foundations Benchmark v3.1 evaluations."""

    SECTION_MAP = {
        "1": "Identity and Access Management",
        "2": "Networking",
        "3": "Compute",
        "4": "Logging and Monitoring",
        "5": "Storage",
        "6": "Asset Management",
    }

    def __init__(
        self,
        oci_config: dict,
        tenancy_id: str,
        regions: Optional[list[str]] = None,
    ):
        self.clients = OCIClientCache(oci_config)
        self.cfg = EvalConfig(
            config=oci_config,
            tenancy_id=tenancy_id,
            regions=regions or [oci_config.get("region", "us-ashburn-1")],
        )
        # Populate compartments once
        self.cfg.compartment_ids = list_all_compartments(self.clients, tenancy_id)
        logger.info(
            f"OCICISEvaluatorEngine: {len(self.cfg.compartment_ids)} compartments, "
            f"{len(EVALUATOR_REGISTRY)} controls registered"
        )

    # ── Run modes ──

    def evaluate_all(self) -> list[dict]:
        """Evaluate all 54 CIS controls."""
        results = []
        for cis_id in sorted(EVALUATOR_REGISTRY, key=self._sort_key):
            fn = EVALUATOR_REGISTRY[cis_id]
            results.extend(safe_evaluate(fn, self.clients, self.cfg))
        logger.info(f"evaluate_all: {len(results)} results from {len(EVALUATOR_REGISTRY)} controls")
        return results

    def evaluate_section(self, section: str) -> list[dict]:
        """Evaluate a single section (e.g. '1' for IAM, '4' for Logging)."""
        results = []
        for cis_id, fn in EVALUATOR_REGISTRY.items():
            if cis_id.split(".")[0] == section:
                results.extend(safe_evaluate(fn, self.clients, self.cfg))
        return results

    def evaluate_single(self, cis_id: str) -> list[dict]:
        """Evaluate a single CIS control."""
        fn = EVALUATOR_REGISTRY.get(cis_id)
        if not fn:
            raise KeyError(f"Unknown CIS ID: {cis_id}")
        return safe_evaluate(fn, self.clients, self.cfg)

    # ── Coverage report ──

    def coverage_report(self) -> dict:
        """Return coverage statistics."""
        total = len(EVALUATOR_REGISTRY)
        by_section = {}
        automated = 0
        manual = 0

        for cis_id, fn in EVALUATOR_REGISTRY.items():
            sec = cis_id.split(".")[0]
            by_section.setdefault(sec, {"total": 0, "automated": 0, "manual": 0})
            by_section[sec]["total"] += 1
            # Check if function returns MANUAL results
            if "manual_result" in (fn.__code__.co_names if hasattr(fn, '__code__') else []):
                by_section[sec]["manual"] += 1
                manual += 1
            else:
                by_section[sec]["automated"] += 1
                automated += 1

        return {
            "benchmark": "CIS OCI Foundations v3.1.0",
            "total_controls": total,
            "automated": automated,
            "manual": manual,
            "coverage_pct": 100.0,
            "sections": {
                sec: {
                    "name": self.SECTION_MAP.get(sec, f"Section {sec}"),
                    **counts,
                }
                for sec, counts in sorted(by_section.items())
            },
        }

    @staticmethod
    def _sort_key(cis_id: str) -> list[int]:
        return [int(p) for p in cis_id.split(".")]
