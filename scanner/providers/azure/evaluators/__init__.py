"""Evaluator registry — maps every CIS control ID to its evaluator function.

This is the SINGLE source of truth for what gets evaluated and how.
Controls without an evaluator are automatically marked as MANUAL.

Usage:
    from evaluators import EVALUATOR_REGISTRY, get_evaluator

    fn = get_evaluator("7.1")  # Returns the evaluator function or None
"""

from __future__ import annotations

import logging
from typing import Optional

from .base import EvaluatorFn

logger = logging.getLogger(__name__)

# ═════════════════════════════════════════════════════════════════
# EVALUATOR REGISTRY
# ═════════════════════════════════════════════════════════════════

EVALUATOR_REGISTRY: dict[str, EvaluatorFn] = {}


def _register_section_2():
    """Section 2: Analytics (Databricks) — 11 controls."""
    from .section_2_analytics import (
        evaluate_cis_2_1_1, evaluate_cis_2_1_2, evaluate_cis_2_1_3,
        evaluate_cis_2_1_4, evaluate_cis_2_1_5, evaluate_cis_2_1_6,
        evaluate_cis_2_1_7, evaluate_cis_2_1_8, evaluate_cis_2_1_9,
        evaluate_cis_2_1_10, evaluate_cis_2_1_11,
    )
    EVALUATOR_REGISTRY.update({
        "2.1.1":  evaluate_cis_2_1_1,
        "2.1.2":  evaluate_cis_2_1_2,
        "2.1.3":  evaluate_cis_2_1_3,
        "2.1.4":  evaluate_cis_2_1_4,
        "2.1.5":  evaluate_cis_2_1_5,
        "2.1.6":  evaluate_cis_2_1_6,
        "2.1.7":  evaluate_cis_2_1_7,
        "2.1.8":  evaluate_cis_2_1_8,
        "2.1.9":  evaluate_cis_2_1_9,
        "2.1.10": evaluate_cis_2_1_10,
        "2.1.11": evaluate_cis_2_1_11,
    })


def _register_section_3():
    """Section 3: Compute (VMs) — 1 control."""
    from .section_3_compute import evaluate_cis_3_1_1
    EVALUATOR_REGISTRY.update({
        "3.1.1": evaluate_cis_3_1_1,
    })


def _register_section_5():
    """Section 5: Identity (Entra ID) — 43 controls."""
    from .section_5_identity import (
        evaluate_cis_5_1_1, evaluate_cis_5_1_2, evaluate_cis_5_1_3,
        evaluate_cis_5_2_1, evaluate_cis_5_2_2, evaluate_cis_5_2_3,
        evaluate_cis_5_2_4, evaluate_cis_5_2_5, evaluate_cis_5_2_6,
        evaluate_cis_5_2_7, evaluate_cis_5_2_8,
        evaluate_cis_5_3_1, evaluate_cis_5_3_2, evaluate_cis_5_3_3,
        evaluate_cis_5_3_4, evaluate_cis_5_3_5, evaluate_cis_5_3_6,
        evaluate_cis_5_3_7,
        evaluate_cis_5_4, evaluate_cis_5_5, evaluate_cis_5_6,
        evaluate_cis_5_7, evaluate_cis_5_8, evaluate_cis_5_9,
        evaluate_cis_5_10, evaluate_cis_5_11, evaluate_cis_5_12,
        evaluate_cis_5_13, evaluate_cis_5_14, evaluate_cis_5_15,
        evaluate_cis_5_16, evaluate_cis_5_17, evaluate_cis_5_18,
        evaluate_cis_5_19, evaluate_cis_5_20, evaluate_cis_5_21,
        evaluate_cis_5_22, evaluate_cis_5_23, evaluate_cis_5_24,
        evaluate_cis_5_25, evaluate_cis_5_26, evaluate_cis_5_27,
        evaluate_cis_5_28,
    )
    EVALUATOR_REGISTRY.update({
        "5.1.1":  evaluate_cis_5_1_1,
        "5.1.2":  evaluate_cis_5_1_2,
        "5.1.3":  evaluate_cis_5_1_3,
        "5.2.1":  evaluate_cis_5_2_1,
        "5.2.2":  evaluate_cis_5_2_2,
        "5.2.3":  evaluate_cis_5_2_3,
        "5.2.4":  evaluate_cis_5_2_4,
        "5.2.5":  evaluate_cis_5_2_5,
        "5.2.6":  evaluate_cis_5_2_6,
        "5.2.7":  evaluate_cis_5_2_7,
        "5.2.8":  evaluate_cis_5_2_8,
        "5.3.1":  evaluate_cis_5_3_1,
        "5.3.2":  evaluate_cis_5_3_2,
        "5.3.3":  evaluate_cis_5_3_3,
        "5.3.4":  evaluate_cis_5_3_4,
        "5.3.5":  evaluate_cis_5_3_5,
        "5.3.6":  evaluate_cis_5_3_6,
        "5.3.7":  evaluate_cis_5_3_7,
        "5.4":    evaluate_cis_5_4,
        "5.5":    evaluate_cis_5_5,
        "5.6":    evaluate_cis_5_6,
        "5.7":    evaluate_cis_5_7,
        "5.8":    evaluate_cis_5_8,
        "5.9":    evaluate_cis_5_9,
        "5.10":   evaluate_cis_5_10,
        "5.11":   evaluate_cis_5_11,
        "5.12":   evaluate_cis_5_12,
        "5.13":   evaluate_cis_5_13,
        "5.14":   evaluate_cis_5_14,
        "5.15":   evaluate_cis_5_15,
        "5.16":   evaluate_cis_5_16,
        "5.17":   evaluate_cis_5_17,
        "5.18":   evaluate_cis_5_18,
        "5.19":   evaluate_cis_5_19,
        "5.20":   evaluate_cis_5_20,
        "5.21":   evaluate_cis_5_21,
        "5.22":   evaluate_cis_5_22,
        "5.23":   evaluate_cis_5_23,
        "5.24":   evaluate_cis_5_24,
        "5.25":   evaluate_cis_5_25,
        "5.26":   evaluate_cis_5_26,
        "5.27":   evaluate_cis_5_27,
        "5.28":   evaluate_cis_5_28,
    })


def _register_section_6():
    """Section 6: Logging & Monitoring — 25 controls."""
    from .section_6_logging import (
        evaluate_cis_6_1_1_1, evaluate_cis_6_1_1_2, evaluate_cis_6_1_1_3,
        evaluate_cis_6_1_1_4, evaluate_cis_6_1_1_5, evaluate_cis_6_1_1_6,
        evaluate_cis_6_1_1_7, evaluate_cis_6_1_1_8, evaluate_cis_6_1_1_9,
        evaluate_cis_6_1_1_10,
        evaluate_cis_6_1_2_1, evaluate_cis_6_1_2_2, evaluate_cis_6_1_2_3,
        evaluate_cis_6_1_2_4, evaluate_cis_6_1_2_5, evaluate_cis_6_1_2_6,
        evaluate_cis_6_1_2_7, evaluate_cis_6_1_2_8, evaluate_cis_6_1_2_9,
        evaluate_cis_6_1_2_10, evaluate_cis_6_1_2_11,
        evaluate_cis_6_1_3_1,
        evaluate_cis_6_1_4, evaluate_cis_6_1_5, evaluate_cis_6_2,
    )
    EVALUATOR_REGISTRY.update({
        "6.1.1.1":  evaluate_cis_6_1_1_1,
        "6.1.1.2":  evaluate_cis_6_1_1_2,
        "6.1.1.3":  evaluate_cis_6_1_1_3,
        "6.1.1.4":  evaluate_cis_6_1_1_4,
        "6.1.1.5":  evaluate_cis_6_1_1_5,
        "6.1.1.6":  evaluate_cis_6_1_1_6,
        "6.1.1.7":  evaluate_cis_6_1_1_7,
        "6.1.1.8":  evaluate_cis_6_1_1_8,
        "6.1.1.9":  evaluate_cis_6_1_1_9,
        "6.1.1.10": evaluate_cis_6_1_1_10,
        "6.1.2.1":  evaluate_cis_6_1_2_1,
        "6.1.2.2":  evaluate_cis_6_1_2_2,
        "6.1.2.3":  evaluate_cis_6_1_2_3,
        "6.1.2.4":  evaluate_cis_6_1_2_4,
        "6.1.2.5":  evaluate_cis_6_1_2_5,
        "6.1.2.6":  evaluate_cis_6_1_2_6,
        "6.1.2.7":  evaluate_cis_6_1_2_7,
        "6.1.2.8":  evaluate_cis_6_1_2_8,
        "6.1.2.9":  evaluate_cis_6_1_2_9,
        "6.1.2.10": evaluate_cis_6_1_2_10,
        "6.1.2.11": evaluate_cis_6_1_2_11,
        "6.1.3.1":  evaluate_cis_6_1_3_1,
        "6.1.4":    evaluate_cis_6_1_4,
        "6.1.5":    evaluate_cis_6_1_5,
        "6.2":      evaluate_cis_6_2,
    })


def _register_section_7():
    """Section 7: Networking — 16 controls."""
    from .section_7_networking import (
        evaluate_cis_7_1, evaluate_cis_7_2, evaluate_cis_7_3,
        evaluate_cis_7_4, evaluate_cis_7_5, evaluate_cis_7_6,
        evaluate_cis_7_7, evaluate_cis_7_8, evaluate_cis_7_9,
        evaluate_cis_7_10, evaluate_cis_7_11, evaluate_cis_7_12,
        evaluate_cis_7_13, evaluate_cis_7_14, evaluate_cis_7_15,
        evaluate_cis_7_16,
    )
    EVALUATOR_REGISTRY.update({
        "7.1":  evaluate_cis_7_1,
        "7.2":  evaluate_cis_7_2,
        "7.3":  evaluate_cis_7_3,
        "7.4":  evaluate_cis_7_4,
        "7.5":  evaluate_cis_7_5,
        "7.6":  evaluate_cis_7_6,
        "7.7":  evaluate_cis_7_7,
        "7.8":  evaluate_cis_7_8,
        "7.9":  evaluate_cis_7_9,
        "7.10": evaluate_cis_7_10,
        "7.11": evaluate_cis_7_11,
        "7.12": evaluate_cis_7_12,
        "7.13": evaluate_cis_7_13,
        "7.14": evaluate_cis_7_14,
        "7.15": evaluate_cis_7_15,
        "7.16": evaluate_cis_7_16,
    })


def _register_section_8():
    """Section 8: Security (Defender + Key Vault + Bastion + DDoS) — 38 controls."""
    from .section_8_security import (
        evaluate_cis_8_1_1_1, evaluate_cis_8_1_2_1,
        evaluate_cis_8_1_3_1, evaluate_cis_8_1_3_2, evaluate_cis_8_1_3_3,
        evaluate_cis_8_1_3_4, evaluate_cis_8_1_3_5,
        evaluate_cis_8_1_4_1, evaluate_cis_8_1_5_1, evaluate_cis_8_1_5_2,
        evaluate_cis_8_1_6_1,
        evaluate_cis_8_1_7_1, evaluate_cis_8_1_7_2, evaluate_cis_8_1_7_3,
        evaluate_cis_8_1_7_4,
        evaluate_cis_8_1_8_1, evaluate_cis_8_1_9_1,
        evaluate_cis_8_1_10, evaluate_cis_8_1_11,
        evaluate_cis_8_1_12, evaluate_cis_8_1_13, evaluate_cis_8_1_14,
        evaluate_cis_8_1_15, evaluate_cis_8_1_16,
        evaluate_cis_8_2_1,
        evaluate_cis_8_3_1, evaluate_cis_8_3_2, evaluate_cis_8_3_3,
        evaluate_cis_8_3_4, evaluate_cis_8_3_5, evaluate_cis_8_3_6,
        evaluate_cis_8_3_7, evaluate_cis_8_3_8, evaluate_cis_8_3_9,
        evaluate_cis_8_3_10, evaluate_cis_8_3_11,
        evaluate_cis_8_4_1, evaluate_cis_8_5,
    )
    EVALUATOR_REGISTRY.update({
        "8.1.1.1":  evaluate_cis_8_1_1_1,
        "8.1.2.1":  evaluate_cis_8_1_2_1,
        "8.1.3.1":  evaluate_cis_8_1_3_1,
        "8.1.3.2":  evaluate_cis_8_1_3_2,
        "8.1.3.3":  evaluate_cis_8_1_3_3,
        "8.1.3.4":  evaluate_cis_8_1_3_4,
        "8.1.3.5":  evaluate_cis_8_1_3_5,
        "8.1.4.1":  evaluate_cis_8_1_4_1,
        "8.1.5.1":  evaluate_cis_8_1_5_1,
        "8.1.5.2":  evaluate_cis_8_1_5_2,
        "8.1.6.1":  evaluate_cis_8_1_6_1,
        "8.1.7.1":  evaluate_cis_8_1_7_1,
        "8.1.7.2":  evaluate_cis_8_1_7_2,
        "8.1.7.3":  evaluate_cis_8_1_7_3,
        "8.1.7.4":  evaluate_cis_8_1_7_4,
        "8.1.8.1":  evaluate_cis_8_1_8_1,
        "8.1.9.1":  evaluate_cis_8_1_9_1,
        "8.1.10":   evaluate_cis_8_1_10,
        "8.1.11":   evaluate_cis_8_1_11,
        "8.1.12":   evaluate_cis_8_1_12,
        "8.1.13":   evaluate_cis_8_1_13,
        "8.1.14":   evaluate_cis_8_1_14,
        "8.1.15":   evaluate_cis_8_1_15,
        "8.1.16":   evaluate_cis_8_1_16,
        "8.2.1":    evaluate_cis_8_2_1,
        "8.3.1":    evaluate_cis_8_3_1,
        "8.3.2":    evaluate_cis_8_3_2,
        "8.3.3":    evaluate_cis_8_3_3,
        "8.3.4":    evaluate_cis_8_3_4,
        "8.3.5":    evaluate_cis_8_3_5,
        "8.3.6":    evaluate_cis_8_3_6,
        "8.3.7":    evaluate_cis_8_3_7,
        "8.3.8":    evaluate_cis_8_3_8,
        "8.3.9":    evaluate_cis_8_3_9,
        "8.3.10":   evaluate_cis_8_3_10,
        "8.3.11":   evaluate_cis_8_3_11,
        "8.4.1":    evaluate_cis_8_4_1,
        "8.5":      evaluate_cis_8_5,
    })


def _register_section_9():
    """Section 9: Storage — 21 controls."""
    from .section_9_storage import (
        evaluate_cis_9_1_1, evaluate_cis_9_1_2, evaluate_cis_9_1_3,
        evaluate_cis_9_2_1, evaluate_cis_9_2_2, evaluate_cis_9_2_3,
        evaluate_cis_9_3_1_1, evaluate_cis_9_3_1_2, evaluate_cis_9_3_1_3,
        evaluate_cis_9_3_2_1, evaluate_cis_9_3_2_2, evaluate_cis_9_3_2_3,
        evaluate_cis_9_3_3_1,
        evaluate_cis_9_3_4, evaluate_cis_9_3_5, evaluate_cis_9_3_6,
        evaluate_cis_9_3_7, evaluate_cis_9_3_8,
        evaluate_cis_9_3_9, evaluate_cis_9_3_10, evaluate_cis_9_3_11,
    )
    EVALUATOR_REGISTRY.update({
        "9.1.1":   evaluate_cis_9_1_1,
        "9.1.2":   evaluate_cis_9_1_2,
        "9.1.3":   evaluate_cis_9_1_3,
        "9.2.1":   evaluate_cis_9_2_1,
        "9.2.2":   evaluate_cis_9_2_2,
        "9.2.3":   evaluate_cis_9_2_3,
        "9.3.1.1": evaluate_cis_9_3_1_1,
        "9.3.1.2": evaluate_cis_9_3_1_2,
        "9.3.1.3": evaluate_cis_9_3_1_3,
        "9.3.2.1": evaluate_cis_9_3_2_1,
        "9.3.2.2": evaluate_cis_9_3_2_2,
        "9.3.2.3": evaluate_cis_9_3_2_3,
        "9.3.3.1": evaluate_cis_9_3_3_1,
        "9.3.4":   evaluate_cis_9_3_4,
        "9.3.5":   evaluate_cis_9_3_5,
        "9.3.6":   evaluate_cis_9_3_6,
        "9.3.7":   evaluate_cis_9_3_7,
        "9.3.8":   evaluate_cis_9_3_8,
        "9.3.9":   evaluate_cis_9_3_9,
        "9.3.10":  evaluate_cis_9_3_10,
        "9.3.11":  evaluate_cis_9_3_11,
    })


# ─────────────────────────────────────────────────────────────────
# Initialize all sections
# ─────────────────────────────────────────────────────────────────

def _load_all_evaluators():
    """Load all evaluator sections. Called once at module import."""
    _register_section_2()
    _register_section_3()
    _register_section_5()
    _register_section_6()
    _register_section_7()
    _register_section_8()
    _register_section_9()
    logger.info("Loaded %d CIS evaluators", len(EVALUATOR_REGISTRY))


# Auto-load on import
_load_all_evaluators()


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

def get_evaluator(cis_id: str) -> Optional[EvaluatorFn]:
    """Get the evaluator function for a CIS control, or None if not implemented."""
    return EVALUATOR_REGISTRY.get(cis_id)


def list_implemented_controls() -> list[str]:
    """Return all CIS IDs that have evaluators."""
    return sorted(EVALUATOR_REGISTRY.keys())


def coverage_report(total_controls: int = 155) -> dict:
    """Return a coverage summary."""
    implemented = len(EVALUATOR_REGISTRY)
    return {
        "total_cis_controls": total_controls,
        "implemented_evaluators": implemented,
        "coverage_pct": round(implemented / total_controls * 100, 1),
        "implemented_ids": sorted(EVALUATOR_REGISTRY.keys()),
    }
