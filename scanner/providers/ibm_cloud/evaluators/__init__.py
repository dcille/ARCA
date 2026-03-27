"""IBM Cloud CIS v2.0.0 Evaluator Registry — maps all 73 control IDs to evaluator functions."""

from __future__ import annotations
import logging
from typing import Optional
from .base import EvaluatorFn

logger = logging.getLogger(__name__)
EVALUATOR_REGISTRY: dict[str, EvaluatorFn] = {}


def _register_section_1():
    from .section_1_iam import (
        evaluate_cis_1_1, evaluate_cis_1_2, evaluate_cis_1_3, evaluate_cis_1_4,
        evaluate_cis_1_5, evaluate_cis_1_6, evaluate_cis_1_7, evaluate_cis_1_8,
        evaluate_cis_1_9, evaluate_cis_1_10, evaluate_cis_1_11, evaluate_cis_1_12,
        evaluate_cis_1_13, evaluate_cis_1_14, evaluate_cis_1_15, evaluate_cis_1_16,
        evaluate_cis_1_17, evaluate_cis_1_18, evaluate_cis_1_19, evaluate_cis_1_20,
    )
    EVALUATOR_REGISTRY.update({
        "1.1": evaluate_cis_1_1, "1.2": evaluate_cis_1_2, "1.3": evaluate_cis_1_3,
        "1.4": evaluate_cis_1_4, "1.5": evaluate_cis_1_5, "1.6": evaluate_cis_1_6,
        "1.7": evaluate_cis_1_7, "1.8": evaluate_cis_1_8, "1.9": evaluate_cis_1_9,
        "1.10": evaluate_cis_1_10, "1.11": evaluate_cis_1_11, "1.12": evaluate_cis_1_12,
        "1.13": evaluate_cis_1_13, "1.14": evaluate_cis_1_14, "1.15": evaluate_cis_1_15,
        "1.16": evaluate_cis_1_16, "1.17": evaluate_cis_1_17, "1.18": evaluate_cis_1_18,
        "1.19": evaluate_cis_1_19, "1.20": evaluate_cis_1_20,
    })


def _register_section_2_6():
    from .section_2_6_storage_log_net import (
        evaluate_cis_2_1_1_1, evaluate_cis_2_1_1_2, evaluate_cis_2_1_1_3,
        evaluate_cis_2_1_2, evaluate_cis_2_1_3, evaluate_cis_2_1_4, evaluate_cis_2_1_5,
        evaluate_cis_2_2_1_1, evaluate_cis_2_2_1_2,
        evaluate_cis_2_2_2_1, evaluate_cis_2_2_2_2, evaluate_cis_2_2_2_3,
        evaluate_cis_2_2_3, evaluate_cis_2_2_4, evaluate_cis_2_2_5,
        evaluate_cis_3_1, evaluate_cis_3_2, evaluate_cis_3_3,
        evaluate_cis_3_4, evaluate_cis_3_5, evaluate_cis_3_6,
        evaluate_cis_4_1, evaluate_cis_4_2, evaluate_cis_4_3,
        evaluate_cis_5_1,
        evaluate_cis_6_1_1, evaluate_cis_6_1_2, evaluate_cis_6_1_3,
        evaluate_cis_6_2_1, evaluate_cis_6_2_2, evaluate_cis_6_2_3,
        evaluate_cis_6_2_4, evaluate_cis_6_2_5,
    )
    EVALUATOR_REGISTRY.update({
        # Section 2 — Storage (15)
        "2.1.1.1": evaluate_cis_2_1_1_1, "2.1.1.2": evaluate_cis_2_1_1_2,
        "2.1.1.3": evaluate_cis_2_1_1_3, "2.1.2": evaluate_cis_2_1_2,
        "2.1.3": evaluate_cis_2_1_3, "2.1.4": evaluate_cis_2_1_4,
        "2.1.5": evaluate_cis_2_1_5,
        "2.2.1.1": evaluate_cis_2_2_1_1, "2.2.1.2": evaluate_cis_2_2_1_2,
        "2.2.2.1": evaluate_cis_2_2_2_1, "2.2.2.2": evaluate_cis_2_2_2_2,
        "2.2.2.3": evaluate_cis_2_2_2_3,
        "2.2.3": evaluate_cis_2_2_3, "2.2.4": evaluate_cis_2_2_4,
        "2.2.5": evaluate_cis_2_2_5,
        # Section 3 — Logging (6)
        "3.1": evaluate_cis_3_1, "3.2": evaluate_cis_3_2, "3.3": evaluate_cis_3_3,
        "3.4": evaluate_cis_3_4, "3.5": evaluate_cis_3_5, "3.6": evaluate_cis_3_6,
        # Section 4 — Databases (3)
        "4.1": evaluate_cis_4_1, "4.2": evaluate_cis_4_2, "4.3": evaluate_cis_4_3,
        # Section 5 — Cloudant (1)
        "5.1": evaluate_cis_5_1,
        # Section 6 — Networking (8)
        "6.1.1": evaluate_cis_6_1_1, "6.1.2": evaluate_cis_6_1_2,
        "6.1.3": evaluate_cis_6_1_3, "6.2.1": evaluate_cis_6_2_1,
        "6.2.2": evaluate_cis_6_2_2, "6.2.3": evaluate_cis_6_2_3,
        "6.2.4": evaluate_cis_6_2_4, "6.2.5": evaluate_cis_6_2_5,
    })


def _register_section_7_9():
    from .section_7_9_k8s_sec_pvs import (
        evaluate_cis_7_1_1, evaluate_cis_7_1_2, evaluate_cis_7_1_3,
        evaluate_cis_7_1_4, evaluate_cis_7_1_5, evaluate_cis_7_1_6,
        evaluate_cis_8_1_1_1, evaluate_cis_8_1_1_2, evaluate_cis_8_1_1_3,
        evaluate_cis_8_2_1, evaluate_cis_8_2_2, evaluate_cis_8_2_3, evaluate_cis_8_2_4,
        evaluate_cis_9_1, evaluate_cis_9_2, evaluate_cis_9_3,
        evaluate_cis_9_4, evaluate_cis_9_5, evaluate_cis_9_6, evaluate_cis_9_7,
    )
    EVALUATOR_REGISTRY.update({
        # Section 7 — Containers (6)
        "7.1.1": evaluate_cis_7_1_1, "7.1.2": evaluate_cis_7_1_2,
        "7.1.3": evaluate_cis_7_1_3, "7.1.4": evaluate_cis_7_1_4,
        "7.1.5": evaluate_cis_7_1_5, "7.1.6": evaluate_cis_7_1_6,
        # Section 8 — Security & Compliance (7)
        "8.1.1.1": evaluate_cis_8_1_1_1, "8.1.1.2": evaluate_cis_8_1_1_2,
        "8.1.1.3": evaluate_cis_8_1_1_3, "8.2.1": evaluate_cis_8_2_1,
        "8.2.2": evaluate_cis_8_2_2, "8.2.3": evaluate_cis_8_2_3,
        "8.2.4": evaluate_cis_8_2_4,
        # Section 9 — PowerVS (7)
        "9.1": evaluate_cis_9_1, "9.2": evaluate_cis_9_2, "9.3": evaluate_cis_9_3,
        "9.4": evaluate_cis_9_4, "9.5": evaluate_cis_9_5, "9.6": evaluate_cis_9_6,
        "9.7": evaluate_cis_9_7,
    })


def _load_all():
    _register_section_1()
    _register_section_2_6()
    _register_section_7_9()
    logger.info("Loaded %d IBM Cloud CIS evaluators", len(EVALUATOR_REGISTRY))


_load_all()


def get_evaluator(cis_id: str) -> Optional[EvaluatorFn]:
    return EVALUATOR_REGISTRY.get(cis_id)


def list_implemented_controls() -> list[str]:
    return sorted(EVALUATOR_REGISTRY.keys())


def coverage_report(total_controls: int = 73) -> dict:
    n = len(EVALUATOR_REGISTRY)
    return {
        "total": total_controls, "implemented": n,
        "coverage_pct": round(n / total_controls * 100, 1),
        "ids": sorted(EVALUATOR_REGISTRY.keys()),
    }
