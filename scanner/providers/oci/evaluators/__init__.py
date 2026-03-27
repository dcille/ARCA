"""OCI CIS v3.1.0 Evaluator Registry -- maps all 54 control IDs to evaluator functions."""

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
        evaluate_cis_1_17,
    )
    EVALUATOR_REGISTRY.update({
        "1.1": evaluate_cis_1_1, "1.2": evaluate_cis_1_2, "1.3": evaluate_cis_1_3,
        "1.4": evaluate_cis_1_4, "1.5": evaluate_cis_1_5, "1.6": evaluate_cis_1_6,
        "1.7": evaluate_cis_1_7, "1.8": evaluate_cis_1_8, "1.9": evaluate_cis_1_9,
        "1.10": evaluate_cis_1_10, "1.11": evaluate_cis_1_11, "1.12": evaluate_cis_1_12,
        "1.13": evaluate_cis_1_13, "1.14": evaluate_cis_1_14, "1.15": evaluate_cis_1_15,
        "1.16": evaluate_cis_1_16, "1.17": evaluate_cis_1_17,
    })


def _register_section_2_3():
    from .section_2_3_network_compute import (
        evaluate_cis_2_1, evaluate_cis_2_2, evaluate_cis_2_3, evaluate_cis_2_4,
        evaluate_cis_2_5, evaluate_cis_2_6, evaluate_cis_2_7, evaluate_cis_2_8,
        evaluate_cis_3_1, evaluate_cis_3_2, evaluate_cis_3_3,
    )
    EVALUATOR_REGISTRY.update({
        "2.1": evaluate_cis_2_1, "2.2": evaluate_cis_2_2, "2.3": evaluate_cis_2_3,
        "2.4": evaluate_cis_2_4, "2.5": evaluate_cis_2_5, "2.6": evaluate_cis_2_6,
        "2.7": evaluate_cis_2_7, "2.8": evaluate_cis_2_8,
        "3.1": evaluate_cis_3_1, "3.2": evaluate_cis_3_2, "3.3": evaluate_cis_3_3,
    })


def _register_section_4():
    from .section_4_logging import (
        evaluate_cis_4_1, evaluate_cis_4_2, evaluate_cis_4_3, evaluate_cis_4_4,
        evaluate_cis_4_5, evaluate_cis_4_6, evaluate_cis_4_7, evaluate_cis_4_8,
        evaluate_cis_4_9, evaluate_cis_4_10, evaluate_cis_4_11, evaluate_cis_4_12,
        evaluate_cis_4_13, evaluate_cis_4_14, evaluate_cis_4_15, evaluate_cis_4_16,
        evaluate_cis_4_17, evaluate_cis_4_18,
    )
    EVALUATOR_REGISTRY.update({
        "4.1": evaluate_cis_4_1, "4.2": evaluate_cis_4_2, "4.3": evaluate_cis_4_3,
        "4.4": evaluate_cis_4_4, "4.5": evaluate_cis_4_5, "4.6": evaluate_cis_4_6,
        "4.7": evaluate_cis_4_7, "4.8": evaluate_cis_4_8, "4.9": evaluate_cis_4_9,
        "4.10": evaluate_cis_4_10, "4.11": evaluate_cis_4_11, "4.12": evaluate_cis_4_12,
        "4.13": evaluate_cis_4_13, "4.14": evaluate_cis_4_14, "4.15": evaluate_cis_4_15,
        "4.16": evaluate_cis_4_16, "4.17": evaluate_cis_4_17, "4.18": evaluate_cis_4_18,
    })


def _register_section_5_6():
    from .section_5_6_storage_asset import (
        evaluate_cis_5_1_1, evaluate_cis_5_1_2, evaluate_cis_5_1_3,
        evaluate_cis_5_2_1, evaluate_cis_5_2_2,
        evaluate_cis_5_3_1,
        evaluate_cis_6_1, evaluate_cis_6_2,
    )
    EVALUATOR_REGISTRY.update({
        "5.1.1": evaluate_cis_5_1_1, "5.1.2": evaluate_cis_5_1_2, "5.1.3": evaluate_cis_5_1_3,
        "5.2.1": evaluate_cis_5_2_1, "5.2.2": evaluate_cis_5_2_2,
        "5.3.1": evaluate_cis_5_3_1,
        "6.1": evaluate_cis_6_1, "6.2": evaluate_cis_6_2,
    })


def _load_all():
    _register_section_1()
    _register_section_2_3()
    _register_section_4()
    _register_section_5_6()
    logger.info("Loaded %d OCI CIS evaluators", len(EVALUATOR_REGISTRY))

_load_all()


def get_evaluator(cis_id: str) -> Optional[EvaluatorFn]:
    return EVALUATOR_REGISTRY.get(cis_id)


def list_implemented_controls() -> list[str]:
    return sorted(EVALUATOR_REGISTRY.keys())


def coverage_report(total_controls: int = 54) -> dict:
    n = len(EVALUATOR_REGISTRY)
    return {"total": total_controls, "implemented": n,
            "coverage_pct": round(n / total_controls * 100, 1),
            "ids": sorted(EVALUATOR_REGISTRY.keys())}
