"""AWS CIS v6.0 Evaluator Registry — maps all 62 control IDs to evaluator functions."""

from __future__ import annotations
import logging
from typing import Optional
from .base import EvaluatorFn

logger = logging.getLogger(__name__)
EVALUATOR_REGISTRY: dict[str, EvaluatorFn] = {}


def _register_section_2():
    from .section_2_iam import (
        evaluate_cis_2_1, evaluate_cis_2_2, evaluate_cis_2_3, evaluate_cis_2_4,
        evaluate_cis_2_5, evaluate_cis_2_6, evaluate_cis_2_7, evaluate_cis_2_8,
        evaluate_cis_2_9, evaluate_cis_2_10, evaluate_cis_2_11, evaluate_cis_2_12,
        evaluate_cis_2_13, evaluate_cis_2_14, evaluate_cis_2_15, evaluate_cis_2_16,
        evaluate_cis_2_17, evaluate_cis_2_18, evaluate_cis_2_19, evaluate_cis_2_20,
        evaluate_cis_2_21,
    )
    EVALUATOR_REGISTRY.update({
        "2.1": evaluate_cis_2_1, "2.2": evaluate_cis_2_2, "2.3": evaluate_cis_2_3,
        "2.4": evaluate_cis_2_4, "2.5": evaluate_cis_2_5, "2.6": evaluate_cis_2_6,
        "2.7": evaluate_cis_2_7, "2.8": evaluate_cis_2_8, "2.9": evaluate_cis_2_9,
        "2.10": evaluate_cis_2_10, "2.11": evaluate_cis_2_11, "2.12": evaluate_cis_2_12,
        "2.13": evaluate_cis_2_13, "2.14": evaluate_cis_2_14, "2.15": evaluate_cis_2_15,
        "2.16": evaluate_cis_2_16, "2.17": evaluate_cis_2_17, "2.18": evaluate_cis_2_18,
        "2.19": evaluate_cis_2_19, "2.20": evaluate_cis_2_20, "2.21": evaluate_cis_2_21,
    })

def _register_section_3():
    from .section_3_storage import (
        evaluate_cis_3_1_1, evaluate_cis_3_1_2, evaluate_cis_3_1_3, evaluate_cis_3_1_4,
        evaluate_cis_3_2_1, evaluate_cis_3_2_2, evaluate_cis_3_2_3, evaluate_cis_3_2_4,
        evaluate_cis_3_3_1,
    )
    EVALUATOR_REGISTRY.update({
        "3.1.1": evaluate_cis_3_1_1, "3.1.2": evaluate_cis_3_1_2,
        "3.1.3": evaluate_cis_3_1_3, "3.1.4": evaluate_cis_3_1_4,
        "3.2.1": evaluate_cis_3_2_1, "3.2.2": evaluate_cis_3_2_2,
        "3.2.3": evaluate_cis_3_2_3, "3.2.4": evaluate_cis_3_2_4,
        "3.3.1": evaluate_cis_3_3_1,
    })

def _register_section_4():
    from .section_4_logging import (
        evaluate_cis_4_1, evaluate_cis_4_2, evaluate_cis_4_3, evaluate_cis_4_4,
        evaluate_cis_4_5, evaluate_cis_4_6, evaluate_cis_4_7, evaluate_cis_4_8,
        evaluate_cis_4_9,
    )
    EVALUATOR_REGISTRY.update({
        "4.1": evaluate_cis_4_1, "4.2": evaluate_cis_4_2, "4.3": evaluate_cis_4_3,
        "4.4": evaluate_cis_4_4, "4.5": evaluate_cis_4_5, "4.6": evaluate_cis_4_6,
        "4.7": evaluate_cis_4_7, "4.8": evaluate_cis_4_8, "4.9": evaluate_cis_4_9,
    })

def _register_section_5():
    from .section_5_monitoring import (
        evaluate_cis_5_1, evaluate_cis_5_2, evaluate_cis_5_3, evaluate_cis_5_4,
        evaluate_cis_5_5, evaluate_cis_5_6, evaluate_cis_5_7, evaluate_cis_5_8,
        evaluate_cis_5_9, evaluate_cis_5_10, evaluate_cis_5_11, evaluate_cis_5_12,
        evaluate_cis_5_13, evaluate_cis_5_14, evaluate_cis_5_15, evaluate_cis_5_16,
    )
    EVALUATOR_REGISTRY.update({
        "5.1": evaluate_cis_5_1, "5.2": evaluate_cis_5_2, "5.3": evaluate_cis_5_3,
        "5.4": evaluate_cis_5_4, "5.5": evaluate_cis_5_5, "5.6": evaluate_cis_5_6,
        "5.7": evaluate_cis_5_7, "5.8": evaluate_cis_5_8, "5.9": evaluate_cis_5_9,
        "5.10": evaluate_cis_5_10, "5.11": evaluate_cis_5_11, "5.12": evaluate_cis_5_12,
        "5.13": evaluate_cis_5_13, "5.14": evaluate_cis_5_14, "5.15": evaluate_cis_5_15,
        "5.16": evaluate_cis_5_16,
    })

def _register_section_6():
    from .section_6_networking import (
        evaluate_cis_6_1_1, evaluate_cis_6_1_2, evaluate_cis_6_2,
        evaluate_cis_6_3, evaluate_cis_6_4, evaluate_cis_6_5, evaluate_cis_6_6,
    )
    EVALUATOR_REGISTRY.update({
        "6.1.1": evaluate_cis_6_1_1, "6.1.2": evaluate_cis_6_1_2,
        "6.2": evaluate_cis_6_2, "6.3": evaluate_cis_6_3,
        "6.4": evaluate_cis_6_4, "6.5": evaluate_cis_6_5, "6.6": evaluate_cis_6_6,
    })

def _load_all():
    _register_section_2()
    _register_section_3()
    _register_section_4()
    _register_section_5()
    _register_section_6()
    logger.info("Loaded %d AWS CIS evaluators", len(EVALUATOR_REGISTRY))

_load_all()

def get_evaluator(cis_id: str) -> Optional[EvaluatorFn]:
    return EVALUATOR_REGISTRY.get(cis_id)

def list_implemented_controls() -> list[str]:
    return sorted(EVALUATOR_REGISTRY.keys())

def coverage_report(total_controls: int = 62) -> dict:
    n = len(EVALUATOR_REGISTRY)
    return {"total": total_controls, "implemented": n,
            "coverage_pct": round(n / total_controls * 100, 1),
            "ids": sorted(EVALUATOR_REGISTRY.keys())}
