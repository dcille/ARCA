"""Alibaba Cloud CIS v2.0 Evaluator Registry — maps all 85 control IDs to evaluator functions."""

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
    )
    EVALUATOR_REGISTRY.update({
        "1.1": evaluate_cis_1_1, "1.2": evaluate_cis_1_2, "1.3": evaluate_cis_1_3,
        "1.4": evaluate_cis_1_4, "1.5": evaluate_cis_1_5, "1.6": evaluate_cis_1_6,
        "1.7": evaluate_cis_1_7, "1.8": evaluate_cis_1_8, "1.9": evaluate_cis_1_9,
        "1.10": evaluate_cis_1_10, "1.11": evaluate_cis_1_11, "1.12": evaluate_cis_1_12,
        "1.13": evaluate_cis_1_13, "1.14": evaluate_cis_1_14, "1.15": evaluate_cis_1_15,
        "1.16": evaluate_cis_1_16,
    })


def _register_section_2_4():
    from .section_2_4_logging_net_vm import (
        evaluate_cis_2_1, evaluate_cis_2_2, evaluate_cis_2_3, evaluate_cis_2_4,
        evaluate_cis_2_5, evaluate_cis_2_6, evaluate_cis_2_7, evaluate_cis_2_8,
        evaluate_cis_2_9, evaluate_cis_2_10, evaluate_cis_2_11, evaluate_cis_2_12,
        evaluate_cis_2_13, evaluate_cis_2_14, evaluate_cis_2_15, evaluate_cis_2_16,
        evaluate_cis_2_17, evaluate_cis_2_18, evaluate_cis_2_19, evaluate_cis_2_20,
        evaluate_cis_2_21, evaluate_cis_2_22, evaluate_cis_2_23,
        evaluate_cis_3_1, evaluate_cis_3_2, evaluate_cis_3_3, evaluate_cis_3_4,
        evaluate_cis_3_5,
        evaluate_cis_4_1, evaluate_cis_4_2, evaluate_cis_4_3, evaluate_cis_4_4,
        evaluate_cis_4_5, evaluate_cis_4_6,
    )
    EVALUATOR_REGISTRY.update({
        "2.1": evaluate_cis_2_1, "2.2": evaluate_cis_2_2, "2.3": evaluate_cis_2_3,
        "2.4": evaluate_cis_2_4, "2.5": evaluate_cis_2_5, "2.6": evaluate_cis_2_6,
        "2.7": evaluate_cis_2_7, "2.8": evaluate_cis_2_8, "2.9": evaluate_cis_2_9,
        "2.10": evaluate_cis_2_10, "2.11": evaluate_cis_2_11, "2.12": evaluate_cis_2_12,
        "2.13": evaluate_cis_2_13, "2.14": evaluate_cis_2_14, "2.15": evaluate_cis_2_15,
        "2.16": evaluate_cis_2_16, "2.17": evaluate_cis_2_17, "2.18": evaluate_cis_2_18,
        "2.19": evaluate_cis_2_19, "2.20": evaluate_cis_2_20, "2.21": evaluate_cis_2_21,
        "2.22": evaluate_cis_2_22, "2.23": evaluate_cis_2_23,
        "3.1": evaluate_cis_3_1, "3.2": evaluate_cis_3_2, "3.3": evaluate_cis_3_3,
        "3.4": evaluate_cis_3_4, "3.5": evaluate_cis_3_5,
        "4.1": evaluate_cis_4_1, "4.2": evaluate_cis_4_2, "4.3": evaluate_cis_4_3,
        "4.4": evaluate_cis_4_4, "4.5": evaluate_cis_4_5, "4.6": evaluate_cis_4_6,
    })


def _register_section_5_6():
    from .section_5_6_storage_rds import (
        evaluate_cis_5_1, evaluate_cis_5_2, evaluate_cis_5_3, evaluate_cis_5_4,
        evaluate_cis_5_5, evaluate_cis_5_6, evaluate_cis_5_7, evaluate_cis_5_8,
        evaluate_cis_5_9,
        evaluate_cis_6_1, evaluate_cis_6_2, evaluate_cis_6_3, evaluate_cis_6_4,
        evaluate_cis_6_5, evaluate_cis_6_6, evaluate_cis_6_7, evaluate_cis_6_8,
        evaluate_cis_6_9,
    )
    EVALUATOR_REGISTRY.update({
        "5.1": evaluate_cis_5_1, "5.2": evaluate_cis_5_2, "5.3": evaluate_cis_5_3,
        "5.4": evaluate_cis_5_4, "5.5": evaluate_cis_5_5, "5.6": evaluate_cis_5_6,
        "5.7": evaluate_cis_5_7, "5.8": evaluate_cis_5_8, "5.9": evaluate_cis_5_9,
        "6.1": evaluate_cis_6_1, "6.2": evaluate_cis_6_2, "6.3": evaluate_cis_6_3,
        "6.4": evaluate_cis_6_4, "6.5": evaluate_cis_6_5, "6.6": evaluate_cis_6_6,
        "6.7": evaluate_cis_6_7, "6.8": evaluate_cis_6_8, "6.9": evaluate_cis_6_9,
    })


def _register_section_7_8():
    from .section_7_8_k8s_security import (
        evaluate_cis_7_1, evaluate_cis_7_2, evaluate_cis_7_3, evaluate_cis_7_4,
        evaluate_cis_7_5, evaluate_cis_7_6, evaluate_cis_7_7, evaluate_cis_7_8,
        evaluate_cis_7_9,
        evaluate_cis_8_1, evaluate_cis_8_2, evaluate_cis_8_3, evaluate_cis_8_4,
        evaluate_cis_8_5, evaluate_cis_8_6, evaluate_cis_8_7, evaluate_cis_8_8,
    )
    EVALUATOR_REGISTRY.update({
        "7.1": evaluate_cis_7_1, "7.2": evaluate_cis_7_2, "7.3": evaluate_cis_7_3,
        "7.4": evaluate_cis_7_4, "7.5": evaluate_cis_7_5, "7.6": evaluate_cis_7_6,
        "7.7": evaluate_cis_7_7, "7.8": evaluate_cis_7_8, "7.9": evaluate_cis_7_9,
        "8.1": evaluate_cis_8_1, "8.2": evaluate_cis_8_2, "8.3": evaluate_cis_8_3,
        "8.4": evaluate_cis_8_4, "8.5": evaluate_cis_8_5, "8.6": evaluate_cis_8_6,
        "8.7": evaluate_cis_8_7, "8.8": evaluate_cis_8_8,
    })


def _load_all():
    _register_section_1()
    _register_section_2_4()
    _register_section_5_6()
    _register_section_7_8()
    logger.info("Loaded %d Alibaba Cloud CIS evaluators", len(EVALUATOR_REGISTRY))


_load_all()


def get_evaluator(cis_id: str) -> Optional[EvaluatorFn]:
    return EVALUATOR_REGISTRY.get(cis_id)


def list_implemented_controls() -> list[str]:
    return sorted(EVALUATOR_REGISTRY.keys())


def coverage_report(total_controls: int = 85) -> dict:
    n = len(EVALUATOR_REGISTRY)
    return {
        "total": total_controls,
        "implemented": n,
        "coverage_pct": round(n / total_controls * 100, 1),
        "ids": sorted(EVALUATOR_REGISTRY.keys()),
    }
