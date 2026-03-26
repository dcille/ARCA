"""GCP CIS v4.0 Evaluator Registry — maps all 84 control IDs to evaluator functions."""

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


def _register_section_2():
    from .section_2_logging import (
        evaluate_cis_2_1, evaluate_cis_2_2, evaluate_cis_2_3, evaluate_cis_2_4,
        evaluate_cis_2_5, evaluate_cis_2_6, evaluate_cis_2_7, evaluate_cis_2_8,
        evaluate_cis_2_9, evaluate_cis_2_10, evaluate_cis_2_11, evaluate_cis_2_12,
        evaluate_cis_2_13, evaluate_cis_2_14, evaluate_cis_2_15, evaluate_cis_2_16,
    )
    EVALUATOR_REGISTRY.update({
        "2.1": evaluate_cis_2_1, "2.2": evaluate_cis_2_2, "2.3": evaluate_cis_2_3,
        "2.4": evaluate_cis_2_4, "2.5": evaluate_cis_2_5, "2.6": evaluate_cis_2_6,
        "2.7": evaluate_cis_2_7, "2.8": evaluate_cis_2_8, "2.9": evaluate_cis_2_9,
        "2.10": evaluate_cis_2_10, "2.11": evaluate_cis_2_11, "2.12": evaluate_cis_2_12,
        "2.13": evaluate_cis_2_13, "2.14": evaluate_cis_2_14, "2.15": evaluate_cis_2_15,
        "2.16": evaluate_cis_2_16,
    })


def _register_section_3():
    from .section_3_networking import (
        evaluate_cis_3_1, evaluate_cis_3_2, evaluate_cis_3_3, evaluate_cis_3_4,
        evaluate_cis_3_5, evaluate_cis_3_6, evaluate_cis_3_7, evaluate_cis_3_8,
        evaluate_cis_3_9, evaluate_cis_3_10,
    )
    EVALUATOR_REGISTRY.update({
        "3.1": evaluate_cis_3_1, "3.2": evaluate_cis_3_2, "3.3": evaluate_cis_3_3,
        "3.4": evaluate_cis_3_4, "3.5": evaluate_cis_3_5, "3.6": evaluate_cis_3_6,
        "3.7": evaluate_cis_3_7, "3.8": evaluate_cis_3_8, "3.9": evaluate_cis_3_9,
        "3.10": evaluate_cis_3_10,
    })


def _register_section_4():
    from .section_4_compute import (
        evaluate_cis_4_1, evaluate_cis_4_2, evaluate_cis_4_3, evaluate_cis_4_4,
        evaluate_cis_4_5, evaluate_cis_4_6, evaluate_cis_4_7, evaluate_cis_4_8,
        evaluate_cis_4_9, evaluate_cis_4_10, evaluate_cis_4_11, evaluate_cis_4_12,
    )
    EVALUATOR_REGISTRY.update({
        "4.1": evaluate_cis_4_1, "4.2": evaluate_cis_4_2, "4.3": evaluate_cis_4_3,
        "4.4": evaluate_cis_4_4, "4.5": evaluate_cis_4_5, "4.6": evaluate_cis_4_6,
        "4.7": evaluate_cis_4_7, "4.8": evaluate_cis_4_8, "4.9": evaluate_cis_4_9,
        "4.10": evaluate_cis_4_10, "4.11": evaluate_cis_4_11, "4.12": evaluate_cis_4_12,
    })


def _register_sections_5_8():
    from .section_5_8_rest import (
        evaluate_cis_5_1, evaluate_cis_5_2,
        evaluate_cis_6_1_1, evaluate_cis_6_1_2, evaluate_cis_6_1_3,
        evaluate_cis_6_2_1, evaluate_cis_6_2_2, evaluate_cis_6_2_3,
        evaluate_cis_6_2_4, evaluate_cis_6_2_5, evaluate_cis_6_2_6,
        evaluate_cis_6_2_7, evaluate_cis_6_2_8,
        evaluate_cis_6_3_1, evaluate_cis_6_3_2, evaluate_cis_6_3_3,
        evaluate_cis_6_3_4, evaluate_cis_6_3_5, evaluate_cis_6_3_6,
        evaluate_cis_6_3_7,
        evaluate_cis_6_4, evaluate_cis_6_5, evaluate_cis_6_6, evaluate_cis_6_7,
        evaluate_cis_7_1, evaluate_cis_7_2, evaluate_cis_7_3, evaluate_cis_7_4,
        evaluate_cis_8_1,
    )
    EVALUATOR_REGISTRY.update({
        # Section 5: Storage
        "5.1": evaluate_cis_5_1, "5.2": evaluate_cis_5_2,
        # Section 6.1: MySQL
        "6.1.1": evaluate_cis_6_1_1, "6.1.2": evaluate_cis_6_1_2,
        "6.1.3": evaluate_cis_6_1_3,
        # Section 6.2: PostgreSQL
        "6.2.1": evaluate_cis_6_2_1, "6.2.2": evaluate_cis_6_2_2,
        "6.2.3": evaluate_cis_6_2_3, "6.2.4": evaluate_cis_6_2_4,
        "6.2.5": evaluate_cis_6_2_5, "6.2.6": evaluate_cis_6_2_6,
        "6.2.7": evaluate_cis_6_2_7, "6.2.8": evaluate_cis_6_2_8,
        # Section 6.3: SQL Server
        "6.3.1": evaluate_cis_6_3_1, "6.3.2": evaluate_cis_6_3_2,
        "6.3.3": evaluate_cis_6_3_3, "6.3.4": evaluate_cis_6_3_4,
        "6.3.5": evaluate_cis_6_3_5, "6.3.6": evaluate_cis_6_3_6,
        "6.3.7": evaluate_cis_6_3_7,
        # Section 6.4-6.7: General SQL
        "6.4": evaluate_cis_6_4, "6.5": evaluate_cis_6_5,
        "6.6": evaluate_cis_6_6, "6.7": evaluate_cis_6_7,
        # Section 7: BigQuery
        "7.1": evaluate_cis_7_1, "7.2": evaluate_cis_7_2,
        "7.3": evaluate_cis_7_3, "7.4": evaluate_cis_7_4,
        # Section 8: Dataproc
        "8.1": evaluate_cis_8_1,
    })


def _load_all():
    _register_section_1()
    _register_section_2()
    _register_section_3()
    _register_section_4()
    _register_sections_5_8()
    logger.info("Loaded %d GCP CIS evaluators", len(EVALUATOR_REGISTRY))


_load_all()


def get_evaluator(cis_id: str) -> Optional[EvaluatorFn]:
    return EVALUATOR_REGISTRY.get(cis_id)


def list_implemented_controls() -> list[str]:
    return sorted(EVALUATOR_REGISTRY.keys())


def coverage_report(total_controls: int = 84) -> dict:
    n = len(EVALUATOR_REGISTRY)
    return {"total": total_controls, "implemented": n,
            "coverage_pct": round(n / total_controls * 100, 1),
            "ids": sorted(EVALUATOR_REGISTRY.keys())}
