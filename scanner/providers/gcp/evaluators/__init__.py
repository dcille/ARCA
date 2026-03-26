"""GCP CIS v4.0 Evaluator Registry — maps all 69 control IDs to evaluator functions."""
from __future__ import annotations
import logging
from typing import Optional
from .base import EvaluatorFn
logger = logging.getLogger(__name__)
EVALUATOR_REGISTRY: dict[str, EvaluatorFn] = {}

def _register_section_1():
    from . import section_1_iam as m
    for i in range(1,18):
        fn = getattr(m, f"evaluate_cis_1_{i}", None)
        if fn: EVALUATOR_REGISTRY[f"1.{i}"] = fn

def _register_section_2():
    from . import section_2_logging as m
    for i in range(1,17):
        fn = getattr(m, f"evaluate_cis_2_{i}", None)
        if fn: EVALUATOR_REGISTRY[f"2.{i}"] = fn

def _register_section_3():
    from . import section_3_networking as m
    for i in range(1,11):
        fn = getattr(m, f"evaluate_cis_3_{i}", None)
        if fn: EVALUATOR_REGISTRY[f"3.{i}"] = fn

def _register_section_4():
    from . import section_4_compute as m
    for i in range(1,13):
        fn = getattr(m, f"evaluate_cis_4_{i}", None)
        if fn: EVALUATOR_REGISTRY[f"4.{i}"] = fn

def _register_sections_5_8():
    from . import section_5_8_rest as m
    for i in (1,2): EVALUATOR_REGISTRY[f"5.{i}"] = getattr(m, f"evaluate_cis_5_{i}")
    for i in range(1,8): EVALUATOR_REGISTRY[f"6.{i}"] = getattr(m, f"evaluate_cis_6_{i}")
    for i in range(1,5): EVALUATOR_REGISTRY[f"7.{i}"] = getattr(m, f"evaluate_cis_7_{i}")
    EVALUATOR_REGISTRY["8.1"] = m.evaluate_cis_8_1

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
