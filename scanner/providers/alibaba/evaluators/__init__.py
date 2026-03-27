"""Alibaba Cloud CIS v2.0 Evaluator Registry — 85/85 controls mapped.

Sections:
  1  Identity and Access Management  16 controls (13 automated,  3 manual)
  2  Logging and Monitoring          23 controls ( 2 automated, 21 manual)
  3  Networking                       5 controls ( 0 automated,  5 manual)
  4  Virtual Machines                 6 controls ( 0 automated,  6 manual)
  5  Storage (OSS)                    9 controls ( 4 automated,  5 manual)
  6  Relational Database Services     9 controls ( 9 automated,  0 manual)
  7  Kubernetes Engine                9 controls ( 9 automated,  0 manual)
  8  Security Center                  8 controls ( 4 automated,  4 manual)
  ─────────────────────────────────────────────────────────────────
  Total                              85 controls (41 automated, 44 manual)
"""
from .section_1_iam import SECTION_1_EVALUATORS
from .section_2_4_logging_net_vm import SECTION_2_EVALUATORS, SECTION_3_EVALUATORS, SECTION_4_EVALUATORS
from .section_5_6_storage_rds import SECTION_5_EVALUATORS, SECTION_6_EVALUATORS
from .section_7_8_k8s_security import SECTION_7_EVALUATORS, SECTION_8_EVALUATORS

EVALUATOR_REGISTRY: dict[str, callable] = {}
EVALUATOR_REGISTRY.update(SECTION_1_EVALUATORS)   # 1.1 – 1.16  (16)
EVALUATOR_REGISTRY.update(SECTION_2_EVALUATORS)    # 2.1 – 2.23  (23)
EVALUATOR_REGISTRY.update(SECTION_3_EVALUATORS)    # 3.1 – 3.5   ( 5)
EVALUATOR_REGISTRY.update(SECTION_4_EVALUATORS)    # 4.1 – 4.6   ( 6)
EVALUATOR_REGISTRY.update(SECTION_5_EVALUATORS)    # 5.1 – 5.9   ( 9)
EVALUATOR_REGISTRY.update(SECTION_6_EVALUATORS)    # 6.1 – 6.9   ( 9)
EVALUATOR_REGISTRY.update(SECTION_7_EVALUATORS)    # 7.1 – 7.9   ( 9)
EVALUATOR_REGISTRY.update(SECTION_8_EVALUATORS)    # 8.1 – 8.8   ( 8)

assert len(EVALUATOR_REGISTRY) == 85, (
    f"Expected 85 evaluators, got {len(EVALUATOR_REGISTRY)}: "
    f"{sorted(EVALUATOR_REGISTRY.keys())}"
)

__all__ = ["EVALUATOR_REGISTRY"]
