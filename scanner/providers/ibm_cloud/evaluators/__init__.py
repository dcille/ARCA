"""IBM Cloud CIS v2.0 Evaluator Registry — 73/73 controls mapped.

Sections:
  1  Identity and Access Management     20 controls ( 3 automated, 17 manual)
  2  Storage (COS + Block + File)       15 controls ( 0 automated, 15 manual)
  3  Logging and Monitoring              6 controls ( 0 automated,  6 manual)
  4  IBM Cloud Databases                 3 controls ( 0 automated,  3 manual)
  5  Cloudant                            1 control  ( 0 automated,  1 manual)
  6  Networking (CIS + VPC)              8 controls ( 0 automated,  8 manual)
  7  Containers (IKS)                    6 controls ( 4 automated,  2 manual)
  8  Security and Compliance             7 controls ( 3 automated,  4 manual)
  9  PowerVS                             7 controls ( 0 automated,  7 manual)
  ─────────────────────────────────────────────────────────────────
  Total                                 73 controls (10 automated, 63 manual)
"""
from .section_1_iam import SECTION_1_EVALUATORS
from .section_2_6_storage_log_net import (
    SECTION_2_EVALUATORS, SECTION_3_EVALUATORS, SECTION_4_EVALUATORS,
    SECTION_5_EVALUATORS, SECTION_6_EVALUATORS,
)
from .section_7_9_k8s_sec_pvs import (
    SECTION_7_EVALUATORS, SECTION_8_EVALUATORS, SECTION_9_EVALUATORS,
)

EVALUATOR_REGISTRY: dict[str, callable] = {}
EVALUATOR_REGISTRY.update(SECTION_1_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_2_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_3_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_4_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_5_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_6_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_7_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_8_EVALUATORS)
EVALUATOR_REGISTRY.update(SECTION_9_EVALUATORS)

assert len(EVALUATOR_REGISTRY) == 73, (
    f"Expected 73 evaluators, got {len(EVALUATOR_REGISTRY)}: "
    f"{sorted(EVALUATOR_REGISTRY.keys())}")

__all__ = ["EVALUATOR_REGISTRY"]
