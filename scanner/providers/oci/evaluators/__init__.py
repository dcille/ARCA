"""OCI CIS v3.1 Evaluator Registry — 54/54 controls mapped.

Sections:
  1  Identity and Access Management  17 controls (10 automated, 7 manual)
  2  Networking                       8 controls ( 5 automated, 3 manual)
  3  Compute                          3 controls ( 3 automated)
  4  Logging and Monitoring          18 controls (18 automated)
  5  Storage                          6 controls ( 6 automated)
  6  Asset Management                 2 controls ( 2 automated)
  ─────────────────────────────────────────────────────────────────
  Total                              54 controls (44 automated, 10 manual)
"""
from .section_1_iam import SECTION_1_EVALUATORS
from .section_2_3_network_compute import SECTION_2_EVALUATORS, SECTION_3_EVALUATORS
from .section_4_logging import SECTION_4_EVALUATORS
from .section_5_6_storage_asset import SECTION_5_EVALUATORS, SECTION_6_EVALUATORS

EVALUATOR_REGISTRY: dict[str, callable] = {}
EVALUATOR_REGISTRY.update(SECTION_1_EVALUATORS)   # 1.1 – 1.17  (17)
EVALUATOR_REGISTRY.update(SECTION_2_EVALUATORS)    # 2.1 – 2.8   ( 8)
EVALUATOR_REGISTRY.update(SECTION_3_EVALUATORS)    # 3.1 – 3.3   ( 3)
EVALUATOR_REGISTRY.update(SECTION_4_EVALUATORS)    # 4.1 – 4.18  (18)
EVALUATOR_REGISTRY.update(SECTION_5_EVALUATORS)    # 5.1.1–5.3.1 ( 6)
EVALUATOR_REGISTRY.update(SECTION_6_EVALUATORS)    # 6.1 – 6.2   ( 2)

assert len(EVALUATOR_REGISTRY) == 54, (
    f"Expected 54 evaluators, got {len(EVALUATOR_REGISTRY)}: "
    f"{sorted(EVALUATOR_REGISTRY.keys())}"
)

__all__ = ["EVALUATOR_REGISTRY"]
