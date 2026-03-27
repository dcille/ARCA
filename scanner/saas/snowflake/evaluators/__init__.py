"""CIS Snowflake v1.0.0 — Evaluator Registry.

Merges Section 1-4 evaluators and applies supplement overlays that
upgrade manual controls to automated where possible.

Final coverage: 39/39 controls (100%) — 36 automated (92.3%)
"""

from __future__ import annotations

from .section_1_iam import SECTION_1_EVALUATORS
from .section_2_monitoring import SECTION_2_EVALUATORS
from .section_3_4_net_data import SECTION_3_EVALUATORS, SECTION_4_EVALUATORS
from .supplements import SUPPLEMENT_EVALUATORS

# Build base registry
EVALUATOR_REGISTRY: dict[str, callable] = {}
EVALUATOR_REGISTRY.update(SECTION_1_EVALUATORS)   # 17 controls
EVALUATOR_REGISTRY.update(SECTION_2_EVALUATORS)    #  9 controls
EVALUATOR_REGISTRY.update(SECTION_3_EVALUATORS)    #  2 controls
EVALUATOR_REGISTRY.update(SECTION_4_EVALUATORS)    # 11 controls
# Total: 39

# Apply supplements overlay (upgrades manual → automated)
EVALUATOR_REGISTRY.update(SUPPLEMENT_EVALUATORS)   # 13 upgrades

__all__ = ["EVALUATOR_REGISTRY"]
