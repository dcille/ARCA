"""Centralized security check registry for ARCA CSPM.

Based on CIS Benchmark controls (904 across 9 benchmarks) as the primary
source of truth. Scanner check_ids map into CIS controls, and MITRE ATT&CK
and Ransomware Readiness modules are cross-referenced through the
scanner_check_ids bridge.

Resolution chain:
  MITRE check_id → scanner_check_id → CIS control in registry
  RR check_id → CHECK_ID_ALIASES → scanner_check_id → CIS control in registry
"""

from scanner.registry.models import CheckDefinition, ProviderType, Severity, Category
from scanner.registry.registry import CheckRegistry, get_default_registry

__all__ = [
    "CheckDefinition",
    "CheckRegistry",
    "ProviderType",
    "Severity",
    "Category",
    "get_default_registry",
]
