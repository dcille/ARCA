"""Centralized check library — backward-compatible facade over scanner.registry.

This module is kept for backward compatibility with existing code that imports
from ``scanner.check_library``.  All functionality is now delegated to
``scanner.registry``, which provides the comprehensive check catalog (679+
checks across 15 providers) and cross-reference validation against MITRE
ATT&CK and Ransomware Readiness modules.

New code should import directly from ``scanner.registry``.
"""

import logging
from typing import Optional

# Re-export the canonical types so existing imports keep working
from scanner.registry.models import CheckDefinition  # noqa: F401
from scanner.registry.registry import (
    CheckRegistry,  # noqa: F401
    get_default_registry,
)

logger = logging.getLogger(__name__)


# ======================================================================
# Module-level convenience functions (backward-compatible API)
# ======================================================================

_default_registry: Optional[CheckRegistry] = None


def get_default_registry_compat() -> CheckRegistry:
    """Return the module-level default registry (delegates to scanner.registry)."""
    return get_default_registry()


def register_custom_check(check: CheckDefinition) -> None:
    """Register a custom check in the default registry."""
    get_default_registry().register_check(check, custom=True)


def search(query: str) -> list[CheckDefinition]:
    """Search the default registry."""
    return get_default_registry().search_checks(query)


def catalog_report() -> dict:
    """Generate a catalog report from the default registry."""
    return get_default_registry().generate_catalog_report()
