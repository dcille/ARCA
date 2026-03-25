"""SaaS Scanner Factory - creates appropriate scanner based on provider type.

Resolves scanner implementations from the central scanner registry
(SCANNER_PROVIDERS) instead of maintaining a separate hardcoded mapping.
"""
from scanner.registry.models import get_scanner_class, SAAS_PROVIDERS


class SaaSScannerFactory:
    """Factory for creating SaaS-specific scanners."""

    _saas_provider_values = {p.value for p in SAAS_PROVIDERS}

    @classmethod
    def create(cls, provider_type: str, credentials: dict):
        if provider_type not in cls._saas_provider_values:
            raise ValueError(
                f"Unsupported SaaS provider: '{provider_type}'. "
                f"Supported: {sorted(cls._saas_provider_values)}"
            )
        scanner_cls = get_scanner_class(provider_type)
        return scanner_cls(credentials)
