"""Cloud security scanner engine.

Supports AWS, Azure, GCP, Kubernetes, OCI, Alibaba, IBM Cloud,
and all SaaS providers registered in the scanner registry.
Each provider implements checks organized by service.
"""
import inspect
import logging
from typing import Optional

from scanner.registry.models import get_scanner_class, SCANNER_PROVIDERS

logger = logging.getLogger(__name__)


class CloudScanner:
    """Main cloud scanner that dispatches to provider-specific scanners.

    Resolves scanner implementations dynamically from the scanner registry
    (SCANNER_PROVIDERS) instead of hardcoding provider-to-class mappings.
    """

    def __init__(
        self,
        provider_type: str,
        credentials: dict,
        region: Optional[str] = None,
        services: Optional[list] = None,
        regions: Optional[list] = None,
        custom_controls: Optional[list[dict]] = None,
    ):
        self.provider_type = provider_type
        self.credentials = credentials
        self.region = region
        self.services = services
        self.regions = regions
        self.custom_controls = custom_controls or []

    def run_checks(self) -> list[dict]:
        """Run all applicable security checks for the configured provider."""
        scanner_cls = get_scanner_class(self.provider_type)
        scanner = self._instantiate_scanner(scanner_cls)

        # Use run_all_checks if available (includes CIS engine + custom controls)
        if hasattr(scanner, "run_all_checks"):
            return scanner.run_all_checks()
        return scanner.scan()

    def _instantiate_scanner(self, scanner_cls):
        """Instantiate a scanner, passing only the parameters it accepts."""
        sig = inspect.signature(scanner_cls.__init__)
        params = set(sig.parameters.keys()) - {"self"}

        kwargs: dict = {"credentials": self.credentials}

        if "regions" in params and self.regions is not None:
            kwargs["regions"] = self.regions
        if "services" in params and self.services is not None:
            kwargs["services"] = self.services
        if "custom_controls" in params and self.custom_controls:
            kwargs["custom_controls"] = self.custom_controls

        return scanner_cls(**kwargs)

    @staticmethod
    def supported_providers() -> list[str]:
        """Return all provider types with registered scanners."""
        return sorted(SCANNER_PROVIDERS.keys())
