"""Cloud security scanner engine.

Supports AWS, Azure, GCP, Kubernetes, OCI, Alibaba, IBM Cloud,
and all SaaS providers registered in the scanner registry.
Each provider implements checks organized by service.
"""
import inspect
import logging
from typing import Optional

from scanner.registry.models import get_scanner_class, SCANNER_PROVIDERS
from scanner.scan_logger import ScanLogger

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
        self.scan_logger = ScanLogger()

    def run_checks(self) -> list[dict]:
        """Run all applicable security checks for the configured provider."""
        slog = self.scan_logger

        # Resolve scanner class
        class_path = SCANNER_PROVIDERS.get(self.provider_type, "unknown")
        scanner_cls = get_scanner_class(self.provider_type)
        module_file = class_path.rsplit(".", 1)[0].replace(".", "/") + ".py"

        slog.log_module_start(module_file, f"Resolved scanner: {scanner_cls.__name__}")

        scanner = self._instantiate_scanner(scanner_cls)
        slog.log_api_call(
            self.provider_type, "init_credentials",
            module=module_file,
            detail=f"Initialised {scanner_cls.__name__} for provider '{self.provider_type}'",
        )

        # Use run_all_checks if available (includes CIS engine + custom controls)
        if hasattr(scanner, "run_all_checks"):
            # Inject scan_logger into the scanner if it accepts it
            scanner._scan_logger = slog

            slog.log_phase_start("run_all_checks", module_file)
            results = scanner.run_all_checks()
            slog.log_phase_end("run_all_checks", module_file, result_count=len(results))
        else:
            slog.log_phase_start("scan", module_file)
            results = scanner.scan()
            slog.log_phase_end("scan", module_file, result_count=len(results))

        slog.log_module_end(module_file, result_count=len(results))
        return results

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
