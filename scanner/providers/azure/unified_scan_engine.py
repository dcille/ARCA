"""Unified Scan Engine — Runs CIS evaluators + custom framework controls in a single scan.

This is the top-level orchestrator that combines:
  1. CIS Evaluator Engine (155 hardcoded Python evaluators for CIS Azure v5.0)
  2. Custom Framework Engine (user-defined controls with CLI/Python evaluation logic)

The scan results are unified into a single list of CheckResult dicts.

Usage in azure_scanner.py:
    from .unified_scan_engine import UnifiedScanEngine

    class AzureScanner:
        def scan(self) -> list[dict]:
            engine = UnifiedScanEngine(
                credentials=self.credentials,
                custom_controls=self._load_custom_controls(),  # From DB
            )
            return engine.evaluate_all()
"""

import logging
from typing import Optional

from .cis_evaluator_engine import CISEvaluatorEngine
from .custom_control_executor import (
    CustomControl,
    CustomControlExecutor,
    CustomFrameworkEngine,
)

logger = logging.getLogger(__name__)


class UnifiedScanEngine:
    """Runs all evaluation sources in a single scan."""

    def __init__(
        self,
        credentials: dict,
        services: Optional[list[str]] = None,
        resource_groups: Optional[list[str]] = None,
        custom_controls: Optional[list[dict]] = None,
        scan_logger=None,
    ):
        self.credentials = credentials
        self.services = services
        self.resource_groups = resource_groups
        self._raw_custom_controls = custom_controls or []
        self._scan_logger = scan_logger

    def _build_custom_controls(self) -> list[CustomControl]:
        """Convert raw control dicts (from DB) into CustomControl objects."""
        controls = []
        for raw in self._raw_custom_controls:
            try:
                controls.append(CustomControl(
                    control_id=raw.get("control_id", raw.get("id", "")),
                    title=raw.get("title", ""),
                    description=raw.get("description", ""),
                    severity=raw.get("severity", "medium"),
                    service=raw.get("service", "general"),
                    framework_id=raw.get("framework_id", ""),
                    remediation=raw.get("remediation", ""),
                    compliance_frameworks=raw.get("compliance_frameworks", []),
                    cli_command=raw.get("cli_command"),
                    pass_condition=raw.get("pass_condition", "empty"),
                    evaluation_script=raw.get("evaluation_script"),
                ))
            except Exception as e:
                logger.warning("Skipping invalid custom control %s: %s",
                               raw.get("control_id", "?"), e)
        return controls

    def evaluate_all(self) -> list[dict]:
        """Run ALL evaluations: CIS + custom frameworks."""
        all_results = []

        # 1. CIS Evaluator Engine (155 controls)
        logger.info("Phase 1: Running CIS evaluators...")
        cis_engine = CISEvaluatorEngine(
            credentials=self.credentials,
            services=self.services,
            resource_groups=self.resource_groups,
            scan_logger=self._scan_logger,
        )
        cis_results = cis_engine.evaluate_all()
        all_results.extend(cis_results)
        logger.info("CIS evaluation: %d results", len(cis_results))

        # 2. Custom Framework Controls
        custom_controls = self._build_custom_controls()
        if custom_controls:
            logger.info("Phase 2: Running %d custom controls...", len(custom_controls))
            from azure.identity import ClientSecretCredential
            credential = ClientSecretCredential(
                tenant_id=self.credentials.get("tenant_id"),
                client_id=self.credentials.get("client_id"),
                client_secret=self.credentials.get("client_secret"),
            )
            custom_engine = CustomFrameworkEngine(
                credential=credential,
                subscription_id=self.credentials.get("subscription_id", ""),
                tenant_id=self.credentials.get("tenant_id", ""),
                controls=custom_controls,
            )
            custom_results = custom_engine.evaluate_all()
            all_results.extend(custom_results)
            logger.info("Custom controls: %d results", len(custom_results))
        else:
            logger.info("Phase 2: No custom controls to evaluate")

        logger.info("Unified scan complete: %d total results", len(all_results))
        return all_results

    def coverage_report(self) -> dict:
        """Report on evaluation coverage."""
        cis_engine = CISEvaluatorEngine(credentials=self.credentials)
        cis_report = cis_engine.coverage_report()

        custom_controls = self._build_custom_controls()
        automated_custom = sum(
            1 for c in custom_controls
            if c.evaluation_script or c.cli_command
        )
        manual_custom = len(custom_controls) - automated_custom

        return {
            "cis": cis_report,
            "custom": {
                "total_controls": len(custom_controls),
                "automated": automated_custom,
                "manual": manual_custom,
            },
            "combined": {
                "total": cis_report["total_controls"] + len(custom_controls),
                "automated": cis_report["evaluators_implemented"] + automated_custom,
            },
        }
