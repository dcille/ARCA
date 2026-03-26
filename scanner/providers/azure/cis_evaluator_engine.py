"""CIS Evaluator Engine — Orchestrates evaluation of ALL CIS controls.

This replaces the old approach where azure_scanner.py had hardcoded checks
and _emit_cis_coverage() filled gaps with MANUAL placeholders.

New flow:
  1. Load CIS control registry (155 controls for Azure v5.0)
  2. For each control, look up its evaluator function
  3. If evaluator exists → run it → get per-resource PASS/FAIL
  4. If no evaluator → emit MANUAL result with reason
  5. Return complete results covering ALL 155 controls

Usage:
    from cis_evaluator_engine import CISEvaluatorEngine

    engine = CISEvaluatorEngine(credentials)
    results = engine.evaluate_all()
    # OR
    results = engine.evaluate_section("7")  # Just networking
"""

import logging
import time
from typing import Optional

from .evaluator.base import (
    AzureClientCache,
    EvalConfig,
    make_manual_result,
    safe_evaluate,
)
from .evaluator import EVALUATOR_REGISTRY, get_evaluator

logger = logging.getLogger(__name__)


class CISEvaluatorEngine:
    """Orchestrates CIS benchmark evaluation across all controls."""

    def __init__(
        self,
        credentials: dict,
        services: Optional[list[str]] = None,
        resource_groups: Optional[list[str]] = None,
    ):
        self.credentials = credentials
        self.subscription_id = credentials.get("subscription_id", "")
        self.tenant_id = credentials.get("tenant_id", "")
        self.services = services
        self.resource_groups = resource_groups

        # Lazy-init
        self._clients: Optional[AzureClientCache] = None
        self._config: Optional[EvalConfig] = None
        self._cis_controls: Optional[list[dict]] = None

    def _get_credential(self):
        from azure.identity import ClientSecretCredential
        return ClientSecretCredential(
            tenant_id=self.credentials.get("tenant_id"),
            client_id=self.credentials.get("client_id"),
            client_secret=self.credentials.get("client_secret"),
        )

    def _get_clients(self) -> AzureClientCache:
        if self._clients is None:
            self._clients = AzureClientCache(
                credential=self._get_credential(),
                subscription_id=self.subscription_id,
            )
        return self._clients

    def _get_config(self) -> EvalConfig:
        if self._config is None:
            self._config = EvalConfig(
                subscription_id=self.subscription_id,
                tenant_id=self.tenant_id,
                resource_groups=self.resource_groups,
            )
        return self._config

    def _get_cis_controls(self) -> list[dict]:
        """Load the CIS control definitions."""
        if self._cis_controls is None:
            from scanner.cis_controls.azure_cis_controls import AZURE_CIS_CONTROLS
            self._cis_controls = AZURE_CIS_CONTROLS
        return self._cis_controls

    # ─────────────────────────────────────────────────────────────
    # Service-section mapping (for filtering by service)
    # ─────────────────────────────────────────────────────────────

    _SECTION_SERVICE_MAP = {
        "2": "analytics",       # Databricks
        "3": "compute",         # VMs
        "5": "identity",        # Entra ID
        "6": "monitoring",      # Logging & monitoring
        "7": "networking",      # Networking
        "8": "security",        # Defender + Key Vault
        "9": "storage",         # Storage
    }

    def _should_evaluate_control(self, cis_id: str) -> bool:
        """Check if this control should be evaluated based on service filters."""
        if not self.services:
            return True  # No filter = evaluate everything

        section = cis_id.split(".")[0]
        mapped_service = self._SECTION_SERVICE_MAP.get(section)
        if mapped_service and mapped_service in self.services:
            return True

        # Also allow if the CIS control's service_area matches
        return False

    # ─────────────────────────────────────────────────────────────
    # Main evaluation methods
    # ─────────────────────────────────────────────────────────────

    def evaluate_all(self) -> list[dict]:
        """Evaluate ALL CIS controls — the main entry point.

        Returns a list of CheckResult dicts covering every CIS control.
        Automated controls get per-resource PASS/FAIL results.
        Unimplemented controls get a single MANUAL result.
        """
        controls = self._get_cis_controls()
        clients = self._get_clients()
        config = self._get_config()

        all_results: list[dict] = []
        evaluated_count = 0
        manual_count = 0
        error_count = 0

        start = time.monotonic()
        logger.info(
            "Starting CIS evaluation: %d controls, %d evaluators available",
            len(controls), len(EVALUATOR_REGISTRY),
        )

        for ctrl in controls:
            cis_id = ctrl["cis_id"]

            # Service filter
            if not self._should_evaluate_control(cis_id):
                continue

            evaluator = get_evaluator(cis_id)

            if evaluator:
                # ── Automated evaluation ──
                results = safe_evaluate(
                    evaluator=evaluator,
                    clients=clients,
                    config=config,
                    cis_id=cis_id,
                    check_id=f"azure_cis_{cis_id.replace('.', '_')}",
                    title=ctrl["title"],
                    service=ctrl.get("service_area", "general"),
                    severity=ctrl["severity"],
                )
                all_results.extend(results)
                evaluated_count += 1

                # Count errors
                for r in results:
                    if r.get("status") == "ERROR":
                        error_count += 1

            else:
                # ── No evaluator → MANUAL ──
                reason = self._classify_manual_reason(ctrl)
                all_results.append(make_manual_result(
                    cis_id=cis_id,
                    check_id=f"azure_cis_{cis_id.replace('.', '_')}",
                    title=ctrl["title"],
                    service=ctrl.get("service_area", "general"),
                    severity=ctrl["severity"],
                    subscription_id=config.subscription_id,
                    reason=reason,
                ))
                manual_count += 1

        elapsed = time.monotonic() - start
        logger.info(
            "CIS evaluation complete: %d controls processed "
            "(%d evaluated, %d manual, %d errors) in %.1fs. "
            "Total results: %d",
            evaluated_count + manual_count,
            evaluated_count, manual_count, error_count,
            elapsed, len(all_results),
        )

        return all_results

    def evaluate_section(self, section: str) -> list[dict]:
        """Evaluate only controls in a specific CIS section (e.g., "7" for Networking)."""
        controls = self._get_cis_controls()
        clients = self._get_clients()
        config = self._get_config()

        results: list[dict] = []
        for ctrl in controls:
            cis_id = ctrl["cis_id"]
            if not cis_id.startswith(f"{section}."):
                continue

            evaluator = get_evaluator(cis_id)
            if evaluator:
                results.extend(safe_evaluate(
                    evaluator=evaluator,
                    clients=clients,
                    config=config,
                    cis_id=cis_id,
                    check_id=f"azure_cis_{cis_id.replace('.', '_')}",
                    title=ctrl["title"],
                    service=ctrl.get("service_area", "general"),
                    severity=ctrl["severity"],
                ))
            else:
                reason = self._classify_manual_reason(ctrl)
                results.append(make_manual_result(
                    cis_id=cis_id,
                    check_id=f"azure_cis_{cis_id.replace('.', '_')}",
                    title=ctrl["title"],
                    service=ctrl.get("service_area", "general"),
                    severity=ctrl["severity"],
                    subscription_id=config.subscription_id,
                    reason=reason,
                ))

        return results

    def evaluate_single(self, cis_id: str) -> list[dict]:
        """Evaluate a single CIS control by its ID."""
        controls = self._get_cis_controls()
        ctrl = next((c for c in controls if c["cis_id"] == cis_id), None)
        if not ctrl:
            return [{"error": f"CIS control {cis_id} not found"}]

        evaluator = get_evaluator(cis_id)
        if not evaluator:
            return [make_manual_result(
                cis_id=cis_id,
                check_id=f"azure_cis_{cis_id.replace('.', '_')}",
                title=ctrl["title"],
                service=ctrl.get("service_area", "general"),
                severity=ctrl["severity"],
                subscription_id=self.subscription_id,
                reason=self._classify_manual_reason(ctrl),
            )]

        return safe_evaluate(
            evaluator=evaluator,
            clients=self._get_clients(),
            config=self._get_config(),
            cis_id=cis_id,
            check_id=f"azure_cis_{cis_id.replace('.', '_')}",
            title=ctrl["title"],
            service=ctrl.get("service_area", "general"),
            severity=ctrl["severity"],
        )

    # ─────────────────────────────────────────────────────────────
    # Manual reason classification
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _classify_manual_reason(ctrl: dict) -> str:
        """Classify WHY a control is manual — useful for compliance reports."""
        assessment_type = ctrl.get("assessment_type", "manual")
        cis_id = ctrl["cis_id"]

        if assessment_type == "manual":
            # The CIS benchmark itself says this is manual
            return (
                f"CIS classifies {cis_id} as a manual assessment. "
                "This control requires human judgment or portal verification."
            )

        # It's "automated" in CIS but we don't have an evaluator yet
        return (
            f"CIS classifies {cis_id} as automatable, but the evaluator "
            "is not yet implemented. Scheduled for a future release."
        )

    # ─────────────────────────────────────────────────────────────
    # Coverage reporting
    # ─────────────────────────────────────────────────────────────

    def coverage_report(self) -> dict:
        """Generate a coverage report showing implemented vs total controls."""
        controls = self._get_cis_controls()

        total = len(controls)
        automated_in_cis = sum(1 for c in controls if c["assessment_type"] == "automated")
        manual_in_cis = sum(1 for c in controls if c["assessment_type"] == "manual")

        implemented = sum(
            1 for c in controls
            if get_evaluator(c["cis_id"]) is not None
        )

        # Break down by section
        by_section: dict[str, dict] = {}
        for c in controls:
            section = c["cis_id"].split(".")[0]
            if section not in by_section:
                by_section[section] = {"total": 0, "implemented": 0, "manual": 0}
            by_section[section]["total"] += 1
            if get_evaluator(c["cis_id"]):
                by_section[section]["implemented"] += 1
            else:
                by_section[section]["manual"] += 1

        return {
            "benchmark": "CIS Microsoft Azure Foundations v5.0.0",
            "total_controls": total,
            "cis_automated": automated_in_cis,
            "cis_manual": manual_in_cis,
            "evaluators_implemented": implemented,
            "evaluators_missing": total - implemented,
            "coverage_pct": round(implemented / total * 100, 1),
            "by_section": by_section,
        }
