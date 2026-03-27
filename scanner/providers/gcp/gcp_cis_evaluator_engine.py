"""GCP CIS Evaluator Engine — Orchestrates evaluation of all 84 CIS GCP v4.0 controls.

Usage:
    from gcp_cis_evaluator_engine import GCPCISEvaluatorEngine

    engine = GCPCISEvaluatorEngine(credentials={"project_id": ..., "service_account_key": ...})
    results = engine.evaluate_all()
"""

import json
import logging
import time
from typing import Optional

from .evaluators.base import GCPClientCache, EvalConfig, make_manual_result, safe_evaluate
from .evaluators import EVALUATOR_REGISTRY, get_evaluator

logger = logging.getLogger(__name__)


class GCPCISEvaluatorEngine:
    """Orchestrates CIS GCP benchmark evaluation across all 84 controls."""

    def __init__(self, credentials: dict, services=None, regions=None, scan_logger=None):
        self.credentials = credentials
        self.project_id = credentials.get("project_id", "")
        self.services = services
        self.regions = regions or ["us-central1"]
        self._scan_logger = scan_logger
        self._clients: Optional[GCPClientCache] = None
        self._config: Optional[EvalConfig] = None
        self._cis_controls = None

    def _get_credentials(self):
        from google.oauth2 import service_account
        cred_info = self.credentials.get("service_account_key")
        if isinstance(cred_info, str):
            cred_info = json.loads(cred_info)
        return service_account.Credentials.from_service_account_info(cred_info)

    def _get_clients(self) -> GCPClientCache:
        if not self._clients:
            self._clients = GCPClientCache(self._get_credentials(), self.project_id)
        return self._clients

    def _get_config(self) -> EvalConfig:
        if not self._config:
            self._config = EvalConfig(project_id=self.project_id, regions=self.regions)
        return self._config

    def _get_cis_controls(self) -> list[dict]:
        if not self._cis_controls:
            from scanner.cis_controls.gcp_cis_controls import GCP_CIS_CONTROLS
            self._cis_controls = GCP_CIS_CONTROLS
        return self._cis_controls

    # Maps top-level section number to service filter key
    _SECTION_SERVICE_MAP = {
        "1": "iam", "2": "logging", "3": "networking", "4": "compute",
        "5": "storage", "6": "sql", "7": "bigquery", "8": "dataproc",
    }

    def _should_evaluate(self, cis_id: str) -> bool:
        """Check if a control should be evaluated based on service filters."""
        if not self.services:
            return True
        section = cis_id.split(".")[0]
        return self._SECTION_SERVICE_MAP.get(section, "") in self.services

    def _classify_manual_reason(self, ctrl: dict) -> str:
        """Generate a meaningful reason for manual/unregistered controls."""
        assessment = ctrl.get("assessment_type", "manual")
        if assessment == "manual":
            return f"CIS classifies {ctrl['cis_id']} as manual assessment. Requires console or organizational verification."
        return f"Evaluator not in registry for {ctrl['cis_id']}."

    def evaluate_all(self) -> list[dict]:
        """Evaluate all CIS controls, returning combined results."""
        controls = self._get_cis_controls()
        clients = self._get_clients()
        config = self._get_config()
        all_results, evaluated, manual = [], 0, 0
        slog = self._scan_logger

        start = time.monotonic()
        logger.info("Starting GCP CIS evaluation: %d controls, %d evaluators",
                     len(controls), len(EVALUATOR_REGISTRY))

        for ctrl in controls:
            cis_id = ctrl["cis_id"]
            if not self._should_evaluate(cis_id):
                continue

            evaluator = get_evaluator(cis_id)
            if evaluator:
                module_name = f"evaluator::gcp_cis_{cis_id}"
                if slog:
                    slog.log_module_start(
                        module_name,
                        f"Evaluating CIS {cis_id}: {ctrl['title']}",
                    )
                results = safe_evaluate(
                    evaluator, clients, config, cis_id,
                    f"gcp_cis_{cis_id.replace('.', '_')}",
                    ctrl["title"],
                    ctrl.get("service_area", "general"),
                    ctrl["severity"],
                )
                all_results.extend(results)
                evaluated += 1
                has_error = any(r.get("status") == "ERROR" for r in results)
                if slog:
                    slog.log_module_end(
                        module_name,
                        result_count=len(results),
                        status="error" if has_error else "success",
                    )
            else:
                all_results.append(make_manual_result(
                    cis_id,
                    f"gcp_cis_{cis_id.replace('.', '_')}",
                    ctrl["title"],
                    ctrl.get("service_area", "general"),
                    ctrl["severity"],
                    config.project_id,
                    self._classify_manual_reason(ctrl),
                ))
                manual += 1

        elapsed = time.monotonic() - start
        logger.info("GCP CIS evaluation complete: %d evaluated, %d manual in %.1fs. Total results: %d",
                     evaluated, manual, elapsed, len(all_results))
        return all_results

    def evaluate_section(self, section: str) -> list[dict]:
        """Evaluate all controls in a specific section (e.g., '1', '6.2')."""
        controls = self._get_cis_controls()
        clients, config = self._get_clients(), self._get_config()
        results = []

        for ctrl in controls:
            cis_id = ctrl["cis_id"]
            if not cis_id.startswith(f"{section}."):
                continue

            evaluator = get_evaluator(cis_id)
            if evaluator:
                results.extend(safe_evaluate(
                    evaluator, clients, config, cis_id,
                    f"gcp_cis_{cis_id.replace('.', '_')}",
                    ctrl["title"],
                    ctrl.get("service_area", "general"),
                    ctrl["severity"],
                ))
            else:
                results.append(make_manual_result(
                    cis_id,
                    f"gcp_cis_{cis_id.replace('.', '_')}",
                    ctrl["title"],
                    ctrl.get("service_area", "general"),
                    ctrl["severity"],
                    config.project_id,
                    self._classify_manual_reason(ctrl),
                ))
        return results

    def evaluate_single(self, cis_id: str) -> list[dict]:
        """Evaluate a single CIS control by ID."""
        ctrl = next((c for c in self._get_cis_controls() if c["cis_id"] == cis_id), None)
        if not ctrl:
            return [{"error": f"CIS control {cis_id} not found"}]

        evaluator = get_evaluator(cis_id)
        if not evaluator:
            return [make_manual_result(
                cis_id,
                f"gcp_cis_{cis_id.replace('.', '_')}",
                ctrl["title"],
                ctrl.get("service_area", "general"),
                ctrl["severity"],
                self._get_config().project_id,
                self._classify_manual_reason(ctrl),
            )]

        return safe_evaluate(
            evaluator, self._get_clients(), self._get_config(), cis_id,
            f"gcp_cis_{cis_id.replace('.', '_')}",
            ctrl["title"],
            ctrl.get("service_area", "general"),
            ctrl["severity"],
        )

    def coverage_report(self) -> dict:
        """Return a coverage summary showing implemented vs total controls."""
        controls = self._get_cis_controls()
        by_section: dict[str, dict] = {}

        for ctrl in controls:
            section = ctrl["cis_id"].split(".")[0]
            by_section.setdefault(section, {"total": 0, "implemented": 0})
            by_section[section]["total"] += 1
            if get_evaluator(ctrl["cis_id"]):
                by_section[section]["implemented"] += 1

        impl = sum(1 for c in controls if get_evaluator(c["cis_id"]))
        return {
            "benchmark": "CIS Google Cloud Platform Foundation v4.0.0",
            "total": len(controls),
            "implemented": impl,
            "coverage_pct": round(impl / len(controls) * 100, 1),
            "by_section": by_section,
        }
