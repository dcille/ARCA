"""AWS CIS Evaluator Engine — Orchestrates evaluation of all 62 CIS AWS v6.0 controls.

Usage:
    from aws_cis_evaluator_engine import AWSCISEvaluatorEngine

    engine = AWSCISEvaluatorEngine(credentials={"access_key_id": ..., "secret_access_key": ...})
    results = engine.evaluate_all()
"""

import logging
import time
from typing import Optional

import boto3

from .evaluators.base import AWSClientCache, EvalConfig, make_manual_result, safe_evaluate
from .evaluators import EVALUATOR_REGISTRY, get_evaluator

logger = logging.getLogger(__name__)


class AWSCISEvaluatorEngine:
    """Orchestrates CIS AWS benchmark evaluation across all 62 controls."""

    def __init__(self, credentials: dict, regions: Optional[list[str]] = None, services: Optional[list[str]] = None, scan_logger=None):
        self.credentials = credentials
        self.regions = regions or ["us-east-1"]
        self.services = services
        self._scan_logger = scan_logger
        self._clients: Optional[AWSClientCache] = None
        self._config: Optional[EvalConfig] = None
        self._cis_controls = None

    def _get_session(self) -> boto3.Session:
        return boto3.Session(
            aws_access_key_id=self.credentials.get("access_key_id"),
            aws_secret_access_key=self.credentials.get("secret_access_key"),
            aws_session_token=self.credentials.get("session_token"),
            region_name=self.regions[0],
        )

    def _get_clients(self) -> AWSClientCache:
        if not self._clients:
            self._clients = AWSClientCache(self._get_session(), self.regions)
        return self._clients

    def _get_config(self) -> EvalConfig:
        if not self._config:
            try:
                sts = self._get_session().client("sts")
                account_id = sts.get_caller_identity()["Account"]
            except Exception:
                account_id = "unknown"
            self._config = EvalConfig(account_id=account_id, regions=self.regions)
        return self._config

    def _get_cis_controls(self) -> list[dict]:
        if not self._cis_controls:
            from scanner.cis_controls.aws_cis_controls import AWS_CIS_CONTROLS
            self._cis_controls = AWS_CIS_CONTROLS
        return self._cis_controls

    _SECTION_SERVICE_MAP = {
        "2": "iam", "3": "storage", "4": "logging", "5": "monitoring", "6": "networking",
    }

    def _should_evaluate(self, cis_id: str) -> bool:
        if not self.services:
            return True
        section = cis_id.split(".")[0]
        return self._SECTION_SERVICE_MAP.get(section, "") in self.services

    def evaluate_all(self) -> list[dict]:
        controls = self._get_cis_controls()
        clients = self._get_clients()
        config = self._get_config()
        all_results, evaluated, manual = [], 0, 0
        slog = self._scan_logger

        start = time.monotonic()
        logger.info("Starting AWS CIS evaluation: %d controls, %d evaluators",
                     len(controls), len(EVALUATOR_REGISTRY))

        for ctrl in controls:
            cis_id = ctrl["cis_id"]
            if not self._should_evaluate(cis_id):
                continue

            evaluator = get_evaluator(cis_id)
            if evaluator:
                module_name = f"evaluator::aws_cis_{cis_id}"
                if slog:
                    slog.log_module_start(
                        module_name,
                        f"Evaluating CIS {cis_id}: {ctrl['title']}",
                    )
                results = safe_evaluate(evaluator, clients, config, cis_id,
                    f"aws_cis_{cis_id.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"])
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
                all_results.append(make_manual_result(cis_id,
                    f"aws_cis_{cis_id.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"],
                    config.account_id,
                    f"CIS classifies {cis_id} as {ctrl.get('assessment_type', 'manual')}. Evaluator not in registry."))
                manual += 1

        elapsed = time.monotonic() - start
        logger.info("AWS CIS evaluation complete: %d evaluated, %d manual in %.1fs. Total results: %d",
                     evaluated, manual, elapsed, len(all_results))
        return all_results

    def evaluate_section(self, section: str) -> list[dict]:
        controls = self._get_cis_controls()
        clients, config = self._get_clients(), self._get_config()
        results = []
        for ctrl in controls:
            cid = ctrl["cis_id"]
            if not cid.startswith(f"{section}."):
                continue
            ev = get_evaluator(cid)
            if ev:
                results.extend(safe_evaluate(ev, clients, config, cid,
                    f"aws_cis_{cid.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"]))
            else:
                results.append(make_manual_result(cid,
                    f"aws_cis_{cid.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"],
                    config.account_id, "No evaluator in registry."))
        return results

    def evaluate_single(self, cis_id: str) -> list[dict]:
        ctrl = next((c for c in self._get_cis_controls() if c["cis_id"] == cis_id), None)
        if not ctrl:
            return [{"error": f"CIS control {cis_id} not found"}]
        ev = get_evaluator(cis_id)
        if not ev:
            return [make_manual_result(cis_id, f"aws_cis_{cis_id.replace('.', '_')}",
                ctrl["title"], ctrl.get("service_area", "general"), ctrl["severity"],
                self._get_config().account_id, "No evaluator.")]
        return safe_evaluate(ev, self._get_clients(), self._get_config(), cis_id,
            f"aws_cis_{cis_id.replace('.', '_')}", ctrl["title"],
            ctrl.get("service_area", "general"), ctrl["severity"])

    def coverage_report(self) -> dict:
        controls = self._get_cis_controls()
        by_section = {}
        for c in controls:
            s = c["cis_id"].split(".")[0]
            by_section.setdefault(s, {"total": 0, "implemented": 0})
            by_section[s]["total"] += 1
            if get_evaluator(c["cis_id"]):
                by_section[s]["implemented"] += 1
        impl = sum(1 for c in controls if get_evaluator(c["cis_id"]))
        return {
            "benchmark": "CIS Amazon Web Services Foundations v6.0.0",
            "total": len(controls), "implemented": impl,
            "coverage_pct": round(impl / len(controls) * 100, 1),
            "by_section": by_section,
        }
