"""Alibaba Cloud CIS Evaluator Engine — Orchestrates evaluation of all 85 CIS Alibaba v2.0 controls.

Usage:
    from scanner.providers.alibaba.alibaba_cis_evaluator_engine import AlibabaCISEvaluatorEngine

    engine = AlibabaCISEvaluatorEngine(
        access_key_id="LTAI...",
        access_key_secret="...",
        regions=["cn-hangzhou", "cn-shanghai"],
    )

    # Full scan
    results = engine.evaluate_all()

    # Single section
    iam_results = engine.evaluate_section("1")

    # Single control
    mfa_results = engine.evaluate_single("1.4")

    # Coverage report
    report = engine.coverage_report()
"""

import logging
import time
from typing import Optional

from .evaluators.base import AlibabaClientCache, EvalConfig, make_manual_result, safe_evaluate
from .evaluators import EVALUATOR_REGISTRY, get_evaluator

logger = logging.getLogger(__name__)


class AlibabaCISEvaluatorEngine:
    """Orchestrates CIS Alibaba Cloud benchmark evaluation across all 85 controls."""

    def __init__(
        self,
        access_key_id: str = "",
        access_key_secret: str = "",
        credentials: Optional[dict] = None,
        regions: Optional[list[str]] = None,
        services: Optional[list[str]] = None,
        scan_logger=None,
    ):
        if credentials:
            self._access_key_id = credentials.get("access_key_id", access_key_id)
            self._access_key_secret = credentials.get("secret_access_key", access_key_secret)
        else:
            self._access_key_id = access_key_id
            self._access_key_secret = access_key_secret

        self.regions = regions or ["cn-hangzhou"]
        self.services = services
        self._scan_logger = scan_logger
        self._clients: Optional[AlibabaClientCache] = None
        self._config: Optional[EvalConfig] = None
        self._cis_controls = None

    def _get_clients(self) -> AlibabaClientCache:
        if not self._clients:
            self._clients = AlibabaClientCache(
                self._access_key_id, self._access_key_secret, self.regions,
            )
        return self._clients

    def _get_config(self) -> EvalConfig:
        if not self._config:
            account_id = "unknown"
            try:
                from alibabacloud_ram20150501 import models as ram_models
                resp = self._get_clients().ram.get_user(ram_models.GetUserRequest())
                account_id = getattr(resp.body.user, "user_id", "unknown") or "unknown"
            except Exception:
                pass
            self._config = EvalConfig(account_id=account_id, regions=self.regions)
        return self._config

    def _get_cis_controls(self) -> list[dict]:
        if not self._cis_controls:
            from scanner.cis_controls.alibaba_cis_controls import ALIBABA_CIS_CONTROLS
            self._cis_controls = ALIBABA_CIS_CONTROLS
        return self._cis_controls

    _SECTION_SERVICE_MAP = {
        "1": "iam",
        "2": "logging",
        "3": "networking",
        "4": "compute",
        "5": "storage",
        "6": "database",
        "7": "kubernetes",
        "8": "security",
    }

    def _should_evaluate(self, cis_id: str) -> bool:
        if not self.services:
            return True
        section = cis_id.split(".")[0]
        return self._SECTION_SERVICE_MAP.get(section, "") in self.services

    def evaluate_all(self) -> list[dict]:
        """Evaluate all 85 CIS Alibaba Cloud v2.0 controls."""
        controls = self._get_cis_controls()
        clients = self._get_clients()
        config = self._get_config()
        all_results, evaluated, manual = [], 0, 0
        slog = self._scan_logger

        start = time.monotonic()
        logger.info(
            "Starting Alibaba CIS evaluation: %d controls, %d evaluators",
            len(controls), len(EVALUATOR_REGISTRY),
        )

        for ctrl in controls:
            cis_id = ctrl["cis_id"]
            if not self._should_evaluate(cis_id):
                continue

            evaluator = get_evaluator(cis_id)
            if evaluator:
                module_name = f"evaluator::ali_cis_{cis_id}"
                if slog:
                    slog.log_module_start(
                        module_name,
                        f"Evaluating CIS {cis_id}: {ctrl['title']}",
                    )
                results = safe_evaluate(
                    evaluator, clients, config, cis_id,
                    f"ali_cis_{cis_id.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"],
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
                    f"ali_cis_{cis_id.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"],
                    config.account_id,
                    f"CIS classifies {cis_id} as {ctrl.get('assessment_type', 'manual')}. "
                    f"Evaluator not in registry.",
                ))
                manual += 1

        elapsed = time.monotonic() - start
        logger.info(
            "Alibaba CIS evaluation complete: %d evaluated, %d manual in %.1fs. Total results: %d",
            evaluated, manual, elapsed, len(all_results),
        )
        return all_results

    def evaluate_section(self, section: str) -> list[dict]:
        """Evaluate all controls in a specific CIS section."""
        controls = self._get_cis_controls()
        clients, config = self._get_clients(), self._get_config()
        results = []
        for ctrl in controls:
            cid = ctrl["cis_id"]
            if not cid.startswith(f"{section}."):
                continue
            ev = get_evaluator(cid)
            if ev:
                results.extend(safe_evaluate(
                    ev, clients, config, cid,
                    f"ali_cis_{cid.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"],
                ))
            else:
                results.append(make_manual_result(
                    cid, f"ali_cis_{cid.replace('.', '_')}", ctrl["title"],
                    ctrl.get("service_area", "general"), ctrl["severity"],
                    config.account_id, "No evaluator in registry.",
                ))
        return results

    def evaluate_single(self, cis_id: str) -> list[dict]:
        """Evaluate a single CIS control by ID."""
        ctrl = next(
            (c for c in self._get_cis_controls() if c["cis_id"] == cis_id), None,
        )
        if not ctrl:
            return [{"error": f"CIS control {cis_id} not found"}]
        ev = get_evaluator(cis_id)
        if not ev:
            return [make_manual_result(
                cis_id, f"ali_cis_{cis_id.replace('.', '_')}",
                ctrl["title"], ctrl.get("service_area", "general"), ctrl["severity"],
                self._get_config().account_id, "No evaluator.",
            )]
        return safe_evaluate(
            ev, self._get_clients(), self._get_config(), cis_id,
            f"ali_cis_{cis_id.replace('.', '_')}", ctrl["title"],
            ctrl.get("service_area", "general"), ctrl["severity"],
        )

    def coverage_report(self) -> dict:
        """Generate a coverage report for implemented evaluators."""
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
            "benchmark": "CIS Alibaba Cloud Foundation Benchmark v2.0.0",
            "total": len(controls),
            "implemented": impl,
            "coverage_pct": round(impl / len(controls) * 100, 1),
            "by_section": by_section,
        }
