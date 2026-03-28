"""CIS Snowflake v1.0.0 — Evaluator Engine.

Orchestrates 39 CIS controls via EVALUATOR_REGISTRY.
Replaces the adhoc checks in snowflake_scanner.py with CIS-mapped evaluators.

Usage:
    engine = SnowflakeCISEvaluatorEngine(
        account="xy12345.us-east-1",
        username="DARCA_SCANNER",
        password="...",
        warehouse="COMPUTE_WH",
    )
    results = engine.evaluate_all()
    report = engine.coverage_report()
"""

from __future__ import annotations
import logging
from typing import Optional

from .evaluators import EVALUATOR_REGISTRY
from .evaluators.base import (
    CheckResult,
    SnowflakeClientCache,
    safe_evaluate,
)

logger = logging.getLogger(__name__)

# Control metadata (CIS Snowflake v1.0.0)
CIS_CONTROL_META: dict[str, dict] = {
    "1.1":  {"title": "SSO configured", "level": 1, "section": "1"},
    "1.2":  {"title": "SCIM integration configured", "level": 1, "section": "1"},
    "1.3":  {"title": "Password unset for SSO users", "level": 1, "section": "1"},
    "1.4":  {"title": "MFA for password-based users", "level": 1, "section": "1"},
    "1.5":  {"title": "Password min length >= 14", "level": 1, "section": "1"},
    "1.6":  {"title": "Service accounts use key pair auth", "level": 1, "section": "1"},
    "1.7":  {"title": "Key pair rotation every 180 days", "level": 1, "section": "1"},
    "1.8":  {"title": "Inactive users disabled (90 days)", "level": 1, "section": "1"},
    "1.9":  {"title": "Session timeout <= 15 min for admins", "level": 1, "section": "1"},
    "1.10": {"title": "Limit ACCOUNTADMIN/SECURITYADMIN count", "level": 1, "section": "1"},
    "1.11": {"title": "ACCOUNTADMIN users have email", "level": 1, "section": "1"},
    "1.12": {"title": "No admin as default role", "level": 1, "section": "1"},
    "1.13": {"title": "Admin roles not granted to custom roles", "level": 1, "section": "1"},
    "1.14": {"title": "Tasks not owned by admin roles", "level": 1, "section": "1"},
    "1.15": {"title": "Tasks don't run with admin privileges", "level": 1, "section": "1"},
    "1.16": {"title": "Procedures not owned by admin roles", "level": 1, "section": "1"},
    "1.17": {"title": "Procedures don't run with admin privileges", "level": 1, "section": "1"},
    "2.1":  {"title": "Monitor admin role grants", "level": 1, "section": "2"},
    "2.2":  {"title": "Monitor MANAGE GRANTS", "level": 1, "section": "2"},
    "2.3":  {"title": "Monitor SSO password logins", "level": 1, "section": "2"},
    "2.4":  {"title": "Monitor password login without MFA", "level": 1, "section": "2"},
    "2.5":  {"title": "Monitor security integration changes", "level": 1, "section": "2"},
    "2.6":  {"title": "Monitor network policy changes", "level": 1, "section": "2"},
    "2.7":  {"title": "Monitor SCIM token creation", "level": 1, "section": "2"},
    "2.8":  {"title": "Monitor share exposures", "level": 1, "section": "2"},
    "2.9":  {"title": "Monitor unsupported connectors", "level": 1, "section": "2"},
    "3.1":  {"title": "Account-level network policy", "level": 2, "section": "3"},
    "3.2":  {"title": "User-level network policies for svc accounts", "level": 1, "section": "3"},
    "4.1":  {"title": "Yearly rekeying enabled", "level": 1, "section": "4"},
    "4.2":  {"title": "AES 256-bit for internal stages", "level": 1, "section": "4"},
    "4.3":  {"title": "DATA_RETENTION >= 90 for critical data", "level": 1, "section": "4"},
    "4.4":  {"title": "MIN_DATA_RETENTION >= 7", "level": 1, "section": "4"},
    "4.5":  {"title": "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION", "level": 1, "section": "4"},
    "4.6":  {"title": "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION", "level": 1, "section": "4"},
    "4.7":  {"title": "External stages have storage integrations", "level": 1, "section": "4"},
    "4.8":  {"title": "PREVENT_UNLOAD_TO_INLINE_URL", "level": 1, "section": "4"},
    "4.9":  {"title": "Tri-Secret Secure enabled", "level": 1, "section": "4"},
    "4.10": {"title": "Data masking for sensitive data", "level": 1, "section": "4"},
    "4.11": {"title": "Row-access policies for sensitive data", "level": 1, "section": "4"},
}


class SnowflakeCISEvaluatorEngine:
    """Orchestrates CIS Snowflake v1.0.0 evaluations."""

    BENCHMARK = "CIS Snowflake Foundations Benchmark v1.0.0"

    def __init__(
        self,
        account: str,
        username: str,
        password: str | None = None,
        private_key: bytes | None = None,
        warehouse: str | None = None,
        role: str | None = None,
    ):
        self._sf = SnowflakeClientCache(
            account=account,
            username=username,
            password=password,
            private_key=private_key,
            warehouse=warehouse,
            role=role,
        )
        self._scan_logger = None

    # ── evaluate_all ──────────────────────────────────────────────────
    def evaluate_all(self) -> list[CheckResult]:
        """Run all 39 CIS controls."""
        slog = self._scan_logger
        results: list[CheckResult] = []
        for cis_id, fn in sorted(EVALUATOR_REGISTRY.items(),
                                  key=lambda x: [int(p) for p in x[0].split(".")]):
            module_name = f"evaluator::sf_cis_{cis_id}"
            if slog:
                slog.log_module_start(module_name, f"Evaluating CIS {cis_id}")
            ctrl_results = safe_evaluate(fn, self._sf)
            results.extend(ctrl_results)
            if slog:
                has_error = any(r.status == "ERROR" for r in ctrl_results)
                slog.log_module_end(
                    module_name,
                    result_count=len(ctrl_results),
                    status="error" if has_error else "success",
                )
        return results

    # ── evaluate_section ──────────────────────────────────────────────
    def evaluate_section(self, section: str) -> list[CheckResult]:
        """Run controls for a specific section (e.g. '1', '2', '3', '4')."""
        results: list[CheckResult] = []
        for cis_id, fn in sorted(EVALUATOR_REGISTRY.items(),
                                  key=lambda x: [int(p) for p in x[0].split(".")]):
            if cis_id.split(".")[0] == section:
                results.extend(safe_evaluate(fn, self._sf))
        return results

    # ── evaluate_single ───────────────────────────────────────────────
    def evaluate_single(self, cis_id: str) -> list[CheckResult]:
        """Run a single CIS control by ID."""
        fn = EVALUATOR_REGISTRY.get(cis_id)
        if fn is None:
            raise ValueError(f"Unknown CIS control: {cis_id}")
        return safe_evaluate(fn, self._sf)

    # ── coverage_report ───────────────────────────────────────────────
    def coverage_report(self) -> dict:
        """Return coverage statistics."""
        total = len(CIS_CONTROL_META)
        in_registry = len(EVALUATOR_REGISTRY)

        # Count by section
        sections = {}
        for cis_id, meta in CIS_CONTROL_META.items():
            sec = meta["section"]
            sections.setdefault(sec, {"total": 0, "automated": 0, "manual": 0})
            sections[sec]["total"] += 1

        # Determine automated vs manual by running a dry check on status
        # (we can't run without a connection, so use supplement presence)
        from .evaluators.supplements import SUPPLEMENT_EVALUATORS
        from .evaluators.section_1_iam import SECTION_1_EVALUATORS
        from .evaluators.section_3_4_net_data import SECTION_4_EVALUATORS

        manual_ids = {"1.3", "4.3", "4.9"}  # Truly manual (no supplement)
        for cis_id, meta in CIS_CONTROL_META.items():
            sec = meta["section"]
            if cis_id in manual_ids:
                sections[sec]["manual"] += 1
            else:
                sections[sec]["automated"] += 1

        automated = total - len(manual_ids)
        return {
            "benchmark": self.BENCHMARK,
            "total_controls": total,
            "automated": automated,
            "manual": len(manual_ids),
            "automation_pct": round(automated / total * 100, 1),
            "sections": sections,
        }

    # ── cleanup ───────────────────────────────────────────────────────
    def close(self):
        self._sf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
