"""DSPM API Router — orchestrates all Data Security Posture Management modules.

Provides :class:`DSPMOrchestrator`, a single entry-point that initialises
every DSPM sub-module, runs individual or full scans, and consolidates
findings into risk-scored reports.

Usage::

    orchestrator = DSPMOrchestrator()
    report = orchestrator.run_full_scan({
        "provider": "aws",
        "credentials": {...},
        "targets": [{"store_type": "s3", "resource_id": "my-bucket"}],
    })
    print(orchestrator.get_summary())
"""

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from scanner.dspm.pii_scanner import PIIScanner, PIIScanResult
from scanner.dspm.content_sampler import ContentSampler, SampleConfig, ContentSampleResult
from scanner.dspm.data_classifier import DataClassifier, ClassificationResult
from scanner.dspm.permission_analyzer import PermissionAnalyzer, DataStoreAccessReport
from scanner.dspm.shadow_detector import ShadowDataDetector, ShadowDataReport
from scanner.dspm.native_integrations import NativeIntegrations, NativeServiceStatus, NativeScanResult
from scanner.dspm.data_store_checks import (
    DSPMCheckResult,
    DSPM_CHECKS,
    get_dspm_checks_for_provider,
    get_dspm_data_stores,
    get_all_dspm_check_ids,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Severity / risk constants
# ═══════════════════════════════════════════════════════════════════════════

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "informational": 0.5,
}

_RISK_THRESHOLDS: list[tuple[float, str]] = [
    (80.0, "critical"),
    (60.0, "high"),
    (35.0, "medium"),
    (0.0, "low"),
]


def _risk_label(score: float) -> str:
    """Map a numeric risk score (0-100) to a human-readable label."""
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


# ═══════════════════════════════════════════════════════════════════════════
# Result dataclasses
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ModuleFinding:
    """A single finding produced by any DSPM sub-module."""

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    module: str = ""
    title: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    description: str = ""
    resource_id: str = ""
    resource_name: str = ""
    provider: str = ""
    category: str = ""
    remediation: str = ""
    evidence: dict = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class ModuleResult:
    """Aggregated output of a single DSPM sub-module execution."""

    module_name: str
    status: str = "pending"  # pending | running | success | error | skipped
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    findings: list[ModuleFinding] = field(default_factory=list)
    finding_count: int = 0
    error_message: str = ""
    raw_result: Any = None


@dataclass
class DSPMReport:
    """Consolidated DSPM report covering all sub-modules."""

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    provider: str = ""
    total_findings: int = 0
    total_modules_run: int = 0
    total_modules_failed: int = 0
    overall_risk_score: float = 0.0
    overall_risk_label: str = "low"
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_module: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    module_results: dict[str, ModuleResult] = field(default_factory=dict)
    prioritised_findings: list[ModuleFinding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    fingerprint: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# DSPMOrchestrator
# ═══════════════════════════════════════════════════════════════════════════


class DSPMOrchestrator:
    """Central orchestrator for all DSPM sub-modules.

    Initialises each sub-module once and exposes individual scan methods as
    well as :meth:`run_full_scan` which runs every analysis in sequence,
    merges findings, scores risk, and produces a :class:`DSPMReport`.

    Args:
        pii_custom_patterns: Optional custom PII patterns forwarded to
            :class:`PIIScanner`.
        sample_config: Optional :class:`SampleConfig` for content sampling.
    """

    _MODULE_NAMES = (
        "pii_scanner",
        "permission_analyzer",
        "shadow_detector",
        "data_classifier",
        "content_sampler",
        "native_integrations",
        "data_store_checks",
    )

    def __init__(
        self,
        pii_custom_patterns: Optional[list[dict]] = None,
        sample_config: Optional[SampleConfig] = None,
    ) -> None:
        self._pii_scanner = PIIScanner(custom_patterns=pii_custom_patterns)
        self._content_sampler = ContentSampler(config=sample_config)
        self._data_classifier = DataClassifier(pii_scanner=self._pii_scanner)
        self._permission_analyzer = PermissionAnalyzer()
        self._shadow_detector = ShadowDataDetector()
        self._native_integrations = NativeIntegrations()

        self._report: Optional[DSPMReport] = None
        self._config: dict = {}
        logger.info("DSPMOrchestrator initialised with %d modules", len(self._MODULE_NAMES))

    # ──────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _run_module(
        self,
        module_name: str,
        callable_fn: Any,
        *args: Any,
        **kwargs: Any,
    ) -> ModuleResult:
        """Execute a module callable, capture timing and errors."""
        result = ModuleResult(module_name=module_name, status="running")
        result.started_at = self._now_iso()
        t0 = time.monotonic()

        try:
            raw = callable_fn(*args, **kwargs)
            result.raw_result = raw
            result.status = "success"
        except Exception as exc:
            logger.exception("Module %s failed: %s", module_name, exc)
            result.status = "error"
            result.error_message = f"{type(exc).__name__}: {exc}"

        result.duration_seconds = round(time.monotonic() - t0, 4)
        result.finished_at = self._now_iso()
        return result

    def _score_finding(self, finding: ModuleFinding) -> float:
        """Compute a 0-100 risk score for a single finding."""
        base = _SEVERITY_WEIGHT.get(finding.severity, 4.0) * 10.0
        # Boost score for high-confidence findings
        if finding.confidence == "high":
            base = min(100.0, base * 1.15)
        elif finding.confidence == "low":
            base *= 0.7
        return round(min(100.0, base), 2)

    def _compute_overall_risk(self, findings: list[ModuleFinding]) -> float:
        """Derive the overall risk score from all findings.

        Uses a weighted approach: the score is the maximum individual finding
        score, boosted by the volume of additional critical/high findings
        (diminishing returns).
        """
        if not findings:
            return 0.0

        scores = sorted([f.risk_score for f in findings], reverse=True)
        peak = scores[0]

        # Add diminishing contribution from remaining high-severity findings
        bonus = 0.0
        for i, score in enumerate(scores[1:], start=1):
            if score < 35.0:
                break
            bonus += score / (2.0 * i + 1.0)

        return round(min(100.0, peak + bonus), 2)

    def _build_fingerprint(self, report: DSPMReport) -> str:
        """Generate a deterministic fingerprint for the report."""
        parts = []
        for name in sorted(report.module_results):
            mr = report.module_results[name]
            parts.append(f"{name}:{mr.finding_count}:{mr.status}")
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        return digest

    # ──────────────────────────────────────────────────────────────────
    # PII scanning
    # ──────────────────────────────────────────────────────────────────

    def scan_pii(
        self,
        text: str = "",
        file_content: Optional[bytes] = None,
        filename: str = "",
        structured_data: Optional[list[dict]] = None,
    ) -> ModuleResult:
        """Run PII detection on the supplied data.

        Exactly one of *text*, *file_content*, or *structured_data* should
        be provided.  Results are converted to :class:`ModuleFinding` entries.

        Returns:
            :class:`ModuleResult` containing PII findings.
        """
        def _do_scan() -> list[PIIScanResult]:
            if file_content is not None:
                return self._pii_scanner.scan_file_content(file_content, filename=filename)
            if structured_data is not None:
                return self._pii_scanner.scan_structured_data(structured_data)
            return self._pii_scanner.scan_text(text)

        result = self._run_module("pii_scanner", _do_scan)

        if result.status == "success" and result.raw_result:
            pii_results: list[PIIScanResult] = result.raw_result
            for pii in pii_results:
                finding = ModuleFinding(
                    module="pii_scanner",
                    title=f"PII detected: {pii.pattern_name}",
                    severity=pii.severity,
                    confidence=pii.confidence,
                    description=(
                        f"{pii.match_count} instance(s) of {pii.pattern_name} "
                        f"({pii.category}) detected"
                    ),
                    category=pii.category,
                    evidence={
                        "pattern_id": pii.pattern_id,
                        "match_count": pii.match_count,
                        "sample_matches": pii.sample_matches,
                        "locations": pii.locations[:20],
                    },
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)
            result.finding_count = len(result.findings)

        logger.info("scan_pii: %d findings", result.finding_count)
        return result

    # ──────────────────────────────────────────────────────────────────
    # Permission analysis
    # ──────────────────────────────────────────────────────────────────

    def analyze_permissions(
        self,
        store_type: str,
        resource_id: str,
        **kwargs: Any,
    ) -> ModuleResult:
        """Analyse effective permissions on a cloud data store.

        Returns:
            :class:`ModuleResult` with permission-related findings.
        """
        result = self._run_module(
            "permission_analyzer",
            self._permission_analyzer.analyze_store,
            store_type,
            resource_id,
            **kwargs,
        )

        if result.status == "success" and result.raw_result:
            report: DataStoreAccessReport = result.raw_result
            # Public access finding
            if report.public_access:
                finding = ModuleFinding(
                    module="permission_analyzer",
                    title=f"Public access enabled on {report.resource_name}",
                    severity="critical",
                    confidence="high",
                    description=(
                        f"Data store {report.resource_name} ({report.store_type}) "
                        f"is publicly accessible"
                    ),
                    resource_id=report.resource_id,
                    resource_name=report.resource_name,
                    provider=report.provider,
                    category="access",
                    remediation="Disable public access and restrict to private networks.",
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)

            # Cross-account access
            if report.cross_account_principals > 0:
                finding = ModuleFinding(
                    module="permission_analyzer",
                    title=f"Cross-account access on {report.resource_name}",
                    severity="medium",
                    confidence="high",
                    description=(
                        f"{report.cross_account_principals} cross-account "
                        f"principal(s) have access to {report.resource_name}"
                    ),
                    resource_id=report.resource_id,
                    resource_name=report.resource_name,
                    provider=report.provider,
                    category="access",
                    remediation="Review and restrict cross-account access policies.",
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)

            # Excessive admin principals
            if report.admin_principals > 3:
                finding = ModuleFinding(
                    module="permission_analyzer",
                    title=f"Excessive admin principals on {report.resource_name}",
                    severity="high",
                    confidence="high",
                    description=(
                        f"{report.admin_principals} principals have admin-level "
                        f"access to {report.resource_name}"
                    ),
                    resource_id=report.resource_id,
                    resource_name=report.resource_name,
                    provider=report.provider,
                    category="access",
                    remediation="Apply least-privilege; reduce admin-level access.",
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)

            # Risk factors from the report itself
            for rf in report.risk_factors:
                finding = ModuleFinding(
                    module="permission_analyzer",
                    title=f"Permission risk: {rf}",
                    severity=report.risk_level,
                    confidence="medium",
                    description=rf,
                    resource_id=report.resource_id,
                    resource_name=report.resource_name,
                    provider=report.provider,
                    category="access",
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)

            result.finding_count = len(result.findings)

        logger.info("analyze_permissions: %d findings", result.finding_count)
        return result

    # ──────────────────────────────────────────────────────────────────
    # Shadow data detection
    # ──────────────────────────────────────────────────────────────────

    def detect_shadow_data(
        self,
        provider: str,
        credentials: Optional[dict] = None,
        **kwargs: Any,
    ) -> ModuleResult:
        """Detect shadow copies of sensitive data in unmanaged locations.

        Returns:
            :class:`ModuleResult` with shadow-data findings.
        """
        result = self._run_module(
            "shadow_detector",
            self._shadow_detector.detect_shadow_data,
            provider,
            credentials,
            **kwargs,
        )

        if result.status == "success" and result.raw_result:
            shadow_report: ShadowDataReport = result.raw_result
            for sf in shadow_report.findings:
                finding = ModuleFinding(
                    module="shadow_detector",
                    title=f"Shadow data: {sf.finding_type}",
                    severity=sf.severity,
                    confidence="medium",
                    description=sf.description,
                    resource_id=sf.resource_id,
                    resource_name=sf.resource_name,
                    provider=sf.provider,
                    category="shadow_data",
                    remediation=sf.remediation,
                    evidence=sf.evidence,
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)
            result.finding_count = len(result.findings)

        logger.info("detect_shadow_data: %d findings", result.finding_count)
        return result

    # ──────────────────────────────────────────────────────────────────
    # Data classification
    # ──────────────────────────────────────────────────────────────────

    def classify_data(
        self,
        pii_results: Optional[list] = None,
        resource_id: str = "",
        resource_name: str = "",
        provider: str = "",
        current_tag: Optional[str] = None,
    ) -> ModuleResult:
        """Classify a resource based on PII scan results and existing tags.

        Returns:
            :class:`ModuleResult` with classification findings (e.g. misclassification).
        """
        pii_list = pii_results if pii_results is not None else []

        result = self._run_module(
            "data_classifier",
            self._data_classifier.classify_from_pii_results,
            pii_list,
            resource_id,
            resource_name,
            provider,
            current_tag,
        )

        if result.status == "success" and result.raw_result:
            cr: ClassificationResult = result.raw_result
            if cr.is_misclassified:
                finding = ModuleFinding(
                    module="data_classifier",
                    title=f"Misclassified resource: {cr.resource_name}",
                    severity="high",
                    confidence=f"{cr.confidence:.0%}",
                    description=(
                        f"Resource tagged as '{cr.current_tag_classification}' "
                        f"but content analysis indicates '{cr.content_classification}'. "
                        f"{cr.recommendation}"
                    ),
                    resource_id=cr.resource_id,
                    resource_name=cr.resource_name,
                    provider=cr.provider,
                    category="classification",
                    remediation=cr.recommendation,
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)

            if cr.has_pci_data or cr.has_health_data:
                label = "PCI" if cr.has_pci_data else "health"
                finding = ModuleFinding(
                    module="data_classifier",
                    title=f"Regulated data ({label}) in {cr.resource_name}",
                    severity="critical",
                    confidence=f"{cr.confidence:.0%}",
                    description=(
                        f"Resource {cr.resource_name} contains {label} data. "
                        f"Classification: {cr.content_classification}"
                    ),
                    resource_id=cr.resource_id,
                    resource_name=cr.resource_name,
                    provider=cr.provider,
                    category="classification",
                    remediation=(
                        f"Ensure {label} compliance controls are applied."
                    ),
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)

            result.finding_count = len(result.findings)

        logger.info("classify_data: %d findings", result.finding_count)
        return result

    # ──────────────────────────────────────────────────────────────────
    # Content sampling
    # ──────────────────────────────────────────────────────────────────

    def sample_content(
        self,
        store_type: str,
        **kwargs: Any,
    ) -> ModuleResult:
        """Sample content from a cloud data store for analysis.

        Returns:
            :class:`ModuleResult` wrapping the :class:`ContentSampleResult`.
        """
        result = self._run_module(
            "content_sampler",
            self._content_sampler.sample_store,
            store_type,
            **kwargs,
        )

        if result.status == "success" and result.raw_result:
            csr: ContentSampleResult = result.raw_result
            if csr.errors:
                for err in csr.errors:
                    finding = ModuleFinding(
                        module="content_sampler",
                        title="Content sampling error",
                        severity="low",
                        confidence="high",
                        description=err,
                        category="sampling",
                    )
                    finding.risk_score = self._score_finding(finding)
                    result.findings.append(finding)
            result.finding_count = len(result.findings)

        logger.info("sample_content: %d findings", result.finding_count)
        return result

    # ──────────────────────────────────────────────────────────────────
    # Native integrations
    # ──────────────────────────────────────────────────────────────────

    def check_integrations(
        self,
        provider: str,
        credentials: Optional[dict] = None,
        **kwargs: Any,
    ) -> ModuleResult:
        """Check status of native cloud data-security services.

        Returns:
            :class:`ModuleResult` with findings about disabled services.
        """
        creds = credentials if credentials is not None else {}

        result = self._run_module(
            "native_integrations",
            self._native_integrations.get_native_service_status,
            provider,
            creds,
            **kwargs,
        )

        if result.status == "success" and result.raw_result:
            status: NativeServiceStatus = result.raw_result
            if not status.enabled:
                finding = ModuleFinding(
                    module="native_integrations",
                    title=f"Native service disabled: {status.service_name}",
                    severity="medium",
                    confidence="high",
                    description=(
                        f"{status.service_name} is not enabled for provider "
                        f"'{status.provider}'. Enable it for enhanced data "
                        f"security scanning."
                    ),
                    provider=status.provider,
                    category="integration",
                    remediation=(
                        f"Enable {status.service_name} for automated "
                        f"sensitive-data discovery."
                    ),
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)
            result.finding_count = len(result.findings)

        logger.info("check_integrations: %d findings", result.finding_count)
        return result

    # ──────────────────────────────────────────────────────────────────
    # Data store checks
    # ──────────────────────────────────────────────────────────────────

    def run_data_store_checks(
        self,
        provider: str,
    ) -> ModuleResult:
        """Retrieve applicable data-store security checks for *provider*.

        This does not perform live cloud API calls; it returns the set of
        checks that *should* be evaluated, each mapped to a finding so
        downstream tooling can track coverage.

        Returns:
            :class:`ModuleResult` listing applicable checks.
        """
        def _get_checks() -> list[dict]:
            return get_dspm_checks_for_provider(provider)

        result = self._run_module("data_store_checks", _get_checks)

        if result.status == "success" and result.raw_result:
            checks: list[dict] = result.raw_result
            for check in checks:
                finding = ModuleFinding(
                    module="data_store_checks",
                    title=check.get("title", check.get("check_id", "")),
                    severity=check.get("severity", "medium"),
                    confidence="high",
                    description=check.get("description", ""),
                    category=check.get("category", ""),
                    remediation=check.get("remediation", ""),
                    provider=provider,
                    evidence={"check_id": check.get("check_id", "")},
                )
                finding.risk_score = self._score_finding(finding)
                result.findings.append(finding)
            result.finding_count = len(result.findings)

        logger.info("run_data_store_checks: %d checks for %s", result.finding_count, provider)
        return result

    # ══════════════════════════════════════════════════════════════════
    # Full scan
    # ══════════════════════════════════════════════════════════════════

    def run_full_scan(self, config: dict) -> DSPMReport:
        """Execute all DSPM analyses and produce a consolidated report.

        *config* is a dict with the following keys:

        - ``provider`` (str): Cloud provider — ``aws``, ``azure``, ``gcp``.
        - ``credentials`` (dict, optional): Provider credentials.
        - ``targets`` (list[dict], optional): Resources to scan. Each dict
          should contain ``store_type`` and ``resource_id``, plus any
          extra kwargs required by the specific sub-module.
        - ``text`` (str, optional): Raw text to scan for PII.
        - ``pii_types`` (list[str], optional): PII types for classification.
        - ``skip_modules`` (list[str], optional): Module names to skip.

        Returns:
            :class:`DSPMReport` with merged, risk-scored, prioritised findings.
        """
        self._config = dict(config)
        scan_start = time.monotonic()

        provider: str = config.get("provider", "")
        credentials: Optional[dict] = config.get("credentials")
        targets: list[dict] = config.get("targets", [])
        skip: set[str] = set(config.get("skip_modules", []))

        report = DSPMReport(provider=provider)
        all_findings: list[ModuleFinding] = []

        logger.info(
            "Starting full DSPM scan: provider=%s, targets=%d, skip=%s",
            provider, len(targets), skip or "none",
        )

        # 1. Content sampling + PII scanning + Data classification pipeline
        # These three modules are chained: content_sampler produces text,
        # pii_scanner detects PII in that text, data_classifier classifies
        # resources based on PII results.
        run_content_pipeline = (
            "content_sampler" not in skip
            and "pii_scanner" not in skip
        )

        if run_content_pipeline:
            sampler_findings: list[ModuleFinding] = []
            pii_findings: list[ModuleFinding] = []
            classifier_findings: list[ModuleFinding] = []

            # Per-target content pipeline
            per_target_pii_types: dict[str, list[str]] = {}

            for target in targets:
                st = target.get("store_type", "")
                target_kwargs = {
                    k: v for k, v in target.items() if k != "store_type"
                }
                if credentials:
                    target_kwargs.setdefault("credentials", credentials)

                # Step 1: Sample content from the data store
                sample_mr = self.sample_content(store_type=st, **target_kwargs)
                sampler_findings.extend(sample_mr.findings)

                # Step 2: If content was sampled, run PII scanner on it
                if sample_mr.status == "success" and sample_mr.raw_result:
                    csr: ContentSampleResult = sample_mr.raw_result
                    target_pii_types: list[str] = []
                    for obj in csr.sampled_objects:
                        if obj.content:
                            pii_mr = self.scan_pii(
                                file_content=obj.content,
                                filename=obj.object_key,
                            )
                            pii_findings.extend(pii_mr.findings)
                            target_pii_types.extend(
                                f.evidence.get("pattern_id", "")
                                for f in pii_mr.findings
                                if f.evidence
                            )

                    rid = target.get("resource_id", "")
                    if target_pii_types:
                        per_target_pii_types[rid] = target_pii_types

                    # Step 3: Classify resource based on PII found
                    if "data_classifier" not in skip:
                        cls_mr = self.classify_data(
                            pii_results=target_pii_types,
                            resource_id=rid,
                            resource_name=target.get("resource_name", rid),
                            provider=provider,
                            current_tag=target.get("current_tag"),
                        )
                        classifier_findings.extend(cls_mr.findings)

            combined_sampler = ModuleResult(module_name="content_sampler", status="success")
            combined_sampler.findings = sampler_findings
            combined_sampler.finding_count = len(sampler_findings)
            report.module_results["content_sampler"] = combined_sampler
            all_findings.extend(sampler_findings)

            combined_pii = ModuleResult(module_name="pii_scanner", status="success")
            combined_pii.findings = pii_findings
            combined_pii.finding_count = len(pii_findings)
            report.module_results["pii_scanner"] = combined_pii
            all_findings.extend(pii_findings)

            if "data_classifier" not in skip:
                combined_cls = ModuleResult(module_name="data_classifier", status="success")
                combined_cls.findings = classifier_findings
                combined_cls.finding_count = len(classifier_findings)
                report.module_results["data_classifier"] = combined_cls
                all_findings.extend(classifier_findings)
            else:
                report.module_results["data_classifier"] = ModuleResult(
                    module_name="data_classifier", status="skipped"
                )
        else:
            # Modules run individually (or skipped)

            # PII scanning on raw text (standalone mode)
            if "pii_scanner" not in skip:
                text = config.get("text", "")
                if text:
                    mr = self.scan_pii(text=text)
                    report.module_results["pii_scanner"] = mr
                    all_findings.extend(mr.findings)
                else:
                    report.module_results["pii_scanner"] = ModuleResult(
                        module_name="pii_scanner", status="skipped"
                    )
            else:
                report.module_results["pii_scanner"] = ModuleResult(
                    module_name="pii_scanner", status="skipped"
                )

            report.module_results["content_sampler"] = ModuleResult(
                module_name="content_sampler", status="skipped"
            )

            # Data classification (standalone, without PII pipeline)
            if "data_classifier" not in skip:
                pii_types = config.get("pii_types", [])
                classifier_findings_standalone: list[ModuleFinding] = []
                for target in targets:
                    mr = self.classify_data(
                        pii_results=pii_types,
                        resource_id=target.get("resource_id", ""),
                        resource_name=target.get("resource_name", target.get("resource_id", "")),
                        provider=provider,
                        current_tag=target.get("current_tag"),
                    )
                    classifier_findings_standalone.extend(mr.findings)
                combined = ModuleResult(module_name="data_classifier", status="success")
                combined.findings = classifier_findings_standalone
                combined.finding_count = len(classifier_findings_standalone)
                report.module_results["data_classifier"] = combined
                all_findings.extend(classifier_findings_standalone)
            else:
                report.module_results["data_classifier"] = ModuleResult(
                    module_name="data_classifier", status="skipped"
                )

        # 4. Permission analysis (per target)
        if "permission_analyzer" not in skip:
            perm_findings: list[ModuleFinding] = []
            for target in targets:
                st = target.get("store_type", "")
                rid = target.get("resource_id", "")
                target_kwargs = {
                    k: v
                    for k, v in target.items()
                    if k not in ("store_type", "resource_id", "resource_name", "current_tag")
                }
                if credentials:
                    target_kwargs.setdefault("credentials", credentials)
                mr = self.analyze_permissions(store_type=st, resource_id=rid, **target_kwargs)
                perm_findings.extend(mr.findings)
            combined = ModuleResult(module_name="permission_analyzer", status="success")
            combined.findings = perm_findings
            combined.finding_count = len(perm_findings)
            report.module_results["permission_analyzer"] = combined
            all_findings.extend(perm_findings)
        else:
            report.module_results["permission_analyzer"] = ModuleResult(
                module_name="permission_analyzer", status="skipped"
            )

        # 5. Shadow data detection
        if "shadow_detector" not in skip and provider:
            mr = self.detect_shadow_data(provider=provider, credentials=credentials)
            report.module_results["shadow_detector"] = mr
            all_findings.extend(mr.findings)
        else:
            report.module_results["shadow_detector"] = ModuleResult(
                module_name="shadow_detector", status="skipped"
            )

        # 6. Native integrations
        if "native_integrations" not in skip and provider:
            mr = self.check_integrations(provider=provider, credentials=credentials)
            report.module_results["native_integrations"] = mr
            all_findings.extend(mr.findings)
        else:
            report.module_results["native_integrations"] = ModuleResult(
                module_name="native_integrations", status="skipped"
            )

        # 7. Data store checks
        if "data_store_checks" not in skip and provider:
            mr = self.run_data_store_checks(provider=provider)
            report.module_results["data_store_checks"] = mr
            all_findings.extend(mr.findings)
        else:
            report.module_results["data_store_checks"] = ModuleResult(
                module_name="data_store_checks", status="skipped"
            )

        # ── Aggregate findings ────────────────────────────────────────
        report.total_findings = len(all_findings)
        report.total_modules_run = sum(
            1 for mr in report.module_results.values() if mr.status not in ("skipped", "pending")
        )
        report.total_modules_failed = sum(
            1 for mr in report.module_results.values() if mr.status == "error"
        )

        # Severity / module / category breakdowns
        for f in all_findings:
            sev = f.severity
            report.findings_by_severity[sev] = report.findings_by_severity.get(sev, 0) + 1
            report.findings_by_module[f.module] = report.findings_by_module.get(f.module, 0) + 1
            if f.category:
                report.findings_by_category[f.category] = (
                    report.findings_by_category.get(f.category, 0) + 1
                )

        # Risk scoring and prioritisation
        report.overall_risk_score = self._compute_overall_risk(all_findings)
        report.overall_risk_label = _risk_label(report.overall_risk_score)
        report.prioritised_findings = sorted(
            all_findings, key=lambda f: f.risk_score, reverse=True
        )

        report.scan_duration_seconds = round(time.monotonic() - scan_start, 4)
        report.fingerprint = self._build_fingerprint(report)
        self._report = report

        logger.info(
            "Full DSPM scan complete: %d findings, risk=%s (%.1f), duration=%.2fs",
            report.total_findings,
            report.overall_risk_label,
            report.overall_risk_score,
            report.scan_duration_seconds,
        )
        return report

    # ══════════════════════════════════════════════════════════════════
    # Reporting
    # ══════════════════════════════════════════════════════════════════

    def get_summary(self) -> dict:
        """Return a concise summary of the most recent scan.

        Raises:
            RuntimeError: If no scan has been run yet.
        """
        if self._report is None:
            raise RuntimeError("No DSPM scan has been run yet. Call run_full_scan() first.")

        r = self._report
        top_findings = []
        for f in r.prioritised_findings[:10]:
            top_findings.append({
                "title": f.title,
                "severity": f.severity,
                "module": f.module,
                "risk_score": f.risk_score,
            })

        module_status = {}
        for name, mr in r.module_results.items():
            module_status[name] = {
                "status": mr.status,
                "findings": mr.finding_count,
                "duration_seconds": mr.duration_seconds,
            }

        return {
            "report_id": r.report_id,
            "created_at": r.created_at,
            "provider": r.provider,
            "overall_risk_score": r.overall_risk_score,
            "overall_risk_label": r.overall_risk_label,
            "total_findings": r.total_findings,
            "findings_by_severity": dict(r.findings_by_severity),
            "modules": module_status,
            "top_findings": top_findings,
            "scan_duration_seconds": r.scan_duration_seconds,
            "fingerprint": r.fingerprint,
        }

    def get_detailed_report(self) -> dict:
        """Return the full detailed report as a serialisable dict.

        Raises:
            RuntimeError: If no scan has been run yet.
        """
        if self._report is None:
            raise RuntimeError("No DSPM scan has been run yet. Call run_full_scan() first.")

        r = self._report

        module_details: dict[str, dict] = {}
        for name, mr in r.module_results.items():
            findings_list = []
            for f in mr.findings:
                findings_list.append({
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                    "resource_id": f.resource_id,
                    "resource_name": f.resource_name,
                    "provider": f.provider,
                    "category": f.category,
                    "remediation": f.remediation,
                    "risk_score": f.risk_score,
                    "evidence": f.evidence,
                })
            module_details[name] = {
                "status": mr.status,
                "started_at": mr.started_at,
                "finished_at": mr.finished_at,
                "duration_seconds": mr.duration_seconds,
                "finding_count": mr.finding_count,
                "error_message": mr.error_message,
                "findings": findings_list,
            }

        all_findings_serialised = []
        for f in r.prioritised_findings:
            all_findings_serialised.append({
                "finding_id": f.finding_id,
                "module": f.module,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "description": f.description,
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "provider": f.provider,
                "category": f.category,
                "remediation": f.remediation,
                "risk_score": f.risk_score,
                "evidence": f.evidence,
            })

        return {
            "report_id": r.report_id,
            "created_at": r.created_at,
            "provider": r.provider,
            "scan_duration_seconds": r.scan_duration_seconds,
            "fingerprint": r.fingerprint,
            "overall_risk_score": r.overall_risk_score,
            "overall_risk_label": r.overall_risk_label,
            "total_findings": r.total_findings,
            "total_modules_run": r.total_modules_run,
            "total_modules_failed": r.total_modules_failed,
            "findings_by_severity": dict(r.findings_by_severity),
            "findings_by_module": dict(r.findings_by_module),
            "findings_by_category": dict(r.findings_by_category),
            "modules": module_details,
            "prioritised_findings": all_findings_serialised,
        }
