"""Ransomware Readiness Scoring Engine.

Implements the weighted scoring algorithm with severity penalties.
Deterministic: same inputs always produce the same score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from scanner.ransomware_readiness.framework import (
    Domain, Severity, ScoreLevel, DOMAIN_WEIGHTS,
    SEVERITY_PENALTY, SCORE_LEVELS, get_score_level,
)


@dataclass
class DomainScoreDetail:
    """Score breakdown for a single domain."""
    domain: Domain
    name: str
    weight: float
    base_score: float  # (passed / total) * 100
    severity_adjustment: float  # sum of penalties
    final_score: float  # max(0, base + adjustment)
    checks_total: int
    checks_passed: int
    checks_failed: int
    checks_warning: int
    critical_fails: int
    high_fails: int
    medium_fails: int
    low_fails: int


@dataclass
class AccountScore:
    """Score for a single cloud account."""
    account_id: str
    provider: str
    account_name: str
    global_score: float
    domain_scores: dict[str, DomainScoreDetail]
    checks_total: int
    checks_passed: int
    checks_failed: int


@dataclass
class RRScoreResult:
    """Complete scoring result across all accounts and domains."""
    global_score: int  # 0-100
    level: str  # Excelente / Bueno / Moderado / Bajo / Critico
    level_color: str
    domain_scores: dict[str, DomainScoreDetail]
    account_scores: list[AccountScore]
    checks_total: int
    checks_passed: int
    checks_failed: int
    checks_warning: int
    critical_findings: int
    trend_30d: Optional[float] = None
    trend_90d: Optional[float] = None


# ── Evaluation result from evaluator, consumed by scorer ─────

@dataclass
class CheckEvaluation:
    """Result of evaluating a single RR rule against findings."""
    rule_id: str
    domain: Domain
    severity: Severity
    status: str  # pass / fail / warning / error / manual
    resource_count: int = 0
    passed_resources: int = 0
    failed_resources: int = 0
    account_id: str = ""
    provider: str = ""
    evidence: dict = field(default_factory=dict)


def calculate_domain_score(
    domain: Domain,
    evaluations: list[CheckEvaluation],
) -> DomainScoreDetail:
    """Calculate score for a single domain from its check evaluations.

    Formula:
        base_score = (passed / total) * 100
        severity_adjustment = sum of penalties for failed checks
        final_score = max(0, base_score + severity_adjustment)
    """
    from scanner.ransomware_readiness.framework import DOMAIN_METADATA

    total = len(evaluations)
    if total == 0:
        meta = DOMAIN_METADATA[domain]
        return DomainScoreDetail(
            domain=domain,
            name=meta["name"],
            weight=DOMAIN_WEIGHTS[domain],
            base_score=100.0,
            severity_adjustment=0.0,
            final_score=100.0,
            checks_total=0, checks_passed=0, checks_failed=0, checks_warning=0,
            critical_fails=0, high_fails=0, medium_fails=0, low_fails=0,
        )

    passed = sum(1 for e in evaluations if e.status == "pass")
    failed = sum(1 for e in evaluations if e.status == "fail")
    warning = sum(1 for e in evaluations if e.status == "warning")

    crit = sum(1 for e in evaluations if e.status == "fail" and e.severity == Severity.CRITICAL)
    high = sum(1 for e in evaluations if e.status == "fail" and e.severity == Severity.HIGH)
    med = sum(1 for e in evaluations if e.status == "fail" and e.severity == Severity.MEDIUM)
    low = sum(1 for e in evaluations if e.status == "fail" and e.severity == Severity.LOW)

    # Base score: only count evaluated checks (pass + fail), exclude warnings
    # Warnings mean checks couldn't be evaluated (no data) — they shouldn't penalize the score
    evaluated = passed + failed
    base = (passed / evaluated) * 100 if evaluated > 0 else 100.0

    adjustment = (
        crit * SEVERITY_PENALTY[Severity.CRITICAL]
        + high * SEVERITY_PENALTY[Severity.HIGH]
        + med * SEVERITY_PENALTY[Severity.MEDIUM]
        + low * SEVERITY_PENALTY[Severity.LOW]
    )

    final = max(0.0, min(100.0, base + adjustment))

    meta = DOMAIN_METADATA[domain]
    return DomainScoreDetail(
        domain=domain,
        name=meta["name"],
        weight=DOMAIN_WEIGHTS[domain],
        base_score=round(base, 1),
        severity_adjustment=round(adjustment, 1),
        final_score=round(final, 1),
        checks_total=total,
        checks_passed=passed,
        checks_failed=failed,
        checks_warning=warning,
        critical_fails=crit,
        high_fails=high,
        medium_fails=med,
        low_fails=low,
    )


def calculate_global_score(
    domain_scores: dict[str, DomainScoreDetail],
) -> tuple[int, str, str]:
    """Calculate weighted global score from domain scores.

    Returns: (score, level_name, level_color)
    """
    weighted_sum = 0.0
    total_weight = 0.0

    for domain_key, detail in domain_scores.items():
        weighted_sum += detail.final_score * detail.weight
        total_weight += detail.weight

    if total_weight > 0:
        score = round(weighted_sum / total_weight)
    else:
        score = 0

    score = max(0, min(100, score))
    level_info = get_score_level(score)

    return score, level_info["level"].value, level_info["color"]


def calculate_full_score(
    evaluations: list[CheckEvaluation],
    previous_score: Optional[int] = None,
    previous_score_90d: Optional[int] = None,
) -> RRScoreResult:
    """Calculate the complete RR score from all evaluations.

    Groups evaluations by domain, calculates domain scores,
    then computes weighted global score.
    """
    # Group by domain
    by_domain: dict[str, list[CheckEvaluation]] = {}
    for e in evaluations:
        key = e.domain.value
        by_domain.setdefault(key, []).append(e)

    # Calculate each domain score (include empty domains)
    domain_scores: dict[str, DomainScoreDetail] = {}
    for domain in Domain:
        evals = by_domain.get(domain.value, [])
        domain_scores[domain.value] = calculate_domain_score(domain, evals)

    # Global score
    score, level, color = calculate_global_score(domain_scores)

    # Aggregate counts
    total = sum(d.checks_total for d in domain_scores.values())
    passed = sum(d.checks_passed for d in domain_scores.values())
    failed = sum(d.checks_failed for d in domain_scores.values())
    warning = sum(d.checks_warning for d in domain_scores.values())
    critical = sum(d.critical_fails for d in domain_scores.values())

    # Per-account scores
    by_account: dict[str, list[CheckEvaluation]] = {}
    for e in evaluations:
        if e.account_id:
            by_account.setdefault(e.account_id, []).append(e)

    account_scores: list[AccountScore] = []
    for acct_id, acct_evals in by_account.items():
        acct_by_domain: dict[str, list[CheckEvaluation]] = {}
        for e in acct_evals:
            acct_by_domain.setdefault(e.domain.value, []).append(e)

        acct_domain_scores: dict[str, DomainScoreDetail] = {}
        for domain in Domain:
            acct_domain_scores[domain.value] = calculate_domain_score(
                domain, acct_by_domain.get(domain.value, [])
            )

        acct_score, _, _ = calculate_global_score(acct_domain_scores)
        provider = acct_evals[0].provider if acct_evals else ""
        account_scores.append(AccountScore(
            account_id=acct_id,
            provider=provider,
            account_name=acct_id,  # will be enriched by caller
            global_score=acct_score,
            domain_scores=acct_domain_scores,
            checks_total=sum(d.checks_total for d in acct_domain_scores.values()),
            checks_passed=sum(d.checks_passed for d in acct_domain_scores.values()),
            checks_failed=sum(d.checks_failed for d in acct_domain_scores.values()),
        ))

    # Trends
    trend_30d = (score - previous_score) if previous_score is not None else None
    trend_90d = (score - previous_score_90d) if previous_score_90d is not None else None

    return RRScoreResult(
        global_score=score,
        level=level,
        level_color=color,
        domain_scores=domain_scores,
        account_scores=account_scores,
        checks_total=total,
        checks_passed=passed,
        checks_failed=failed,
        checks_warning=warning,
        critical_findings=critical,
        trend_30d=trend_30d,
        trend_90d=trend_90d,
    )
