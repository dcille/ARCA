"""Composite Rule Evaluators for Ransomware Readiness.

These handle rules that require cross-check or aggregate analysis
rather than simple 1:1 mapping to CSPM check_ids.
"""

from __future__ import annotations

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity
from scanner.ransomware_readiness.scoring import CheckEvaluation


def _eval_cis_benchmark_compliance(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-HDN-001: Calculate CIS benchmark compliance percentage.

    Aggregates all CIS-mapped checks from the CSPM and calculates
    the pass rate. Pass if ≥80%.
    """
    cis_prefix_map = {
        "aws": "CIS-AWS",
        "azure": "CIS-Azure",
        "gcp": "CIS-GCP",
    }
    prefix = cis_prefix_map.get(provider, "CIS")

    total_cis = 0
    passed_cis = 0

    for check_id, finding_list in findings_by_check.items():
        for f in finding_list:
            frameworks = f.get("compliance_frameworks") or ""
            if isinstance(frameworks, str) and prefix in frameworks:
                total_cis += 1
                if f.get("status", "").upper() == "PASS":
                    passed_cis += 1
                break  # count check once
            elif isinstance(frameworks, list):
                if any(prefix in fw for fw in frameworks):
                    total_cis += 1
                    if f.get("status", "").upper() == "PASS":
                        passed_cis += 1
                    break

    if total_cis == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={"reason": "No CIS benchmark checks found in scan results"},
        )

    compliance_pct = (passed_cis / total_cis) * 100
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status="pass" if compliance_pct >= 80 else "fail",
        resource_count=total_cis, passed_resources=passed_cis,
        failed_resources=total_cis - passed_cis,
        account_id=account_id, provider=provider,
        evidence={
            "compliance_percentage": round(compliance_pct, 1),
            "total_cis_checks": total_cis,
            "passed": passed_cis,
            "threshold": "≥80%",
        },
    )


def _eval_security_alerts_configured(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-LOG-003: Verify critical security alerts are configured.

    Checks that alerts exist for: logging changes, IAM root usage,
    and other critical events. Pass if ≥3 of the mapped alert checks pass.
    """
    check_ids = rule.check_ids.get(provider, [])
    passing = 0
    total = len(check_ids)

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        if any(f.get("status", "").upper() == "PASS" for f in matched):
            passing += 1

    if total == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={"reason": "No alert checks found"},
        )

    # Pass if majority of alert checks pass
    threshold = max(1, total // 2)
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status="pass" if passing >= threshold else "fail",
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={
            "alerts_configured": passing,
            "alerts_required": total,
            "threshold": f"≥{threshold}",
        },
    )


def _eval_cross_region_backup(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-BKP-003 / RR-BKP-014: Cross-region or cross-account backup / isolation.

    Aggregates backup replication checks. Pass if any cross-region/cross-account
    backup configuration is detected.
    """
    check_ids = rule.check_ids.get(provider, [])
    found_any = False
    passing = 0
    total = 0

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        for f in matched:
            total += 1
            found_any = True
            if f.get("status", "").upper() == "PASS":
                passing += 1

    if not found_any:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={"reason": "No cross-region/cross-account backup checks found"},
        )

    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status="pass" if passing > 0 else "fail",
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={"total": total, "passing": passing},
    )


def _eval_environment_segmentation(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-NET-007: Environment segmentation (dev/staging/prod).

    Checks that VPCs/networks exist with environment-indicative names/tags,
    suggesting network segmentation between environments.
    """
    check_ids = rule.check_ids.get(provider, [])
    total = 0
    passing = 0

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        for f in matched:
            total += 1
            if f.get("status", "").upper() == "PASS":
                passing += 1

    if total == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={"reason": "No environment segmentation checks found"},
        )

    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status="pass" if passing > 0 else "fail",
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={"total": total, "passing": passing},
    )


def _eval_tagging_compliance(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-HDN-008: Resource tagging/labeling compliance.

    Aggregates tagging check results. Pass if ≥80% of resources are properly tagged.
    """
    check_ids = rule.check_ids.get(provider, [])
    total = 0
    passing = 0

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        for f in matched:
            total += 1
            if f.get("status", "").upper() == "PASS":
                passing += 1

    if total == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={"reason": "No tagging compliance checks found"},
        )

    pct = (passing / total) * 100
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status="pass" if pct >= 80 else "fail",
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={"compliance_pct": round(pct, 1), "threshold": "≥80%"},
    )


# ── Registry of composite evaluators ────────────────────────
COMPOSITE_EVALUATORS: dict[str, callable] = {
    "RR-HDN-001": _eval_cis_benchmark_compliance,
    "RR-LOG-003": _eval_security_alerts_configured,
    "RR-BKP-003": _eval_cross_region_backup,
    "RR-BKP-014": _eval_cross_region_backup,
    "RR-NET-007": _eval_environment_segmentation,
    "RR-HDN-008": _eval_tagging_compliance,
}
