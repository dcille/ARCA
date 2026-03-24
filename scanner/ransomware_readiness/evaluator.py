"""Ransomware Readiness Evaluator.

Orchestrates the evaluation of existing CSPM findings against the RR framework.
Consumes findings from the CSPM database and produces CheckEvaluations
that feed into the scoring engine.
"""

from __future__ import annotations

from scanner.ransomware_readiness.framework import (
    Domain, Severity, RRRule,
    get_all_rules, build_check_id_to_rules_map,
)
from scanner.ransomware_readiness.scoring import CheckEvaluation


def evaluate_findings_against_rules(
    findings: list[dict],
    provider: str,
    account_id: str,
    governance_data: dict | None = None,
) -> list[CheckEvaluation]:
    """Evaluate a list of CSPM findings against all RR rules for a provider.

    Args:
        findings: List of finding dicts from the DB (check_id, status, severity, resource_id, ...).
        provider: Cloud provider type (aws, azure, gcp).
        account_id: The cloud account / subscription / project ID.
        governance_data: Optional dict with manual governance inputs for D7 rules.

    Returns:
        List of CheckEvaluation results, one per applicable RR rule.
    """
    # Index findings by check_id
    findings_by_check: dict[str, list[dict]] = {}
    for f in findings:
        cid = f.get("check_id", "")
        findings_by_check.setdefault(cid, []).append(f)

    all_rules = get_all_rules()
    evaluations: list[CheckEvaluation] = []

    for rule in all_rules:
        # Skip rules not applicable to this provider
        if provider not in rule.cloud_providers:
            continue

        # Handle manual / governance rules
        if rule.is_manual:
            ev = _evaluate_manual_rule(rule, governance_data, account_id, provider)
            evaluations.append(ev)
            continue

        # Handle composite rules
        if rule.is_composite:
            ev = _evaluate_composite_rule(rule, findings_by_check, provider, account_id)
            evaluations.append(ev)
            continue

        # Standard rule: map check_ids to findings
        ev = _evaluate_standard_rule(rule, findings_by_check, provider, account_id)
        evaluations.append(ev)

    return evaluations


def _evaluate_standard_rule(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """Evaluate a standard rule by aggregating its mapped CSPM check results."""
    check_ids = rule.check_ids.get(provider, [])
    if not check_ids:
        # Rule defined for provider but no check_ids mapped -> warning
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={"reason": "No CSPM checks mapped for this rule and provider"},
        )

    total_resources = 0
    passed_resources = 0
    failed_resources = 0
    all_evidence: list[dict] = []

    for cid in check_ids:
        matched_findings = findings_by_check.get(cid, [])
        for f in matched_findings:
            total_resources += 1
            status = f.get("status", "").upper()
            if status == "PASS":
                passed_resources += 1
            elif status == "FAIL":
                failed_resources += 1
                all_evidence.append({
                    "check_id": cid,
                    "resource_id": f.get("resource_id"),
                    "resource_name": f.get("resource_name"),
                    "status_extended": f.get("status_extended"),
                })

    if total_resources == 0:
        # No findings found for mapped checks -> could mean checks weren't run
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={"reason": "No findings found for mapped checks — checks may not have been executed"},
        )

    # Rule passes only if ALL resources pass
    if failed_resources == 0:
        status = "pass"
    else:
        status = "fail"

    return CheckEvaluation(
        rule_id=rule.rule_id,
        domain=rule.domain,
        severity=rule.severity,
        status=status,
        resource_count=total_resources,
        passed_resources=passed_resources,
        failed_resources=failed_resources,
        account_id=account_id,
        provider=provider,
        evidence={
            "total": total_resources,
            "passed": passed_resources,
            "failed": failed_resources,
            "failed_details": all_evidence[:20],  # cap evidence for storage
        },
    )


def _evaluate_composite_rule(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """Evaluate composite rules that require cross-check analysis.

    Composite rules aggregate results from multiple checks and may apply
    custom logic (e.g. CIS compliance percentage, cross-region backup existence).
    For now, we use a standard aggregation — specific composite logic
    can be added per rule_id in composite_rules.py.
    """
    from scanner.ransomware_readiness.composite_rules import COMPOSITE_EVALUATORS

    evaluator_fn = COMPOSITE_EVALUATORS.get(rule.rule_id)
    if evaluator_fn:
        return evaluator_fn(rule, findings_by_check, provider, account_id)

    # Default: fall back to standard aggregation
    return _evaluate_standard_rule(rule, findings_by_check, provider, account_id)


def _evaluate_manual_rule(
    rule: RRRule,
    governance_data: dict | None,
    account_id: str,
    provider: str,
) -> CheckEvaluation:
    """Evaluate manual / governance rules from operator-provided data."""
    if not governance_data:
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={"reason": "Governance data not provided — please complete the Governance questionnaire"},
        )

    # Map rule_ids to governance data fields
    field_map = {
        "RR-GOV-001": "ransomware_response_plan",
        "RR-GOV-002": "last_tabletop_exercise_date",
        "RR-GOV-003": "security_training_completion",
        "RR-GOV-004": "ir_roles_defined",
        "RR-GOV-005": "communication_plan_exists",
        "RR-BKP-015": "rto_rpo_documented",
        "RR-BKP-016": "backup_restore_tested",
        "RR-BKP-017": "dr_plan_documented",
        "RR-HDN-015": "iac_scanning_integrated",
        "RR-LOG-009": "siem_integration_configured",
    }

    field_name = field_map.get(rule.rule_id, rule.rule_id.lower())
    value = governance_data.get(field_name)

    if value is None:
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={"reason": f"Field '{field_name}' not provided in governance data"},
        )

    # Boolean fields
    if isinstance(value, bool):
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="pass" if value else "fail",
            account_id=account_id,
            provider=provider,
            evidence={"field": field_name, "value": value},
        )

    # Date fields (e.g. last tabletop exercise — must be within 6 months)
    if field_name == "last_tabletop_exercise_date":
        from datetime import datetime, timedelta
        try:
            exercise_date = datetime.fromisoformat(str(value))
            six_months_ago = datetime.utcnow() - timedelta(days=180)
            is_recent = exercise_date >= six_months_ago
            return CheckEvaluation(
                rule_id=rule.rule_id,
                domain=rule.domain,
                severity=rule.severity,
                status="pass" if is_recent else "fail",
                account_id=account_id,
                provider=provider,
                evidence={"field": field_name, "value": str(value), "threshold": "within 6 months"},
            )
        except (ValueError, TypeError):
            pass

    # Percentage fields (e.g. training completion — must be ≥90%)
    if field_name == "security_training_completion":
        try:
            pct = float(value)
            return CheckEvaluation(
                rule_id=rule.rule_id,
                domain=rule.domain,
                severity=rule.severity,
                status="pass" if pct >= 90.0 else "fail",
                account_id=account_id,
                provider=provider,
                evidence={"field": field_name, "value": pct, "threshold": "≥90%"},
            )
        except (ValueError, TypeError):
            pass

    # Default: truthy check
    return CheckEvaluation(
        rule_id=rule.rule_id,
        domain=rule.domain,
        severity=rule.severity,
        status="pass" if value else "fail",
        account_id=account_id,
        provider=provider,
        evidence={"field": field_name, "value": str(value)},
    )


def evaluate_all_accounts(
    accounts: list[dict],
    governance_data: dict | None = None,
) -> list[CheckEvaluation]:
    """Evaluate RR rules across multiple cloud accounts.

    Args:
        accounts: List of dicts with keys: account_id, provider, name, findings (list of finding dicts)
        governance_data: Optional governance inputs

    Returns:
        Combined list of CheckEvaluations for all accounts
    """
    all_evaluations: list[CheckEvaluation] = []

    for account in accounts:
        evals = evaluate_findings_against_rules(
            findings=account.get("findings", []),
            provider=account["provider"],
            account_id=account["account_id"],
            governance_data=governance_data,
        )
        all_evaluations.extend(evals)

    return all_evaluations
