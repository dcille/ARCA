"""Ransomware Readiness evaluation Celery tasks."""
import json
import logging
from datetime import datetime

from api.celery_app import celery_app

logger = logging.getLogger(__name__)

SYNC_DATABASE_URL = "postgresql://darca:darca@postgres:5432/darca"


def _get_sync_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(SYNC_DATABASE_URL)
    return sessionmaker(bind=engine)()


@celery_app.task(bind=True, name="api.tasks.rr_tasks.evaluate_ransomware_readiness")
def evaluate_ransomware_readiness(self, user_id: str, scan_id: str = None):
    """Evaluate Ransomware Readiness for a user using their latest scan findings.

    Called after each cloud scan completes, or manually via API.
    """
    from api.models.provider import Provider
    from api.models.scan import Scan
    from api.models.finding import Finding
    from api.models.rr_score import RRScore
    from api.models.rr_finding import RRFinding
    from api.models.rr_governance import RRGovernance
    from scanner.ransomware_readiness.evaluator import evaluate_findings_against_rules
    from scanner.ransomware_readiness.scoring import calculate_full_score

    session = _get_sync_session()
    try:
        # Get all providers for user
        providers = session.query(Provider).filter(Provider.user_id == user_id).all()
        if not providers:
            logger.warning(f"RR evaluation: no providers for user {user_id}")
            return

        # Get governance data
        gov = session.query(RRGovernance).filter(RRGovernance.user_id == user_id).first()
        governance_data = None
        if gov:
            governance_data = {
                "ransomware_response_plan": gov.ransomware_response_plan,
                "last_tabletop_exercise_date": gov.last_tabletop_exercise_date.isoformat() if gov.last_tabletop_exercise_date else None,
                "security_training_completion": gov.security_training_completion,
                "ir_roles_defined": gov.ir_roles_defined,
                "communication_plan_exists": gov.communication_plan_exists,
                "rto_rpo_documented": gov.rto_rpo_documented,
                "backup_restore_tested": gov.backup_restore_tested,
                "dr_plan_documented": gov.dr_plan_documented,
                "iac_scanning_integrated": gov.iac_scanning_integrated,
                "siem_integration_configured": gov.siem_integration_configured,
            }

        # Get previous global score for trending
        prev_global = (
            session.query(RRScore)
            .filter(RRScore.user_id == user_id, RRScore.scope == "global")
            .order_by(RRScore.calculated_at.desc())
            .first()
        )
        previous_score = prev_global.score if prev_global else None

        all_evaluations = []

        for provider in providers:
            # Get latest completed scan for this provider
            latest_scan = (
                session.query(Scan)
                .filter(
                    Scan.user_id == user_id,
                    Scan.provider_id == provider.id,
                    Scan.status == "completed",
                    Scan.scan_type == "cloud",
                )
                .order_by(Scan.completed_at.desc())
                .first()
            )

            if not latest_scan:
                continue

            # Get all findings from latest scan
            findings = (
                session.query(Finding)
                .filter(Finding.scan_id == latest_scan.id)
                .all()
            )

            findings_dicts = [
                {
                    "check_id": f.check_id,
                    "status": f.status,
                    "severity": f.severity,
                    "resource_id": f.resource_id,
                    "resource_name": f.resource_name,
                    "status_extended": f.status_extended,
                    "service": f.service,
                    "compliance_frameworks": f.compliance_frameworks,
                }
                for f in findings
            ]

            evals = evaluate_findings_against_rules(
                findings=findings_dicts,
                provider=provider.provider_type,
                account_id=provider.id,
                governance_data=governance_data,
            )
            all_evaluations.extend(evals)

        if not all_evaluations:
            logger.info(f"RR evaluation: no evaluations generated for user {user_id}")
            return

        # Calculate scores
        score_result = calculate_full_score(
            evaluations=all_evaluations,
            previous_score=previous_score,
        )

        # Persist global score
        domain_scores_json = {}
        for dk, dv in score_result.domain_scores.items():
            domain_scores_json[dk] = {
                "name": dv.name,
                "weight": dv.weight,
                "final_score": dv.final_score,
                "base_score": dv.base_score,
                "checks_total": dv.checks_total,
                "checks_passed": dv.checks_passed,
                "checks_failed": dv.checks_failed,
                "checks_warning": dv.checks_warning,
                "critical_fails": dv.critical_fails,
                "high_fails": dv.high_fails,
                "medium_fails": dv.medium_fails,
                "low_fails": dv.low_fails,
            }

        global_score = RRScore(
            user_id=user_id,
            scope="global",
            score=score_result.global_score,
            level=score_result.level,
            checks_passed=score_result.checks_passed,
            checks_failed=score_result.checks_failed,
            checks_warning=score_result.checks_warning,
            domain_scores=json.dumps(domain_scores_json),
            scan_id=scan_id,
        )
        session.add(global_score)

        # Persist per-account scores
        for acct in score_result.account_scores:
            acct_ds = {}
            for dk, dv in acct.domain_scores.items():
                acct_ds[dk] = {
                    "name": dv.name,
                    "final_score": dv.final_score,
                    "checks_total": dv.checks_total,
                    "checks_passed": dv.checks_passed,
                    "checks_failed": dv.checks_failed,
                    "critical_fails": dv.critical_fails,
                    "high_fails": dv.high_fails,
                }
            acct_score = RRScore(
                user_id=user_id,
                scope="account",
                scope_id=acct.account_id,
                score=acct.global_score,
                level="",  # will be enriched
                checks_passed=acct.checks_passed,
                checks_failed=acct.checks_failed,
                domain_scores=json.dumps(acct_ds),
                scan_id=scan_id,
            )
            from scanner.ransomware_readiness.framework import get_score_level
            level_info = get_score_level(acct.global_score)
            acct_score.level = level_info["level"].value
            session.add(acct_score)

        # Persist RR findings
        for ev in all_evaluations:
            rr_finding = RRFinding(
                user_id=user_id,
                scan_id=scan_id,
                rule_id=ev.rule_id,
                domain=ev.domain.value,
                severity=ev.severity.value,
                status=ev.status,
                provider=ev.provider,
                account_id=ev.account_id,
                resource_count=ev.resource_count,
                passed_resources=ev.passed_resources,
                failed_resources=ev.failed_resources,
                evidence=json.dumps(ev.evidence) if ev.evidence else None,
                finding_status="open" if ev.status == "fail" else "resolved" if ev.status == "pass" else "open",
            )
            session.add(rr_finding)

        session.commit()
        logger.info(
            f"RR evaluation complete for user {user_id}: "
            f"score={score_result.global_score} ({score_result.level}), "
            f"{score_result.checks_passed} passed, {score_result.checks_failed} failed"
        )

    except Exception as e:
        logger.exception(f"RR evaluation failed for user {user_id}: {e}")
        session.rollback()
    finally:
        session.close()
