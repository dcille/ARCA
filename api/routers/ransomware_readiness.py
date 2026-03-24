"""Ransomware Readiness API router — all REST endpoints."""
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.models.scan import Scan
from api.models.finding import Finding
from api.models.rr_score import RRScore
from api.models.rr_finding import RRFinding
from api.models.rr_governance import RRGovernance
from api.services.auth_service import get_current_user
from scanner.ransomware_readiness.framework import (
    Domain, DOMAIN_WEIGHTS, DOMAIN_METADATA, get_all_rules, get_rule_by_id,
)

router = APIRouter()


# ── Pydantic Schemas ─────────────────────────────────────────

class GovernanceUpdate(BaseModel):
    ransomware_response_plan: Optional[bool] = None
    last_tabletop_exercise_date: Optional[str] = None
    security_training_completion: Optional[float] = None
    ir_roles_defined: Optional[bool] = None
    communication_plan_exists: Optional[bool] = None
    rto_rpo_documented: Optional[bool] = None
    backup_restore_tested: Optional[bool] = None
    dr_plan_documented: Optional[bool] = None
    iac_scanning_integrated: Optional[bool] = None
    siem_integration_configured: Optional[bool] = None
    notes: Optional[str] = None


class FindingUpdate(BaseModel):
    finding_status: Optional[str] = None  # open/accepted/exception/resolved
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    ticket_url: Optional[str] = None


# ── Score endpoints ──────────────────────────────────────────

@router.get("/score")
async def get_rr_score(
    account_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the latest Ransomware Readiness score (global or per-account)."""
    query = (
        select(RRScore)
        .where(RRScore.user_id == current_user.id)
        .where(RRScore.scope == ("account" if account_id else "global"))
    )
    if account_id:
        query = query.where(RRScore.scope_id == account_id)
    query = query.order_by(desc(RRScore.calculated_at)).limit(1)

    result = await db.execute(query)
    score = result.scalar_one_or_none()

    if not score:
        return {
            "global_score": 0,
            "level": "Critico",
            "message": "No ransomware readiness assessment has been run yet. Run a cloud scan first.",
            "domains": [],
            "summary": {"total_checks": 0, "passed": 0, "failed": 0, "warning": 0, "critical_findings": 0},
        }

    domain_scores = json.loads(score.domain_scores) if score.domain_scores else {}

    # Get trend
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    prev_query = (
        select(RRScore)
        .where(RRScore.user_id == current_user.id)
        .where(RRScore.scope == score.scope)
        .where(RRScore.calculated_at < thirty_days_ago)
        .order_by(desc(RRScore.calculated_at))
        .limit(1)
    )
    prev_result = await db.execute(prev_query)
    prev_score = prev_result.scalar_one_or_none()
    trend_30d = (score.score - prev_score.score) if prev_score else None

    domains_list = []
    for domain in Domain:
        d = domain.value
        ds = domain_scores.get(d, {})
        meta = DOMAIN_METADATA.get(domain, {})
        domains_list.append({
            "id": d,
            "name": meta.get("name", d),
            "nist_csf": meta.get("nist_csf", ""),
            "score": ds.get("final_score", 0),
            "weight": DOMAIN_WEIGHTS.get(domain, 0),
            "checks_total": ds.get("checks_total", 0),
            "checks_passed": ds.get("checks_passed", 0),
            "checks_failed": ds.get("checks_failed", 0),
            "checks_warning": ds.get("checks_warning", 0),
            "critical_fails": ds.get("critical_fails", 0),
        })

    return {
        "global_score": score.score,
        "level": score.level,
        "trend_30d": trend_30d,
        "calculated_at": score.calculated_at.isoformat() if score.calculated_at else None,
        "domains": domains_list,
        "summary": {
            "total_checks": score.checks_passed + score.checks_failed + score.checks_warning,
            "passed": score.checks_passed,
            "failed": score.checks_failed,
            "warning": score.checks_warning,
            "critical_findings": sum(d.get("critical_fails", 0) for d in domain_scores.values()),
        },
    }


@router.get("/score/history")
async def get_score_history(
    days: int = Query(default=90, le=365),
    scope: str = Query(default="global"),
    scope_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get historical RR scores for trending."""
    since = datetime.utcnow() - timedelta(days=days)
    query = (
        select(RRScore)
        .where(RRScore.user_id == current_user.id)
        .where(RRScore.scope == scope)
        .where(RRScore.calculated_at >= since)
        .order_by(RRScore.calculated_at.asc())
    )
    if scope_id:
        query = query.where(RRScore.scope_id == scope_id)

    result = await db.execute(query)
    scores = result.scalars().all()

    return [
        {
            "score": s.score,
            "level": s.level,
            "date": s.calculated_at.strftime("%Y-%m-%d") if s.calculated_at else "",
            "checks_passed": s.checks_passed,
            "checks_failed": s.checks_failed,
        }
        for s in scores
    ]


# ── Domain endpoints ─────────────────────────────────────────

@router.get("/domains")
async def get_domains(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all 7 domains with their current score."""
    # Fetch latest global score for domain breakdown
    score_q = (
        select(RRScore)
        .where(RRScore.user_id == current_user.id, RRScore.scope == "global")
        .order_by(desc(RRScore.calculated_at)).limit(1)
    )
    result = await db.execute(score_q)
    latest = result.scalar_one_or_none()
    domain_scores = json.loads(latest.domain_scores) if latest and latest.domain_scores else {}

    domains = []
    all_rules = get_all_rules()
    for domain in Domain:
        d = domain.value
        meta = DOMAIN_METADATA[domain]
        ds = domain_scores.get(d, {})
        rule_count = len([r for r in all_rules if r.domain == domain])
        domains.append({
            "id": d,
            "name": meta["name"],
            "description": meta["description"],
            "nist_csf": meta["nist_csf"],
            "weight": DOMAIN_WEIGHTS[domain],
            "score": ds.get("final_score", 0),
            "rule_count": rule_count,
            "checks_passed": ds.get("checks_passed", 0),
            "checks_failed": ds.get("checks_failed", 0),
            "checks_warning": ds.get("checks_warning", 0),
            "critical_fails": ds.get("critical_fails", 0),
            "high_fails": ds.get("high_fails", 0),
        })

    return domains


@router.get("/domains/{domain_id}/rules")
async def get_domain_rules(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get rules for a domain with their latest evaluation status."""
    try:
        domain = Domain(domain_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Domain {domain_id} not found")

    all_rules = get_all_rules()
    domain_rules = [r for r in all_rules if r.domain == domain]

    # Get latest findings for these rules
    rule_ids = [r.rule_id for r in domain_rules]
    findings_q = (
        select(RRFinding)
        .where(RRFinding.user_id == current_user.id, RRFinding.rule_id.in_(rule_ids))
        .order_by(desc(RRFinding.created_at))
    )
    findings_result = await db.execute(findings_q)
    findings = findings_result.scalars().all()

    # Index latest finding per rule
    latest_by_rule: dict[str, RRFinding] = {}
    for f in findings:
        if f.rule_id not in latest_by_rule:
            latest_by_rule[f.rule_id] = f

    rules_response = []
    for rule in domain_rules:
        finding = latest_by_rule.get(rule.rule_id)
        rules_response.append({
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "ransomware_context": rule.ransomware_context,
            "severity": rule.severity.value,
            "cloud_providers": rule.cloud_providers,
            "nist_category": rule.nist_category,
            "nist_subcategory": rule.nist_subcategory,
            "is_manual": rule.is_manual,
            "status": finding.status if finding else "not_evaluated",
            "resource_count": finding.resource_count if finding else 0,
            "failed_resources": finding.failed_resources if finding else 0,
            "last_evaluated": finding.created_at.isoformat() if finding else None,
        })

    return rules_response


# ── Findings endpoints ───────────────────────────────────────

@router.get("/findings")
async def get_rr_findings(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    finding_status: Optional[str] = Query(None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List RR findings with filters and pagination."""
    query = select(RRFinding).where(RRFinding.user_id == current_user.id)

    if severity:
        query = query.where(RRFinding.severity == severity)
    if status:
        query = query.where(RRFinding.status == status)
    if domain:
        query = query.where(RRFinding.domain == domain)
    if account_id:
        query = query.where(RRFinding.account_id == account_id)
    if finding_status:
        query = query.where(RRFinding.finding_status == finding_status)

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Paginate
    query = query.order_by(desc(RRFinding.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    findings = result.scalars().all()

    # Enrich with rule metadata
    items = []
    for f in findings:
        rule = get_rule_by_id(f.rule_id)
        items.append({
            "id": f.id,
            "rule_id": f.rule_id,
            "rule_name": rule.name if rule else f.rule_id,
            "domain": f.domain,
            "severity": f.severity,
            "status": f.status,
            "provider": f.provider,
            "account_id": f.account_id,
            "resource_count": f.resource_count,
            "failed_resources": f.failed_resources,
            "finding_status": f.finding_status,
            "assigned_to": f.assigned_to,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/findings/{finding_id}")
async def get_rr_finding_detail(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get detailed view of a single RR finding."""
    result = await db.execute(
        select(RRFinding).where(RRFinding.id == finding_id, RRFinding.user_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    rule = get_rule_by_id(finding.rule_id)
    evidence = json.loads(finding.evidence) if finding.evidence else {}

    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "rule_name": rule.name if rule else finding.rule_id,
        "rule_description": rule.description if rule else "",
        "ransomware_context": rule.ransomware_context if rule else "",
        "domain": finding.domain,
        "severity": finding.severity,
        "status": finding.status,
        "provider": finding.provider,
        "account_id": finding.account_id,
        "resource_count": finding.resource_count,
        "passed_resources": finding.passed_resources,
        "failed_resources": finding.failed_resources,
        "evidence": evidence,
        "finding_status": finding.finding_status,
        "assigned_to": finding.assigned_to,
        "notes": finding.notes,
        "ticket_url": finding.ticket_url,
        "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "nist_mapping": {
            "category": rule.nist_category if rule else "",
            "subcategory": rule.nist_subcategory if rule else "",
        },
        "remediation": rule.remediation if rule else {},
        "cloud_providers": rule.cloud_providers if rule else [],
    }


@router.patch("/findings/{finding_id}")
async def update_rr_finding(
    finding_id: str,
    update: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update finding status (accept, exception, resolve) or assign."""
    result = await db.execute(
        select(RRFinding).where(RRFinding.id == finding_id, RRFinding.user_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if update.finding_status is not None:
        if update.finding_status not in ("open", "accepted", "exception", "resolved"):
            raise HTTPException(status_code=400, detail="Invalid finding_status")
        finding.finding_status = update.finding_status
        if update.finding_status == "resolved":
            finding.resolved_at = datetime.utcnow()
    if update.assigned_to is not None:
        finding.assigned_to = update.assigned_to
    if update.notes is not None:
        finding.notes = update.notes
    if update.ticket_url is not None:
        finding.ticket_url = update.ticket_url

    await db.commit()
    return {"status": "updated", "id": finding_id}


# ── Account endpoints ────────────────────────────────────────

@router.get("/accounts")
async def get_rr_accounts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get RR score per cloud account."""
    providers_q = select(Provider).where(Provider.user_id == current_user.id)
    providers_result = await db.execute(providers_q)
    providers = providers_result.scalars().all()

    accounts = []
    for p in providers:
        score_q = (
            select(RRScore)
            .where(RRScore.user_id == current_user.id, RRScore.scope == "account", RRScore.scope_id == p.id)
            .order_by(desc(RRScore.calculated_at)).limit(1)
        )
        score_result = await db.execute(score_q)
        score = score_result.scalar_one_or_none()

        accounts.append({
            "id": p.id,
            "provider": p.provider_type,
            "alias": p.alias,
            "account_id": p.account_id,
            "score": score.score if score else 0,
            "level": score.level if score else "Critico",
            "checks_passed": score.checks_passed if score else 0,
            "checks_failed": score.checks_failed if score else 0,
            "domain_scores": json.loads(score.domain_scores) if score and score.domain_scores else {},
        })

    return accounts


@router.get("/accounts/{account_id}")
async def get_rr_account_detail(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Detailed RR view for a specific cloud account."""
    # Verify provider
    result = await db.execute(
        select(Provider).where(Provider.id == account_id, Provider.user_id == current_user.id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Account not found")

    # Latest score
    score_q = (
        select(RRScore)
        .where(RRScore.user_id == current_user.id, RRScore.scope == "account", RRScore.scope_id == account_id)
        .order_by(desc(RRScore.calculated_at)).limit(1)
    )
    score = (await db.execute(score_q)).scalar_one_or_none()

    # Findings for this account
    findings_q = (
        select(RRFinding)
        .where(RRFinding.user_id == current_user.id, RRFinding.account_id == account_id)
        .order_by(desc(RRFinding.created_at))
        .limit(100)
    )
    findings = (await db.execute(findings_q)).scalars().all()

    findings_list = []
    for f in findings:
        rule = get_rule_by_id(f.rule_id)
        findings_list.append({
            "id": f.id,
            "rule_id": f.rule_id,
            "rule_name": rule.name if rule else f.rule_id,
            "domain": f.domain,
            "severity": f.severity,
            "status": f.status,
            "finding_status": f.finding_status,
            "failed_resources": f.failed_resources,
        })

    return {
        "account": {
            "id": provider.id,
            "provider": provider.provider_type,
            "alias": provider.alias,
            "account_id": provider.account_id,
        },
        "score": score.score if score else 0,
        "level": score.level if score else "Critico",
        "domain_scores": json.loads(score.domain_scores) if score and score.domain_scores else {},
        "findings": findings_list,
    }


# ── Rules catalog ────────────────────────────────────────────

@router.get("/rules")
async def get_rr_rules(
    domain: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
):
    """Get the complete rule catalog with metadata."""
    all_rules = get_all_rules()

    if domain:
        all_rules = [r for r in all_rules if r.domain.value == domain]
    if severity:
        all_rules = [r for r in all_rules if r.severity.value == severity]
    if provider:
        all_rules = [r for r in all_rules if provider in r.cloud_providers]

    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "ransomware_context": r.ransomware_context,
            "domain": r.domain.value,
            "severity": r.severity.value,
            "cloud_providers": r.cloud_providers,
            "resource_types": r.resource_types,
            "nist_category": r.nist_category,
            "nist_subcategory": r.nist_subcategory,
            "is_manual": r.is_manual,
            "is_composite": r.is_composite,
            "remediation": r.remediation,
        }
        for r in all_rules
    ]


# ── Governance endpoints ─────────────────────────────────────

@router.get("/governance")
async def get_governance(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current governance/manual inputs."""
    result = await db.execute(
        select(RRGovernance).where(RRGovernance.user_id == current_user.id)
    )
    gov = result.scalar_one_or_none()

    if not gov:
        return {
            "ransomware_response_plan": False,
            "last_tabletop_exercise_date": None,
            "security_training_completion": None,
            "ir_roles_defined": False,
            "communication_plan_exists": False,
            "rto_rpo_documented": False,
            "backup_restore_tested": False,
            "dr_plan_documented": False,
            "iac_scanning_integrated": False,
            "siem_integration_configured": False,
            "notes": None,
            "updated_at": None,
        }

    return {
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
        "notes": gov.notes,
        "updated_at": gov.updated_at.isoformat() if gov.updated_at else None,
    }


@router.put("/governance")
async def update_governance(
    data: GovernanceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update governance/manual inputs."""
    result = await db.execute(
        select(RRGovernance).where(RRGovernance.user_id == current_user.id)
    )
    gov = result.scalar_one_or_none()

    if not gov:
        gov = RRGovernance(user_id=current_user.id)
        db.add(gov)

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "last_tabletop_exercise_date" and value is not None:
            try:
                value = datetime.fromisoformat(value)
            except (ValueError, TypeError):
                continue
        setattr(gov, field, value)

    gov.updated_at = datetime.utcnow()
    await db.commit()
    return {"status": "updated"}


# ── Evaluate endpoint ────────────────────────────────────────

@router.post("/evaluate")
async def trigger_evaluation(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger a manual RR evaluation using latest scan data."""
    from api.tasks.rr_tasks import evaluate_ransomware_readiness
    from api.celery_app import celery_app

    task = celery_app.send_task(
        "api.tasks.rr_tasks.evaluate_ransomware_readiness",
        args=[current_user.id],
    )

    return {"status": "evaluation_started", "task_id": task.id}
