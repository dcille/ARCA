"""Findings router."""
import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.finding_action import FindingAction
from api.models.scan import Scan
from api.models.provider import Provider
from api.schemas.finding import FindingResponse
from api.services.auth_service import get_current_user

EVIDENCE_UPLOAD_DIR = os.environ.get("EVIDENCE_UPLOAD_DIR", "/app/data/evidence")

router = APIRouter()


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    service: Optional[str] = None,
    region: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        select(Finding, Provider.provider_type, Provider.alias)
        .join(Scan, Finding.scan_id == Scan.id)
        .outerjoin(Provider, Finding.provider_id == Provider.id)
        .where(Scan.user_id == current_user.id)
    )
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if service:
        query = query.where(Finding.service == service)
    if region:
        query = query.where(Finding.region == region)

    query = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)

    from scanner.mitre.attack_mapping import CHECK_DESCRIPTIONS, CHECK_EVIDENCE

    findings = []
    for row in result.all():
        finding = row[0]
        provider_type = row[1]
        provider_alias = row[2]
        resp = FindingResponse.model_validate(finding)
        resp.provider_type = provider_type
        resp.provider_alias = provider_alias
        # Fallback to static descriptions/evidence for older findings
        if not resp.check_description:
            resp.check_description = CHECK_DESCRIPTIONS.get(finding.check_id, "")
        if not resp.evidence_log:
            resp.evidence_log = CHECK_EVIDENCE.get(finding.check_id, "")
        findings.append(resp)
    return findings


@router.get("/stats")
async def findings_stats(
    scan_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base_query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if scan_id:
        base_query = base_query.where(Finding.scan_id == scan_id)

    total = await db.execute(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    total_count = total.scalar() or 0

    severity_query = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(Finding.severity)
    )
    severity_breakdown = {row[0]: row[1] for row in severity_query.all()}

    status_query = await db.execute(
        select(Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(Finding.status)
    )
    status_breakdown = {row[0]: row[1] for row in status_query.all()}

    service_query = await db.execute(
        select(Finding.service, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(Finding.service)
        .order_by(func.count(Finding.id).desc())
        .limit(20)
    )
    by_service = {row[0]: row[1] for row in service_query.all()}

    passed = status_breakdown.get("PASS", 0)
    pass_rate = (passed / total_count * 100) if total_count > 0 else 0

    return {
        "total": total_count,
        "pass_rate": round(pass_rate, 1),
        "severity_breakdown": severity_breakdown,
        "status_breakdown": status_breakdown,
        "by_service": by_service,
    }


@router.post("/{finding_id}/exception")
async def create_exception(
    finding_id: str,
    reason: str = Form(...),
    evidence: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create an exception for a finding with optional evidence upload."""
    # Verify finding belongs to user
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.user_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence_file_name = None
    evidence_file_path = None
    if evidence:
        os.makedirs(EVIDENCE_UPLOAD_DIR, exist_ok=True)
        ext = os.path.splitext(evidence.filename or "")[1]
        safe_name = f"{uuid.uuid4()}{ext}"
        file_path = os.path.join(EVIDENCE_UPLOAD_DIR, safe_name)
        content = await evidence.read()
        with open(file_path, "wb") as f:
            f.write(content)
        evidence_file_name = evidence.filename
        evidence_file_path = file_path

    action = FindingAction(
        finding_id=finding_id,
        user_id=current_user.id,
        action_type="exception",
        reason=reason,
        evidence_file_name=evidence_file_name,
        evidence_file_path=evidence_file_path,
    )
    db.add(action)

    # Update finding status to EXCEPTION
    finding.status = "EXCEPTION"
    await db.commit()

    return {
        "id": action.id,
        "finding_id": finding_id,
        "action_type": "exception",
        "reason": reason,
        "evidence_file_name": evidence_file_name,
        "created_at": action.created_at.isoformat(),
    }


@router.post("/{finding_id}/remediate")
async def mark_remediated(
    finding_id: str,
    reason: str = Form(...),
    evidence: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark a finding as manually remediated with explanation."""
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.user_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence_file_name = None
    evidence_file_path = None
    if evidence:
        os.makedirs(EVIDENCE_UPLOAD_DIR, exist_ok=True)
        ext = os.path.splitext(evidence.filename or "")[1]
        safe_name = f"{uuid.uuid4()}{ext}"
        file_path = os.path.join(EVIDENCE_UPLOAD_DIR, safe_name)
        content = await evidence.read()
        with open(file_path, "wb") as f:
            f.write(content)
        evidence_file_name = evidence.filename
        evidence_file_path = file_path

    action = FindingAction(
        finding_id=finding_id,
        user_id=current_user.id,
        action_type="remediated",
        reason=reason,
        evidence_file_name=evidence_file_name,
        evidence_file_path=evidence_file_path,
    )
    db.add(action)

    # Update finding status to REMEDIATED
    finding.status = "REMEDIATED"
    await db.commit()

    return {
        "id": action.id,
        "finding_id": finding_id,
        "action_type": "remediated",
        "reason": reason,
        "evidence_file_name": evidence_file_name,
        "created_at": action.created_at.isoformat(),
    }


@router.get("/{finding_id}/actions")
async def get_finding_actions(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all actions (exceptions, remediations) for a finding."""
    # Verify finding belongs to user
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.user_id == current_user.id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Finding not found")

    result = await db.execute(
        select(FindingAction)
        .where(FindingAction.finding_id == finding_id)
        .order_by(FindingAction.created_at.desc())
    )
    actions = result.scalars().all()

    return [
        {
            "id": a.id,
            "action_type": a.action_type,
            "reason": a.reason,
            "evidence_file_name": a.evidence_file_name,
            "created_at": a.created_at.isoformat(),
        }
        for a in actions
    ]
