"""Findings router."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.scan import Scan
from api.schemas.finding import FindingResponse
from api.services.auth_service import get_current_user

router = APIRouter()


@router.get("/", response_model=list[FindingResponse])
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
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
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
    return [FindingResponse.model_validate(f) for f in result.scalars().all()]


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
