"""Dashboard router."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.models.scan import Scan
from api.models.finding import Finding
from api.models.saas_connection import SaaSConnection
from api.models.saas_finding import SaaSFinding
from api.services.auth_service import get_current_user

router = APIRouter()


@router.get("/overview")
async def dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    providers_count = await db.execute(
        select(func.count(Provider.id)).where(Provider.user_id == current_user.id)
    )
    saas_count = await db.execute(
        select(func.count(SaaSConnection.id)).where(SaaSConnection.user_id == current_user.id)
    )
    scans_count = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    )

    cloud_findings = await db.execute(
        select(Finding.severity, Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(Finding.severity, Finding.status)
    )
    saas_findings = await db.execute(
        select(SaaSFinding.severity, SaaSFinding.status, func.count(SaaSFinding.id))
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(SaaSFinding.severity, SaaSFinding.status)
    )

    severity_breakdown = {}
    total_findings = 0
    passed = 0
    for severity, f_status, count in list(cloud_findings.all()) + list(saas_findings.all()):
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + count
        total_findings += count
        if f_status == "PASS":
            passed += count

    recent_scans_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    recent_scans = [
        {
            "id": s.id,
            "scan_type": s.scan_type,
            "status": s.status,
            "progress": s.progress,
            "total_checks": s.total_checks,
            "passed_checks": s.passed_checks,
            "failed_checks": s.failed_checks,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in recent_scans_result.scalars().all()
    ]

    by_provider_q = await db.execute(
        select(Finding.service, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(Finding.service)
        .order_by(func.count(Finding.id).desc())
        .limit(15)
    )
    findings_by_service = {r[0]: r[1] for r in by_provider_q.all()}

    return {
        "total_cloud_providers": providers_count.scalar() or 0,
        "total_saas_connections": saas_count.scalar() or 0,
        "total_scans": scans_count.scalar() or 0,
        "total_findings": total_findings,
        "pass_rate": round((passed / total_findings * 100) if total_findings > 0 else 0, 1),
        "severity_breakdown": severity_breakdown,
        "findings_by_service": findings_by_service,
        "recent_scans": recent_scans,
    }
