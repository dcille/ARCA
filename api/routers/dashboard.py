"""Dashboard router."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case

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


@router.get("/trends")
async def dashboard_trends(
    days: int = Query(default=30, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get scan history and finding trends over time."""
    since = datetime.utcnow() - timedelta(days=days)

    # Get completed scans with stats
    scans_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .where(Scan.status == "completed")
        .where(Scan.created_at >= since)
        .order_by(Scan.created_at.asc())
    )
    scans = scans_result.scalars().all()

    scan_history = []
    for s in scans:
        total = s.total_checks or 0
        passed = s.passed_checks or 0
        rate = round((passed / total * 100) if total > 0 else 0, 1)
        scan_history.append({
            "date": s.created_at.strftime("%Y-%m-%d") if s.created_at else "",
            "total_checks": total,
            "passed": passed,
            "failed": s.failed_checks or 0,
            "pass_rate": rate,
            "scan_type": s.scan_type,
        })

    # Finding severity trends - group by date
    findings_result = await db.execute(
        select(
            func.date(Finding.created_at).label("date"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.created_at >= since)
        .group_by(func.date(Finding.created_at), Finding.severity)
        .order_by(func.date(Finding.created_at))
    )
    findings_by_date: dict[str, dict] = {}
    for row in findings_result.all():
        date_str = str(row.date)
        if date_str not in findings_by_date:
            findings_by_date[date_str] = {"date": date_str, "critical": 0, "high": 0, "medium": 0, "low": 0}
        findings_by_date[date_str][row.severity] = row.count

    return {
        "scan_history": scan_history,
        "findings_trend": list(findings_by_date.values()),
    }
