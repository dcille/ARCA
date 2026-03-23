"""Dashboard router."""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
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


@router.get("/account/{provider_id}")
async def account_dashboard(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Per-account dashboard with posture, inventory, frameworks, findings, MITRE, attack paths, trends."""

    # Verify provider belongs to user
    result = await db.execute(
        select(Provider).where(Provider.id == provider_id, Provider.user_id == current_user.id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    # ── General Posture ──────────────────────────────────────────
    findings_q = (
        select(Finding.severity, Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.provider_id == provider_id)
        .group_by(Finding.severity, Finding.status)
    )
    findings_rows = (await db.execute(findings_q)).all()

    severity_breakdown = {}
    total = 0
    passed = 0
    for severity, status, count in findings_rows:
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + count
        total += count
        if status == "PASS":
            passed += count

    pass_rate = round((passed / total * 100) if total > 0 else 0, 1)

    # ── Inventory Summary ────────────────────────────────────────
    services_q = (
        select(Finding.service, func.count(func.distinct(Finding.resource_id)))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.provider_id == provider_id)
        .group_by(Finding.service)
        .order_by(func.count(func.distinct(Finding.resource_id)).desc())
    )
    services_rows = (await db.execute(services_q)).all()
    inventory = [{"service": s, "resource_count": c} for s, c in services_rows]

    # ── Applicable Frameworks ────────────────────────────────────
    from scanner.compliance.frameworks import FRAMEWORKS, get_framework_providers, get_checks_for_framework_by_provider
    applicable_frameworks = []
    for fw_id, fw in FRAMEWORKS.items():
        fw_providers = get_framework_providers(fw_id)
        if provider.provider_type in fw_providers:
            checks = get_checks_for_framework_by_provider(fw_id, provider.provider_type)
            applicable_frameworks.append({
                "id": fw_id,
                "name": fw["name"],
                "total_checks": len(checks),
            })

    # ── Top Findings ─────────────────────────────────────────────
    top_findings_q = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.provider_id == provider_id, Finding.status == "FAIL")
        .order_by(
            case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                else_=4,
            )
        )
        .limit(10)
    )
    top_findings_rows = (await db.execute(top_findings_q)).scalars().all()
    top_findings = [
        {
            "id": f.id,
            "check_title": f.check_title,
            "severity": f.severity,
            "service": f.service,
            "resource_id": f.resource_id,
            "resource_name": f.resource_name,
        }
        for f in top_findings_rows
    ]

    # ── MITRE ATT&CK Summary ────────────────────────────────────
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE
    mitre_hits: dict[str, int] = {}
    for f in top_findings_rows:
        for tid in CHECK_TO_MITRE.get(f.check_id, []):
            mitre_hits[tid] = mitre_hits.get(tid, 0) + 1

    mitre_summary = [
        {"id": tid, "name": MITRE_TECHNIQUES.get(tid, {}).get("name", tid), "finding_count": count}
        for tid, count in sorted(mitre_hits.items(), key=lambda x: -x[1])[:10]
    ]

    # ── Scan History Trends ──────────────────────────────────────
    since = datetime.utcnow() - timedelta(days=30)
    scans_q = (
        select(Scan)
        .where(Scan.user_id == current_user.id, Scan.provider_id == provider_id, Scan.status == "completed", Scan.created_at >= since)
        .order_by(Scan.created_at.asc())
    )
    scans_rows = (await db.execute(scans_q)).scalars().all()
    scan_trends = [
        {
            "date": s.created_at.strftime("%Y-%m-%d") if s.created_at else "",
            "total_checks": s.total_checks or 0,
            "passed": s.passed_checks or 0,
            "failed": s.failed_checks or 0,
            "pass_rate": round(((s.passed_checks or 0) / (s.total_checks or 1)) * 100, 1),
        }
        for s in scans_rows
    ]

    # ── AI Security Summary ──────────────────────────────────────
    critical_count = severity_breakdown.get("critical", 0)
    high_count = severity_breakdown.get("high", 0)
    medium_count = severity_breakdown.get("medium", 0)
    failed_count = total - passed

    risk_level = "Critical" if critical_count > 0 else "High" if high_count > 5 else "Medium" if high_count > 0 else "Low"

    top_services_at_risk = [f["service"] for f in top_findings[:5]]
    unique_services = list(dict.fromkeys(top_services_at_risk))

    recommendations = []
    if critical_count > 0:
        recommendations.append(f"URGENT: Address {critical_count} critical finding(s) immediately — these represent active exploitability or data exposure risks.")
    if high_count > 0:
        recommendations.append(f"Prioritize remediation of {high_count} high-severity finding(s) within the next sprint cycle.")
    if unique_services:
        recommendations.append(f"Focus security hardening on: {', '.join(unique_services[:3])} — these services have the most failed checks.")
    if pass_rate < 70:
        recommendations.append(f"Overall posture is below acceptable threshold ({pass_rate}%). Consider a comprehensive security review.")
    if len(applicable_frameworks) > 0:
        recommendations.append(f"This account maps to {len(applicable_frameworks)} compliance framework(s). Run compliance assessments regularly.")
    if not recommendations:
        recommendations.append("Security posture is healthy. Continue monitoring and maintain current configurations.")

    ai_summary = {
        "risk_level": risk_level,
        "summary": f"This {provider.provider_type.upper()} account ({provider.alias}) has {total} total findings with a {pass_rate}% pass rate. "
                   f"There are {critical_count} critical, {high_count} high, and {medium_count} medium severity issues. "
                   f"{'Immediate action is required.' if critical_count > 0 else 'The posture is generally acceptable but can be improved.' if failed_count > 0 else 'All checks are passing.'}",
        "recommendations": recommendations,
    }

    return {
        "provider": {
            "id": provider.id,
            "provider_type": provider.provider_type,
            "alias": provider.alias,
            "account_id": provider.account_id,
            "region": provider.region,
            "status": provider.status,
        },
        "posture": {
            "total_findings": total,
            "passed": passed,
            "failed": failed_count,
            "pass_rate": pass_rate,
            "severity_breakdown": severity_breakdown,
        },
        "inventory": inventory,
        "applicable_frameworks": applicable_frameworks,
        "top_findings": top_findings,
        "mitre_summary": mitre_summary,
        "scan_trends": scan_trends,
        "ai_summary": ai_summary,
    }
