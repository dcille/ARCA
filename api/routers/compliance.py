"""Compliance router."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.scan import Scan
from api.services.auth_service import get_current_user
from scanner.compliance.frameworks import FRAMEWORKS, get_frameworks_for_check

router = APIRouter()

COMPLIANCE_FRAMEWORKS = {
    fw_id: {"name": fw["name"], "description": fw["description"]}
    for fw_id, fw in FRAMEWORKS.items()
}


def _framework_filter(framework_id: str):
    """Build SQLAlchemy filter for a compliance framework.

    Frameworks with checks="all" match ALL findings.
    Frameworks with a specific check list use check_id IN (...) OR
    compliance_frameworks LIKE '%framework_id%' for backward compat.
    """
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        return None

    checks = fw.get("checks", [])
    if checks in ("all", "all_saas"):
        # Match all findings
        return None  # No additional filter needed
    elif isinstance(checks, list) and checks:
        # Match by check_id list OR by compliance_frameworks string containing framework_id
        return or_(
            Finding.check_id.in_(checks),
            Finding.compliance_frameworks.contains(framework_id),
        )
    else:
        return Finding.compliance_frameworks.contains(framework_id)


@router.get("/frameworks")
async def list_frameworks():
    return [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in COMPLIANCE_FRAMEWORKS.items()
    ]


@router.get("/summary")
async def compliance_summary(
    framework: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        select(Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if framework:
        fw_filter = _framework_filter(framework)
        if fw_filter is not None:
            query = query.where(fw_filter)
    query = query.group_by(Finding.status)

    result = await db.execute(query)
    counts = {row[0]: row[1] for row in result.all()}

    passed = counts.get("PASS", 0)
    failed = counts.get("FAIL", 0)
    total = passed + failed
    pass_rate = (passed / total * 100) if total > 0 else 0

    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(pass_rate, 1),
    }


@router.get("/frameworks/{framework_id}/checks")
async def framework_checks(
    framework_id: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=200, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if framework_id not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    base_filter = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    fw_filter = _framework_filter(framework_id)
    if fw_filter is not None:
        base_filter = base_filter.where(fw_filter)

    if status:
        base_filter = base_filter.where(Finding.status == status.upper())
    if severity:
        base_filter = base_filter.where(Finding.severity == severity.lower())

    # Get summary stats (unfiltered by status/severity for the totals)
    stats_query = (
        select(Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if fw_filter is not None:
        stats_query = stats_query.where(fw_filter)
    stats_query = stats_query.group_by(Finding.status)

    stats_result = await db.execute(stats_query)
    stats_counts = {row[0]: row[1] for row in stats_result.all()}
    passed = stats_counts.get("PASS", 0)
    failed = stats_counts.get("FAIL", 0)
    total = passed + failed
    pass_rate = (passed / total * 100) if total > 0 else 0

    # Get paginated findings
    query = base_filter.order_by(Finding.severity, Finding.status).offset(offset).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()

    from scanner.mitre.attack_mapping import CHECK_DESCRIPTIONS, CHECK_EVIDENCE

    return {
        "framework": {
            "id": framework_id,
            "name": COMPLIANCE_FRAMEWORKS[framework_id]["name"],
            "description": COMPLIANCE_FRAMEWORKS[framework_id]["description"],
        },
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(pass_rate, 1),
        },
        "findings": [
            {
                "id": f.id,
                "check_id": f.check_id,
                "check_title": f.check_title,
                "service": f.service,
                "severity": f.severity,
                "status": f.status,
                "region": f.region,
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "status_extended": f.status_extended,
                "remediation": f.remediation,
                "remediation_url": f.remediation_url,
                "check_description": f.check_description or CHECK_DESCRIPTIONS.get(f.check_id, ""),
                "evidence_log": f.evidence_log or CHECK_EVIDENCE.get(f.check_id, ""),
                "mitre_techniques": f.mitre_techniques,
            }
            for f in findings
        ],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
    }


@router.get("/frameworks/{framework_id}/stats")
async def framework_stats(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if framework_id not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    query = (
        select(
            Finding.service,
            Finding.status,
            func.count(Finding.id),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    fw_filter = _framework_filter(framework_id)
    if fw_filter is not None:
        query = query.where(fw_filter)
    query = query.group_by(Finding.service, Finding.status)

    result = await db.execute(query)
    rows = result.all()

    services: dict = {}
    for service, status, count in rows:
        if service not in services:
            services[service] = {"service": service, "passed": 0, "failed": 0, "total": 0}
        if status == "PASS":
            services[service]["passed"] = count
        elif status == "FAIL":
            services[service]["failed"] = count
        services[service]["total"] = services[service]["passed"] + services[service]["failed"]

    return {
        "framework_id": framework_id,
        "services": list(services.values()),
    }


@router.get("/frameworks/{framework_id}/library")
async def framework_check_library(
    framework_id: str,
    current_user: User = Depends(get_current_user),
):
    """Return the full check library for a compliance framework with descriptions."""
    if framework_id not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    from scanner.mitre.attack_mapping import CHECK_DESCRIPTIONS, CHECK_EVIDENCE

    fw = FRAMEWORKS.get(framework_id, {})
    checks_def = fw.get("checks", [])

    # For "all" frameworks, gather all known check IDs
    if checks_def in ("all", "all_saas"):
        check_ids = sorted(CHECK_DESCRIPTIONS.keys())
    elif isinstance(checks_def, list):
        check_ids = checks_def
    else:
        check_ids = []

    library = []
    for check_id in check_ids:
        library.append({
            "check_id": check_id,
            "description": CHECK_DESCRIPTIONS.get(check_id, "Security check for " + check_id.replace("_", " ")),
            "evidence_method": CHECK_EVIDENCE.get(check_id, ""),
        })

    return {
        "framework": {
            "id": framework_id,
            "name": COMPLIANCE_FRAMEWORKS[framework_id]["name"],
            "description": COMPLIANCE_FRAMEWORKS[framework_id]["description"],
        },
        "total_checks": len(library),
        "checks": library,
    }
