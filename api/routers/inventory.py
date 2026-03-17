"""Asset/Resource Inventory router."""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, distinct, case, literal_column

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.models.scan import Scan
from api.models.finding import Finding
from api.services.auth_service import get_current_user

router = APIRouter()


@router.get("/resources")
async def list_resources(
    provider_type: Optional[str] = None,
    service: Optional[str] = None,
    region: Optional[str] = None,
    status: Optional[str] = Query(None, description="Filter by finding status: at_risk, compliant, all"),
    search: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List unique resources discovered across all scans."""
    # Get the latest finding per resource to get current status
    base_q = (
        select(
            Finding.resource_id,
            Finding.resource_name,
            Finding.service,
            Finding.region,
            Finding.provider_id,
            func.count(Finding.id).label("total_findings"),
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("failed_count"),
            func.sum(case((Finding.status == "PASS", 1), else_=0)).label("passed_count"),
            func.max(Finding.created_at).label("last_seen"),
            func.min(
                case(
                    (Finding.severity == "critical", literal_column("1")),
                    (Finding.severity == "high", literal_column("2")),
                    (Finding.severity == "medium", literal_column("3")),
                    (Finding.severity == "low", literal_column("4")),
                    else_=literal_column("5"),
                )
            ).label("max_severity_rank"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.resource_id.isnot(None))
        .where(Finding.resource_id != "")
    )

    if provider_type:
        base_q = base_q.join(Provider, Finding.provider_id == Provider.id).where(
            Provider.provider_type == provider_type
        )
    if service:
        base_q = base_q.where(Finding.service == service)
    if region:
        base_q = base_q.where(Finding.region == region)
    if search:
        base_q = base_q.where(
            (Finding.resource_name.ilike(f"%{search}%")) |
            (Finding.resource_id.ilike(f"%{search}%"))
        )

    base_q = base_q.group_by(
        Finding.resource_id, Finding.resource_name,
        Finding.service, Finding.region, Finding.provider_id
    )

    if status == "at_risk":
        base_q = base_q.having(func.sum(case((Finding.status == "FAIL", 1), else_=0)) > 0)
    elif status == "compliant":
        base_q = base_q.having(func.sum(case((Finding.status == "FAIL", 1), else_=0)) == 0)

    # Order by severity (worst first), then by failed count
    base_q = base_q.order_by("max_severity_rank", func.sum(case((Finding.status == "FAIL", 1), else_=0)).desc())
    base_q = base_q.offset(offset).limit(limit)

    result = await db.execute(base_q)
    rows = result.all()

    # Get provider info for enrichment
    provider_ids = list(set(r.provider_id for r in rows if r.provider_id))
    providers_map = {}
    if provider_ids:
        prov_result = await db.execute(
            select(Provider).where(Provider.id.in_(provider_ids))
        )
        for p in prov_result.scalars().all():
            providers_map[p.id] = {"provider_type": p.provider_type, "alias": p.alias, "account_id": p.account_id}

    severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "informational"}

    resources = []
    for r in rows:
        provider = providers_map.get(r.provider_id, {})
        resources.append({
            "resource_id": r.resource_id,
            "resource_name": r.resource_name,
            "service": r.service,
            "region": r.region,
            "provider_type": provider.get("provider_type", ""),
            "provider_alias": provider.get("alias", ""),
            "account_id": provider.get("account_id", ""),
            "total_findings": r.total_findings,
            "failed_findings": r.failed_count,
            "passed_findings": r.passed_count,
            "max_severity": severity_map.get(r.max_severity_rank, "informational"),
            "status": "at_risk" if r.failed_count > 0 else "compliant",
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        })

    return resources


@router.get("/resources/{resource_id}/findings")
async def resource_findings(
    resource_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all findings for a specific resource."""
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.resource_id == resource_id)
        .order_by(
            case(
                (Finding.severity == "critical", 1),
                (Finding.severity == "high", 2),
                (Finding.severity == "medium", 3),
                (Finding.severity == "low", 4),
                else_=5,
            ),
            Finding.status.desc(),  # FAIL first
        )
    )

    result = await db.execute(query)
    findings = result.scalars().all()

    return [
        {
            "id": f.id,
            "check_id": f.check_id,
            "check_title": f.check_title,
            "check_description": f.check_description,
            "status": f.status,
            "severity": f.severity,
            "service": f.service,
            "region": f.region,
            "resource_id": f.resource_id,
            "resource_name": f.resource_name,
            "remediation": f.remediation,
            "remediation_url": f.remediation_url,
            "evidence_log": f.evidence_log,
            "status_extended": f.status_extended,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]


@router.get("/summary")
async def inventory_summary(
    provider_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get inventory summary statistics."""
    base_q = (
        select(
            Finding.resource_id,
            Finding.service,
            Finding.region,
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("failed"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.resource_id.isnot(None))
        .where(Finding.resource_id != "")
    )

    if provider_type:
        base_q = base_q.join(Provider, Finding.provider_id == Provider.id).where(
            Provider.provider_type == provider_type
        )

    base_q = base_q.group_by(Finding.resource_id, Finding.service, Finding.region)
    result = await db.execute(base_q)
    rows = result.all()

    total_resources = len(rows)
    at_risk = sum(1 for r in rows if r.failed > 0)
    compliant = total_resources - at_risk

    by_service: dict[str, int] = {}
    by_region: dict[str, int] = {}
    for r in rows:
        by_service[r.service] = by_service.get(r.service, 0) + 1
        if r.region:
            by_region[r.region] = by_region.get(r.region, 0) + 1

    return {
        "total_resources": total_resources,
        "at_risk": at_risk,
        "compliant": compliant,
        "compliance_rate": round((compliant / total_resources * 100) if total_resources > 0 else 0, 1),
        "by_service": dict(sorted(by_service.items(), key=lambda x: x[1], reverse=True)),
        "by_region": dict(sorted(by_region.items(), key=lambda x: x[1], reverse=True)[:15]),
    }
