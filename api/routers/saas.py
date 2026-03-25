"""SaaS Security router - ServiceNow, M365, Salesforce, Snowflake."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.saas_connection import SaaSConnection
from api.models.saas_finding import SaaSFinding
from api.models.scan import Scan
from api.schemas.saas import (
    SaaSConnectionCreate,
    SaaSConnectionResponse,
    SaaSFindingResponse,
    SaaSOverview,
    ServiceNowCredentials,
    M365Credentials,
    SalesforceCredentials,
    SnowflakeCredentials,
    GitHubCredentials,
    GoogleWorkspaceCredentials,
    CloudflareCredentials,
    OpenStackCredentials,
)
from api.services.auth_service import get_current_user, encrypt_credentials

router = APIRouter()

VALID_SAAS_PROVIDERS = ("servicenow", "m365", "salesforce", "snowflake", "github", "google_workspace", "cloudflare", "openstack")

# Lazy cache for registry check counts
_registry_check_counts: dict[str, int] | None = None


def _get_registry_check_counts() -> dict[str, int]:
    """Load check counts per SaaS provider from the check registry."""
    global _registry_check_counts
    if _registry_check_counts is not None:
        return _registry_check_counts

    counts: dict[str, int] = {}
    try:
        from scanner.registry.definitions import (
            servicenow_checks, m365_checks, salesforce_checks, snowflake_checks,
            github_checks, google_workspace_checks, cloudflare_checks, openstack_checks,
        )
        provider_modules = {
            "servicenow": servicenow_checks,
            "m365": m365_checks,
            "salesforce": salesforce_checks,
            "snowflake": snowflake_checks,
            "github": github_checks,
            "google_workspace": google_workspace_checks,
            "cloudflare": cloudflare_checks,
            "openstack": openstack_checks,
        }
        for provider_id, mod in provider_modules.items():
            counts[provider_id] = len(mod.get_checks())
    except Exception:
        # Fallback if registry not available
        pass
    _registry_check_counts = counts
    return counts

CREDENTIAL_VALIDATORS = {
    "servicenow": ServiceNowCredentials,
    "m365": M365Credentials,
    "salesforce": SalesforceCredentials,
    "snowflake": SnowflakeCredentials,
    "github": GitHubCredentials,
    "google_workspace": GoogleWorkspaceCredentials,
    "cloudflare": CloudflareCredentials,
    "openstack": OpenStackCredentials,
}


@router.get("/connections", response_model=list[SaaSConnectionResponse])
async def list_connections(
    provider_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(SaaSConnection).where(SaaSConnection.user_id == current_user.id)
    if provider_type:
        query = query.where(SaaSConnection.provider_type == provider_type)
    query = query.order_by(SaaSConnection.created_at.desc())
    result = await db.execute(query)
    return [SaaSConnectionResponse.model_validate(c) for c in result.scalars().all()]


@router.post("/connections", response_model=SaaSConnectionResponse, status_code=status.HTTP_201_CREATED)
async def create_connection(
    data: SaaSConnectionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.provider_type not in VALID_SAAS_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Invalid SaaS provider. Must be one of: {VALID_SAAS_PROVIDERS}")

    validator = CREDENTIAL_VALIDATORS[data.provider_type]
    try:
        validator(**data.credentials)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid credentials format: {str(e)}")

    connection = SaaSConnection(
        user_id=current_user.id,
        provider_type=data.provider_type,
        alias=data.alias,
        credentials_encrypted=encrypt_credentials(data.credentials),
    )
    db.add(connection)
    await db.commit()
    await db.refresh(connection)
    return SaaSConnectionResponse.model_validate(connection)


@router.get("/connections/{connection_id}", response_model=SaaSConnectionResponse)
async def get_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SaaSConnection).where(
            SaaSConnection.id == connection_id,
            SaaSConnection.user_id == current_user.id,
        )
    )
    conn = result.scalar_one_or_none()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return SaaSConnectionResponse.model_validate(conn)


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SaaSConnection).where(
            SaaSConnection.id == connection_id,
            SaaSConnection.user_id == current_user.id,
        )
    )
    conn = result.scalar_one_or_none()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    await db.delete(conn)
    await db.commit()


@router.post("/connections/{connection_id}/test")
async def test_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SaaSConnection).where(
            SaaSConnection.id == connection_id,
            SaaSConnection.user_id == current_user.id,
        )
    )
    conn = result.scalar_one_or_none()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")

    from api.services.auth_service import decrypt_credentials
    creds = decrypt_credentials(conn.credentials_encrypted)

    from scanner.saas.connection_tester import test_saas_connection
    success, message = await test_saas_connection(conn.provider_type, creds)

    if success:
        conn.status = "connected"
    else:
        conn.status = "error"
    await db.commit()

    return {"success": success, "message": message, "status": conn.status}


@router.get("/findings", response_model=list[SaaSFindingResponse])
async def list_saas_findings(
    provider_type: Optional[str] = None,
    severity: Optional[str] = None,
    check_status: Optional[str] = None,
    service_area: Optional[str] = None,
    connection_id: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        select(SaaSFinding)
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if provider_type:
        query = query.where(SaaSFinding.provider_type == provider_type)
    if severity:
        query = query.where(SaaSFinding.severity == severity)
    if check_status:
        query = query.where(SaaSFinding.status == check_status)
    if service_area:
        query = query.where(SaaSFinding.service_area == service_area)
    if connection_id:
        query = query.where(SaaSFinding.connection_id == connection_id)

    query = query.order_by(SaaSFinding.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return [SaaSFindingResponse.model_validate(f) for f in result.scalars().all()]


@router.get("/overview", response_model=SaaSOverview)
async def saas_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    connections_result = await db.execute(
        select(func.count(SaaSConnection.id)).where(SaaSConnection.user_id == current_user.id)
    )
    total_connections = connections_result.scalar() or 0

    active_scans_result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.user_id == current_user.id,
            Scan.scan_type == "saas",
            Scan.status == "running",
        )
    )
    active_scans = active_scans_result.scalar() or 0

    findings_query = (
        select(SaaSFinding.severity, SaaSFinding.status, func.count(SaaSFinding.id))
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(SaaSFinding.severity, SaaSFinding.status)
    )
    findings_result = await db.execute(findings_query)
    findings_rows = findings_result.all()

    severity_counts = {}
    total_findings = 0
    passed = 0
    for severity, f_status, count in findings_rows:
        severity_counts[severity] = severity_counts.get(severity, 0) + count
        total_findings += count
        if f_status == "PASS":
            passed += count

    by_provider_query = await db.execute(
        select(SaaSFinding.provider_type, SaaSFinding.status, func.count(SaaSFinding.id))
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(SaaSFinding.provider_type, SaaSFinding.status)
    )
    by_provider = {}
    for ptype, f_status, count in by_provider_query.all():
        if ptype not in by_provider:
            by_provider[ptype] = {"total": 0, "passed": 0, "failed": 0}
        by_provider[ptype]["total"] += count
        if f_status == "PASS":
            by_provider[ptype]["passed"] += count
        else:
            by_provider[ptype]["failed"] += count

    return SaaSOverview(
        total_connections=total_connections,
        active_scans=active_scans,
        total_findings=total_findings,
        critical_findings=severity_counts.get("critical", 0),
        high_findings=severity_counts.get("high", 0),
        medium_findings=severity_counts.get("medium", 0),
        low_findings=severity_counts.get("low", 0),
        pass_rate=round((passed / total_findings * 100) if total_findings > 0 else 0, 1),
        by_provider=by_provider,
        registry_check_counts=_get_registry_check_counts(),
    )


@router.get("/findings/stats")
async def saas_findings_stats(
    provider_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base = (
        select(SaaSFinding)
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if provider_type:
        base = base.where(SaaSFinding.provider_type == provider_type)

    severity_q = await db.execute(
        select(SaaSFinding.severity, func.count(SaaSFinding.id))
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(SaaSFinding.severity)
    )
    severity_breakdown = {r[0]: r[1] for r in severity_q.all()}

    area_q = await db.execute(
        select(SaaSFinding.service_area, func.count(SaaSFinding.id))
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(SaaSFinding.service_area)
        .order_by(func.count(SaaSFinding.id).desc())
    )
    by_service_area = {r[0]: r[1] for r in area_q.all()}

    return {
        "severity_breakdown": severity_breakdown,
        "by_service_area": by_service_area,
    }
