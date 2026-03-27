"""Scans router."""
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.database import get_db
from api.models.user import User
from api.models.scan import Scan
from api.schemas.scan import ScanCreate, ScanResponse, ScanLogResponse
from api.services.auth_service import get_current_user

router = APIRouter()


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    scan_type: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Scan).where(Scan.user_id == current_user.id)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    query = query.order_by(Scan.created_at.desc())
    result = await db.execute(query)
    return [ScanResponse.model_validate(s) for s in result.scalars().all()]


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    data: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from api.celery_app import celery_app

    scan = Scan(
        user_id=current_user.id,
        provider_id=data.provider_id,
        connection_id=data.connection_id,
        scan_type=data.scan_type,
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    if data.scan_type == "cloud":
        task = celery_app.send_task(
            "api.tasks.scan_tasks.run_cloud_scan",
            args=[scan.id, data.provider_id],
            kwargs={"services": data.services, "regions": data.regions},
        )
    elif data.scan_type == "saas":
        task = celery_app.send_task(
            "api.tasks.saas_tasks.run_saas_scan",
            args=[scan.id, data.connection_id],
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid scan type")

    scan.task_id = task.id
    await db.commit()
    await db.refresh(scan)
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/logs", response_model=ScanLogResponse)
async def get_scan_logs(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the execution log for a completed scan.

    Shows step-by-step which Python modules were executed and what
    cloud API calls were made during the scan.
    """
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_log = None
    if scan.scan_log:
        try:
            scan_log = json.loads(scan.scan_log)
        except (json.JSONDecodeError, TypeError):
            scan_log = {"raw": scan.scan_log}

    return ScanLogResponse(
        scan_id=scan.id,
        status=scan.status,
        scan_log=scan_log,
    )
