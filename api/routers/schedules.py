"""Scan schedules router."""
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.database import get_db
from api.models.user import User
from api.models.scan_schedule import ScanSchedule
from api.services.auth_service import get_current_user
from pydantic import BaseModel

router = APIRouter()

FREQUENCY_DELTAS = {
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
}


class ScheduleCreate(BaseModel):
    provider_id: Optional[str] = None
    connection_id: Optional[str] = None
    scan_type: str = "cloud"
    name: str
    frequency: str  # daily, weekly, monthly
    services: Optional[list[str]] = None
    regions: Optional[list[str]] = None


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    frequency: Optional[str] = None
    enabled: Optional[bool] = None
    services: Optional[list[str]] = None
    regions: Optional[list[str]] = None


class ScheduleResponse(BaseModel):
    id: str
    scan_type: str
    name: str
    frequency: str
    enabled: bool
    provider_id: Optional[str]
    connection_id: Optional[str]
    services: Optional[list[str]] = None
    regions: Optional[list[str]] = None
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


def _compute_next_run(frequency: str) -> datetime:
    delta = FREQUENCY_DELTAS.get(frequency, timedelta(days=1))
    return datetime.utcnow() + delta


def _model_to_response(s: ScanSchedule) -> ScheduleResponse:
    services = None
    regions = None
    try:
        if s.services:
            services = json.loads(s.services)
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        if s.regions:
            regions = json.loads(s.regions)
    except (json.JSONDecodeError, TypeError):
        pass

    return ScheduleResponse(
        id=s.id,
        scan_type=s.scan_type,
        name=s.name,
        frequency=s.frequency,
        enabled=s.enabled,
        provider_id=s.provider_id,
        connection_id=s.connection_id,
        services=services,
        regions=regions,
        last_run_at=s.last_run_at,
        next_run_at=s.next_run_at,
        created_at=s.created_at,
    )


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.user_id == current_user.id)
        .order_by(ScanSchedule.created_at.desc())
    )
    return [_model_to_response(s) for s in result.scalars().all()]


@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    data: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.frequency not in FREQUENCY_DELTAS:
        raise HTTPException(status_code=400, detail="Frequency must be daily, weekly, or monthly")

    schedule = ScanSchedule(
        user_id=current_user.id,
        provider_id=data.provider_id,
        connection_id=data.connection_id,
        scan_type=data.scan_type,
        name=data.name,
        frequency=data.frequency,
        services=json.dumps(data.services) if data.services else None,
        regions=json.dumps(data.regions) if data.regions else None,
        enabled=True,
        next_run_at=_compute_next_run(data.frequency),
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return _model_to_response(schedule)


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: str,
    data: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.id == schedule_id, ScanSchedule.user_id == current_user.id)
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if data.name is not None:
        schedule.name = data.name
    if data.frequency is not None:
        if data.frequency not in FREQUENCY_DELTAS:
            raise HTTPException(status_code=400, detail="Invalid frequency")
        schedule.frequency = data.frequency
        schedule.next_run_at = _compute_next_run(data.frequency)
    if data.enabled is not None:
        schedule.enabled = data.enabled
    if data.services is not None:
        schedule.services = json.dumps(data.services)
    if data.regions is not None:
        schedule.regions = json.dumps(data.regions)

    await db.commit()
    await db.refresh(schedule)
    return _model_to_response(schedule)


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.id == schedule_id, ScanSchedule.user_id == current_user.id)
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await db.delete(schedule)
    await db.commit()
