"""Audit log router - view platform activity history."""
from typing import Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from api.database import get_db
from api.models.user import User
from api.models.audit_log import AuditLog
from api.services.auth_service import get_current_user
from pydantic import BaseModel

router = APIRouter()


class AuditLogResponse(BaseModel):
    id: str
    user_id: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    detail: Optional[str]
    ip_address: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("")
async def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action: create, update, delete, login, scan, export"),
    resource_type: Optional[str] = Query(None, description="Filter by resource: provider, scan, schedule, integration, finding, report"),
    days: int = Query(default=30, le=90, description="Number of days to look back"),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List audit log entries for the current user."""
    since = datetime.utcnow() - timedelta(days=days)

    query = (
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .where(AuditLog.created_at >= since)
    )

    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)

    query = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    return [
        AuditLogResponse(
            id=log.id,
            user_id=log.user_id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            detail=log.detail,
            ip_address=log.ip_address,
            created_at=log.created_at,
        )
        for log in logs
    ]


@router.get("/stats")
async def audit_log_stats(
    days: int = Query(default=30, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get audit log statistics."""
    since = datetime.utcnow() - timedelta(days=days)

    base = select(AuditLog).where(
        AuditLog.user_id == current_user.id,
        AuditLog.created_at >= since,
    )

    # Total count
    total_q = select(func.count(AuditLog.id)).where(
        AuditLog.user_id == current_user.id,
        AuditLog.created_at >= since,
    )
    total = (await db.execute(total_q)).scalar() or 0

    # By action
    action_q = (
        select(AuditLog.action, func.count(AuditLog.id))
        .where(AuditLog.user_id == current_user.id, AuditLog.created_at >= since)
        .group_by(AuditLog.action)
    )
    action_result = await db.execute(action_q)
    by_action = {row[0]: row[1] for row in action_result.all()}

    # By resource_type
    resource_q = (
        select(AuditLog.resource_type, func.count(AuditLog.id))
        .where(AuditLog.user_id == current_user.id, AuditLog.created_at >= since)
        .group_by(AuditLog.resource_type)
    )
    resource_result = await db.execute(resource_q)
    by_resource = {row[0]: row[1] for row in resource_result.all()}

    return {
        "total_events": total,
        "by_action": by_action,
        "by_resource": by_resource,
        "days": days,
    }
