"""Notifications router."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update

from api.database import get_db
from api.models.user import User
from api.models.notification import Notification
from api.services.auth_service import get_current_user
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter()


class NotificationResponse(BaseModel):
    id: str
    title: str
    message: str
    type: str
    severity: Optional[str]
    read: bool
    link: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("")
async def list_notifications(
    unread_only: bool = False,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Notification).where(Notification.user_id == current_user.id)
    if unread_only:
        query = query.where(Notification.read == False)
    query = query.order_by(Notification.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    notifications = result.scalars().all()

    return [
        NotificationResponse(
            id=n.id,
            title=n.title,
            message=n.message,
            type=n.type,
            severity=n.severity,
            read=n.read,
            link=n.link,
            created_at=n.created_at,
        )
        for n in notifications
    ]


@router.get("/count")
async def notification_count(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(func.count(Notification.id))
        .where(Notification.user_id == current_user.id)
        .where(Notification.read == False)
    )
    return {"unread_count": result.scalar() or 0}


@router.put("/{notification_id}/read")
async def mark_read(
    notification_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Notification)
        .where(Notification.id == notification_id, Notification.user_id == current_user.id)
    )
    notif = result.scalar_one_or_none()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.read = True
    await db.commit()
    return {"status": "ok"}


@router.put("/read-all")
async def mark_all_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await db.execute(
        update(Notification)
        .where(Notification.user_id == current_user.id)
        .where(Notification.read == False)
        .values(read=True)
    )
    await db.commit()
    return {"status": "ok"}
