"""Audit logging service for recording user actions."""
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from api.models.audit_log import AuditLog


async def record_audit(
    db: AsyncSession,
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
):
    """Record an audit log entry.

    Actions: login, logout, create, update, delete, scan, export, download, view
    Resource types: provider, scan, schedule, integration, finding, report, organization, user, saas_connection
    """
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(log)
    await db.commit()
    return log
