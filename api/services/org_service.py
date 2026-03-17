"""Organization service for multi-tenancy data scoping."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.models.user import User


async def get_org_user_ids(db: AsyncSession, user: User) -> list[str]:
    """Get all user IDs in the same organization for data scoping."""
    if not user.organization_id:
        return [user.id]
    result = await db.execute(
        select(User.id).where(User.organization_id == user.organization_id)
    )
    return [r[0] for r in result.all()]
