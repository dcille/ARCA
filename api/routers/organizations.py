"""Organizations router for multi-tenancy support."""
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from datetime import datetime

from api.database import get_db
from api.models.user import User
from api.models.organization import Organization
from api.services.auth_service import get_current_user

router = APIRouter()


# ---------- Schemas ----------

class OrganizationCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    plan: str = "free"


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    plan: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    plan: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MemberResponse(BaseModel):
    id: str
    email: str
    name: str
    org_role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class InviteMember(BaseModel):
    email: str
    org_role: str = "member"


class UpdateMemberRole(BaseModel):
    org_role: str


# ---------- Helpers ----------

def _slugify(name: str) -> str:
    """Generate a URL-friendly slug from a name."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")


def _require_org_admin(user: User):
    """Raise 403 if user is not an owner or admin of the organization."""
    if user.org_role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only organization owners and admins can perform this action",
        )


# ---------- Endpoints ----------

@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    data: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new organization. The creator becomes the owner."""
    if current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already belongs to an organization",
        )

    slug = data.slug or _slugify(data.name)

    # Check slug uniqueness
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization with slug '{slug}' already exists",
        )

    org = Organization(
        id=str(uuid.uuid4()),
        name=data.name,
        slug=slug,
        plan=data.plan,
    )
    db.add(org)

    # Make the creator the owner
    current_user.organization_id = org.id
    current_user.org_role = "owner"

    await db.commit()
    await db.refresh(org)
    return OrganizationResponse.model_validate(org)


@router.get("/current", response_model=OrganizationResponse)
async def get_current_organization(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the current user's organization."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not belong to an organization",
        )

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return OrganizationResponse.model_validate(org)


@router.put("/current", response_model=OrganizationResponse)
async def update_current_organization(
    data: OrganizationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update the current user's organization (owner/admin only)."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not belong to an organization",
        )
    _require_org_admin(current_user)

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    if data.name is not None:
        org.name = data.name
    if data.slug is not None:
        # Check slug uniqueness
        existing = await db.execute(
            select(Organization).where(Organization.slug == data.slug, Organization.id != org.id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Organization with slug '{data.slug}' already exists",
            )
        org.slug = data.slug
    if data.plan is not None:
        org.plan = data.plan

    await db.commit()
    await db.refresh(org)
    return OrganizationResponse.model_validate(org)


@router.get("/current/members", response_model=list[MemberResponse])
async def list_members(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all members in the current user's organization."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not belong to an organization",
        )

    result = await db.execute(
        select(User)
        .where(User.organization_id == current_user.organization_id)
        .order_by(User.created_at)
    )
    members = result.scalars().all()
    return [MemberResponse.model_validate(m) for m in members]


@router.post("/current/members/invite", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
async def invite_member(
    data: InviteMember,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Invite a member to the organization by email (owner/admin only)."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not belong to an organization",
        )
    _require_org_admin(current_user)

    if data.org_role not in ("admin", "member", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be one of: admin, member, viewer",
        )

    # Find user by email
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User with this email not found",
        )

    if user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already belongs to an organization",
        )

    user.organization_id = current_user.organization_id
    user.org_role = data.org_role

    await db.commit()
    await db.refresh(user)
    return MemberResponse.model_validate(user)


@router.delete("/current/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove a member from the organization (owner/admin only)."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not belong to an organization",
        )
    _require_org_admin(current_user)

    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from the organization",
        )

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

    if user.org_role == "owner":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the organization owner",
        )

    user.organization_id = None
    user.org_role = "member"
    await db.commit()


@router.put("/current/members/{user_id}/role", response_model=MemberResponse)
async def change_member_role(
    user_id: str,
    data: UpdateMemberRole,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change a member's role in the organization (owner/admin only)."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not belong to an organization",
        )
    _require_org_admin(current_user)

    if data.org_role not in ("owner", "admin", "member", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be one of: owner, admin, member, viewer",
        )

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

    # Only owners can promote to owner or change another owner's role
    if data.org_role == "owner" and current_user.org_role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the owner can transfer ownership",
        )
    if user.org_role == "owner" and current_user.org_role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the owner can change the owner's role",
        )

    user.org_role = data.org_role
    await db.commit()
    await db.refresh(user)
    return MemberResponse.model_validate(user)
