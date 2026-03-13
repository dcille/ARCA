"""Cloud providers router."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.schemas.provider import ProviderCreate, ProviderResponse, ProviderUpdate
from api.services.auth_service import get_current_user, encrypt_credentials

router = APIRouter()


@router.get("/", response_model=list[ProviderResponse])
async def list_providers(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Provider).where(Provider.user_id == current_user.id).order_by(Provider.created_at.desc())
    )
    return [ProviderResponse.model_validate(p) for p in result.scalars().all()]


@router.post("/", response_model=ProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_provider(
    data: ProviderCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.provider_type not in ("aws", "azure", "gcp", "kubernetes"):
        raise HTTPException(status_code=400, detail="Invalid provider type")

    provider = Provider(
        user_id=current_user.id,
        provider_type=data.provider_type,
        alias=data.alias,
        credentials_encrypted=encrypt_credentials(data.credentials),
        region=data.region,
        account_id=data.account_id,
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return ProviderResponse.model_validate(provider)


@router.get("/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Provider).where(Provider.id == provider_id, Provider.user_id == current_user.id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ProviderResponse.model_validate(provider)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Provider).where(Provider.id == provider_id, Provider.user_id == current_user.id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    await db.delete(provider)
    await db.commit()
