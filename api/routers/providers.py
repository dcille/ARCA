"""Cloud providers router."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.schemas.provider import ProviderCreate, ProviderResponse, ProviderUpdate, DiscoveredAccount
from api.services.auth_service import get_current_user, encrypt_credentials

router = APIRouter()


@router.get("", response_model=list[ProviderResponse])
async def list_providers(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Provider).where(Provider.user_id == current_user.id).order_by(Provider.created_at.desc())
    )
    return [ProviderResponse.model_validate(p) for p in result.scalars().all()]


@router.post("", response_model=ProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_provider(
    data: ProviderCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.provider_type not in ("aws", "azure", "gcp", "kubernetes", "oci", "alibaba", "ibm_cloud"):
        raise HTTPException(status_code=400, detail="Invalid provider type")

    if data.account_type not in ("single", "organization", "management"):
        raise HTTPException(status_code=400, detail="Invalid account type. Must be single, organization, or management")

    is_mgmt = data.account_type in ("organization", "management")

    provider = Provider(
        user_id=current_user.id,
        provider_type=data.provider_type,
        alias=data.alias,
        credentials_encrypted=encrypt_credentials(data.credentials),
        region=data.region,
        account_id=data.account_id,
        account_type=data.account_type,
        is_management_account=is_mgmt,
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


@router.put("/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: str,
    data: ProviderUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Provider).where(Provider.id == provider_id, Provider.user_id == current_user.id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    if data.alias is not None:
        provider.alias = data.alias
    if data.region is not None:
        provider.region = data.region
    if data.credentials is not None:
        provider.credentials_encrypted = encrypt_credentials(data.credentials)

    await db.commit()
    await db.refresh(provider)
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


@router.post("/{provider_id}/discover-accounts", response_model=list[DiscoveredAccount])
async def discover_accounts(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Discover child accounts/subscriptions for an organization/management provider."""
    result = await db.execute(
        select(Provider).where(Provider.id == provider_id, Provider.user_id == current_user.id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    if not provider.is_management_account:
        raise HTTPException(status_code=400, detail="Provider is not a management/organization account")

    # In production, this would call AWS Organizations API, Azure Subscriptions API, etc.
    # For now, return simulated discovered accounts based on provider type.
    discovered: list[dict] = []

    if provider.provider_type == "aws":
        discovered = [
            {"account_id": "111122223333", "name": "Production", "status": "active", "provider_type": "aws"},
            {"account_id": "444455556666", "name": "Staging", "status": "active", "provider_type": "aws"},
            {"account_id": "777788889999", "name": "Development", "status": "active", "provider_type": "aws"},
        ]
    elif provider.provider_type == "azure":
        discovered = [
            {"account_id": "sub-prod-001", "name": "Production Subscription", "status": "active", "provider_type": "azure"},
            {"account_id": "sub-dev-002", "name": "Development Subscription", "status": "active", "provider_type": "azure"},
        ]
    elif provider.provider_type == "gcp":
        discovered = [
            {"account_id": "proj-prod-001", "name": "Production Project", "status": "active", "provider_type": "gcp"},
            {"account_id": "proj-staging-002", "name": "Staging Project", "status": "active", "provider_type": "gcp"},
        ]
    elif provider.provider_type == "oci":
        discovered = [
            {"account_id": "ocid1.compartment.oc1..prod", "name": "Production Compartment", "status": "active", "provider_type": "oci"},
            {"account_id": "ocid1.compartment.oc1..dev", "name": "Development Compartment", "status": "active", "provider_type": "oci"},
        ]
    elif provider.provider_type == "alibaba":
        discovered = [
            {"account_id": "1234567890123456", "name": "Production Account", "status": "active", "provider_type": "alibaba"},
            {"account_id": "6543210987654321", "name": "Staging Account", "status": "active", "provider_type": "alibaba"},
        ]

    return [DiscoveredAccount(**a) for a in discovered]


@router.get("/{provider_id}/accounts", response_model=list[ProviderResponse])
async def list_child_accounts(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List child accounts/subscriptions linked to a parent provider."""
    # Verify parent provider exists and belongs to user
    result = await db.execute(
        select(Provider).where(Provider.id == provider_id, Provider.user_id == current_user.id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    # Get child accounts
    result = await db.execute(
        select(Provider)
        .where(Provider.parent_provider_id == provider_id, Provider.user_id == current_user.id)
        .order_by(Provider.created_at.desc())
    )
    return [ProviderResponse.model_validate(p) for p in result.scalars().all()]
