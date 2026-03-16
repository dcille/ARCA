"""Integrations router - webhooks for Slack, Teams, Jira, etc."""
import json
import httpx
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.database import get_db
from api.models.user import User
from api.models.integration import Integration
from api.services.auth_service import get_current_user
from pydantic import BaseModel

router = APIRouter()


class IntegrationCreate(BaseModel):
    name: str
    type: str  # slack, teams, jira, webhook, email
    webhook_url: Optional[str] = None
    config: Optional[dict] = None
    events: list[str] = ["scan_complete", "critical_finding"]
    min_severity: str = "high"


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    webhook_url: Optional[str] = None
    config: Optional[dict] = None
    events: Optional[list[str]] = None
    min_severity: Optional[str] = None
    enabled: Optional[bool] = None


class IntegrationResponse(BaseModel):
    id: str
    name: str
    type: str
    webhook_url: Optional[str]
    config: Optional[dict]
    events: list[str]
    min_severity: str
    enabled: bool
    last_triggered_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


def _model_to_response(i: Integration) -> IntegrationResponse:
    config = None
    events = []
    try:
        if i.config_json:
            config = json.loads(i.config_json)
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        if i.events:
            events = json.loads(i.events)
    except (json.JSONDecodeError, TypeError):
        pass

    # Mask webhook URL for display (show only last 8 chars)
    masked_url = None
    if i.webhook_url:
        masked_url = "***" + i.webhook_url[-8:] if len(i.webhook_url) > 8 else i.webhook_url

    return IntegrationResponse(
        id=i.id,
        name=i.name,
        type=i.type,
        webhook_url=masked_url,
        config=config,
        events=events,
        min_severity=i.min_severity,
        enabled=i.enabled,
        last_triggered_at=i.last_triggered_at,
        created_at=i.created_at,
    )


@router.get("")
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Integration)
        .where(Integration.user_id == current_user.id)
        .order_by(Integration.created_at.desc())
    )
    return [_model_to_response(i) for i in result.scalars().all()]


@router.post("", status_code=201)
async def create_integration(
    data: IntegrationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.type not in ("slack", "teams", "jira", "webhook", "email"):
        raise HTTPException(status_code=400, detail="Invalid integration type")

    integration = Integration(
        user_id=current_user.id,
        name=data.name,
        type=data.type,
        webhook_url=data.webhook_url,
        config_json=json.dumps(data.config) if data.config else None,
        events=json.dumps(data.events),
        min_severity=data.min_severity,
        enabled=True,
    )
    db.add(integration)
    await db.commit()
    await db.refresh(integration)
    return _model_to_response(integration)


@router.put("/{integration_id}")
async def update_integration(
    integration_id: str,
    data: IntegrationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Integration)
        .where(Integration.id == integration_id, Integration.user_id == current_user.id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if data.name is not None:
        integration.name = data.name
    if data.webhook_url is not None:
        integration.webhook_url = data.webhook_url
    if data.config is not None:
        integration.config_json = json.dumps(data.config)
    if data.events is not None:
        integration.events = json.dumps(data.events)
    if data.min_severity is not None:
        integration.min_severity = data.min_severity
    if data.enabled is not None:
        integration.enabled = data.enabled

    await db.commit()
    await db.refresh(integration)
    return _model_to_response(integration)


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Integration)
        .where(Integration.id == integration_id, Integration.user_id == current_user.id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    await db.delete(integration)
    await db.commit()


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send a test message to the integration."""
    result = await db.execute(
        select(Integration)
        .where(Integration.id == integration_id, Integration.user_id == current_user.id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if not integration.webhook_url:
        raise HTTPException(status_code=400, detail="No webhook URL configured")

    test_payload = _build_test_payload(integration.type)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(integration.webhook_url, json=test_payload)
            if response.status_code >= 400:
                return {
                    "success": False,
                    "message": f"Webhook returned status {response.status_code}",
                }
    except httpx.TimeoutException:
        return {"success": False, "message": "Webhook request timed out"}
    except Exception as e:
        return {"success": False, "message": str(e)}

    integration.last_triggered_at = datetime.utcnow()
    await db.commit()

    return {"success": True, "message": "Test message sent successfully"}


def _build_test_payload(integration_type: str) -> dict:
    """Build provider-specific test payload."""
    if integration_type == "slack":
        return {
            "text": ":shield: *ARCA Test Notification*\nThis is a test message from ARCA Cloud Security.",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":shield: *ARCA Security Alert - Test*\n"
                                "This is a test notification from ARCA Cloud Security Posture Management.\n"
                                "If you see this, your integration is working correctly!",
                    },
                },
            ],
        }
    elif integration_type == "teams":
        return {
            "@type": "MessageCard",
            "themeColor": "22c55e",
            "summary": "ARCA Test Notification",
            "sections": [
                {
                    "activityTitle": "ARCA Security Alert - Test",
                    "activitySubtitle": "Cloud Security Posture Management",
                    "text": "This is a test notification from ARCA. If you see this, your integration is working correctly!",
                }
            ],
        }
    else:
        return {
            "source": "ARCA",
            "type": "test",
            "message": "This is a test notification from ARCA Cloud Security Posture Management.",
            "timestamp": datetime.utcnow().isoformat(),
        }
