"""Notification service - creates in-app notifications and fires webhook integrations."""
import json
import logging
from datetime import datetime

import httpx
from sqlalchemy.orm import Session

from api.models.notification import Notification
from api.models.integration import Integration

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def create_scan_complete_notification(
    db: Session,
    user_id: str,
    scan_id: str,
    scan_type: str,
    total: int,
    passed: int,
    failed: int,
):
    """Create an in-app notification when a scan completes and fire webhooks."""
    severity = "info"
    if failed > 0:
        severity = "medium"
    if failed >= 10:
        severity = "high"
    if failed >= 25:
        severity = "critical"

    title = f"{'Cloud' if scan_type == 'cloud' else 'SaaS'} scan completed"
    message = (
        f"Scan finished with {total} checks: {passed} passed, {failed} failed."
    )

    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        type="scan_complete",
        severity=severity,
        link=f"/darca/findings?scan_id={scan_id}",
    )
    db.add(notification)
    db.flush()

    _fire_webhooks(
        db,
        user_id=user_id,
        event="scan_complete",
        severity=severity,
        payload={
            "scan_id": scan_id,
            "scan_type": scan_type,
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "severity": severity,
            "completed_at": datetime.utcnow().isoformat(),
        },
    )


def create_critical_finding_notification(
    db: Session,
    user_id: str,
    scan_id: str,
    check_id: str,
    check_title: str,
    resource_id: str | None = None,
):
    """Create an in-app notification for critical/high findings and fire webhooks."""
    notification = Notification(
        user_id=user_id,
        title=f"Critical finding: {check_title}",
        message=f"Check {check_id} failed{f' on {resource_id}' if resource_id else ''}.",
        type="critical_finding",
        severity="critical",
        link=f"/darca/findings?scan_id={scan_id}",
    )
    db.add(notification)
    db.flush()

    _fire_webhooks(
        db,
        user_id=user_id,
        event="critical_finding",
        severity="critical",
        payload={
            "scan_id": scan_id,
            "check_id": check_id,
            "check_title": check_title,
            "resource_id": resource_id,
            "severity": "critical",
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


def _fire_webhooks(
    db: Session,
    user_id: str,
    event: str,
    severity: str,
    payload: dict,
):
    """Send webhook notifications to all matching integrations."""
    integrations = (
        db.query(Integration)
        .filter(
            Integration.user_id == user_id,
            Integration.enabled == True,
        )
        .all()
    )

    for integration in integrations:
        try:
            events = json.loads(integration.events) if integration.events else []
        except (json.JSONDecodeError, TypeError):
            events = []

        if event not in events:
            continue

        min_rank = SEVERITY_RANK.get(integration.min_severity, 0)
        event_rank = SEVERITY_RANK.get(severity, 0)
        if event_rank < min_rank:
            continue

        if not integration.webhook_url:
            continue

        webhook_payload = _build_payload(integration.type, event, payload)

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(integration.webhook_url, json=webhook_payload)
                if resp.status_code < 400:
                    integration.last_triggered_at = datetime.utcnow()
                else:
                    logger.warning(
                        f"Webhook {integration.id} returned {resp.status_code}"
                    )
        except Exception as e:
            logger.warning(f"Webhook {integration.id} failed: {e}")


def _build_payload(integration_type: str, event: str, data: dict) -> dict:
    """Build provider-specific webhook payload."""
    summary = _event_summary(event, data)

    if integration_type == "slack":
        color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308"}.get(
            data.get("severity", ""), "#22c55e"
        )
        return {
            "text": f":shield: ARCA Security Alert: {summary}",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": k, "value": str(v), "short": True}
                        for k, v in data.items()
                        if k != "severity"
                    ],
                }
            ],
        }

    if integration_type == "teams":
        color = {"critical": "FF0000", "high": "FF8C00", "medium": "FFD700"}.get(
            data.get("severity", ""), "22c55e"
        )
        return {
            "@type": "MessageCard",
            "themeColor": color,
            "summary": f"ARCA: {summary}",
            "sections": [
                {
                    "activityTitle": f"ARCA Security Alert",
                    "activitySubtitle": summary,
                    "facts": [
                        {"name": k, "value": str(v)} for k, v in data.items()
                    ],
                }
            ],
        }

    # Generic webhook / Jira / email
    return {
        "source": "ARCA",
        "event": event,
        "summary": summary,
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
    }


def _event_summary(event: str, data: dict) -> str:
    if event == "scan_complete":
        return (
            f"Scan completed - {data.get('total_checks', 0)} checks, "
            f"{data.get('failed', 0)} failed"
        )
    if event == "critical_finding":
        return f"Critical finding: {data.get('check_title', data.get('check_id', ''))}"
    return f"Event: {event}"
