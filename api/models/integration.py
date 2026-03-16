"""Integration model for webhooks (Slack, Jira, Teams, etc.)."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # slack, teams, jira, webhook, email
    webhook_url: Mapped[str] = mapped_column(Text, nullable=True)
    config_json: Mapped[str] = mapped_column(Text, nullable=True)  # JSON: extra config per type
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    events: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list: scan_complete, critical_finding, etc.
    min_severity: Mapped[str] = mapped_column(String(20), default="high")  # Minimum severity to trigger
    last_triggered_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
