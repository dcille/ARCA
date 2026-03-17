"""Notification model for alerts and events."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # scan_complete, critical_finding, schedule, system
    severity: Mapped[str] = mapped_column(String(20), nullable=True)  # critical, high, medium, low, info
    read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    link: Mapped[str] = mapped_column(String(500), nullable=True)  # Optional link to related page
    metadata_json: Mapped[str] = mapped_column(Text, nullable=True)  # JSON extra data
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
