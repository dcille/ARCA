"""Scan schedule model for recurring scans."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("providers.id"), nullable=True)
    connection_id: Mapped[str] = mapped_column(String(36), ForeignKey("saas_connections.id"), nullable=True)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # cloud, saas
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    frequency: Mapped[str] = mapped_column(String(50), nullable=False)  # daily, weekly, monthly
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=True)  # for custom schedules
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    services: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list
    regions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list
    last_run_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
