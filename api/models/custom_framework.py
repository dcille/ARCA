"""Custom Framework models for user-defined compliance frameworks."""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Text, ForeignKey, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.database import Base


class CustomFramework(Base):
    __tablename__ = "custom_frameworks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[str] = mapped_column(String(50), default="1.0")
    providers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array: ["aws","azure",...]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    selected_checks: Mapped[list["CustomFrameworkCheck"]] = relationship(
        "CustomFrameworkCheck", back_populates="framework", cascade="all, delete-orphan"
    )
    custom_controls: Mapped[list["CustomControl"]] = relationship(
        "CustomControl", back_populates="framework", cascade="all, delete-orphan"
    )


class CustomFrameworkCheck(Base):
    """Reference to a check that already exists in the registry (CIS or supplementary)."""
    __tablename__ = "custom_framework_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    framework_id: Mapped[str] = mapped_column(String(36), ForeignKey("custom_frameworks.id"), nullable=False, index=True)
    registry_check_id: Mapped[str] = mapped_column(String(200), nullable=False)
    display_order: Mapped[int] = mapped_column(Integer, default=0)

    framework: Mapped["CustomFramework"] = relationship("CustomFramework", back_populates="selected_checks")


class CustomControl(Base):
    """Completely new control created by the user."""
    __tablename__ = "custom_controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    framework_id: Mapped[str] = mapped_column(String(36), ForeignKey("custom_frameworks.id"), nullable=False, index=True)
    check_id: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    service: Mapped[str] = mapped_column(String(100), default="custom")
    category: Mapped[str] = mapped_column(String(100), default="Compliance")
    assessment_type: Mapped[str] = mapped_column(String(20), default="manual")
    risks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cli_commands: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    scanner_check_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Executable evaluation fields for automated custom controls
    evaluation_script: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cli_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pass_condition: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, default="empty")
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    references: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    display_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    framework: Mapped["CustomFramework"] = relationship("CustomFramework", back_populates="custom_controls")
