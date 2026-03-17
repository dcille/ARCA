"""Cloud provider model."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class Provider(Base):
    __tablename__ = "providers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(50), nullable=False)  # aws, azure, gcp, kubernetes
    alias: Mapped[str] = mapped_column(String(255), nullable=False)
    credentials_encrypted: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="connected")
    region: Mapped[str] = mapped_column(String(100), nullable=True)
    account_id: Mapped[str] = mapped_column(String(255), nullable=True)
    account_type: Mapped[str] = mapped_column(String(50), default="single")  # single, organization, management
    parent_provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("providers.id"), nullable=True)
    is_management_account: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
