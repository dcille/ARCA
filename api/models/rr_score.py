"""Ransomware Readiness Score model — stores calculated scores for trending."""
import uuid
from datetime import datetime

from sqlalchemy import String, SmallInteger, Integer, Float, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class RRScore(Base):
    __tablename__ = "rr_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(20), nullable=False)  # global / account / domain
    scope_id: Mapped[str] = mapped_column(String(256), nullable=True)  # account_id or domain_id
    score: Mapped[int] = mapped_column(SmallInteger, nullable=False)  # 0-100
    level: Mapped[str] = mapped_column(String(20), nullable=False)  # Excelente/Bueno/Moderado/Bajo/Critico
    checks_passed: Mapped[int] = mapped_column(Integer, default=0)
    checks_failed: Mapped[int] = mapped_column(Integer, default=0)
    checks_warning: Mapped[int] = mapped_column(Integer, default=0)
    domain_scores: Mapped[str] = mapped_column(Text, nullable=True)  # JSON
    scan_id: Mapped[str] = mapped_column(String(36), nullable=True)  # associated scan
    calculated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
