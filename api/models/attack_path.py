"""Attack Path model for storing discovered attack paths."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey, Float, Integer
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True, index=True)
    analysis_run_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entry_point: Mapped[str] = mapped_column(String(500), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    techniques: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    affected_resources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    remediation: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    graph_data: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string (nodes + edges)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
