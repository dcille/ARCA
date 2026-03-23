"""Finding action model for exceptions and manual remediations."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class FindingAction(Base):
    __tablename__ = "finding_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)  # exception, remediated
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_file_name: Mapped[str] = mapped_column(String(500), nullable=True)
    evidence_file_path: Mapped[str] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
