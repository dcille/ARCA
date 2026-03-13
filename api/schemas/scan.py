"""Scan schemas."""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ScanCreate(BaseModel):
    provider_id: Optional[str] = None
    connection_id: Optional[str] = None
    scan_type: str = "cloud"  # cloud or saas
    services: Optional[list[str]] = None
    regions: Optional[list[str]] = None


class ScanResponse(BaseModel):
    id: str
    scan_type: str
    status: str
    progress: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True
