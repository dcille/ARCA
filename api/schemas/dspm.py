"""DSPM schemas for scan requests and responses."""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class DSPMScanRequest(BaseModel):
    provider_id: Optional[str] = None
    skip_modules: Optional[list[str]] = None
    enable_content_scanning: bool = False


class DSPMScanResponse(BaseModel):
    scan_id: str
    task_id: str
    status: str
    message: str


class DSPMScanStatusResponse(BaseModel):
    scan_id: str
    task_id: str
    status: str  # pending, running, completed, failed
    progress: Optional[float] = None
    total_findings: int = 0
    overall_risk_score: float = 0.0
    overall_risk_label: str = "low"
    modules_run: int = 0
    modules_failed: int = 0
    findings_by_severity: Optional[dict] = None
    findings_by_module: Optional[dict] = None
    duration_seconds: float = 0.0
    completed_at: Optional[datetime] = None


class DSPMFindingResponse(BaseModel):
    id: str
    scan_id: str
    module: str
    title: str
    severity: str
    confidence: str
    description: str
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    category: str
    remediation: Optional[str] = None
    risk_score: float = 0.0
    evidence: Optional[dict] = None
    status: str = "open"
    source: str = "dspm_engine"
    created_at: datetime

    class Config:
        from_attributes = True


class DSPMFindingStatusUpdate(BaseModel):
    status: str  # open, resolved, ignored
