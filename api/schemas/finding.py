"""Finding schemas."""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    check_id: str
    check_title: str
    service: str
    severity: str
    status: str
    region: Optional[str]
    resource_id: Optional[str]
    resource_name: Optional[str]
    status_extended: Optional[str]
    remediation: Optional[str]
    remediation_url: Optional[str]
    compliance_frameworks: Optional[str] = None
    check_description: Optional[str] = None
    evidence_log: Optional[str] = None
    mitre_techniques: Optional[str] = None
    provider_type: Optional[str] = None
    provider_alias: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FindingFilter(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    service: Optional[str] = None
    region: Optional[str] = None
