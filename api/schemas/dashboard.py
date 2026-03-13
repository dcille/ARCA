"""Dashboard schemas."""
from pydantic import BaseModel
from typing import Optional


class DashboardOverview(BaseModel):
    total_providers: int
    total_scans: int
    total_findings: int
    pass_rate: float
    severity_breakdown: dict
    status_breakdown: dict
    findings_by_service: dict
    findings_by_provider: dict
    recent_scans: list
    compliance_summary: dict


class ComplianceSummary(BaseModel):
    framework: str
    total_checks: int
    passed: int
    failed: int
    pass_rate: float
