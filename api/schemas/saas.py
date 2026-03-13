"""SaaS connection and finding schemas."""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ServiceNowCredentials(BaseModel):
    instance_name: str
    username: str
    password: str
    instance_region: str = "us"
    failed_login_breaching_rate: int = 5


class M365Credentials(BaseModel):
    client_id: str
    client_secret: str
    tenant_id: str
    tenant_location: str = "US"


class SalesforceCredentials(BaseModel):
    client_id: str
    client_secret: str
    username: str
    password: str
    security_token: str
    instance_location: str = "NA224"
    api_version: str = "v58.0"
    failed_login_breaching_rate: int = 5


class SnowflakeCredentials(BaseModel):
    username: str
    password: str
    account_id: str
    warehouse_name: str
    region: str
    service_account_usernames: list[str] = []


class SaaSConnectionCreate(BaseModel):
    provider_type: str  # servicenow, m365, salesforce, snowflake
    alias: str
    credentials: dict


class SaaSConnectionResponse(BaseModel):
    id: str
    provider_type: str
    alias: str
    status: str
    is_active: bool
    last_scan_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class SaaSFindingResponse(BaseModel):
    id: str
    scan_id: str
    connection_id: str
    provider_type: str
    check_id: str
    check_title: str
    service_area: str
    severity: str
    status: str
    resource_id: Optional[str]
    resource_name: Optional[str]
    description: Optional[str]
    remediation: Optional[str]
    remediation_url: Optional[str]
    compliance_frameworks: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class SaaSOverview(BaseModel):
    total_connections: int
    active_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    pass_rate: float
    by_provider: dict
