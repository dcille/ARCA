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
    account: str  # Account identifier with region (e.g. xy12345.us-east-1)
    username: str  # User with ACCOUNTADMIN, SECURITYADMIN, or custom DARCA_READER role
    auth_method: str = "password"  # "password" or "key_pair"
    password: Optional[str] = None  # Required when auth_method == "password"
    private_key: Optional[str] = None  # RSA private key PEM (PKCS8) when auth_method == "key_pair"
    warehouse: Optional[str] = "COMPUTE_WH"  # Virtual warehouse for query execution (XSMALL sufficient)
    role: Optional[str] = "ACCOUNTADMIN"  # Role to assume (ACCOUNTADMIN or custom DARCA_READER)
    # Legacy field aliases for backward compatibility
    account_id: Optional[str] = None  # Deprecated: use 'account'
    warehouse_name: Optional[str] = None  # Deprecated: use 'warehouse'
    region: Optional[str] = None  # Deprecated: included in account identifier
    service_account_usernames: list[str] = []


class GitHubCredentials(BaseModel):
    personal_access_token: str
    organization: str = ""


class GoogleWorkspaceCredentials(BaseModel):
    service_account_key: str  # JSON key file contents as string
    admin_email: str  # Super Admin email for domain-wide delegation
    domain: str  # Primary Google Workspace domain
    customer_id: str = "my_customer"  # GWS customer ID, defaults to auto-detect


class CloudflareCredentials(BaseModel):
    api_token: str
    account_id: str = ""


class OpenStackCredentials(BaseModel):
    auth_url: str
    username: str
    password: str
    project_name: str
    user_domain_name: str = "Default"
    project_domain_name: str = "Default"


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
    registry_check_counts: dict = {}
