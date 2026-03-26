"""Pydantic schemas for Custom Framework endpoints."""
import json
from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime

from scanner.registry.models import ProviderType, Severity, Category


class CustomFrameworkCreate(BaseModel):
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    providers: list[str]
    selected_check_ids: list[str] = []

    @field_validator("providers")
    @classmethod
    def validate_providers(cls, v: list[str]) -> list[str]:
        valid = {p.value for p in ProviderType}
        for p in v:
            if p not in valid:
                raise ValueError(f"Invalid provider '{p}'. Must be one of: {sorted(valid)}")
        return v


class CustomFrameworkUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None
    providers: Optional[list[str]] = None

    @field_validator("providers")
    @classmethod
    def validate_providers(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        valid = {p.value for p in ProviderType}
        for p in v:
            if p not in valid:
                raise ValueError(f"Invalid provider '{p}'. Must be one of: {sorted(valid)}")
        return v


class CustomFrameworkResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    version: str
    providers: list[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    total_checks: int = 0
    total_custom_controls: int = 0
    type: str = "custom"

    class Config:
        from_attributes = True


class CustomFrameworkDetailResponse(CustomFrameworkResponse):
    selected_checks: list[dict] = []
    custom_controls: list[dict] = []
    summary: Optional[dict] = None


class SelectedCheckAdd(BaseModel):
    registry_check_ids: list[str]


class CustomControlCreate(BaseModel):
    check_id: str
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    provider: str
    service: str = "custom"
    category: str = "Compliance"
    risks: Optional[str] = None
    cli_commands: Optional[dict] = None
    remediation: Optional[str] = None
    remediation_steps: Optional[list[str]] = None
    scanner_check_ids: list[str] = []
    tags: list[str] = []
    references: list[str] = []

    # Executable evaluation fields
    evaluation_script: Optional[str] = None
    cli_command: Optional[str] = None
    pass_condition: Optional[str] = "empty"

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {s.value for s in Severity}
        if v not in valid:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {sorted(valid)}")
        return v

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        valid = {p.value for p in ProviderType}
        if v not in valid:
            raise ValueError(f"Invalid provider '{v}'. Must be one of: {sorted(valid)}")
        return v

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        valid = {c.value for c in Category}
        if v not in valid:
            raise ValueError(f"Invalid category '{v}'. Must be one of: {sorted(valid)}")
        return v


class CustomControlUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    provider: Optional[str] = None
    service: Optional[str] = None
    category: Optional[str] = None
    risks: Optional[str] = None
    cli_commands: Optional[dict] = None
    remediation: Optional[str] = None
    remediation_steps: Optional[list[str]] = None
    scanner_check_ids: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    references: Optional[list[str]] = None

    # Executable evaluation fields
    evaluation_script: Optional[str] = None
    cli_command: Optional[str] = None
    pass_condition: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        valid = {s.value for s in Severity}
        if v not in valid:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {sorted(valid)}")
        return v

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        valid = {p.value for p in ProviderType}
        if v not in valid:
            raise ValueError(f"Invalid provider '{v}'. Must be one of: {sorted(valid)}")
        return v

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        valid = {c.value for c in Category}
        if v not in valid:
            raise ValueError(f"Invalid category '{v}'. Must be one of: {sorted(valid)}")
        return v


class CustomControlResponse(BaseModel):
    id: str
    check_id: str
    title: str
    description: Optional[str] = None
    severity: str
    provider: str
    service: str
    category: str
    assessment_type: str
    risks: Optional[str] = None
    cli_commands: Optional[dict] = None
    remediation: Optional[str] = None
    remediation_steps: Optional[list[str]] = None
    scanner_check_ids: list[str] = []
    tags: list[str] = []
    references: list[str] = []
    evaluation_script: Optional[str] = None
    cli_command: Optional[str] = None
    pass_condition: Optional[str] = None
    evaluation_type: Optional[str] = None
    display_order: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


class ExcelImportPreview(BaseModel):
    valid: list[dict] = []
    errors: list[dict] = []
    warnings: list[dict] = []
    total_rows: int = 0


class ExcelImportConfirm(BaseModel):
    controls: list[CustomControlCreate]
