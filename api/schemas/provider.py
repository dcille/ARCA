"""Provider schemas."""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ProviderCreate(BaseModel):
    provider_type: str
    alias: str
    credentials: dict
    region: Optional[str] = None
    account_id: Optional[str] = None


class ProviderResponse(BaseModel):
    id: str
    provider_type: str
    alias: str
    status: str
    region: Optional[str]
    account_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ProviderUpdate(BaseModel):
    alias: Optional[str] = None
    credentials: Optional[dict] = None
    region: Optional[str] = None
