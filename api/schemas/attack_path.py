"""Attack Path schemas."""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AttackPathNode(BaseModel):
    id: str
    node_type: str
    label: str
    service: str
    severity: str = ""
    metadata: dict = {}


class AttackPathEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: str
    label: str = ""


class AttackPathResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    risk_score: float
    category: str
    entry_point: str
    target: str
    node_count: int
    edge_count: int
    techniques: list[str] = []
    affected_resources: list[str] = []
    remediation: list[str] = []
    created_at: datetime

    class Config:
        from_attributes = True


class AttackPathDetailResponse(AttackPathResponse):
    graph_data: Optional[dict] = None


class AttackPathSummary(BaseModel):
    total_paths: int
    critical_paths: int
    high_paths: int
    medium_paths: int
    low_paths: int
    top_categories: dict[str, int]
    avg_risk_score: float
    most_affected_services: list[str]
