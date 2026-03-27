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


# ── BAS 2.0 schemas ──────────────────────────────────────────────


class BlastRadiusResponse(BaseModel):
    total_reachable: int = 0
    data_stores: int = 0
    compute_instances: int = 0
    identities: int = 0
    pii_exposure: bool = False
    backup_exposure: bool = False
    admin_escalation: bool = False
    severity: str = "low"
    summary: str = ""


class DetectionCoverageResponse(BaseModel):
    coverage_pct: float = 0.0
    detected_steps: int = 0
    undetected_steps: int = 0
    total_steps: int = 0
    verdict: str = "not_evaluable"
    blind_spot_summary: list[str] = []


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
    # BAS 2.0 fields
    blast_radius: Optional[dict] = None
    detection_coverage: Optional[dict] = None
    confidence: str = "template"
    source: str = "scenario"
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
    # BAS 2.0 summary fields
    avg_blast_radius: float = 0
    avg_detection_coverage: float = 0
    blind_paths: int = 0


class ShadowAdminResponse(BaseModel):
    principal_id: str
    principal_name: str
    principal_type: str
    provider: str
    escalation_paths: list[str]
    shortest_path_steps: int
    blast_radius_estimate: int = 0
