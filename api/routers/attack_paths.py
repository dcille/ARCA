"""Attack Paths router."""
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.scan import Scan
from api.models.attack_path import AttackPath
from api.schemas.attack_path import (
    AttackPathResponse,
    AttackPathDetailResponse,
    AttackPathSummary,
)
from api.services.auth_service import get_current_user
from scanner.attack_paths.graph_engine import AttackPathAnalyzer

router = APIRouter()


def _parse_json_field(value: Optional[str]) -> list:
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []


def _model_to_response(ap: AttackPath) -> AttackPathResponse:
    return AttackPathResponse(
        id=ap.id,
        title=ap.title,
        description=ap.description,
        severity=ap.severity,
        risk_score=ap.risk_score,
        category=ap.category,
        entry_point=ap.entry_point,
        target=ap.target,
        node_count=ap.node_count,
        edge_count=ap.edge_count,
        techniques=_parse_json_field(ap.techniques),
        affected_resources=_parse_json_field(ap.affected_resources),
        remediation=_parse_json_field(ap.remediation),
        created_at=ap.created_at,
    )


def _model_to_detail(ap: AttackPath) -> AttackPathDetailResponse:
    graph = None
    if ap.graph_data:
        try:
            graph = json.loads(ap.graph_data)
        except (json.JSONDecodeError, TypeError):
            graph = None

    return AttackPathDetailResponse(
        id=ap.id,
        title=ap.title,
        description=ap.description,
        severity=ap.severity,
        risk_score=ap.risk_score,
        category=ap.category,
        entry_point=ap.entry_point,
        target=ap.target,
        node_count=ap.node_count,
        edge_count=ap.edge_count,
        techniques=_parse_json_field(ap.techniques),
        affected_resources=_parse_json_field(ap.affected_resources),
        remediation=_parse_json_field(ap.remediation),
        graph_data=graph,
        created_at=ap.created_at,
    )


@router.post("/analyze")
async def analyze_attack_paths(
    scan_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run attack path analysis on existing findings."""
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.status == "FAIL")
    )
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    result = await db.execute(query)
    findings_models = result.scalars().all()

    if not findings_models:
        return {"message": "No failed findings to analyze", "paths_discovered": 0}

    findings_dicts = [
        {
            "id": f.id,
            "check_id": f.check_id,
            "check_title": f.check_title,
            "service": f.service,
            "severity": f.severity,
            "status": f.status,
            "region": f.region,
            "resource_id": f.resource_id,
            "resource_name": f.resource_name,
            "remediation": f.remediation,
        }
        for f in findings_models
    ]

    analyzer = AttackPathAnalyzer(findings_dicts)
    paths = analyzer.analyze()

    # Clear old paths for this user (optionally scoped to scan)
    delete_q = delete(AttackPath).where(AttackPath.user_id == current_user.id)
    if scan_id:
        delete_q = delete_q.where(AttackPath.scan_id == scan_id)
    await db.execute(delete_q)

    # Save new paths
    for p in paths:
        graph_data = {
            "nodes": [
                {
                    "id": n.id,
                    "node_type": n.node_type.value if hasattr(n.node_type, 'value') else n.node_type,
                    "label": n.label,
                    "service": n.service,
                    "severity": n.severity,
                    "metadata": n.metadata,
                }
                for n in p.nodes
            ],
            "edges": [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "edge_type": e.edge_type.value if hasattr(e.edge_type, 'value') else e.edge_type,
                    "label": e.label,
                }
                for e in p.edges
            ],
        }

        db_path = AttackPath(
            user_id=current_user.id,
            scan_id=scan_id,
            title=p.title,
            description=p.description,
            severity=p.severity,
            risk_score=p.risk_score,
            category=p.category,
            entry_point=p.entry_point,
            target=p.target,
            node_count=len(p.nodes),
            edge_count=len(p.edges),
            techniques=json.dumps(p.techniques),
            affected_resources=json.dumps(p.affected_resources),
            remediation=json.dumps(p.remediation),
            graph_data=json.dumps(graph_data),
        )
        db.add(db_path)

    await db.commit()

    return {
        "message": f"Analysis complete. {len(paths)} attack path(s) discovered.",
        "paths_discovered": len(paths),
        "findings_analyzed": len(findings_dicts),
    }


@router.get("/", response_model=list[AttackPathResponse])
async def list_attack_paths(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all discovered attack paths."""
    query = select(AttackPath).where(AttackPath.user_id == current_user.id)
    if severity:
        query = query.where(AttackPath.severity == severity)
    if category:
        query = query.where(AttackPath.category == category)

    query = query.order_by(AttackPath.risk_score.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return [_model_to_response(ap) for ap in result.scalars().all()]


@router.get("/summary", response_model=AttackPathSummary)
async def attack_paths_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get summary statistics for attack paths."""
    paths_result = await db.execute(
        select(AttackPath).where(AttackPath.user_id == current_user.id)
    )
    paths = paths_result.scalars().all()

    if not paths:
        return AttackPathSummary(
            total_paths=0,
            critical_paths=0,
            high_paths=0,
            medium_paths=0,
            low_paths=0,
            top_categories={},
            avg_risk_score=0,
            most_affected_services=[],
        )

    severity_counts = {}
    category_counts = {}
    all_resources = []
    total_score = 0

    for p in paths:
        severity_counts[p.severity] = severity_counts.get(p.severity, 0) + 1
        category_counts[p.category] = category_counts.get(p.category, 0) + 1
        total_score += p.risk_score
        resources = _parse_json_field(p.affected_resources)
        all_resources.extend(resources)

    service_counts: dict[str, int] = {}
    for r in all_resources:
        svc = r.split("/")[0] if "/" in r else r.split(":")[0] if ":" in r else r
        service_counts[svc] = service_counts.get(svc, 0) + 1

    most_affected = sorted(service_counts.keys(), key=lambda s: service_counts[s], reverse=True)[:10]

    return AttackPathSummary(
        total_paths=len(paths),
        critical_paths=severity_counts.get("critical", 0),
        high_paths=severity_counts.get("high", 0),
        medium_paths=severity_counts.get("medium", 0),
        low_paths=severity_counts.get("low", 0),
        top_categories=category_counts,
        avg_risk_score=round(total_score / len(paths), 1),
        most_affected_services=most_affected,
    )


@router.get("/{path_id}", response_model=AttackPathDetailResponse)
async def get_attack_path(
    path_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single attack path with full graph data."""
    result = await db.execute(
        select(AttackPath)
        .where(AttackPath.id == path_id)
        .where(AttackPath.user_id == current_user.id)
    )
    ap = result.scalar_one_or_none()
    if not ap:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return _model_to_detail(ap)
