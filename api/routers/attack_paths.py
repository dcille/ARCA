"""Attack Paths router."""
import json
import uuid as uuid_mod
from collections import Counter

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
    """Run attack path analysis on existing findings. Preserves history via analysis_run_id."""
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

    # Generate a unique run_id for this analysis (keeps history)
    run_id = str(uuid_mod.uuid4())

    # Save new paths with run_id
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
            analysis_run_id=run_id,
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
        "analysis_run_id": run_id,
    }


@router.get("/runs")
async def list_analysis_runs(
    limit: int = Query(default=20, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all analysis runs with summary stats."""
    query = (
        select(
            AttackPath.analysis_run_id,
            func.count(AttackPath.id).label("total_paths"),
            func.avg(AttackPath.risk_score).label("avg_risk"),
            func.min(AttackPath.created_at).label("created_at"),
            func.count(func.nullif(AttackPath.severity != "critical", True)).label("critical_count"),
            func.count(func.nullif(AttackPath.severity != "high", True)).label("high_count"),
        )
        .where(AttackPath.user_id == current_user.id)
        .where(AttackPath.analysis_run_id.isnot(None))
        .group_by(AttackPath.analysis_run_id)
        .order_by(func.min(AttackPath.created_at).desc())
        .limit(limit)
    )
    result = await db.execute(query)
    rows = result.all()

    return [
        {
            "analysis_run_id": row.analysis_run_id,
            "total_paths": row.total_paths,
            "avg_risk_score": round(float(row.avg_risk or 0), 1),
            "critical_paths": row.critical_count,
            "high_paths": row.high_count,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@router.get("/choke-points")
async def get_choke_points(
    analysis_run_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the top nodes that appear most frequently across attack paths (choke points)."""
    query = select(AttackPath).where(AttackPath.user_id == current_user.id)
    if analysis_run_id:
        query = query.where(AttackPath.analysis_run_id == analysis_run_id)
    else:
        # Get the latest run
        sub = (
            select(AttackPath.analysis_run_id)
            .where(AttackPath.user_id == current_user.id)
            .where(AttackPath.analysis_run_id.isnot(None))
            .order_by(AttackPath.created_at.desc())
            .limit(1)
        )
        sub_result = await db.execute(sub)
        latest_run = sub_result.scalar_one_or_none()
        if latest_run:
            query = query.where(AttackPath.analysis_run_id == latest_run)

    result = await db.execute(query)
    paths = result.scalars().all()

    if not paths:
        return {"choke_points": [], "total_paths_analyzed": 0}

    # Count node appearances across all paths
    node_appearances: Counter = Counter()
    node_info: dict[str, dict] = {}
    node_connections: Counter = Counter()

    for p in paths:
        graph = None
        try:
            graph = json.loads(p.graph_data) if p.graph_data else None
        except (json.JSONDecodeError, TypeError):
            continue
        if not graph:
            continue

        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        node_ids_in_path = {n["id"] for n in nodes}

        for n in nodes:
            nid = n["id"]
            node_appearances[nid] += 1
            if nid not in node_info:
                node_info[nid] = {
                    "id": nid,
                    "label": n.get("label", ""),
                    "node_type": n.get("node_type", ""),
                    "service": n.get("service", ""),
                }

        for e in edges:
            node_connections[e["source_id"]] += 1
            node_connections[e["target_id"]] += 1

    # Score: appearances * connections (simplified centrality)
    choke_scores = {}
    for nid in node_appearances:
        choke_scores[nid] = node_appearances[nid] * (1 + node_connections.get(nid, 0) * 0.3)

    # Top 10 choke points (exclude generic Internet node)
    top = sorted(
        [(nid, score) for nid, score in choke_scores.items() if node_info.get(nid, {}).get("node_type") != "internet"],
        key=lambda x: x[1],
        reverse=True,
    )[:10]

    return {
        "choke_points": [
            {
                **node_info[nid],
                "path_appearances": node_appearances[nid],
                "connection_count": node_connections.get(nid, 0),
                "choke_score": round(score, 2),
            }
            for nid, score in top
        ],
        "total_paths_analyzed": len(paths),
    }


@router.get("/compare")
async def compare_runs(
    run1: str = Query(..., description="First analysis_run_id"),
    run2: str = Query(..., description="Second analysis_run_id"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare attack paths between two analysis runs."""
    async def _load_run(run_id: str):
        result = await db.execute(
            select(AttackPath)
            .where(AttackPath.user_id == current_user.id)
            .where(AttackPath.analysis_run_id == run_id)
        )
        return result.scalars().all()

    paths1 = await _load_run(run1)
    paths2 = await _load_run(run2)

    if not paths1 and not paths2:
        raise HTTPException(status_code=404, detail="No paths found for either run")

    def _path_key(p):
        return (p.category, p.entry_point, p.target)

    def _resource_set(p):
        return set(_parse_json_field(p.affected_resources))

    matched1 = set()
    matched2 = set()
    persistent = []

    for i, p1 in enumerate(paths1):
        key1 = _path_key(p1)
        res1 = _resource_set(p1)
        for j, p2 in enumerate(paths2):
            if j in matched2:
                continue
            if _path_key(p2) != key1:
                continue
            res2 = _resource_set(p2)
            if res1 and res2:
                overlap = len(res1 & res2) / max(len(res1 | res2), 1)
                if overlap < 0.5:
                    continue
            matched1.add(i)
            matched2.add(j)
            persistent.append({
                "title": p2.title,
                "category": p2.category,
                "severity": p2.severity,
                "risk_score_before": p1.risk_score,
                "risk_score_after": p2.risk_score,
                "risk_change": round(p2.risk_score - p1.risk_score, 1),
            })
            break

    new_paths = [
        {"id": p.id, "title": p.title, "severity": p.severity, "risk_score": p.risk_score, "category": p.category}
        for j, p in enumerate(paths2) if j not in matched2
    ]
    resolved_paths = [
        {"id": p.id, "title": p.title, "severity": p.severity, "risk_score": p.risk_score, "category": p.category}
        for i, p in enumerate(paths1) if i not in matched1
    ]

    return {
        "run1": {"analysis_run_id": run1, "total_paths": len(paths1)},
        "run2": {"analysis_run_id": run2, "total_paths": len(paths2)},
        "new_paths": new_paths,
        "resolved_paths": resolved_paths,
        "persistent_paths": persistent,
        "summary": {
            "new_count": len(new_paths),
            "resolved_count": len(resolved_paths),
            "persistent_count": len(persistent),
            "risk_changes": [p for p in persistent if p["risk_change"] != 0],
            "avg_risk_change": round(
                sum(p["risk_change"] for p in persistent) / max(len(persistent), 1), 1
            ),
        },
    }


@router.get("", response_model=list[AttackPathResponse])
async def list_attack_paths(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    analysis_run_id: Optional[str] = None,
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
    if analysis_run_id:
        query = query.where(AttackPath.analysis_run_id == analysis_run_id)
    else:
        # Default: show latest run only
        sub = (
            select(AttackPath.analysis_run_id)
            .where(AttackPath.user_id == current_user.id)
            .where(AttackPath.analysis_run_id.isnot(None))
            .order_by(AttackPath.created_at.desc())
            .limit(1)
        )
        sub_result = await db.execute(sub)
        latest_run = sub_result.scalar_one_or_none()
        if latest_run:
            query = query.where(AttackPath.analysis_run_id == latest_run)

    query = query.order_by(AttackPath.risk_score.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return [_model_to_response(ap) for ap in result.scalars().all()]


@router.get("/summary", response_model=AttackPathSummary)
async def attack_paths_summary(
    analysis_run_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get summary statistics for attack paths."""
    query = select(AttackPath).where(AttackPath.user_id == current_user.id)
    if analysis_run_id:
        query = query.where(AttackPath.analysis_run_id == analysis_run_id)

    paths_result = await db.execute(query)
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
