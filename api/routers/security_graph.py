"""Security Graph router — builds a visual graph of cloud resource relationships."""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, literal_column

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.models.scan import Scan
from api.models.finding import Finding
from api.services.auth_service import get_current_user

router = APIRouter()

# Hierarchy: cloud_provider -> account -> region -> service -> resource
# Findings attach to resources and determine risk colouring.

SERVICE_CATEGORIES = {
    "IAM": "identity",
    "S3": "storage",
    "EC2": "compute",
    "RDS": "database",
    "Lambda": "compute",
    "EBS": "storage",
    "VPC": "network",
    "CloudTrail": "logging",
    "CloudWatch": "logging",
    "KMS": "encryption",
    "SNS": "messaging",
    "SQS": "messaging",
    "ELB": "network",
    "EKS": "compute",
    "DynamoDB": "database",
    "Redshift": "database",
    "ElastiCache": "database",
    "Route53": "network",
    "CloudFront": "network",
    "GuardDuty": "security",
    "Config": "management",
    "SecurityHub": "security",
    "WAF": "security",
    "Firewall": "network",
    "Storage Accounts": "storage",
    "Virtual Machines": "compute",
    "SQL Database": "database",
    "Key Vault": "encryption",
    "Network Security Groups": "network",
    "Active Directory": "identity",
    "Monitor": "logging",
    "Compute Engine": "compute",
    "Cloud Storage": "storage",
    "Cloud SQL": "database",
    "BigQuery": "database",
    "Cloud Logging": "logging",
    "Cloud KMS": "encryption",
    "Compute": "compute",
    "Networking": "network",
    "Identity": "identity",
    "Logging": "logging",
    "Encryption": "encryption",
}


def _categorize_service(service: str) -> str:
    if not service:
        return "other"
    for key, category in SERVICE_CATEGORIES.items():
        if key.lower() in service.lower():
            return category
    return "other"


@router.get("/graph")
async def get_security_graph(
    provider_type: Optional[str] = None,
    provider_id: Optional[str] = None,
    service: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = Query(None, description="at_risk or compliant"),
    depth: str = Query("service", description="Granularity: provider, region, service, resource"),
    limit: int = Query(200, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Build a hierarchical security graph from cloud resources."""

    base_q = (
        select(
            Finding.resource_id,
            Finding.resource_name,
            Finding.service,
            Finding.region,
            Finding.provider_id,
            func.count(Finding.id).label("total_findings"),
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("failed_count"),
            func.sum(case((Finding.status == "PASS", 1), else_=0)).label("passed_count"),
            func.min(
                case(
                    (Finding.severity == "critical", literal_column("1")),
                    (Finding.severity == "high", literal_column("2")),
                    (Finding.severity == "medium", literal_column("3")),
                    (Finding.severity == "low", literal_column("4")),
                    else_=literal_column("5"),
                )
            ).label("max_severity_rank"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.resource_id.isnot(None))
        .where(Finding.resource_id != "")
    )

    if provider_type:
        base_q = base_q.join(Provider, Finding.provider_id == Provider.id).where(
            Provider.provider_type == provider_type
        )
    elif provider_id:
        base_q = base_q.where(Finding.provider_id == provider_id)

    if service:
        base_q = base_q.where(Finding.service == service)
    if severity:
        base_q = base_q.where(Finding.severity == severity)

    base_q = base_q.group_by(
        Finding.resource_id, Finding.resource_name,
        Finding.service, Finding.region, Finding.provider_id,
    )

    if status == "at_risk":
        base_q = base_q.having(func.sum(case((Finding.status == "FAIL", 1), else_=0)) > 0)
    elif status == "compliant":
        base_q = base_q.having(func.sum(case((Finding.status == "FAIL", 1), else_=0)) == 0)

    base_q = base_q.order_by("max_severity_rank").limit(limit)

    result = await db.execute(base_q)
    rows = result.all()

    # Gather provider metadata
    provider_ids = list({r.provider_id for r in rows if r.provider_id})
    providers_map = {}
    if provider_ids:
        prov_result = await db.execute(
            select(Provider).where(Provider.id.in_(provider_ids))
        )
        for p in prov_result.scalars().all():
            providers_map[p.id] = {
                "provider_type": p.provider_type,
                "alias": p.alias,
                "account_id": p.account_id,
            }

    severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "informational"}

    # Build graph nodes & edges
    nodes = []
    edges = []
    node_ids = set()

    # Root node — the cloud environment
    root_id = "root"
    nodes.append({
        "id": root_id,
        "label": "Cloud Environment",
        "type": "root",
        "category": "root",
        "severity": None,
        "meta": {},
    })
    node_ids.add(root_id)

    for r in rows:
        pinfo = providers_map.get(r.provider_id, {})
        ptype = pinfo.get("provider_type", "unknown")
        alias = pinfo.get("alias", ptype)
        account = pinfo.get("account_id", "")
        svc = r.service or "Unknown"
        region = r.region or "global"
        sev = severity_map.get(r.max_severity_rank, "informational")
        is_at_risk = r.failed_count > 0

        # Provider node
        prov_node_id = f"provider:{r.provider_id}"
        if prov_node_id not in node_ids:
            nodes.append({
                "id": prov_node_id,
                "label": alias,
                "type": "provider",
                "category": ptype,
                "severity": None,
                "meta": {"provider_type": ptype, "account_id": account},
            })
            node_ids.add(prov_node_id)
            edges.append({"source": root_id, "target": prov_node_id, "label": ""})

        if depth == "provider":
            continue

        # Region node
        region_node_id = f"region:{r.provider_id}:{region}"
        if region_node_id not in node_ids:
            nodes.append({
                "id": region_node_id,
                "label": region,
                "type": "region",
                "category": "region",
                "severity": None,
                "meta": {},
            })
            node_ids.add(region_node_id)
            edges.append({"source": prov_node_id, "target": region_node_id, "label": ""})

        if depth == "region":
            continue

        # Service node
        svc_node_id = f"service:{r.provider_id}:{region}:{svc}"
        if svc_node_id not in node_ids:
            nodes.append({
                "id": svc_node_id,
                "label": svc,
                "type": "service",
                "category": _categorize_service(svc),
                "severity": None,
                "meta": {},
            })
            node_ids.add(svc_node_id)
            edges.append({"source": region_node_id, "target": svc_node_id, "label": ""})

        if depth == "service":
            continue

        # Resource node
        res_node_id = f"resource:{r.resource_id}"
        if res_node_id not in node_ids:
            nodes.append({
                "id": res_node_id,
                "label": r.resource_name or r.resource_id or "unnamed",
                "type": "resource",
                "category": _categorize_service(svc),
                "severity": sev if is_at_risk else None,
                "meta": {
                    "resource_id": r.resource_id,
                    "total_findings": r.total_findings,
                    "failed_findings": r.failed_count,
                    "passed_findings": r.passed_count,
                    "status": "at_risk" if is_at_risk else "compliant",
                },
            })
            node_ids.add(res_node_id)
            edges.append({"source": svc_node_id, "target": res_node_id, "label": ""})

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_resources": len([n for n in nodes if n["type"] == "resource"]),
            "at_risk_resources": len([n for n in nodes if n["type"] == "resource" and n.get("severity")]),
            "providers": len([n for n in nodes if n["type"] == "provider"]),
            "services": len([n for n in nodes if n["type"] == "service"]),
            "regions": len([n for n in nodes if n["type"] == "region"]),
        },
    }


@router.get("/stats")
async def security_graph_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Quick statistics for the security graph overview cards."""

    base_q = (
        select(
            Finding.resource_id,
            Finding.service,
            Finding.provider_id,
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("failed"),
            func.min(
                case(
                    (Finding.severity == "critical", literal_column("1")),
                    (Finding.severity == "high", literal_column("2")),
                    (Finding.severity == "medium", literal_column("3")),
                    (Finding.severity == "low", literal_column("4")),
                    else_=literal_column("5"),
                )
            ).label("sev"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.resource_id.isnot(None))
        .where(Finding.resource_id != "")
        .group_by(Finding.resource_id, Finding.service, Finding.provider_id)
    )

    result = await db.execute(base_q)
    rows = result.all()

    total = len(rows)
    at_risk = sum(1 for r in rows if r.failed > 0)
    services = len({r.service for r in rows})
    providers = len({r.provider_id for r in rows})
    sev_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "informational"}
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for r in rows:
        if r.failed > 0:
            s = sev_map.get(r.sev, "informational")
            by_severity[s] += 1

    return {
        "total_resources": total,
        "at_risk": at_risk,
        "compliant": total - at_risk,
        "services": services,
        "providers": providers,
        "by_severity": by_severity,
    }
