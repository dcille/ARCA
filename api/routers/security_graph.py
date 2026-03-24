"""
Security Graph router — builds a real security graph with cross-resource relationships.

Transforms the hierarchical tree (provider→region→service→resource) into a true
security graph with IAM, network, data, and attack-path relationship edges.
"""
from typing import Optional
from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, literal_column, or_

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.models.scan import Scan
from api.models.finding import Finding
from api.services.auth_service import get_current_user

router = APIRouter()

# ── Service categories (expanded) ──
SERVICE_CATEGORIES = {
    # AWS
    "IAM": "identity", "S3": "storage", "EC2": "compute", "RDS": "database",
    "Lambda": "compute", "EBS": "storage", "VPC": "network", "CloudTrail": "logging",
    "CloudWatch": "logging", "KMS": "encryption", "SNS": "messaging", "SQS": "messaging",
    "ELB": "network", "EKS": "compute", "ECS": "compute", "DynamoDB": "database",
    "Redshift": "database", "ElastiCache": "database", "Route53": "network",
    "CloudFront": "network", "GuardDuty": "security", "Config": "management",
    "SecurityHub": "security", "WAF": "security", "Firewall": "network",
    "SecretsManager": "encryption", "ACM": "encryption", "SSM": "management",
    # Azure
    "Storage Accounts": "storage", "Virtual Machines": "compute", "SQL Database": "database",
    "Key Vault": "encryption", "Network Security Groups": "network",
    "Active Directory": "identity", "Monitor": "logging", "App Service": "compute",
    "Azure SQL": "database", "Cosmos DB": "database",
    # GCP
    "Compute Engine": "compute", "Cloud Storage": "storage", "Cloud SQL": "database",
    "BigQuery": "database", "Cloud Logging": "logging", "Cloud KMS": "encryption",
    "GKE": "compute",
    # Generic
    "Compute": "compute", "Networking": "network", "Identity": "identity",
    "Logging": "logging", "Encryption": "encryption", "Storage": "storage",
    "Database": "database", "Security": "security",
}

# Edge type definitions for the security graph
EDGE_TYPES = {
    "hierarchy": {"color": "#d1d5db", "style": "solid", "label": "Contains"},
    "has_access": {"color": "#3b82f6", "style": "solid", "label": "Has Access"},
    "exposes": {"color": "#ef4444", "style": "dashed", "label": "Exposes"},
    "internet_exposed": {"color": "#dc2626", "style": "dashed", "label": "Internet Exposed"},
    "stores_data": {"color": "#8b5cf6", "style": "solid", "label": "Stores Data"},
    "encrypts": {"color": "#10b981", "style": "solid", "label": "Encrypts"},
    "logs": {"color": "#06b6d4", "style": "solid", "label": "Logs"},
    "attack_path": {"color": "#dc2626", "style": "dotted", "label": "Attack Path"},
    "network_path": {"color": "#f59e0b", "style": "solid", "label": "Network Path"},
    "monitors": {"color": "#06b6d4", "style": "solid", "label": "Monitors"},
}

# Check patterns that indicate specific relationships
IAM_ACCESS_PATTERNS = [
    "admin", "privilege", "access_key", "policy", "permission", "role",
    "assume", "cross_account", "mfa", "password", "credential",
]
NETWORK_EXPOSURE_PATTERNS = [
    "0.0.0.0", "unrestricted", "public", "open_port", "ingress",
    "ssh", "rdp", "any_source", "all_traffic", "security_group",
    "nsg", "firewall", "waf",
]
DATA_STORE_SERVICES = {
    "S3", "RDS", "DynamoDB", "Redshift", "ElastiCache", "EBS",
    "Storage Accounts", "SQL Database", "Cloud Storage", "Cloud SQL",
    "BigQuery", "Cosmos DB", "Azure SQL", "SecretsManager", "Key Vault",
}
ENCRYPTION_SERVICES = {"KMS", "Cloud KMS", "Key Vault", "ACM", "SecretsManager"}
LOGGING_SERVICES = {"CloudTrail", "CloudWatch", "Cloud Logging", "Monitor", "GuardDuty", "Config"}


def _categorize_service(service: str) -> str:
    if not service:
        return "other"
    for key, category in SERVICE_CATEGORIES.items():
        if key.lower() in service.lower():
            return category
    return "other"


def _is_iam_related(check_id: str, check_title: str) -> bool:
    lower = (check_id + " " + (check_title or "")).lower()
    return any(p in lower for p in IAM_ACCESS_PATTERNS)


def _is_network_exposure(check_id: str, check_title: str, status_ext: str) -> bool:
    lower = (check_id + " " + (check_title or "") + " " + (status_ext or "")).lower()
    return any(p in lower for p in NETWORK_EXPOSURE_PATTERNS)


def _infer_relationships(rows, findings_detail, providers_map):
    """
    Infer cross-resource relationships from findings data.
    Returns a list of relationship edges.
    """
    relationship_edges = []
    resource_nodes = {}  # resource_id -> node_id
    service_nodes = {}   # (provider_id, region, service) -> node_id

    # Build lookup maps
    for r in rows:
        res_id = f"resource:{r.resource_id}"
        resource_nodes[r.resource_id] = res_id
        svc = r.service or "Unknown"
        region = r.region or "global"
        svc_key = (r.provider_id, region, svc)
        service_nodes[svc_key] = f"service:{r.provider_id}:{region}:{svc}"

    # Group findings by resource for relationship analysis
    resource_findings = defaultdict(list)
    for f in findings_detail:
        if f.resource_id:
            resource_findings[f.resource_id].append(f)

    iam_resources = set()
    network_exposed_resources = set()
    data_store_resources = set()
    encryption_resources = set()
    logging_resources = set()

    # Classify resources by their findings and service type
    for r in rows:
        svc = r.service or ""
        res_id = r.resource_id

        if _categorize_service(svc) == "identity":
            iam_resources.add(res_id)
        if any(ds.lower() in svc.lower() for ds in DATA_STORE_SERVICES):
            data_store_resources.add(res_id)
        if any(es.lower() in svc.lower() for es in ENCRYPTION_SERVICES):
            encryption_resources.add(res_id)
        if any(ls.lower() in svc.lower() for ls in LOGGING_SERVICES):
            logging_resources.add(res_id)

    # Analyze findings for network exposure
    for res_id, findings in resource_findings.items():
        for f in findings:
            check_id = f.check_id or ""
            title = f.check_title or ""
            status_ext = f.status_extended or ""

            if f.status == "FAIL" and _is_network_exposure(check_id, title, status_ext):
                network_exposed_resources.add(res_id)

    # ── Generate relationship edges ──

    # 1. IAM → Resource access relationships
    # IAM resources with FAIL findings indicate excessive access to other resources
    for iam_res in iam_resources:
        iam_node = resource_nodes.get(iam_res)
        if not iam_node:
            continue
        iam_findings = resource_findings.get(iam_res, [])
        has_excessive = any(
            f.status == "FAIL" and _is_iam_related(f.check_id or "", f.check_title or "")
            for f in iam_findings
        )
        if has_excessive:
            # IAM with issues → connect to data stores in same provider
            iam_provider = None
            for r in rows:
                if r.resource_id == iam_res:
                    iam_provider = r.provider_id
                    break
            if iam_provider:
                for ds_res in data_store_resources:
                    ds_node = resource_nodes.get(ds_res)
                    if not ds_node or ds_node == iam_node:
                        continue
                    # Check same provider
                    for r in rows:
                        if r.resource_id == ds_res and r.provider_id == iam_provider:
                            relationship_edges.append({
                                "source": iam_node,
                                "target": ds_node,
                                "label": "Excessive Access",
                                "edge_type": "has_access",
                                "risk_level": "high",
                            })
                            break

    # 2. Internet → Network-exposed resources
    for exposed_res in network_exposed_resources:
        res_node = resource_nodes.get(exposed_res)
        if res_node:
            relationship_edges.append({
                "source": "internet",
                "target": res_node,
                "label": "Internet Exposed",
                "edge_type": "internet_exposed",
                "risk_level": "critical",
            })

    # 3. Data store relationships (encryption, logging)
    for ds_res in data_store_resources:
        ds_node = resource_nodes.get(ds_res)
        if not ds_node:
            continue
        ds_provider = None
        for r in rows:
            if r.resource_id == ds_res:
                ds_provider = r.provider_id
                break

        if ds_provider:
            # Link encryption services to data stores in same provider
            for enc_res in encryption_resources:
                enc_node = resource_nodes.get(enc_res)
                if not enc_node or enc_node == ds_node:
                    continue
                for r in rows:
                    if r.resource_id == enc_res and r.provider_id == ds_provider:
                        relationship_edges.append({
                            "source": enc_node,
                            "target": ds_node,
                            "label": "Encrypts",
                            "edge_type": "encrypts",
                            "risk_level": "low",
                        })
                        break

            # Link logging services to data stores
            for log_res in logging_resources:
                log_node = resource_nodes.get(log_res)
                if not log_node or log_node == ds_node:
                    continue
                for r in rows:
                    if r.resource_id == log_res and r.provider_id == ds_provider:
                        relationship_edges.append({
                            "source": log_node,
                            "target": ds_node,
                            "label": "Monitors",
                            "edge_type": "monitors",
                            "risk_level": "low",
                        })
                        break

    # 4. Network path relationships (SG/NSG → Compute)
    for r in rows:
        svc = r.service or ""
        if _categorize_service(svc) == "network" and r.resource_id in resource_nodes:
            net_node = resource_nodes[r.resource_id]
            # Connect to compute resources in same region/provider
            for r2 in rows:
                if (r2.provider_id == r.provider_id and
                    r2.region == r.region and
                    _categorize_service(r2.service or "") == "compute" and
                    r2.resource_id in resource_nodes):
                    compute_node = resource_nodes[r2.resource_id]
                    if compute_node != net_node:
                        relationship_edges.append({
                            "source": net_node,
                            "target": compute_node,
                            "label": "Network Path",
                            "edge_type": "network_path",
                            "risk_level": "medium",
                        })

    return (
        relationship_edges,
        network_exposed_resources,
        data_store_resources,
        iam_resources,
    )


@router.get("/graph")
async def get_security_graph(
    provider_type: Optional[str] = None,
    provider_id: Optional[str] = None,
    service: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = Query(None, description="at_risk or compliant"),
    depth: str = Query("resource", description="Granularity: provider, region, service, resource"),
    limit: int = Query(300, le=2000),
    include_relationships: bool = Query(True, description="Include cross-resource relationship edges"),
    edge_types: Optional[str] = Query(None, description="Comma-separated edge types to include"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Build a security graph with hierarchical + relationship edges."""

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

    # If relationships enabled, fetch detailed findings for inference
    findings_detail = []
    if include_relationships and depth == "resource" and rows:
        resource_ids = [r.resource_id for r in rows if r.resource_id]
        if resource_ids:
            detail_q = (
                select(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .where(Scan.user_id == current_user.id)
                .where(Finding.resource_id.in_(resource_ids))
            )
            detail_result = await db.execute(detail_q)
            findings_detail = detail_result.scalars().all()

    severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "informational"}

    # Build graph nodes & edges
    nodes = []
    edges = []
    node_ids = set()

    # Root node
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
        category = _categorize_service(svc)

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
            edges.append({"source": root_id, "target": prov_node_id, "label": "", "edge_type": "hierarchy"})

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
            edges.append({"source": prov_node_id, "target": region_node_id, "label": "", "edge_type": "hierarchy"})

        if depth == "region":
            continue

        # Service node
        svc_node_id = f"service:{r.provider_id}:{region}:{svc}"
        if svc_node_id not in node_ids:
            nodes.append({
                "id": svc_node_id,
                "label": svc,
                "type": "service",
                "category": category,
                "severity": None,
                "meta": {"service_category": category},
            })
            node_ids.add(svc_node_id)
            edges.append({"source": region_node_id, "target": svc_node_id, "label": "", "edge_type": "hierarchy"})

        if depth == "service":
            continue

        # Resource node
        res_node_id = f"resource:{r.resource_id}"
        if res_node_id not in node_ids:
            is_data_store = any(ds.lower() in svc.lower() for ds in DATA_STORE_SERVICES)
            is_identity = category == "identity"

            nodes.append({
                "id": res_node_id,
                "label": r.resource_name or r.resource_id or "unnamed",
                "type": "resource",
                "category": category,
                "severity": sev if is_at_risk else None,
                "meta": {
                    "resource_id": r.resource_id,
                    "service": svc,
                    "region": region,
                    "provider_type": ptype,
                    "total_findings": r.total_findings,
                    "failed_findings": r.failed_count,
                    "passed_findings": r.passed_count,
                    "status": "at_risk" if is_at_risk else "compliant",
                    "is_data_store": is_data_store,
                    "is_identity": is_identity,
                },
            })
            node_ids.add(res_node_id)
            edges.append({"source": svc_node_id, "target": res_node_id, "label": "", "edge_type": "hierarchy"})

    # ── Infer and add relationship edges ──
    relationship_count = 0
    internet_exposed_count = 0

    if include_relationships and depth == "resource" and findings_detail:
        rel_edges, net_exposed, ds_resources, iam_res = _infer_relationships(
            rows, findings_detail, providers_map
        )
        internet_exposed_count = len(net_exposed)

        # Add Internet node if there are exposed resources
        if net_exposed:
            nodes.append({
                "id": "internet",
                "label": "Internet",
                "type": "internet",
                "category": "external",
                "severity": None,
                "meta": {"description": "External internet access point"},
            })
            node_ids.add("internet")

        # Filter by requested edge types
        allowed_types = None
        if edge_types:
            allowed_types = set(edge_types.split(","))

        for rel in rel_edges:
            if rel["source"] in node_ids and rel["target"] in node_ids:
                if allowed_types and rel["edge_type"] not in allowed_types:
                    continue
                edges.append(rel)
                relationship_count += 1

    # Integrate attack paths as edges
    try:
        from api.models.attack_path import AttackPath as AttackPathModel
        import json

        ap_q = (
            select(AttackPathModel)
            .where(AttackPathModel.user_id == current_user.id)
            .where(AttackPathModel.risk_score >= 50)
            .order_by(AttackPathModel.risk_score.desc())
            .limit(20)
        )
        ap_result = await db.execute(ap_q)
        attack_paths = ap_result.scalars().all()

        for ap in attack_paths:
            try:
                affected = json.loads(ap.affected_resources) if ap.affected_resources else []
                if len(affected) >= 2:
                    # Create attack path edges between consecutive affected resources
                    for i in range(len(affected) - 1):
                        src_node = f"resource:{affected[i]}"
                        tgt_node = f"resource:{affected[i + 1]}"
                        if src_node in node_ids and tgt_node in node_ids:
                            edges.append({
                                "source": src_node,
                                "target": tgt_node,
                                "label": ap.title or "Attack Path",
                                "edge_type": "attack_path",
                                "risk_level": ap.severity,
                                "meta": {"attack_path_id": str(ap.id), "risk_score": ap.risk_score},
                            })
                            relationship_count += 1
            except (json.JSONDecodeError, TypeError):
                continue
    except Exception:
        pass  # Attack paths table may not have data

    return {
        "nodes": nodes,
        "edges": edges,
        "edge_type_definitions": EDGE_TYPES,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_resources": len([n for n in nodes if n["type"] == "resource"]),
            "at_risk_resources": len([n for n in nodes if n["type"] == "resource" and n.get("severity")]),
            "providers": len([n for n in nodes if n["type"] == "provider"]),
            "services": len([n for n in nodes if n["type"] == "service"]),
            "regions": len([n for n in nodes if n["type"] == "region"]),
            "relationship_edges": relationship_count,
            "internet_exposed": internet_exposed_count,
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

    # Count internet-exposed resources (findings with network exposure patterns)
    internet_exposed = 0
    if rows:
        exp_q = (
            select(func.count(func.distinct(Finding.resource_id)))
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.user_id == current_user.id)
            .where(Finding.status == "FAIL")
            .where(
                or_(
                    Finding.check_id.ilike("%unrestricted%"),
                    Finding.check_id.ilike("%public%"),
                    Finding.check_id.ilike("%open%"),
                    Finding.status_extended.ilike("%0.0.0.0%"),
                )
            )
        )
        exp_result = await db.execute(exp_q)
        internet_exposed = exp_result.scalar() or 0

    return {
        "total_resources": total,
        "at_risk": at_risk,
        "compliant": total - at_risk,
        "services": services,
        "providers": providers,
        "by_severity": by_severity,
        "internet_exposed": internet_exposed,
        "has_scan_data": total > 0,
    }


@router.get("/nodes/{node_id}")
async def get_node_detail(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get detailed information about a specific graph node (resource)."""

    # Extract resource_id from node_id format "resource:xxx"
    resource_id = node_id.replace("resource:", "") if node_id.startswith("resource:") else node_id

    # Get all findings for this resource
    findings_q = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.resource_id == resource_id)
        .order_by(
            case(
                (Finding.severity == "critical", 1),
                (Finding.severity == "high", 2),
                (Finding.severity == "medium", 3),
                (Finding.severity == "low", 4),
                else_=5,
            )
        )
    )
    result = await db.execute(findings_q)
    findings = result.scalars().all()

    if not findings:
        return {"node_id": node_id, "resource_id": resource_id, "findings": [], "summary": {}}

    # Build summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    frameworks = set()
    mitre_techniques = set()
    passed = 0
    failed = 0

    findings_list = []
    for f in findings:
        if f.severity:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        if f.status == "PASS":
            passed += 1
        elif f.status == "FAIL":
            failed += 1

        # Parse compliance frameworks
        if f.compliance_frameworks:
            try:
                import json
                fws = json.loads(f.compliance_frameworks)
                if isinstance(fws, list):
                    frameworks.update(fws)
                elif isinstance(fws, dict):
                    frameworks.update(fws.keys())
            except (json.JSONDecodeError, TypeError):
                pass

        findings_list.append({
            "id": str(f.id),
            "check_id": f.check_id,
            "check_title": f.check_title,
            "severity": f.severity,
            "status": f.status,
            "service": f.service,
            "status_extended": f.status_extended,
            "remediation": f.remediation,
        })

    first = findings[0]
    return {
        "node_id": node_id,
        "resource_id": resource_id,
        "resource_name": first.resource_name,
        "service": first.service,
        "region": first.region,
        "provider_type": first.provider_type if hasattr(first, 'provider_type') else None,
        "findings": findings_list,
        "summary": {
            "total_findings": len(findings),
            "passed": passed,
            "failed": failed,
            "severity_breakdown": severity_counts,
            "pass_rate": round(passed / len(findings) * 100, 1) if findings else 0,
        },
        "compliance_frameworks": sorted(frameworks),
        "is_internet_exposed": any(
            _is_network_exposure(f.check_id or "", f.check_title or "", f.status_extended or "")
            and f.status == "FAIL"
            for f in findings
        ),
        "is_data_store": any(
            any(ds.lower() in (f.service or "").lower() for ds in DATA_STORE_SERVICES)
            for f in findings
        ),
    }


@router.get("/blast-radius/{node_id}")
async def get_blast_radius(
    node_id: str,
    max_depth: int = Query(3, le=5),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Compute blast radius: all nodes reachable from a compromised node within N hops.
    Uses BFS over relationship edges (not hierarchy edges).
    """
    # First get the full graph with relationships
    graph_data = await get_security_graph(
        depth="resource",
        include_relationships=True,
        limit=500,
        db=db,
        current_user=current_user,
    )

    nodes_map = {n["id"]: n for n in graph_data["nodes"]}
    if node_id not in nodes_map:
        return {"center_node": node_id, "reachable": [], "depth_map": {}}

    # Build adjacency from relationship edges only (not hierarchy)
    adjacency = defaultdict(set)
    for e in graph_data["edges"]:
        etype = e.get("edge_type", "hierarchy")
        if etype != "hierarchy":
            adjacency[e["source"]].add(e["target"])
            adjacency[e["target"]].add(e["source"])  # bidirectional for blast radius

    # BFS from node_id
    visited = {}
    queue = [(node_id, 0)]
    visited[node_id] = 0

    while queue:
        current, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for neighbor in adjacency.get(current, set()):
            if neighbor not in visited:
                visited[neighbor] = depth + 1
                queue.append((neighbor, depth + 1))

    reachable = []
    for nid, d in visited.items():
        if nid == node_id:
            continue
        node = nodes_map.get(nid)
        if node:
            reachable.append({**node, "blast_depth": d})

    return {
        "center_node": node_id,
        "center_label": nodes_map[node_id].get("label", ""),
        "max_depth": max_depth,
        "total_reachable": len(reachable),
        "reachable": sorted(reachable, key=lambda n: n["blast_depth"]),
        "depth_counts": {
            d: len([n for n in reachable if n["blast_depth"] == d])
            for d in range(1, max_depth + 1)
        },
    }


@router.get("/paths")
async def find_paths(
    source: str = Query(..., description="Source node ID"),
    target: str = Query(..., description="Target node ID"),
    max_paths: int = Query(5, le=10),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Find all paths between two nodes through relationship edges."""
    graph_data = await get_security_graph(
        depth="resource",
        include_relationships=True,
        limit=500,
        db=db,
        current_user=current_user,
    )

    nodes_map = {n["id"]: n for n in graph_data["nodes"]}
    if source not in nodes_map or target not in nodes_map:
        return {"source": source, "target": target, "paths": []}

    # Build adjacency (relationship edges only, directed)
    adjacency = defaultdict(list)
    edge_lookup = {}
    for e in graph_data["edges"]:
        etype = e.get("edge_type", "hierarchy")
        if etype != "hierarchy":
            adjacency[e["source"]].append(e["target"])
            edge_lookup[(e["source"], e["target"])] = e

    # BFS to find paths
    paths = []
    queue = [[source]]

    while queue and len(paths) < max_paths:
        path = queue.pop(0)
        current = path[-1]

        if current == target and len(path) > 1:
            # Build path with edge details
            path_edges = []
            for i in range(len(path) - 1):
                edge = edge_lookup.get((path[i], path[i + 1]), {})
                path_edges.append({
                    "source": path[i],
                    "target": path[i + 1],
                    "edge_type": edge.get("edge_type", "unknown"),
                    "label": edge.get("label", ""),
                })
            paths.append({
                "nodes": [nodes_map.get(nid, {"id": nid}) for nid in path],
                "edges": path_edges,
                "length": len(path) - 1,
            })
            continue

        if len(path) >= 8:
            continue

        for neighbor in adjacency.get(current, []):
            if neighbor not in path:
                queue.append(path + [neighbor])

    return {
        "source": source,
        "source_label": nodes_map[source].get("label", ""),
        "target": target,
        "target_label": nodes_map[target].get("label", ""),
        "paths": paths,
        "total_paths": len(paths),
    }


@router.get("/search")
async def search_nodes(
    q: str = Query(..., min_length=1),
    limit: int = Query(20, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fuzzy search for nodes by name or resource_id."""
    search_q = (
        select(
            Finding.resource_id,
            Finding.resource_name,
            Finding.service,
            Finding.region,
            Finding.provider_id,
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.resource_id.isnot(None))
        .where(
            or_(
                Finding.resource_name.ilike(f"%{q}%"),
                Finding.resource_id.ilike(f"%{q}%"),
                Finding.service.ilike(f"%{q}%"),
            )
        )
        .group_by(
            Finding.resource_id, Finding.resource_name,
            Finding.service, Finding.region, Finding.provider_id,
        )
        .limit(limit)
    )

    result = await db.execute(search_q)
    rows = result.all()

    return {
        "query": q,
        "results": [
            {
                "node_id": f"resource:{r.resource_id}",
                "resource_id": r.resource_id,
                "resource_name": r.resource_name,
                "service": r.service,
                "region": r.region,
            }
            for r in rows
        ],
    }
