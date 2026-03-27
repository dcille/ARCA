"""DSPM router — Data Security Posture Management."""
import json

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.scan import Scan
from api.models.provider import Provider
from api.models.dspm_scan import DSPMScan
from api.models.dspm_finding import DSPMFinding
from api.services.auth_service import get_current_user
from api.schemas.dspm import (
    DSPMScanRequest,
    DSPMScanResponse,
    DSPMScanStatusResponse,
    DSPMFindingStatusUpdate,
)
from scanner.dspm.data_store_checks import (
    DSPM_CHECKS,
    DATA_STORE_TYPES,
    PROVIDER_DATA_CHECK_MAPPING,
    get_dspm_checks_for_provider,
    get_dspm_data_stores,
    get_data_check_ids,
    get_data_checks_for_provider,
    get_data_checks_by_category,
)
from scanner.dspm.pii_scanner import DEFAULT_PATTERNS, PIIScanner
from scanner.dspm.data_classifier import (
    CLASSIFICATION_LEVELS,
    CLASSIFICATION_RULES,
    PII_CATEGORY_MAP,
    TAG_MAPPING,
    DataClassifier,
)
from scanner.dspm.router import DSPMOrchestrator
from scanner.attack_paths.graph_engine import AttackPathAnalyzer

router = APIRouter()


@router.get("/overview")
async def dspm_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """DSPM overview with data store inventory and risk summary."""
    # Get all providers
    providers_q = await db.execute(
        select(Provider).where(Provider.user_id == current_user.id)
    )
    providers = providers_q.scalars().all()

    # Get data-related findings
    data_services = set()
    for provider_stores in DATA_STORE_TYPES.values():
        for store in provider_stores:
            data_services.add(store["service"])

    # Map scanner service names to DSPM data store service names
    _SERVICE_ALIAS = {
        "s3": ["s3"], "rds": ["rds"], "dynamodb": ["dynamodb"],
        "redshift": ["redshift"], "efs": ["efs"], "elasticache": ["elasticache"],
        "secretsmanager": ["secretsmanager", "secrets_manager"],
        "elasticsearch": ["elasticsearch", "opensearch"],
        "azure_blob": ["storage", "azure_blob"], "azure_sql": ["sql", "azure_sql", "database"],
        "cosmosdb": ["cosmosdb", "cosmos"], "azure_files": ["azure_files"],
        "keyvault": ["keyvault", "key_vault", "key vault"],
        "gcs": ["gcs", "cloud_storage", "cloud storage", "storage"],
        "cloudsql": ["cloudsql", "cloud_sql", "cloud sql"],
        "bigquery": ["bigquery"], "firestore": ["firestore"],
        "secretmanager": ["secretmanager", "secret_manager"],
    }

    # Count findings by data service (including aliases)
    findings_q = await db.execute(
        select(Finding.service, Finding.status, Finding.check_id, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .group_by(Finding.service, Finding.status, Finding.check_id)
    )
    service_findings: dict[str, dict] = {}
    for service, status, check_id, count in findings_q.all():
        svc_lower = service.lower()
        # Direct match
        if svc_lower not in service_findings:
            service_findings[svc_lower] = {"pass": 0, "fail": 0, "total": 0}
        if status == "PASS":
            service_findings[svc_lower]["pass"] += count
        else:
            service_findings[svc_lower]["fail"] += count
        service_findings[svc_lower]["total"] += count

        # Also map to DSPM service aliases
        for dspm_svc, aliases in _SERVICE_ALIAS.items():
            if svc_lower in aliases and dspm_svc != svc_lower:
                if dspm_svc not in service_findings:
                    service_findings[dspm_svc] = {"pass": 0, "fail": 0, "total": 0}
                if status == "PASS":
                    service_findings[dspm_svc]["pass"] += count
                else:
                    service_findings[dspm_svc]["fail"] += count
                service_findings[dspm_svc]["total"] += count

    # Build data store inventory across all providers
    data_inventory = []
    for p in providers:
        stores = get_dspm_data_stores(p.provider_type)
        for store in stores:
            svc = store["service"]
            findings = service_findings.get(svc, {"pass": 0, "fail": 0, "total": 0})
            data_inventory.append({
                "provider_id": p.id,
                "provider_type": p.provider_type,
                "provider_alias": p.alias,
                "service": svc,
                "label": store["label"],
                "store_type": store["type"],
                "total_findings": findings["total"],
                "passed": findings["pass"],
                "failed": findings["fail"],
                "risk_score": _calculate_risk_score(findings["fail"], findings["total"]),
            })

    # Overall stats
    total_stores = len(data_inventory)
    stores_at_risk = sum(1 for d in data_inventory if d["failed"] > 0)
    total_data_findings = sum(d["total_findings"] for d in data_inventory)
    total_data_passed = sum(d["passed"] for d in data_inventory)
    data_pass_rate = round((total_data_passed / total_data_findings * 100) if total_data_findings > 0 else 0, 1)

    return {
        "summary": {
            "total_data_stores": total_stores,
            "stores_at_risk": stores_at_risk,
            "total_findings": total_data_findings,
            "pass_rate": data_pass_rate,
            "providers_scanned": len(providers),
        },
        "data_inventory": sorted(data_inventory, key=lambda d: -d["failed"]),
        "check_catalog": [
            {
                "check_id": c["check_id"],
                "title": c["title"],
                "category": c["category"],
                "severity": c["severity"],
                "description": c["description"],
            }
            for c in DSPM_CHECKS
        ],
    }


@router.get("/checks")
async def dspm_checks(
    provider_type: Optional[str] = None,
):
    """List all DSPM checks, optionally filtered by provider."""
    if provider_type:
        checks = get_dspm_checks_for_provider(provider_type)
    else:
        checks = DSPM_CHECKS

    return [
        {
            "check_id": c["check_id"],
            "title": c["title"],
            "category": c["category"],
            "severity": c["severity"],
            "description": c["description"],
            "remediation": c["remediation"],
            "applies_to": c["applies_to"],
        }
        for c in checks
    ]


@router.get("/data-stores")
async def dspm_data_stores(
    provider_type: Optional[str] = None,
):
    """List data store types, optionally filtered by provider."""
    if provider_type:
        return get_dspm_data_stores(provider_type)

    all_stores = []
    for provider, stores in DATA_STORE_TYPES.items():
        for s in stores:
            all_stores.append({**s, "provider": provider})
    return all_stores


@router.get("/attack-paths")
async def dspm_attack_paths(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Data-related attack paths derived from data store findings."""
    data_check_ids = get_data_check_ids()

    # Get all data-related findings
    findings_q = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.user_id == current_user.id,
            Finding.check_id.in_(data_check_ids),
        )
    )
    findings = findings_q.scalars().all()

    if not findings:
        return {"attack_paths": [], "summary": {"total_paths": 0, "critical": 0, "high": 0}}

    # Convert to dicts for the analyzer
    finding_dicts = []
    for f in findings:
        finding_dicts.append({
            "id": str(f.id),
            "check_id": f.check_id,
            "check_title": f.check_title or f.check_id,
            "service": f.service,
            "severity": f.severity,
            "status": f.status,
            "resource_id": f.resource_id or "",
            "resource_name": f.resource_name or "",
            "region": f.region or "",
            "remediation": f.remediation or "",
        })

    analyzer = AttackPathAnalyzer(finding_dicts)
    paths = analyzer.analyze()

    result_paths = []
    for p in paths:
        result_paths.append({
            "id": p.id,
            "title": p.title,
            "description": p.description,
            "severity": p.severity,
            "risk_score": p.risk_score,
            "category": p.category,
            "entry_point": p.entry_point,
            "target": p.target,
            "techniques": p.techniques,
            "affected_resources": p.affected_resources,
            "remediation": p.remediation,
            "nodes": [
                {"id": n.id, "type": n.node_type.value, "label": n.label, "service": n.service}
                for n in p.nodes
            ],
            "edges": [
                {"source": e.source_id, "target": e.target_id, "type": e.edge_type.value, "label": e.label}
                for e in p.edges
            ],
        })

    critical = sum(1 for p in result_paths if p["severity"] == "critical")
    high = sum(1 for p in result_paths if p["severity"] == "high")

    return {
        "attack_paths": result_paths,
        "summary": {
            "total_paths": len(result_paths),
            "critical": critical,
            "high": high,
        },
    }


@router.get("/findings")
async def dspm_findings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    category: Optional[str] = None,
    provider: Optional[str] = None,
    data_store: Optional[str] = None,
):
    """All data-related findings from provider scans, mapped to DSPM categories."""
    data_check_ids = get_data_check_ids()

    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.user_id == current_user.id,
            Finding.check_id.in_(data_check_ids),
        )
    )
    findings_q = await db.execute(query)
    findings = findings_q.scalars().all()

    results = []
    for f in findings:
        mapping = PROVIDER_DATA_CHECK_MAPPING.get(f.check_id)
        if not mapping:
            continue
        if category and mapping["category"] != category:
            continue
        if provider and mapping["provider"] != provider:
            continue
        if data_store and mapping["data_store"] != data_store:
            continue

        results.append({
            "id": str(f.id),
            "check_id": f.check_id,
            "check_title": f.check_title or f.check_id,
            "service": f.service,
            "severity": f.severity,
            "status": f.status,
            "resource_id": f.resource_id or "",
            "resource_name": f.resource_name or "",
            "dspm_category": mapping["category"],
            "dspm_data_store": mapping["data_store"],
            "dspm_provider": mapping["provider"],
            "remediation": f.remediation or "",
        })

    # Category summary
    cat_summary: dict[str, dict] = {}
    for r in results:
        cat = r["dspm_category"]
        if cat not in cat_summary:
            cat_summary[cat] = {"total": 0, "pass": 0, "fail": 0}
        cat_summary[cat]["total"] += 1
        if r["status"] == "PASS":
            cat_summary[cat]["pass"] += 1
        else:
            cat_summary[cat]["fail"] += 1

    return {
        "findings": sorted(results, key=lambda x: (x["status"] != "FAIL", x["severity"])),
        "category_summary": cat_summary,
        "total": len(results),
    }


@router.get("/pii-patterns")
async def dspm_pii_patterns():
    """Return all available PII detection patterns from the PII scanner module."""
    patterns_by_category: dict[str, list[dict]] = {}

    for p in DEFAULT_PATTERNS:
        entry = {
            "pattern_id": p.pattern_id,
            "name": p.name,
            "category": p.category,
            "gdpr_category": p.gdpr_category,
            "severity": p.severity,
            "has_validator": p.validator is not None,
            "confidence": "high" if p.validator is not None else "medium",
        }
        patterns_by_category.setdefault(p.gdpr_category, []).append(entry)

    # Summary counts
    severity_counts: dict[str, int] = {}
    for p in DEFAULT_PATTERNS:
        severity_counts[p.severity] = severity_counts.get(p.severity, 0) + 1

    return {
        "total_patterns": len(DEFAULT_PATTERNS),
        "patterns_by_gdpr_category": patterns_by_category,
        "patterns": [
            {
                "pattern_id": p.pattern_id,
                "name": p.name,
                "category": p.category,
                "gdpr_category": p.gdpr_category,
                "severity": p.severity,
                "has_validator": p.validator is not None,
                "confidence": "high" if p.validator is not None else "medium",
            }
            for p in DEFAULT_PATTERNS
        ],
        "severity_summary": severity_counts,
    }


@router.get("/classification-levels")
async def dspm_classification_levels():
    """Return data classification levels, rules, and tag conventions."""
    level_descriptions = {
        "public": {
            "label": "Public",
            "description": "Data intended for public access. No PII or sensitive content.",
            "color": "green",
            "order": 0,
        },
        "internal": {
            "label": "Internal",
            "description": "Internal data containing medium-sensitivity PII such as emails or phone numbers.",
            "color": "blue",
            "order": 1,
        },
        "confidential": {
            "label": "Confidential",
            "description": "Confidential data with high-severity PII such as government IDs or passports.",
            "color": "orange",
            "order": 2,
        },
        "restricted": {
            "label": "Restricted",
            "description": "Highly restricted data with critical PII: financial records, health data, or national IDs.",
            "color": "red",
            "order": 3,
        },
    }

    rules = []
    for r in CLASSIFICATION_RULES:
        rules.append({
            "pii_categories": r["pii_categories"],
            "min_matches": r["min_matches"],
            "level": r["level"],
            "confidence": r["confidence"],
        })

    return {
        "levels": list(CLASSIFICATION_LEVELS),
        "level_details": level_descriptions,
        "rules": rules,
        "pii_category_map": PII_CATEGORY_MAP,
        "tag_conventions": TAG_MAPPING,
    }


@router.post("/scan")
async def dspm_scan(
    request: DSPMScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Launch a DSPM scan. Runs DSPMOrchestrator via Celery in background.

    One scan per provider. If provider_id is omitted, scans all providers.
    Returns scan_id(s) for tracking.
    """
    from api.tasks.dspm_tasks import run_dspm_scan

    # Get provider(s)
    if request.provider_id:
        prov_q = await db.execute(
            select(Provider).where(
                Provider.id == request.provider_id,
                Provider.user_id == current_user.id,
            )
        )
        provider = prov_q.scalar_one_or_none()
        if not provider:
            raise HTTPException(status_code=404, detail="Provider not found")
        providers = [provider]
    else:
        prov_q = await db.execute(
            select(Provider).where(Provider.user_id == current_user.id)
        )
        providers = prov_q.scalars().all()

    if not providers:
        raise HTTPException(status_code=400, detail="No providers configured. Add a cloud provider first.")

    scans_created = []
    for provider in providers:
        dspm_scan_record = DSPMScan(
            user_id=current_user.id,
            provider_id=provider.id,
            status="pending",
            enable_content_scanning=request.enable_content_scanning,
        )
        db.add(dspm_scan_record)
        await db.flush()

        task = run_dspm_scan.delay(
            dspm_scan_id=dspm_scan_record.id,
            provider_id=provider.id,
            user_id=current_user.id,
            enable_content_scanning=request.enable_content_scanning,
            skip_modules=request.skip_modules,
        )

        dspm_scan_record.task_id = task.id
        scans_created.append({
            "scan_id": dspm_scan_record.id,
            "task_id": task.id,
            "provider_id": provider.id,
            "provider_type": provider.provider_type,
            "provider_alias": provider.alias,
        })

    await db.commit()

    if len(scans_created) == 1:
        s = scans_created[0]
        return DSPMScanResponse(
            scan_id=s["scan_id"],
            task_id=s["task_id"],
            status="queued",
            message=f"DSPM scan queued for {s['provider_type']} ({s['provider_alias']})",
        )

    return {
        "status": "queued",
        "message": f"DSPM scans queued for {len(scans_created)} providers",
        "scans": scans_created,
    }


@router.get("/scan-status/{scan_id}")
async def dspm_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the status of a DSPM scan."""
    q = await db.execute(
        select(DSPMScan).where(
            DSPMScan.id == scan_id,
            DSPMScan.user_id == current_user.id,
        )
    )
    scan = q.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="DSPM scan not found")

    return DSPMScanStatusResponse(
        scan_id=scan.id,
        task_id=scan.task_id or "",
        status=scan.status,
        total_findings=scan.total_findings,
        overall_risk_score=scan.overall_risk_score,
        overall_risk_label=scan.overall_risk_label,
        modules_run=scan.modules_run,
        modules_failed=scan.modules_failed,
        findings_by_severity=json.loads(scan.findings_by_severity) if scan.findings_by_severity else None,
        findings_by_module=json.loads(scan.findings_by_module) if scan.findings_by_module else None,
        duration_seconds=scan.duration_seconds,
        completed_at=scan.completed_at,
    )


@router.get("/scans")
async def dspm_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100),
):
    """List DSPM scans for the current user."""
    q = await db.execute(
        select(DSPMScan)
        .where(DSPMScan.user_id == current_user.id)
        .order_by(desc(DSPMScan.created_at))
        .limit(limit)
    )
    scans = q.scalars().all()

    # Fetch provider info
    prov_q = await db.execute(
        select(Provider).where(Provider.user_id == current_user.id)
    )
    providers_map = {p.id: p for p in prov_q.scalars().all()}

    results = []
    for s in scans:
        prov = providers_map.get(s.provider_id)
        results.append({
            "scan_id": s.id,
            "task_id": s.task_id,
            "status": s.status,
            "provider_id": s.provider_id,
            "provider_type": prov.provider_type if prov else None,
            "provider_alias": prov.alias if prov else None,
            "total_findings": s.total_findings,
            "overall_risk_score": s.overall_risk_score,
            "overall_risk_label": s.overall_risk_label,
            "modules_run": s.modules_run,
            "duration_seconds": s.duration_seconds,
            "enable_content_scanning": s.enable_content_scanning,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        })

    return results


@router.get("/scans/{scan_id}")
async def dspm_scan_detail(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get detailed DSPM scan with all findings grouped by module."""
    q = await db.execute(
        select(DSPMScan).where(
            DSPMScan.id == scan_id,
            DSPMScan.user_id == current_user.id,
        )
    )
    scan = q.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="DSPM scan not found")

    # Get findings
    findings_q = await db.execute(
        select(DSPMFinding)
        .where(DSPMFinding.scan_id == scan_id)
        .order_by(desc(DSPMFinding.risk_score))
    )
    findings = findings_q.scalars().all()

    # Group by module
    by_module: dict[str, list[dict]] = {}
    for f in findings:
        entry = {
            "id": f.id,
            "module": f.module,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "description": f.description,
            "resource_id": f.resource_id,
            "resource_name": f.resource_name,
            "category": f.category,
            "remediation": f.remediation,
            "risk_score": f.risk_score,
            "evidence": json.loads(f.evidence) if f.evidence else None,
            "status": f.status,
            "source": "dspm_engine",
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        by_module.setdefault(f.module, []).append(entry)

    # Provider info
    prov = None
    if scan.provider_id:
        prov_q = await db.execute(select(Provider).where(Provider.id == scan.provider_id))
        prov = prov_q.scalar_one_or_none()

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "provider_id": scan.provider_id,
        "provider_type": prov.provider_type if prov else None,
        "provider_alias": prov.alias if prov else None,
        "total_findings": scan.total_findings,
        "overall_risk_score": scan.overall_risk_score,
        "overall_risk_label": scan.overall_risk_label,
        "modules_run": scan.modules_run,
        "modules_failed": scan.modules_failed,
        "findings_by_severity": json.loads(scan.findings_by_severity) if scan.findings_by_severity else {},
        "findings_by_module": json.loads(scan.findings_by_module) if scan.findings_by_module else {},
        "duration_seconds": scan.duration_seconds,
        "fingerprint": scan.fingerprint,
        "enable_content_scanning": scan.enable_content_scanning,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings_by_module_detail": by_module,
        "all_findings": [e for findings_list in by_module.values() for e in findings_list],
    }


@router.get("/scan-findings")
async def dspm_scan_findings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    module: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Get DSPM findings with filters. Returns both cloud scanner and DSPM engine findings."""
    # DSPM engine findings
    query = (
        select(DSPMFinding)
        .where(DSPMFinding.user_id == current_user.id)
    )
    if module:
        query = query.where(DSPMFinding.module == module)
    if severity:
        query = query.where(DSPMFinding.severity == severity)
    if category:
        query = query.where(DSPMFinding.category == category)
    if status:
        query = query.where(DSPMFinding.status == status)
    if scan_id:
        query = query.where(DSPMFinding.scan_id == scan_id)

    query = query.order_by(desc(DSPMFinding.risk_score)).offset(offset).limit(limit)

    findings_q = await db.execute(query)
    dspm_findings = findings_q.scalars().all()

    # Count total
    count_query = (
        select(func.count(DSPMFinding.id))
        .where(DSPMFinding.user_id == current_user.id)
    )
    if module:
        count_query = count_query.where(DSPMFinding.module == module)
    if severity:
        count_query = count_query.where(DSPMFinding.severity == severity)
    if category:
        count_query = count_query.where(DSPMFinding.category == category)
    if status:
        count_query = count_query.where(DSPMFinding.status == status)
    if scan_id:
        count_query = count_query.where(DSPMFinding.scan_id == scan_id)

    total_q = await db.execute(count_query)
    total = total_q.scalar() or 0

    results = []
    for f in dspm_findings:
        results.append({
            "id": f.id,
            "scan_id": f.scan_id,
            "module": f.module,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "description": f.description,
            "resource_id": f.resource_id,
            "resource_name": f.resource_name,
            "category": f.category,
            "remediation": f.remediation,
            "risk_score": f.risk_score,
            "evidence": json.loads(f.evidence) if f.evidence else None,
            "status": f.status,
            "source": "dspm_engine",
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    return {
        "findings": results,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.put("/scan-findings/{finding_id}/status")
async def update_dspm_finding_status(
    finding_id: str,
    update: DSPMFindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update the status of a DSPM finding (open/resolved/ignored)."""
    if update.status not in ("open", "resolved", "ignored"):
        raise HTTPException(status_code=400, detail="Status must be one of: open, resolved, ignored")

    q = await db.execute(
        select(DSPMFinding).where(
            DSPMFinding.id == finding_id,
            DSPMFinding.user_id == current_user.id,
        )
    )
    finding = q.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="DSPM finding not found")

    finding.status = update.status
    await db.commit()

    return {"id": finding.id, "status": finding.status, "message": f"Finding status updated to '{update.status}'"}


@router.get("/scan-capabilities")
async def dspm_scan_capabilities():
    """Return a summary of all DSPM module capabilities and status."""
    modules = [
        {
            "id": "pii_scanner",
            "name": "PII Scanner",
            "description": "Detects Personally Identifiable Information across text, files, and structured data with GDPR-focused pattern matching.",
            "capabilities": [
                "Text scanning with regex-based PII detection",
                "File content scanning (UTF-8 and Latin-1)",
                "Structured data scanning (CSV/JSON rows)",
                "Validator-based confidence scoring (Luhn, DNI, NIE, IBAN)",
                "Automatic match redaction for safe reporting",
            ],
            "pattern_count": len(DEFAULT_PATTERNS),
            "status": "active",
        },
        {
            "id": "permission_analyzer",
            "name": "Permission Analyzer",
            "description": "Analyses effective permissions on cloud data stores to identify public access, cross-account access, and excessive privileges.",
            "capabilities": [
                "Public access detection",
                "Cross-account principal analysis",
                "Admin privilege enumeration",
                "Risk factor identification",
            ],
            "status": "active",
        },
        {
            "id": "shadow_detector",
            "name": "Shadow Data Detector",
            "description": "Detects shadow copies of sensitive data in unmanaged or unexpected locations across cloud providers.",
            "capabilities": [
                "Unmanaged data store discovery",
                "Shadow copy detection",
                "Cross-region data replication alerts",
            ],
            "status": "active",
        },
        {
            "id": "data_classifier",
            "name": "Data Classifier",
            "description": "Classifies cloud resources based on content analysis (PII scan results) and existing cloud tags, detecting misclassifications.",
            "capabilities": [
                "Content-based classification (public/internal/confidential/restricted)",
                "Tag-based classification from cloud resource tags",
                "Misclassification detection",
                "Bulk classification support",
                "Tag recommendation generation per cloud provider",
            ],
            "classification_levels": list(CLASSIFICATION_LEVELS),
            "status": "active",
        },
        {
            "id": "content_sampler",
            "name": "Content Sampler",
            "description": "Samples content from cloud data stores for PII and classification analysis without downloading entire datasets.",
            "capabilities": [
                "Configurable sampling strategies",
                "Support for multiple data store types",
                "Size-limited content extraction",
            ],
            "status": "active",
        },
        {
            "id": "native_integrations",
            "name": "Native Integrations",
            "description": "Checks the status of native cloud data-security services (e.g. AWS Macie, Azure Purview) and recommends enabling them.",
            "capabilities": [
                "Cloud-native service status checks",
                "Integration recommendations",
                "Multi-provider support (AWS, Azure, GCP)",
            ],
            "status": "active",
        },
        {
            "id": "data_store_checks",
            "name": "Data Store Checks",
            "description": "Security checks for cloud data stores covering encryption, access control, backup, retention, logging, and classification.",
            "capabilities": [
                "Encryption-at-rest and in-transit validation",
                "Access control policy checks",
                "Backup and retention compliance",
                "Logging and audit trail verification",
                "Classification tag presence checks",
            ],
            "check_count": len(DSPM_CHECKS),
            "status": "active",
        },
    ]

    return {
        "total_modules": len(modules),
        "active_modules": sum(1 for m in modules if m["status"] == "active"),
        "modules": modules,
        "total_pii_patterns": len(DEFAULT_PATTERNS),
        "total_security_checks": len(DSPM_CHECKS),
        "classification_levels": list(CLASSIFICATION_LEVELS),
    }


def _calculate_risk_score(failed: int, total: int) -> str:
    """Simple risk classification."""
    if total == 0:
        return "unknown"
    fail_rate = failed / total
    if fail_rate > 0.5:
        return "critical"
    if fail_rate > 0.3:
        return "high"
    if fail_rate > 0.1:
        return "medium"
    if fail_rate > 0:
        return "low"
    return "none"
