"""DSPM router — Data Security Posture Management."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.scan import Scan
from api.models.provider import Provider
from api.services.auth_service import get_current_user
from scanner.dspm.data_store_checks import (
    DSPM_CHECKS,
    DATA_STORE_TYPES,
    get_dspm_checks_for_provider,
    get_dspm_data_stores,
)

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
