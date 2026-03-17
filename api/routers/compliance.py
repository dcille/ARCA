"""Compliance router."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.scan import Scan
from api.services.auth_service import get_current_user

router = APIRouter()

COMPLIANCE_FRAMEWORKS = {
    "CIS-AWS-1.5": {
        "name": "CIS Amazon Web Services Foundations Benchmark v1.5",
        "description": "Center for Internet Security AWS benchmark",
    },
    "CIS-Azure-2.0": {
        "name": "CIS Microsoft Azure Foundations Benchmark v2.0",
        "description": "Center for Internet Security Azure benchmark",
    },
    "CIS-GCP-2.0": {
        "name": "CIS Google Cloud Platform Foundation Benchmark v2.0",
        "description": "Center for Internet Security GCP benchmark",
    },
    "CIS-OCI-2.0": {
        "name": "CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0",
        "description": "Center for Internet Security OCI benchmark",
    },
    "CIS-Alibaba-1.0": {
        "name": "CIS Alibaba Cloud Foundation Benchmark v1.0",
        "description": "Center for Internet Security Alibaba Cloud benchmark",
    },
    "NIST-800-53": {
        "name": "NIST SP 800-53 Rev. 5",
        "description": "Security and Privacy Controls for Information Systems",
    },
    "PCI-DSS-3.2.1": {
        "name": "PCI DSS v3.2.1",
        "description": "Payment Card Industry Data Security Standard",
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act",
    },
    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2",
    },
    "ISO-27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "Information security management systems",
    },
    "GDPR": {
        "name": "GDPR",
        "description": "General Data Protection Regulation",
    },
    "NIST-CSF": {
        "name": "NIST Cybersecurity Framework",
        "description": "Framework for Improving Critical Infrastructure Cybersecurity",
    },
}


@router.get("/frameworks")
async def list_frameworks():
    return [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in COMPLIANCE_FRAMEWORKS.items()
    ]


@router.get("/summary")
async def compliance_summary(
    framework: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        select(Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if framework:
        query = query.where(Finding.compliance_frameworks.contains(framework))
    query = query.group_by(Finding.status)

    result = await db.execute(query)
    counts = {row[0]: row[1] for row in result.all()}

    passed = counts.get("PASS", 0)
    failed = counts.get("FAIL", 0)
    total = passed + failed
    pass_rate = (passed / total * 100) if total > 0 else 0

    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(pass_rate, 1),
    }


@router.get("/frameworks/{framework_id}/checks")
async def framework_checks(
    framework_id: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=200, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if framework_id not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    base_filter = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.compliance_frameworks.contains(framework_id))
    )

    if status:
        base_filter = base_filter.where(Finding.status == status.upper())
    if severity:
        base_filter = base_filter.where(Finding.severity == severity.lower())

    # Get summary stats (unfiltered by status/severity for the totals)
    stats_query = (
        select(Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.compliance_frameworks.contains(framework_id))
        .group_by(Finding.status)
    )
    stats_result = await db.execute(stats_query)
    stats_counts = {row[0]: row[1] for row in stats_result.all()}
    passed = stats_counts.get("PASS", 0)
    failed = stats_counts.get("FAIL", 0)
    total = passed + failed
    pass_rate = (passed / total * 100) if total > 0 else 0

    # Get paginated findings
    query = base_filter.order_by(Finding.severity, Finding.status).offset(offset).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()

    return {
        "framework": {
            "id": framework_id,
            "name": COMPLIANCE_FRAMEWORKS[framework_id]["name"],
            "description": COMPLIANCE_FRAMEWORKS[framework_id]["description"],
        },
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(pass_rate, 1),
        },
        "findings": [
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
                "status_extended": f.status_extended,
                "remediation": f.remediation,
                "remediation_url": f.remediation_url,
                "check_description": f.check_description,
                "evidence_log": f.evidence_log,
                "mitre_techniques": f.mitre_techniques,
            }
            for f in findings
        ],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
    }


@router.get("/frameworks/{framework_id}/stats")
async def framework_stats(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if framework_id not in COMPLIANCE_FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    query = (
        select(
            Finding.service,
            Finding.status,
            func.count(Finding.id),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.compliance_frameworks.contains(framework_id))
        .group_by(Finding.service, Finding.status)
    )

    result = await db.execute(query)
    rows = result.all()

    services: dict = {}
    for service, status, count in rows:
        if service not in services:
            services[service] = {"service": service, "passed": 0, "failed": 0, "total": 0}
        if status == "PASS":
            services[service]["passed"] = count
        elif status == "FAIL":
            services[service]["failed"] = count
        services[service]["total"] = services[service]["passed"] + services[service]["failed"]

    return {
        "framework_id": framework_id,
        "services": list(services.values()),
    }
