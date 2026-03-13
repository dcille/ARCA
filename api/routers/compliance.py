"""Compliance router."""
from fastapi import APIRouter, Depends
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
