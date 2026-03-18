"""MITRE ATT&CK Matrix router."""
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.scan import Scan
from api.models.provider import Provider
from api.services.auth_service import get_current_user

router = APIRouter()


@router.get("/matrix")
async def get_attack_matrix(
    provider_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get MITRE ATT&CK matrix data with pass/fail coloring based on findings."""
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE

    # Get all findings for this user (optionally filtered by provider/scan)
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if provider_id:
        query = query.where(Finding.provider_id == provider_id)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    result = await db.execute(query)
    findings = result.scalars().all()

    # Build a technique -> status mapping
    technique_status = {}  # technique_id -> {"checks": [...], "pass_count": int, "fail_count": int}

    for finding in findings:
        # Get MITRE techniques from the finding itself or from the mapping
        techniques = []
        if finding.mitre_techniques:
            try:
                techniques = json.loads(finding.mitre_techniques)
            except (json.JSONDecodeError, TypeError):
                pass
        if not techniques:
            techniques = CHECK_TO_MITRE.get(finding.check_id, [])

        for tech_id in techniques:
            if tech_id not in technique_status:
                technique_status[tech_id] = {
                    "checks": [],
                    "pass_count": 0,
                    "fail_count": 0,
                }
            technique_status[tech_id]["checks"].append({
                "finding_id": finding.id,
                "check_id": finding.check_id,
                "check_title": finding.check_title,
                "status": finding.status,
                "severity": finding.severity,
                "resource_id": finding.resource_id,
                "resource_name": finding.resource_name,
            })
            if finding.status == "PASS":
                technique_status[tech_id]["pass_count"] += 1
            else:
                technique_status[tech_id]["fail_count"] += 1

    # Build matrix organized by tactic
    tactics_order = [
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "exfiltration", "impact",
    ]

    tactic_labels = {
        "initial-access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "Privilege Escalation",
        "defense-evasion": "Defense Evasion",
        "credential-access": "Credential Access",
        "discovery": "Discovery",
        "lateral-movement": "Lateral Movement",
        "collection": "Collection",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }

    matrix = []
    for tactic in tactics_order:
        tactic_techniques = []
        for tech_id, tech_info in MITRE_TECHNIQUES.items():
            # Normalize tactic comparison: mapping uses "Initial Access", router uses "initial-access"
            tech_tactic = tech_info.get("tactic", "").lower().replace(" ", "-")
            if tech_tactic == tactic:
                status_data = technique_status.get(tech_id, {})
                pass_count = status_data.get("pass_count", 0)
                fail_count = status_data.get("fail_count", 0)
                total = pass_count + fail_count

                # Determine color: red if any fail, green if all pass, gray if not assessed
                if total == 0:
                    color = "gray"
                elif fail_count > 0:
                    color = "red"
                else:
                    color = "green"

                tactic_techniques.append({
                    "id": tech_id,
                    "name": tech_info["name"],
                    "description": tech_info.get("description", ""),
                    "url": tech_info.get("url", ""),
                    "color": color,
                    "pass_count": pass_count,
                    "fail_count": fail_count,
                    "total_checks": total,
                    "checks": status_data.get("checks", []),
                })

        matrix.append({
            "tactic": tactic,
            "tactic_label": tactic_labels.get(tactic, tactic),
            "techniques": tactic_techniques,
        })

    # Summary stats
    total_techniques = sum(len(t["techniques"]) for t in matrix)
    assessed = sum(1 for t in matrix for tech in t["techniques"] if tech["total_checks"] > 0)
    protected = sum(1 for t in matrix for tech in t["techniques"] if tech["color"] == "green")
    at_risk = sum(1 for t in matrix for tech in t["techniques"] if tech["color"] == "red")

    return {
        "matrix": matrix,
        "summary": {
            "total_techniques": total_techniques,
            "assessed": assessed,
            "protected": protected,
            "at_risk": at_risk,
            "not_assessed": total_techniques - assessed,
            "coverage_rate": round((assessed / total_techniques * 100) if total_techniques > 0 else 0, 1),
        },
    }


@router.get("/technique/{technique_id}")
async def get_technique_detail(
    technique_id: str,
    provider_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get detailed information about a specific MITRE ATT&CK technique."""
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE, CHECK_DESCRIPTIONS, CHECK_EVIDENCE

    if technique_id not in MITRE_TECHNIQUES:
        raise HTTPException(status_code=404, detail="Technique not found")

    technique = MITRE_TECHNIQUES[technique_id]

    # Find which check_ids map to this technique
    related_check_ids = [
        check_id for check_id, techs in CHECK_TO_MITRE.items() if technique_id in techs
    ]

    # Get findings for those checks
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.check_id.in_(related_check_ids))
    )
    if provider_id:
        query = query.where(Finding.provider_id == provider_id)

    result = await db.execute(query)
    findings = result.scalars().all()

    checks_detail = []
    for f in findings:
        checks_detail.append({
            "finding_id": f.id,
            "check_id": f.check_id,
            "check_title": f.check_title,
            "status": f.status,
            "severity": f.severity,
            "service": f.service,
            "region": f.region,
            "resource_id": f.resource_id,
            "resource_name": f.resource_name,
            "status_extended": f.status_extended,
            "remediation": f.remediation,
            "check_description": f.check_description or CHECK_DESCRIPTIONS.get(f.check_id, ""),
            "evidence_log": f.evidence_log or CHECK_EVIDENCE.get(f.check_id, ""),
        })

    pass_count = sum(1 for c in checks_detail if c["status"] == "PASS")
    fail_count = sum(1 for c in checks_detail if c["status"] == "FAIL")

    return {
        "technique": {
            "id": technique_id,
            "name": technique["name"],
            "tactic": technique.get("tactic", ""),
            "description": technique.get("description", ""),
            "url": technique.get("url", ""),
        },
        "assessment": {
            "pass_count": pass_count,
            "fail_count": fail_count,
            "total": pass_count + fail_count,
            "status": "not_assessed" if (pass_count + fail_count) == 0 else ("protected" if fail_count == 0 else "at_risk"),
        },
        "checks": checks_detail,
    }
