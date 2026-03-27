"""MITRE ATT&CK Matrix router.

Supports both cloud provider findings (Finding) and SaaS findings (SaaSFinding),
with optional framework filtering to scope the matrix to selected benchmarks.
"""
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.saas_finding import SaaSFinding
from api.models.scan import Scan
from api.models.provider import Provider
from api.models.saas_connection import SaaSConnection
from api.models.attack_path import AttackPath
from api.services.auth_service import get_current_user

router = APIRouter()

# Framework prefixes: CIS control id prefix -> framework label
FRAMEWORK_PREFIXES = {
    "azure_cis_": "CIS Azure v5.0",
    "aws_cis_": "CIS AWS v6.0",
    "gcp_cis_": "CIS GCP v4.0",
    "oci_cis_": "CIS OCI v3.1",
    "alibaba_cis_": "CIS Alibaba v2.0",
    "ibm_cis_": "CIS IBM Cloud v2.0",
    "m365_cis_": "CIS M365 v6.0.1",
    "gws_cis_": "CIS Google Workspace v1.3.0",
    "sf_cis_": "CIS Snowflake v1.0.0",
}


def _build_reverse_mapping(check_to_mitre: dict) -> dict[str, list[str]]:
    """Build technique_id -> [check_ids] reverse mapping."""
    reverse: dict[str, list[str]] = {}
    for check_id, tech_ids in check_to_mitre.items():
        for tid in tech_ids:
            reverse.setdefault(tid, []).append(check_id)
    return reverse


def _filter_check_to_mitre(check_to_mitre: dict, frameworks: list[str] | None) -> dict:
    """Filter CHECK_TO_MITRE to only include entries matching selected frameworks.

    If frameworks is None or empty, returns all entries (no filtering).
    """
    if not frameworks:
        return check_to_mitre

    # Build set of allowed prefixes from selected framework labels
    allowed_prefixes = set()
    for prefix, label in FRAMEWORK_PREFIXES.items():
        if label in frameworks:
            allowed_prefixes.add(prefix)

    if not allowed_prefixes:
        return check_to_mitre

    # Keep entries that match an allowed prefix OR are non-CIS check_ids
    filtered = {}
    for check_id, techs in check_to_mitre.items():
        is_cis = any(check_id.startswith(p) for p in FRAMEWORK_PREFIXES)
        if not is_cis:
            # Non-CIS scanner check_ids (e.g. iam_root_mfa_enabled) — always include
            filtered[check_id] = techs
        elif any(check_id.startswith(p) for p in allowed_prefixes):
            filtered[check_id] = techs
    return filtered


async def _collect_findings(
    db: AsyncSession,
    user_id: str,
    provider_id: str | None = None,
    connection_id: str | None = None,
    scan_id: str | None = None,
) -> list[dict]:
    """Collect findings from both Finding and SaaSFinding tables into a uniform list."""
    results: list[dict] = []

    # 1. Cloud provider findings
    cloud_query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == user_id)
    )
    if provider_id:
        cloud_query = cloud_query.where(Finding.provider_id == provider_id)
    if scan_id:
        cloud_query = cloud_query.where(Finding.scan_id == scan_id)

    cloud_result = await db.execute(cloud_query)
    for f in cloud_result.scalars().all():
        techniques = []
        if f.mitre_techniques:
            try:
                techniques = json.loads(f.mitre_techniques)
            except (json.JSONDecodeError, TypeError):
                pass
        results.append({
            "id": f.id,
            "check_id": f.check_id,
            "check_title": f.check_title,
            "status": f.status,
            "severity": f.severity,
            "resource_id": f.resource_id,
            "resource_name": f.resource_name,
            "service": getattr(f, "service", ""),
            "region": getattr(f, "region", ""),
            "mitre_techniques": techniques,
            "source": "cloud",
        })

    # 2. SaaS findings
    saas_query = (
        select(SaaSFinding)
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == user_id)
    )
    if connection_id:
        saas_query = saas_query.where(SaaSFinding.connection_id == connection_id)
    if provider_id:
        # If provider_id is actually a SaaS connection ID, filter by it
        saas_query = saas_query.where(SaaSFinding.connection_id == provider_id)
    if scan_id:
        saas_query = saas_query.where(SaaSFinding.scan_id == scan_id)

    saas_result = await db.execute(saas_query)
    for sf in saas_result.scalars().all():
        techniques = []
        if sf.mitre_techniques:
            try:
                techniques = json.loads(sf.mitre_techniques)
            except (json.JSONDecodeError, TypeError):
                pass
        results.append({
            "id": sf.id,
            "check_id": sf.check_id,
            "check_title": sf.check_title,
            "status": sf.status,
            "severity": sf.severity,
            "resource_id": sf.resource_id or "",
            "resource_name": sf.resource_name or "",
            "service": sf.service_area,
            "region": "",
            "mitre_techniques": techniques,
            "source": "saas",
        })

    return results


@router.get("/frameworks")
async def get_available_frameworks(
    current_user: User = Depends(get_current_user),
):
    """List available frameworks that can be used to filter the MITRE matrix."""
    return {
        "frameworks": [
            {"id": prefix.rstrip("_"), "label": label}
            for prefix, label in sorted(FRAMEWORK_PREFIXES.items(), key=lambda x: x[1])
        ]
    }


@router.get("/matrix")
async def get_attack_matrix(
    provider_id: Optional[str] = None,
    connection_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    frameworks: Optional[str] = Query(
        None,
        description="Comma-separated framework labels to filter, e.g. 'CIS AWS v6.0,CIS Azure v5.0'",
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get MITRE ATT&CK matrix data with pass/fail coloring based on findings.

    Combines cloud and SaaS findings. Supports filtering by:
    - provider_id / connection_id: scope to a single account
    - frameworks: comma-separated list of framework labels to include
    """
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE

    # Parse framework filter
    fw_list = [f.strip() for f in frameworks.split(",") if f.strip()] if frameworks else None
    active_mapping = _filter_check_to_mitre(CHECK_TO_MITRE, fw_list)

    # Collect all findings
    findings = await _collect_findings(
        db, current_user.id, provider_id=provider_id,
        connection_id=connection_id, scan_id=scan_id,
    )

    # Build a technique -> status mapping
    technique_status: dict[str, dict] = {}

    for finding in findings:
        techniques = finding["mitre_techniques"]
        if not techniques:
            techniques = active_mapping.get(finding["check_id"], [])

        for tech_id in techniques:
            if tech_id not in technique_status:
                technique_status[tech_id] = {
                    "checks": [],
                    "pass_count": 0,
                    "fail_count": 0,
                }
            technique_status[tech_id]["checks"].append({
                "finding_id": finding["id"],
                "check_id": finding["check_id"],
                "check_title": finding["check_title"],
                "status": finding["status"],
                "severity": finding["severity"],
                "resource_id": finding["resource_id"],
                "resource_name": finding["resource_name"],
            })
            if finding["status"] == "PASS":
                technique_status[tech_id]["pass_count"] += 1
            else:
                technique_status[tech_id]["fail_count"] += 1

    # Build matrix organized by tactic
    tactics_order = [
        "reconnaissance", "initial-access", "execution", "persistence",
        "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "exfiltration", "impact",
    ]

    tactic_labels = {
        "reconnaissance": "Reconnaissance",
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
            tech_tactic = tech_info.get("tactic", "").lower().replace(" ", "-")
            if tech_tactic == tactic:
                status_data = technique_status.get(tech_id, {})
                pass_count = status_data.get("pass_count", 0)
                fail_count = status_data.get("fail_count", 0)
                total = pass_count + fail_count

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
        "active_frameworks": fw_list or [],
    }


@router.get("/technique/{technique_id}")
async def get_technique_detail(
    technique_id: str,
    provider_id: Optional[str] = None,
    connection_id: Optional[str] = None,
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

    # Get cloud findings
    cloud_query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.check_id.in_(related_check_ids))
    )
    if provider_id:
        cloud_query = cloud_query.where(Finding.provider_id == provider_id)

    cloud_result = await db.execute(cloud_query)

    checks_detail = []
    for f in cloud_result.scalars().all():
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
            "source": "cloud",
        })

    # Get SaaS findings
    saas_query = (
        select(SaaSFinding)
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(SaaSFinding.check_id.in_(related_check_ids))
    )
    if connection_id:
        saas_query = saas_query.where(SaaSFinding.connection_id == connection_id)
    if provider_id:
        saas_query = saas_query.where(SaaSFinding.connection_id == provider_id)

    saas_result = await db.execute(saas_query)
    for sf in saas_result.scalars().all():
        checks_detail.append({
            "finding_id": sf.id,
            "check_id": sf.check_id,
            "check_title": sf.check_title,
            "status": sf.status,
            "severity": sf.severity,
            "service": sf.service_area,
            "region": "",
            "resource_id": sf.resource_id or "",
            "resource_name": sf.resource_name or "",
            "status_extended": "",
            "remediation": sf.remediation or "",
            "check_description": sf.description or CHECK_DESCRIPTIONS.get(sf.check_id, ""),
            "evidence_log": "",
            "source": "saas",
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


@router.get("/technique/{technique_id}/checks")
async def get_technique_checks(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all check_ids that detect/mitigate a specific technique, with their current status."""
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE

    if technique_id not in MITRE_TECHNIQUES:
        raise HTTPException(status_code=404, detail="Technique not found")

    reverse = _build_reverse_mapping(CHECK_TO_MITRE)
    check_ids = reverse.get(technique_id, [])

    # Cloud findings
    cloud_query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.check_id.in_(check_ids))
    )
    cloud_result = await db.execute(cloud_query)

    check_status: dict[str, dict] = {}
    for f in cloud_result.scalars().all():
        cid = f.check_id
        if cid not in check_status:
            check_status[cid] = {"check_id": cid, "check_title": f.check_title, "pass": 0, "fail": 0, "service": f.service}
        if f.status == "PASS":
            check_status[cid]["pass"] += 1
        else:
            check_status[cid]["fail"] += 1

    # SaaS findings
    saas_query = (
        select(SaaSFinding)
        .join(Scan, SaaSFinding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(SaaSFinding.check_id.in_(check_ids))
    )
    saas_result = await db.execute(saas_query)
    for sf in saas_result.scalars().all():
        cid = sf.check_id
        if cid not in check_status:
            check_status[cid] = {"check_id": cid, "check_title": sf.check_title, "pass": 0, "fail": 0, "service": sf.service_area}
        if sf.status == "PASS":
            check_status[cid]["pass"] += 1
        else:
            check_status[cid]["fail"] += 1

    return {
        "technique_id": technique_id,
        "technique_name": MITRE_TECHNIQUES[technique_id]["name"],
        "checks": [
            {**v, "status": "fail" if v["fail"] > 0 else ("pass" if v["pass"] > 0 else "not_assessed")}
            for v in check_status.values()
        ],
        "unmapped_checks": [cid for cid in check_ids if cid not in check_status],
    }


@router.get("/coverage-gaps")
async def get_coverage_gaps(
    provider_id: Optional[str] = None,
    connection_id: Optional[str] = None,
    frameworks: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Analyze MITRE technique coverage gaps."""
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE

    fw_list = [f.strip() for f in frameworks.split(",") if f.strip()] if frameworks else None
    active_mapping = _filter_check_to_mitre(CHECK_TO_MITRE, fw_list)

    findings = await _collect_findings(
        db, current_user.id, provider_id=provider_id, connection_id=connection_id,
    )

    tech_pass: dict[str, int] = {}
    tech_fail: dict[str, int] = {}

    for f in findings:
        techs = f["mitre_techniques"] or active_mapping.get(f["check_id"], [])
        for tid in techs:
            if f["status"] == "PASS":
                tech_pass[tid] = tech_pass.get(tid, 0) + 1
            else:
                tech_fail[tid] = tech_fail.get(tid, 0) + 1

    covered_passing = []
    covered_failing = []
    not_covered = []

    for tid, info in MITRE_TECHNIQUES.items():
        p = tech_pass.get(tid, 0)
        f_count = tech_fail.get(tid, 0)
        entry = {
            "id": tid,
            "name": info["name"],
            "tactic": info.get("tactic", ""),
            "pass_count": p,
            "fail_count": f_count,
        }
        if p + f_count == 0:
            not_covered.append(entry)
        elif f_count > 0:
            covered_failing.append(entry)
        else:
            covered_passing.append(entry)

    total = len(MITRE_TECHNIQUES)
    assessed = len(covered_passing) + len(covered_failing)

    return {
        "coverage_score": round((len(covered_passing) / total * 100) if total else 0, 1),
        "total_techniques": total,
        "assessed": assessed,
        "protected": len(covered_passing),
        "at_risk": len(covered_failing),
        "not_covered": len(not_covered),
        "techniques_passing": covered_passing,
        "techniques_failing": sorted(covered_failing, key=lambda t: t["fail_count"], reverse=True),
        "techniques_not_covered": not_covered,
    }


@router.get("/navigator-layer")
async def export_navigator_layer(
    provider_id: Optional[str] = None,
    connection_id: Optional[str] = None,
    frameworks: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export MITRE ATT&CK Navigator layer (JSON v4.4)."""
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE

    fw_list = [f.strip() for f in frameworks.split(",") if f.strip()] if frameworks else None
    active_mapping = _filter_check_to_mitre(CHECK_TO_MITRE, fw_list)

    findings = await _collect_findings(
        db, current_user.id, provider_id=provider_id, connection_id=connection_id,
    )

    tech_pass: dict[str, int] = {}
    tech_fail: dict[str, int] = {}
    tech_checks: dict[str, list[str]] = {}

    for f in findings:
        techs = f["mitre_techniques"] or active_mapping.get(f["check_id"], [])
        for tid in techs:
            if f["status"] == "PASS":
                tech_pass[tid] = tech_pass.get(tid, 0) + 1
            else:
                tech_fail[tid] = tech_fail.get(tid, 0) + 1
            tech_checks.setdefault(tid, [])
            if f["check_id"] not in tech_checks[tid]:
                tech_checks[tid].append(f["check_id"])

    fail_check_ids = {f["check_id"] for f in findings if f["status"] == "FAIL"}

    techniques_layer = []
    for tid, info in MITRE_TECHNIQUES.items():
        p = tech_pass.get(tid, 0)
        f_count = tech_fail.get(tid, 0)
        total = p + f_count

        if total == 0:
            score = 0
            color = ""
        elif f_count > 0:
            score = 2
            color = "#ff6666"
        else:
            score = 1
            color = "#83d353"

        failing = [c for c in tech_checks.get(tid, []) if c in fail_check_ids]
        comment = f"{p} pass, {f_count} fail" if total > 0 else "Not assessed"
        if failing:
            comment += f". Failing: {', '.join(failing[:5])}"

        entry = {
            "techniqueID": tid,
            "score": score,
            "comment": comment,
            "enabled": True,
            "showSubtechniques": False,
        }
        if color:
            entry["color"] = color
        techniques_layer.append(entry)

    return {
        "name": "D-ARCA Security Coverage",
        "versions": {
            "attack": "15",
            "navigator": "4.4",
            "layer": "4.4",
        },
        "domain": "enterprise-attack",
        "description": "Auto-generated MITRE ATT&CK coverage layer from D-ARCA CSPM findings.",
        "filters": {
            "platforms": ["Linux", "macOS", "Windows", "IaaS", "SaaS", "Containers", "Azure AD", "Google Workspace", "Office 365"]
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "aggregateFunction": "max",
        },
        "techniques": techniques_layer,
        "gradient": {
            "colors": ["#ffffff", "#83d353", "#ff6666"],
            "minValue": 0,
            "maxValue": 2,
        },
        "legendItems": [
            {"label": "Not Assessed", "color": "#ffffff"},
            {"label": "Protected (all pass)", "color": "#83d353"},
            {"label": "At Risk (failures)", "color": "#ff6666"},
        ],
    }


@router.get("/attack-paths")
async def get_mitre_attack_paths_coverage(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Show which MITRE techniques are covered by discovered attack paths."""
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES

    result = await db.execute(
        select(AttackPath).where(AttackPath.user_id == current_user.id)
    )
    paths = result.scalars().all()

    technique_paths: dict[str, list[dict]] = {}
    for p in paths:
        techniques = []
        if p.techniques:
            try:
                techniques = json.loads(p.techniques)
            except (json.JSONDecodeError, TypeError):
                pass
        for tid in techniques:
            technique_paths.setdefault(tid, []).append({
                "path_id": p.id,
                "title": p.title,
                "severity": p.severity,
                "risk_score": p.risk_score,
                "category": p.category,
            })

    coverage = []
    for tid, info in MITRE_TECHNIQUES.items():
        related = technique_paths.get(tid, [])
        if related:
            coverage.append({
                "technique_id": tid,
                "technique_name": info["name"],
                "tactic": info.get("tactic", ""),
                "attack_paths": related,
                "path_count": len(related),
                "max_risk_score": max(p["risk_score"] for p in related),
            })

    return {
        "techniques_with_paths": len(coverage),
        "total_techniques": len(MITRE_TECHNIQUES),
        "coverage": sorted(coverage, key=lambda c: c["max_risk_score"], reverse=True),
    }
