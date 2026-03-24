"""Reports router - PDF report generation."""
import json
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from api.database import get_db
from api.models.user import User
from api.models.provider import Provider
from api.models.scan import Scan
from api.models.finding import Finding
from api.models.attack_path import AttackPath
from api.services.auth_service import get_current_user
from api.services.report_service import generate_executive_report, generate_technical_report

router = APIRouter()


async def _gather_report_data(
    db: AsyncSession,
    user: User,
    provider_type: Optional[str] = None,
    account_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    service: Optional[str] = None,
):
    """Gather all data needed for report generation."""

    # ── Providers ──────────────────────────────────────────────────
    prov_q = select(Provider).where(Provider.user_id == user.id)
    if provider_type:
        prov_q = prov_q.where(Provider.provider_type == provider_type)
    if account_id:
        prov_q = prov_q.where(Provider.account_id == account_id)
    providers_result = await db.execute(prov_q)
    providers = providers_result.scalars().all()
    provider_ids = [p.id for p in providers]

    provider_info = {
        "providers": [
            {"provider_type": p.provider_type, "alias": p.alias,
             "account_id": p.account_id, "region": p.region}
            for p in providers
        ]
    }

    # ── Findings ───────────────────────────────────────────────────
    findings_q = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == user.id)
    )
    if provider_ids and provider_type:
        findings_q = findings_q.where(Finding.provider_id.in_(provider_ids))
    if scan_id:
        findings_q = findings_q.where(Finding.scan_id == scan_id)
    if severity:
        findings_q = findings_q.where(Finding.severity == severity)
    if service:
        findings_q = findings_q.where(Finding.service == service)

    findings_result = await db.execute(findings_q)
    findings_models = findings_result.scalars().all()

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
            "status_extended": f.status_extended,
            "remediation": f.remediation,
        }
        for f in findings_models
    ]

    # ── Aggregate stats ────────────────────────────────────────────
    total = len(findings_dicts)
    passed = sum(1 for f in findings_dicts if f["status"] == "PASS")
    severity_breakdown = {}
    by_service = {}
    for f in findings_dicts:
        severity_breakdown[f["severity"]] = severity_breakdown.get(f["severity"], 0) + 1
        by_service[f["service"]] = by_service.get(f["service"], 0) + 1

    scans_q = select(func.count(Scan.id)).where(Scan.user_id == user.id)
    scans_count = (await db.execute(scans_q)).scalar() or 0

    overview = {
        "total_findings": total,
        "pass_rate": round((passed / total * 100) if total > 0 else 0, 1),
        "severity_breakdown": severity_breakdown,
        "total_scans": scans_count,
        "total_cloud_providers": len([p for p in providers if True]),
        "total_saas_connections": 0,
    }

    # ── Attack paths ───────────────────────────────────────────────
    ap_q = select(AttackPath).where(AttackPath.user_id == user.id)
    ap_result = await db.execute(ap_q)
    attack_paths_models = ap_result.scalars().all()

    attack_paths_list = []
    ap_severity_counts = {}
    total_score = 0
    for ap in attack_paths_models:
        techniques = []
        remediation = []
        try:
            techniques = json.loads(ap.techniques) if ap.techniques else []
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            remediation = json.loads(ap.remediation) if ap.remediation else []
        except (json.JSONDecodeError, TypeError):
            pass

        attack_paths_list.append({
            "title": ap.title,
            "description": ap.description,
            "severity": ap.severity,
            "risk_score": ap.risk_score,
            "category": ap.category,
            "entry_point": ap.entry_point,
            "target": ap.target,
            "node_count": ap.node_count,
            "edge_count": ap.edge_count,
            "techniques": techniques,
            "remediation": remediation,
        })
        ap_severity_counts[ap.severity] = ap_severity_counts.get(ap.severity, 0) + 1
        total_score += ap.risk_score

    attack_paths_summary = {
        "total_paths": len(attack_paths_models),
        "critical_paths": ap_severity_counts.get("critical", 0),
        "high_paths": ap_severity_counts.get("high", 0),
        "medium_paths": ap_severity_counts.get("medium", 0),
        "low_paths": ap_severity_counts.get("low", 0),
        "avg_risk_score": round(total_score / len(attack_paths_models), 1) if attack_paths_models else 0,
    }

    # ── Compliance (basic) ─────────────────────────────────────────
    from scanner.compliance.frameworks import FRAMEWORKS, get_all_checks_for_framework

    compliance_frameworks_data = []
    for fw_id, fw in FRAMEWORKS.items():
        fw_check_ids = get_all_checks_for_framework(fw_id)
        # Calculate per-unique-check stats
        fw_passed = 0
        fw_failed = 0
        for cid in (fw_check_ids if fw_check_ids else set()):
            matching = [f for f in findings_dicts if f["check_id"] == cid]
            if any(f["status"] == "FAIL" for f in matching):
                fw_failed += 1
            elif any(f["status"] == "PASS" for f in matching):
                fw_passed += 1
        fw_total = fw_passed + fw_failed
        fw_rate = (fw_passed / fw_total * 100) if fw_total > 0 else 0
        compliance_frameworks_data.append({
            "framework": fw_id,
            "name": fw["name"],
            "total_checks": len(fw_check_ids),
            "passed": fw_passed,
            "failed": fw_failed,
            "pass_rate": round(fw_rate, 1),
        })

    compliance_summary = {
        "frameworks": sorted(compliance_frameworks_data, key=lambda x: x["pass_rate"])
    }

    # ── MITRE ATT&CK ─────────────────────────────────────────────
    from scanner.mitre.attack_mapping import MITRE_TECHNIQUES, CHECK_TO_MITRE

    technique_status = {}
    for f in findings_dicts:
        techs = CHECK_TO_MITRE.get(f.get("check_id", ""), [])
        for tid in techs:
            if tid not in technique_status:
                technique_status[tid] = {"pass": 0, "fail": 0}
            if f["status"] == "PASS":
                technique_status[tid]["pass"] += 1
            else:
                technique_status[tid]["fail"] += 1

    total_techniques = len(MITRE_TECHNIQUES)
    assessed = len(technique_status)
    at_risk_techniques = [
        {"id": tid, "name": MITRE_TECHNIQUES.get(tid, {}).get("name", tid), "fail_count": s["fail"]}
        for tid, s in technique_status.items() if s["fail"] > 0
    ]
    protected_count = sum(1 for s in technique_status.values() if s["fail"] == 0 and s["pass"] > 0)

    mitre_summary = {
        "total_techniques": total_techniques,
        "assessed": assessed,
        "protected": protected_count,
        "at_risk": len(at_risk_techniques),
        "not_assessed": total_techniques - assessed,
        "coverage_rate": round((assessed / total_techniques * 100) if total_techniques > 0 else 0, 1),
        "top_at_risk": sorted(at_risk_techniques, key=lambda x: x["fail_count"], reverse=True)[:10],
    }

    filters = {
        "provider_type": provider_type,
        "account_id": account_id,
        "scan_id": scan_id,
        "severity": severity,
        "service": service,
    }

    return {
        "overview": overview,
        "findings": findings_dicts,
        "findings_by_severity": severity_breakdown,
        "findings_by_service": by_service,
        "compliance_summary": compliance_summary,
        "mitre_summary": mitre_summary,
        "attack_paths_summary": attack_paths_summary,
        "attack_paths": attack_paths_list,
        "provider_info": provider_info,
        "filters": filters,
    }


@router.get("/executive")
async def download_executive_report(
    provider_type: Optional[str] = Query(None, description="Filter by provider: aws, azure, gcp, oci, kubernetes"),
    account_id: Optional[str] = Query(None, description="Filter by account/subscription ID"),
    scan_id: Optional[str] = Query(None, description="Filter by specific scan"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and download an Executive Summary PDF report."""
    data = await _gather_report_data(db, current_user, provider_type, account_id, scan_id)

    pdf_bytes = generate_executive_report(
        overview=data["overview"],
        findings_by_severity=data["findings_by_severity"],
        findings_by_service=data["findings_by_service"],
        compliance_summary=data["compliance_summary"],
        mitre_summary=data.get("mitre_summary"),
        attack_paths_summary=data["attack_paths_summary"],
        provider_info=data["provider_info"],
        filters=data["filters"],
    )

    filename = "ARCA_Executive_Report"
    if provider_type:
        filename += f"_{provider_type.upper()}"
    if account_id:
        filename += f"_{account_id}"
    filename += ".pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/technical")
async def download_technical_report(
    provider_type: Optional[str] = Query(None, description="Filter by provider: aws, azure, gcp, oci, kubernetes"),
    account_id: Optional[str] = Query(None, description="Filter by account/subscription ID"),
    scan_id: Optional[str] = Query(None, description="Filter by specific scan"),
    severity: Optional[str] = Query(None, description="Filter findings by severity"),
    service: Optional[str] = Query(None, description="Filter findings by service"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and download a Technical Assessment PDF report."""
    data = await _gather_report_data(
        db, current_user, provider_type, account_id, scan_id, severity, service
    )

    pdf_bytes = generate_technical_report(
        overview=data["overview"],
        findings=data["findings"],
        findings_by_severity=data["findings_by_severity"],
        findings_by_service=data["findings_by_service"],
        compliance_summary=data["compliance_summary"],
        mitre_summary=data.get("mitre_summary"),
        attack_paths=data["attack_paths"],
        provider_info=data["provider_info"],
        filters=data["filters"],
    )

    filename = "ARCA_Technical_Report"
    if provider_type:
        filename += f"_{provider_type.upper()}"
    if account_id:
        filename += f"_{account_id}"
    filename += ".pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/findings")
async def export_findings(
    format: str = Query("csv", description="Export format: csv or json"),
    provider_type: Optional[str] = None,
    account_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    service: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export findings as CSV or JSON."""
    findings_q = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )

    if provider_type:
        findings_q = findings_q.join(Provider, Finding.provider_id == Provider.id).where(
            Provider.provider_type == provider_type
        )
    if scan_id:
        findings_q = findings_q.where(Finding.scan_id == scan_id)
    if severity:
        findings_q = findings_q.where(Finding.severity == severity)
    if service:
        findings_q = findings_q.where(Finding.service == service)
    if status:
        findings_q = findings_q.where(Finding.status == status)

    result = await db.execute(findings_q)
    findings = result.scalars().all()

    if format == "json":
        data = [
            {
                "check_id": f.check_id,
                "check_title": f.check_title,
                "service": f.service,
                "severity": f.severity,
                "status": f.status,
                "region": f.region,
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "remediation": f.remediation,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ]
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="ARCA_Findings.json"'},
        )

    # CSV
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Check ID", "Title", "Service", "Severity", "Status",
                     "Region", "Resource ID", "Resource Name", "Remediation", "Date"])
    for f in findings:
        writer.writerow([
            f.check_id, f.check_title, f.service, f.severity, f.status,
            f.region, f.resource_id, f.resource_name, f.remediation,
            f.created_at.isoformat() if f.created_at else "",
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ARCA_Findings.csv"'},
    )


@router.get("/ransomware-readiness")
async def ransomware_readiness_report(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate Ransomware Readiness executive PDF report."""
    from api.services.rr_report_service import gather_rr_report_data, generate_rr_executive_html

    data = await gather_rr_report_data(db, current_user.id)
    if "error" in data:
        raise HTTPException(status_code=404, detail=data["error"])

    html = generate_rr_executive_html(data, org_name="Organization")

    # Convert HTML to PDF using the same approach as executive reports
    try:
        from api.services.report_service import html_to_pdf
        pdf_bytes = html_to_pdf(html)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": 'attachment; filename="ARCA_Ransomware_Readiness_Report.pdf"'
            },
        )
    except Exception:
        # Fallback: return HTML if PDF conversion not available
        return Response(
            content=html.encode(),
            media_type="text/html",
            headers={
                "Content-Disposition": 'attachment; filename="ARCA_Ransomware_Readiness_Report.html"'
            },
        )
