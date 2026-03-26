"""Compliance router — per-unique-check calculation and control-level library."""
import os
import uuid as _uuid_mod

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, or_
from typing import Optional

from pydantic import BaseModel

from api.database import get_db
from api.models.user import User
from api.models.finding import Finding
from api.models.finding_action import FindingAction
from api.models.scan import Scan
from api.models.framework_preference import FrameworkPreference
from api.services.auth_service import get_current_user
from api.models.provider import Provider
from api.models.saas_connection import SaaSConnection
from scanner.compliance.frameworks import (
    FRAMEWORKS,
    get_all_checks_for_framework,
    get_checks_for_framework_by_provider,
    get_framework_controls,
    get_framework_providers,
)

EVIDENCE_UPLOAD_DIR = os.environ.get("EVIDENCE_UPLOAD_DIR", "/app/data/evidence")

router = APIRouter()


def _get_fw_meta(framework_id: str) -> dict:
    fw = FRAMEWORKS.get(framework_id, {})
    return {"id": framework_id, "name": fw.get("name", ""), "description": fw.get("description", "")}


def _build_fw_filter(framework_id: str):
    """Build SQLAlchemy filter for a framework using its check_id list."""
    check_ids = get_all_checks_for_framework(framework_id)
    if not check_ids:
        # Broad frameworks (mapped to ALL checks) — no filter
        return None
    return or_(
        Finding.check_id.in_(check_ids),
        Finding.compliance_frameworks.contains(framework_id),
    )


async def _per_check_summary(
    db: AsyncSession,
    user_id: str,
    framework_id: str,
    provider_id: Optional[str] = None,
    provider_type: Optional[str] = None,
) -> dict:
    """Calculate compliance summary using per-unique-check aggregation.

    For each unique check_id in the framework:
    - If ANY finding with that check_id has status=FAIL → check is FAIL
    - If ALL findings with that check_id have status=PASS → check is PASS
    - If findings exist but only MANUAL/ERROR → MANUAL
    - If no findings exist → NOT_EVALUATED

    Pass rate = passed_checks / (passed_checks + failed_checks), excluding NOT_EVALUATED and MANUAL.
    Total checks = number of unique check_ids the framework defines.
    """
    # When filtering by provider_type, only use that provider's checks
    if provider_type:
        all_check_ids = get_checks_for_framework_by_provider(framework_id, provider_type)
    else:
        all_check_ids = get_all_checks_for_framework(framework_id)

    # Query: for each check_id, get fail_count, pass_count, manual_count, exception_count
    fw_filter = _build_fw_filter(framework_id)
    query = (
        select(
            Finding.check_id,
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("fail_count"),
            func.sum(case((Finding.status == "PASS", 1), else_=0)).label("pass_count"),
            func.sum(case((Finding.status == "MANUAL", 1), else_=0)).label("manual_count"),
            func.sum(case((Finding.status == "EXCEPTION", 1), else_=0)).label("exception_count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == user_id)
    )
    if fw_filter is not None:
        query = query.where(fw_filter)
    # Filter by specific provider account
    if provider_id:
        query = query.where(Finding.provider_id == provider_id)
    query = query.group_by(Finding.check_id)

    result = await db.execute(query)
    rows = {
        row.check_id: (row.fail_count or 0, row.pass_count or 0, row.manual_count or 0, row.exception_count or 0)
        for row in result.all()
    }

    # Calculate per-check status
    total_defined = len(all_check_ids) if all_check_ids else len(rows)
    passed_checks = 0
    failed_checks = 0
    manual_checks = 0
    not_evaluated = 0
    exception_checks = 0

    check_ids_to_evaluate = all_check_ids if all_check_ids else sorted(rows.keys())

    for cid in check_ids_to_evaluate:
        if cid in rows:
            fail_count, pass_count, manual_count, exception_count = rows[cid]
            if fail_count > 0:
                failed_checks += 1
            elif pass_count > 0:
                passed_checks += 1
            elif exception_count > 0:
                exception_checks += 1
            elif manual_count > 0:
                manual_checks += 1
            else:
                not_evaluated += 1
        else:
            not_evaluated += 1

    evaluated = passed_checks + failed_checks
    pass_rate = (passed_checks / evaluated * 100) if evaluated > 0 else 0

    return {
        "total_checks": total_defined,
        "passed": passed_checks,
        "failed": failed_checks,
        "manual": manual_checks,
        "not_evaluated": not_evaluated,
        "exception": exception_checks,
        "pass_rate": round(pass_rate, 1),
    }


@router.get("/accounts")
async def list_compliance_accounts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return all cloud providers and SaaS connections for the compliance filter."""
    # Cloud providers
    result = await db.execute(
        select(Provider.id, Provider.provider_type, Provider.alias, Provider.account_id)
        .where(Provider.user_id == current_user.id)
    )
    providers = [
        {
            "id": r.id,
            "type": "cloud",
            "provider_type": r.provider_type,
            "alias": r.alias,
            "account_id": r.account_id,
        }
        for r in result.all()
    ]

    # SaaS connections
    result = await db.execute(
        select(SaaSConnection.id, SaaSConnection.provider_type, SaaSConnection.alias)
        .where(SaaSConnection.user_id == current_user.id)
    )
    saas = [
        {
            "id": r.id,
            "type": "saas",
            "provider_type": r.provider_type,
            "alias": r.alias,
            "account_id": None,
        }
        for r in result.all()
    ]

    return providers + saas


@router.get("/frameworks")
async def list_frameworks(
    provider_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List built-in + custom frameworks, optionally filtering by provider_type."""
    # Fetch user's framework preferences
    pref_result = await db.execute(
        select(FrameworkPreference.framework_id, FrameworkPreference.is_enabled)
        .where(FrameworkPreference.user_id == current_user.id)
    )
    pref_map = {row.framework_id: row.is_enabled for row in pref_result.all()}

    results = []
    # Built-in frameworks
    for fw_id, fw in FRAMEWORKS.items():
        fw_providers = get_framework_providers(fw_id)
        if provider_type and provider_type not in fw_providers:
            continue
        if provider_type:
            total_checks = len(get_checks_for_framework_by_provider(fw_id, provider_type))
        else:
            total_checks = len(get_all_checks_for_framework(fw_id))
        controls = get_framework_controls(fw_id)
        results.append({
            "id": fw_id,
            "name": fw["name"],
            "description": fw["description"],
            "category": fw.get("category", ""),
            "providers": fw_providers,
            "total_controls": len(controls),
            "total_checks": total_checks,
            "type": "built_in",
            "is_enabled": pref_map.get(fw_id, True),
        })

    # Custom frameworks
    from api.models.custom_framework import CustomFramework
    from sqlalchemy.orm import selectinload
    import json

    query = (
        select(CustomFramework)
        .options(
            selectinload(CustomFramework.selected_checks),
            selectinload(CustomFramework.custom_controls),
        )
        .where(CustomFramework.user_id == current_user.id, CustomFramework.is_active == True)
    )
    result = await db.execute(query)
    custom_fws = result.scalars().all()

    for cfw in custom_fws:
        cfw_providers = json.loads(cfw.providers) if cfw.providers else []
        if provider_type and provider_type not in cfw_providers:
            continue
        total = len(cfw.selected_checks) + len(cfw.custom_controls)
        results.append({
            "id": cfw.id,
            "name": cfw.name,
            "description": cfw.description or "",
            "category": "Custom",
            "providers": cfw_providers,
            "total_controls": 0,
            "total_checks": total,
            "type": "custom",
            "version": cfw.version,
            "is_enabled": pref_map.get(cfw.id, True),
        })

    return results


@router.get("/summary")
async def compliance_summary(
    framework: Optional[str] = None,
    provider_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if framework:
        # Check if it's a custom framework (UUID format)
        if len(framework) == 36 and "-" in framework and framework not in FRAMEWORKS:
            from api.models.custom_framework import CustomFramework
            from sqlalchemy.orm import selectinload
            result = await db.execute(
                select(CustomFramework)
                .options(
                    selectinload(CustomFramework.selected_checks),
                    selectinload(CustomFramework.custom_controls),
                )
                .where(
                    CustomFramework.id == framework,
                    CustomFramework.user_id == current_user.id,
                    CustomFramework.is_active == True,
                )
            )
            cfw = result.scalars().first()
            if cfw:
                from api.services.custom_framework_service import evaluate_custom_framework
                return await evaluate_custom_framework(cfw, db, current_user.id, provider_id)
        return await _per_check_summary(db, current_user.id, framework, provider_id, provider_type)

    # Overall summary across all frameworks
    query = (
        select(
            Finding.check_id,
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("fail_count"),
            func.sum(case((Finding.status == "PASS", 1), else_=0)).label("pass_count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if provider_id:
        query = query.where(Finding.provider_id == provider_id)
    query = query.group_by(Finding.check_id)
    result = await db.execute(query)
    rows = result.all()

    passed = sum(1 for r in rows if (r.fail_count or 0) == 0 and (r.pass_count or 0) > 0)
    failed = sum(1 for r in rows if (r.fail_count or 0) > 0)
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
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    # Get per-unique-check summary
    summary = await _per_check_summary(db, current_user.id, framework_id)

    # Get paginated findings
    base_filter = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    fw_filter = _build_fw_filter(framework_id)
    if fw_filter is not None:
        base_filter = base_filter.where(fw_filter)

    if status:
        base_filter = base_filter.where(Finding.status == status.upper())
    if severity:
        base_filter = base_filter.where(Finding.severity == severity.lower())

    query = base_filter.order_by(Finding.severity, Finding.status).offset(offset).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()

    from scanner.mitre.attack_mapping import CHECK_DESCRIPTIONS, CHECK_EVIDENCE

    return {
        "framework": _get_fw_meta(framework_id),
        "summary": summary,
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
                "check_description": f.check_description or CHECK_DESCRIPTIONS.get(f.check_id, ""),
                "evidence_log": f.evidence_log or CHECK_EVIDENCE.get(f.check_id, ""),
                "mitre_techniques": f.mitre_techniques,
            }
            for f in findings
        ],
        "pagination": {"limit": limit, "offset": offset, "total": summary["total_checks"]},
    }


@router.get("/frameworks/{framework_id}/stats")
async def framework_stats(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    # Per-unique-check aggregation grouped by service
    fw_filter = _build_fw_filter(framework_id)
    query = (
        select(
            Finding.service,
            Finding.check_id,
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("fail_count"),
            func.sum(case((Finding.status == "PASS", 1), else_=0)).label("pass_count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if fw_filter is not None:
        query = query.where(fw_filter)
    query = query.group_by(Finding.service, Finding.check_id)

    result = await db.execute(query)
    rows = result.all()

    services: dict = {}
    for row in rows:
        svc = row.service
        if svc not in services:
            services[svc] = {"service": svc, "passed": 0, "failed": 0, "total": 0}
        if (row.fail_count or 0) > 0:
            services[svc]["failed"] += 1
        elif (row.pass_count or 0) > 0:
            services[svc]["passed"] += 1
        services[svc]["total"] = services[svc]["passed"] + services[svc]["failed"]

    return {
        "framework_id": framework_id,
        "services": sorted(services.values(), key=lambda s: s["total"], reverse=True),
    }


@router.get("/frameworks/{framework_id}/library")
async def framework_check_library(
    framework_id: str,
    provider_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """Return the full control-level check library for a framework."""
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    from scanner.mitre.attack_mapping import CHECK_DESCRIPTIONS, CHECK_EVIDENCE

    fw = FRAMEWORKS[framework_id]
    controls = get_framework_controls(framework_id)
    all_check_ids = get_all_checks_for_framework(framework_id)

    controls_out = []
    total_filtered_checks = 0
    for ctrl in controls:
        checks_map = ctrl.get("checks", {})
        # Build per-provider check details
        provider_checks = {}
        if isinstance(checks_map, dict):
            for provider, cids in checks_map.items():
                if provider_type and provider != provider_type:
                    continue
                provider_checks[provider] = [
                    {
                        "check_id": cid,
                        "description": CHECK_DESCRIPTIONS.get(cid, f"Security check: {cid.replace('_', ' ')}"),
                        "evidence_method": CHECK_EVIDENCE.get(cid, ""),
                    }
                    for cid in cids
                ]
                total_filtered_checks += len(cids)

        if provider_type and not provider_checks:
            continue

        controls_out.append({
            "id": ctrl.get("id", ""),
            "title": ctrl.get("title", ""),
            "description": ctrl.get("description", ""),
            "checks": provider_checks,
            "rationale": ctrl.get("rationale", ""),
            "impact": ctrl.get("impact", ""),
            "remediation_guide": ctrl.get("remediation_guide", ""),
            "audit": ctrl.get("audit", ""),
            "default_value": ctrl.get("default_value", ""),
            "cis_level": ctrl.get("cis_level", ""),
            "assessment_type": ctrl.get("assessment_type", ""),
            "severity": ctrl.get("severity", ""),
            "service": ctrl.get("service", ""),
        })

    return {
        "framework": _get_fw_meta(framework_id),
        "framework_description": fw.get("description", ""),
        "category": fw.get("category", ""),
        "total_controls": len(controls_out),
        "total_checks": total_filtered_checks if provider_type else len(all_check_ids),
        "controls": controls_out,
    }


@router.get("/frameworks/{framework_id}/controls")
async def framework_controls_with_results(
    framework_id: str,
    provider_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return control-level results: each control with its evaluation status and findings."""
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    from scanner.mitre.attack_mapping import CHECK_DESCRIPTIONS, CHECK_EVIDENCE

    fw = FRAMEWORKS[framework_id]
    controls = get_framework_controls(framework_id)

    # Query all findings for this framework
    fw_filter = _build_fw_filter(framework_id)
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
    )
    if fw_filter is not None:
        query = query.where(fw_filter)
    if provider_id:
        query = query.where(Finding.provider_id == provider_id)
    result = await db.execute(query)
    all_findings = result.scalars().all()

    # Index findings by check_id
    findings_by_check: dict = {}
    for f in all_findings:
        findings_by_check.setdefault(f.check_id, []).append(f)

    # Build per-check status: PASS/FAIL/MANUAL/EXCEPTION/NOT_EVALUATED
    check_statuses: dict = {}
    for cid, findings_list in findings_by_check.items():
        has_fail = any(f.status == "FAIL" for f in findings_list)
        has_pass = any(f.status == "PASS" for f in findings_list)
        has_exception = any(f.status == "EXCEPTION" for f in findings_list)
        has_manual = any(f.status == "MANUAL" for f in findings_list)
        if has_fail:
            check_statuses[cid] = "FAIL"
        elif has_pass:
            check_statuses[cid] = "PASS"
        elif has_exception:
            check_statuses[cid] = "EXCEPTION"
        elif has_manual:
            check_statuses[cid] = "MANUAL"
        else:
            check_statuses[cid] = "NOT_EVALUATED"

    summary = await _per_check_summary(db, current_user.id, framework_id, provider_id, provider_type)

    controls_out = []
    for ctrl in controls:
        checks_map = ctrl.get("checks", {})
        provider_checks = {}
        ctrl_passed = 0
        ctrl_failed = 0
        ctrl_manual = 0
        ctrl_not_evaluated = 0
        ctrl_exception = 0

        if isinstance(checks_map, dict):
            for provider, cids in checks_map.items():
                # When filtering by provider_type, only include matching provider checks
                if provider_type and provider != provider_type:
                    continue
                provider_checks[provider] = []
                for cid in cids:
                    status = check_statuses.get(cid, "NOT_EVALUATED")
                    if status == "PASS":
                        ctrl_passed += 1
                    elif status == "FAIL":
                        ctrl_failed += 1
                    elif status == "EXCEPTION":
                        ctrl_exception += 1
                    elif status == "MANUAL":
                        ctrl_manual += 1
                    else:
                        ctrl_not_evaluated += 1

                    # Get one representative finding for details
                    check_findings = findings_by_check.get(cid, [])
                    provider_checks[provider].append({
                        "check_id": cid,
                        "status": status,
                        "description": CHECK_DESCRIPTIONS.get(cid, f"Security check: {cid.replace('_', ' ')}"),
                        "evidence_method": CHECK_EVIDENCE.get(cid, ""),
                        "finding_count": len(check_findings),
                        "fail_count": sum(1 for f in check_findings if f.status == "FAIL"),
                        "pass_count": sum(1 for f in check_findings if f.status == "PASS"),
                    })

        # Control-level status
        if ctrl_failed > 0:
            ctrl_status = "FAIL"
        elif ctrl_passed > 0:
            ctrl_status = "PASS"
        elif ctrl_exception > 0:
            ctrl_status = "EXCEPTION"
        elif ctrl_manual > 0:
            ctrl_status = "MANUAL"
        else:
            ctrl_status = "NOT_EVALUATED"

        # Skip controls with no checks after provider filtering
        if provider_type and not provider_checks:
            continue

        controls_out.append({
            "id": ctrl.get("id", ""),
            "title": ctrl.get("title", ""),
            "description": ctrl.get("description", ""),
            "status": ctrl_status,
            "passed": ctrl_passed,
            "failed": ctrl_failed,
            "manual": ctrl_manual,
            "not_evaluated": ctrl_not_evaluated,
            "exception": ctrl_exception,
            "checks": provider_checks,
            # Rich metadata from framework definition
            "rationale": ctrl.get("rationale", ""),
            "impact": ctrl.get("impact", ""),
            "remediation_guide": ctrl.get("remediation_guide", ""),
            "audit": ctrl.get("audit", ""),
            "default_value": ctrl.get("default_value", ""),
            "cis_level": ctrl.get("cis_level", ""),
            "assessment_type": ctrl.get("assessment_type", ""),
            "severity": ctrl.get("severity", ""),
            "service": ctrl.get("service", ""),
        })

    return {
        "framework": _get_fw_meta(framework_id),
        "summary": summary,
        "total_controls": len(controls_out),
        "controls": controls_out,
    }


# ---------------------------------------------------------------------------
# Manual control overrides (pass / fail / exception)
# ---------------------------------------------------------------------------


@router.post("/controls/{check_id}/override")
async def override_control_status(
    check_id: str,
    action: str = Form(...),  # "pass", "fail", "exception"
    reason: str = Form(""),
    evidence: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Override a manual/not-evaluated control status.

    action values:
      - "pass"      → finding status becomes PASS
      - "fail"      → finding status becomes FAIL
      - "exception" → finding status becomes EXCEPTION
    """
    if action not in ("pass", "fail", "exception"):
        raise HTTPException(status_code=400, detail="action must be 'pass', 'fail', or 'exception'")

    # Find all MANUAL findings with this check_id for the user
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.check_id == check_id)
    )
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(status_code=404, detail=f"No findings found for check_id {check_id}")

    new_status = action.upper()  # PASS, FAIL, EXCEPTION

    # Handle evidence upload
    evidence_file_name = None
    evidence_file_path = None
    if evidence:
        os.makedirs(EVIDENCE_UPLOAD_DIR, exist_ok=True)
        ext = os.path.splitext(evidence.filename or "")[1]
        safe_name = f"{_uuid_mod.uuid4()}{ext}"
        file_path = os.path.join(EVIDENCE_UPLOAD_DIR, safe_name)
        content = await evidence.read()
        with open(file_path, "wb") as f:
            f.write(content)
        evidence_file_name = evidence.filename
        evidence_file_path = file_path

    # Update all findings for this check_id and record the action
    updated_count = 0
    for finding in findings:
        finding.status = new_status
        # Record the action in finding_actions
        fa = FindingAction(
            finding_id=finding.id,
            user_id=current_user.id,
            action_type=action,
            reason=reason or f"Manual override to {action}",
            evidence_file_name=evidence_file_name,
            evidence_file_path=evidence_file_path,
        )
        db.add(fa)
        updated_count += 1

    await db.commit()

    return {
        "check_id": check_id,
        "new_status": new_status,
        "updated_findings": updated_count,
        "reason": reason,
        "evidence_file_name": evidence_file_name,
    }


@router.get("/controls/{check_id}/actions")
async def get_control_actions(
    check_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get override action history for a specific check_id."""
    # Get finding IDs for this check_id belonging to the user
    result = await db.execute(
        select(Finding.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.check_id == check_id)
    )
    finding_ids = [row[0] for row in result.all()]
    if not finding_ids:
        return []

    result = await db.execute(
        select(FindingAction)
        .where(FindingAction.finding_id.in_(finding_ids))
        .order_by(FindingAction.created_at.desc())
    )
    actions = result.scalars().all()

    return [
        {
            "id": a.id,
            "action_type": a.action_type,
            "reason": a.reason,
            "evidence_file_name": a.evidence_file_name,
            "created_at": a.created_at.isoformat(),
        }
        for a in actions
    ]


# ---------------------------------------------------------------------------
# Framework preferences
# ---------------------------------------------------------------------------


class FrameworkPreferencesBody(BaseModel):
    preferences: dict[str, bool]


@router.get("/framework-preferences")
async def get_framework_preferences(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return a dict of framework_id -> is_enabled for the current user.

    Frameworks without an explicit preference are assumed enabled (True).
    """
    result = await db.execute(
        select(FrameworkPreference.framework_id, FrameworkPreference.is_enabled)
        .where(FrameworkPreference.user_id == current_user.id)
    )
    prefs = {row.framework_id: row.is_enabled for row in result.all()}
    return prefs


@router.put("/framework-preferences")
async def update_framework_preferences(
    body: FrameworkPreferencesBody,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Upsert framework preferences for the current user.

    Body: {"preferences": {"CIS-AWS-6.0": false, "CIS-GCP-3.0": true}}
    """
    import uuid as _uuid
    from datetime import datetime as _dt

    # Fetch existing preferences for this user
    result = await db.execute(
        select(FrameworkPreference)
        .where(FrameworkPreference.user_id == current_user.id)
        .where(FrameworkPreference.framework_id.in_(list(body.preferences.keys())))
    )
    existing = {pref.framework_id: pref for pref in result.scalars().all()}

    for fw_id, is_enabled in body.preferences.items():
        if fw_id in existing:
            existing[fw_id].is_enabled = is_enabled
            existing[fw_id].updated_at = _dt.utcnow()
        else:
            db.add(FrameworkPreference(
                id=str(_uuid.uuid4()),
                user_id=current_user.id,
                framework_id=fw_id,
                is_enabled=is_enabled,
            ))

    await db.commit()
    return {"status": "ok"}
