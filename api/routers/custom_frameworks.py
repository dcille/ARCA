"""Custom Frameworks router — CRUD, check selection, custom controls, Excel."""
import json
import uuid
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from api.database import get_db
from api.models.user import User
from api.models.custom_framework import CustomFramework, CustomFrameworkCheck, CustomControl
from api.schemas.custom_framework import (
    CustomFrameworkCreate,
    CustomFrameworkUpdate,
    CustomFrameworkResponse,
    SelectedCheckAdd,
    CustomControlCreate,
    CustomControlUpdate,
    ExcelImportPreview,
    ExcelImportConfirm,
)
from api.services.auth_service import get_current_user
from api.services.custom_framework_service import (
    _parse_json_list,
    _to_json,
    determine_assessment_type,
    register_custom_control_in_registry,
    unregister_custom_control_from_registry,
    format_custom_control_response,
    format_framework_response,
    evaluate_custom_framework,
)
from scanner.registry import get_default_registry, CheckDefinition

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------
# Available Checks (from registry)
# ---------------------------------------------------------------

@router.get("/available-checks")
async def list_available_checks(
    search: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
):
    """List all checks from the registry, with search and filters."""
    registry = get_default_registry()

    if search:
        checks = registry.search_checks(search)
    else:
        checks = registry.list_checks()

    if provider:
        checks = [c for c in checks if c.provider == provider]
    if category:
        checks = [c for c in checks if c.category.lower() == category.lower()]
    if severity:
        checks = [c for c in checks if c.severity == severity]
    if source:
        checks = [c for c in checks if c.source == source]

    total = len(checks)
    page = checks[offset:offset + limit]

    return {
        "total": total,
        "items": [_check_to_summary(c) for c in page],
    }


def _check_to_summary(c: CheckDefinition) -> dict:
    return {
        "check_id": c.check_id,
        "title": c.title,
        "description": c.description,
        "provider": c.provider,
        "service": c.service,
        "category": c.category,
        "severity": c.severity,
        "assessment_type": c.assessment_type,
        "source": c.source,
        "cis_id": c.cis_id,
        "has_scanner": len(c.scanner_check_ids) > 0,
        "tags": c.tags,
    }


# ---------------------------------------------------------------
# Registry metadata
# ---------------------------------------------------------------

@router.get("/registry-stats")
async def registry_stats():
    """Return registry statistics for the UI."""
    registry = get_default_registry()
    checks = registry.list_checks()

    providers = {}
    categories = {}
    severities = {}
    sources = {}
    for c in checks:
        providers[c.provider] = providers.get(c.provider, 0) + 1
        categories[c.category] = categories.get(c.category, 0) + 1
        severities[c.severity] = severities.get(c.severity, 0) + 1
        sources[c.source] = sources.get(c.source, 0) + 1

    return {
        "total_checks": len(checks),
        "providers": providers,
        "categories": categories,
        "severities": severities,
        "sources": sources,
    }


# ---------------------------------------------------------------
# CRUD Framework
# ---------------------------------------------------------------

@router.post("")
async def create_framework(
    body: CustomFrameworkCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new custom framework."""
    registry = get_default_registry()

    fw = CustomFramework(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        name=body.name,
        description=body.description,
        version=body.version,
        providers=json.dumps(body.providers),
    )
    db.add(fw)

    # Add selected checks from registry
    for idx, check_id in enumerate(body.selected_check_ids):
        if not registry.has_check(check_id):
            raise HTTPException(
                status_code=400,
                detail=f"Check '{check_id}' not found in registry",
            )
        sc = CustomFrameworkCheck(
            id=str(uuid.uuid4()),
            framework_id=fw.id,
            registry_check_id=check_id,
            display_order=idx,
        )
        db.add(sc)

    await db.commit()
    await db.refresh(fw, attribute_names=["selected_checks", "custom_controls"])

    return format_framework_response(fw)


@router.get("")
async def list_frameworks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all custom frameworks for the current user."""
    result = await db.execute(
        select(CustomFramework)
        .options(selectinload(CustomFramework.selected_checks), selectinload(CustomFramework.custom_controls))
        .where(CustomFramework.user_id == current_user.id, CustomFramework.is_active == True)
        .order_by(CustomFramework.created_at.desc())
    )
    frameworks = result.scalars().all()
    return [format_framework_response(fw) for fw in frameworks]


@router.get("/{fw_id}")
async def get_framework(
    fw_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get framework detail with resolved checks and compliance summary."""
    fw = await _get_framework(fw_id, current_user.id, db)
    registry = get_default_registry()

    # Resolve selected checks from registry
    selected = []
    for sc in fw.selected_checks:
        check = registry.get_check(sc.registry_check_id)
        if check:
            selected.append({
                "id": sc.id,
                "registry_check_id": sc.registry_check_id,
                "title": check.title,
                "description": check.description,
                "provider": check.provider,
                "service": check.service,
                "category": check.category,
                "severity": check.severity,
                "assessment_type": check.assessment_type,
                "source": check.source,
                "cis_id": check.cis_id,
                "has_scanner": len(check.scanner_check_ids) > 0,
                "tags": check.tags,
                "display_order": sc.display_order,
            })
        else:
            selected.append({
                "id": sc.id,
                "registry_check_id": sc.registry_check_id,
                "title": f"Unknown: {sc.registry_check_id}",
                "description": "",
                "provider": "unknown",
                "severity": "medium",
                "assessment_type": "manual",
                "source": "unknown",
                "display_order": sc.display_order,
            })

    # Format custom controls
    custom_ctrls = [format_custom_control_response(ctrl) for ctrl in fw.custom_controls]

    # Evaluate compliance
    summary = await evaluate_custom_framework(fw, db, current_user.id)

    resp = format_framework_response(fw)
    resp["selected_checks"] = selected
    resp["custom_controls"] = custom_ctrls
    resp["summary"] = summary

    return resp


@router.get("/{fw_id}/evaluation")
async def get_framework_evaluation(
    fw_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get per-check evaluation status for a custom framework."""
    from sqlalchemy import func, case
    from api.models.finding import Finding
    from api.models.scan import Scan

    fw = await _get_framework(fw_id, current_user.id, db)
    registry = get_default_registry()

    # Collect all scanner_check_ids
    all_scanner_ids: list[str] = []
    check_scanner_map: dict[str, list[str]] = {}  # check_id -> [scanner_ids]

    for sc in (fw.selected_checks or []):
        check = registry.get_check(sc.registry_check_id)
        if check:
            sids = check.scanner_check_ids or [check.check_id]
            check_scanner_map[check.check_id] = sids
            all_scanner_ids.extend(sids)
        else:
            check_scanner_map[sc.registry_check_id] = [sc.registry_check_id]
            all_scanner_ids.append(sc.registry_check_id)

    for ctrl in (fw.custom_controls or []):
        sids = _parse_json_list(ctrl.scanner_check_ids)
        if sids:
            check_scanner_map[ctrl.check_id] = sids
            all_scanner_ids.extend(sids)
        else:
            check_scanner_map[ctrl.check_id] = [ctrl.check_id]
            all_scanner_ids.append(ctrl.check_id)

    if not all_scanner_ids:
        return {"check_statuses": {}}

    # Query findings grouped by check_id
    query = (
        select(
            Finding.check_id,
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("fail_count"),
            func.sum(case((Finding.status == "PASS", 1), else_=0)).label("pass_count"),
            func.sum(case((Finding.status == "MANUAL", 1), else_=0)).label("manual_count"),
            func.sum(case((Finding.status == "ERROR", 1), else_=0)).label("error_count"),
            func.count(Finding.id).label("total"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .where(Finding.check_id.in_(all_scanner_ids))
        .group_by(Finding.check_id)
    )
    result = await db.execute(query)
    findings_map = {
        row.check_id: (row.fail_count or 0, row.pass_count or 0, row.manual_count or 0, row.error_count or 0, row.total or 0)
        for row in result.all()
    }

    # Build per-check status
    check_statuses: dict[str, dict] = {}
    for check_id, scanner_ids in check_scanner_map.items():
        has_fail = False
        has_pass = False
        has_manual = False
        has_error = False
        total_findings = 0
        total_fails = 0
        for sid in scanner_ids:
            if sid in findings_map:
                fc, pc, mc, ec, t = findings_map[sid]
                if fc > 0:
                    has_fail = True
                    total_fails += fc
                if pc > 0:
                    has_pass = True
                if mc > 0:
                    has_manual = True
                if ec > 0:
                    has_error = True
                total_findings += t

        if has_fail:
            status = "FAIL"
        elif has_pass:
            status = "PASS"
        elif has_manual:
            status = "MANUAL"
        elif has_error:
            status = "ERROR"
        else:
            status = "NOT_EVALUATED"

        check_statuses[check_id] = {
            "status": status,
            "findings": total_findings,
            "fail_count": total_fails,
        }

    return {"check_statuses": check_statuses}


@router.put("/{fw_id}")
async def update_framework(
    fw_id: str,
    body: CustomFrameworkUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update framework metadata."""
    fw = await _get_framework(fw_id, current_user.id, db)

    if body.name is not None:
        fw.name = body.name
    if body.description is not None:
        fw.description = body.description
    if body.version is not None:
        fw.version = body.version
    if body.providers is not None:
        fw.providers = json.dumps(body.providers)

    await db.commit()
    await db.refresh(fw, attribute_names=["selected_checks", "custom_controls"])
    return format_framework_response(fw)


@router.delete("/{fw_id}")
async def delete_framework(
    fw_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Soft delete framework and unregister its custom controls."""
    fw = await _get_framework(fw_id, current_user.id, db)

    # Unregister custom controls from registry
    for ctrl in fw.custom_controls:
        unregister_custom_control_from_registry(ctrl.check_id)

    fw.is_active = False
    await db.commit()
    return {"detail": "Framework deleted"}


@router.post("/{fw_id}/clone")
async def clone_framework(
    fw_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Clone a framework with all its checks and controls."""
    fw = await _get_framework(fw_id, current_user.id, db)

    new_fw = CustomFramework(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        name=f"{fw.name} (Copy)",
        description=fw.description,
        version=fw.version,
        providers=fw.providers,
    )
    db.add(new_fw)

    # Clone selected checks
    for sc in fw.selected_checks:
        new_sc = CustomFrameworkCheck(
            id=str(uuid.uuid4()),
            framework_id=new_fw.id,
            registry_check_id=sc.registry_check_id,
            display_order=sc.display_order,
        )
        db.add(new_sc)

    # Clone custom controls (new check_ids to avoid collisions)
    for ctrl in fw.custom_controls:
        new_check_id = f"{ctrl.check_id}_copy_{str(uuid.uuid4())[:8]}"
        new_ctrl = CustomControl(
            id=str(uuid.uuid4()),
            framework_id=new_fw.id,
            check_id=new_check_id,
            title=ctrl.title,
            description=ctrl.description,
            severity=ctrl.severity,
            provider=ctrl.provider,
            service=ctrl.service,
            category=ctrl.category,
            assessment_type=ctrl.assessment_type,
            risks=ctrl.risks,
            cli_commands=ctrl.cli_commands,
            remediation=ctrl.remediation,
            remediation_steps=ctrl.remediation_steps,
            scanner_check_ids=ctrl.scanner_check_ids,
            tags=ctrl.tags,
            references=ctrl.references,
            evaluation_script=ctrl.evaluation_script,
            cli_command=ctrl.cli_command,
            pass_condition=ctrl.pass_condition,
            display_order=ctrl.display_order,
        )
        db.add(new_ctrl)
        # Register cloned control in registry
        try:
            register_custom_control_in_registry(new_ctrl)
        except ValueError as exc:
            logger.warning("Clone: could not register %s: %s", new_check_id, exc)

    await db.commit()
    await db.refresh(new_fw, attribute_names=["selected_checks", "custom_controls"])
    return format_framework_response(new_fw)


# ---------------------------------------------------------------
# Selected checks management
# ---------------------------------------------------------------

@router.post("/{fw_id}/checks")
async def add_selected_checks(
    fw_id: str,
    body: SelectedCheckAdd,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add checks from the registry to the framework."""
    fw = await _get_framework(fw_id, current_user.id, db)
    registry = get_default_registry()

    existing_ids = {sc.registry_check_id for sc in fw.selected_checks}
    max_order = max((sc.display_order for sc in fw.selected_checks), default=-1) + 1
    added = []

    for check_id in body.registry_check_ids:
        if not registry.has_check(check_id):
            raise HTTPException(status_code=400, detail=f"Check '{check_id}' not found in registry")
        if check_id in existing_ids:
            continue
        sc = CustomFrameworkCheck(
            id=str(uuid.uuid4()),
            framework_id=fw.id,
            registry_check_id=check_id,
            display_order=max_order,
        )
        db.add(sc)
        added.append(check_id)
        existing_ids.add(check_id)
        max_order += 1

    await db.commit()
    return {"added": len(added), "check_ids": added}


@router.delete("/{fw_id}/checks/{check_record_id}")
async def remove_selected_check(
    fw_id: str,
    check_record_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove a selected check from the framework."""
    await _get_framework(fw_id, current_user.id, db)

    result = await db.execute(
        select(CustomFrameworkCheck)
        .where(CustomFrameworkCheck.id == check_record_id, CustomFrameworkCheck.framework_id == fw_id)
    )
    sc = result.scalars().first()
    if not sc:
        raise HTTPException(status_code=404, detail="Check not found in framework")

    await db.delete(sc)
    await db.commit()
    return {"detail": "Check removed"}


# ---------------------------------------------------------------
# Custom controls CRUD
# ---------------------------------------------------------------

@router.post("/{fw_id}/controls")
async def create_custom_control(
    fw_id: str,
    body: CustomControlCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new custom control within a framework."""
    fw = await _get_framework(fw_id, current_user.id, db)
    registry = get_default_registry()

    # Check uniqueness
    if registry.has_check(body.check_id):
        raise HTTPException(
            status_code=400,
            detail=f"check_id '{body.check_id}' already exists in the registry",
        )

    # Determine assessment_type: if eval fields present, it's automated
    has_evaluation = bool(body.evaluation_script or body.cli_command)
    if has_evaluation:
        assessment = "automated"
    else:
        assessment = determine_assessment_type(body.scanner_check_ids)

    # Validate evaluation script syntax
    warnings = []
    if body.evaluation_script:
        try:
            compile(body.evaluation_script, f"<control:{body.check_id}>", "exec")
        except SyntaxError as e:
            raise HTTPException(
                status_code=422,
                detail=f"Python script has syntax error at line {e.lineno}: {e.msg}",
            )

    # Validate CLI command (basic safety checks)
    if body.cli_command:
        cmd = body.cli_command.strip()
        if not cmd.startswith("az "):
            raise HTTPException(
                status_code=422,
                detail="CLI command must start with 'az ' (Azure CLI).",
            )
        cmd_parts = cmd.split()
        dangerous = {"delete", "remove", "purge", "update", "create", "set"}
        if len(cmd_parts) > 2 and cmd_parts[2] in dangerous:
            raise HTTPException(
                status_code=422,
                detail=f"CLI command contains destructive operation '{cmd_parts[2]}'. "
                       "Only read operations (list, show, get) are allowed.",
            )

    # Validate scanner_check_ids (warn but don't block)
    for sid in body.scanner_check_ids:
        if not registry.has_scanner_id(sid):
            warnings.append(f"scanner_check_id '{sid}' not found in registry")

    max_order = max((c.display_order for c in fw.custom_controls), default=-1) + 1

    ctrl = CustomControl(
        id=str(uuid.uuid4()),
        framework_id=fw.id,
        check_id=body.check_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        provider=body.provider,
        service=body.service,
        category=body.category,
        assessment_type=assessment,
        risks=body.risks,
        cli_commands=_to_json(body.cli_commands),
        remediation=body.remediation,
        remediation_steps=_to_json(body.remediation_steps),
        scanner_check_ids=_to_json(body.scanner_check_ids),
        tags=_to_json(body.tags),
        references=_to_json(body.references),
        evaluation_script=body.evaluation_script,
        cli_command=body.cli_command,
        pass_condition=body.pass_condition,
        display_order=max_order,
    )
    db.add(ctrl)
    await db.commit()
    await db.refresh(ctrl)

    # Register in runtime registry
    try:
        register_custom_control_in_registry(ctrl)
    except ValueError as exc:
        logger.warning("Could not register custom control in registry: %s", exc)

    resp = format_custom_control_response(ctrl)
    if warnings:
        resp["warnings"] = warnings
    return resp


@router.put("/{fw_id}/controls/{ctrl_id}")
async def update_custom_control(
    fw_id: str,
    ctrl_id: str,
    body: CustomControlUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a custom control."""
    await _get_framework(fw_id, current_user.id, db)

    result = await db.execute(
        select(CustomControl)
        .where(CustomControl.id == ctrl_id, CustomControl.framework_id == fw_id)
    )
    ctrl = result.scalars().first()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Custom control not found")

    old_check_id = ctrl.check_id

    if body.title is not None:
        ctrl.title = body.title
    if body.description is not None:
        ctrl.description = body.description
    if body.severity is not None:
        ctrl.severity = body.severity
    if body.provider is not None:
        ctrl.provider = body.provider
    if body.service is not None:
        ctrl.service = body.service
    if body.category is not None:
        ctrl.category = body.category
    if body.risks is not None:
        ctrl.risks = body.risks
    if body.cli_commands is not None:
        ctrl.cli_commands = _to_json(body.cli_commands)
    if body.remediation is not None:
        ctrl.remediation = body.remediation
    if body.remediation_steps is not None:
        ctrl.remediation_steps = _to_json(body.remediation_steps)
    if body.scanner_check_ids is not None:
        ctrl.scanner_check_ids = _to_json(body.scanner_check_ids)
        ctrl.assessment_type = determine_assessment_type(body.scanner_check_ids)
    if body.tags is not None:
        ctrl.tags = _to_json(body.tags)
    if body.references is not None:
        ctrl.references = _to_json(body.references)
    if body.evaluation_script is not None:
        # Validate syntax
        try:
            compile(body.evaluation_script, f"<control:{ctrl.check_id}>", "exec")
        except SyntaxError as e:
            raise HTTPException(
                status_code=422,
                detail=f"Python script has syntax error at line {e.lineno}: {e.msg}",
            )
        ctrl.evaluation_script = body.evaluation_script
    if body.cli_command is not None:
        if body.cli_command and not body.cli_command.strip().startswith("az "):
            raise HTTPException(status_code=422, detail="CLI command must start with 'az '.")
        ctrl.cli_command = body.cli_command
    if body.pass_condition is not None:
        ctrl.pass_condition = body.pass_condition

    # Re-evaluate assessment_type based on all evaluation fields
    has_eval = bool(ctrl.evaluation_script or ctrl.cli_command)
    if has_eval:
        ctrl.assessment_type = "automated"
    elif body.scanner_check_ids is not None:
        ctrl.assessment_type = determine_assessment_type(body.scanner_check_ids)

    await db.commit()
    await db.refresh(ctrl)

    # Re-register in registry
    unregister_custom_control_from_registry(old_check_id)
    try:
        register_custom_control_in_registry(ctrl)
    except ValueError as exc:
        logger.warning("Could not re-register custom control: %s", exc)

    return format_custom_control_response(ctrl)


@router.delete("/{fw_id}/controls/{ctrl_id}")
async def delete_custom_control(
    fw_id: str,
    ctrl_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a custom control from framework and registry."""
    await _get_framework(fw_id, current_user.id, db)

    result = await db.execute(
        select(CustomControl)
        .where(CustomControl.id == ctrl_id, CustomControl.framework_id == fw_id)
    )
    ctrl = result.scalars().first()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Custom control not found")

    unregister_custom_control_from_registry(ctrl.check_id)
    await db.delete(ctrl)
    await db.commit()
    return {"detail": "Custom control deleted"}


@router.post("/{fw_id}/controls/{ctrl_id}/test")
async def test_custom_control(
    fw_id: str,
    ctrl_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Dry-run a custom control's evaluation logic.

    Returns evaluation results without saving them as scan findings.
    Requires the control to have evaluation_script or cli_command.
    """
    await _get_framework(fw_id, current_user.id, db)

    result = await db.execute(
        select(CustomControl)
        .where(CustomControl.id == ctrl_id, CustomControl.framework_id == fw_id)
    )
    ctrl = result.scalars().first()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Custom control not found")

    eval_script = getattr(ctrl, "evaluation_script", None)
    cli_cmd = getattr(ctrl, "cli_command", None)

    if not eval_script and not cli_cmd:
        raise HTTPException(
            status_code=400,
            detail="This control has no evaluation logic (no evaluation_script or cli_command).",
        )

    # We need credentials for the test — get the user's Azure provider
    from api.models.provider import Provider
    from api.services.auth_service import decrypt_credentials

    provider_result = await db.execute(
        select(Provider).where(
            Provider.user_id == current_user.id,
            Provider.provider_type == "azure",
        ).limit(1)
    )
    provider = provider_result.scalars().first()
    if not provider:
        raise HTTPException(
            status_code=400,
            detail="No Azure provider configured. Add an Azure provider to test controls.",
        )

    credentials = decrypt_credentials(provider.credentials_encrypted)

    # Build the custom control and execute
    from scanner.providers.azure.custom_control_executor import CustomControl as ExecControl, CustomControlExecutor

    try:
        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=credentials.get("tenant_id"),
            client_id=credentials.get("client_id"),
            client_secret=credentials.get("client_secret"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create Azure credential: {e}")

    exec_control = ExecControl(
        control_id=ctrl.check_id,
        title=ctrl.title,
        description=ctrl.description or "",
        severity=ctrl.severity,
        service=ctrl.service,
        framework_id=fw_id,
        remediation=ctrl.remediation or "",
        evaluation_script=eval_script,
        cli_command=cli_cmd,
        pass_condition=getattr(ctrl, "pass_condition", "empty") or "empty",
    )

    executor = CustomControlExecutor(
        credential=credential,
        subscription_id=credentials.get("subscription_id", ""),
        tenant_id=credentials.get("tenant_id", ""),
    )

    results = executor.execute(exec_control)

    return {
        "control_id": ctrl.check_id,
        "evaluation_type": "python_script" if eval_script else "cli_command",
        "results": results,
        "total": len(results),
        "passed": sum(1 for r in results if r.get("status") == "PASS"),
        "failed": sum(1 for r in results if r.get("status") == "FAIL"),
        "errors": sum(1 for r in results if r.get("status") == "ERROR"),
    }


# ---------------------------------------------------------------
# Excel import/export
# ---------------------------------------------------------------

@router.get("/{fw_id}/template.xlsx")
async def download_template(
    fw_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download Excel template with registry reference data."""
    await _get_framework(fw_id, current_user.id, db)

    try:
        from api.services.excel_template_service import generate_template
        content = generate_template()
        return StreamingResponse(
            content,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename=custom_controls_template.xlsx"},
        )
    except ImportError:
        raise HTTPException(status_code=501, detail="Excel support not available. Install openpyxl.")


@router.post("/{fw_id}/import-excel")
async def import_excel_preview(
    fw_id: str,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Parse uploaded Excel and return validation preview (no persistence)."""
    await _get_framework(fw_id, current_user.id, db)

    try:
        from api.services.excel_import_service import parse_and_validate_excel
    except ImportError:
        raise HTTPException(status_code=501, detail="Excel support not available. Install openpyxl.")

    content = await file.read()
    result = parse_and_validate_excel(content)
    return result


@router.post("/{fw_id}/import-confirm")
async def import_excel_confirm(
    fw_id: str,
    body: ExcelImportConfirm,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Confirm import: persist controls to DB and register in registry."""
    fw = await _get_framework(fw_id, current_user.id, db)
    registry = get_default_registry()

    max_order = max((c.display_order for c in fw.custom_controls), default=-1) + 1
    created = []

    for ctrl_data in body.controls:
        if registry.has_check(ctrl_data.check_id):
            logger.warning("Skipping duplicate check_id during import: %s", ctrl_data.check_id)
            continue

        assessment = determine_assessment_type(ctrl_data.scanner_check_ids)

        has_eval = bool(getattr(ctrl_data, "evaluation_script", None) or getattr(ctrl_data, "cli_command", None))
        if has_eval:
            assessment = "automated"

        ctrl = CustomControl(
            id=str(uuid.uuid4()),
            framework_id=fw.id,
            check_id=ctrl_data.check_id,
            title=ctrl_data.title,
            description=ctrl_data.description,
            severity=ctrl_data.severity,
            provider=ctrl_data.provider,
            service=ctrl_data.service,
            category=ctrl_data.category,
            assessment_type=assessment,
            risks=ctrl_data.risks,
            cli_commands=_to_json(ctrl_data.cli_commands),
            remediation=ctrl_data.remediation,
            remediation_steps=_to_json(ctrl_data.remediation_steps),
            scanner_check_ids=_to_json(ctrl_data.scanner_check_ids),
            tags=_to_json(ctrl_data.tags),
            references=_to_json(ctrl_data.references),
            evaluation_script=getattr(ctrl_data, "evaluation_script", None),
            cli_command=getattr(ctrl_data, "cli_command", None),
            pass_condition=getattr(ctrl_data, "pass_condition", None),
            display_order=max_order,
        )
        db.add(ctrl)
        max_order += 1

        try:
            register_custom_control_in_registry(ctrl)
        except ValueError:
            pass

        created.append(ctrl_data.check_id)

    await db.commit()
    return {"imported": len(created), "check_ids": created}


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

async def _get_framework(fw_id: str, user_id: str, db: AsyncSession) -> CustomFramework:
    result = await db.execute(
        select(CustomFramework)
        .options(selectinload(CustomFramework.selected_checks), selectinload(CustomFramework.custom_controls))
        .where(CustomFramework.id == fw_id, CustomFramework.user_id == user_id, CustomFramework.is_active == True)
    )
    fw = result.scalars().first()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    return fw
