"""Service layer for Custom Frameworks — sync, evaluation, helpers."""
import json
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case

from api.models.custom_framework import CustomFramework, CustomFrameworkCheck, CustomControl
from api.models.finding import Finding
from api.models.scan import Scan
from scanner.registry.registry import get_default_registry
from scanner.registry.models import CheckDefinition

logger = logging.getLogger(__name__)


def _parse_json_list(value: Optional[str]) -> list:
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []


def _to_json(value) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value)


def _generated_check_id(check_id: str) -> str:
    """Generate the check_id that the custom control executor will use for findings."""
    return f"custom_{check_id.lower().replace('-', '_').replace('.', '_')}"


def _to_check_definition(ctrl: CustomControl) -> CheckDefinition:
    """Convert a CustomControl DB row to a CheckDefinition for the registry."""
    scanner_ids = _parse_json_list(ctrl.scanner_check_ids)
    tags = _parse_json_list(ctrl.tags)
    if "custom" not in tags:
        tags.append("custom")

    # If this control has evaluation logic, include the generated check_id
    # so the compliance system can find its findings
    has_eval = bool(getattr(ctrl, "evaluation_script", None) or getattr(ctrl, "cli_command", None))
    if has_eval:
        gen_id = _generated_check_id(ctrl.check_id)
        if gen_id not in scanner_ids:
            scanner_ids.append(gen_id)

    return CheckDefinition(
        check_id=ctrl.check_id,
        title=ctrl.title,
        description=ctrl.description or "",
        severity=ctrl.severity,
        provider=ctrl.provider,
        service=ctrl.service,
        category=ctrl.category,
        assessment_type=ctrl.assessment_type,
        scanner_check_ids=scanner_ids,
        remediation=ctrl.remediation or "",
        references=_parse_json_list(ctrl.references),
        tags=tags,
        source="custom",
    )


def determine_assessment_type(scanner_check_ids: list[str], has_evaluation_logic: bool = False) -> str:
    """Determine assessment_type based on whether scanner_check_ids map to real scanners."""
    if has_evaluation_logic:
        return "automated"
    if not scanner_check_ids:
        return "manual"
    registry = get_default_registry()
    for sid in scanner_check_ids:
        if registry.has_scanner_id(sid):
            return "automated"
    return "manual"


async def sync_custom_controls_to_registry(db: AsyncSession) -> int:
    """Load all custom controls from DB into the registry at startup."""
    registry = get_default_registry()
    result = await db.execute(select(CustomControl))
    controls = result.scalars().all()
    count = 0
    for ctrl in controls:
        if registry.has_check(ctrl.check_id):
            continue
        check_def = _to_check_definition(ctrl)
        try:
            registry.register_check(check_def, custom=True)
            count += 1
        except ValueError as exc:
            logger.warning("Skipping custom control %s: %s", ctrl.check_id, exc)
    return count


def register_custom_control_in_registry(ctrl: CustomControl) -> None:
    """Register a single custom control in the runtime registry."""
    registry = get_default_registry()
    check_def = _to_check_definition(ctrl)
    registry.register_check(check_def, custom=True)


def unregister_custom_control_from_registry(check_id: str) -> None:
    """Remove a custom control from the runtime registry."""
    registry = get_default_registry()
    try:
        registry.unregister_check(check_id)
    except KeyError:
        logger.warning("Custom control %s not found in registry for unregister", check_id)


def format_custom_control_response(ctrl: CustomControl) -> dict:
    """Format a CustomControl row for API response."""
    # Determine evaluation type
    if getattr(ctrl, "evaluation_script", None):
        eval_type = "python_script"
    elif getattr(ctrl, "cli_command", None):
        eval_type = "cli_command"
    else:
        eval_type = "manual"

    return {
        "id": ctrl.id,
        "check_id": ctrl.check_id,
        "title": ctrl.title,
        "description": ctrl.description,
        "severity": ctrl.severity,
        "provider": ctrl.provider,
        "service": ctrl.service,
        "category": ctrl.category,
        "assessment_type": ctrl.assessment_type,
        "risks": ctrl.risks,
        "cli_commands": _parse_json_list(ctrl.cli_commands) if ctrl.cli_commands else None,
        "remediation": ctrl.remediation,
        "remediation_steps": _parse_json_list(ctrl.remediation_steps),
        "scanner_check_ids": _parse_json_list(ctrl.scanner_check_ids),
        "tags": _parse_json_list(ctrl.tags),
        "references": _parse_json_list(ctrl.references),
        "evaluation_script": getattr(ctrl, "evaluation_script", None),
        "cli_command": getattr(ctrl, "cli_command", None),
        "pass_condition": getattr(ctrl, "pass_condition", None),
        "evaluation_type": eval_type,
        "display_order": ctrl.display_order,
        "created_at": ctrl.created_at.isoformat() if ctrl.created_at else None,
    }


def format_framework_response(fw: CustomFramework) -> dict:
    """Format a CustomFramework row for API response."""
    return {
        "id": fw.id,
        "name": fw.name,
        "description": fw.description,
        "version": fw.version,
        "providers": _parse_json_list(fw.providers),
        "is_active": fw.is_active,
        "created_at": fw.created_at.isoformat() if fw.created_at else None,
        "updated_at": fw.updated_at.isoformat() if fw.updated_at else None,
        "total_checks": len(fw.selected_checks) if fw.selected_checks else 0,
        "total_custom_controls": len(fw.custom_controls) if fw.custom_controls else 0,
        "type": "custom",
    }


async def evaluate_custom_framework(
    fw: CustomFramework,
    db: AsyncSession,
    user_id: str,
    provider_id: Optional[str] = None,
) -> dict:
    """Calculate pass rate for a custom framework by querying findings."""
    registry = get_default_registry()

    # Collect all scanner_check_ids to query
    all_check_ids_to_query: list[str] = []
    check_entries: list[dict] = []  # {check_id, assessment_type, source}

    # From selected registry checks
    for sc in (fw.selected_checks or []):
        check = registry.get_check(sc.registry_check_id)
        if not check:
            check_entries.append({
                "check_id": sc.registry_check_id,
                "assessment_type": "manual",
                "source": "unknown",
                "scanner_ids": [],
            })
            continue
        scanner_ids = check.scanner_check_ids or [check.check_id]
        all_check_ids_to_query.extend(scanner_ids)
        check_entries.append({
            "check_id": check.check_id,
            "assessment_type": check.assessment_type,
            "source": check.source,
            "scanner_ids": scanner_ids,
        })

    # From custom controls
    for ctrl in (fw.custom_controls or []):
        scanner_ids = _parse_json_list(ctrl.scanner_check_ids)
        if scanner_ids:
            all_check_ids_to_query.extend(scanner_ids)
        else:
            all_check_ids_to_query.append(ctrl.check_id)
        check_entries.append({
            "check_id": ctrl.check_id,
            "assessment_type": ctrl.assessment_type,
            "source": "custom",
            "scanner_ids": scanner_ids or [ctrl.check_id],
        })

    if not all_check_ids_to_query:
        return {
            "total_checks": len(check_entries),
            "automated": 0,
            "manual": len(check_entries),
            "passed": 0,
            "failed": 0,
            "not_evaluated": 0,
            "pass_rate": 0,
            "evaluation_coverage": 0,
        }

    # Query findings for all scanner_check_ids
    query = (
        select(
            Finding.check_id,
            func.sum(case((Finding.status == "FAIL", 1), else_=0)).label("fail_count"),
            func.sum(case((Finding.status == "PASS", 1), else_=0)).label("pass_count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == user_id)
        .where(Finding.check_id.in_(all_check_ids_to_query))
        .group_by(Finding.check_id)
    )
    if provider_id:
        query = query.where(Finding.provider_id == provider_id)

    result = await db.execute(query)
    findings_map = {
        row.check_id: (row.fail_count or 0, row.pass_count or 0)
        for row in result.all()
    }

    # Evaluate each check
    total = len(check_entries)
    automated = 0
    manual = 0
    passed = 0
    failed = 0
    not_evaluated = 0

    for entry in check_entries:
        if entry["assessment_type"] == "manual":
            manual += 1
            continue
        automated += 1
        # Check if any scanner_id has findings
        has_fail = False
        has_pass = False
        for sid in entry["scanner_ids"]:
            if sid in findings_map:
                fc, pc = findings_map[sid]
                if fc > 0:
                    has_fail = True
                if pc > 0:
                    has_pass = True

        if has_fail:
            failed += 1
        elif has_pass:
            passed += 1
        else:
            not_evaluated += 1

    evaluated = passed + failed
    pass_rate = round((passed / evaluated * 100), 1) if evaluated > 0 else 0
    evaluation_coverage = round((automated / total * 100), 1) if total > 0 else 0

    return {
        "total_checks": total,
        "automated": automated,
        "manual": manual,
        "passed": passed,
        "failed": failed,
        "not_evaluated": not_evaluated,
        "pass_rate": pass_rate,
        "evaluation_coverage": evaluation_coverage,
    }
