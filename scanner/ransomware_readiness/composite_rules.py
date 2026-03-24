"""Composite Rule Evaluators for Ransomware Readiness.

These handle rules that require cross-check or aggregate analysis
rather than simple 1:1 mapping to CSPM check_ids.
"""

from __future__ import annotations

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity
from scanner.ransomware_readiness.scoring import CheckEvaluation


def _eval_cis_benchmark_compliance(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-HDN-001: Calculate CIS benchmark compliance percentage.

    Aggregates all CIS-mapped checks from the CSPM and calculates
    the pass rate. Pass if ≥80%.
    """
    cis_prefix_map = {
        "aws": "CIS-AWS",
        "azure": "CIS-Azure",
        "gcp": "CIS-GCP",
    }
    prefix = cis_prefix_map.get(provider, "CIS")

    total_cis = 0
    passed_cis = 0

    for check_id, finding_list in findings_by_check.items():
        for f in finding_list:
            frameworks = f.get("compliance_frameworks") or ""
            if isinstance(frameworks, str) and prefix in frameworks:
                total_cis += 1
                if f.get("status", "").upper() == "PASS":
                    passed_cis += 1
                break  # count check once
            elif isinstance(frameworks, list):
                if any(prefix in fw for fw in frameworks):
                    total_cis += 1
                    if f.get("status", "").upper() == "PASS":
                        passed_cis += 1
                    break

    if total_cis == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={
                "summary": f"No se encontraron checks de CIS Benchmark ({prefix}) en los resultados del scan.",
                "check_type": "composite",
                "expected": "Checks de CIS Benchmark Level 1 presentes en los resultados del scan",
                "actual": "Sin resultados de CIS Benchmark disponibles",
            },
        )

    compliance_pct = (passed_cis / total_cis) * 100
    status = "pass" if compliance_pct >= 80 else "fail"
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status=status,
        resource_count=total_cis, passed_resources=passed_cis,
        failed_resources=total_cis - passed_cis,
        account_id=account_id, provider=provider,
        evidence={
            "summary": f"Compliance CIS Benchmark: {round(compliance_pct, 1)}% ({passed_cis}/{total_cis} checks). "
                       f"Umbral mínimo: 80%. Resultado: {'CUMPLE' if status == 'pass' else 'NO CUMPLE'}.",
            "check_type": "composite",
            "expected": "Porcentaje de compliance CIS Benchmark Level 1 ≥ 80%",
            "actual": f"{round(compliance_pct, 1)}% ({passed_cis} de {total_cis} checks pasan)",
            "compliance_percentage": round(compliance_pct, 1),
            "total_cis_checks": total_cis,
            "passed": passed_cis,
        },
    )


def _eval_security_alerts_configured(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-LOG-003: Verify critical security alerts are configured.

    Checks that alerts exist for: logging changes, IAM root usage,
    and other critical events. Pass if ≥3 of the mapped alert checks pass.
    """
    check_ids = rule.check_ids.get(provider, [])
    passing = 0
    total = len(check_ids)

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        if any(f.get("status", "").upper() == "PASS" for f in matched):
            passing += 1

    if total == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={
                "summary": f"No se encontraron checks de alertas de seguridad para {provider.upper()}.",
                "check_type": "composite",
                "checks_evaluated": check_ids,
                "expected": "Alertas configuradas para eventos críticos de seguridad",
                "actual": "Sin checks de alertas disponibles en el scan",
            },
        )

    # Pass if majority of alert checks pass
    threshold = max(1, total // 2)
    status = "pass" if passing >= threshold else "fail"
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status=status,
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={
            "summary": f"Alertas de seguridad configuradas: {passing} de {total} checks verificados. "
                       f"Se requiere ≥{threshold} alertas activas. "
                       f"Checks: {', '.join(check_ids)}. "
                       f"Resultado: {'CUMPLE' if status == 'pass' else 'NO CUMPLE'}.",
            "check_type": "composite",
            "checks_evaluated": check_ids,
            "expected": f"Al menos {threshold} de {total} alertas de seguridad configuradas",
            "actual": f"{passing} alertas configuradas de {total} verificadas",
        },
    )


def _eval_cross_region_backup(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-BKP-003 / RR-BKP-014: Cross-region or cross-account backup / isolation.

    Aggregates backup replication checks. Pass if any cross-region/cross-account
    backup configuration is detected.
    """
    check_ids = rule.check_ids.get(provider, [])
    found_any = False
    passing = 0
    total = 0

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        for f in matched:
            total += 1
            found_any = True
            if f.get("status", "").upper() == "PASS":
                passing += 1

    if not found_any:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={
                "summary": f"No se encontraron checks de backup cross-region/cross-account para {provider.upper()}.",
                "check_type": "composite",
                "checks_evaluated": check_ids,
                "expected": "Configuración de backup cross-region o cross-account detectada",
                "actual": "Sin checks de backup cross-region disponibles en el scan",
            },
        )

    status = "pass" if passing > 0 else "fail"
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status=status,
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={
            "summary": f"Backup cross-region/cross-account: {passing} de {total} recursos con replicación. "
                       f"Se requiere al menos 1 recurso con replicación. "
                       f"Resultado: {'CUMPLE' if status == 'pass' else 'NO CUMPLE'}.",
            "check_type": "composite",
            "checks_evaluated": check_ids,
            "expected": "Al menos 1 configuración de backup cross-region/cross-account",
            "actual": f"{passing} de {total} recursos con replicación configurada",
        },
    )


def _eval_environment_segmentation(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-NET-007: Environment segmentation (dev/staging/prod).

    Checks that VPCs/networks exist with environment-indicative names/tags,
    suggesting network segmentation between environments.
    """
    check_ids = rule.check_ids.get(provider, [])
    total = 0
    passing = 0

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        for f in matched:
            total += 1
            if f.get("status", "").upper() == "PASS":
                passing += 1

    if total == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={
                "summary": f"No se encontraron checks de segmentación de ambientes para {provider.upper()}.",
                "check_type": "composite",
                "checks_evaluated": check_ids,
                "expected": "Evidencia de segmentación entre ambientes (dev/staging/prod)",
                "actual": "Sin checks de segmentación disponibles en el scan",
            },
        )

    status = "pass" if passing > 0 else "fail"
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status=status,
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={
            "summary": f"Segmentación de ambientes: {passing} de {total} redes con segmentación. "
                       f"Se requiere al menos 1 configuración de segmentación. "
                       f"Resultado: {'CUMPLE' if status == 'pass' else 'NO CUMPLE'}.",
            "check_type": "composite",
            "checks_evaluated": check_ids,
            "expected": "Al menos 1 evidencia de segmentación entre ambientes",
            "actual": f"{passing} de {total} redes con indicadores de segmentación",
        },
    )


def _eval_tagging_compliance(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """RR-HDN-008: Resource tagging/labeling compliance.

    Aggregates tagging check results. Pass if ≥80% of resources are properly tagged.
    """
    check_ids = rule.check_ids.get(provider, [])
    total = 0
    passing = 0

    for cid in check_ids:
        matched = findings_by_check.get(cid, [])
        for f in matched:
            total += 1
            if f.get("status", "").upper() == "PASS":
                passing += 1

    if total == 0:
        return CheckEvaluation(
            rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
            status="warning", account_id=account_id, provider=provider,
            evidence={
                "summary": f"No se encontraron checks de tagging/labeling compliance para {provider.upper()}.",
                "check_type": "composite",
                "checks_evaluated": check_ids,
                "expected": "Checks de compliance de tagging disponibles",
                "actual": "Sin checks de tagging disponibles en el scan",
            },
        )

    pct = (passing / total) * 100
    status = "pass" if pct >= 80 else "fail"
    return CheckEvaluation(
        rule_id=rule.rule_id, domain=rule.domain, severity=rule.severity,
        status=status,
        resource_count=total, passed_resources=passing,
        failed_resources=total - passing,
        account_id=account_id, provider=provider,
        evidence={
            "summary": f"Tagging compliance: {round(pct, 1)}% ({passing}/{total} recursos). "
                       f"Umbral mínimo: 80%. Resultado: {'CUMPLE' if status == 'pass' else 'NO CUMPLE'}.",
            "check_type": "composite",
            "checks_evaluated": check_ids,
            "expected": "Porcentaje de recursos correctamente etiquetados ≥ 80%",
            "actual": f"{round(pct, 1)}% ({passing} de {total} recursos correctamente etiquetados)",
        },
    )


# ── Registry of composite evaluators ────────────────────────
COMPOSITE_EVALUATORS: dict[str, callable] = {
    "RR-HDN-001": _eval_cis_benchmark_compliance,
    "RR-LOG-003": _eval_security_alerts_configured,
    "RR-BKP-003": _eval_cross_region_backup,
    "RR-BKP-014": _eval_cross_region_backup,
    "RR-NET-007": _eval_environment_segmentation,
    "RR-HDN-008": _eval_tagging_compliance,
}
