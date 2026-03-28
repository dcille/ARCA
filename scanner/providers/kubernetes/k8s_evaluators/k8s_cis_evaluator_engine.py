"""CIS Kubernetes v1.12.0 Evaluator Engine.

Orchestrates all CIS evaluators registered in EVALUATOR_REGISTRY,
produces results for automated controls, and emits MANUAL results
for controls not covered by any evaluator.

Path: scanner/providers/kubernetes/k8s_cis_evaluator_engine.py
"""

import logging
from scanner.providers.kubernetes.evaluators.base import (
    EVALUATOR_REGISTRY, K8sClientCache, build_result,
)
from scanner.cis_controls.kubernetes_cis_controls import KUBERNETES_CIS_CONTROLS

logger = logging.getLogger(__name__)

# Import all section modules to trigger @register decorators
import scanner.providers.kubernetes.evaluators.section_1_control_plane  # noqa: F401
import scanner.providers.kubernetes.evaluators.section_2_3_4            # noqa: F401
import scanner.providers.kubernetes.evaluators.section_5_supplements    # noqa: F401


class K8sCISEvaluatorEngine:
    """Runs all CIS K8s v1.12.0 evaluators against a cluster."""

    def __init__(self, credentials: dict):
        self.cache = K8sClientCache(credentials)

    def run_all(self) -> list[dict]:
        """Execute all registered evaluators + emit MANUAL for uncovered controls.

        Returns a complete list of results covering all 131 CIS controls.
        """
        results = []
        covered_cis_ids = set()

        # ── Run all registered evaluators ──
        for cis_id, evaluator_fn in sorted(EVALUATOR_REGISTRY.items()):
            try:
                eval_results = evaluator_fn(self.cache)
                results.extend(eval_results)
                covered_cis_ids.add(cis_id)
                logger.debug("Evaluated CIS %s: %d results", cis_id, len(eval_results))
            except Exception as e:
                logger.error("Evaluator for CIS %s failed: %s", cis_id, e)
                results.append(build_result(
                    check_id=f"k8s_cis_{cis_id.replace('.', '_')}",
                    title=f"CIS {cis_id} evaluation error",
                    service="evaluator", severity="medium",
                    status="ERROR", resource_id="cluster",
                    status_extended=f"Evaluator for {cis_id} failed: {e}",
                    remediation=f"Check evaluator logs for CIS {cis_id}",
                    cis_id=cis_id,
                ))
                covered_cis_ids.add(cis_id)

        # ── Also count existing scanner checks that cover CIS controls ──
        # The k8s_scanner.py already covers many Section 5 controls
        SCANNER_CIS_MAPPING = {
            "k8s_pod_no_privileged": "5.2.2",
            "k8s_pod_no_host_pid": "5.2.3",
            "k8s_pod_no_host_ipc": "5.2.4",
            "k8s_pod_no_host_network": "5.2.5",
            "k8s_pod_no_privilege_escalation": "5.2.6",
            "k8s_pod_run_as_non_root": "5.2.7",
            "k8s_pod_capability_drop_all": "5.2.8",
            "k8s_pod_seccomp_profile": "5.6.2",
            "k8s_rbac_no_wildcard_cluster_admin": "5.1.1",
            "k8s_rbac_no_wildcard_verbs": "5.1.3",
            "k8s_rbac_limit_secrets_access": "5.1.2",
            "k8s_rbac_no_default_sa_token": "5.1.5",
            "k8s_namespace_network_policy": "5.3.2",
            "k8s_no_pods_in_default": "5.6.4",
            "k8s_secrets_encrypted_etcd": "1.2.27",
            "k8s_secrets_no_env_vars": "5.4.1",
            "k8s_admission_pod_security": "5.2.1",
            "k8s_api_audit_logging": "1.2.16",
            "k8s_api_tls_enabled": "1.2.24",
        }
        for scanner_check, cis_id in SCANNER_CIS_MAPPING.items():
            covered_cis_ids.add(cis_id)

        # ── Emit MANUAL for uncovered controls ──
        for cis_id, title, level, assessment_type, severity, service_area in KUBERNETES_CIS_CONTROLS:
            if cis_id in covered_cis_ids:
                continue
            results.append(build_result(
                check_id=f"k8s_cis_{cis_id.replace('.', '_')}",
                title=title,
                service=service_area, severity=severity,
                status="MANUAL", resource_id="cluster",
                status_extended=f"CIS {cis_id}: Requires manual verification — {title}",
                remediation=f"Review CIS Kubernetes Benchmark v1.12.0 control {cis_id}",
                cis_id=cis_id,
                assessment_type=assessment_type,
            ))

        logger.info(
            "K8s CIS v1.12.0: %d evaluators ran, %d CIS controls covered, "
            "%d MANUAL, %d total results",
            len(EVALUATOR_REGISTRY), len(covered_cis_ids),
            131 - len(covered_cis_ids), len(results),
        )
        return results

    def get_coverage_stats(self) -> dict:
        """Return evaluator coverage statistics."""
        scanner_checks = 19  # from existing k8s_scanner.py
        evaluator_count = len(EVALUATOR_REGISTRY)
        total_cis = len(KUBERNETES_CIS_CONTROLS)

        # Dedup: some CIS IDs covered by both evaluators and scanner
        unique_covered = set(EVALUATOR_REGISTRY.keys())
        scanner_cis = {
            "5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6", "5.2.7", "5.2.8",
            "5.6.2", "5.1.1", "5.1.2", "5.1.3", "5.1.5", "5.3.2", "5.6.4",
            "5.4.1", "5.2.1", "1.2.16", "1.2.24", "1.2.27",
        }
        unique_covered.update(scanner_cis)

        return {
            "total_cis_controls": total_cis,
            "evaluator_functions": evaluator_count,
            "scanner_checks": scanner_checks,
            "unique_cis_covered": len(unique_covered),
            "manual_only": total_cis - len(unique_covered),
            "automation_rate": round(len(unique_covered) / total_cis * 100, 1),
        }
