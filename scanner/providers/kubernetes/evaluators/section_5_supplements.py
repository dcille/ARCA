"""CIS Kubernetes v1.12.0 — Section 5 supplements.

Upgrades manual controls to automated using the K8s RBAC and Pod APIs.
The existing k8s_scanner.py already covers ~20 Section 5 controls via
pod/RBAC/network checks. These supplements add 7 more.

Path: scanner/providers/kubernetes/evaluators/section_5_supplements.py
"""

from scanner.providers.kubernetes.evaluators.base import (
    register, build_result, K8sClientCache,
)
import logging

logger = logging.getLogger(__name__)


@register("5.1.4")
def eval_5_1_4(cache: K8sClientCache) -> list[dict]:
    """Minimize access to create pods. CIS: Manual → upgraded."""
    results = []
    try:
        cluster_roles = cache.rbac.list_cluster_role()
        for cr in cluster_roles.items:
            name = cr.metadata.name
            if name.startswith("system:"):
                continue
            for rule in cr.rules or []:
                resources = rule.resources or []
                verbs = rule.verbs or []
                if ("pods" in resources or "*" in resources) and \
                   ("create" in verbs or "*" in verbs):
                    results.append(build_result("k8s_rbac_pod_create_limited",
                        "ClusterRole does not grant broad pod create", "rbac", "high",
                        "FAIL", name,
                        f"ClusterRole {name} grants pod create ({', '.join(verbs)} on {', '.join(resources)})",
                        "Restrict pod creation to specific roles and namespaces",
                        cis_id="5.1.4"))
                    break
    except Exception as e:
        logger.warning("5.1.4 check failed: %s", e)
    return results


@register("5.1.6")
def eval_5_1_6(cache: K8sClientCache) -> list[dict]:
    """SA tokens only mounted where necessary. CIS: Manual → upgraded."""
    results = []
    try:
        pods = cache.v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            ns = pod.metadata.namespace
            if ns.startswith("kube-"):
                continue
            name = pod.metadata.name
            auto_mount = pod.spec.automount_service_account_token
            if auto_mount is not False:
                results.append(build_result("k8s_sa_token_mount_needed",
                    "Pod SA token auto-mount is justified", "pods", "high",
                    "FAIL", f"{ns}/{name}",
                    f"Pod {ns}/{name} auto-mounts SA token (automountServiceAccountToken not false)",
                    "Set automountServiceAccountToken: false on pods not needing API access",
                    cis_id="5.1.6"))
    except Exception as e:
        logger.warning("5.1.6 check failed: %s", e)
    return results


@register("5.1.7")
def eval_5_1_7(cache: K8sClientCache) -> list[dict]:
    """Avoid use of system:masters group. CIS: Manual → upgraded."""
    results = []
    try:
        crbs = cache.rbac.list_cluster_role_binding()
        for crb in crbs.items:
            if crb.role_ref.name != "cluster-admin":
                continue
            for subject in crb.subjects or []:
                if subject.kind == "Group" and subject.name == "system:masters":
                    # This is the default binding, skip
                    if crb.metadata.name == "cluster-admin":
                        continue
                    results.append(build_result("k8s_rbac_no_system_masters",
                        "system:masters group not used in custom bindings", "rbac",
                        "critical", "FAIL", crb.metadata.name,
                        f"ClusterRoleBinding {crb.metadata.name} binds cluster-admin to system:masters",
                        "Remove system:masters group bindings; use specific user/group bindings",
                        cis_id="5.1.7"))
    except Exception as e:
        logger.warning("5.1.7 check failed: %s", e)
    return results


@register("5.1.8")
def eval_5_1_8(cache: K8sClientCache) -> list[dict]:
    """Limit Bind, Impersonate, Escalate permissions. CIS: Manual → upgraded."""
    results = []
    DANGEROUS_VERBS = {"bind", "impersonate", "escalate"}
    try:
        cluster_roles = cache.rbac.list_cluster_role()
        for cr in cluster_roles.items:
            name = cr.metadata.name
            if name.startswith("system:"):
                continue
            for rule in cr.rules or []:
                verbs = set(v.lower() for v in (rule.verbs or []))
                dangerous = verbs & DANGEROUS_VERBS
                if dangerous or "*" in verbs:
                    resources = rule.resources or []
                    results.append(build_result("k8s_rbac_no_escalate_perms",
                        "ClusterRole does not grant bind/impersonate/escalate",
                        "rbac", "critical", "FAIL", name,
                        f"ClusterRole {name} grants {', '.join(dangerous or ['*'])} on {', '.join(resources)}",
                        "Remove bind, impersonate, and escalate verbs from non-system ClusterRoles",
                        cis_id="5.1.8"))
                    break
    except Exception as e:
        logger.warning("5.1.8 check failed: %s", e)
    return results


@register("5.2.10")
def eval_5_2_10(cache: K8sClientCache) -> list[dict]:
    """Minimize Windows HostProcess containers. CIS: Manual → upgraded."""
    results = []
    try:
        pods = cache.v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            ns = pod.metadata.namespace
            if ns.startswith("kube-"):
                continue
            name = pod.metadata.name
            for container in pod.spec.containers or []:
                sc = container.security_context
                if sc and hasattr(sc, 'windows_options') and sc.windows_options:
                    if sc.windows_options.host_process:
                        results.append(build_result("k8s_pod_no_windows_host_process",
                            "Container does not use Windows HostProcess", "pods",
                            "high", "FAIL", f"{ns}/{name}/{container.name}",
                            f"Container {container.name} uses Windows HostProcess",
                            "Remove windowsOptions.hostProcess from container securityContext",
                            cis_id="5.2.10"))
    except Exception as e:
        logger.warning("5.2.10 check failed: %s", e)
    return results


@register("5.2.11")
def eval_5_2_11(cache: K8sClientCache) -> list[dict]:
    """Minimize HostPath volumes. CIS: Manual → upgraded."""
    results = []
    try:
        pods = cache.v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            ns = pod.metadata.namespace
            if ns.startswith("kube-"):
                continue
            name = pod.metadata.name
            for vol in pod.spec.volumes or []:
                if vol.host_path:
                    results.append(build_result("k8s_pod_no_host_path",
                        "Pod does not use HostPath volumes", "pods", "high",
                        "FAIL", f"{ns}/{name}",
                        f"Pod {ns}/{name} uses HostPath volume: {vol.host_path.path}",
                        "Replace HostPath volumes with PersistentVolumeClaims",
                        cis_id="5.2.11"))
                    break
    except Exception as e:
        logger.warning("5.2.11 check failed: %s", e)
    return results


@register("5.2.12")
def eval_5_2_12(cache: K8sClientCache) -> list[dict]:
    """Minimize containers which use HostPorts. NEW in v1.12. CIS: Manual → upgraded."""
    results = []
    try:
        pods = cache.v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            ns = pod.metadata.namespace
            if ns.startswith("kube-"):
                continue
            name = pod.metadata.name
            for container in pod.spec.containers or []:
                for port in container.ports or []:
                    if port.host_port and port.host_port > 0:
                        results.append(build_result("k8s_pod_no_host_ports",
                            "Container does not use HostPorts", "pods", "medium",
                            "FAIL", f"{ns}/{name}/{container.name}",
                            f"Container {container.name} uses hostPort {port.host_port}",
                            "Remove hostPort; use Services for port exposure",
                            cis_id="5.2.12"))
                        break
    except Exception as e:
        logger.warning("5.2.12 check failed: %s", e)
    return results


@register("5.5.1")
def eval_5_5_1(cache: K8sClientCache) -> list[dict]:
    """ImagePolicyWebhook admission controller. NEW section. CIS: Manual → upgraded."""
    args = cache.api_server_args
    ok = any("ImagePolicyWebhook" in a for a in args)
    return [build_result("k8s_image_policy_webhook",
        "ImagePolicyWebhook admission controller configured", "apiserver", "medium",
        "PASS" if ok else "FAIL", "kube-apiserver",
        f"ImagePolicyWebhook in admission plugins: {ok}",
        "Add ImagePolicyWebhook to --enable-admission-plugins", cis_id="5.5.1")]
