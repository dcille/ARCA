"""CIS Kubernetes v1.12.0 — Sections 2, 3, 4 evaluators.

Section 2: etcd (7 controls, 6 automated)
Section 3: Control Plane Configuration (5 controls, 0 CIS-auto → 1 upgraded)
Section 4: Worker Nodes (25 controls, 11 CIS-auto + 2 upgraded)

Path: scanner/providers/kubernetes/evaluators/section_2_3_4.py
"""

from scanner.providers.kubernetes.evaluators.base import (
    register, build_result, has_flag, get_flag_value,
    flag_is_true, flag_is_false, flag_not_set,
    flag_int_gte, K8sClientCache,
)
import logging

logger = logging.getLogger(__name__)


# ======================================================================
# Section 2: etcd (7 controls)
# ======================================================================

@register("2.1")
def eval_2_1(cache: K8sClientCache) -> list[dict]:
    """--cert-file and --key-file are set."""
    args = cache.etcd_args
    cert = has_flag(args, "--cert-file")
    key = has_flag(args, "--key-file")
    ok = cert and key
    return [build_result("k8s_etcd_cert_key", "etcd uses TLS cert and key",
        "etcd", "high", "PASS" if ok else "FAIL", "etcd",
        f"cert-file: {cert}, key-file: {key}", "Set --cert-file and --key-file on etcd",
        cis_id="2.1")]

@register("2.2")
def eval_2_2(cache: K8sClientCache) -> list[dict]:
    """--client-cert-auth true."""
    args = cache.etcd_args
    ok = flag_is_true(args, "--client-cert-auth")
    return [build_result("k8s_etcd_client_cert_auth", "etcd requires client cert auth",
        "etcd", "high", "PASS" if ok else "FAIL", "etcd",
        f"--client-cert-auth=true: {ok}", "Set --client-cert-auth=true",
        cis_id="2.2")]

@register("2.3")
def eval_2_3(cache: K8sClientCache) -> list[dict]:
    """--auto-tls not true."""
    args = cache.etcd_args
    ok = not flag_is_true(args, "--auto-tls")
    return [build_result("k8s_etcd_no_auto_tls", "etcd auto-tls is disabled",
        "etcd", "high", "PASS" if ok else "FAIL", "etcd",
        f"--auto-tls not true: {ok}", "Do not set --auto-tls=true; use proper certificates",
        cis_id="2.3")]

@register("2.4")
def eval_2_4(cache: K8sClientCache) -> list[dict]:
    """--peer-cert-file and --peer-key-file set."""
    args = cache.etcd_args
    cert = has_flag(args, "--peer-cert-file")
    key = has_flag(args, "--peer-key-file")
    ok = cert and key
    return [build_result("k8s_etcd_peer_certs", "etcd uses peer TLS certs",
        "etcd", "high", "PASS" if ok else "FAIL", "etcd",
        f"peer-cert-file: {cert}, peer-key-file: {key}",
        "Set --peer-cert-file and --peer-key-file", cis_id="2.4")]

@register("2.5")
def eval_2_5(cache: K8sClientCache) -> list[dict]:
    """--peer-client-cert-auth true."""
    args = cache.etcd_args
    ok = flag_is_true(args, "--peer-client-cert-auth")
    return [build_result("k8s_etcd_peer_client_auth", "etcd requires peer client cert auth",
        "etcd", "high", "PASS" if ok else "FAIL", "etcd",
        f"--peer-client-cert-auth=true: {ok}", "Set --peer-client-cert-auth=true",
        cis_id="2.5")]

@register("2.6")
def eval_2_6(cache: K8sClientCache) -> list[dict]:
    """--peer-auto-tls not true."""
    args = cache.etcd_args
    ok = not flag_is_true(args, "--peer-auto-tls")
    return [build_result("k8s_etcd_no_peer_auto_tls", "etcd peer auto-tls disabled",
        "etcd", "high", "PASS" if ok else "FAIL", "etcd",
        f"--peer-auto-tls not true: {ok}", "Do not set --peer-auto-tls=true",
        cis_id="2.6")]


# ======================================================================
# Section 3: Control Plane Configuration (5 controls — all manual)
# 3.2.1 upgraded to automated
# ======================================================================

@register("3.2.1")
def eval_3_2_1(cache: K8sClientCache) -> list[dict]:
    """Minimal audit policy created. CIS: Manual → upgraded."""
    args = cache.api_server_args
    ok = has_flag(args, "--audit-policy-file")
    return [build_result("k8s_audit_policy_exists", "Audit policy file is configured",
        "control-plane-config", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--audit-policy-file set: {ok}",
        "Create an audit policy YAML and set --audit-policy-file on API server",
        cis_id="3.2.1")]


# ======================================================================
# Section 4: Worker Nodes
# 4.2.1-4.2.3, 4.2.6, 4.2.10 automated
# 4.2.14, 4.3.1 upgraded
# ======================================================================

@register("4.2.1")
def eval_4_2_1(cache: K8sClientCache) -> list[dict]:
    """Kubelet --anonymous-auth false."""
    results = []
    try:
        nodes = cache.v1.list_node()
        for node in nodes.items:
            node_name = node.metadata.name
            try:
                proxy_path = f"/api/v1/nodes/{node_name}/proxy/configz"
                config = cache.v1.api_client.call_api(
                    proxy_path, "GET", response_type="object",
                    _return_http_data_only=True)
                kc = config.get("kubeletconfig", {}) if isinstance(config, dict) else {}
                auth = kc.get("authentication", {}).get("anonymous", {})
                enabled = auth.get("enabled", True)
                ok = not enabled
            except Exception:
                ok = None
            status = "PASS" if ok else ("FAIL" if ok is False else "MANUAL")
            results.append(build_result("k8s_kubelet_anonymous_auth",
                "Kubelet anonymous auth disabled", "kubelet", "critical",
                status, node_name,
                f"Node {node_name}: anonymous auth enabled={not ok if ok is not None else 'unknown'}",
                "Set authentication.anonymous.enabled=false in kubelet config",
                cis_id="4.2.1"))
    except Exception as e:
        logger.warning("4.2.1 check failed: %s", e)
    return results

@register("4.2.2")
def eval_4_2_2(cache: K8sClientCache) -> list[dict]:
    """Kubelet --authorization-mode not AlwaysAllow."""
    results = []
    try:
        nodes = cache.v1.list_node()
        for node in nodes.items:
            node_name = node.metadata.name
            try:
                proxy_path = f"/api/v1/nodes/{node_name}/proxy/configz"
                config = cache.v1.api_client.call_api(
                    proxy_path, "GET", response_type="object",
                    _return_http_data_only=True)
                kc = config.get("kubeletconfig", {}) if isinstance(config, dict) else {}
                mode = kc.get("authorization", {}).get("mode", "")
                ok = mode != "AlwaysAllow"
            except Exception:
                ok = None
            status = "PASS" if ok else ("FAIL" if ok is False else "MANUAL")
            results.append(build_result("k8s_kubelet_auth_mode",
                "Kubelet authorization not AlwaysAllow", "kubelet", "critical",
                status, node_name,
                f"Node {node_name}: authorization mode not AlwaysAllow: {ok}",
                "Set authorization.mode=Webhook in kubelet config", cis_id="4.2.2"))
    except Exception as e:
        logger.warning("4.2.2 check failed: %s", e)
    return results

@register("4.2.6")
def eval_4_2_6(cache: K8sClientCache) -> list[dict]:
    """--make-iptables-util-chains true."""
    results = []
    try:
        nodes = cache.v1.list_node()
        for node in nodes.items:
            node_name = node.metadata.name
            try:
                proxy_path = f"/api/v1/nodes/{node_name}/proxy/configz"
                config = cache.v1.api_client.call_api(
                    proxy_path, "GET", response_type="object",
                    _return_http_data_only=True)
                kc = config.get("kubeletconfig", {}) if isinstance(config, dict) else {}
                ok = kc.get("makeIPTablesUtilChains", True)  # default is true
            except Exception:
                ok = None
            status = "PASS" if ok else ("FAIL" if ok is False else "MANUAL")
            results.append(build_result("k8s_kubelet_iptables_chains",
                "Kubelet makeIPTablesUtilChains enabled", "kubelet", "medium",
                status, node_name,
                f"Node {node_name}: makeIPTablesUtilChains={ok}",
                "Set makeIPTablesUtilChains=true in kubelet config", cis_id="4.2.6"))
    except Exception as e:
        logger.warning("4.2.6 check failed: %s", e)
    return results

@register("4.2.10")
def eval_4_2_10(cache: K8sClientCache) -> list[dict]:
    """--rotate-certificates not false."""
    results = []
    try:
        nodes = cache.v1.list_node()
        for node in nodes.items:
            node_name = node.metadata.name
            try:
                proxy_path = f"/api/v1/nodes/{node_name}/proxy/configz"
                config = cache.v1.api_client.call_api(
                    proxy_path, "GET", response_type="object",
                    _return_http_data_only=True)
                kc = config.get("kubeletconfig", {}) if isinstance(config, dict) else {}
                ok = kc.get("rotateCertificates", True)  # default is true
            except Exception:
                ok = None
            status = "PASS" if ok else ("FAIL" if ok is False else "MANUAL")
            results.append(build_result("k8s_kubelet_rotate_certs",
                "Kubelet certificate rotation enabled", "kubelet", "high",
                status, node_name,
                f"Node {node_name}: rotateCertificates={ok}",
                "Set rotateCertificates=true in kubelet config", cis_id="4.2.10"))
    except Exception as e:
        logger.warning("4.2.10 check failed: %s", e)
    return results

@register("4.2.14")
def eval_4_2_14(cache: K8sClientCache) -> list[dict]:
    """--seccomp-default true. NEW in v1.12. CIS: Manual → upgraded."""
    results = []
    try:
        nodes = cache.v1.list_node()
        for node in nodes.items:
            node_name = node.metadata.name
            try:
                proxy_path = f"/api/v1/nodes/{node_name}/proxy/configz"
                config = cache.v1.api_client.call_api(
                    proxy_path, "GET", response_type="object",
                    _return_http_data_only=True)
                kc = config.get("kubeletconfig", {}) if isinstance(config, dict) else {}
                ok = kc.get("seccompDefault", False)
            except Exception:
                ok = None
            status = "PASS" if ok else ("FAIL" if ok is False else "MANUAL")
            results.append(build_result("k8s_kubelet_seccomp_default",
                "Kubelet seccomp-default enabled", "kubelet", "medium",
                status, node_name,
                f"Node {node_name}: seccompDefault={ok}",
                "Set seccompDefault=true in kubelet config", cis_id="4.2.14"))
    except Exception as e:
        logger.warning("4.2.14 check failed: %s", e)
    return results

@register("4.3.1")
def eval_4_3_1(cache: K8sClientCache) -> list[dict]:
    """kube-proxy metrics bound to localhost. NEW section. CIS: Manual → upgraded."""
    results = []
    try:
        try:
            cm = cache.v1.read_namespaced_config_map("kube-proxy", "kube-system")
            config_data = cm.data.get("config.conf", cm.data.get("kubeconfig.conf", ""))
            # Check metricsBindAddress
            ok = ("metricsBindAddress: 127.0.0.1" in config_data or
                  "metricsBindAddress: \"127.0.0.1" in config_data or
                  "metricsBindAddress: localhost" in config_data)
            if "metricsBindAddress: \"0.0.0.0" in config_data or \
               "metricsBindAddress: 0.0.0.0" in config_data:
                ok = False
            results.append(build_result("k8s_kube_proxy_metrics_localhost",
                "kube-proxy metrics bound to localhost", "kube-proxy", "medium",
                "PASS" if ok else "FAIL", "kube-proxy-config",
                f"metricsBindAddress bound to localhost: {ok}",
                "Set metricsBindAddress to 127.0.0.1:10249 in kube-proxy config",
                cis_id="4.3.1"))
        except Exception:
            results.append(build_result("k8s_kube_proxy_metrics_localhost",
                "kube-proxy metrics bound to localhost", "kube-proxy", "medium",
                "MANUAL", "kube-proxy-config",
                "Could not read kube-proxy configmap; verify metricsBindAddress manually",
                "Set metricsBindAddress to 127.0.0.1:10249", cis_id="4.3.1"))
    except Exception as e:
        logger.warning("4.3.1 check failed: %s", e)
    return results
