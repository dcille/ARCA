"""CIS Kubernetes v1.12.0 — Section 1.2 API Server, 1.3 Controller Manager, 1.4 Scheduler.

Evaluates control plane component flags by inspecting pod specs in kube-system.
30 controls in 1.2, 7 in 1.3, 2 in 1.4 = 39 controls total.
34 automated by CIS + 5 manual upgraded = 39 evaluators.

Path: scanner/providers/kubernetes/evaluators/section_1_control_plane.py
"""

from scanner.providers.kubernetes.evaluators.base import (
    register, build_result, has_flag, get_flag_value,
    flag_is_true, flag_is_false, flag_not_set,
    flag_includes, flag_excludes, flag_int_gte, K8sClientCache,
)


# ======================================================================
# 1.2 API Server (30 controls)
# ======================================================================

@register("1.2.1")
def eval_1_2_1(cache: K8sClientCache) -> list[dict]:
    """--anonymous-auth set to false. CIS: Manual → upgraded."""
    args = cache.api_server_args
    ok = flag_is_false(args, "--anonymous-auth")
    return [build_result("k8s_api_anonymous_auth", "API server anonymous-auth is disabled",
        "apiserver", "critical", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--anonymous-auth=false: {ok}", "Set --anonymous-auth=false on the API server",
        cis_id="1.2.1")]

@register("1.2.2")
def eval_1_2_2(cache: K8sClientCache) -> list[dict]:
    """--token-auth-file not set."""
    args = cache.api_server_args
    ok = flag_not_set(args, "--token-auth-file")
    return [build_result("k8s_api_no_token_auth_file", "API server does not use static token file",
        "apiserver", "critical", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--token-auth-file not set: {ok}", "Remove --token-auth-file; use OIDC or certificates",
        cis_id="1.2.2")]

@register("1.2.4")
def eval_1_2_4(cache: K8sClientCache) -> list[dict]:
    """--kubelet-client-certificate and --kubelet-client-key are set."""
    args = cache.api_server_args
    cert = has_flag(args, "--kubelet-client-certificate")
    key = has_flag(args, "--kubelet-client-key")
    ok = cert and key
    return [build_result("k8s_api_kubelet_client_cert", "API server uses kubelet client certs",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"kubelet-client-certificate: {cert}, kubelet-client-key: {key}",
        "Set --kubelet-client-certificate and --kubelet-client-key", cis_id="1.2.4")]

@register("1.2.5")
def eval_1_2_5(cache: K8sClientCache) -> list[dict]:
    """--kubelet-certificate-authority is set."""
    args = cache.api_server_args
    ok = has_flag(args, "--kubelet-certificate-authority")
    return [build_result("k8s_api_kubelet_ca", "API server kubelet CA is configured",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--kubelet-certificate-authority set: {ok}",
        "Set --kubelet-certificate-authority", cis_id="1.2.5")]

@register("1.2.6")
def eval_1_2_6(cache: K8sClientCache) -> list[dict]:
    """--authorization-mode not AlwaysAllow."""
    args = cache.api_server_args
    ok = flag_excludes(args, "--authorization-mode", "AlwaysAllow")
    return [build_result("k8s_api_no_always_allow", "API server authorization not AlwaysAllow",
        "apiserver", "critical", "PASS" if ok else "FAIL", "kube-apiserver",
        f"AlwaysAllow excluded: {ok}", "Remove AlwaysAllow from --authorization-mode",
        cis_id="1.2.6")]

@register("1.2.7")
def eval_1_2_7(cache: K8sClientCache) -> list[dict]:
    """--authorization-mode includes Node."""
    args = cache.api_server_args
    ok = flag_includes(args, "--authorization-mode", "Node")
    return [build_result("k8s_api_auth_mode_node", "API server authorization includes Node",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"Node in authorization-mode: {ok}", "Add Node to --authorization-mode",
        cis_id="1.2.7")]

@register("1.2.8")
def eval_1_2_8(cache: K8sClientCache) -> list[dict]:
    """--authorization-mode includes RBAC."""
    args = cache.api_server_args
    ok = flag_includes(args, "--authorization-mode", "RBAC")
    return [build_result("k8s_api_auth_mode_rbac", "API server authorization includes RBAC",
        "apiserver", "critical", "PASS" if ok else "FAIL", "kube-apiserver",
        f"RBAC in authorization-mode: {ok}", "Add RBAC to --authorization-mode",
        cis_id="1.2.8")]

@register("1.2.10")
def eval_1_2_10(cache: K8sClientCache) -> list[dict]:
    """AlwaysAdmit not in admission plugins."""
    args = cache.api_server_args
    ok = flag_excludes(args, "--enable-admission-plugins", "AlwaysAdmit")
    return [build_result("k8s_api_no_always_admit", "AlwaysAdmit admission plugin not enabled",
        "apiserver", "critical", "PASS" if ok else "FAIL", "kube-apiserver",
        f"AlwaysAdmit excluded: {ok}", "Remove AlwaysAdmit from --enable-admission-plugins",
        cis_id="1.2.10")]

@register("1.2.12")
def eval_1_2_12(cache: K8sClientCache) -> list[dict]:
    """ServiceAccount admission plugin set."""
    args = cache.api_server_args
    val = get_flag_value(args, "--disable-admission-plugins")
    ok = val is None or "ServiceAccount" not in val
    return [build_result("k8s_api_sa_admission", "ServiceAccount admission plugin enabled",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"ServiceAccount not disabled: {ok}",
        "Ensure ServiceAccount is not in --disable-admission-plugins", cis_id="1.2.12")]

@register("1.2.13")
def eval_1_2_13(cache: K8sClientCache) -> list[dict]:
    """NamespaceLifecycle admission plugin set."""
    args = cache.api_server_args
    val = get_flag_value(args, "--disable-admission-plugins")
    ok = val is None or "NamespaceLifecycle" not in val
    return [build_result("k8s_api_ns_lifecycle", "NamespaceLifecycle admission plugin enabled",
        "apiserver", "medium", "PASS" if ok else "FAIL", "kube-apiserver",
        f"NamespaceLifecycle not disabled: {ok}",
        "Ensure NamespaceLifecycle not in --disable-admission-plugins", cis_id="1.2.13")]

@register("1.2.14")
def eval_1_2_14(cache: K8sClientCache) -> list[dict]:
    """NodeRestriction admission plugin set."""
    args = cache.api_server_args
    ok = flag_includes(args, "--enable-admission-plugins", "NodeRestriction")
    return [build_result("k8s_api_node_restriction", "NodeRestriction admission plugin enabled",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"NodeRestriction enabled: {ok}",
        "Add NodeRestriction to --enable-admission-plugins", cis_id="1.2.14")]

@register("1.2.15")
def eval_1_2_15(cache: K8sClientCache) -> list[dict]:
    """--profiling false."""
    args = cache.api_server_args
    ok = flag_is_false(args, "--profiling")
    return [build_result("k8s_api_profiling_disabled", "API server profiling is disabled",
        "apiserver", "medium", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--profiling=false: {ok}", "Set --profiling=false", cis_id="1.2.15")]

@register("1.2.16")
def eval_1_2_16(cache: K8sClientCache) -> list[dict]:
    """--audit-log-path is set."""
    args = cache.api_server_args
    ok = has_flag(args, "--audit-log-path")
    return [build_result("k8s_api_audit_log_path", "API server audit log path is configured",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--audit-log-path set: {ok}", "Set --audit-log-path to a valid path",
        cis_id="1.2.16")]

@register("1.2.17")
def eval_1_2_17(cache: K8sClientCache) -> list[dict]:
    """--audit-log-maxage >= 30."""
    args = cache.api_server_args
    result = flag_int_gte(args, "--audit-log-maxage", 30)
    status = "PASS" if result else ("FAIL" if result is False else "FAIL")
    val = get_flag_value(args, "--audit-log-maxage") or "not set"
    return [build_result("k8s_api_audit_maxage", "API server audit log maxage >= 30 days",
        "apiserver", "medium", status, "kube-apiserver",
        f"--audit-log-maxage: {val}", "Set --audit-log-maxage=30 or higher",
        cis_id="1.2.17")]

@register("1.2.18")
def eval_1_2_18(cache: K8sClientCache) -> list[dict]:
    """--audit-log-maxbackup >= 10."""
    args = cache.api_server_args
    result = flag_int_gte(args, "--audit-log-maxbackup", 10)
    status = "PASS" if result else "FAIL"
    val = get_flag_value(args, "--audit-log-maxbackup") or "not set"
    return [build_result("k8s_api_audit_maxbackup", "API server audit log maxbackup >= 10",
        "apiserver", "medium", status, "kube-apiserver",
        f"--audit-log-maxbackup: {val}", "Set --audit-log-maxbackup=10 or higher",
        cis_id="1.2.18")]

@register("1.2.19")
def eval_1_2_19(cache: K8sClientCache) -> list[dict]:
    """--audit-log-maxsize >= 100."""
    args = cache.api_server_args
    result = flag_int_gte(args, "--audit-log-maxsize", 100)
    status = "PASS" if result else "FAIL"
    val = get_flag_value(args, "--audit-log-maxsize") or "not set"
    return [build_result("k8s_api_audit_maxsize", "API server audit log maxsize >= 100MB",
        "apiserver", "medium", status, "kube-apiserver",
        f"--audit-log-maxsize: {val}", "Set --audit-log-maxsize=100 or higher",
        cis_id="1.2.19")]

@register("1.2.21")
def eval_1_2_21(cache: K8sClientCache) -> list[dict]:
    """--service-account-lookup true."""
    args = cache.api_server_args
    # Default is true, so only FAIL if explicitly set to false
    ok = not flag_is_false(args, "--service-account-lookup")
    return [build_result("k8s_api_sa_lookup", "API server service-account-lookup enabled",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--service-account-lookup not false: {ok}",
        "Set --service-account-lookup=true or remove the flag (default is true)",
        cis_id="1.2.21")]

@register("1.2.22")
def eval_1_2_22(cache: K8sClientCache) -> list[dict]:
    """--service-account-key-file is set."""
    args = cache.api_server_args
    ok = has_flag(args, "--service-account-key-file")
    return [build_result("k8s_api_sa_key_file", "API server SA key file configured",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--service-account-key-file set: {ok}",
        "Set --service-account-key-file", cis_id="1.2.22")]

@register("1.2.23")
def eval_1_2_23(cache: K8sClientCache) -> list[dict]:
    """--etcd-certfile and --etcd-keyfile set."""
    args = cache.api_server_args
    cert = has_flag(args, "--etcd-certfile")
    key = has_flag(args, "--etcd-keyfile")
    ok = cert and key
    return [build_result("k8s_api_etcd_certs", "API server uses etcd client certs",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"etcd-certfile: {cert}, etcd-keyfile: {key}",
        "Set --etcd-certfile and --etcd-keyfile", cis_id="1.2.23")]

@register("1.2.24")
def eval_1_2_24(cache: K8sClientCache) -> list[dict]:
    """--tls-cert-file and --tls-private-key-file set."""
    args = cache.api_server_args
    cert = has_flag(args, "--tls-cert-file")
    key = has_flag(args, "--tls-private-key-file")
    ok = cert and key
    return [build_result("k8s_api_tls_certs", "API server TLS certificates configured",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"tls-cert-file: {cert}, tls-private-key-file: {key}",
        "Set --tls-cert-file and --tls-private-key-file", cis_id="1.2.24")]

@register("1.2.25")
def eval_1_2_25(cache: K8sClientCache) -> list[dict]:
    """--client-ca-file is set."""
    args = cache.api_server_args
    ok = has_flag(args, "--client-ca-file")
    return [build_result("k8s_api_client_ca", "API server client CA file configured",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--client-ca-file set: {ok}", "Set --client-ca-file", cis_id="1.2.25")]

@register("1.2.26")
def eval_1_2_26(cache: K8sClientCache) -> list[dict]:
    """--etcd-cafile is set."""
    args = cache.api_server_args
    ok = has_flag(args, "--etcd-cafile")
    return [build_result("k8s_api_etcd_ca", "API server etcd CA file configured",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--etcd-cafile set: {ok}", "Set --etcd-cafile", cis_id="1.2.26")]

@register("1.2.27")
def eval_1_2_27(cache: K8sClientCache) -> list[dict]:
    """--encryption-provider-config is set. CIS: Manual → upgraded."""
    args = cache.api_server_args
    ok = has_flag(args, "--encryption-provider-config")
    return [build_result("k8s_api_encryption_config", "Encryption provider config is set",
        "apiserver", "high", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--encryption-provider-config set: {ok}",
        "Set --encryption-provider-config with EncryptionConfiguration", cis_id="1.2.27")]

@register("1.2.29")
def eval_1_2_29(cache: K8sClientCache) -> list[dict]:
    """API server uses strong ciphers. CIS: Manual → upgraded."""
    args = cache.api_server_args
    STRONG = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
              "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
              "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
              "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}
    val = get_flag_value(args, "--tls-cipher-suites")
    if val:
        configured = set(val.split(","))
        weak = configured - STRONG
        ok = not weak
        ext = f"Weak ciphers: {', '.join(weak)}" if weak else "All strong"
    else:
        ok = False
        ext = "--tls-cipher-suites not set; may include weak defaults"
    return [build_result("k8s_api_strong_ciphers", "API server uses strong ciphers only",
        "apiserver", "medium", "PASS" if ok else "FAIL", "kube-apiserver",
        ext, "Set --tls-cipher-suites with strong TLS 1.2+ ciphers only",
        cis_id="1.2.29")]

@register("1.2.30")
def eval_1_2_30(cache: K8sClientCache) -> list[dict]:
    """--service-account-extend-token-expiration false. NEW in v1.12."""
    args = cache.api_server_args
    ok = flag_is_false(args, "--service-account-extend-token-expiration")
    return [build_result("k8s_api_sa_token_no_extend", "SA token extension disabled",
        "apiserver", "medium", "PASS" if ok else "FAIL", "kube-apiserver",
        f"--service-account-extend-token-expiration=false: {ok}",
        "Set --service-account-extend-token-expiration=false", cis_id="1.2.30")]


# ======================================================================
# 1.3 Controller Manager (7 controls)
# ======================================================================

@register("1.3.2")
def eval_1_3_2(cache: K8sClientCache) -> list[dict]:
    """--profiling false."""
    args = cache.controller_manager_args
    ok = flag_is_false(args, "--profiling")
    return [build_result("k8s_cm_profiling_disabled", "Controller manager profiling disabled",
        "controller-manager", "medium", "PASS" if ok else "FAIL",
        "kube-controller-manager", f"--profiling=false: {ok}",
        "Set --profiling=false on controller manager", cis_id="1.3.2")]

@register("1.3.3")
def eval_1_3_3(cache: K8sClientCache) -> list[dict]:
    """--use-service-account-credentials true."""
    args = cache.controller_manager_args
    ok = flag_is_true(args, "--use-service-account-credentials")
    return [build_result("k8s_cm_sa_credentials", "Controller manager uses SA credentials",
        "controller-manager", "high", "PASS" if ok else "FAIL",
        "kube-controller-manager", f"--use-service-account-credentials=true: {ok}",
        "Set --use-service-account-credentials=true", cis_id="1.3.3")]

@register("1.3.4")
def eval_1_3_4(cache: K8sClientCache) -> list[dict]:
    """--service-account-private-key-file set."""
    args = cache.controller_manager_args
    ok = has_flag(args, "--service-account-private-key-file")
    return [build_result("k8s_cm_sa_private_key", "Controller manager SA private key set",
        "controller-manager", "high", "PASS" if ok else "FAIL",
        "kube-controller-manager", f"--service-account-private-key-file set: {ok}",
        "Set --service-account-private-key-file", cis_id="1.3.4")]

@register("1.3.5")
def eval_1_3_5(cache: K8sClientCache) -> list[dict]:
    """--root-ca-file set."""
    args = cache.controller_manager_args
    ok = has_flag(args, "--root-ca-file")
    return [build_result("k8s_cm_root_ca", "Controller manager root CA file set",
        "controller-manager", "high", "PASS" if ok else "FAIL",
        "kube-controller-manager", f"--root-ca-file set: {ok}",
        "Set --root-ca-file", cis_id="1.3.5")]

@register("1.3.6")
def eval_1_3_6(cache: K8sClientCache) -> list[dict]:
    """RotateKubeletServerCertificate true."""
    args = cache.controller_manager_args
    ok = flag_is_true(args, "--feature-gates") and "RotateKubeletServerCertificate=true" in " ".join(args)
    # Also check if it's a standalone flag
    if not ok:
        ok = any("RotateKubeletServerCertificate=true" in a for a in args)
    return [build_result("k8s_cm_rotate_kubelet_cert", "RotateKubeletServerCertificate enabled",
        "controller-manager", "medium", "PASS" if ok else "FAIL",
        "kube-controller-manager", f"RotateKubeletServerCertificate=true: {ok}",
        "Set RotateKubeletServerCertificate=true in --feature-gates", cis_id="1.3.6")]

@register("1.3.7")
def eval_1_3_7(cache: K8sClientCache) -> list[dict]:
    """--bind-address 127.0.0.1."""
    args = cache.controller_manager_args
    val = get_flag_value(args, "--bind-address")
    ok = val == "127.0.0.1" if val else False
    return [build_result("k8s_cm_bind_localhost", "Controller manager bound to localhost",
        "controller-manager", "high", "PASS" if ok else "FAIL",
        "kube-controller-manager", f"--bind-address: {val or 'not set'}",
        "Set --bind-address=127.0.0.1", cis_id="1.3.7")]


# ======================================================================
# 1.4 Scheduler (2 controls)
# ======================================================================

@register("1.4.1")
def eval_1_4_1(cache: K8sClientCache) -> list[dict]:
    """--profiling false."""
    args = cache.scheduler_args
    ok = flag_is_false(args, "--profiling")
    return [build_result("k8s_sched_profiling_disabled", "Scheduler profiling disabled",
        "scheduler", "medium", "PASS" if ok else "FAIL", "kube-scheduler",
        f"--profiling=false: {ok}", "Set --profiling=false on scheduler",
        cis_id="1.4.1")]

@register("1.4.2")
def eval_1_4_2(cache: K8sClientCache) -> list[dict]:
    """--bind-address 127.0.0.1."""
    args = cache.scheduler_args
    val = get_flag_value(args, "--bind-address")
    ok = val == "127.0.0.1" if val else False
    return [build_result("k8s_sched_bind_localhost", "Scheduler bound to localhost",
        "scheduler", "high", "PASS" if ok else "FAIL", "kube-scheduler",
        f"--bind-address: {val or 'not set'}", "Set --bind-address=127.0.0.1",
        cis_id="1.4.2")]
