"""Kubernetes Security Scanner — comprehensive CIS K8s Benchmark-aligned checks.

Implements 30+ security checks following CIS Kubernetes Benchmark v1.8, NIST 800-53, and CCM v4.1.
Provides complete CIS Kubernetes Benchmark v1.9.0 coverage by emitting MANUAL results for any
controls not covered by automated checks.
"""
import logging

from scanner.cis_controls.kubernetes_cis_controls import KUBERNETES_CIS_CONTROLS
from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)

COMPLIANCE = ["CIS-K8s-1.8", "NIST-800-53", "CCM-4.1"]


class K8sScanner:
    """Kubernetes cluster security scanner with comprehensive CIS-aligned checks."""

    def __init__(self, credentials: dict):
        self.credentials = credentials

    def _get_client(self):
        from kubernetes import client, config
        kubeconfig = self.credentials.get("kubeconfig")
        if kubeconfig:
            import tempfile, os, yaml
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
                if isinstance(kubeconfig, dict):
                    yaml.dump(kubeconfig, f)
                else:
                    f.write(kubeconfig)
                config_path = f.name
            config.load_kube_config(config_path)
            os.unlink(config_path)
        else:
            config.load_incluster_config()
        return client

    def scan(self) -> list[dict]:
        """Run all Kubernetes security checks."""
        results = []
        try:
            k8s_client = self._get_client()
            results.extend(self._check_pods(k8s_client))
            results.extend(self._check_rbac(k8s_client))
            results.extend(self._check_network_policies(k8s_client))
            results.extend(self._check_namespaces(k8s_client))
            results.extend(self._check_secrets(k8s_client))
            results.extend(self._check_services(k8s_client))
            results.extend(self._check_api_server(k8s_client))
            results.extend(self._check_admission(k8s_client))
        except Exception as e:
            logger.error(f"Kubernetes scan failed: {e}")
        return results

    # ── helpers ──────────────────────────────────────────────────────────

    def _pod_result(self, check_id, title, severity, status, resource_id,
                    resource_name, status_extended, remediation):
        return CheckResult(
            check_id=check_id, check_title=title,
            service="pods", severity=severity, status=status,
            resource_id=resource_id, resource_name=resource_name,
            status_extended=status_extended, remediation=remediation,
            compliance_frameworks=COMPLIANCE,
        ).to_dict()

    # ── Pod checks ──────────────────────────────────────────────────────

    def _check_pods(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            pods = v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                name = pod.metadata.name
                ns = pod.metadata.namespace
                spec = pod.spec

                # Host-level checks (per-pod, not per-container)
                # k8s_pod_no_host_network
                host_net = spec.host_network or False
                results.append(self._pod_result(
                    "k8s_pod_no_host_network",
                    "Pod does not use host network",
                    "high", "FAIL" if host_net else "PASS",
                    f"{ns}/{name}", name,
                    f"Pod {ns}/{name} hostNetwork: {host_net}",
                    "Set spec.hostNetwork to false",
                ))

                # k8s_pod_no_host_pid
                host_pid = spec.host_pid or False
                results.append(self._pod_result(
                    "k8s_pod_no_host_pid",
                    "Pod does not use host PID namespace",
                    "high", "FAIL" if host_pid else "PASS",
                    f"{ns}/{name}", name,
                    f"Pod {ns}/{name} hostPID: {host_pid}",
                    "Set spec.hostPID to false",
                ))

                # k8s_pod_no_host_ipc
                host_ipc = spec.host_ipc or False
                results.append(self._pod_result(
                    "k8s_pod_no_host_ipc",
                    "Pod does not use host IPC namespace",
                    "high", "FAIL" if host_ipc else "PASS",
                    f"{ns}/{name}", name,
                    f"Pod {ns}/{name} hostIPC: {host_ipc}",
                    "Set spec.hostIPC to false",
                ))

                for container in spec.containers or []:
                    sc = container.security_context
                    rid = f"{ns}/{name}/{container.name}"
                    cname = container.name

                    # k8s_pod_no_privileged
                    if sc and sc.privileged:
                        results.append(self._pod_result(
                            "k8s_pod_no_privileged",
                            "Container is not running as privileged",
                            "high", "FAIL", rid, cname,
                            f"Container {cname} in pod {ns}/{name} runs as privileged",
                            "Set securityContext.privileged to false",
                        ))

                    # k8s_pod_run_as_non_root
                    run_as_root = not sc or not sc.run_as_non_root
                    results.append(self._pod_result(
                        "k8s_pod_run_as_non_root",
                        "Container runs as non-root user",
                        "medium", "FAIL" if run_as_root else "PASS", rid, cname,
                        f"Container {cname} runAsNonRoot: {not run_as_root}",
                        "Set securityContext.runAsNonRoot to true",
                    ))

                    # k8s_pod_readonly_rootfs
                    read_only = sc and sc.read_only_root_filesystem
                    results.append(self._pod_result(
                        "k8s_pod_readonly_rootfs",
                        "Container has read-only root filesystem",
                        "low", "PASS" if read_only else "FAIL", rid, cname,
                        f"Container {cname} readOnlyRootFilesystem: {read_only}",
                        "Set securityContext.readOnlyRootFilesystem to true",
                    ))

                    # k8s_pod_resource_limits
                    has_limits = container.resources and container.resources.limits
                    results.append(self._pod_result(
                        "k8s_pod_resource_limits",
                        "Container has resource limits",
                        "medium", "PASS" if has_limits else "FAIL", rid, cname,
                        f"Container {cname} has resource limits: {bool(has_limits)}",
                        "Set CPU and memory limits for the container",
                    ))

                    # k8s_pod_no_privilege_escalation
                    no_escalation = sc and sc.allow_privilege_escalation is False
                    results.append(self._pod_result(
                        "k8s_pod_no_privilege_escalation",
                        "Container does not allow privilege escalation",
                        "high", "PASS" if no_escalation else "FAIL", rid, cname,
                        f"Container {cname} allowPrivilegeEscalation: {not no_escalation}",
                        "Set securityContext.allowPrivilegeEscalation to false",
                    ))

                    # k8s_pod_capability_drop_all
                    caps = sc.capabilities if sc else None
                    drops_all = False
                    if caps and caps.drop:
                        drop_lower = [c.lower() for c in caps.drop]
                        drops_all = "all" in drop_lower
                    results.append(self._pod_result(
                        "k8s_pod_capability_drop_all",
                        "Container drops all Linux capabilities",
                        "medium", "PASS" if drops_all else "FAIL", rid, cname,
                        f"Container {cname} drops ALL capabilities: {drops_all}",
                        "Set securityContext.capabilities.drop to ['ALL']",
                    ))

                    # k8s_pod_seccomp_profile
                    has_seccomp = False
                    if sc and sc.seccomp_profile:
                        has_seccomp = sc.seccomp_profile.type in (
                            "RuntimeDefault", "Localhost",
                        )
                    # Also check pod-level seccomp
                    if not has_seccomp and spec.security_context and spec.security_context.seccomp_profile:
                        has_seccomp = spec.security_context.seccomp_profile.type in (
                            "RuntimeDefault", "Localhost",
                        )
                    results.append(self._pod_result(
                        "k8s_pod_seccomp_profile",
                        "Container has a Seccomp profile configured",
                        "medium", "PASS" if has_seccomp else "FAIL", rid, cname,
                        f"Container {cname} seccomp profile configured: {has_seccomp}",
                        "Set securityContext.seccompProfile.type to RuntimeDefault or Localhost",
                    ))

                    # k8s_pod_image_pull_policy
                    pull_policy = container.image_pull_policy or ""
                    image = container.image or ""
                    good_policy = pull_policy == "Always" or (
                        ":" in image and not image.endswith(":latest")
                    )
                    results.append(self._pod_result(
                        "k8s_pod_image_pull_policy",
                        "Container image pull policy is Always or uses pinned tag",
                        "low", "PASS" if good_policy else "FAIL", rid, cname,
                        f"Container {cname} imagePullPolicy: {pull_policy}, image: {image}",
                        "Set imagePullPolicy to Always or use a specific image tag",
                    ))

                    # k8s_pod_liveness_probe
                    has_liveness = container.liveness_probe is not None
                    results.append(self._pod_result(
                        "k8s_pod_liveness_probe",
                        "Container has a liveness probe configured",
                        "low", "PASS" if has_liveness else "FAIL", rid, cname,
                        f"Container {cname} liveness probe configured: {has_liveness}",
                        "Configure a livenessProbe to enable automatic restart on failure",
                    ))

                    # k8s_pod_readiness_probe
                    has_readiness = container.readiness_probe is not None
                    results.append(self._pod_result(
                        "k8s_pod_readiness_probe",
                        "Container has a readiness probe configured",
                        "low", "PASS" if has_readiness else "FAIL", rid, cname,
                        f"Container {cname} readiness probe configured: {has_readiness}",
                        "Configure a readinessProbe to prevent traffic to unready containers",
                    ))

        except Exception as e:
            logger.warning(f"K8s pod checks failed: {e}")
        return results

    # ── RBAC checks ─────────────────────────────────────────────────────

    def _check_rbac(self, k8s_client) -> list[dict]:
        results = []
        rbac = k8s_client.RbacAuthorizationV1Api()
        v1 = k8s_client.CoreV1Api()
        try:
            # k8s_rbac_no_wildcard_cluster_admin
            cluster_role_bindings = rbac.list_cluster_role_binding()
            for crb in cluster_role_bindings.items:
                if crb.role_ref.name == "cluster-admin":
                    for subject in crb.subjects or []:
                        if subject.kind == "Group" and subject.name in (
                            "system:authenticated", "system:unauthenticated",
                        ):
                            results.append(CheckResult(
                                check_id="k8s_rbac_no_wildcard_cluster_admin",
                                check_title="cluster-admin not bound to broad groups",
                                service="rbac", severity="critical", status="FAIL",
                                resource_id=crb.metadata.name,
                                status_extended=f"cluster-admin bound to group {subject.name}",
                                remediation="Remove cluster-admin binding from broad groups",
                                compliance_frameworks=COMPLIANCE,
                            ).to_dict())

            # k8s_rbac_no_wildcard_verbs
            cluster_roles = rbac.list_cluster_role()
            for cr in cluster_roles.items:
                cr_name = cr.metadata.name
                if cr_name.startswith("system:"):
                    continue
                for rule in cr.rules or []:
                    verbs = rule.verbs or []
                    resources = rule.resources or []
                    api_groups = rule.api_groups or []
                    if "*" in verbs and "*" in resources:
                        results.append(CheckResult(
                            check_id="k8s_rbac_no_wildcard_verbs",
                            check_title="ClusterRole does not use wildcard verbs on all resources",
                            service="rbac", severity="high", status="FAIL",
                            resource_id=cr_name, resource_name=cr_name,
                            status_extended=f"ClusterRole {cr_name} grants wildcard verbs on wildcard resources",
                            remediation="Replace wildcard verbs and resources with specific permissions",
                            compliance_frameworks=COMPLIANCE,
                        ).to_dict())
                        break  # one finding per role is enough

            # k8s_rbac_limit_secrets_access
            for cr in cluster_roles.items:
                cr_name = cr.metadata.name
                if cr_name.startswith("system:"):
                    continue
                for rule in cr.rules or []:
                    resources = rule.resources or []
                    verbs = rule.verbs or []
                    if "secrets" in resources and ("*" in verbs or "get" in verbs or "list" in verbs):
                        results.append(CheckResult(
                            check_id="k8s_rbac_limit_secrets_access",
                            check_title="ClusterRole limits access to secrets",
                            service="rbac", severity="high", status="FAIL",
                            resource_id=cr_name, resource_name=cr_name,
                            status_extended=f"ClusterRole {cr_name} grants broad secrets access ({', '.join(verbs)})",
                            remediation="Restrict secrets access to only the roles that require it",
                            compliance_frameworks=COMPLIANCE,
                        ).to_dict())
                        break

            # k8s_rbac_no_default_sa_token
            namespaces = v1.list_namespace()
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                if ns_name.startswith("kube-"):
                    continue
                try:
                    sa = v1.read_namespaced_service_account("default", ns_name)
                    auto_mount = sa.automount_service_account_token
                    # Default is True when not explicitly set
                    is_disabled = auto_mount is False
                    results.append(CheckResult(
                        check_id="k8s_rbac_no_default_sa_token",
                        check_title="Default service account token auto-mount is disabled",
                        service="rbac", severity="medium",
                        status="PASS" if is_disabled else "FAIL",
                        resource_id=f"{ns_name}/default",
                        resource_name="default",
                        status_extended=f"Default SA in {ns_name} automountServiceAccountToken: {auto_mount}",
                        remediation="Set automountServiceAccountToken to false on the default service account",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"K8s RBAC checks failed: {e}")
        return results

    # ── Network policy checks ───────────────────────────────────────────

    def _check_network_policies(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        net = k8s_client.NetworkingV1Api()
        try:
            namespaces = v1.list_namespace()
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                if ns_name.startswith("kube-"):
                    continue

                policies = net.list_namespaced_network_policy(ns_name)

                # k8s_namespace_network_policy
                results.append(CheckResult(
                    check_id="k8s_namespace_network_policy",
                    check_title="Namespace has network policies",
                    service="network", severity="medium",
                    status="PASS" if policies.items else "FAIL",
                    resource_id=ns_name, resource_name=ns_name,
                    status_extended=f"Namespace {ns_name} has {len(policies.items)} network policy(ies)",
                    remediation="Create network policies to restrict pod traffic",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # k8s_network_deny_all_default
                has_deny_all = False
                for pol in policies.items:
                    spec = pol.spec
                    # A deny-all policy selects all pods and has empty ingress/egress
                    if spec.pod_selector and not spec.pod_selector.match_labels:
                        policy_types = spec.policy_types or []
                        if "Ingress" in policy_types and not spec.ingress:
                            has_deny_all = True
                            break
                        if "Egress" in policy_types and not spec.egress:
                            has_deny_all = True
                            break

                results.append(CheckResult(
                    check_id="k8s_network_deny_all_default",
                    check_title="Namespace has a default deny-all network policy",
                    service="network", severity="medium",
                    status="PASS" if has_deny_all else "FAIL",
                    resource_id=ns_name, resource_name=ns_name,
                    status_extended=f"Namespace {ns_name} default deny-all policy: {has_deny_all}",
                    remediation="Create a default deny-all NetworkPolicy for ingress and egress",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # k8s_network_ingress_rules — check that ingress policies specify source restrictions
                for pol in policies.items:
                    pol_name = pol.metadata.name
                    spec = pol.spec
                    policy_types = spec.policy_types or []
                    if "Ingress" not in policy_types:
                        continue
                    for ingress_rule in spec.ingress or []:
                        has_from = bool(ingress_rule._from)
                        if not has_from:
                            results.append(CheckResult(
                                check_id="k8s_network_ingress_rules",
                                check_title="Network policy ingress rule specifies source restrictions",
                                service="network", severity="medium", status="FAIL",
                                resource_id=f"{ns_name}/{pol_name}",
                                resource_name=pol_name,
                                status_extended=f"NetworkPolicy {pol_name} in {ns_name} has an ingress rule with no source restriction",
                                remediation="Specify 'from' selectors in ingress rules to restrict source traffic",
                                compliance_frameworks=COMPLIANCE,
                            ).to_dict())

        except Exception as e:
            logger.warning(f"K8s network policy checks failed: {e}")
        return results

    # ── Namespace checks ────────────────────────────────────────────────

    def _check_namespaces(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            # k8s_no_pods_in_default
            pods = v1.list_namespaced_pod("default")
            non_system_pods = [p for p in pods.items if not p.metadata.name.startswith("kube-")]
            results.append(CheckResult(
                check_id="k8s_no_pods_in_default",
                check_title="No workload pods in default namespace",
                service="namespaces", severity="medium",
                status="N/A" if not non_system_pods else "FAIL",
                resource_id="default",
                status_extended=f"Default namespace has {len(non_system_pods)} non-system pod(s). Control not applicable." if not non_system_pods else f"Default namespace has {len(non_system_pods)} non-system pod(s)",
                remediation="Move workloads out of the default namespace",
                compliance_frameworks=COMPLIANCE,
            ).to_dict())

            # k8s_namespace_resource_quotas & k8s_namespace_limit_ranges
            namespaces = v1.list_namespace()
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                if ns_name.startswith("kube-"):
                    continue

                # k8s_namespace_resource_quotas
                quotas = v1.list_namespaced_resource_quota(ns_name)
                results.append(CheckResult(
                    check_id="k8s_namespace_resource_quotas",
                    check_title="Namespace has resource quotas defined",
                    service="namespaces", severity="medium",
                    status="PASS" if quotas.items else "FAIL",
                    resource_id=ns_name, resource_name=ns_name,
                    status_extended=f"Namespace {ns_name} has {len(quotas.items)} resource quota(s)",
                    remediation="Create ResourceQuota objects to limit resource consumption per namespace",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # k8s_namespace_limit_ranges
                limit_ranges = v1.list_namespaced_limit_range(ns_name)
                results.append(CheckResult(
                    check_id="k8s_namespace_limit_ranges",
                    check_title="Namespace has LimitRange defined",
                    service="namespaces", severity="low",
                    status="PASS" if limit_ranges.items else "FAIL",
                    resource_id=ns_name, resource_name=ns_name,
                    status_extended=f"Namespace {ns_name} has {len(limit_ranges.items)} LimitRange(s)",
                    remediation="Create LimitRange objects to set default resource requests and limits",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"K8s namespace checks failed: {e}")
        return results

    # ── Secrets checks ──────────────────────────────────────────────────

    def _check_secrets(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            # k8s_secrets_encrypted_etcd — check if encryption configuration exists
            # We can only infer this from the API server flags; direct check needs
            # node-level access. We inspect the kube-system pods for the flag.
            try:
                api_pods = v1.list_namespaced_pod("kube-system", label_selector="component=kube-apiserver")
                encryption_configured = False
                for pod in api_pods.items:
                    for container in pod.spec.containers or []:
                        for arg in container.command or []:
                            if "--encryption-provider-config" in arg:
                                encryption_configured = True
                                break
                        if not encryption_configured:
                            for arg in container.args or []:
                                if "--encryption-provider-config" in arg:
                                    encryption_configured = True
                                    break
                results.append(CheckResult(
                    check_id="k8s_secrets_encrypted_etcd",
                    check_title="Secrets encryption at rest is configured for etcd",
                    service="secrets", severity="high",
                    status="PASS" if encryption_configured else "FAIL",
                    resource_id="kube-apiserver",
                    status_extended=f"API server --encryption-provider-config flag detected: {encryption_configured}",
                    remediation="Configure EncryptionConfiguration and pass --encryption-provider-config to the API server",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())
            except Exception:
                pass

            # k8s_secrets_no_env_vars — secrets should be mounted as volumes, not env vars
            pods = v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                name = pod.metadata.name
                ns = pod.metadata.namespace
                if ns.startswith("kube-"):
                    continue
                for container in pod.spec.containers or []:
                    secret_env_vars = []
                    for env in container.env or []:
                        if env.value_from and env.value_from.secret_key_ref:
                            secret_env_vars.append(env.name)
                    for env_from in container.env_from or []:
                        if env_from.secret_ref:
                            secret_env_vars.append(f"envFrom:{env_from.secret_ref.name}")
                    if secret_env_vars:
                        results.append(CheckResult(
                            check_id="k8s_secrets_no_env_vars",
                            check_title="Secrets are not exposed as environment variables",
                            service="secrets", severity="medium", status="FAIL",
                            resource_id=f"{ns}/{name}/{container.name}",
                            resource_name=container.name,
                            status_extended=(
                                f"Container {container.name} in {ns}/{name} exposes secrets via "
                                f"env vars: {', '.join(secret_env_vars)}"
                            ),
                            remediation="Mount secrets as files using volume mounts instead of environment variables",
                            compliance_frameworks=COMPLIANCE,
                        ).to_dict())

        except Exception as e:
            logger.warning(f"K8s secrets checks failed: {e}")
        return results

    # ── Services checks ─────────────────────────────────────────────────

    def _check_services(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            services = v1.list_service_for_all_namespaces()
            for svc in services.items:
                svc_name = svc.metadata.name
                ns = svc.metadata.namespace
                if ns.startswith("kube-"):
                    continue

                svc_type = svc.spec.type or "ClusterIP"

                # k8s_service_no_loadbalancer_public
                if svc_type == "LoadBalancer":
                    # Check for internal LB annotation (cloud-specific)
                    annotations = svc.metadata.annotations or {}
                    is_internal = any(
                        "internal" in (v or "").lower()
                        for k, v in annotations.items()
                        if "load-balancer" in k.lower() or "lb" in k.lower()
                    )
                    results.append(CheckResult(
                        check_id="k8s_service_no_loadbalancer_public",
                        check_title="LoadBalancer service is not publicly exposed",
                        service="services", severity="high",
                        status="PASS" if is_internal else "FAIL",
                        resource_id=f"{ns}/{svc_name}", resource_name=svc_name,
                        status_extended=f"Service {ns}/{svc_name} is type LoadBalancer, internal: {is_internal}",
                        remediation="Use internal LoadBalancer annotations or switch to ClusterIP with an Ingress controller",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                # k8s_service_no_nodeport
                if svc_type == "NodePort":
                    results.append(CheckResult(
                        check_id="k8s_service_no_nodeport",
                        check_title="Service does not use NodePort type",
                        service="services", severity="medium", status="FAIL",
                        resource_id=f"{ns}/{svc_name}", resource_name=svc_name,
                        status_extended=f"Service {ns}/{svc_name} uses NodePort which exposes ports on all nodes",
                        remediation="Use ClusterIP services with an Ingress controller instead of NodePort",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"K8s services checks failed: {e}")
        return results

    # ── API Server checks ───────────────────────────────────────────────

    def _check_api_server(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            api_pods = v1.list_namespaced_pod(
                "kube-system", label_selector="component=kube-apiserver",
            )
            for pod in api_pods.items:
                all_args = []
                for container in pod.spec.containers or []:
                    all_args.extend(container.command or [])
                    all_args.extend(container.args or [])

                # k8s_api_audit_logging
                audit_enabled = any("--audit-log-path" in arg for arg in all_args)
                results.append(CheckResult(
                    check_id="k8s_api_audit_logging",
                    check_title="API server has audit logging enabled",
                    service="apiserver", severity="high",
                    status="PASS" if audit_enabled else "FAIL",
                    resource_id=pod.metadata.name,
                    resource_name="kube-apiserver",
                    status_extended=f"API server audit logging configured: {audit_enabled}",
                    remediation="Configure --audit-log-path and --audit-policy-file on the API server",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # k8s_api_tls_enabled
                tls_cert = any("--tls-cert-file" in arg for arg in all_args)
                tls_key = any("--tls-private-key-file" in arg for arg in all_args)
                tls_ok = tls_cert and tls_key
                results.append(CheckResult(
                    check_id="k8s_api_tls_enabled",
                    check_title="API server has TLS enabled",
                    service="apiserver", severity="critical",
                    status="PASS" if tls_ok else "FAIL",
                    resource_id=pod.metadata.name,
                    resource_name="kube-apiserver",
                    status_extended=f"API server TLS cert: {tls_cert}, key: {tls_key}",
                    remediation="Configure --tls-cert-file and --tls-private-key-file on the API server",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"K8s API server checks failed: {e}")
        return results

    # ── Admission checks ────────────────────────────────────────────────

    def _check_admission(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            # k8s_admission_pod_security — check for PodSecurity admission (PSA labels on namespaces)
            namespaces = v1.list_namespace()
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                if ns_name.startswith("kube-"):
                    continue

                labels = ns.metadata.labels or {}
                psa_enforce = labels.get("pod-security.kubernetes.io/enforce")
                psa_configured = psa_enforce is not None
                results.append(CheckResult(
                    check_id="k8s_admission_pod_security",
                    check_title="Namespace has Pod Security Standards (PSA) enforce label",
                    service="admission", severity="high",
                    status="PASS" if psa_configured else "FAIL",
                    resource_id=ns_name, resource_name=ns_name,
                    status_extended=(
                        f"Namespace {ns_name} PSA enforce level: {psa_enforce}"
                        if psa_configured
                        else f"Namespace {ns_name} has no pod-security.kubernetes.io/enforce label"
                    ),
                    remediation="Add pod-security.kubernetes.io/enforce label with 'restricted' or 'baseline' level",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"K8s admission checks failed: {e}")
        return results

    # ── CIS coverage ─────────────────────────────────────────────────

    def _emit_cis_coverage(self, automated_results: list[dict]) -> list[dict]:
        """Emit MANUAL results for CIS controls not covered by automated checks.

        Ensures complete CIS Kubernetes Benchmark v1.9.0 reporting by scanning
        all controls and marking uncovered ones with MANUAL status.
        """
        # Build set of CIS control IDs already covered by automated results
        covered_cis_ids = set()
        for result in automated_results:
            cis_id = result.get("cis_control_id")
            if cis_id:
                covered_cis_ids.add(cis_id)

        # Map existing check_ids to CIS control IDs
        check_to_cis = {
            "k8s_pod_no_host_network": "5.2.4",
            "k8s_pod_no_host_pid": "5.2.2",
            "k8s_pod_no_host_ipc": "5.2.3",
            "k8s_pod_no_privileged": "5.2.5",
            "k8s_pod_run_as_non_root": "5.2.7",
            "k8s_pod_readonly_rootfs": "5.2.10",
            "k8s_pod_resource_limits": "5.4.1",
            "k8s_pod_no_privilege_escalation": "5.2.6",
            "k8s_pod_capability_drop_all": "5.2.8",
            "k8s_pod_seccomp_profile": "5.7.2",
            "k8s_pod_image_pull_policy": "5.5.1",
            "k8s_pod_liveness_probe": "5.5.2",
            "k8s_pod_readiness_probe": "5.5.3",
            "k8s_rbac_no_wildcard_cluster_admin": "5.1.1",
            "k8s_rbac_no_wildcard_verbs": "5.1.3",
            "k8s_rbac_limit_secrets_access": "5.1.2",
            "k8s_rbac_no_default_sa_token": "5.1.5",
            "k8s_namespace_network_policy": "5.3.2",
            "k8s_network_deny_all_default": "5.3.1",
            "k8s_network_ingress_rules": "5.3.3",
            "k8s_no_pods_in_default": "5.7.4",
            "k8s_namespace_resource_quotas": "5.4.2",
            "k8s_namespace_limit_ranges": "5.4.3",
            "k8s_secrets_encrypted_etcd": "1.2.29",
            "k8s_secrets_no_env_vars": "5.4.4",
            "k8s_service_no_loadbalancer_public": "5.5.4",
            "k8s_service_no_nodeport": "5.5.5",
            "k8s_api_audit_logging": "1.2.18",
            "k8s_api_tls_enabled": "1.2.25",
            "k8s_admission_pod_security": "5.2.1",
        }

        for result in automated_results:
            check_id = result.get("check_id", "")
            cis_id = check_to_cis.get(check_id)
            if cis_id:
                covered_cis_ids.add(cis_id)

        # Emit MANUAL results for uncovered controls
        manual_results = []
        for cis_id, title, level, assessment_type, severity, service_area in KUBERNETES_CIS_CONTROLS:
            if cis_id in covered_cis_ids:
                continue

            manual_results.append(CheckResult(
                check_id=f"k8s_cis_{cis_id.replace('.', '_')}",
                check_title=title,
                service=service_area,
                severity=severity,
                status="MANUAL",
                resource_id="cluster",
                resource_name="kubernetes-cluster",
                status_extended=f"CIS {cis_id}: Requires manual verification — {title}",
                remediation=f"Review CIS Kubernetes Benchmark v1.9.0 control {cis_id}: {title}",
                compliance_frameworks=COMPLIANCE,
                assessment_type=assessment_type,
                cis_control_id=cis_id,
                cis_level=level,
            ).to_dict())

        return manual_results

    def run_all_checks(self) -> list[dict]:
        """Run all Kubernetes security checks including complete CIS benchmark coverage."""
        results = self.scan()

        # Add MANUAL results for any CIS controls not covered by automated checks
        results.extend(self._emit_cis_coverage(results))

        return results
