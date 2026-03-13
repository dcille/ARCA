"""Kubernetes Security Scanner.

Implements security checks for Kubernetes clusters following CIS benchmarks.
"""
import logging

from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)


class K8sScanner:
    """Kubernetes cluster security scanner."""

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
        results = []
        try:
            k8s_client = self._get_client()
            results.extend(self._check_pods(k8s_client))
            results.extend(self._check_rbac(k8s_client))
            results.extend(self._check_network_policies(k8s_client))
            results.extend(self._check_namespaces(k8s_client))
        except Exception as e:
            logger.error(f"Kubernetes scan failed: {e}")
        return results

    def _check_pods(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            pods = v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                name = pod.metadata.name
                ns = pod.metadata.namespace

                for container in pod.spec.containers or []:
                    sc = container.security_context

                    if sc and sc.privileged:
                        results.append(CheckResult(
                            check_id="k8s_pod_no_privileged",
                            check_title="Container is not running as privileged",
                            service="pods", severity="high", status="FAIL",
                            resource_id=f"{ns}/{name}/{container.name}",
                            resource_name=container.name,
                            status_extended=f"Container {container.name} in pod {ns}/{name} runs as privileged",
                            remediation="Set securityContext.privileged to false",
                            compliance_frameworks=["CIS-K8s", "NIST-800-53"],
                        ).to_dict())

                    run_as_root = not sc or not sc.run_as_non_root
                    results.append(CheckResult(
                        check_id="k8s_pod_run_as_non_root",
                        check_title="Container runs as non-root user",
                        service="pods", severity="medium",
                        status="FAIL" if run_as_root else "PASS",
                        resource_id=f"{ns}/{name}/{container.name}",
                        resource_name=container.name,
                        status_extended=f"Container {container.name} runAsNonRoot: {not run_as_root}",
                        remediation="Set securityContext.runAsNonRoot to true",
                        compliance_frameworks=["CIS-K8s", "NIST-800-53"],
                    ).to_dict())

                    read_only = sc and sc.read_only_root_filesystem
                    results.append(CheckResult(
                        check_id="k8s_pod_readonly_rootfs",
                        check_title="Container has read-only root filesystem",
                        service="pods", severity="low",
                        status="PASS" if read_only else "FAIL",
                        resource_id=f"{ns}/{name}/{container.name}",
                        resource_name=container.name,
                        status_extended=f"Container {container.name} readOnlyRootFilesystem: {read_only}",
                        remediation="Set securityContext.readOnlyRootFilesystem to true",
                        compliance_frameworks=["CIS-K8s", "NIST-800-53"],
                    ).to_dict())

                    has_limits = container.resources and container.resources.limits
                    results.append(CheckResult(
                        check_id="k8s_pod_resource_limits",
                        check_title="Container has resource limits",
                        service="pods", severity="medium",
                        status="PASS" if has_limits else "FAIL",
                        resource_id=f"{ns}/{name}/{container.name}",
                        resource_name=container.name,
                        status_extended=f"Container {container.name} has resource limits: {bool(has_limits)}",
                        remediation="Set CPU and memory limits for the container",
                        compliance_frameworks=["CIS-K8s"],
                    ).to_dict())

        except Exception as e:
            logger.warning(f"K8s pod checks failed: {e}")
        return results

    def _check_rbac(self, k8s_client) -> list[dict]:
        results = []
        rbac = k8s_client.RbacAuthorizationV1Api()
        try:
            cluster_roles = rbac.list_cluster_role_binding()
            for crb in cluster_roles.items:
                if crb.role_ref.name == "cluster-admin":
                    for subject in crb.subjects or []:
                        if subject.kind == "Group" and subject.name in ("system:authenticated", "system:unauthenticated"):
                            results.append(CheckResult(
                                check_id="k8s_rbac_no_wildcard_cluster_admin",
                                check_title="cluster-admin not bound to broad groups",
                                service="rbac", severity="critical", status="FAIL",
                                resource_id=crb.metadata.name,
                                status_extended=f"cluster-admin bound to group {subject.name}",
                                remediation="Remove cluster-admin binding from broad groups",
                                compliance_frameworks=["CIS-K8s", "NIST-800-53"],
                            ).to_dict())

        except Exception as e:
            logger.warning(f"K8s RBAC checks failed: {e}")
        return results

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
                results.append(CheckResult(
                    check_id="k8s_namespace_network_policy",
                    check_title="Namespace has network policies",
                    service="network", severity="medium",
                    status="PASS" if policies.items else "FAIL",
                    resource_id=ns_name, resource_name=ns_name,
                    status_extended=f"Namespace {ns_name} has {len(policies.items)} network policy(ies)",
                    remediation="Create network policies to restrict pod traffic",
                    compliance_frameworks=["CIS-K8s", "NIST-800-53"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"K8s network policy checks failed: {e}")
        return results

    def _check_namespaces(self, k8s_client) -> list[dict]:
        results = []
        v1 = k8s_client.CoreV1Api()
        try:
            pods = v1.list_namespaced_pod("default")
            non_system_pods = [p for p in pods.items if not p.metadata.name.startswith("kube-")]
            results.append(CheckResult(
                check_id="k8s_no_pods_in_default",
                check_title="No workload pods in default namespace",
                service="namespaces", severity="medium",
                status="PASS" if not non_system_pods else "FAIL",
                resource_id="default",
                status_extended=f"Default namespace has {len(non_system_pods)} non-system pod(s)",
                remediation="Move workloads out of the default namespace",
                compliance_frameworks=["CIS-K8s", "NIST-800-53"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"K8s namespace checks failed: {e}")
        return results
