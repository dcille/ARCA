"""CIS Kubernetes Benchmark v1.12.0 -- Complete Control Registry.

Updated from v1.9.0 to v1.12.0 (September 2025).
Reference: CIS Kubernetes Benchmark v1.12.0

Changes from v1.9.0:
  - 10 NEW controls: 1.2.27-30, 3.2.1-2, 4.2.14, 4.3.1, 5.2.12, 5.5.1
  - 2 REMOVED: old 5.2.10 (caps beyond default), old 5.2.13 (allowed volumes)
  - 17 status changes (mostly automated→manual in 1.1, 4.x, 5.2)
  - Section 5.7 renumbered to 5.6
  - Total: 131 controls (64 automated, 67 manual)
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
KUBERNETES_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Control Plane Components
    # =========================================================================

    # 1.1 Control Plane Node Configuration Files
    ("1.1.1", "Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.2", "Ensure that the API server pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.3", "Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.4", "Ensure that the controller manager pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.5", "Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.6", "Ensure that the scheduler pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.7", "Ensure that the etcd pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.8", "Ensure that the etcd pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.9", "Ensure that the Container Network Interface file permissions are set to 600 or more restrictive",
     "L1", "manual", "medium", "control_plane"),
    ("1.1.10", "Ensure that the Container Network Interface file ownership is set to root:root",
     "L1", "manual", "medium", "control_plane"),
    ("1.1.11", "Ensure that the etcd data directory permissions are set to 700 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.12", "Ensure that the etcd data directory ownership is set to etcd:etcd",
     "L1", "automated", "high", "control_plane"),
    ("1.1.13", "Ensure that the default administrative credential file permissions are set to 600",
     "L1", "automated", "high", "control_plane"),
    ("1.1.14", "Ensure that the default administrative credential file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.15", "Ensure that the scheduler.conf file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.16", "Ensure that the scheduler.conf file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.17", "Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.18", "Ensure that the controller-manager.conf file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.19", "Ensure that the Kubernetes PKI directory and file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.20", "Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive",
     "L1", "manual", "high", "control_plane"),  # v1.12: was automated, now manual; 600→644
    ("1.1.21", "Ensure that the Kubernetes PKI key file permissions are set to 600",
     "L1", "manual", "high", "control_plane"),  # v1.12: was automated, now manual

    # 1.2 API Server
    ("1.2.1", "Ensure that the --anonymous-auth argument is set to false",
     "L1", "manual", "critical", "control_plane"),  # v1.12: was automated, now manual
    ("1.2.2", "Ensure that the --token-auth-file parameter is not set",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.3", "Ensure that the DenyServiceExternalIPs is set",
     "L1", "manual", "medium", "control_plane"),
    ("1.2.4", "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.5", "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.6", "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.7", "Ensure that the --authorization-mode argument includes Node",
     "L1", "automated", "high", "control_plane"),
    ("1.2.8", "Ensure that the --authorization-mode argument includes RBAC",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.9", "Ensure that the admission control plugin EventRateLimit is set",
     "L1", "manual", "medium", "control_plane"),
    ("1.2.10", "Ensure that the admission control plugin AlwaysAdmit is not set",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.11", "Ensure that the admission control plugin AlwaysPullImages is set",
     "L1", "manual", "medium", "control_plane"),
    ("1.2.12", "Ensure that the admission control plugin ServiceAccount is set",
     "L1", "automated", "high", "control_plane"),
    ("1.2.13", "Ensure that the admission control plugin NamespaceLifecycle is set",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.14", "Ensure that the admission control plugin NodeRestriction is set",
     "L1", "automated", "high", "control_plane"),
    ("1.2.15", "Ensure that the --profiling argument is set to false",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.16", "Ensure that the --audit-log-path argument is set",
     "L1", "automated", "high", "control_plane"),
    ("1.2.17", "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.18", "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.19", "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.20", "Ensure that the --request-timeout argument is set as appropriate",
     "L1", "manual", "medium", "control_plane"),
    ("1.2.21", "Ensure that the --service-account-lookup argument is set to true",
     "L1", "automated", "high", "control_plane"),
    ("1.2.22", "Ensure that the --service-account-key-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.23", "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.24", "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.25", "Ensure that the --client-ca-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.26", "Ensure that the --etcd-cafile argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    # NEW in v1.12.0
    ("1.2.27", "Ensure that the --encryption-provider-config argument is set as appropriate",
     "L1", "manual", "high", "control_plane"),
    ("1.2.28", "Ensure that encryption providers are appropriately configured",
     "L1", "manual", "high", "control_plane"),
    ("1.2.29", "Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
     "L1", "manual", "medium", "control_plane"),
    ("1.2.30", "Ensure that the --service-account-extend-token-expiration parameter is set to false",
     "L1", "automated", "medium", "control_plane"),

    # 1.3 Controller Manager
    ("1.3.1", "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate",
     "L1", "manual", "medium", "control_plane"),
    ("1.3.2", "Ensure that the --profiling argument is set to false",
     "L1", "automated", "medium", "control_plane"),
    ("1.3.3", "Ensure that the --use-service-account-credentials argument is set to true",
     "L1", "automated", "high", "control_plane"),
    ("1.3.4", "Ensure that the --service-account-private-key-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.3.5", "Ensure that the --root-ca-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.3.6", "Ensure that the RotateKubeletServerCertificate argument is set to true",
     "L1", "automated", "medium", "control_plane"),  # v1.12: was L2, now L1
    ("1.3.7", "Ensure that the --bind-address argument is set to 127.0.0.1",
     "L1", "automated", "high", "control_plane"),

    # 1.4 Scheduler
    ("1.4.1", "Ensure that the --profiling argument is set to false",
     "L1", "automated", "medium", "control_plane"),
    ("1.4.2", "Ensure that the --bind-address argument is set to 127.0.0.1",
     "L1", "automated", "high", "control_plane"),

    # =========================================================================
    # Section 2: etcd
    # =========================================================================
    ("2.1", "Ensure that the --cert-file and --key-file arguments are set as appropriate",
     "L1", "automated", "high", "etcd"),
    ("2.2", "Ensure that the --client-cert-auth argument is set to true",
     "L1", "automated", "high", "etcd"),
    ("2.3", "Ensure that the --auto-tls argument is not set to true",
     "L1", "automated", "high", "etcd"),
    ("2.4", "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
     "L1", "automated", "high", "etcd"),
    ("2.5", "Ensure that the --peer-client-cert-auth argument is set to true",
     "L1", "automated", "high", "etcd"),
    ("2.6", "Ensure that the --peer-auto-tls argument is not set to true",
     "L1", "automated", "high", "etcd"),
    ("2.7", "Ensure that a unique Certificate Authority is used for etcd",
     "L2", "manual", "medium", "etcd"),

    # =========================================================================
    # Section 3: Control Plane Configuration
    # =========================================================================
    # 3.1 Authentication and Authorization
    ("3.1.1", "Client certificate authentication should not be used for users",
     "L1", "manual", "medium", "control_plane_config"),
    ("3.1.2", "Service account token authentication should not be used for users",
     "L1", "manual", "medium", "control_plane_config"),
    ("3.1.3", "Bootstrap token authentication should not be used for users",
     "L1", "manual", "medium", "control_plane_config"),
    # 3.2 Logging — NEW in v1.12.0
    ("3.2.1", "Ensure that a minimal audit policy is created",
     "L1", "manual", "high", "control_plane_config"),
    ("3.2.2", "Ensure that the audit policy covers key security concerns",
     "L2", "manual", "medium", "control_plane_config"),

    # =========================================================================
    # Section 4: Worker Nodes
    # =========================================================================
    # 4.1 Worker Node Configuration Files
    ("4.1.1", "Ensure that the kubelet service file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "worker_nodes"),
    ("4.1.2", "Ensure that the kubelet service file ownership is set to root:root",
     "L1", "automated", "high", "worker_nodes"),
    ("4.1.3", "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive",
     "L1", "manual", "high", "worker_nodes"),  # v1.12: was automated
    ("4.1.4", "If proxy kubeconfig file exists ensure ownership is set to root:root",
     "L1", "manual", "high", "worker_nodes"),  # v1.12: was automated
    ("4.1.5", "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "worker_nodes"),
    ("4.1.6", "Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root",
     "L1", "automated", "high", "worker_nodes"),
    ("4.1.7", "Ensure that the certificate authorities file permissions are set to 644 or more restrictive",
     "L1", "manual", "high", "worker_nodes"),  # v1.12: was automated, 600→644
    ("4.1.8", "Ensure that the client certificate authorities file ownership is set to root:root",
     "L1", "manual", "high", "worker_nodes"),  # v1.12: was automated
    ("4.1.9", "If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive",
     "L1", "automated", "high", "worker_nodes"),
    ("4.1.10", "If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root",
     "L1", "automated", "high", "worker_nodes"),

    # 4.2 Kubelet
    ("4.2.1", "Ensure that the --anonymous-auth argument is set to false",
     "L1", "automated", "critical", "worker_nodes"),
    ("4.2.2", "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
     "L1", "automated", "critical", "worker_nodes"),
    ("4.2.3", "Ensure that the --client-ca-file argument is set as appropriate",
     "L1", "automated", "high", "worker_nodes"),
    ("4.2.4", "Verify that if defined, readOnlyPort is set to 0",
     "L1", "manual", "high", "worker_nodes"),
    ("4.2.5", "Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
     "L1", "manual", "medium", "worker_nodes"),
    ("4.2.6", "Ensure that the --make-iptables-util-chains argument is set to true",
     "L1", "automated", "medium", "worker_nodes"),
    ("4.2.7", "Ensure that the --hostname-override argument is not set",
     "L1", "manual", "medium", "worker_nodes"),
    ("4.2.8", "Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture",
     "L2", "manual", "low", "worker_nodes"),
    ("4.2.9", "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
     "L1", "manual", "high", "worker_nodes"),  # v1.12: was automated
    ("4.2.10", "Ensure that the --rotate-certificates argument is not set to false",
     "L1", "automated", "high", "worker_nodes"),
    ("4.2.11", "Verify that the RotateKubeletServerCertificate argument is set to true",
     "L1", "manual", "high", "worker_nodes"),  # v1.12: was automated
    ("4.2.12", "Ensure that the Kubelet only makes use of strong cryptographic ciphers",
     "L1", "manual", "medium", "worker_nodes"),
    ("4.2.13", "Ensure that a limit is set on pod PIDs",
     "L1", "manual", "medium", "worker_nodes"),
    # NEW in v1.12.0
    ("4.2.14", "Ensure that the --seccomp-default parameter is set to true",
     "L1", "manual", "medium", "worker_nodes"),

    # 4.3 kube-proxy — NEW section in v1.12.0
    ("4.3.1", "Ensure that the kube-proxy metrics service is bound to localhost",
     "L1", "manual", "medium", "worker_nodes"),

    # =========================================================================
    # Section 5: Policies
    # =========================================================================
    # 5.1 RBAC and Service Accounts
    ("5.1.1", "Ensure that the cluster-admin role is only used where required",
     "L1", "manual", "critical", "policies"),
    ("5.1.2", "Minimize access to secrets",
     "L1", "manual", "high", "policies"),
    ("5.1.3", "Minimize wildcard use in Roles and ClusterRoles",
     "L1", "manual", "high", "policies"),
    ("5.1.4", "Minimize access to create pods",
     "L1", "manual", "high", "policies"),
    ("5.1.5", "Ensure that default service accounts are not actively used",
     "L1", "manual", "high", "policies"),
    ("5.1.6", "Ensure that Service Account Tokens are only mounted where necessary",
     "L1", "manual", "high", "policies"),
    ("5.1.7", "Avoid use of system:masters group",
     "L1", "manual", "critical", "policies"),
    ("5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
     "L1", "manual", "critical", "policies"),
    ("5.1.9", "Minimize access to create persistent volumes",
     "L1", "manual", "medium", "policies"),
    ("5.1.10", "Minimize access to the proxy sub-resource of nodes",
     "L1", "manual", "high", "policies"),
    ("5.1.11", "Minimize access to the approval sub-resource of certificatesigningrequests objects",
     "L1", "manual", "high", "policies"),
    ("5.1.12", "Minimize access to webhook configuration objects",
     "L1", "manual", "high", "policies"),
    ("5.1.13", "Minimize access to the service account token creation",
     "L1", "manual", "high", "policies"),

    # 5.2 Pod Security Standards — ALL manual in v1.12.0
    ("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place",
     "L1", "manual", "critical", "policies"),
    ("5.2.2", "Minimize the admission of privileged containers",
     "L1", "manual", "critical", "policies"),  # v1.12: was automated
    ("5.2.3", "Minimize the admission of containers wishing to share the host process ID namespace",
     "L1", "manual", "high", "policies"),  # v1.12: was automated
    ("5.2.4", "Minimize the admission of containers wishing to share the host IPC namespace",
     "L1", "manual", "high", "policies"),  # v1.12: was automated
    ("5.2.5", "Minimize the admission of containers wishing to share the host network namespace",
     "L1", "manual", "high", "policies"),  # v1.12: was automated
    ("5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation",
     "L1", "manual", "high", "policies"),  # v1.12: was automated
    ("5.2.7", "Minimize the admission of root containers",
     "L2", "manual", "high", "policies"),  # v1.12: was automated
    ("5.2.8", "Minimize the admission of containers with the NET_RAW capability",
     "L1", "manual", "high", "policies"),  # v1.12: was automated
    ("5.2.9", "Minimize the admission of containers with capabilities assigned",
     "L1", "manual", "medium", "policies"),  # v1.12: was automated
    ("5.2.10", "Minimize the admission of Windows HostProcess Containers",
     "L1", "manual", "high", "policies"),  # Renumbered: was 5.2.11 in v1.9
    ("5.2.11", "Minimize the admission of HostPath volumes",
     "L1", "manual", "high", "policies"),  # Renumbered: was 5.2.12 in v1.9
    # NEW in v1.12.0
    ("5.2.12", "Minimize the admission of containers which use HostPorts",
     "L1", "manual", "medium", "policies"),

    # 5.3 Network Policies and CNI
    ("5.3.1", "Ensure that the CNI in use supports Network Policies",
     "L1", "manual", "high", "policies"),
    ("5.3.2", "Ensure that all Namespaces have Network Policies defined",
     "L1", "manual", "high", "policies"),

    # 5.4 Secrets Management
    ("5.4.1", "Prefer using secrets as files over secrets as environment variables",
     "L2", "manual", "medium", "policies"),
    ("5.4.2", "Consider external secret storage",
     "L2", "manual", "medium", "policies"),

    # 5.5 Extensible Admission Control — NEW section in v1.12.0
    ("5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller",
     "L2", "manual", "medium", "policies"),

    # 5.6 General Policies (renumbered from 5.7 in v1.9)
    ("5.6.1", "Create administrative boundaries between resources using namespaces",
     "L1", "manual", "medium", "policies"),
    ("5.6.2", "Ensure that the seccomp profile is set to docker/default in your Pod definitions",
     "L2", "manual", "medium", "policies"),
    ("5.6.3", "Apply SecurityContext to your Pods and Containers",
     "L2", "manual", "medium", "policies"),
    ("5.6.4", "The default namespace should not be used",
     "L1", "manual", "medium", "policies"),
]


def get_kubernetes_cis_registry():
    return [{"cis_control_id": c[0], "title": c[1], "cis_level": c[2],
             "assessment_type": c[3], "severity": c[4], "service_area": c[5]}
            for c in KUBERNETES_CIS_CONTROLS]

def get_kubernetes_control_count(): return len(KUBERNETES_CIS_CONTROLS)
def get_kubernetes_automated_count(): return sum(1 for c in KUBERNETES_CIS_CONTROLS if c[3] == "automated")
def get_kubernetes_manual_count(): return sum(1 for c in KUBERNETES_CIS_CONTROLS if c[3] == "manual")
