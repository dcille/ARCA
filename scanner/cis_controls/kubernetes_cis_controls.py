"""CIS Kubernetes Benchmark v1.9.0 -- Complete Control Registry.

This registry contains ALL controls from the CIS Kubernetes Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS Kubernetes Benchmark v1.9.0
Total controls: ~130 across 5 sections.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" or "L2"
# assessment_type: "automated" or "manual"
# severity: "critical", "high", "medium", "low"
# service_area: "control_plane", "etcd", "control_plane_config", "worker_node", "policies"

KUBERNETES_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Control Plane Components
    # =========================================================================

    # 1.1 Control Plane Node Configuration Files
    ("1.1.1", "Ensure API server pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.2", "Ensure API server pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.3", "Ensure controller manager pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.4", "Ensure controller manager pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.5", "Ensure scheduler pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.6", "Ensure scheduler pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.7", "Ensure etcd pod specification file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.8", "Ensure etcd pod specification file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.9", "Ensure the Container Network Interface file permissions are set to 600 or more restrictive",
     "L1", "manual", "medium", "control_plane"),
    ("1.1.10", "Ensure the Container Network Interface file ownership is set to root:root",
     "L1", "manual", "medium", "control_plane"),
    ("1.1.11", "Ensure etcd data directory permissions are set to 700 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.12", "Ensure etcd data directory ownership is set to etcd:etcd",
     "L1", "automated", "high", "control_plane"),
    ("1.1.13", "Ensure admin.conf file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.14", "Ensure admin.conf file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.15", "Ensure scheduler.conf file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.16", "Ensure scheduler.conf file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.17", "Ensure controller-manager.conf file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.18", "Ensure controller-manager.conf file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.19", "Ensure the Kubernetes PKI directory and file ownership is set to root:root",
     "L1", "automated", "high", "control_plane"),
    ("1.1.20", "Ensure the Kubernetes PKI certificate file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "control_plane"),
    ("1.1.21", "Ensure the Kubernetes PKI key file permissions are set to 600",
     "L1", "automated", "high", "control_plane"),

    # 1.2 API Server
    ("1.2.1", "Ensure --anonymous-auth argument is set to false",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.2", "Ensure --token-auth-file parameter is not set",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.3", "Ensure --DenyServiceExternalIPs is not set",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.4", "Ensure --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.5", "Ensure --kubelet-certificate-authority argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.6", "Ensure --authorization-mode argument is not set to AlwaysAllow",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.7", "Ensure --authorization-mode argument includes Node",
     "L1", "automated", "high", "control_plane"),
    ("1.2.8", "Ensure --authorization-mode argument includes RBAC",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.9", "Ensure admission control plugin EventRateLimit is set",
     "L1", "manual", "medium", "control_plane"),
    ("1.2.10", "Ensure admission control plugin AlwaysAdmit is not set",
     "L1", "automated", "critical", "control_plane"),
    ("1.2.11", "Ensure admission control plugin AlwaysPullImages is set",
     "L1", "manual", "medium", "control_plane"),
    ("1.2.12", "Ensure admission control plugin ServiceAccount is set",
     "L1", "automated", "high", "control_plane"),
    ("1.2.13", "Ensure admission control plugin NamespaceLifecycle is set",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.14", "Ensure admission control plugin NodeRestriction is set",
     "L1", "automated", "high", "control_plane"),
    ("1.2.15", "Ensure --profiling argument is set to false",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.16", "Ensure --audit-log-path argument is set",
     "L1", "automated", "high", "control_plane"),
    ("1.2.17", "Ensure --audit-log-maxage argument is set to 30 or as appropriate",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.18", "Ensure --audit-log-maxbackup argument is set to 10 or as appropriate",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.19", "Ensure --audit-log-maxsize argument is set to 100 or as appropriate",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.20", "Ensure --request-timeout argument is set as appropriate",
     "L1", "automated", "medium", "control_plane"),
    ("1.2.21", "Ensure --service-account-lookup argument is set to true",
     "L1", "automated", "high", "control_plane"),
    ("1.2.22", "Ensure --service-account-key-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.23", "Ensure --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.24", "Ensure --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.25", "Ensure --client-ca-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.2.26", "Ensure --etcd-cafile argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),

    # 1.3 Controller Manager
    ("1.3.1", "Ensure --terminated-pod-gc-threshold argument is set as appropriate",
     "L1", "manual", "medium", "control_plane"),
    ("1.3.2", "Ensure --profiling argument is set to false",
     "L1", "automated", "medium", "control_plane"),
    ("1.3.3", "Ensure --use-service-account-credentials argument is set to true",
     "L1", "automated", "high", "control_plane"),
    ("1.3.4", "Ensure --service-account-private-key-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.3.5", "Ensure --root-ca-file argument is set as appropriate",
     "L1", "automated", "high", "control_plane"),
    ("1.3.6", "Ensure RotateKubeletServerCertificate argument is set to true",
     "L2", "automated", "medium", "control_plane"),
    ("1.3.7", "Ensure --bind-address argument is set to 127.0.0.1",
     "L1", "automated", "high", "control_plane"),

    # 1.4 Scheduler
    ("1.4.1", "Ensure --profiling argument is set to false",
     "L1", "automated", "medium", "control_plane"),
    ("1.4.2", "Ensure --bind-address argument is set to 127.0.0.1",
     "L1", "automated", "high", "control_plane"),

    # =========================================================================
    # Section 2: etcd
    # =========================================================================

    ("2.1", "Ensure --cert-file and --key-file arguments are set as appropriate",
     "L1", "automated", "high", "etcd"),
    ("2.2", "Ensure --client-cert-auth argument is set to true",
     "L1", "automated", "high", "etcd"),
    ("2.3", "Ensure --auto-tls argument is not set to true",
     "L1", "automated", "high", "etcd"),
    ("2.4", "Ensure --peer-cert-file and --peer-key-file arguments are set as appropriate",
     "L1", "automated", "high", "etcd"),
    ("2.5", "Ensure --peer-client-cert-auth argument is set to true",
     "L1", "automated", "high", "etcd"),
    ("2.6", "Ensure --peer-auto-tls argument is not set to true",
     "L1", "automated", "high", "etcd"),
    ("2.7", "Ensure a unique Certificate Authority is used for etcd",
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

    # =========================================================================
    # Section 4: Worker Nodes
    # =========================================================================

    # 4.1 Worker Node Configuration Files
    ("4.1.1", "Ensure the kubelet service file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "worker_node"),
    ("4.1.2", "Ensure the kubelet service file ownership is set to root:root",
     "L1", "automated", "high", "worker_node"),
    ("4.1.3", "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "worker_node"),
    ("4.1.4", "If proxy kubeconfig file exists ensure ownership is set to root:root",
     "L1", "automated", "high", "worker_node"),
    ("4.1.5", "Ensure --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "worker_node"),
    ("4.1.6", "Ensure --kubeconfig kubelet.conf file ownership is set to root:root",
     "L1", "automated", "high", "worker_node"),
    ("4.1.7", "Ensure certificate authorities file permissions are set to 600 or more restrictive",
     "L1", "automated", "high", "worker_node"),
    ("4.1.8", "Ensure client certificate authorities file ownership is set to root:root",
     "L1", "automated", "high", "worker_node"),
    ("4.1.9", "If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive",
     "L1", "automated", "high", "worker_node"),
    ("4.1.10", "If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root",
     "L1", "automated", "high", "worker_node"),

    # 4.2 Kubelet
    ("4.2.1", "Ensure --anonymous-auth argument is set to false",
     "L1", "automated", "critical", "worker_node"),
    ("4.2.2", "Ensure --authorization-mode argument is not set to AlwaysAllow",
     "L1", "automated", "critical", "worker_node"),
    ("4.2.3", "Ensure --client-ca-file argument is set as appropriate",
     "L1", "automated", "high", "worker_node"),
    ("4.2.4", "Verify that --read-only-port argument is set to 0",
     "L1", "automated", "high", "worker_node"),
    ("4.2.5", "Ensure --streaming-connection-idle-timeout argument is not set to 0",
     "L1", "automated", "medium", "worker_node"),
    ("4.2.6", "Ensure --make-iptables-util-chains argument is set to true",
     "L1", "automated", "medium", "worker_node"),
    ("4.2.7", "Ensure --hostname-override argument is not set",
     "L1", "manual", "medium", "worker_node"),
    ("4.2.8", "Ensure --eventRecordQPS argument is set to a level which ensures appropriate event capture",
     "L2", "automated", "low", "worker_node"),
    ("4.2.9", "Ensure --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
     "L1", "automated", "high", "worker_node"),
    ("4.2.10", "Ensure --rotate-certificates argument is not set to false",
     "L1", "automated", "high", "worker_node"),
    ("4.2.11", "Verify that the RotateKubeletServerCertificate argument is set to true",
     "L1", "automated", "high", "worker_node"),
    ("4.2.12", "Ensure the Kubelet only makes use of strong cryptographic ciphers",
     "L1", "manual", "medium", "worker_node"),
    ("4.2.13", "Ensure that a limit is set on pod PIDs",
     "L1", "manual", "medium", "worker_node"),

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

    # 5.2 Pod Security Standards
    ("5.2.1", "Ensure Pod Security Standards are Enforced",
     "L1", "manual", "critical", "policies"),
    ("5.2.2", "Ensure Privileged Containers are not used",
     "L1", "automated", "critical", "policies"),
    ("5.2.3", "Ensure Containers do not share the host process ID namespace",
     "L1", "automated", "high", "policies"),
    ("5.2.4", "Ensure Containers do not share the host IPC namespace",
     "L1", "automated", "high", "policies"),
    ("5.2.5", "Ensure Containers do not share the host network namespace",
     "L1", "automated", "high", "policies"),
    ("5.2.6", "Ensure Containers with allowPrivilegeEscalation are not used",
     "L1", "automated", "high", "policies"),
    ("5.2.7", "Ensure Containers that run as root are not used",
     "L2", "automated", "high", "policies"),
    ("5.2.8", "Ensure Containers with NET_RAW capability are not used",
     "L1", "automated", "high", "policies"),
    ("5.2.9", "Ensure Containers with added capabilities are not used",
     "L1", "automated", "medium", "policies"),
    ("5.2.10", "Ensure Containers with capabilities assigned beyond the default set are not used",
     "L2", "automated", "medium", "policies"),
    ("5.2.11", "Ensure Windows HostProcess Containers are not used",
     "L1", "automated", "high", "policies"),
    ("5.2.12", "Ensure HostPath volumes are not used",
     "L1", "automated", "high", "policies"),
    ("5.2.13", "Ensure Containers only use allowed volume types",
     "L2", "manual", "medium", "policies"),

    # 5.3 Network Policies and CNI
    ("5.3.1", "Ensure that the CNI in use supports NetworkPolicies",
     "L1", "manual", "high", "policies"),
    ("5.3.2", "Ensure that all Namespaces have NetworkPolicies defined",
     "L1", "manual", "high", "policies"),

    # 5.4 Secrets Management
    ("5.4.1", "Prefer using Secrets as files over Secrets as environment variables",
     "L2", "manual", "medium", "policies"),
    ("5.4.2", "Consider external secret storage",
     "L2", "manual", "medium", "policies"),

    # 5.7 General Policies
    ("5.7.1", "Create administrative boundaries between resources using namespaces",
     "L1", "manual", "medium", "policies"),
    ("5.7.2", "Ensure that the seccomp profile is set to docker/default in your Pod definitions",
     "L2", "manual", "medium", "policies"),
    ("5.7.3", "Apply SecurityContext to your Pods and Containers",
     "L2", "manual", "medium", "policies"),
    ("5.7.4", "Ensure the default namespace is not actively used",
     "L1", "automated", "medium", "policies"),
]


def get_kubernetes_cis_registry():
    """Return the complete CIS Kubernetes control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in KUBERNETES_CIS_CONTROLS
    ]


def get_kubernetes_control_count():
    """Return total number of CIS Kubernetes controls."""
    return len(KUBERNETES_CIS_CONTROLS)


def get_kubernetes_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in KUBERNETES_CIS_CONTROLS if c[3] == "automated")


def get_kubernetes_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in KUBERNETES_CIS_CONTROLS if c[3] == "manual")


def get_kubernetes_controls_by_section(section_prefix):
    """Return controls matching a section prefix (e.g., '1.1', '5.2')."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in KUBERNETES_CIS_CONTROLS
        if ctrl[0].startswith(section_prefix)
    ]


def get_kubernetes_controls_by_severity(severity):
    """Return controls matching a given severity level."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in KUBERNETES_CIS_CONTROLS
        if ctrl[4] == severity
    ]


def get_kubernetes_controls_by_service_area(service_area):
    """Return controls matching a given service area."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in KUBERNETES_CIS_CONTROLS
        if ctrl[5] == service_area
    ]
