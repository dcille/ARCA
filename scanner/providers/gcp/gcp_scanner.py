"""GCP Security Scanner.

Implements security checks for Google Cloud Platform services.
"""
import logging
from typing import Optional

from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)


class GCPScanner:
    """GCP cloud security scanner."""

    def __init__(self, credentials: dict, services: Optional[list] = None):
        self.credentials = credentials
        self.services = services
        self.project_id = credentials.get("project_id")

    def _get_credentials(self):
        from google.oauth2 import service_account
        import json
        cred_info = self.credentials.get("service_account_key")
        if isinstance(cred_info, str):
            cred_info = json.loads(cred_info)
        return service_account.Credentials.from_service_account_info(cred_info)

    def scan(self) -> list[dict]:
        results = []
        check_methods = {
            "iam": self._check_iam,
            "compute": self._check_compute,
            "storage": self._check_storage,
            "sql": self._check_sql,
            "logging": self._check_logging,
            "kms": self._check_kms,
            "gke": self._check_gke,
            "networking": self._check_networking,
        }

        for service_name, check_fn in check_methods.items():
            if self.services and service_name not in self.services:
                continue
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.warning(f"GCP {service_name} checks failed: {e}")

        return results

    def _check_iam(self) -> list[dict]:
        results = []
        try:
            from google.cloud import resourcemanager_v3
            credentials = self._get_credentials()
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)

            from google.iam.v1 import iam_policy_pb2
            policy = client.get_iam_policy(
                request=iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{self.project_id}")
            )

            for binding in policy.bindings:
                for member in binding.members:
                    if member == "allUsers" or member == "allAuthenticatedUsers":
                        results.append(CheckResult(
                            check_id="gcp_iam_no_public_access",
                            check_title="IAM policy does not grant public access",
                            service="iam", severity="critical", status="FAIL",
                            resource_id=f"projects/{self.project_id}",
                            status_extended=f"Role {binding.role} is granted to {member}",
                            remediation="Remove allUsers and allAuthenticatedUsers from IAM bindings",
                            compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                        ).to_dict())

        except Exception as e:
            logger.warning(f"GCP IAM checks failed: {e}")
        return results

    def _check_compute(self) -> list[dict]:
        results = []
        try:
            from google.cloud import compute_v1
            credentials = self._get_credentials()
            instances_client = compute_v1.InstancesClient(credentials=credentials)

            agg = instances_client.aggregated_list(project=self.project_id)
            for zone, response in agg:
                for instance in response.instances or []:
                    name = instance.name
                    zone_name = zone.split("/")[-1]

                    has_ext_ip = any(
                        ac.nat_i_p for ni in instance.network_interfaces or []
                        for ac in ni.access_configs or []
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_no_external_ip",
                        check_title="VM instance has no external IP",
                        service="compute", severity="medium",
                        status="FAIL" if has_ext_ip else "PASS",
                        resource_id=f"projects/{self.project_id}/zones/{zone_name}/instances/{name}",
                        resource_name=name,
                        status_extended=f"Instance {name} external IP: {has_ext_ip}",
                        remediation="Remove external IP addresses from instances that don't need them",
                        compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                    ).to_dict())

                    os_login = any(
                        item.key == "enable-oslogin" and item.value.lower() == "true"
                        for item in (instance.metadata.items or []) if instance.metadata
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_os_login",
                        check_title="VM instance has OS Login enabled",
                        service="compute", severity="medium",
                        status="PASS" if os_login else "FAIL",
                        resource_id=f"projects/{self.project_id}/zones/{zone_name}/instances/{name}",
                        resource_name=name,
                        status_extended=f"Instance {name} OS Login: {os_login}",
                        remediation="Enable OS Login for centralized SSH key management",
                        compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP compute checks failed: {e}")
        return results

    def _check_storage(self) -> list[dict]:
        results = []
        try:
            from google.cloud import storage
            credentials = self._get_credentials()
            client = storage.Client(credentials=credentials, project=self.project_id)

            buckets = list(client.list_buckets())
            for bucket in buckets:
                name = bucket.name

                uniform_access = bucket.iam_configuration.uniform_bucket_level_access_enabled
                results.append(CheckResult(
                    check_id="gcp_storage_uniform_access",
                    check_title="Bucket has uniform bucket-level access",
                    service="storage", severity="medium",
                    status="PASS" if uniform_access else "FAIL",
                    resource_id=f"gs://{name}", resource_name=name,
                    status_extended=f"Bucket {name} uniform access: {uniform_access}",
                    remediation="Enable uniform bucket-level access",
                    compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                ).to_dict())

                versioning = bucket.versioning_enabled
                results.append(CheckResult(
                    check_id="gcp_storage_versioning",
                    check_title="Bucket has versioning enabled",
                    service="storage", severity="low",
                    status="PASS" if versioning else "FAIL",
                    resource_id=f"gs://{name}", resource_name=name,
                    status_extended=f"Bucket {name} versioning: {versioning}",
                    remediation="Enable versioning for data protection",
                    compliance_frameworks=["NIST-800-53", "SOC2"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP storage checks failed: {e}")
        return results

    def _check_sql(self) -> list[dict]:
        results = []
        try:
            from googleapiclient.discovery import build
            credentials = self._get_credentials()
            service = build("sqladmin", "v1beta4", credentials=credentials)

            instances = service.instances().list(project=self.project_id).execute()
            for instance in instances.get("items", []):
                name = instance["name"]
                settings = instance.get("settings", {})

                ip_config = settings.get("ipConfiguration", {})
                public_ip = ip_config.get("ipv4Enabled", True)
                results.append(CheckResult(
                    check_id="gcp_sql_no_public_ip",
                    check_title="Cloud SQL instance has no public IP",
                    service="sql", severity="high",
                    status="FAIL" if public_ip else "PASS",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} public IP: {public_ip}",
                    remediation="Disable public IP for the Cloud SQL instance",
                    compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                ).to_dict())

                ssl_required = ip_config.get("requireSsl", False)
                results.append(CheckResult(
                    check_id="gcp_sql_ssl_required",
                    check_title="Cloud SQL instance requires SSL",
                    service="sql", severity="high",
                    status="PASS" if ssl_required else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} SSL required: {ssl_required}",
                    remediation="Enable SSL/TLS requirement for connections",
                    compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53", "PCI-DSS-3.2.1"],
                ).to_dict())

                backup = settings.get("backupConfiguration", {})
                backup_enabled = backup.get("enabled", False)
                results.append(CheckResult(
                    check_id="gcp_sql_backup_enabled",
                    check_title="Cloud SQL instance has backups enabled",
                    service="sql", severity="medium",
                    status="PASS" if backup_enabled else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} backups: {backup_enabled}",
                    remediation="Enable automated backups for the SQL instance",
                    compliance_frameworks=["NIST-800-53", "SOC2"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP SQL checks failed: {e}")
        return results

    def _check_logging(self) -> list[dict]:
        results = []
        try:
            from google.cloud import logging as gcp_logging
            credentials = self._get_credentials()
            client = gcp_logging.Client(credentials=credentials, project=self.project_id)

            sinks = list(client.list_sinks())
            results.append(CheckResult(
                check_id="gcp_logging_sinks_configured",
                check_title="Log sinks are configured",
                service="logging", severity="medium",
                status="PASS" if sinks else "FAIL",
                resource_id=f"projects/{self.project_id}",
                status_extended=f"Project has {len(sinks)} log sink(s)",
                remediation="Configure log sinks for log export and retention",
                compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"GCP logging checks failed: {e}")
        return results

    def _check_kms(self) -> list[dict]:
        results = []
        try:
            from google.cloud import kms
            credentials = self._get_credentials()
            client = kms.KeyManagementServiceClient(credentials=credentials)

            parent = f"projects/{self.project_id}/locations/-"
            key_rings = list(client.list_key_rings(request={"parent": parent}))

            for ring in key_rings:
                keys = list(client.list_crypto_keys(request={"parent": ring.name}))
                for key in keys:
                    rotation = key.rotation_period
                    has_rotation = rotation is not None and rotation.total_seconds() <= 7776000  # 90 days
                    results.append(CheckResult(
                        check_id="gcp_kms_key_rotation",
                        check_title="KMS key has rotation period of 90 days or less",
                        service="kms", severity="medium",
                        status="PASS" if has_rotation else "FAIL",
                        resource_id=key.name, resource_name=key.name.split("/")[-1],
                        status_extended=f"KMS key rotation configured: {has_rotation}",
                        remediation="Set key rotation period to 90 days or less",
                        compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP KMS checks failed: {e}")
        return results

    def _check_gke(self) -> list[dict]:
        results = []
        try:
            from google.cloud import container_v1
            credentials = self._get_credentials()
            client = container_v1.ClusterManagerClient(credentials=credentials)

            parent = f"projects/{self.project_id}/locations/-"
            response = client.list_clusters(request={"parent": parent})

            for cluster in response.clusters:
                name = cluster.name
                location = cluster.location

                private_cluster = cluster.private_cluster_config and cluster.private_cluster_config.enable_private_nodes
                results.append(CheckResult(
                    check_id="gcp_gke_private_cluster",
                    check_title="GKE cluster uses private nodes",
                    service="gke", severity="high",
                    status="PASS" if private_cluster else "FAIL",
                    resource_id=f"projects/{self.project_id}/locations/{location}/clusters/{name}",
                    resource_name=name,
                    status_extended=f"GKE cluster {name} private nodes: {private_cluster}",
                    remediation="Enable private nodes for the GKE cluster",
                    compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                ).to_dict())

                network_policy = cluster.network_policy and cluster.network_policy.enabled
                results.append(CheckResult(
                    check_id="gcp_gke_network_policy",
                    check_title="GKE cluster has network policy enabled",
                    service="gke", severity="medium",
                    status="PASS" if network_policy else "FAIL",
                    resource_id=f"projects/{self.project_id}/locations/{location}/clusters/{name}",
                    resource_name=name,
                    status_extended=f"GKE cluster {name} network policy: {network_policy}",
                    remediation="Enable network policy for pod-level network security",
                    compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP GKE checks failed: {e}")
        return results

    def _check_networking(self) -> list[dict]:
        results = []
        try:
            from google.cloud import compute_v1
            credentials = self._get_credentials()
            firewalls_client = compute_v1.FirewallsClient(credentials=credentials)

            firewalls = firewalls_client.list(project=self.project_id)
            for fw in firewalls:
                if fw.direction != "INGRESS":
                    continue
                for src_range in fw.source_ranges or []:
                    if src_range == "0.0.0.0/0":
                        for allowed in fw.allowed or []:
                            for port in allowed.ports or []:
                                if port in ("22", "3389"):
                                    results.append(CheckResult(
                                        check_id=f"gcp_firewall_open_{port}",
                                        check_title=f"Firewall rule allows unrestricted access to port {port}",
                                        service="networking", severity="high",
                                        status="FAIL",
                                        resource_id=fw.self_link, resource_name=fw.name,
                                        status_extended=f"Firewall {fw.name} allows 0.0.0.0/0 on port {port}",
                                        remediation=f"Restrict port {port} to specific source IP ranges",
                                        compliance_frameworks=["CIS-GCP-2.0", "NIST-800-53"],
                                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP networking checks failed: {e}")
        return results
