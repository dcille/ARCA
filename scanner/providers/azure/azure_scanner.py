"""Azure Security Scanner.

Implements security checks for Azure services following CIS and NIST frameworks.
"""
import logging
from typing import Optional

from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)


class AzureScanner:
    """Azure cloud security scanner."""

    def __init__(self, credentials: dict, services: Optional[list] = None):
        self.credentials = credentials
        self.services = services
        self.subscription_id = credentials.get("subscription_id")
        self.tenant_id = credentials.get("tenant_id")
        self.client_id = credentials.get("client_id")
        self.client_secret = credentials.get("client_secret")

    def _get_credential(self):
        from azure.identity import ClientSecretCredential
        return ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

    def scan(self) -> list[dict]:
        results = []
        check_methods = {
            "identity": self._check_identity,
            "storage": self._check_storage,
            "network": self._check_network,
            "compute": self._check_compute,
            "database": self._check_database,
            "keyvault": self._check_keyvault,
            "monitor": self._check_monitor,
            "appservice": self._check_appservice,
        }

        for service_name, check_fn in check_methods.items():
            if self.services and service_name not in self.services:
                continue
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.warning(f"Azure {service_name} checks failed: {e}")

        return results

    def _check_identity(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
            credential = self._get_credential()
            auth_client = AuthorizationManagementClient(credential, self.subscription_id)

            role_assignments = list(auth_client.role_assignments.list())
            owner_count = sum(1 for ra in role_assignments if "Owner" in str(ra.role_definition_id))

            results.append(CheckResult(
                check_id="azure_iam_owner_count",
                check_title="Subscription has limited number of owners",
                service="identity", severity="high",
                status="PASS" if owner_count <= 3 else "FAIL",
                resource_id=self.subscription_id,
                status_extended=f"Subscription has {owner_count} owner role assignments",
                remediation="Limit the number of subscription owners to 3 or fewer",
                compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"Azure identity checks failed: {e}")
        return results

    def _check_storage(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.storage import StorageManagementClient
            credential = self._get_credential()
            storage_client = StorageManagementClient(credential, self.subscription_id)

            accounts = list(storage_client.storage_accounts.list())
            for account in accounts:
                name = account.name
                resource_id = account.id

                https_only = account.enable_https_traffic_only
                results.append(CheckResult(
                    check_id="azure_storage_https_only",
                    check_title="Storage account requires HTTPS",
                    service="storage", severity="high",
                    status="PASS" if https_only else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"Storage account {name} HTTPS only: {https_only}",
                    remediation="Enable HTTPS-only traffic for the storage account",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                ).to_dict())

                min_tls = account.minimum_tls_version
                results.append(CheckResult(
                    check_id="azure_storage_tls_12",
                    check_title="Storage account uses TLS 1.2",
                    service="storage", severity="high",
                    status="PASS" if min_tls == "TLS1_2" else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"Storage account {name} minimum TLS: {min_tls}",
                    remediation="Set minimum TLS version to 1.2",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53", "PCI-DSS-3.2.1"],
                ).to_dict())

                public_access = account.allow_blob_public_access
                results.append(CheckResult(
                    check_id="azure_storage_no_public_access",
                    check_title="Storage account blocks public blob access",
                    service="storage", severity="high",
                    status="PASS" if not public_access else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"Storage account {name} public blob access: {public_access}",
                    remediation="Disable public blob access for the storage account",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Azure storage checks failed: {e}")
        return results

    def _check_network(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.network import NetworkManagementClient
            credential = self._get_credential()
            network_client = NetworkManagementClient(credential, self.subscription_id)

            nsgs = list(network_client.network_security_groups.list_all())
            for nsg in nsgs:
                for rule in nsg.security_rules or []:
                    if (rule.direction == "Inbound" and rule.access == "Allow"
                            and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")):
                        port = rule.destination_port_range
                        if port in ("22", "3389", "*"):
                            results.append(CheckResult(
                                check_id=f"azure_nsg_open_port_{port}",
                                check_title=f"NSG allows unrestricted inbound on port {port}",
                                service="network", severity="high",
                                status="FAIL",
                                resource_id=nsg.id, resource_name=nsg.name,
                                status_extended=f"NSG {nsg.name} rule {rule.name} allows 0.0.0.0/0 on port {port}",
                                remediation=f"Restrict inbound access on port {port} to specific IPs",
                                compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                            ).to_dict())

            watchers = list(network_client.network_watchers.list_all())
            results.append(CheckResult(
                check_id="azure_network_watcher_enabled",
                check_title="Network Watcher is enabled",
                service="network", severity="medium",
                status="PASS" if watchers else "FAIL",
                resource_id=self.subscription_id,
                status_extended=f"Network Watcher instances: {len(watchers)}",
                remediation="Enable Network Watcher in all regions",
                compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"Azure network checks failed: {e}")
        return results

    def _check_compute(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.compute import ComputeManagementClient
            credential = self._get_credential()
            compute_client = ComputeManagementClient(credential, self.subscription_id)

            vms = list(compute_client.virtual_machines.list_all())
            for vm in vms:
                name = vm.name
                resource_id = vm.id

                os_disk = vm.storage_profile.os_disk
                encrypted = os_disk.managed_disk and os_disk.managed_disk.disk_encryption_set
                results.append(CheckResult(
                    check_id="azure_vm_disk_encryption",
                    check_title="VM has disk encryption enabled",
                    service="compute", severity="high",
                    status="PASS" if encrypted else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"VM {name} disk encryption: {'enabled' if encrypted else 'not configured'}",
                    remediation="Enable Azure Disk Encryption or use encrypted managed disks",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53", "HIPAA"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Azure compute checks failed: {e}")
        return results

    def _check_database(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.sql import SqlManagementClient
            credential = self._get_credential()
            sql_client = SqlManagementClient(credential, self.subscription_id)

            servers = list(sql_client.servers.list())
            for server in servers:
                rg = server.id.split("/")[4]
                name = server.name

                auditing = sql_client.server_blob_auditing_policies.get(rg, name)
                results.append(CheckResult(
                    check_id="azure_sql_auditing_enabled",
                    check_title="SQL Server has auditing enabled",
                    service="database", severity="high",
                    status="PASS" if auditing.state == "Enabled" else "FAIL",
                    resource_id=server.id, resource_name=name,
                    status_extended=f"SQL Server {name} auditing: {auditing.state}",
                    remediation="Enable auditing for the SQL Server",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53", "PCI-DSS-3.2.1"],
                ).to_dict())

                tde_check = server.minimal_tls_version
                results.append(CheckResult(
                    check_id="azure_sql_tls_12",
                    check_title="SQL Server requires TLS 1.2",
                    service="database", severity="high",
                    status="PASS" if tde_check == "1.2" else "FAIL",
                    resource_id=server.id, resource_name=name,
                    status_extended=f"SQL Server {name} minimum TLS: {tde_check}",
                    remediation="Set minimum TLS version to 1.2",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Azure database checks failed: {e}")
        return results

    def _check_keyvault(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            credential = self._get_credential()
            kv_client = KeyVaultManagementClient(credential, self.subscription_id)

            vaults = list(kv_client.vaults.list())
            for vault in vaults:
                name = vault.name
                resource_id = vault.id
                props = vault.properties

                soft_delete = props.enable_soft_delete if props else False
                purge_protection = props.enable_purge_protection if props else False

                results.append(CheckResult(
                    check_id="azure_keyvault_soft_delete",
                    check_title="Key Vault has soft delete enabled",
                    service="keyvault", severity="medium",
                    status="PASS" if soft_delete else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"Key Vault {name} soft delete: {soft_delete}",
                    remediation="Enable soft delete for the Key Vault",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                ).to_dict())

                results.append(CheckResult(
                    check_id="azure_keyvault_purge_protection",
                    check_title="Key Vault has purge protection enabled",
                    service="keyvault", severity="medium",
                    status="PASS" if purge_protection else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"Key Vault {name} purge protection: {purge_protection}",
                    remediation="Enable purge protection for the Key Vault",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Azure keyvault checks failed: {e}")
        return results

    def _check_monitor(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.monitor import MonitorManagementClient
            credential = self._get_credential()
            monitor_client = MonitorManagementClient(credential, self.subscription_id)

            log_profiles = list(monitor_client.log_profiles.list())
            results.append(CheckResult(
                check_id="azure_monitor_log_profile",
                check_title="Activity log profile is configured",
                service="monitor", severity="medium",
                status="PASS" if log_profiles else "FAIL",
                resource_id=self.subscription_id,
                status_extended=f"Activity log profiles: {len(log_profiles)}",
                remediation="Configure an activity log profile for monitoring",
                compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"Azure monitor checks failed: {e}")
        return results

    def _check_appservice(self) -> list[dict]:
        results = []
        try:
            from azure.mgmt.web import WebSiteManagementClient
            credential = self._get_credential()
            web_client = WebSiteManagementClient(credential, self.subscription_id)

            apps = list(web_client.web_apps.list())
            for app in apps:
                name = app.name
                resource_id = app.id

                https_only = app.https_only
                results.append(CheckResult(
                    check_id="azure_appservice_https_only",
                    check_title="App Service requires HTTPS",
                    service="appservice", severity="high",
                    status="PASS" if https_only else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"App Service {name} HTTPS only: {https_only}",
                    remediation="Enable HTTPS-only for the App Service",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                ).to_dict())

                min_tls = app.site_config.min_tls_version if app.site_config else None
                results.append(CheckResult(
                    check_id="azure_appservice_tls_12",
                    check_title="App Service uses TLS 1.2",
                    service="appservice", severity="high",
                    status="PASS" if min_tls == "1.2" else "FAIL",
                    resource_id=resource_id, resource_name=name,
                    status_extended=f"App Service {name} minimum TLS: {min_tls}",
                    remediation="Set minimum TLS version to 1.2",
                    compliance_frameworks=["CIS-Azure-2.0", "NIST-800-53"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Azure appservice checks failed: {e}")
        return results
