"""DSPM Permission Analyzer — effective access analysis for data stores."""
import logging
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AccessPrincipal:
    principal_type: str  # user, role, group, service_account, federated
    principal_id: str
    principal_name: str
    provider: str
    is_admin: bool = False
    source: str = "direct"  # direct, inherited, assumed_role, group_membership


@dataclass
class EffectivePermission:
    principal: AccessPrincipal
    actions: list[str] = field(default_factory=list)
    effect: str = "allow"
    resource_pattern: str = "*"
    conditions: dict = field(default_factory=dict)
    is_cross_account: bool = False
    is_public: bool = False


@dataclass
class DataStoreAccessReport:
    store_type: str
    resource_id: str
    resource_name: str
    provider: str
    region: str = ""
    total_principals: int = 0
    admin_principals: int = 0
    cross_account_principals: int = 0
    public_access: bool = False
    permissions: list[EffectivePermission] = field(default_factory=list)
    risk_level: str = "low"
    risk_factors: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
# S3 admin-level actions used to detect admin principals
# ═══════════════════════════════════════════════════════════════════════

_S3_ADMIN_ACTIONS = {
    "s3:*",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutBucketPublicAccessBlock",
}

_AZURE_STORAGE_ADMIN_ROLES = {
    "Storage Account Contributor",
    "Owner",
    "Contributor",
}

_GCS_ADMIN_ROLES = {
    "roles/storage.admin",
    "roles/owner",
    "roles/editor",
}


# ═══════════════════════════════════════════════════════════════════════
# PermissionAnalyzer
# ═══════════════════════════════════════════════════════════════════════

class PermissionAnalyzer:
    """Analyses effective permissions on cloud data stores."""

    # ── public dispatcher ────────────────────────────────────────────

    def analyze_store(
        self,
        store_type: str,
        resource_id: str,
        **kwargs,
    ) -> DataStoreAccessReport:
        """Dispatch to the correct provider-specific analyzer."""
        dispatch = {
            "s3": self.analyze_s3_bucket,
            "rds": self.analyze_rds_instance,
            "azure_storage": self.analyze_azure_storage,
            "azure_sql": self.analyze_azure_sql,
            "gcs": self.analyze_gcs_bucket,
            "cloud_sql": self.analyze_cloud_sql,
        }
        handler = dispatch.get(store_type)
        if handler is None:
            logger.warning("Unsupported store_type=%s", store_type)
            return DataStoreAccessReport(
                store_type=store_type,
                resource_id=resource_id,
                resource_name=resource_id,
                provider="unknown",
                risk_level="unknown",
                risk_factors=[f"Unsupported store type: {store_type}"],
            )
        return handler(resource_id, **kwargs)

    # ── AWS S3 ───────────────────────────────────────────────────────

    def analyze_s3_bucket(
        self,
        bucket_name: str,
        credentials: Optional[dict] = None,
        region: str = "us-east-1",
    ) -> DataStoreAccessReport:
        """Analyse effective permissions on an S3 bucket."""
        try:
            import boto3
        except ImportError:
            logger.error("boto3 is required for S3 permission analysis")
            return DataStoreAccessReport(
                store_type="s3",
                resource_id=bucket_name,
                resource_name=bucket_name,
                provider="aws",
                region=region,
                risk_level="unknown",
                risk_factors=["boto3 SDK not installed"],
            )

        session_kwargs = {}
        if credentials:
            session_kwargs.update({
                "aws_access_key_id": credentials.get("access_key"),
                "aws_secret_access_key": credentials.get("secret_key"),
                "aws_session_token": credentials.get("session_token"),
            })
        session = boto3.Session(region_name=region, **session_kwargs)
        s3_client = session.client("s3")
        iam_client = session.client("iam")
        sts_client = session.client("sts")

        permissions: list[EffectivePermission] = []

        # Determine account ID for cross-account detection
        try:
            caller = sts_client.get_caller_identity()
            own_account_id = caller.get("Account", "")
        except Exception:
            own_account_id = ""

        # 1. Bucket policy
        policy_perms = self._parse_s3_bucket_policy(s3_client, bucket_name, own_account_id)
        permissions.extend(policy_perms)

        # 2. ACLs
        acl_perms = self._parse_s3_acl(s3_client, bucket_name, own_account_id)
        permissions.extend(acl_perms)

        # 3. Block Public Access
        public_block = self._check_public_access_block(s3_client, bucket_name)

        # 4. IAM entities with s3 access
        iam_perms = self._get_iam_entities_with_s3_access(iam_client, bucket_name)
        permissions.extend(iam_perms)

        # Build report
        report = DataStoreAccessReport(
            store_type="s3",
            resource_id=bucket_name,
            resource_name=bucket_name,
            provider="aws",
            region=region,
            permissions=permissions,
        )
        report.public_access = any(p.is_public for p in permissions) and not public_block
        report.total_principals = len({p.principal.principal_id for p in permissions})
        report.admin_principals = len({
            p.principal.principal_id for p in permissions
            if p.principal.is_admin
        })
        report.cross_account_principals = len({
            p.principal.principal_id for p in permissions
            if p.is_cross_account
        })

        report.risk_level = self._calculate_risk_level(report)
        self._add_risk_factors_and_recommendations(report, public_block)
        return report

    # ── AWS RDS ──────────────────────────────────────────────────────

    def analyze_rds_instance(
        self,
        instance_id: str,
        credentials: Optional[dict] = None,
        region: str = "us-east-1",
    ) -> DataStoreAccessReport:
        """Analyse effective permissions on an RDS instance."""
        try:
            import boto3
        except ImportError:
            logger.error("boto3 is required for RDS permission analysis")
            return DataStoreAccessReport(
                store_type="rds",
                resource_id=instance_id,
                resource_name=instance_id,
                provider="aws",
                region=region,
                risk_level="unknown",
                risk_factors=["boto3 SDK not installed"],
            )

        session_kwargs = {}
        if credentials:
            session_kwargs.update({
                "aws_access_key_id": credentials.get("access_key"),
                "aws_secret_access_key": credentials.get("secret_key"),
                "aws_session_token": credentials.get("session_token"),
            })
        session = boto3.Session(region_name=region, **session_kwargs)
        rds_client = session.client("rds")
        ec2_client = session.client("ec2")

        permissions: list[EffectivePermission] = []
        risk_factors: list[str] = []
        recommendations: list[str] = []

        try:
            resp = rds_client.describe_db_instances(DBInstanceIdentifier=instance_id)
            instances = resp.get("DBInstances", [])
            if not instances:
                logger.warning("RDS instance %s not found", instance_id)
                return DataStoreAccessReport(
                    store_type="rds", resource_id=instance_id,
                    resource_name=instance_id, provider="aws", region=region,
                    risk_level="unknown",
                    risk_factors=["Instance not found"],
                )
            db = instances[0]
        except Exception as exc:
            logger.error("Failed to describe RDS instance %s: %s", instance_id, exc)
            return DataStoreAccessReport(
                store_type="rds", resource_id=instance_id,
                resource_name=instance_id, provider="aws", region=region,
                risk_level="unknown",
                risk_factors=[f"API error: {exc}"],
            )

        resource_name = db.get("DBInstanceIdentifier", instance_id)

        # Public accessibility
        publicly_accessible = db.get("PubliclyAccessible", False)
        if publicly_accessible:
            risk_factors.append("Instance is publicly accessible")
            recommendations.append("Disable public accessibility for the RDS instance")
            permissions.append(EffectivePermission(
                principal=AccessPrincipal(
                    principal_type="federated",
                    principal_id="*",
                    principal_name="Public (Internet)",
                    provider="aws",
                ),
                actions=["rds-db:connect"],
                effect="allow",
                resource_pattern=instance_id,
                is_public=True,
            ))

        # Security groups
        for sg_membership in db.get("VpcSecurityGroups", []):
            sg_id = sg_membership.get("VpcSecurityGroupId", "")
            try:
                sg_resp = ec2_client.describe_security_groups(GroupIds=[sg_id])
                for sg in sg_resp.get("SecurityGroups", []):
                    for rule in sg.get("IpPermissions", []):
                        for ip_range in rule.get("IpRanges", []):
                            cidr = ip_range.get("CidrIp", "")
                            if cidr == "0.0.0.0/0":
                                risk_factors.append(
                                    f"Security group {sg_id} allows inbound from 0.0.0.0/0"
                                )
                                recommendations.append(
                                    f"Restrict inbound rules in security group {sg_id}"
                                )
                                permissions.append(EffectivePermission(
                                    principal=AccessPrincipal(
                                        principal_type="federated",
                                        principal_id="0.0.0.0/0",
                                        principal_name="Any IPv4",
                                        provider="aws",
                                    ),
                                    actions=["network:inbound"],
                                    effect="allow",
                                    resource_pattern=sg_id,
                                    is_public=True,
                                ))
            except Exception as exc:
                logger.warning("Could not describe SG %s: %s", sg_id, exc)

        # IAM authentication
        iam_auth = db.get("IAMDatabaseAuthenticationEnabled", False)
        if not iam_auth:
            risk_factors.append("IAM database authentication is not enabled")
            recommendations.append("Enable IAM database authentication")

        report = DataStoreAccessReport(
            store_type="rds",
            resource_id=instance_id,
            resource_name=resource_name,
            provider="aws",
            region=region,
            permissions=permissions,
            risk_factors=risk_factors,
            recommendations=recommendations,
            public_access=publicly_accessible,
            total_principals=len({p.principal.principal_id for p in permissions}),
        )
        report.risk_level = self._calculate_risk_level(report)
        return report

    # ── Azure Storage ────────────────────────────────────────────────

    def analyze_azure_storage(
        self,
        storage_account: str,
        credentials: Optional[dict] = None,
    ) -> DataStoreAccessReport:
        """Analyse effective permissions on an Azure Storage account."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.storage import StorageManagementClient
        except ImportError:
            logger.error("Azure SDK packages are required for Azure storage analysis")
            return DataStoreAccessReport(
                store_type="azure_storage",
                resource_id=storage_account,
                resource_name=storage_account,
                provider="azure",
                risk_level="unknown",
                risk_factors=["Azure SDK not installed"],
            )

        subscription_id = (credentials or {}).get("subscription_id", "")
        resource_group = (credentials or {}).get("resource_group", "")

        credential = DefaultAzureCredential()
        storage_client = StorageManagementClient(credential, subscription_id)
        auth_client = AuthorizationManagementClient(credential, subscription_id)

        permissions: list[EffectivePermission] = []
        risk_factors: list[str] = []
        recommendations: list[str] = []

        # Retrieve account properties
        try:
            account = storage_client.storage_accounts.get_properties(
                resource_group, storage_account,
            )
        except Exception as exc:
            logger.error("Failed to get storage account %s: %s", storage_account, exc)
            return DataStoreAccessReport(
                store_type="azure_storage",
                resource_id=storage_account,
                resource_name=storage_account,
                provider="azure",
                risk_level="unknown",
                risk_factors=[f"API error: {exc}"],
            )

        # Network rules
        network_rules = getattr(account, "network_rule_set", None)
        if network_rules:
            default_action = getattr(network_rules, "default_action", "Allow")
            if default_action == "Allow":
                risk_factors.append("Network default action is Allow (open to all networks)")
                recommendations.append(
                    "Set network default action to Deny and add explicit allow rules"
                )

        # Public blob access
        allow_blob_public = getattr(account, "allow_blob_public_access", False)
        if allow_blob_public:
            risk_factors.append("Public blob access is allowed on the storage account")
            recommendations.append("Disable public blob access on the storage account")

        # HTTPS only
        https_only = getattr(account, "enable_https_traffic_only", True)
        if not https_only:
            risk_factors.append("HTTPS-only traffic is not enforced")
            recommendations.append("Enable HTTPS-only traffic")

        # RBAC assignments
        scope = (
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Storage/storageAccounts/{storage_account}"
        )
        rbac_perms = self._get_storage_rbac_assignments(auth_client, scope)
        permissions.extend(rbac_perms)

        # SAS policy check (account-level)
        sas_policy = getattr(account, "sas_policy", None)
        if sas_policy is None:
            risk_factors.append("No SAS expiration policy configured")
            recommendations.append(
                "Configure a SAS expiration policy to limit shared access signature lifetime"
            )

        report = DataStoreAccessReport(
            store_type="azure_storage",
            resource_id=storage_account,
            resource_name=storage_account,
            provider="azure",
            permissions=permissions,
            risk_factors=risk_factors,
            recommendations=recommendations,
            public_access=allow_blob_public,
            total_principals=len({p.principal.principal_id for p in permissions}),
            admin_principals=len({
                p.principal.principal_id for p in permissions
                if p.principal.is_admin
            }),
        )
        report.risk_level = self._calculate_risk_level(report)
        return report

    # ── Azure SQL ────────────────────────────────────────────────────

    def analyze_azure_sql(
        self,
        server_name: str,
        credentials: Optional[dict] = None,
    ) -> DataStoreAccessReport:
        """Analyse effective permissions on an Azure SQL server."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.sql import SqlManagementClient
        except ImportError:
            logger.error("Azure SDK packages are required for Azure SQL analysis")
            return DataStoreAccessReport(
                store_type="azure_sql",
                resource_id=server_name,
                resource_name=server_name,
                provider="azure",
                risk_level="unknown",
                risk_factors=["Azure SDK not installed"],
            )

        subscription_id = (credentials or {}).get("subscription_id", "")
        resource_group = (credentials or {}).get("resource_group", "")

        credential = DefaultAzureCredential()
        sql_client = SqlManagementClient(credential, subscription_id)

        risk_factors: list[str] = []
        recommendations: list[str] = []
        permissions: list[EffectivePermission] = []

        # Firewall rules
        try:
            fw_rules = sql_client.firewall_rules.list_by_server(resource_group, server_name)
            for rule in fw_rules:
                start_ip = getattr(rule, "start_ip_address", "")
                end_ip = getattr(rule, "end_ip_address", "")
                if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
                    risk_factors.append(
                        f"Firewall rule '{rule.name}' allows all IP addresses"
                    )
                    recommendations.append(
                        f"Restrict firewall rule '{rule.name}' to specific IP ranges"
                    )
                    permissions.append(EffectivePermission(
                        principal=AccessPrincipal(
                            principal_type="federated",
                            principal_id="0.0.0.0/0",
                            principal_name="Any IPv4",
                            provider="azure",
                        ),
                        actions=["sql:connect"],
                        effect="allow",
                        resource_pattern=server_name,
                        is_public=True,
                    ))
                elif start_ip == "0.0.0.0" and end_ip == "0.0.0.0":
                    risk_factors.append("Allow Azure services rule is enabled")
                    recommendations.append(
                        "Disable 'Allow Azure services' unless explicitly required"
                    )
        except Exception as exc:
            logger.warning("Could not list firewall rules for %s: %s", server_name, exc)

        # AD admin
        try:
            ad_admins = sql_client.server_azure_ad_administrators.list_by_server(
                resource_group, server_name,
            )
            ad_admin_found = False
            for admin in ad_admins:
                ad_admin_found = True
                permissions.append(EffectivePermission(
                    principal=AccessPrincipal(
                        principal_type="user",
                        principal_id=getattr(admin, "sid", ""),
                        principal_name=getattr(admin, "login", ""),
                        provider="azure",
                        is_admin=True,
                    ),
                    actions=["sql:*"],
                    effect="allow",
                    resource_pattern=server_name,
                ))
            if not ad_admin_found:
                risk_factors.append("No Azure AD administrator is configured")
                recommendations.append("Configure an Azure AD administrator for the SQL server")
        except Exception as exc:
            logger.warning("Could not list AD admins for %s: %s", server_name, exc)

        report = DataStoreAccessReport(
            store_type="azure_sql",
            resource_id=server_name,
            resource_name=server_name,
            provider="azure",
            permissions=permissions,
            risk_factors=risk_factors,
            recommendations=recommendations,
            public_access=any(p.is_public for p in permissions),
            total_principals=len({p.principal.principal_id for p in permissions}),
            admin_principals=len({
                p.principal.principal_id for p in permissions
                if p.principal.is_admin
            }),
        )
        report.risk_level = self._calculate_risk_level(report)
        return report

    # ── GCP Cloud Storage ────────────────────────────────────────────

    def analyze_gcs_bucket(
        self,
        bucket_name: str,
        credentials: Optional[dict] = None,
    ) -> DataStoreAccessReport:
        """Analyse effective permissions on a GCS bucket."""
        try:
            from google.cloud import storage as gcs_storage
        except ImportError:
            logger.error("google-cloud-storage is required for GCS analysis")
            return DataStoreAccessReport(
                store_type="gcs",
                resource_id=bucket_name,
                resource_name=bucket_name,
                provider="gcp",
                risk_level="unknown",
                risk_factors=["google-cloud-storage SDK not installed"],
            )

        try:
            client_kwargs = {}
            if credentials and credentials.get("project"):
                client_kwargs["project"] = credentials["project"]
            client = gcs_storage.Client(**client_kwargs)
            bucket = client.get_bucket(bucket_name)
        except Exception as exc:
            logger.error("Failed to get GCS bucket %s: %s", bucket_name, exc)
            return DataStoreAccessReport(
                store_type="gcs",
                resource_id=bucket_name,
                resource_name=bucket_name,
                provider="gcp",
                risk_level="unknown",
                risk_factors=[f"API error: {exc}"],
            )

        permissions: list[EffectivePermission] = []
        risk_factors: list[str] = []
        recommendations: list[str] = []

        # IAM bindings
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            iam_perms = self._parse_iam_bindings(policy)
            permissions.extend(iam_perms)
        except Exception as exc:
            logger.warning("Could not get IAM policy for bucket %s: %s", bucket_name, exc)

        # allUsers / allAuthenticatedUsers check
        public_access = self._check_allUsers_access(permissions)
        if public_access:
            risk_factors.append("Bucket is publicly accessible via allUsers or allAuthenticatedUsers")
            recommendations.append("Remove allUsers and allAuthenticatedUsers bindings")

        # Uniform bucket-level access
        iam_config = getattr(bucket, "iam_configuration", {})
        ubla = iam_config.get("uniformBucketLevelAccess", {}) if isinstance(iam_config, dict) else {}
        if not ubla.get("enabled", False):
            risk_factors.append("Uniform bucket-level access is not enabled")
            recommendations.append("Enable uniform bucket-level access to simplify permissions")

        report = DataStoreAccessReport(
            store_type="gcs",
            resource_id=bucket_name,
            resource_name=bucket_name,
            provider="gcp",
            permissions=permissions,
            risk_factors=risk_factors,
            recommendations=recommendations,
            public_access=public_access,
            total_principals=len({p.principal.principal_id for p in permissions}),
            admin_principals=len({
                p.principal.principal_id for p in permissions
                if p.principal.is_admin
            }),
        )
        report.risk_level = self._calculate_risk_level(report)
        return report

    # ── GCP Cloud SQL ────────────────────────────────────────────────

    def analyze_cloud_sql(
        self,
        instance_id: str,
        credentials: Optional[dict] = None,
        project: Optional[str] = None,
    ) -> DataStoreAccessReport:
        """Analyse effective permissions on a Cloud SQL instance."""
        try:
            from googleapiclient import discovery as google_discovery
        except ImportError:
            logger.error("google-api-python-client is required for Cloud SQL analysis")
            return DataStoreAccessReport(
                store_type="cloud_sql",
                resource_id=instance_id,
                resource_name=instance_id,
                provider="gcp",
                risk_level="unknown",
                risk_factors=["google-api-python-client SDK not installed"],
            )

        project = project or (credentials or {}).get("project", "")
        if not project:
            return DataStoreAccessReport(
                store_type="cloud_sql",
                resource_id=instance_id,
                resource_name=instance_id,
                provider="gcp",
                risk_level="unknown",
                risk_factors=["GCP project ID is required"],
            )

        try:
            service = google_discovery.build("sqladmin", "v1beta4")
            instance = service.instances().get(
                project=project, instance=instance_id,
            ).execute()
        except Exception as exc:
            logger.error("Failed to get Cloud SQL instance %s: %s", instance_id, exc)
            return DataStoreAccessReport(
                store_type="cloud_sql",
                resource_id=instance_id,
                resource_name=instance_id,
                provider="gcp",
                risk_level="unknown",
                risk_factors=[f"API error: {exc}"],
            )

        risk_factors: list[str] = []
        recommendations: list[str] = []
        permissions: list[EffectivePermission] = []

        # Authorized networks
        settings = instance.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        authorized_networks = ip_config.get("authorizedNetworks", [])
        for network in authorized_networks:
            cidr = network.get("value", "")
            if cidr == "0.0.0.0/0":
                risk_factors.append("Authorized network 0.0.0.0/0 allows all IP addresses")
                recommendations.append("Remove the 0.0.0.0/0 authorized network entry")
                permissions.append(EffectivePermission(
                    principal=AccessPrincipal(
                        principal_type="federated",
                        principal_id="0.0.0.0/0",
                        principal_name="Any IPv4",
                        provider="gcp",
                    ),
                    actions=["cloudsql:connect"],
                    effect="allow",
                    resource_pattern=instance_id,
                    is_public=True,
                ))

        # Public IP
        ip_addresses = instance.get("ipAddresses", [])
        has_public_ip = any(ip.get("type") == "PRIMARY" for ip in ip_addresses)
        if has_public_ip:
            risk_factors.append("Instance has a public IP address")
            recommendations.append(
                "Use private IP only and Cloud SQL Proxy for connections"
            )

        # SSL enforcement
        require_ssl = ip_config.get("requireSsl", False)
        if not require_ssl:
            risk_factors.append("SSL is not required for connections")
            recommendations.append("Enable SSL enforcement for Cloud SQL connections")

        report = DataStoreAccessReport(
            store_type="cloud_sql",
            resource_id=instance_id,
            resource_name=instance.get("name", instance_id),
            provider="gcp",
            permissions=permissions,
            risk_factors=risk_factors,
            recommendations=recommendations,
            public_access=has_public_ip and any(p.is_public for p in permissions),
            total_principals=len({p.principal.principal_id for p in permissions}),
        )
        report.risk_level = self._calculate_risk_level(report)
        return report

    # ═══════════════════════════════════════════════════════════════════
    # Private helpers — AWS
    # ═══════════════════════════════════════════════════════════════════

    def _parse_s3_bucket_policy(
        self, s3_client, bucket_name: str, own_account_id: str,
    ) -> list[EffectivePermission]:
        """Parse S3 bucket policy statements into EffectivePermission entries."""
        import json

        permissions: list[EffectivePermission] = []
        try:
            resp = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(resp.get("Policy", "{}"))
        except Exception:
            # No bucket policy or access denied
            return permissions

        for statement in policy.get("Statement", []):
            effect = statement.get("Effect", "Allow")
            principals_raw = statement.get("Principal", {})
            actions = statement.get("Action", [])
            conditions = statement.get("Condition", {})

            if isinstance(actions, str):
                actions = [actions]

            # Normalise principals
            principal_arns: list[str] = []
            if isinstance(principals_raw, str):
                principal_arns = [principals_raw]
            elif isinstance(principals_raw, dict):
                for _, v in principals_raw.items():
                    if isinstance(v, str):
                        principal_arns.append(v)
                    elif isinstance(v, list):
                        principal_arns.extend(v)

            for arn in principal_arns:
                is_public = arn == "*"
                is_cross_account = False
                principal_name = arn

                if not is_public and own_account_id:
                    # Check if the principal belongs to a different account
                    parts = arn.split(":")
                    if len(parts) >= 5 and parts[4] and parts[4] != own_account_id:
                        is_cross_account = True

                is_admin = any(a in _S3_ADMIN_ACTIONS for a in actions)

                permissions.append(EffectivePermission(
                    principal=AccessPrincipal(
                        principal_type="federated" if is_public else "role",
                        principal_id=arn,
                        principal_name=principal_name,
                        provider="aws",
                        is_admin=is_admin,
                        source="direct",
                    ),
                    actions=actions,
                    effect=effect.lower(),
                    resource_pattern=bucket_name,
                    conditions=conditions,
                    is_cross_account=is_cross_account,
                    is_public=is_public,
                ))

        return permissions

    def _parse_s3_acl(
        self, s3_client, bucket_name: str, own_account_id: str,
    ) -> list[EffectivePermission]:
        """Parse S3 bucket ACL into EffectivePermission entries."""
        permissions: list[EffectivePermission] = []
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        except Exception:
            return permissions

        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "")
            grantee_type = grantee.get("Type", "")
            uri = grantee.get("URI", "")
            grantee_id = grantee.get("ID", "")

            is_public = False
            principal_name = grantee.get("DisplayName", grantee_id)

            if uri == "http://acs.amazonaws.com/groups/global/AllUsers":
                is_public = True
                principal_name = "AllUsers (Public)"
            elif uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                is_public = True
                principal_name = "AuthenticatedUsers"

            principal_type = "group" if grantee_type == "Group" else "user"

            permissions.append(EffectivePermission(
                principal=AccessPrincipal(
                    principal_type=principal_type,
                    principal_id=grantee_id or uri,
                    principal_name=principal_name,
                    provider="aws",
                    is_admin=permission == "FULL_CONTROL",
                    source="direct",
                ),
                actions=[f"s3:{permission}"],
                effect="allow",
                resource_pattern=bucket_name,
                is_public=is_public,
            ))

        return permissions

    def _check_public_access_block(self, s3_client, bucket_name: str) -> bool:
        """Return True if Public Access Block is fully enabled (all four settings)."""
        try:
            resp = s3_client.get_public_access_block(Bucket=bucket_name)
            config = resp.get("PublicAccessBlockConfiguration", {})
            return all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
        except Exception:
            # If the call fails (e.g. NoSuchPublicAccessBlockConfiguration),
            # public access block is not enabled.
            return False

    def _get_iam_entities_with_s3_access(
        self, iam_client, bucket_name: str,
    ) -> list[EffectivePermission]:
        """Find IAM users and roles that have policies granting S3 access."""
        permissions: list[EffectivePermission] = []

        # Check IAM users
        try:
            paginator = iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    user_arn = user["Arn"]
                    try:
                        attached = iam_client.list_attached_user_policies(UserName=username)
                        for pol in attached.get("AttachedPolicies", []):
                            policy_name = pol.get("PolicyName", "")
                            if "S3" in policy_name or "s3" in policy_name or "AdministratorAccess" in policy_name:
                                is_admin = "FullAccess" in policy_name or "AdministratorAccess" in policy_name
                                permissions.append(EffectivePermission(
                                    principal=AccessPrincipal(
                                        principal_type="user",
                                        principal_id=user_arn,
                                        principal_name=username,
                                        provider="aws",
                                        is_admin=is_admin,
                                        source="direct",
                                    ),
                                    actions=["s3:*"] if is_admin else ["s3:GetObject", "s3:ListBucket"],
                                    effect="allow",
                                    resource_pattern=bucket_name,
                                ))
                    except Exception as exc:
                        logger.debug("Could not check policies for user %s: %s", username, exc)
        except Exception as exc:
            logger.warning("Could not list IAM users: %s", exc)

        # Check IAM roles
        try:
            paginator = iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    try:
                        attached = iam_client.list_attached_role_policies(RoleName=role_name)
                        for pol in attached.get("AttachedPolicies", []):
                            policy_name = pol.get("PolicyName", "")
                            if "S3" in policy_name or "s3" in policy_name or "AdministratorAccess" in policy_name:
                                is_admin = "FullAccess" in policy_name or "AdministratorAccess" in policy_name
                                permissions.append(EffectivePermission(
                                    principal=AccessPrincipal(
                                        principal_type="role",
                                        principal_id=role_arn,
                                        principal_name=role_name,
                                        provider="aws",
                                        is_admin=is_admin,
                                        source="assumed_role",
                                    ),
                                    actions=["s3:*"] if is_admin else ["s3:GetObject", "s3:ListBucket"],
                                    effect="allow",
                                    resource_pattern=bucket_name,
                                ))
                    except Exception as exc:
                        logger.debug("Could not check policies for role %s: %s", role_name, exc)
        except Exception as exc:
            logger.warning("Could not list IAM roles: %s", exc)

        return permissions

    # ═══════════════════════════════════════════════════════════════════
    # Private helpers — Azure
    # ═══════════════════════════════════════════════════════════════════

    def _get_storage_rbac_assignments(
        self, auth_client, scope: str,
    ) -> list[EffectivePermission]:
        """Fetch RBAC role assignments scoped to an Azure Storage account."""
        permissions: list[EffectivePermission] = []
        try:
            assignments = auth_client.role_assignments.list_for_scope(scope)
            for assignment in assignments:
                principal_id = getattr(assignment, "principal_id", "")
                principal_type = getattr(assignment, "principal_type", "user")
                role_def_id = getattr(assignment, "role_definition_id", "")

                # Extract role name from definition ID (last segment)
                role_name = role_def_id.rsplit("/", 1)[-1] if role_def_id else "Unknown"
                is_admin = role_name in _AZURE_STORAGE_ADMIN_ROLES

                permissions.append(EffectivePermission(
                    principal=AccessPrincipal(
                        principal_type=principal_type.lower() if principal_type else "user",
                        principal_id=principal_id,
                        principal_name=principal_id,  # Would need Graph API to resolve
                        provider="azure",
                        is_admin=is_admin,
                        source="direct",
                    ),
                    actions=[role_name],
                    effect="allow",
                    resource_pattern=scope,
                ))
        except Exception as exc:
            logger.warning("Could not list RBAC assignments for %s: %s", scope, exc)

        return permissions

    # ═══════════════════════════════════════════════════════════════════
    # Private helpers — GCP
    # ═══════════════════════════════════════════════════════════════════

    def _parse_iam_bindings(self, policy) -> list[EffectivePermission]:
        """Parse GCS IAM policy bindings into EffectivePermission entries."""
        permissions: list[EffectivePermission] = []

        for binding in getattr(policy, "bindings", []):
            role = binding.get("role", "") if isinstance(binding, dict) else getattr(binding, "role", "")
            members = binding.get("members", []) if isinstance(binding, dict) else getattr(binding, "members", [])
            condition = binding.get("condition", {}) if isinstance(binding, dict) else getattr(binding, "condition", {})

            is_admin = role in _GCS_ADMIN_ROLES

            for member in members:
                # member format: "type:identifier" e.g. "user:alice@example.com"
                parts = member.split(":", 1)
                member_type = parts[0] if len(parts) > 1 else "user"
                member_id = parts[1] if len(parts) > 1 else member

                is_public = member in ("allUsers", "allAuthenticatedUsers")

                permissions.append(EffectivePermission(
                    principal=AccessPrincipal(
                        principal_type="group" if member_type == "group" else (
                            "service_account" if member_type == "serviceAccount" else "user"
                        ),
                        principal_id=member,
                        principal_name=member_id,
                        provider="gcp",
                        is_admin=is_admin,
                        source="direct",
                    ),
                    actions=[role],
                    effect="allow",
                    resource_pattern="*",
                    conditions=condition if isinstance(condition, dict) else {},
                    is_public=is_public,
                ))

        return permissions

    def _check_allUsers_access(self, permissions: list[EffectivePermission]) -> bool:
        """Return True if any permission grants access to allUsers or allAuthenticatedUsers."""
        for perm in permissions:
            if perm.is_public and perm.effect == "allow":
                return True
        return False

    # ═══════════════════════════════════════════════════════════════════
    # Risk calculation
    # ═══════════════════════════════════════════════════════════════════

    def _calculate_risk_level(self, report: DataStoreAccessReport) -> str:
        """Calculate a composite risk level based on the report findings."""
        if report.public_access:
            return "critical"
        if report.cross_account_principals > 0 and report.admin_principals > 0:
            return "critical"
        if report.admin_principals > 3:
            return "high"
        if report.cross_account_principals > 0:
            return "high"
        if len(report.risk_factors) >= 3:
            return "high"
        if len(report.risk_factors) >= 1:
            return "medium"
        return "low"

    def _add_risk_factors_and_recommendations(
        self,
        report: DataStoreAccessReport,
        public_access_blocked: bool,
    ) -> None:
        """Populate risk factors and recommendations for S3 reports."""
        if report.public_access:
            report.risk_factors.append("Bucket has public access")
            report.recommendations.append("Enable S3 Block Public Access on the bucket")
        if not public_access_blocked:
            report.risk_factors.append("S3 Block Public Access is not fully enabled")
            report.recommendations.append(
                "Enable all four Block Public Access settings on the bucket"
            )
        if report.admin_principals > 3:
            report.risk_factors.append(
                f"{report.admin_principals} principals have admin-level access"
            )
            report.recommendations.append(
                "Review and reduce the number of principals with admin-level S3 access"
            )
        if report.cross_account_principals > 0:
            report.risk_factors.append(
                f"{report.cross_account_principals} cross-account principals detected"
            )
            report.recommendations.append(
                "Audit cross-account access and ensure it follows least privilege"
            )
