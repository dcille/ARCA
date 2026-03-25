"""Snowflake SaaS Security Scanner.

Implements 32+ security checks across 3 auditor categories:
- Users: MFA, RSA keys, inactive users, admin roles, password rotation
- Account: SSO/SCIM, session timeouts, network policies, password policies
- Data & Operations: Warehouses, retention, masking, row access, stages, audit, sharing
"""
import logging

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult
from scanner.cis_controls.snowflake_cis_controls import SNOWFLAKE_CIS_CONTROLS

logger = logging.getLogger(__name__)


class SnowflakeScanner(BaseSaaSScanner):
    """Snowflake SaaS security scanner."""

    provider_type = "snowflake"

    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.account_id = credentials["account_id"]
        self.warehouse_name = credentials.get("warehouse_name", "")
        self.region = credentials.get("region", "")
        self.service_account_usernames = credentials.get("service_account_usernames", [])
        self._connection = None

    def _get_connection(self):
        """Get Snowflake database connection."""
        if self._connection:
            return self._connection

        import snowflake.connector
        self._connection = snowflake.connector.connect(
            user=self.username,
            password=self.password,
            account=self.account_id,
            warehouse=self.warehouse_name,
            database="SNOWFLAKE",
            schema="ACCOUNT_USAGE",
        )
        return self._connection

    def _execute_query(self, query: str) -> list[dict]:
        """Execute a SQL query and return results as list of dicts."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        finally:
            cursor.close()

    def run_all_checks(self) -> list[dict]:
        results = []
        check_groups = [
            self._check_users,
            self._check_account,
            self._check_data_operations,
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"Snowflake check group failed: {e}")

        # Add CIS coverage for uncovered controls
        results.extend(self._emit_cis_coverage(results))

        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass

        return results

    def _emit_cis_coverage(self, existing_results: list[dict]) -> list[dict]:
        """Emit MANUAL results for CIS controls not covered by automated checks."""
        covered_cis_ids: set[str] = set()
        check_to_cis = {}
        for ctrl in SNOWFLAKE_CIS_CONTROLS:
            cis_id = ctrl["cis_id"]
            check_to_cis[f"sf_cis_{cis_id.replace('.', '_')}"] = cis_id

        for result in existing_results:
            check_id = result.get("check_id", "")
            if check_id in check_to_cis:
                covered_cis_ids.add(check_to_cis[check_id])

        manual_results = []
        fw = ["CIS-Snowflake-1.1.0", "SOC2", "ISO-27001"]

        for ctrl in SNOWFLAKE_CIS_CONTROLS:
            cis_id = ctrl["cis_id"]
            title = ctrl["title"]
            level = ctrl["cis_level"]
            assess_type = ctrl["assessment_type"]
            severity = ctrl["severity"]
            area = ctrl["service_area"]
            if cis_id not in covered_cis_ids:
                manual_results.append(SaaSCheckResult(
                    check_id=f"sf_cis_{cis_id.replace('.', '_')}",
                    check_title=f"{title} (CIS {cis_id})",
                    service_area=area,
                    severity=severity,
                    status="MANUAL",
                    resource_id=self.account if hasattr(self, 'account') else "snowflake-account",
                    description=(
                        f"CIS {cis_id} [{level}] - {assess_type.upper()} assessment. "
                        f"This control requires {'manual verification' if assess_type == 'manual' else 'automated check implementation'}."
                    ),
                    remediation=ctrl.get("remediation", f"Refer to CIS Snowflake Foundations Benchmark v1.1.0, control {cis_id}."),
                    compliance_frameworks=fw,
                    assessment_type=assess_type,
                    cis_control_id=cis_id,
                    cis_level=level,
                ).to_dict())

        return manual_results

    def _check_users(self) -> list[dict]:
        """User security checks."""
        results = []

        try:
            users = self._execute_query("""
                SELECT NAME, LOGIN_NAME, DISPLAY_NAME, EMAIL, HAS_PASSWORD,
                       HAS_RSA_PUBLIC_KEY, EXT_AUTHN_DUO, DISABLED,
                       LAST_SUCCESS_LOGIN, DEFAULT_ROLE, CREATED_ON,
                       PASSWORD_LAST_SET_TIME, MUST_CHANGE_PASSWORD
                FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
                WHERE DELETED_ON IS NULL
            """)

            admin_count = 0

            for user in users:
                username = user.get("NAME", "Unknown")
                login_name = user.get("LOGIN_NAME", "")
                disabled = user.get("DISABLED", "false")
                has_password = user.get("HAS_PASSWORD", "false")
                has_rsa = user.get("HAS_RSA_PUBLIC_KEY", "false")
                has_mfa = user.get("EXT_AUTHN_DUO", "false")
                default_role = user.get("DEFAULT_ROLE", "")
                last_login = user.get("LAST_SUCCESS_LOGIN")
                password_last_set = user.get("PASSWORD_LAST_SET_TIME")

                if str(disabled).lower() == "true":
                    continue

                is_service_account = username in self.service_account_usernames

                # MFA for password users
                if str(has_password).lower() == "true" and not is_service_account:
                    results.append(SaaSCheckResult(
                        check_id="snowflake_user_mfa_enabled",
                        check_title="Password user has MFA enabled",
                        service_area="users", severity="high",
                        status="PASS" if str(has_mfa).lower() == "true" else "FAIL",
                        resource_id=username, resource_name=login_name,
                        description=f"User {username} MFA: {has_mfa}",
                        remediation="Enable MFA (Duo) for password-authenticated users",
                        compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                    ).to_dict())

                # RSA key for service accounts
                if is_service_account:
                    results.append(SaaSCheckResult(
                        check_id="snowflake_service_account_rsa",
                        check_title="Service account uses RSA key authentication",
                        service_area="users", severity="high",
                        status="PASS" if str(has_rsa).lower() == "true" else "FAIL",
                        resource_id=username, resource_name=login_name,
                        description=f"Service account {username} RSA key: {has_rsa}",
                        remediation="Configure RSA key pair authentication for service accounts",
                        compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                    ).to_dict())

                # Inactive user check
                if last_login:
                    from datetime import datetime, timezone
                    try:
                        if isinstance(last_login, str):
                            last_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                        else:
                            last_dt = last_login.replace(tzinfo=timezone.utc) if last_login.tzinfo is None else last_login
                        days_inactive = (datetime.now(timezone.utc) - last_dt).days
                        results.append(SaaSCheckResult(
                            check_id="snowflake_user_not_inactive",
                            check_title="User has logged in within 90 days",
                            service_area="users", severity="medium",
                            status="PASS" if days_inactive <= 90 else "FAIL",
                            resource_id=username, resource_name=login_name,
                            description=f"User {username} last login: {days_inactive} days ago",
                            remediation="Disable users inactive for more than 90 days",
                            compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                        ).to_dict())
                    except Exception:
                        pass

                # Admin email verification
                if default_role and "ADMIN" in default_role.upper():
                    admin_count += 1
                    email = user.get("EMAIL")
                    results.append(SaaSCheckResult(
                        check_id="snowflake_admin_has_email",
                        check_title="Admin user has verified email",
                        service_area="users", severity="medium",
                        status="PASS" if email else "FAIL",
                        resource_id=username, resource_name=login_name,
                        description=f"Admin user {username} email: {'set' if email else 'not set'}",
                        remediation="Set an email address for admin users for recovery and notifications",
                        compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                    ).to_dict())

                # Default role check
                if default_role and default_role.upper() in ("ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN"):
                    results.append(SaaSCheckResult(
                        check_id="snowflake_user_no_admin_default_role",
                        check_title="User does not have admin as default role",
                        service_area="users", severity="high",
                        status="FAIL",
                        resource_id=username, resource_name=login_name,
                        description=f"User {username} has {default_role} as default role",
                        remediation="Set a custom role as the user's default role instead of admin roles",
                        compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                    ).to_dict())

                # Password rotation check
                if str(has_password).lower() == "true" and password_last_set:
                    try:
                        from datetime import datetime, timezone
                        if isinstance(password_last_set, str):
                            pwd_dt = datetime.fromisoformat(password_last_set.replace("Z", "+00:00"))
                        else:
                            pwd_dt = password_last_set.replace(tzinfo=timezone.utc) if password_last_set.tzinfo is None else password_last_set
                        pwd_age = (datetime.now(timezone.utc) - pwd_dt).days
                        results.append(SaaSCheckResult(
                            check_id="snowflake_user_password_rotation",
                            check_title="User password has been rotated within 90 days",
                            service_area="users", severity="medium",
                            status="PASS" if pwd_age <= 90 else "FAIL",
                            resource_id=username, resource_name=login_name,
                            description=f"User {username} password age: {pwd_age} days",
                            remediation="Rotate passwords at least every 90 days",
                            compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                        ).to_dict())
                    except Exception:
                        pass

            # Admin count check (should be 2-10)
            results.append(SaaSCheckResult(
                check_id="snowflake_admin_count_appropriate",
                check_title="Account admin count is between 2 and 10",
                service_area="users", severity="high",
                status="PASS" if 2 <= admin_count <= 10 else "FAIL",
                resource_id=self.account_id,
                description=f"Account admin users: {admin_count}",
                remediation="Maintain between 2 and 10 account admin users",
                compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"Snowflake user checks failed: {e}")

        return results

    def _check_account(self) -> list[dict]:
        """Account-level security checks."""
        results = []

        try:
            # SSO configuration
            try:
                sso_params = self._execute_query("""
                    SELECT VALUE FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                    WHERE QUERY_TEXT ILIKE '%SAML_IDENTITY_PROVIDER%'
                    LIMIT 1
                """)
                # Try direct parameter check
                params = self._execute_query("SHOW PARAMETERS LIKE 'SAML_IDENTITY_PROVIDER' IN ACCOUNT")
                sso_configured = bool(params and any(p.get("value") for p in params))
            except Exception:
                sso_configured = False

            results.append(SaaSCheckResult(
                check_id="snowflake_account_sso_configured",
                check_title="SSO/SAML is configured",
                service_area="account", severity="high",
                status="PASS" if sso_configured else "FAIL",
                resource_id=self.account_id,
                description=f"SSO configuration: {'configured' if sso_configured else 'not configured'}",
                remediation="Configure SAML-based SSO for centralized authentication",
                compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
            ).to_dict())

            # Network policy check
            try:
                network_policies = self._execute_query("SHOW NETWORK POLICIES")
                has_network_policy = bool(network_policies)
            except Exception:
                has_network_policy = False

            results.append(SaaSCheckResult(
                check_id="snowflake_account_network_policy",
                check_title="Network policy is configured",
                service_area="account", severity="high",
                status="PASS" if has_network_policy else "FAIL",
                resource_id=self.account_id,
                description=f"Network policies: {'configured' if has_network_policy else 'not configured'}",
                remediation="Create network policies to restrict access by IP address",
                compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
            ).to_dict())

            # Session timeout check
            try:
                session_params = self._execute_query(
                    "SHOW PARAMETERS LIKE 'STATEMENT_TIMEOUT_IN_SECONDS' IN ACCOUNT"
                )
                timeout = int(session_params[0].get("value", 0)) if session_params else 0
                results.append(SaaSCheckResult(
                    check_id="snowflake_account_session_timeout",
                    check_title="Session timeout is configured (15 minutes or less)",
                    service_area="account", severity="medium",
                    status="PASS" if 0 < timeout <= 900 else "FAIL",
                    resource_id=self.account_id,
                    description=f"Statement timeout: {timeout} seconds",
                    remediation="Set STATEMENT_TIMEOUT_IN_SECONDS to 900 (15 minutes) or less for admin roles",
                    compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                ).to_dict())
            except Exception:
                pass

            # Password policy check
            try:
                password_policies = self._execute_query("SHOW PASSWORD POLICIES")
                has_password_policy = bool(password_policies)

                results.append(SaaSCheckResult(
                    check_id="snowflake_account_password_policy",
                    check_title="Custom password policy is configured",
                    service_area="account", severity="high",
                    status="PASS" if has_password_policy else "FAIL",
                    resource_id=self.account_id,
                    description=f"Password policies: {'configured' if has_password_policy else 'using defaults'}",
                    remediation="Create a custom password policy with minimum 14 characters",
                    compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                ).to_dict())

                if has_password_policy:
                    for policy in password_policies:
                        min_length = policy.get("PASSWORD_MIN_LENGTH", 0)
                        if isinstance(min_length, str):
                            min_length = int(min_length) if min_length.isdigit() else 0
                        results.append(SaaSCheckResult(
                            check_id="snowflake_account_password_min_length",
                            check_title="Password minimum length is at least 14 characters",
                            service_area="account", severity="high",
                            status="PASS" if min_length >= 14 else "FAIL",
                            resource_id=self.account_id,
                            description=f"Password minimum length: {min_length}",
                            remediation="Set PASSWORD_MIN_LENGTH to 14 or higher",
                            compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                        ).to_dict())
            except Exception:
                pass

            # Task and stored procedure ownership
            try:
                tasks = self._execute_query("""
                    SELECT NAME, DATABASE_NAME, SCHEMA_NAME, OWNER
                    FROM SNOWFLAKE.ACCOUNT_USAGE.TASKS
                    WHERE DELETED_ON IS NULL
                """)
                for task in tasks:
                    owner = task.get("OWNER", "")
                    if owner.upper() in ("ACCOUNTADMIN", "SECURITYADMIN"):
                        results.append(SaaSCheckResult(
                            check_id="snowflake_task_no_admin_owner",
                            check_title="Task is not owned by admin role",
                            service_area="account", severity="medium",
                            status="FAIL",
                            resource_id=task.get("NAME", ""),
                            resource_name=f"{task.get('DATABASE_NAME')}.{task.get('SCHEMA_NAME')}.{task.get('NAME')}",
                            description=f"Task owned by {owner} (should use custom role)",
                            remediation="Transfer task ownership to a custom role with least privilege",
                            compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                        ).to_dict())
            except Exception:
                pass

            # SCIM integration check
            try:
                integrations = self._execute_query("SHOW INTEGRATIONS")
                scim_integrations = [
                    i for i in integrations
                    if str(i.get("type", "")).upper() == "SCIM"
                    and str(i.get("enabled", "")).lower() == "true"
                ]
                results.append(SaaSCheckResult(
                    check_id="snowflake_account_scim_configured",
                    check_title="SCIM integration is configured for user provisioning",
                    service_area="account", severity="medium",
                    status="PASS" if scim_integrations else "FAIL",
                    resource_id=self.account_id,
                    description=f"Active SCIM integrations: {len(scim_integrations)}",
                    remediation="Configure SCIM for automated user provisioning and deprovisioning",
                    compliance_frameworks=["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"],
                ).to_dict())
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Snowflake account checks failed: {e}")

        return results

    def _check_data_operations(self) -> list[dict]:
        """Data protection and operations checks."""
        results = []
        frameworks = ["SOC2", "CCM-4.1", "HIPAA", "NIST-800-53"]

        try:
            # Warehouse auto-suspend
            try:
                warehouses = self._execute_query("SHOW WAREHOUSES")
                for wh in warehouses:
                    wh_name = wh.get("name", "Unknown")
                    auto_suspend = wh.get("auto_suspend", 0)
                    if isinstance(auto_suspend, str):
                        auto_suspend = int(auto_suspend) if auto_suspend.isdigit() else 0
                    results.append(SaaSCheckResult(
                        check_id="snowflake_warehouse_auto_suspend",
                        check_title="Warehouse has auto-suspend configured (10 minutes or less)",
                        service_area="data_operations", severity="medium",
                        status="PASS" if 0 < auto_suspend <= 600 else "FAIL",
                        resource_id=wh_name, resource_name=wh_name,
                        description=f"Warehouse {wh_name} auto-suspend: {auto_suspend} seconds",
                        remediation="Set warehouse auto-suspend to 600 seconds (10 minutes) or less",
                        compliance_frameworks=frameworks,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"Warehouse auto-suspend check failed: {e}")

            # Data retention configured
            try:
                retention_params = self._execute_query(
                    "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT"
                )
                retention = int(retention_params[0].get("value", 0)) if retention_params else 0
                results.append(SaaSCheckResult(
                    check_id="snowflake_data_retention_configured",
                    check_title="Data retention period is configured (at least 1 day)",
                    service_area="data_operations", severity="high",
                    status="PASS" if retention >= 1 else "FAIL",
                    resource_id=self.account_id,
                    description=f"Data retention time: {retention} days",
                    remediation="Set DATA_RETENTION_TIME_IN_DAYS to at least 1 day for Time Travel",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Data retention check failed: {e}")

            # Column masking policies
            try:
                masking_policies = self._execute_query("SHOW MASKING POLICIES")
                has_masking = bool(masking_policies)
                results.append(SaaSCheckResult(
                    check_id="snowflake_column_masking_policies",
                    check_title="Column-level masking policies are configured",
                    service_area="data_operations", severity="high",
                    status="PASS" if has_masking else "FAIL",
                    resource_id=self.account_id,
                    description=f"Masking policies: {len(masking_policies) if masking_policies else 0}",
                    remediation="Create dynamic data masking policies to protect sensitive columns",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Masking policies check failed: {e}")

            # Row access policies
            try:
                row_policies = self._execute_query("SHOW ROW ACCESS POLICIES")
                has_row_policies = bool(row_policies)
                results.append(SaaSCheckResult(
                    check_id="snowflake_row_access_policies",
                    check_title="Row access policies are configured",
                    service_area="data_operations", severity="medium",
                    status="PASS" if has_row_policies else "FAIL",
                    resource_id=self.account_id,
                    description=f"Row access policies: {len(row_policies) if row_policies else 0}",
                    remediation="Create row access policies to enforce row-level security",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Row access policies check failed: {e}")

            # External functions restricted
            try:
                ext_functions = self._execute_query("""
                    SELECT FUNCTION_NAME, FUNCTION_SCHEMA, FUNCTION_CATALOG
                    FROM SNOWFLAKE.ACCOUNT_USAGE.FUNCTIONS
                    WHERE IS_EXTERNAL = 'YES' AND DELETED IS NULL
                """)
                ext_count = len(ext_functions) if ext_functions else 0
                results.append(SaaSCheckResult(
                    check_id="snowflake_external_functions_restricted",
                    check_title="External functions are limited and reviewed",
                    service_area="data_operations", severity="medium",
                    status="PASS" if ext_count <= 5 else "FAIL",
                    resource_id=self.account_id,
                    description=f"External functions configured: {ext_count}",
                    remediation="Review and limit external functions to only those that are necessary",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"External functions check failed: {e}")

            # Stages encrypted
            try:
                stages = self._execute_query("SHOW STAGES")
                unencrypted_stages = []
                for stage in (stages or []):
                    stage_name = stage.get("name", "")
                    stage_type = str(stage.get("type", "")).upper()
                    # Internal stages are encrypted by default; check external
                    if stage_type == "EXTERNAL":
                        encryption = stage.get("encryption", "")
                        if not encryption or "NONE" in str(encryption).upper():
                            unencrypted_stages.append(stage_name)
                results.append(SaaSCheckResult(
                    check_id="snowflake_stages_encrypted",
                    check_title="External stages use encryption",
                    service_area="data_operations", severity="high",
                    status="PASS" if not unencrypted_stages else "FAIL",
                    resource_id=self.account_id,
                    description=f"Unencrypted external stages: {len(unencrypted_stages)}",
                    remediation="Configure encryption for all external stages (e.g., SSE-S3, SSE-KMS)",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Stage encryption check failed: {e}")

            # Audit logging enabled
            try:
                audit_records = self._execute_query("""
                    SELECT COUNT(*) AS cnt
                    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
                    WHERE EVENT_TIMESTAMP >= DATEADD('day', -1, CURRENT_TIMESTAMP())
                """)
                count = audit_records[0].get("cnt", audit_records[0].get("CNT", 0)) if audit_records else 0
                results.append(SaaSCheckResult(
                    check_id="snowflake_audit_logging_enabled",
                    check_title="Audit logging is active (login history available)",
                    service_area="data_operations", severity="high",
                    status="PASS" if count > 0 else "FAIL",
                    resource_id=self.account_id,
                    description=f"Login history records in last 24h: {count}",
                    remediation="Ensure ACCOUNT_USAGE schema is accessible and audit logging is active",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Audit logging check failed: {e}")

            # Query history retention
            try:
                query_records = self._execute_query("""
                    SELECT MIN(START_TIME) AS oldest
                    FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                    WHERE START_TIME >= DATEADD('day', -365, CURRENT_TIMESTAMP())
                    LIMIT 1
                """)
                has_history = bool(query_records and query_records[0].get("oldest", query_records[0].get("OLDEST")))
                results.append(SaaSCheckResult(
                    check_id="snowflake_query_history_retention",
                    check_title="Query history is retained for audit purposes",
                    service_area="data_operations", severity="medium",
                    status="PASS" if has_history else "FAIL",
                    resource_id=self.account_id,
                    description="Query history should be retained for at least 365 days for compliance",
                    remediation="Ensure query history is available in ACCOUNT_USAGE for audit retention",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Query history retention check failed: {e}")

            # Data sharing monitored
            try:
                shares = self._execute_query("SHOW SHARES")
                outbound_shares = [
                    s for s in (shares or [])
                    if str(s.get("kind", "")).upper() == "OUTBOUND"
                ]
                results.append(SaaSCheckResult(
                    check_id="snowflake_data_sharing_monitored",
                    check_title="Outbound data shares are monitored and limited",
                    service_area="data_operations", severity="high",
                    status="PASS" if len(outbound_shares) <= 10 else "FAIL",
                    resource_id=self.account_id,
                    description=f"Outbound data shares: {len(outbound_shares)}",
                    remediation="Review outbound data shares and remove any that are no longer needed",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Data sharing check failed: {e}")

            # Cortex access restricted
            try:
                cortex_grants = self._execute_query("""
                    SELECT GRANTEE_NAME, PRIVILEGE
                    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                    WHERE PRIVILEGE ILIKE '%CORTEX%'
                    AND DELETED_ON IS NULL
                """)
                cortex_count = len(cortex_grants) if cortex_grants else 0
                results.append(SaaSCheckResult(
                    check_id="snowflake_cortex_access_restricted",
                    check_title="Snowflake Cortex access is restricted to authorized roles",
                    service_area="data_operations", severity="medium",
                    status="PASS" if cortex_count <= 3 else "FAIL",
                    resource_id=self.account_id,
                    description=f"Cortex-related privilege grants: {cortex_count}",
                    remediation="Restrict Cortex function access to only authorized roles",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Cortex access check failed: {e}")

            # Failover configured
            try:
                replication = self._execute_query("SHOW REPLICATION ACCOUNTS")
                has_failover = bool(replication)
                results.append(SaaSCheckResult(
                    check_id="snowflake_failover_configured",
                    check_title="Account replication/failover is configured",
                    service_area="data_operations", severity="medium",
                    status="PASS" if has_failover else "FAIL",
                    resource_id=self.account_id,
                    description=f"Replication accounts: {len(replication) if replication else 0}",
                    remediation="Configure account replication and failover for business continuity",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failover check failed: {e}")

        except Exception as e:
            logger.warning(f"Snowflake data operations checks failed: {e}")

        return results

    def test_connection(self) -> tuple[bool, str]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT CURRENT_VERSION()")
            version = cursor.fetchone()[0]
            cursor.close()
            return True, f"Connected to Snowflake version {version}"
        except Exception as e:
            return False, str(e)
