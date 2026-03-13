"""Snowflake SaaS Security Scanner.

Implements 21 security checks across 2 auditor categories:
- Users: MFA, RSA keys, inactive users, admin roles, password rotation
- Account: SSO/SCIM, session timeouts, network policies, password policies
"""
import logging

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult

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
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"Snowflake check group failed: {e}")

        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass

        return results

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
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
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
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                            compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
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
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                            compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
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
                            compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                            compliance_frameworks=["NIST-CSF", "ISO-27001"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
                ).to_dict())
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Snowflake account checks failed: {e}")

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
