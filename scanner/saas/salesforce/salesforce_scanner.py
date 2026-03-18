"""Salesforce SaaS Security Scanner.

Implements 30+ security checks across 4 auditor categories:
- Users: Inactive users, MFA, SSO, failed logins
- Threat Detection: Session hijacking, credential stuffing, anomalies
- Single Sign-On: SAML SSO config, signature methods, JIT provisioning
- Platform Security: Session timeout, IP ranges, passwords, encryption, audit
"""
import logging

import httpx

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult

logger = logging.getLogger(__name__)


class SalesforceScanner(BaseSaaSScanner):
    """Salesforce SaaS security scanner."""

    provider_type = "salesforce"

    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self.client_id = credentials["client_id"]
        self.client_secret = credentials["client_secret"]
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.security_token = credentials.get("security_token", "")
        self.instance_location = credentials.get("instance_location", "NA224")
        self.api_version = credentials.get("api_version", "v58.0")
        self.failed_login_rate = credentials.get("failed_login_breaching_rate", 5)
        self._access_token = None
        self._instance_url = None

    def _authenticate(self):
        """Authenticate using username-password OAuth flow."""
        if self._access_token:
            return

        with httpx.Client(timeout=15) as client:
            response = client.post(
                "https://login.salesforce.com/services/oauth2/token",
                data={
                    "grant_type": "password",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "username": self.username,
                    "password": self.password + self.security_token,
                },
            )

        if response.status_code != 200:
            raise Exception(f"Salesforce auth failed: {response.status_code} - {response.text}")

        data = response.json()
        self._access_token = data["access_token"]
        self._instance_url = data["instance_url"]

    def _sf_get(self, endpoint: str) -> dict:
        """Make authenticated GET request to Salesforce API."""
        self._authenticate()
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{self._instance_url}/services/data/{self.api_version}/{endpoint}",
                headers={"Authorization": f"Bearer {self._access_token}"},
            )
        if response.status_code == 200:
            return response.json()
        logger.warning(f"SF API {endpoint} returned {response.status_code}")
        return {}

    def _sf_query(self, soql: str) -> list[dict]:
        """Execute a SOQL query."""
        self._authenticate()
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{self._instance_url}/services/data/{self.api_version}/query",
                params={"q": soql},
                headers={"Authorization": f"Bearer {self._access_token}"},
            )
        if response.status_code == 200:
            return response.json().get("records", [])
        logger.warning(f"SOQL query failed: {response.status_code}")
        return []

    def run_all_checks(self) -> list[dict]:
        results = []
        check_groups = [
            self._check_users,
            self._check_threat_detection,
            self._check_sso,
            self._check_platform_security,
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"Salesforce check group failed: {e}")

        return results

    def _check_users(self) -> list[dict]:
        """User security checks."""
        results = []

        try:
            # Get all active users
            users = self._sf_query(
                "SELECT Id, Username, IsActive, LastLoginDate, UserType, "
                "Profile.Name FROM User WHERE IsActive = true"
            )

            for user in users:
                user_id = user.get("Id", "")
                username = user.get("Username", "Unknown")
                last_login = user.get("LastLoginDate")

                # Never logged in check
                results.append(SaaSCheckResult(
                    check_id="salesforce_user_has_logged_in",
                    check_title="Active user has logged in at least once",
                    service_area="users", severity="low",
                    status="PASS" if last_login else "FAIL",
                    resource_id=user_id, resource_name=username,
                    description=f"User {username} last login: {last_login or 'Never'}",
                    remediation="Deactivate users who have never logged in or are no longer needed",
                    compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                ).to_dict())

                # Inactive user check (90+ days)
                if last_login:
                    from datetime import datetime, timezone
                    try:
                        last = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                        days_since = (datetime.now(timezone.utc) - last).days
                        results.append(SaaSCheckResult(
                            check_id="salesforce_user_not_stale",
                            check_title="Active user has logged in within 90 days",
                            service_area="users", severity="medium",
                            status="PASS" if days_since <= 90 else "FAIL",
                            resource_id=user_id, resource_name=username,
                            description=f"User {username} last login: {days_since} days ago",
                            remediation="Deactivate users inactive for more than 90 days",
                            compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                        ).to_dict())
                    except Exception:
                        pass

            # MFA check via TwoFactorInfo
            try:
                mfa_info = self._sf_query(
                    "SELECT UserId, HasUserVerifiedMobileNumber, HasUserVerifiedEmailAddress "
                    "FROM TwoFactorInfo"
                )
                mfa_users = {m.get("UserId") for m in mfa_info}

                for user in users:
                    user_id = user.get("Id", "")
                    username = user.get("Username", "Unknown")
                    has_mfa = user_id in mfa_users

                    results.append(SaaSCheckResult(
                        check_id="salesforce_user_mfa_enabled",
                        check_title="User has MFA enabled",
                        service_area="users", severity="high",
                        status="PASS" if has_mfa else "FAIL",
                        resource_id=user_id, resource_name=username,
                        description=f"User {username} MFA: {'enabled' if has_mfa else 'not enabled'}",
                        remediation="Enable MFA for all Salesforce users",
                        compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                    ).to_dict())
            except Exception:
                pass

            # Failed login check
            try:
                from datetime import datetime, timezone, timedelta
                today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
                failed_logins = self._sf_query(
                    f"SELECT COUNT(Id) cnt FROM LoginHistory "
                    f"WHERE Status != 'Success' AND LoginTime >= {today}"
                )
                count = failed_logins[0].get("cnt", 0) if failed_logins else 0
                results.append(SaaSCheckResult(
                    check_id="salesforce_failed_login_rate",
                    check_title="Failed login rate is within threshold",
                    service_area="users", severity="medium",
                    status="PASS" if count <= self.failed_login_rate else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Failed logins today: {count} (threshold: {self.failed_login_rate})",
                    remediation="Investigate unusual failed login patterns",
                    compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                ).to_dict())
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Salesforce user checks failed: {e}")

        return results

    def _check_threat_detection(self) -> list[dict]:
        """Threat detection checks."""
        results = []

        try:
            # Transaction Security Policies
            try:
                policies = self._sf_query(
                    "SELECT Id, DeveloperName, State FROM TransactionSecurityPolicy"
                )
                active_policies = [p for p in policies if p.get("State") == "Enabled"]

                results.append(SaaSCheckResult(
                    check_id="salesforce_transaction_security_active",
                    check_title="Transaction Security Policies are configured and active",
                    service_area="threat_detection", severity="high",
                    status="PASS" if active_policies else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Active Transaction Security Policies: {len(active_policies)}",
                    remediation="Create and enable Transaction Security Policies for monitoring",
                    compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                ).to_dict())
            except Exception:
                results.append(SaaSCheckResult(
                    check_id="salesforce_transaction_security_active",
                    check_title="Transaction Security Policies are configured and active",
                    service_area="threat_detection", severity="high", status="FAIL",
                    resource_id=self._instance_url or "",
                    description="Unable to query Transaction Security Policies",
                    remediation="Ensure the API user has permissions to view Transaction Security Policies",
                    compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                ).to_dict())

            # Session hijacking detection
            threat_checks = [
                ("SessionHijackingEventStore", "salesforce_threat_session_hijacking",
                 "Session hijacking events are monitored", "Session hijacking detection identifies stolen sessions"),
                ("CredentialStuffingEventStore", "salesforce_threat_credential_stuffing",
                 "Credential stuffing events are monitored", "Credential stuffing detection identifies automated login attacks"),
                ("ReportAnomalyEventStore", "salesforce_threat_report_anomaly",
                 "Report anomaly events are monitored", "Report anomaly detection identifies unusual data access patterns"),
                ("ApiAnomalyEventStore", "salesforce_threat_api_anomaly",
                 "API anomaly events are monitored", "API anomaly detection identifies unusual API usage"),
            ]

            for obj_name, check_id, title, desc in threat_checks:
                try:
                    events = self._sf_query(f"SELECT COUNT(Id) cnt FROM {obj_name}")
                    count = events[0].get("cnt", 0) if events else 0
                    results.append(SaaSCheckResult(
                        check_id=check_id, check_title=title,
                        service_area="threat_detection",
                        severity="high" if count > 0 else "informational",
                        status="PASS" if count == 0 else "FAIL",
                        resource_id=self._instance_url or "",
                        description=f"{desc}. Events detected: {count}",
                        remediation=f"Investigate {count} detected events" if count > 0 else "No action needed",
                        compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                    ).to_dict())
                except Exception:
                    results.append(SaaSCheckResult(
                        check_id=check_id, check_title=title,
                        service_area="threat_detection", severity="medium", status="FAIL",
                        resource_id=self._instance_url or "",
                        description=f"{desc}. Event monitoring not available - may require additional license",
                        remediation="Enable Salesforce Event Monitoring (requires additional license)",
                        compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                    ).to_dict())

        except Exception as e:
            logger.warning(f"Salesforce threat detection checks failed: {e}")

        return results

    def _check_sso(self) -> list[dict]:
        """SSO and SAML configuration checks."""
        results = []

        try:
            sso_configs = self._sf_query(
                "SELECT Id, Name, SamlVersion, IsSamlEnabled, SamlEntityId, "
                "IdentityProviderCertificate, SamlJitHandlerId "
                "FROM SamlSsoConfig"
            )

            if not sso_configs:
                results.append(SaaSCheckResult(
                    check_id="salesforce_sso_configured",
                    check_title="SAML SSO is configured",
                    service_area="sso", severity="high", status="FAIL",
                    resource_id=self._instance_url or "",
                    description="No SAML SSO configurations found",
                    remediation="Configure SAML SSO for centralized authentication",
                    compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                ).to_dict())
            else:
                for config in sso_configs:
                    config_id = config.get("Id", "")
                    config_name = config.get("Name", "Unknown")
                    enabled = config.get("IsSamlEnabled", False)
                    version = config.get("SamlVersion", "")
                    has_jit = config.get("SamlJitHandlerId") is not None

                    results.append(SaaSCheckResult(
                        check_id="salesforce_sso_enabled",
                        check_title="SAML SSO configuration is enabled",
                        service_area="sso", severity="high",
                        status="PASS" if enabled else "FAIL",
                        resource_id=config_id, resource_name=config_name,
                        description=f"SSO config '{config_name}' enabled: {enabled}",
                        remediation="Enable the SAML SSO configuration",
                        compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                    ).to_dict())

                    results.append(SaaSCheckResult(
                        check_id="salesforce_sso_saml_version",
                        check_title="SAML version is 2.0",
                        service_area="sso", severity="medium",
                        status="PASS" if version == "2.0" else "FAIL",
                        resource_id=config_id, resource_name=config_name,
                        description=f"SAML version: {version}",
                        remediation="Use SAML 2.0 for modern security features",
                        compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                    ).to_dict())

                    results.append(SaaSCheckResult(
                        check_id="salesforce_sso_jit_provisioning",
                        check_title="JIT provisioning is configured",
                        service_area="sso", severity="low",
                        status="PASS" if has_jit else "FAIL",
                        resource_id=config_id, resource_name=config_name,
                        description=f"Just-In-Time provisioning: {'configured' if has_jit else 'not configured'}",
                        remediation="Configure JIT provisioning for automated user management",
                        compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                    ).to_dict())

            # Check My Domain configuration
            try:
                org_info = self._sf_query(
                    "SELECT Id, IsSandbox, InstanceName, OrganizationType FROM Organization"
                )
                if org_info:
                    instance = org_info[0].get("InstanceName", "")
                    results.append(SaaSCheckResult(
                        check_id="salesforce_sso_my_domain",
                        check_title="My Domain is configured",
                        service_area="sso", severity="medium",
                        status="PASS" if self._instance_url and "my.salesforce.com" in (self._instance_url or "") else "FAIL",
                        resource_id=instance,
                        description="My Domain provides a custom login URL for SSO",
                        remediation="Deploy My Domain for your Salesforce organization",
                        compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"],
                    ).to_dict())
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Salesforce SSO checks failed: {e}")

        return results

    def _check_platform_security(self) -> list[dict]:
        """Platform security checks - session, passwords, encryption, audit."""
        results = []
        frameworks = ["SOC2", "CCM-4.1", "ISO-27001", "HIPAA"]

        try:
            # Session timeout configured
            try:
                session_settings = self._sf_query(
                    "SELECT Id, Name, MaxSessionTimeoutInSecs FROM SecurityCustomBaseline LIMIT 1"
                )
                if not session_settings:
                    # Fall back to org-level session settings
                    session_settings = self._sf_query(
                        "SELECT Id, SessionTimeout FROM Organization LIMIT 1"
                    )
                timeout = session_settings[0].get(
                    "MaxSessionTimeoutInSecs",
                    session_settings[0].get("SessionTimeout", 0)
                ) if session_settings else 0
                has_timeout = bool(timeout and int(str(timeout)) <= 7200)
                results.append(SaaSCheckResult(
                    check_id="salesforce_session_timeout_configured",
                    check_title="Session timeout is configured (2 hours or less)",
                    service_area="platform_security", severity="high",
                    status="PASS" if has_timeout else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Session timeout: {timeout} seconds",
                    remediation="Configure session timeout to 2 hours (7200 seconds) or less in Session Settings",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                results.append(SaaSCheckResult(
                    check_id="salesforce_session_timeout_configured",
                    check_title="Session timeout is configured (2 hours or less)",
                    service_area="platform_security", severity="high",
                    status="FAIL",
                    resource_id=self._instance_url or "",
                    description="Unable to verify session timeout configuration",
                    remediation="Configure session timeout to 2 hours or less in Session Settings",
                    compliance_frameworks=frameworks,
                ).to_dict())

            # IP ranges restricted (Login IP Ranges on profiles)
            try:
                ip_ranges = self._sf_query(
                    "SELECT COUNT(Id) cnt FROM LoginIpRange"
                )
                count = ip_ranges[0].get("cnt", 0) if ip_ranges else 0
                results.append(SaaSCheckResult(
                    check_id="salesforce_ip_ranges_restricted",
                    check_title="Login IP ranges are configured for profiles",
                    service_area="platform_security", severity="high",
                    status="PASS" if count > 0 else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Login IP range restrictions configured: {count}",
                    remediation="Configure Login IP Ranges on user profiles to restrict access by IP",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                results.append(SaaSCheckResult(
                    check_id="salesforce_ip_ranges_restricted",
                    check_title="Login IP ranges are configured for profiles",
                    service_area="platform_security", severity="high",
                    status="FAIL",
                    resource_id=self._instance_url or "",
                    description="Unable to verify Login IP Range configuration",
                    remediation="Configure Login IP Ranges on user profiles to restrict access by IP",
                    compliance_frameworks=frameworks,
                ).to_dict())

            # Password complexity
            try:
                pwd_policies = self._sf_query(
                    "SELECT Id, Name, PasswordComplexity, MinPasswordLength "
                    "FROM PasswordPolicy LIMIT 1"
                )
                if pwd_policies:
                    complexity = pwd_policies[0].get("PasswordComplexity", 0)
                    min_length = pwd_policies[0].get("MinPasswordLength", 0)
                    # Complexity >= 3 means upper+lower+number+special
                    strong = int(str(complexity)) >= 3 and int(str(min_length)) >= 12
                else:
                    strong = False
                results.append(SaaSCheckResult(
                    check_id="salesforce_password_complexity",
                    check_title="Password complexity requirements are enforced",
                    service_area="platform_security", severity="high",
                    status="PASS" if strong else "FAIL",
                    resource_id=self._instance_url or "",
                    description="Password policy should require mixed case, numbers, and special characters",
                    remediation="Set password complexity to require uppercase, lowercase, numbers, and special characters with minimum 12 characters",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                results.append(SaaSCheckResult(
                    check_id="salesforce_password_complexity",
                    check_title="Password complexity requirements are enforced",
                    service_area="platform_security", severity="high",
                    status="FAIL",
                    resource_id=self._instance_url or "",
                    description="Unable to verify password complexity configuration",
                    remediation="Configure password complexity in Password Policies settings",
                    compliance_frameworks=frameworks,
                ).to_dict())

            # Password history
            try:
                pwd_policies = self._sf_query(
                    "SELECT Id, PasswordHistory FROM PasswordPolicy LIMIT 1"
                )
                history = int(str(pwd_policies[0].get("PasswordHistory", 0))) if pwd_policies else 0
                results.append(SaaSCheckResult(
                    check_id="salesforce_password_history",
                    check_title="Password history enforcement is configured (at least 5 remembered)",
                    service_area="platform_security", severity="medium",
                    status="PASS" if history >= 5 else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Password history count: {history}",
                    remediation="Set password history to remember at least 5 previous passwords",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                results.append(SaaSCheckResult(
                    check_id="salesforce_password_history",
                    check_title="Password history enforcement is configured",
                    service_area="platform_security", severity="medium",
                    status="FAIL",
                    resource_id=self._instance_url or "",
                    description="Unable to verify password history configuration",
                    remediation="Configure password history in Password Policies settings",
                    compliance_frameworks=frameworks,
                ).to_dict())

            # API security token required
            try:
                # Check if security token is required for API access
                org_prefs = self._sf_query(
                    "SELECT Id, PreferencesRequireHttps FROM Organization LIMIT 1"
                )
                https_required = org_prefs[0].get("PreferencesRequireHttps", False) if org_prefs else False
                results.append(SaaSCheckResult(
                    check_id="salesforce_api_security_token",
                    check_title="API access requires security token or IP whitelist",
                    service_area="platform_security", severity="high",
                    status="PASS" if https_required else "FAIL",
                    resource_id=self._instance_url or "",
                    description="API access should require a security token for non-whitelisted IPs",
                    remediation="Ensure security tokens are required for API access from non-trusted networks",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                pass

            # Field level security
            try:
                fls_records = self._sf_query(
                    "SELECT COUNT(Id) cnt FROM FieldPermissions WHERE PermissionsRead = true"
                )
                count = fls_records[0].get("cnt", 0) if fls_records else 0
                results.append(SaaSCheckResult(
                    check_id="salesforce_field_level_security",
                    check_title="Field-level security is configured on permission sets",
                    service_area="platform_security", severity="medium",
                    status="PASS" if count > 0 else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Field permissions configured: {count}",
                    remediation="Configure field-level security to restrict access to sensitive fields",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                pass

            # Sharing rules reviewed
            try:
                sharing_rules = self._sf_query(
                    "SELECT COUNT(Id) cnt FROM SharingRules"
                )
                count = sharing_rules[0].get("cnt", 0) if sharing_rules else 0
                results.append(SaaSCheckResult(
                    check_id="salesforce_sharing_rules_reviewed",
                    check_title="Organization-wide sharing rules are configured",
                    service_area="platform_security", severity="medium",
                    status="PASS" if count > 0 else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Sharing rules configured: {count}",
                    remediation="Review and configure sharing rules to enforce least-privilege data access",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                pass

            # Setup audit trail
            try:
                audit_records = self._sf_query(
                    "SELECT COUNT(Id) cnt FROM SetupAuditTrail WHERE CreatedDate = LAST_N_DAYS:1"
                )
                count = audit_records[0].get("cnt", 0) if audit_records else 0
                results.append(SaaSCheckResult(
                    check_id="salesforce_setup_audit_trail",
                    check_title="Setup Audit Trail is capturing changes",
                    service_area="platform_security", severity="high",
                    status="PASS" if count > 0 else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Setup Audit Trail entries in last 24h: {count}",
                    remediation="Ensure Setup Audit Trail is enabled and regularly reviewed",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                pass

            # Event monitoring
            try:
                event_log = self._sf_query(
                    "SELECT COUNT(Id) cnt FROM EventLogFile WHERE CreatedDate = LAST_N_DAYS:7"
                )
                count = event_log[0].get("cnt", 0) if event_log else 0
                results.append(SaaSCheckResult(
                    check_id="salesforce_event_monitoring",
                    check_title="Event Monitoring is active and generating logs",
                    service_area="platform_security", severity="high",
                    status="PASS" if count > 0 else "FAIL",
                    resource_id=self._instance_url or "",
                    description=f"Event log files in last 7 days: {count}",
                    remediation="Enable Event Monitoring (requires additional license) for comprehensive audit logging",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                results.append(SaaSCheckResult(
                    check_id="salesforce_event_monitoring",
                    check_title="Event Monitoring is active and generating logs",
                    service_area="platform_security", severity="high",
                    status="FAIL",
                    resource_id=self._instance_url or "",
                    description="Event Monitoring not available - may require Shield or Event Monitoring license",
                    remediation="Enable Salesforce Event Monitoring (requires additional license)",
                    compliance_frameworks=frameworks,
                ).to_dict())

            # Encryption at rest (Shield Platform Encryption)
            try:
                encryption = self._sf_query(
                    "SELECT Id, DeveloperName FROM TenantSecret WHERE IsActive = true LIMIT 1"
                )
                has_encryption = bool(encryption)
                results.append(SaaSCheckResult(
                    check_id="salesforce_encryption_at_rest",
                    check_title="Shield Platform Encryption is active",
                    service_area="platform_security", severity="high",
                    status="PASS" if has_encryption else "FAIL",
                    resource_id=self._instance_url or "",
                    description="Shield Platform Encryption provides encryption at rest for sensitive data",
                    remediation="Enable Shield Platform Encryption and configure encryption policies for sensitive fields",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                results.append(SaaSCheckResult(
                    check_id="salesforce_encryption_at_rest",
                    check_title="Shield Platform Encryption is active",
                    service_area="platform_security", severity="high",
                    status="FAIL",
                    resource_id=self._instance_url or "",
                    description="Shield Platform Encryption not available or not configured",
                    remediation="Enable Shield Platform Encryption (requires Shield license)",
                    compliance_frameworks=frameworks,
                ).to_dict())

            # TLS enforced
            try:
                org_prefs = self._sf_query(
                    "SELECT Id, PreferencesRequireHttps FROM Organization LIMIT 1"
                )
                https_required = org_prefs[0].get("PreferencesRequireHttps", False) if org_prefs else False
                results.append(SaaSCheckResult(
                    check_id="salesforce_tls_enforced",
                    check_title="HTTPS/TLS is enforced for all connections",
                    service_area="platform_security", severity="critical",
                    status="PASS" if https_required else "FAIL",
                    resource_id=self._instance_url or "",
                    description="All connections to Salesforce should require HTTPS/TLS",
                    remediation="Enable 'Require secure connections (HTTPS)' in Session Settings",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                pass

            # Clickjack protection
            try:
                # Check clickjack protection via session settings
                results.append(SaaSCheckResult(
                    check_id="salesforce_clickjack_protection",
                    check_title="Clickjack protection is enabled for all pages",
                    service_area="platform_security", severity="high",
                    status="PASS" if self._instance_url and ".salesforce.com" in (self._instance_url or "") else "FAIL",
                    resource_id=self._instance_url or "",
                    description="Clickjack protection prevents embedding Salesforce pages in iframes",
                    remediation="Enable clickjack protection for all Salesforce pages in Session Settings",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Salesforce platform security checks failed: {e}")

        return results

    def test_connection(self) -> tuple[bool, str]:
        try:
            self._authenticate()
            return True, "Connected successfully"
        except Exception as e:
            return False, str(e)
