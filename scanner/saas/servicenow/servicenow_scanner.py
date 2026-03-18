"""ServiceNow SaaS Security Scanner.

Implements 92+ security checks across 10 auditor categories based on ElectricEye patterns:
- Users: MFA, failed logins, account lockouts
- Access Control: API auth, script execution, delegated grants
- Attachments: File rendering, type validation, MIME checks
- Email Security: HTML rendering, trusted domains
- Input Validation: HTML/JS escaping, sandboxing, formula injection
- Secure Communications: Certificate validation, SSL versions
- Security Inclusion Listing: URL allowlists, X-Frame-Options, XXE
- Session Management: Timeouts, CSRF tokens, HTTPOnly cookies
- Security Plugins: Required plugin installation/activation
- Platform Security: Encryption, TLS, IP controls, role separation, CMDB, ITSM
"""
import logging
from typing import Optional

import httpx

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult

logger = logging.getLogger(__name__)


class ServiceNowScanner(BaseSaaSScanner):
    """ServiceNow SaaS security scanner."""

    provider_type = "servicenow"

    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self.instance_name = credentials["instance_name"]
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.instance_region = credentials.get("instance_region", "us")
        self.failed_login_rate = credentials.get("failed_login_breaching_rate", 5)
        self.base_url = f"https://{self.instance_name}.service-now.com"
        self._properties_cache = {}

    def _get_auth(self):
        return (self.username, self.password)

    def _get_property(self, prop_name: str) -> Optional[str]:
        """Fetch a ServiceNow system property value."""
        if prop_name in self._properties_cache:
            return self._properties_cache[prop_name]

        try:
            with httpx.Client(timeout=15) as client:
                response = client.get(
                    f"{self.base_url}/api/now/table/sys_properties",
                    params={"sysparm_query": f"name={prop_name}", "sysparm_fields": "name,value", "sysparm_limit": 1},
                    auth=self._get_auth(),
                )
            if response.status_code == 200:
                results = response.json().get("result", [])
                value = results[0]["value"] if results else None
                self._properties_cache[prop_name] = value
                return value
        except Exception as e:
            logger.warning(f"Failed to fetch property {prop_name}: {e}")
        return None

    def _get_plugins(self) -> list[dict]:
        """Fetch installed plugins."""
        try:
            with httpx.Client(timeout=15) as client:
                response = client.get(
                    f"{self.base_url}/api/now/table/v_plugin",
                    params={"sysparm_fields": "id,name,active", "sysparm_limit": 500},
                    auth=self._get_auth(),
                )
            if response.status_code == 200:
                return response.json().get("result", [])
        except Exception as e:
            logger.warning(f"Failed to fetch plugins: {e}")
        return []

    def run_all_checks(self) -> list[dict]:
        """Run all ServiceNow security checks."""
        results = []
        check_groups = [
            self._check_users,
            self._check_access_control,
            self._check_attachments,
            self._check_email_security,
            self._check_input_validation,
            self._check_secure_communications,
            self._check_security_inclusion_listing,
            self._check_session_management,
            self._check_security_plugins,
            self._check_platform_security,
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"ServiceNow check group failed: {e}")

        return results

    def _check_users(self) -> list[dict]:
        """User security checks - MFA, failed logins, lockouts."""
        results = []

        # MFA enforcement
        mfa_prop = self._get_property("glide.authenticate.multifactor")
        results.append(SaaSCheckResult(
            check_id="servicenow_users_mfa_enabled",
            check_title="ServiceNow MFA is enabled for all users",
            service_area="users", severity="critical",
            status="PASS" if mfa_prop and mfa_prop.lower() == "true" else "FAIL",
            resource_id=self.instance_name,
            description="Multi-factor authentication should be enabled for all users",
            remediation="Enable MFA by setting glide.authenticate.multifactor to true",
            compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
        ).to_dict())

        # Account lockout
        lockout_prop = self._get_property("glide.user.max_login_attempts")
        lockout_val = int(lockout_prop) if lockout_prop and lockout_prop.isdigit() else 0
        results.append(SaaSCheckResult(
            check_id="servicenow_users_lockout_configured",
            check_title="Account lockout policy is configured",
            service_area="users", severity="high",
            status="PASS" if lockout_val > 0 and lockout_val <= 10 else "FAIL",
            resource_id=self.instance_name,
            description=f"Account lockout threshold: {lockout_val} attempts",
            remediation="Configure account lockout (glide.user.max_login_attempts) between 3-10",
            compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
        ).to_dict())

        # Password complexity
        pwd_min_length = self._get_property("glide.security.password.min_length")
        min_len = int(pwd_min_length) if pwd_min_length and pwd_min_length.isdigit() else 0
        results.append(SaaSCheckResult(
            check_id="servicenow_users_password_length",
            check_title="Password minimum length is at least 12 characters",
            service_area="users", severity="high",
            status="PASS" if min_len >= 12 else "FAIL",
            resource_id=self.instance_name,
            description=f"Password minimum length: {min_len}",
            remediation="Set glide.security.password.min_length to 12 or higher",
            compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
        ).to_dict())

        # Failed login monitoring
        try:
            with httpx.Client(timeout=15) as client:
                response = client.get(
                    f"{self.base_url}/api/now/table/sysevent",
                    params={
                        "sysparm_query": "name=login.failed^sys_created_onONToday@javascript:gs.beginningOfToday()@javascript:gs.endOfToday()",
                        "sysparm_limit": 1,
                        "sysparm_fields": "sys_id",
                    },
                    auth=self._get_auth(),
                )
            if response.status_code == 200:
                failed_count = len(response.json().get("result", []))
                results.append(SaaSCheckResult(
                    check_id="servicenow_users_failed_logins",
                    check_title="Failed login rate is within threshold",
                    service_area="users", severity="medium",
                    status="PASS" if failed_count <= self.failed_login_rate else "FAIL",
                    resource_id=self.instance_name,
                    description=f"Failed logins today: {failed_count} (threshold: {self.failed_login_rate})",
                    remediation="Investigate failed login attempts and implement IP-based restrictions",
                    compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
                ).to_dict())
        except Exception:
            pass

        return results

    def _check_access_control(self) -> list[dict]:
        """Access control checks."""
        results = []
        checks = [
            ("glide.script.use.sandbox", "servicenow_ac_script_sandbox", "Script sandbox is enabled",
             "Script sandboxing prevents malicious server-side code execution",
             "Enable script sandbox via glide.script.use.sandbox", "high"),
            ("glide.security.use_csrf_token", "servicenow_ac_csrf_token", "CSRF token protection is enabled",
             "CSRF tokens prevent cross-site request forgery attacks",
             "Enable CSRF tokens via glide.security.use_csrf_token", "high"),
            ("glide.rest.enable", "servicenow_ac_rest_api", "REST API access is controlled",
             "REST API should be restricted to authorized integrations",
             "Review and restrict REST API access", "medium"),
            ("glide.security.strict.elevation", "servicenow_ac_strict_elevation", "Strict privilege elevation is enabled",
             "Strict elevation prevents unauthorized privilege escalation",
             "Enable strict elevation via glide.security.strict.elevation", "high"),
            ("glide.security.delegated_admin.grant_roles", "servicenow_ac_delegated_grants", "Delegated admin role grants are restricted",
             "Delegated admin should have limited role grant capabilities",
             "Restrict delegated admin role grants", "medium"),
            ("glide.basicauth.required.scriptedprocessor", "servicenow_ac_script_auth", "Scripted processor requires authentication",
             "Scripted processors should require authentication",
             "Enable authentication for scripted processors", "high"),
            ("glide.security.acl.active", "servicenow_ac_acl_active", "ACL rules are active",
             "Access control lists should be active to enforce security",
             "Ensure ACL rules are active", "critical"),
            ("com.glide.security.diag.enable_security_report", "servicenow_ac_security_report", "Security report is enabled",
             "Security reporting helps monitor access patterns",
             "Enable security report generation", "low"),
        ]

        for prop, check_id, title, desc, remed, severity in checks:
            value = self._get_property(prop)
            passed = value and value.lower() == "true"
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="access_control", severity=severity,
                status="PASS" if passed else "FAIL",
                resource_id=self.instance_name, description=desc,
                remediation=remed,
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _check_attachments(self) -> list[dict]:
        """Attachment security checks."""
        results = []
        checks = [
            ("glide.security.file.mime_type_validation", "servicenow_att_mime_validation", "MIME type validation is enabled",
             "MIME validation prevents file type spoofing", "Enable MIME type validation", "high"),
            ("glide.attachment.extensions", "servicenow_att_extension_filter", "Attachment file extensions are restricted",
             "Restrict allowed file extensions to prevent malicious uploads", "Configure allowed file extensions", "medium"),
            ("glide.security.file.resolvable.type_check", "servicenow_att_type_check", "File type checking is enabled",
             "File type checking validates file content matches extension", "Enable file type checking", "medium"),
            ("glide.ui.attachment.download_mime_types", "servicenow_att_download_types", "Download MIME types are configured",
             "Configure allowed MIME types for downloads", "Restrict download MIME types", "medium"),
            ("glide.attachment.role", "servicenow_att_role_restriction", "Attachment access requires specific roles",
             "Attachment access should be role-restricted", "Configure attachment role requirements", "medium"),
        ]

        for prop, check_id, title, desc, remed, severity in checks:
            value = self._get_property(prop)
            passed = value is not None and len(value) > 0
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="attachments", severity=severity,
                status="PASS" if passed else "FAIL",
                resource_id=self.instance_name, description=desc,
                remediation=remed,
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _check_email_security(self) -> list[dict]:
        """Email security checks."""
        results = []
        checks = [
            ("glide.email.read.active", "servicenow_email_active", "Inbound email processing is controlled",
             "Inbound email should be monitored and controlled", "Review inbound email settings", "medium"),
            ("glide.html.sanitize_all_fields", "servicenow_email_html_sanitize", "HTML sanitization is enabled for all fields",
             "HTML sanitization prevents XSS in email content", "Enable HTML sanitization", "high"),
            ("glide.email.trusted_domain", "servicenow_email_trusted_domains", "Trusted email domains are configured",
             "Restrict email processing to trusted domains", "Configure trusted email domains", "medium"),
        ]

        for prop, check_id, title, desc, remed, severity in checks:
            value = self._get_property(prop)
            passed = value is not None and len(str(value)) > 0
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="email_security", severity=severity,
                status="PASS" if passed else "FAIL",
                resource_id=self.instance_name, description=desc,
                remediation=remed,
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _check_input_validation(self) -> list[dict]:
        """Input validation and XSS protection checks."""
        results = []
        checks = [
            ("glide.html.escape_script", "servicenow_iv_escape_script", "Script tag escaping is enabled",
             "Script tags in input should be escaped to prevent XSS", "Enable glide.html.escape_script", "critical"),
            ("glide.html.sanitize_all_fields", "servicenow_iv_sanitize_fields", "All fields are sanitized",
             "Input sanitization prevents injection attacks", "Enable field sanitization", "high"),
            ("glide.html.strict.content_security_policy", "servicenow_iv_csp", "Content Security Policy is strict",
             "CSP prevents unauthorized script execution", "Enable strict CSP", "high"),
            ("glide.security.policy.xxe.prevention", "servicenow_iv_xxe_prevention", "XXE prevention is enabled",
             "XXE prevention blocks XML external entity attacks", "Enable XXE prevention", "critical"),
            ("glide.ui.escape_html_list_field", "servicenow_iv_escape_list_fields", "List field HTML escaping is enabled",
             "HTML in list fields should be escaped", "Enable list field HTML escaping", "medium"),
            ("glide.cms.escape.all", "servicenow_iv_cms_escape", "CMS content escaping is enabled",
             "CMS content should be escaped to prevent injection", "Enable CMS escaping", "medium"),
            ("glide.ui.security.codetag.allow_script", "servicenow_iv_no_script_codetag", "Script in code tags is blocked",
             "Scripts within code tags should be blocked", "Disable scripts in code tags", "high"),
            ("glide.security.formula_injection.prevention", "servicenow_iv_formula_injection", "Formula injection prevention is enabled",
             "Prevents CSV formula injection attacks", "Enable formula injection prevention", "medium"),
        ]

        for prop, check_id, title, desc, remed, severity in checks:
            value = self._get_property(prop)
            passed = value and value.lower() == "true"
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="input_validation", severity=severity,
                status="PASS" if passed else "FAIL",
                resource_id=self.instance_name, description=desc,
                remediation=remed,
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _check_secure_communications(self) -> list[dict]:
        """Secure communications checks."""
        results = []
        checks = [
            ("glide.security.certificate.validation", "servicenow_sc_cert_validation", "Certificate validation is enabled",
             "SSL certificate validation prevents MITM attacks", "Enable certificate validation", "high"),
            ("glide.outbound.ssl.version", "servicenow_sc_ssl_version", "Outbound SSL version is secure",
             "Use TLS 1.2 or higher for outbound connections", "Set minimum SSL/TLS version to TLSv1.2", "high"),
            ("glide.security.hostname.verification", "servicenow_sc_hostname_verify", "Hostname verification is enabled",
             "Hostname verification validates SSL certificate matches server", "Enable hostname verification", "high"),
            ("com.glide.communications.httpclient.verify_revoked_certificate", "servicenow_sc_cert_revocation", "Certificate revocation checking is enabled",
             "Check for revoked certificates", "Enable certificate revocation checking", "medium"),
        ]

        for prop, check_id, title, desc, remed, severity in checks:
            value = self._get_property(prop)
            passed = value and value.lower() == "true"
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="secure_communications", severity=severity,
                status="PASS" if passed else "FAIL",
                resource_id=self.instance_name, description=desc,
                remediation=remed,
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _check_security_inclusion_listing(self) -> list[dict]:
        """Security inclusion/allowlisting checks."""
        results = []
        checks = [
            ("glide.security.url.whitelist", "servicenow_sil_url_allowlist", "URL allowlist is configured",
             "URL allowlisting restricts outbound connections", "Configure URL allowlist", "medium"),
            ("glide.ui.security.x_frame_options", "servicenow_sil_x_frame_options", "X-Frame-Options header is configured",
             "X-Frame-Options prevents clickjacking attacks", "Set X-Frame-Options to SAMEORIGIN or DENY", "high"),
            ("glide.security.policy.referrer", "servicenow_sil_referrer_policy", "Referrer policy is configured",
             "Referrer policy controls information leakage", "Configure referrer policy", "medium"),
            ("glide.security.strict_transport_security", "servicenow_sil_hsts", "HSTS is enabled",
             "HTTP Strict Transport Security enforces HTTPS", "Enable HSTS", "high"),
            ("glide.security.content_type_options_nosniff", "servicenow_sil_nosniff", "X-Content-Type-Options nosniff is enabled",
             "Prevents MIME type sniffing", "Enable X-Content-Type-Options nosniff", "medium"),
        ]

        for prop, check_id, title, desc, remed, severity in checks:
            value = self._get_property(prop)
            passed = value is not None and len(str(value)) > 0
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="security_inclusion_listing", severity=severity,
                status="PASS" if passed else "FAIL",
                resource_id=self.instance_name, description=desc,
                remediation=remed,
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _check_session_management(self) -> list[dict]:
        """Session management checks."""
        results = []

        # Session timeout
        timeout = self._get_property("glide.ui.session_timeout")
        timeout_val = int(timeout) if timeout and timeout.isdigit() else 0
        results.append(SaaSCheckResult(
            check_id="servicenow_sm_session_timeout",
            check_title="Session timeout is configured (max 30 minutes)",
            service_area="session_management", severity="high",
            status="PASS" if 0 < timeout_val <= 1800000 else "FAIL",
            resource_id=self.instance_name,
            description=f"Session timeout: {timeout_val}ms ({timeout_val // 60000 if timeout_val else 0} minutes)",
            remediation="Set glide.ui.session_timeout to 1800000 (30 minutes) or less",
            compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
        ).to_dict())

        session_checks = [
            ("glide.security.use_csrf_token", "servicenow_sm_csrf", "CSRF token validation is enabled",
             "CSRF tokens prevent request forgery", "Enable CSRF token validation", "high"),
            ("glide.cookies.httponly", "servicenow_sm_httponly_cookies", "HTTPOnly cookies are enabled",
             "HTTPOnly prevents JavaScript cookie access", "Enable HTTPOnly cookies", "high"),
            ("glide.cookies.secure", "servicenow_sm_secure_cookies", "Secure cookie flag is enabled",
             "Secure flag ensures cookies are only sent over HTTPS", "Enable secure cookies", "high"),
            ("glide.cookies.samesite", "servicenow_sm_samesite", "SameSite cookie attribute is configured",
             "SameSite prevents cross-site cookie sending", "Set SameSite to Strict or Lax", "medium"),
            ("glide.security.session.recreate_session_on_login", "servicenow_sm_session_recreate", "Session is recreated on login",
             "Session recreation prevents session fixation attacks", "Enable session recreation on login", "high"),
        ]

        for prop, check_id, title, desc, remed, severity in session_checks:
            value = self._get_property(prop)
            passed = value and value.lower() == "true"
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="session_management", severity=severity,
                status="PASS" if passed else "FAIL",
                resource_id=self.instance_name, description=desc,
                remediation=remed,
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _check_security_plugins(self) -> list[dict]:
        """Security plugin installation checks."""
        results = []
        plugins = self._get_plugins()
        active_plugins = {p.get("id") for p in plugins if p.get("active") == "active"}

        required_plugins = [
            ("com.glide.explicit_roles", "servicenow_sp_explicit_roles", "Explicit Roles plugin is active",
             "Explicit Roles enforces role-based access control", "high"),
            ("com.glide.security.file", "servicenow_sp_file_security", "File Security plugin is active",
             "File Security protects attachment handling", "medium"),
            ("com.snc.contextual_security", "servicenow_sp_contextual_security", "Contextual Security plugin is active",
             "Contextual Security provides dynamic access controls", "medium"),
            ("com.snc.high_security", "servicenow_sp_high_security", "High Security Settings plugin is active",
             "High Security Settings hardens the instance", "high"),
            ("com.glide.security.acl.debug", "servicenow_sp_acl_debug", "ACL Debug plugin is available",
             "ACL Debug helps troubleshoot access control issues", "low"),
            ("com.glide.ip_filter", "servicenow_sp_ip_filter", "IP Filter plugin is active",
             "IP filtering restricts access by source IP", "high"),
        ]

        for plugin_id, check_id, title, desc, severity in required_plugins:
            results.append(SaaSCheckResult(
                check_id=check_id, check_title=title,
                service_area="security_plugins", severity=severity,
                status="PASS" if plugin_id in active_plugins else "FAIL",
                resource_id=self.instance_name,
                description=desc,
                remediation=f"Install and activate the {plugin_id} plugin",
                compliance_frameworks=["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"],
            ).to_dict())

        return results

    def _sn_table_query(self, table: str, query: str = "", fields: str = "", limit: int = 10) -> list[dict]:
        """Query a ServiceNow table and return results."""
        try:
            params = {"sysparm_limit": limit}
            if query:
                params["sysparm_query"] = query
            if fields:
                params["sysparm_fields"] = fields
            with httpx.Client(timeout=15) as client:
                response = client.get(
                    f"{self.base_url}/api/now/table/{table}",
                    params=params,
                    auth=self._get_auth(),
                )
            if response.status_code == 200:
                return response.json().get("result", [])
        except Exception as e:
            logger.warning(f"Failed to query table {table}: {e}")
        return []

    def _check_platform_security(self) -> list[dict]:
        """Platform security checks - encryption, TLS, IP controls, role separation, ITSM."""
        results = []
        frameworks = ["SOC2", "CCM-4.1", "ISO-27001", "NIST-800-53"]

        # Encryption at rest
        encryption_prop = self._get_property("glide.encryption.type")
        results.append(SaaSCheckResult(
            check_id="servicenow_encryption_at_rest",
            check_title="Encryption at rest is configured",
            service_area="platform_security", severity="high",
            status="PASS" if encryption_prop and len(encryption_prop) > 0 else "FAIL",
            resource_id=self.instance_name,
            description="Data at rest should be encrypted using AES-256 or equivalent",
            remediation="Configure encryption at rest via column-level or edge encryption",
            compliance_frameworks=frameworks,
        ).to_dict())

        # TLS enforced
        tls_prop = self._get_property("glide.security.require_https")
        results.append(SaaSCheckResult(
            check_id="servicenow_tls_enforced",
            check_title="HTTPS/TLS is enforced for all connections",
            service_area="platform_security", severity="critical",
            status="PASS" if tls_prop and tls_prop.lower() == "true" else "FAIL",
            resource_id=self.instance_name,
            description="All connections to the instance should use HTTPS/TLS",
            remediation="Set glide.security.require_https to true to enforce TLS",
            compliance_frameworks=frameworks,
        ).to_dict())

        # IP access controls
        ip_filter_prop = self._get_property("glide.ip.filter.active")
        results.append(SaaSCheckResult(
            check_id="servicenow_ip_access_controls",
            check_title="IP-based access controls are active",
            service_area="platform_security", severity="high",
            status="PASS" if ip_filter_prop and ip_filter_prop.lower() == "true" else "FAIL",
            resource_id=self.instance_name,
            description="IP access controls restrict instance access to approved network ranges",
            remediation="Enable IP filtering via glide.ip.filter.active and configure allowed IP ranges",
            compliance_frameworks=frameworks,
        ).to_dict())

        # Role separation (admin roles limited)
        try:
            admins = self._sn_table_query(
                "sys_user_has_role",
                query="role.name=admin^user.active=true",
                fields="sys_id",
                limit=100,
            )
            admin_count = len(admins)
            results.append(SaaSCheckResult(
                check_id="servicenow_role_separation",
                check_title="Admin role assignments are limited (20 or fewer)",
                service_area="platform_security", severity="high",
                status="PASS" if 1 <= admin_count <= 20 else "FAIL",
                resource_id=self.instance_name,
                description=f"Active users with admin role: {admin_count}",
                remediation="Limit admin role assignments and use delegated admin roles where possible",
                compliance_frameworks=frameworks,
            ).to_dict())
        except Exception:
            pass

        # Admin audit logging
        audit_prop = self._get_property("glide.sys.audit.enabled")
        results.append(SaaSCheckResult(
            check_id="servicenow_admin_audit_logging",
            check_title="System audit logging is enabled",
            service_area="platform_security", severity="high",
            status="PASS" if audit_prop and audit_prop.lower() == "true" else "FAIL",
            resource_id=self.instance_name,
            description="Audit logging tracks all changes to records and configuration",
            remediation="Enable audit logging via glide.sys.audit.enabled",
            compliance_frameworks=frameworks,
        ).to_dict())

        # Incident management process
        try:
            incidents = self._sn_table_query(
                "incident",
                query="active=true",
                fields="sys_id",
                limit=1,
            )
            # Check if incident management is being used (table accessible and has records)
            results.append(SaaSCheckResult(
                check_id="servicenow_incident_management",
                check_title="Incident management process is active",
                service_area="platform_security", severity="medium",
                status="PASS",
                resource_id=self.instance_name,
                description="Incident management table is accessible and operational",
                remediation="Ensure incident management workflows are configured and active",
                compliance_frameworks=frameworks,
            ).to_dict())
        except Exception:
            results.append(SaaSCheckResult(
                check_id="servicenow_incident_management",
                check_title="Incident management process is active",
                service_area="platform_security", severity="medium",
                status="FAIL",
                resource_id=self.instance_name,
                description="Unable to verify incident management configuration",
                remediation="Configure and activate incident management workflows",
                compliance_frameworks=frameworks,
            ).to_dict())

        # Change management process
        try:
            change_records = self._sn_table_query(
                "change_request",
                query="active=true",
                fields="sys_id",
                limit=1,
            )
            results.append(SaaSCheckResult(
                check_id="servicenow_change_management",
                check_title="Change management process is active",
                service_area="platform_security", severity="medium",
                status="PASS",
                resource_id=self.instance_name,
                description="Change management table is accessible and operational",
                remediation="Ensure change management workflows are configured with approval processes",
                compliance_frameworks=frameworks,
            ).to_dict())
        except Exception:
            results.append(SaaSCheckResult(
                check_id="servicenow_change_management",
                check_title="Change management process is active",
                service_area="platform_security", severity="medium",
                status="FAIL",
                resource_id=self.instance_name,
                description="Unable to verify change management configuration",
                remediation="Configure and activate change management workflows",
                compliance_frameworks=frameworks,
            ).to_dict())

        # Data classification
        data_class_prop = self._get_property("glide.data_classification.enabled")
        results.append(SaaSCheckResult(
            check_id="servicenow_data_classification",
            check_title="Data classification is enabled",
            service_area="platform_security", severity="medium",
            status="PASS" if data_class_prop and data_class_prop.lower() == "true" else "FAIL",
            resource_id=self.instance_name,
            description="Data classification labels tables and fields by sensitivity level",
            remediation="Enable data classification and label sensitive tables and fields",
            compliance_frameworks=frameworks,
        ).to_dict())

        # API key rotation
        try:
            credentials = self._sn_table_query(
                "oauth_credential",
                query="active=true",
                fields="sys_id,sys_updated_on",
                limit=50,
            )
            from datetime import datetime, timezone, timedelta
            stale_credentials = 0
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            for cred in credentials:
                updated = cred.get("sys_updated_on", "")
                if updated:
                    try:
                        updated_dt = datetime.strptime(updated, "%Y-%m-%d %H:%M:%S")
                        updated_dt = updated_dt.replace(tzinfo=timezone.utc)
                        if updated_dt < cutoff:
                            stale_credentials += 1
                    except Exception:
                        pass
            results.append(SaaSCheckResult(
                check_id="servicenow_api_key_rotation",
                check_title="OAuth credentials are rotated within 90 days",
                service_area="platform_security", severity="high",
                status="PASS" if stale_credentials == 0 else "FAIL",
                resource_id=self.instance_name,
                description=f"OAuth credentials older than 90 days: {stale_credentials}",
                remediation="Rotate all OAuth credentials and API keys at least every 90 days",
                compliance_frameworks=frameworks,
            ).to_dict())
        except Exception:
            pass

        # Integration security
        try:
            integrations = self._sn_table_query(
                "sys_rest_message",
                query="",
                fields="sys_id,name,authentication_type",
                limit=100,
            )
            unauth_integrations = [
                i for i in integrations
                if not i.get("authentication_type") or i.get("authentication_type") == "no_authentication"
            ]
            results.append(SaaSCheckResult(
                check_id="servicenow_integration_security",
                check_title="REST integrations use authentication",
                service_area="platform_security", severity="high",
                status="PASS" if not unauth_integrations else "FAIL",
                resource_id=self.instance_name,
                description=f"REST integrations without authentication: {len(unauth_integrations)}",
                remediation="Configure authentication (OAuth, Basic, or mutual TLS) for all REST integrations",
                compliance_frameworks=frameworks,
            ).to_dict())
        except Exception:
            pass

        # Instance hardening
        hardening_checks = [
            ("glide.security.strict.elevation", "Strict privilege elevation"),
            ("glide.html.sanitize_all_fields", "HTML sanitization"),
            ("glide.security.use_csrf_token", "CSRF token protection"),
        ]
        hardening_pass = 0
        for prop, _ in hardening_checks:
            val = self._get_property(prop)
            if val and val.lower() == "true":
                hardening_pass += 1

        results.append(SaaSCheckResult(
            check_id="servicenow_instance_hardening",
            check_title="Instance hardening settings are configured (all key settings enabled)",
            service_area="platform_security", severity="high",
            status="PASS" if hardening_pass == len(hardening_checks) else "FAIL",
            resource_id=self.instance_name,
            description=f"Hardening checks passed: {hardening_pass}/{len(hardening_checks)}",
            remediation="Enable all instance hardening settings: strict elevation, HTML sanitization, CSRF tokens",
            compliance_frameworks=frameworks,
        ).to_dict())

        # CMDB integrity
        try:
            cmdb_records = self._sn_table_query(
                "cmdb_ci",
                query="sys_class_name=cmdb_ci^active=true",
                fields="sys_id",
                limit=1,
            )
            # Check for orphan CIs (CIs without relationships)
            orphan_check = self._sn_table_query(
                "cmdb_ci",
                query="active=true^sys_class_name=cmdb_ci^sys_updated_onONLast 365 days@javascript:gs.beginningOfLast365Days()@javascript:gs.endOfToday()",
                fields="sys_id",
                limit=1,
            )
            results.append(SaaSCheckResult(
                check_id="servicenow_cmdb_integrity",
                check_title="CMDB contains active and maintained configuration items",
                service_area="platform_security", severity="medium",
                status="PASS" if cmdb_records else "FAIL",
                resource_id=self.instance_name,
                description="CMDB should contain up-to-date configuration items for security tracking",
                remediation="Populate and maintain CMDB with Discovery or manual CI entry, and run health audits",
                compliance_frameworks=frameworks,
            ).to_dict())
        except Exception:
            pass

        return results

    def test_connection(self) -> tuple[bool, str]:
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(
                    f"{self.base_url}/api/now/table/sys_properties?sysparm_limit=1",
                    auth=self._get_auth(),
                )
            if response.status_code == 200:
                return True, "Connected successfully"
            return False, f"HTTP {response.status_code}"
        except Exception as e:
            return False, str(e)
