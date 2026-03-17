"""Google Workspace SaaS Security Scanner.

Implements 22 security checks across 4 auditor categories:
- Users: Admin MFA, user 2FA enrollment, suspended accounts, password policy, admin count, super admin usage
- Security: SSO configured, security keys for admins, login challenges, less secure apps, app access control
- Email Security: SPF/DKIM/DMARC configured, email allowlist review, content compliance, phishing protections
- Drive & Data: External sharing restrictions, link sharing defaults, DLP rules configured
"""
import json
import logging

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult

logger = logging.getLogger(__name__)

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    service_account = None
    build = None
    HttpError = None
    logger.warning(
        "Google API client not installed. Install with: "
        "pip install google-api-python-client google-auth"
    )


class GoogleWorkspaceScanner(BaseSaaSScanner):
    """Google Workspace SaaS security scanner."""

    provider_type = "google_workspace"

    ADMIN_SCOPES = [
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/apps.groups.settings",
    ]

    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self.admin_email = credentials["admin_email"]
        self.domain = credentials["domain"]
        service_account_key = credentials["service_account_key"]
        if isinstance(service_account_key, str):
            self._sa_info = json.loads(service_account_key)
        else:
            self._sa_info = service_account_key
        self._directory_service = None
        self._reports_service = None

    def _get_credentials(self):
        """Build delegated credentials for the admin user."""
        if service_account is None:
            raise ImportError("google-auth is not installed")
        creds = service_account.Credentials.from_service_account_info(
            self._sa_info, scopes=self.ADMIN_SCOPES
        )
        return creds.with_subject(self.admin_email)

    def _get_directory_service(self):
        """Get the Admin SDK Directory API service."""
        if self._directory_service:
            return self._directory_service
        if build is None:
            raise ImportError("google-api-python-client is not installed")
        creds = self._get_credentials()
        self._directory_service = build("admin", "directory_v1", credentials=creds)
        return self._directory_service

    def _get_reports_service(self):
        """Get the Admin SDK Reports API service."""
        if self._reports_service:
            return self._reports_service
        if build is None:
            raise ImportError("google-api-python-client is not installed")
        creds = self._get_credentials()
        self._reports_service = build("admin", "reports_v1", credentials=creds)
        return self._reports_service

    def run_all_checks(self) -> list[dict]:
        """Run all Google Workspace security checks."""
        results = []
        check_groups = [
            self._check_users,
            self._check_security,
            self._check_email_security,
            self._check_drive_and_data,
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"Google Workspace check group failed: {e}")

        return results

    def _check_users(self) -> list[dict]:
        """User security checks."""
        results = []

        try:
            service = self._get_directory_service()

            # Get all users
            users = []
            request = service.users().list(domain=self.domain, maxResults=500)
            while request:
                try:
                    response = request.execute()
                    users.extend(response.get("users", []))
                    request = service.users().list_next(request, response)
                except Exception:
                    break

            admin_count = 0
            super_admin_count = 0
            suspended_count = 0
            no_2fa_count = 0

            for user in users:
                user_id = user.get("id", "")
                email = user.get("primaryEmail", "Unknown")
                is_admin = user.get("isAdmin", False)
                is_delegated_admin = user.get("isDelegatedAdmin", False)
                is_suspended = user.get("suspended", False)
                is_enrolled_2fa = user.get("isEnrolledIn2Sv", False)
                is_enforced_2fa = user.get("isEnforcedIn2Sv", False)

                if is_suspended:
                    suspended_count += 1
                    continue

                # 2FA enrollment check
                if not is_enrolled_2fa:
                    no_2fa_count += 1

                results.append(SaaSCheckResult(
                    check_id="gws_user_2fa_enrolled",
                    check_title="User is enrolled in 2-step verification",
                    service_area="users", severity="high",
                    status="PASS" if is_enrolled_2fa else "FAIL",
                    resource_id=user_id, resource_name=email,
                    description=f"User {email} 2SV enrolled: {is_enrolled_2fa}, enforced: {is_enforced_2fa}",
                    remediation="Enroll user in 2-step verification via Admin Console > Security",
                    remediation_url="https://admin.google.com/ac/security/2sv",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())

                # Admin MFA enforced
                if is_admin or is_delegated_admin:
                    admin_count += 1
                    if is_admin and not is_delegated_admin:
                        super_admin_count += 1

                    results.append(SaaSCheckResult(
                        check_id="gws_admin_mfa_enforced",
                        check_title="Admin user has 2-step verification enforced",
                        service_area="users", severity="critical",
                        status="PASS" if is_enforced_2fa else "FAIL",
                        resource_id=user_id, resource_name=email,
                        description=f"Admin {email} has 2SV enforced: {is_enforced_2fa}",
                        remediation="Enforce 2-step verification for all admin users",
                        remediation_url="https://admin.google.com/ac/security/2sv",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                    ).to_dict())

            # Suspended accounts cleanup
            results.append(SaaSCheckResult(
                check_id="gws_suspended_accounts_reviewed",
                check_title="Suspended accounts are reviewed and cleaned up",
                service_area="users", severity="low",
                status="PASS" if suspended_count <= 5 else "FAIL",
                resource_id=self.domain,
                description=f"Suspended accounts: {suspended_count}. Should be periodically reviewed and deleted",
                remediation="Review suspended accounts and delete those no longer needed",
                remediation_url="https://admin.google.com/ac/users",
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
            ).to_dict())

            # Password policy strength
            try:
                # Check password length and strength requirements via customer settings
                reports = self._get_reports_service()
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_PASSWORD_MIN_LENGTH",
                    maxResults=1
                ).execute()
                events = activities.get("items", [])
                if events:
                    params = events[0].get("events", [{}])[0].get("parameters", [])
                    min_length = None
                    for p in params:
                        if p.get("name") == "NEW_VALUE":
                            min_length = p.get("intValue")
                    password_strong = min_length is not None and int(min_length) >= 12
                else:
                    password_strong = False

                results.append(SaaSCheckResult(
                    check_id="gws_password_policy_strength",
                    check_title="Password policy requires minimum 12 characters",
                    service_area="users", severity="high",
                    status="PASS" if password_strong else "FAIL",
                    resource_id=self.domain,
                    description="Password policy should require strong passwords with minimum 12 characters",
                    remediation="Set minimum password length to 12+ characters in Admin Console > Security > Password management",
                    remediation_url="https://admin.google.com/ac/security/passwordmanagement",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check password policy: {e}")
                results.append(SaaSCheckResult(
                    check_id="gws_password_policy_strength",
                    check_title="Password policy requires minimum 12 characters",
                    service_area="users", severity="high", status="FAIL",
                    resource_id=self.domain,
                    description="Unable to verify password policy strength",
                    remediation="Verify password policy in Admin Console > Security > Password management",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())

            # Admin count review
            results.append(SaaSCheckResult(
                check_id="gws_admin_count_appropriate",
                check_title="Admin count is between 2 and 10",
                service_area="users", severity="high",
                status="PASS" if 2 <= admin_count <= 10 else "FAIL",
                resource_id=self.domain,
                description=f"Total admins: {admin_count} (super admins: {super_admin_count}). Recommended: 2-10",
                remediation="Maintain between 2 and 10 admin accounts for availability and least privilege",
                remediation_url="https://admin.google.com/ac/users",
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
            ).to_dict())

            # Super admin usage
            results.append(SaaSCheckResult(
                check_id="gws_super_admin_minimal",
                check_title="Super admin accounts are minimized (2-3 recommended)",
                service_area="users", severity="critical",
                status="PASS" if 1 <= super_admin_count <= 3 else "FAIL",
                resource_id=self.domain,
                description=f"Super admin accounts: {super_admin_count}. Should be 2-3 for emergency access only",
                remediation="Limit super admin accounts to 2-3. Use delegated admin roles for daily tasks",
                remediation_url="https://admin.google.com/ac/roles",
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"Google Workspace user checks failed: {e}")

        return results

    def _check_security(self) -> list[dict]:
        """Security configuration checks."""
        results = []

        try:
            reports = self._get_reports_service()

            # SSO configured - check via admin audit logs for SSO profile changes
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="ADD_SSO_PROFILE",
                    maxResults=1
                ).execute()
                sso_configured = bool(activities.get("items", []))

                results.append(SaaSCheckResult(
                    check_id="gws_sso_configured",
                    check_title="Single Sign-On (SSO) is configured",
                    service_area="security", severity="high",
                    status="PASS" if sso_configured else "FAIL",
                    resource_id=self.domain,
                    description="SSO provides centralized authentication through an identity provider",
                    remediation="Configure SSO with your identity provider in Admin Console > Security > SSO with third-party IdP",
                    remediation_url="https://admin.google.com/ac/security/ssowithidp",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check SSO configuration: {e}")

            # Security keys required for admins
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="ENFORCE_STRONG_AUTHENTICATION",
                    maxResults=1
                ).execute()
                security_keys_enforced = bool(activities.get("items", []))

                results.append(SaaSCheckResult(
                    check_id="gws_security_keys_admins",
                    check_title="Security keys are required for admin accounts",
                    service_area="security", severity="high",
                    status="PASS" if security_keys_enforced else "FAIL",
                    resource_id=self.domain,
                    description="Phishing-resistant security keys provide the strongest form of 2SV for admins",
                    remediation="Require security keys for admin accounts in Admin Console > Security > Advanced settings",
                    remediation_url="https://admin.google.com/ac/security/2sv",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check security keys enforcement: {e}")

            # Login challenges enabled
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_LOGIN_CHALLENGE_STATUS",
                    maxResults=1
                ).execute()
                events = activities.get("items", [])
                login_challenges_enabled = True  # Default is enabled
                if events:
                    params = events[0].get("events", [{}])[0].get("parameters", [])
                    for p in params:
                        if p.get("name") == "NEW_VALUE" and p.get("value") == "OFF":
                            login_challenges_enabled = False

                results.append(SaaSCheckResult(
                    check_id="gws_login_challenges_enabled",
                    check_title="Login challenges are enabled for suspicious sign-ins",
                    service_area="security", severity="medium",
                    status="PASS" if login_challenges_enabled else "FAIL",
                    resource_id=self.domain,
                    description="Login challenges add extra verification when suspicious activity is detected",
                    remediation="Enable login challenges in Admin Console > Security > Login challenges",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check login challenges: {e}")

            # Less secure apps disabled
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_ALLOW_LESS_SECURE_APPS",
                    maxResults=1
                ).execute()
                events = activities.get("items", [])
                less_secure_disabled = True  # Modern default
                if events:
                    params = events[0].get("events", [{}])[0].get("parameters", [])
                    for p in params:
                        if p.get("name") == "NEW_VALUE" and p.get("value") == "ALLOWED":
                            less_secure_disabled = False

                results.append(SaaSCheckResult(
                    check_id="gws_less_secure_apps_disabled",
                    check_title="Less secure app access is disabled",
                    service_area="security", severity="high",
                    status="PASS" if less_secure_disabled else "FAIL",
                    resource_id=self.domain,
                    description="Less secure apps use basic authentication which bypasses 2SV",
                    remediation="Disable less secure app access in Admin Console > Security > Less secure apps",
                    remediation_url="https://admin.google.com/ac/security/lsa",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check less secure apps: {e}")

            # App access control (third-party app permissions)
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_APP_ACCESS_SETTINGS_CHANGE_APP_ACCESS",
                    maxResults=1
                ).execute()
                events = activities.get("items", [])
                app_access_restricted = bool(events)

                results.append(SaaSCheckResult(
                    check_id="gws_app_access_controlled",
                    check_title="Third-party app access is controlled",
                    service_area="security", severity="high",
                    status="PASS" if app_access_restricted else "FAIL",
                    resource_id=self.domain,
                    description="Third-party app access control prevents unauthorized OAuth consent to risky apps",
                    remediation="Review and restrict third-party app access in Admin Console > Security > API controls",
                    remediation_url="https://admin.google.com/ac/owl/list?tab=configuredApps",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check app access control: {e}")

        except Exception as e:
            logger.warning(f"Google Workspace security checks failed: {e}")

        return results

    def _check_email_security(self) -> list[dict]:
        """Email security checks (SPF, DKIM, DMARC)."""
        results = []

        try:
            import dns.resolver
            has_dns = True
        except ImportError:
            has_dns = False
            logger.warning("dnspython not installed. DNS checks will be skipped. Install with: pip install dnspython")

        if has_dns:
            domain = self.domain

            # SPF check
            try:
                answers = dns.resolver.resolve(domain, "TXT")
                spf_records = [
                    str(r) for r in answers if "v=spf1" in str(r)
                ]
                has_spf = len(spf_records) > 0
                spf_strict = any("-all" in r for r in spf_records)

                results.append(SaaSCheckResult(
                    check_id="gws_email_spf_configured",
                    check_title="SPF record is configured for the domain",
                    service_area="email_security", severity="high",
                    status="PASS" if has_spf else "FAIL",
                    resource_id=domain,
                    description=f"SPF record: {spf_records[0] if spf_records else 'not found'}",
                    remediation="Add an SPF TXT record to your DNS: v=spf1 include:_spf.google.com -all",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())

                results.append(SaaSCheckResult(
                    check_id="gws_email_spf_strict",
                    check_title="SPF record uses strict fail (-all) policy",
                    service_area="email_security", severity="medium",
                    status="PASS" if spf_strict else "FAIL",
                    resource_id=domain,
                    description="SPF should use '-all' (hard fail) rather than '~all' (soft fail)",
                    remediation="Update SPF record to use '-all' instead of '~all'",
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check SPF: {e}")

            # DKIM check
            try:
                dkim_selector = "google"
                dkim_domain = f"{dkim_selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, "TXT")
                has_dkim = len(list(answers)) > 0

                results.append(SaaSCheckResult(
                    check_id="gws_email_dkim_configured",
                    check_title="DKIM is configured for the domain",
                    service_area="email_security", severity="high",
                    status="PASS" if has_dkim else "FAIL",
                    resource_id=domain,
                    description="DKIM cryptographically signs outbound email to prevent spoofing",
                    remediation="Enable DKIM in Admin Console > Apps > Google Workspace > Gmail > Authenticate email",
                    remediation_url="https://admin.google.com/ac/apps/gmail/authenticateemail",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except dns.resolver.NXDOMAIN:
                results.append(SaaSCheckResult(
                    check_id="gws_email_dkim_configured",
                    check_title="DKIM is configured for the domain",
                    service_area="email_security", severity="high",
                    status="FAIL",
                    resource_id=domain,
                    description="No DKIM record found at google._domainkey." + domain,
                    remediation="Enable DKIM in Admin Console > Apps > Google Workspace > Gmail > Authenticate email",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check DKIM: {e}")

            # DMARC check
            try:
                dmarc_domain = f"_dmarc.{domain}"
                answers = dns.resolver.resolve(dmarc_domain, "TXT")
                dmarc_records = [str(r) for r in answers if "v=DMARC1" in str(r)]
                has_dmarc = len(dmarc_records) > 0
                dmarc_reject = any("p=reject" in r for r in dmarc_records)
                dmarc_quarantine = any("p=quarantine" in r for r in dmarc_records)

                results.append(SaaSCheckResult(
                    check_id="gws_email_dmarc_configured",
                    check_title="DMARC record is configured for the domain",
                    service_area="email_security", severity="high",
                    status="PASS" if has_dmarc else "FAIL",
                    resource_id=domain,
                    description=f"DMARC record: {dmarc_records[0] if dmarc_records else 'not found'}",
                    remediation="Add a DMARC TXT record: _dmarc.{domain} v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())

                results.append(SaaSCheckResult(
                    check_id="gws_email_dmarc_policy_strict",
                    check_title="DMARC policy is set to reject or quarantine",
                    service_area="email_security", severity="high",
                    status="PASS" if dmarc_reject or dmarc_quarantine else "FAIL",
                    resource_id=domain,
                    description="DMARC policy should be 'reject' or 'quarantine' to prevent email spoofing",
                    remediation="Set DMARC policy to p=reject or p=quarantine",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except dns.resolver.NXDOMAIN:
                results.append(SaaSCheckResult(
                    check_id="gws_email_dmarc_configured",
                    check_title="DMARC record is configured for the domain",
                    service_area="email_security", severity="high",
                    status="FAIL",
                    resource_id=domain,
                    description="No DMARC record found at _dmarc." + domain,
                    remediation="Add a DMARC TXT record to your DNS",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check DMARC: {e}")

        # Email allowlist review and phishing protections via Reports API
        try:
            reports = self._get_reports_service()

            # Email allowlist check
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_EMAIL_SETTING",
                    maxResults=10
                ).execute()
                allowlist_events = [
                    e for e in activities.get("items", [])
                    if any(
                        "whitelist" in str(p.get("value", "")).lower() or "allowlist" in str(p.get("value", "")).lower()
                        for evt in e.get("events", [])
                        for p in evt.get("parameters", [])
                    )
                ]

                results.append(SaaSCheckResult(
                    check_id="gws_email_allowlist_reviewed",
                    check_title="Email allowlist entries are reviewed and minimal",
                    service_area="email_security", severity="medium",
                    status="PASS" if not allowlist_events else "FAIL",
                    resource_id=self.domain,
                    description="Email allowlists bypass spam filtering and should be minimized",
                    remediation="Review and minimize email allowlist entries in Admin Console > Apps > Gmail > Spam, Phishing and Malware",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check email allowlist: {e}")

            # Content compliance rules
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_EMAIL_SETTING",
                    maxResults=5
                ).execute()
                has_compliance = bool(activities.get("items", []))

                results.append(SaaSCheckResult(
                    check_id="gws_email_content_compliance",
                    check_title="Email content compliance rules are configured",
                    service_area="email_security", severity="medium",
                    status="PASS" if has_compliance else "FAIL",
                    resource_id=self.domain,
                    description="Content compliance rules help enforce data protection policies in email",
                    remediation="Configure content compliance rules in Admin Console > Apps > Gmail > Compliance",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check content compliance: {e}")

            # Phishing protections
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_SAFETY_SETTING",
                    maxResults=1
                ).execute()
                phishing_configured = bool(activities.get("items", []))

                results.append(SaaSCheckResult(
                    check_id="gws_email_phishing_protection",
                    check_title="Advanced phishing and malware protections are configured",
                    service_area="email_security", severity="high",
                    status="PASS" if phishing_configured else "FAIL",
                    resource_id=self.domain,
                    description="Advanced protections flag suspicious attachments and links in email",
                    remediation="Enable advanced phishing protections in Admin Console > Apps > Gmail > Safety",
                    remediation_url="https://admin.google.com/ac/apps/gmail/safety",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check phishing protections: {e}")

        except Exception as e:
            logger.warning(f"Google Workspace email security checks failed: {e}")

        return results

    def _check_drive_and_data(self) -> list[dict]:
        """Drive and data protection checks."""
        results = []

        try:
            reports = self._get_reports_service()

            # External sharing restrictions
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_DOCS_SETTING",
                    maxResults=10
                ).execute()
                sharing_events = activities.get("items", [])
                external_sharing_restricted = False
                for event in sharing_events:
                    for evt in event.get("events", []):
                        for param in evt.get("parameters", []):
                            if "sharing" in str(param.get("name", "")).lower():
                                if param.get("value") in ("RESTRICTED", "OFF", "SHARING_NOT_ALLOWED"):
                                    external_sharing_restricted = True

                results.append(SaaSCheckResult(
                    check_id="gws_drive_external_sharing_restricted",
                    check_title="External file sharing is restricted",
                    service_area="drive_and_data", severity="high",
                    status="PASS" if external_sharing_restricted else "FAIL",
                    resource_id=self.domain,
                    description="External sharing should be restricted or require approval to prevent data leakage",
                    remediation="Restrict external sharing in Admin Console > Apps > Google Workspace > Drive > Sharing settings",
                    remediation_url="https://admin.google.com/ac/apps/sites/sharing",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check external sharing: {e}")

            # Link sharing defaults
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CHANGE_DOCS_SETTING",
                    maxResults=10
                ).execute()
                link_sharing_restricted = False
                for event in activities.get("items", []):
                    for evt in event.get("events", []):
                        for param in evt.get("parameters", []):
                            if "link_sharing" in str(param.get("name", "")).lower():
                                if "restricted" in str(param.get("value", "")).lower():
                                    link_sharing_restricted = True

                results.append(SaaSCheckResult(
                    check_id="gws_drive_link_sharing_defaults",
                    check_title="Default link sharing is set to restricted",
                    service_area="drive_and_data", severity="high",
                    status="PASS" if link_sharing_restricted else "FAIL",
                    resource_id=self.domain,
                    description="Default link sharing should be restricted to specific people, not anyone with the link",
                    remediation="Set default link sharing to 'Restricted' in Drive sharing settings",
                    remediation_url="https://admin.google.com/ac/apps/sites/sharing",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check link sharing defaults: {e}")

            # DLP rules configured
            try:
                activities = reports.activities().list(
                    userKey="all", applicationName="admin",
                    eventName="CREATE_RULE",
                    maxResults=5
                ).execute()
                dlp_events = [
                    e for e in activities.get("items", [])
                    if any(
                        "dlp" in str(p.get("value", "")).lower() or "data_loss" in str(p.get("value", "")).lower()
                        for evt in e.get("events", [])
                        for p in evt.get("parameters", [])
                    )
                ]

                results.append(SaaSCheckResult(
                    check_id="gws_drive_dlp_configured",
                    check_title="Data Loss Prevention (DLP) rules are configured",
                    service_area="drive_and_data", severity="high",
                    status="PASS" if dlp_events else "FAIL",
                    resource_id=self.domain,
                    description="DLP rules detect and prevent sharing of sensitive data like PII, financial data, and credentials",
                    remediation="Configure DLP rules in Admin Console > Security > Data protection",
                    remediation_url="https://admin.google.com/ac/security/dataprotection",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check DLP rules: {e}")

        except Exception as e:
            logger.warning(f"Google Workspace Drive and data checks failed: {e}")

        return results

    def test_connection(self) -> tuple[bool, str]:
        """Test connection to Google Workspace Admin SDK."""
        try:
            service = self._get_directory_service()
            service.users().list(domain=self.domain, maxResults=1).execute()
            return True, f"Connected to Google Workspace domain '{self.domain}'"
        except Exception as e:
            return False, str(e)
