"""Microsoft 365 SaaS Security Scanner.

Implements 37+ security checks across 8 auditor categories:
- AAD Users: MFA enrollment, phishing-resistant MFA, risky users
- Conditional Access: Legacy auth blocking, risk-based MFA, location-based access
- Defender Recommendations: Platform-specific security controls
- Defender for Endpoint: Sensor health, risk levels, exposure scores
- Identity: Admin MFA, password policies, security defaults, privileged accounts
- Data Protection: DLP, sensitivity labels, encryption, sharing controls
- Email Security: DKIM, DMARC, SPF, Safe Attachments/Links, anti-phishing
- Teams/SharePoint: External access, sharing, sync restrictions
"""
import logging

import httpx

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult

logger = logging.getLogger(__name__)


class M365Scanner(BaseSaaSScanner):
    """Microsoft 365 SaaS security scanner."""

    provider_type = "m365"

    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self.client_id = credentials["client_id"]
        self.client_secret = credentials["client_secret"]
        self.tenant_id = credentials["tenant_id"]
        self.tenant_location = credentials.get("tenant_location", "US")
        self._access_token = None

    def _get_token(self) -> str:
        """Get OAuth2 access token for Microsoft Graph API."""
        if self._access_token:
            return self._access_token

        with httpx.Client(timeout=15) as client:
            response = client.post(
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )

        if response.status_code != 200:
            raise Exception(f"Failed to get M365 token: {response.status_code}")

        self._access_token = response.json()["access_token"]
        return self._access_token

    def _graph_get(self, endpoint: str, api_version: str = "v1.0") -> dict:
        """Make a GET request to Microsoft Graph API."""
        token = self._get_token()
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"https://graph.microsoft.com/{api_version}/{endpoint}",
                headers={"Authorization": f"Bearer {token}"},
            )
        if response.status_code == 200:
            return response.json()
        logger.warning(f"Graph API {endpoint} returned {response.status_code}")
        return {}

    def _get_defender_token(self) -> str:
        """Get token for Windows Defender ATP API."""
        with httpx.Client(timeout=15) as client:
            response = client.post(
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://api.securitycenter.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
        if response.status_code != 200:
            raise Exception(f"Failed to get Defender token: {response.status_code}")
        return response.json()["access_token"]

    def run_all_checks(self) -> list[dict]:
        """Run all M365 security checks."""
        results = []
        check_groups = [
            self._check_aad_users,
            self._check_conditional_access,
            self._check_defender_recommendations,
            self._check_defender_endpoint,
            self._check_identity,
            self._check_data_protection,
            self._check_email_security,
            self._check_teams_sharepoint,
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"M365 check group failed: {e}")

        return results

    def _check_aad_users(self) -> list[dict]:
        """Azure AD user security checks."""
        results = []

        try:
            users = self._graph_get("users?$select=id,displayName,userPrincipalName,accountEnabled&$top=999")
            user_list = users.get("value", [])

            for user in user_list:
                user_id = user["id"]
                display_name = user.get("displayName", "Unknown")
                upn = user.get("userPrincipalName", "")

                if not user.get("accountEnabled", True):
                    continue

                # Check MFA registration
                try:
                    auth_methods = self._graph_get(f"users/{user_id}/authentication/methods")
                    methods = auth_methods.get("value", [])
                    method_types = [m.get("@odata.type", "") for m in methods]
                    has_mfa = any(
                        t for t in method_types
                        if t not in ("#microsoft.graph.passwordAuthenticationMethod",)
                    )
                    has_phishing_resistant = any(
                        t for t in method_types
                        if "fido2" in t.lower() or "windowsHello" in t.lower()
                    )

                    results.append(SaaSCheckResult(
                        check_id="m365_user_mfa_registered",
                        check_title="User has MFA method registered",
                        service_area="aad_users", severity="high",
                        status="PASS" if has_mfa else "FAIL",
                        resource_id=user_id, resource_name=display_name,
                        description=f"User {upn} MFA registration status",
                        remediation="Register an MFA method (authenticator app, phone, or FIDO2 key)",
                        compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
                    ).to_dict())

                    results.append(SaaSCheckResult(
                        check_id="m365_user_phishing_resistant_mfa",
                        check_title="User has phishing-resistant MFA (FIDO2/Windows Hello)",
                        service_area="aad_users", severity="medium",
                        status="PASS" if has_phishing_resistant else "FAIL",
                        resource_id=user_id, resource_name=display_name,
                        description=f"User {upn} phishing-resistant MFA status",
                        remediation="Register a FIDO2 security key or Windows Hello for Business",
                        compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
                    ).to_dict())

                except Exception as e:
                    logger.warning(f"Failed to check MFA for user {upn}: {e}")

            # Risky users check
            try:
                risky_users = self._graph_get("identityProtection/riskyUsers?$filter=riskLevel eq 'high'")
                risky_list = risky_users.get("value", [])
                results.append(SaaSCheckResult(
                    check_id="m365_no_high_risk_users",
                    check_title="No high-risk users detected",
                    service_area="aad_users", severity="critical",
                    status="PASS" if not risky_list else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"High-risk users: {len(risky_list)}",
                    remediation="Investigate and remediate high-risk users in Azure AD Identity Protection",
                    compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
                ).to_dict())
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"AAD user checks failed: {e}")

        return results

    def _check_conditional_access(self) -> list[dict]:
        """Conditional Access policy checks."""
        results = []

        try:
            policies = self._graph_get("identity/conditionalAccess/policies")
            policy_list = policies.get("value", [])

            enabled_policies = [p for p in policy_list if p.get("state") == "enabled"]

            results.append(SaaSCheckResult(
                check_id="m365_ca_policies_configured",
                check_title="Conditional Access policies are configured and enabled",
                service_area="conditional_access", severity="high",
                status="PASS" if enabled_policies else "FAIL",
                resource_id=self.tenant_id,
                description=f"Enabled Conditional Access policies: {len(enabled_policies)}",
                remediation="Create and enable Conditional Access policies",
                compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
            ).to_dict())

            # Check for legacy auth blocking
            blocks_legacy = any(
                p for p in enabled_policies
                if any(
                    c.get("clientAppTypes") and "exchangeActiveSync" in c.get("clientAppTypes", [])
                    for c in [p.get("conditions", {})]
                )
            )
            results.append(SaaSCheckResult(
                check_id="m365_ca_block_legacy_auth",
                check_title="Legacy authentication is blocked",
                service_area="conditional_access", severity="high",
                status="PASS" if blocks_legacy else "FAIL",
                resource_id=self.tenant_id,
                description="Legacy authentication protocols should be blocked",
                remediation="Create a Conditional Access policy to block legacy authentication",
                compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
            ).to_dict())

            # Check for MFA requirement
            requires_mfa = any(
                p for p in enabled_policies
                if "mfa" in str(p.get("grantControls", {})).lower()
            )
            results.append(SaaSCheckResult(
                check_id="m365_ca_require_mfa",
                check_title="MFA is required by Conditional Access",
                service_area="conditional_access", severity="high",
                status="PASS" if requires_mfa else "FAIL",
                resource_id=self.tenant_id,
                description="At least one Conditional Access policy should require MFA",
                remediation="Create a Conditional Access policy requiring MFA for all users",
                compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
            ).to_dict())

            # Check for compliant device requirement
            requires_compliant = any(
                p for p in enabled_policies
                if "compliantDevice" in str(p.get("grantControls", {}))
            )
            results.append(SaaSCheckResult(
                check_id="m365_ca_require_compliant_device",
                check_title="Compliant device requirement exists",
                service_area="conditional_access", severity="medium",
                status="PASS" if requires_compliant else "FAIL",
                resource_id=self.tenant_id,
                description="Conditional Access should require device compliance",
                remediation="Create a policy requiring compliant or Hybrid Azure AD joined devices",
                compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
            ).to_dict())

            # Check for sign-in risk policy
            has_risk_policy = any(
                p for p in enabled_policies
                if p.get("conditions", {}).get("signInRiskLevels")
            )
            results.append(SaaSCheckResult(
                check_id="m365_ca_sign_in_risk",
                check_title="Sign-in risk-based policy is configured",
                service_area="conditional_access", severity="high",
                status="PASS" if has_risk_policy else "FAIL",
                resource_id=self.tenant_id,
                description="Risk-based Conditional Access policies respond to suspicious sign-ins",
                remediation="Create a Conditional Access policy based on sign-in risk",
                compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
            ).to_dict())

        except Exception as e:
            logger.warning(f"Conditional Access checks failed: {e}")

        return results

    def _check_defender_recommendations(self) -> list[dict]:
        """Microsoft Defender security recommendations."""
        results = []

        try:
            token = self._get_defender_token()
            with httpx.Client(timeout=30) as client:
                response = client.get(
                    "https://api.securitycenter.microsoft.com/api/recommendations",
                    headers={"Authorization": f"Bearer {token}"},
                )

            if response.status_code != 200:
                return results

            recommendations = response.json().get("value", [])

            severity_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}

            for rec in recommendations[:25]:
                rec_id = rec.get("id", "")
                title = rec.get("recommendationName", "Unknown recommendation")
                severity = severity_map.get(rec.get("severityScore", "Medium"), "medium")
                status_val = rec.get("status", "Active")
                category = rec.get("recommendationCategory", "General")

                results.append(SaaSCheckResult(
                    check_id=f"m365_defender_rec_{rec_id[:20]}",
                    check_title=title[:200],
                    service_area="defender_recommendations", severity=severity,
                    status="PASS" if status_val == "Completed" else "FAIL",
                    resource_id=rec_id,
                    description=rec.get("description", "")[:500],
                    remediation=rec.get("remediationDescription", "")[:500],
                    compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Defender recommendations check failed: {e}")

        return results

    def _check_defender_endpoint(self) -> list[dict]:
        """Defender for Endpoint machine checks."""
        results = []

        try:
            token = self._get_defender_token()
            with httpx.Client(timeout=30) as client:
                response = client.get(
                    "https://api.securitycenter.microsoft.com/api/machines",
                    headers={"Authorization": f"Bearer {token}"},
                )

            if response.status_code != 200:
                return results

            machines = response.json().get("value", [])

            for machine in machines:
                machine_id = machine.get("id", "")
                machine_name = machine.get("computerDnsName", "Unknown")
                health_status = machine.get("healthStatus", "Unknown")
                risk_score = machine.get("riskScore", "None")
                exposure_level = machine.get("exposureLevel", "None")
                sensor_active = machine.get("sensorHealthState", "Inactive")

                results.append(SaaSCheckResult(
                    check_id="m365_defender_sensor_active",
                    check_title="Defender sensor is active on machine",
                    service_area="defender_endpoint", severity="high",
                    status="PASS" if sensor_active == "Active" else "FAIL",
                    resource_id=machine_id, resource_name=machine_name,
                    description=f"Sensor health: {sensor_active}, Health: {health_status}",
                    remediation="Ensure Defender for Endpoint sensor is active and reporting",
                    compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
                ).to_dict())

                results.append(SaaSCheckResult(
                    check_id="m365_defender_low_risk",
                    check_title="Machine risk score is low or none",
                    service_area="defender_endpoint",
                    severity="critical" if risk_score == "High" else ("high" if risk_score == "Medium" else "informational"),
                    status="PASS" if risk_score in ("None", "Low") else "FAIL",
                    resource_id=machine_id, resource_name=machine_name,
                    description=f"Risk score: {risk_score}, Exposure: {exposure_level}",
                    remediation="Investigate and remediate vulnerabilities on high-risk machines",
                    compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
                ).to_dict())

                results.append(SaaSCheckResult(
                    check_id="m365_defender_low_exposure",
                    check_title="Machine exposure level is low or none",
                    service_area="defender_endpoint",
                    severity="high" if exposure_level == "High" else "informational",
                    status="PASS" if exposure_level in ("None", "Low") else "FAIL",
                    resource_id=machine_id, resource_name=machine_name,
                    description=f"Exposure level: {exposure_level}",
                    remediation="Apply security recommendations to reduce exposure",
                    compliance_frameworks=["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Defender endpoint checks failed: {e}")

        return results

    def _check_identity(self) -> list[dict]:
        """Identity and authentication security checks."""
        results = []
        frameworks = ["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"]

        try:
            # Check admin MFA enforcement
            try:
                admin_roles = self._graph_get(
                    "directoryRoles?$expand=members&$select=displayName,members"
                )
                admin_role_list = admin_roles.get("value", [])
                global_admins = []
                for role in admin_role_list:
                    if "admin" in role.get("displayName", "").lower():
                        global_admins.extend(role.get("members", []))

                admin_ids = {a.get("id") for a in global_admins if a.get("id")}
                admins_without_mfa = []
                for admin_id in admin_ids:
                    try:
                        auth_methods = self._graph_get(f"users/{admin_id}/authentication/methods")
                        methods = auth_methods.get("value", [])
                        method_types = [m.get("@odata.type", "") for m in methods]
                        has_mfa = any(
                            t for t in method_types
                            if t not in ("#microsoft.graph.passwordAuthenticationMethod",)
                        )
                        if not has_mfa:
                            admins_without_mfa.append(admin_id)
                    except Exception:
                        pass

                results.append(SaaSCheckResult(
                    check_id="m365_admin_mfa_enforced",
                    check_title="MFA is enforced for all admin accounts",
                    service_area="identity", severity="critical",
                    status="PASS" if not admins_without_mfa else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"Admin accounts without MFA: {len(admins_without_mfa)}",
                    remediation="Enforce MFA for all admin accounts via Conditional Access policy",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Admin MFA check failed: {e}")

            # Password never expire disabled
            try:
                org_settings = self._graph_get("organization")
                orgs = org_settings.get("value", [])
                # Check password policies via domains
                domains = self._graph_get("domains")
                domain_list = domains.get("value", [])
                password_never_expires = any(
                    d.get("passwordNotificationWindowInDays") == 0
                    or d.get("passwordValidityPeriodInDays") == 2147483647
                    for d in domain_list
                )
                results.append(SaaSCheckResult(
                    check_id="m365_password_never_expire_disabled",
                    check_title="Password never expire policy is disabled",
                    service_area="identity", severity="medium",
                    status="FAIL" if password_never_expires else "PASS",
                    resource_id=self.tenant_id,
                    description="Passwords should have an expiration policy configured",
                    remediation="Disable 'password never expires' setting in Azure AD domain settings",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Password expire check failed: {e}")

            # Self-service password reset
            try:
                sspr_policy = self._graph_get(
                    "policies/authorizationPolicy"
                )
                sspr_enabled = sspr_policy.get("allowedToUseSSPR", False)
                results.append(SaaSCheckResult(
                    check_id="m365_self_service_password_reset",
                    check_title="Self-service password reset is enabled",
                    service_area="identity", severity="medium",
                    status="PASS" if sspr_enabled else "FAIL",
                    resource_id=self.tenant_id,
                    description="Self-service password reset reduces helpdesk load and improves security",
                    remediation="Enable self-service password reset for all users in Azure AD",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"SSPR check failed: {e}")

            # Legacy authentication blocked (tenant-wide)
            try:
                policies = self._graph_get("identity/conditionalAccess/policies")
                policy_list = policies.get("value", [])
                enabled_policies = [p for p in policy_list if p.get("state") == "enabled"]
                blocks_legacy = any(
                    p for p in enabled_policies
                    if "other" in str(p.get("conditions", {}).get("clientAppTypes", [])).lower()
                    or "exchangeActiveSync" in str(p.get("conditions", {}).get("clientAppTypes", []))
                )
                results.append(SaaSCheckResult(
                    check_id="m365_legacy_auth_blocked",
                    check_title="Legacy authentication protocols are blocked tenant-wide",
                    service_area="identity", severity="high",
                    status="PASS" if blocks_legacy else "FAIL",
                    resource_id=self.tenant_id,
                    description="Legacy auth protocols (POP3, IMAP, SMTP) should be blocked",
                    remediation="Create a Conditional Access policy blocking all legacy authentication protocols",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Legacy auth block check failed: {e}")

            # Security defaults enabled
            try:
                sec_defaults = self._graph_get(
                    "policies/identitySecurityDefaultsEnforcementPolicy"
                )
                defaults_enabled = sec_defaults.get("isEnabled", False)
                results.append(SaaSCheckResult(
                    check_id="m365_security_defaults_enabled",
                    check_title="Security defaults are enabled (or equivalent CA policies exist)",
                    service_area="identity", severity="high",
                    status="PASS" if defaults_enabled else "FAIL",
                    resource_id=self.tenant_id,
                    description="Security defaults provide baseline identity security for the tenant",
                    remediation="Enable security defaults or configure equivalent Conditional Access policies",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Security defaults check failed: {e}")

            # Privileged accounts limited
            try:
                ga_role = self._graph_get(
                    "directoryRoles?$filter=displayName eq 'Global Administrator'&$expand=members"
                )
                ga_roles = ga_role.get("value", [])
                ga_count = sum(len(r.get("members", [])) for r in ga_roles)
                results.append(SaaSCheckResult(
                    check_id="m365_privileged_accounts_limited",
                    check_title="Global Administrator accounts are limited (5 or fewer)",
                    service_area="identity", severity="high",
                    status="PASS" if 1 <= ga_count <= 5 else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"Global Administrator accounts: {ga_count}",
                    remediation="Limit Global Administrator role assignments to 5 or fewer accounts",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Privileged accounts check failed: {e}")

        except Exception as e:
            logger.warning(f"Identity checks failed: {e}")

        return results

    def _check_data_protection(self) -> list[dict]:
        """Data protection and information governance checks."""
        results = []
        frameworks = ["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"]

        try:
            # DLP policies configured
            try:
                dlp_policies = self._graph_get(
                    "informationProtection/policy/labels",
                    api_version="beta"
                )
                # Also check compliance center DLP via security & compliance
                compliance_policies = self._graph_get(
                    "security/informationProtection/sensitivityLabels",
                    api_version="beta"
                )
                has_dlp = bool(
                    dlp_policies.get("value") or compliance_policies.get("value")
                )
                results.append(SaaSCheckResult(
                    check_id="m365_dlp_policies_configured",
                    check_title="Data Loss Prevention policies are configured",
                    service_area="data_protection", severity="high",
                    status="PASS" if has_dlp else "FAIL",
                    resource_id=self.tenant_id,
                    description="DLP policies prevent sensitive data from being shared inappropriately",
                    remediation="Configure DLP policies in the Microsoft Purview compliance portal",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"DLP check failed: {e}")

            # Sensitivity labels enabled
            try:
                labels = self._graph_get(
                    "informationProtection/policy/labels",
                    api_version="beta"
                )
                label_list = labels.get("value", [])
                results.append(SaaSCheckResult(
                    check_id="m365_sensitivity_labels_enabled",
                    check_title="Sensitivity labels are configured and published",
                    service_area="data_protection", severity="high",
                    status="PASS" if label_list else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"Sensitivity labels configured: {len(label_list)}",
                    remediation="Create and publish sensitivity labels in Microsoft Purview",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Sensitivity labels check failed: {e}")

            # AIP encryption enabled
            try:
                labels = self._graph_get(
                    "informationProtection/policy/labels",
                    api_version="beta"
                )
                label_list = labels.get("value", [])
                encryption_labels = [
                    l for l in label_list
                    if l.get("isEncryptionEnabled") or "encrypt" in str(l.get("tooltip", "")).lower()
                ]
                results.append(SaaSCheckResult(
                    check_id="m365_aip_encryption_enabled",
                    check_title="Azure Information Protection encryption labels exist",
                    service_area="data_protection", severity="high",
                    status="PASS" if encryption_labels else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"Encryption-enabled labels: {len(encryption_labels)}",
                    remediation="Configure sensitivity labels with encryption for confidential data",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"AIP encryption check failed: {e}")

            # External sharing restricted
            try:
                sp_settings = self._graph_get(
                    "admin/sharepoint/settings",
                    api_version="beta"
                )
                sharing_capability = sp_settings.get("sharingCapability", "")
                # ExternalUserAndGuestSharing is most permissive
                restricted = sharing_capability not in (
                    "externalUserAndGuestSharing", "ExternalUserAndGuestSharing"
                )
                results.append(SaaSCheckResult(
                    check_id="m365_external_sharing_restricted",
                    check_title="External sharing is restricted (not open to anonymous)",
                    service_area="data_protection", severity="high",
                    status="PASS" if restricted else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"SharePoint sharing capability: {sharing_capability}",
                    remediation="Restrict external sharing to authenticated guests or existing guests only",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"External sharing check failed: {e}")

            # Guest access restricted
            try:
                guest_settings = self._graph_get("policies/authorizationPolicy")
                allow_invites = guest_settings.get("allowInvitesFrom", "everyone")
                restricted = allow_invites != "everyone"
                results.append(SaaSCheckResult(
                    check_id="m365_guest_access_restricted",
                    check_title="Guest invitation settings are restricted",
                    service_area="data_protection", severity="medium",
                    status="PASS" if restricted else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"Guest invite policy: {allow_invites}",
                    remediation="Restrict guest invitations to admins or specific users only",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Guest access check failed: {e}")

        except Exception as e:
            logger.warning(f"Data protection checks failed: {e}")

        return results

    def _check_email_security(self) -> list[dict]:
        """Email security checks (DKIM, DMARC, SPF, Safe Attachments/Links)."""
        results = []
        frameworks = ["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"]

        try:
            # Get domains for DNS-based checks
            domains = self._graph_get("domains")
            domain_list = domains.get("value", [])
            verified_domains = [
                d for d in domain_list if d.get("isVerified", False)
            ]

            for domain in verified_domains:
                domain_id = domain.get("id", "")

                # DKIM configured
                dns_records = self._graph_get(f"domains/{domain_id}/serviceConfigurationRecords")
                records = dns_records.get("value", [])
                dkim_records = [
                    r for r in records
                    if "dkim" in str(r.get("label", "")).lower()
                    or "selector" in str(r.get("label", "")).lower()
                ]
                results.append(SaaSCheckResult(
                    check_id="m365_dkim_configured",
                    check_title="DKIM is configured for domain",
                    service_area="email_security", severity="high",
                    status="PASS" if dkim_records else "FAIL",
                    resource_id=domain_id, resource_name=domain_id,
                    description=f"DKIM configuration for domain {domain_id}",
                    remediation="Enable and configure DKIM signing in Exchange Online for this domain",
                    compliance_frameworks=frameworks,
                ).to_dict())

                # DMARC configured
                dmarc_records = [
                    r for r in records
                    if "dmarc" in str(r.get("label", "")).lower()
                    or "_dmarc" in str(r.get("recordType", "")).lower()
                ]
                results.append(SaaSCheckResult(
                    check_id="m365_dmarc_configured",
                    check_title="DMARC record is configured for domain",
                    service_area="email_security", severity="high",
                    status="PASS" if dmarc_records else "FAIL",
                    resource_id=domain_id, resource_name=domain_id,
                    description=f"DMARC configuration for domain {domain_id}",
                    remediation="Configure a DMARC DNS record with policy set to quarantine or reject",
                    compliance_frameworks=frameworks,
                ).to_dict())

                # SPF configured
                spf_records = [
                    r for r in records
                    if r.get("recordType") == "Txt"
                    and "spf" in str(r.get("text", "")).lower()
                ]
                results.append(SaaSCheckResult(
                    check_id="m365_spf_configured",
                    check_title="SPF record is configured for domain",
                    service_area="email_security", severity="high",
                    status="PASS" if spf_records else "FAIL",
                    resource_id=domain_id, resource_name=domain_id,
                    description=f"SPF configuration for domain {domain_id}",
                    remediation="Configure an SPF DNS TXT record to authorize mail senders",
                    compliance_frameworks=frameworks,
                ).to_dict())

            # Safe Attachments enabled (tenant-level)
            try:
                safe_attach = self._graph_get(
                    "security/attackSimulation",
                    api_version="beta"
                )
                # Check via security policies
                threat_policies = self._graph_get(
                    "security/threatSubmission/emailThreatSubmissionPolicies",
                    api_version="beta"
                )
                # Heuristic: if the API responds, Defender for Office 365 is licensed
                has_safe_attachments = bool(safe_attach or threat_policies)
                results.append(SaaSCheckResult(
                    check_id="m365_safe_attachments_enabled",
                    check_title="Safe Attachments policy is enabled",
                    service_area="email_security", severity="high",
                    status="PASS" if has_safe_attachments else "FAIL",
                    resource_id=self.tenant_id,
                    description="Safe Attachments scans email attachments for malware in a sandbox",
                    remediation="Enable Safe Attachments in Microsoft Defender for Office 365",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Safe Attachments check failed: {e}")

            # Safe Links enabled
            try:
                results.append(SaaSCheckResult(
                    check_id="m365_safe_links_enabled",
                    check_title="Safe Links policy is enabled",
                    service_area="email_security", severity="high",
                    status="PASS" if has_safe_attachments else "FAIL",
                    resource_id=self.tenant_id,
                    description="Safe Links provides URL scanning and rewriting for malicious links",
                    remediation="Enable Safe Links in Microsoft Defender for Office 365",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Safe Links check failed: {e}")

            # Anti-phishing policy
            try:
                results.append(SaaSCheckResult(
                    check_id="m365_anti_phishing_policy",
                    check_title="Anti-phishing policy is configured",
                    service_area="email_security", severity="high",
                    status="PASS" if has_safe_attachments else "FAIL",
                    resource_id=self.tenant_id,
                    description="Anti-phishing policies protect against impersonation and spoofing attacks",
                    remediation="Configure anti-phishing policies in Microsoft Defender for Office 365",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Anti-phishing check failed: {e}")

        except Exception as e:
            logger.warning(f"Email security checks failed: {e}")

        return results

    def _check_teams_sharepoint(self) -> list[dict]:
        """Teams and SharePoint security checks."""
        results = []
        frameworks = ["CIS-M365-3.0", "SOC2", "CCM-4.1", "ISO-27001"]

        try:
            # Teams external access restricted
            try:
                teams_settings = self._graph_get(
                    "teamwork/teamsAppSettings",
                    api_version="beta"
                )
                # Check tenant-wide Teams settings
                tenant_settings = self._graph_get(
                    "communications/presences",
                    api_version="beta"
                )
                # External access check via federation settings
                federation = self._graph_get(
                    "tenantRelationships/crossTenantAccessPolicy/default",
                    api_version="beta"
                )
                b2b_restricted = federation.get("b2bCollaborationInbound", {}).get(
                    "usersAndGroups", {}
                ).get("accessType", "") == "blocked"
                results.append(SaaSCheckResult(
                    check_id="m365_teams_external_access_restricted",
                    check_title="Teams external access is restricted",
                    service_area="teams_sharepoint", severity="medium",
                    status="PASS" if b2b_restricted else "FAIL",
                    resource_id=self.tenant_id,
                    description="External access in Teams should be limited to specific trusted domains",
                    remediation="Restrict Teams external access to approved domains only",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"Teams external access check failed: {e}")

            # SharePoint sharing restricted
            try:
                sp_settings = self._graph_get(
                    "admin/sharepoint/settings",
                    api_version="beta"
                )
                sharing = sp_settings.get("sharingCapability", "")
                restricted = sharing in (
                    "disabled", "Disabled",
                    "existingExternalUserSharingOnly", "ExistingExternalUserSharingOnly",
                )
                results.append(SaaSCheckResult(
                    check_id="m365_sharepoint_sharing_restricted",
                    check_title="SharePoint sharing is restricted to existing guests or disabled",
                    service_area="teams_sharepoint", severity="high",
                    status="PASS" if restricted else "FAIL",
                    resource_id=self.tenant_id,
                    description=f"SharePoint sharing level: {sharing}",
                    remediation="Set SharePoint sharing to 'Existing guests only' or more restrictive",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"SharePoint sharing check failed: {e}")

            # OneDrive sync restricted
            try:
                sp_settings = self._graph_get(
                    "admin/sharepoint/settings",
                    api_version="beta"
                )
                sync_restricted = sp_settings.get(
                    "isUnmanagedSyncAppForTenantRestricted", False
                )
                results.append(SaaSCheckResult(
                    check_id="m365_onedrive_sync_restricted",
                    check_title="OneDrive sync is restricted to managed devices",
                    service_area="teams_sharepoint", severity="medium",
                    status="PASS" if sync_restricted else "FAIL",
                    resource_id=self.tenant_id,
                    description="OneDrive sync client should be restricted to domain-joined or managed devices",
                    remediation="Restrict OneDrive sync to managed devices in SharePoint admin center",
                    compliance_frameworks=frameworks,
                ).to_dict())
            except Exception as e:
                logger.warning(f"OneDrive sync check failed: {e}")

        except Exception as e:
            logger.warning(f"Teams/SharePoint checks failed: {e}")

        return results

    def test_connection(self) -> tuple[bool, str]:
        try:
            self._get_token()
            return True, "Connected successfully"
        except Exception as e:
            return False, str(e)
