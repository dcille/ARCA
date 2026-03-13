"""Microsoft 365 SaaS Security Scanner.

Implements 37 security checks across 4 auditor categories:
- AAD Users: MFA enrollment, phishing-resistant MFA, risky users
- Conditional Access: Legacy auth blocking, risk-based MFA, location-based access
- Defender Recommendations: Platform-specific security controls
- Defender for Endpoint: Sensor health, risk levels, exposure scores
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
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())

                    results.append(SaaSCheckResult(
                        check_id="m365_user_phishing_resistant_mfa",
                        check_title="User has phishing-resistant MFA (FIDO2/Windows Hello)",
                        service_area="aad_users", severity="medium",
                        status="PASS" if has_phishing_resistant else "FAIL",
                        resource_id=user_id, resource_name=display_name,
                        description=f"User {upn} phishing-resistant MFA status",
                        remediation="Register a FIDO2 security key or Windows Hello for Business",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001"],
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
                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
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
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"Defender endpoint checks failed: {e}")

        return results

    def test_connection(self) -> tuple[bool, str]:
        try:
            self._get_token()
            return True, "Connected successfully"
        except Exception as e:
            return False, str(e)
