"""Cloudflare SaaS Security Scanner.

Implements 25 security checks across 5 auditor categories:
- DNS Security: DNSSEC enabled, CAA records, dangling DNS entries, zone transfer restrictions
- SSL/TLS: Minimum TLS version, HSTS, full strict SSL, automatic HTTPS rewrites, always use HTTPS
- WAF & Security: WAF managed rules, rate limiting, bot management, DDoS protection, firewall rules
- Access Control: API token permissions, 2FA on account, access policies, zero trust policies
- Performance & Security: Page rules review, HTTP/2 and HTTP/3, early hints, origin server protection
"""
import logging

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult

logger = logging.getLogger(__name__)

try:
    import CloudFlare
except ImportError:
    CloudFlare = None
    logger.warning("cloudflare SDK not installed. Install with: pip install cloudflare")


class CloudflareScanner(BaseSaaSScanner):
    """Cloudflare SaaS security scanner."""

    provider_type = "cloudflare"

    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self.api_token = credentials["api_token"]
        self.account_id = credentials["account_id"]
        self._client = None

    def _get_client(self):
        """Get authenticated Cloudflare client."""
        if self._client:
            return self._client
        if CloudFlare is None:
            raise ImportError("cloudflare SDK is not installed")
        self._client = CloudFlare.CloudFlare(token=self.api_token)
        return self._client

    def _get_zones(self) -> list[dict]:
        """Get all zones for the account."""
        try:
            cf = self._get_client()
            zones = cf.zones.get(params={"per_page": 50})
            return zones
        except Exception as e:
            logger.warning(f"Failed to get zones: {e}")
            return []

    def run_all_checks(self) -> list[dict]:
        """Run all Cloudflare security checks."""
        results = []
        check_groups = [
            self._check_dns_security,
            self._check_ssl_tls,
            self._check_waf_security,
            self._check_access_control,
            self._check_performance_security,
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"Cloudflare check group failed: {e}")

        return results

    def _check_dns_security(self) -> list[dict]:
        """DNS security checks."""
        results = []

        try:
            cf = self._get_client()
            zones = self._get_zones()

            for zone in zones:
                zone_id = zone.get("id", "")
                zone_name = zone.get("name", "Unknown")

                # DNSSEC enabled
                try:
                    dnssec = cf.zones.dnssec.get(zone_id)
                    dnssec_status = dnssec.get("status", "disabled")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_dns_dnssec_enabled",
                        check_title="DNSSEC is enabled for the zone",
                        service_area="dns_security", severity="high",
                        status="PASS" if dnssec_status == "active" else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"DNSSEC status: {dnssec_status}. DNSSEC prevents DNS spoofing and cache poisoning",
                        remediation="Enable DNSSEC in Cloudflare dashboard under DNS > Settings",
                        remediation_url=f"https://dash.cloudflare.com/{self.account_id}/{zone_name}/dns",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check DNSSEC for {zone_name}: {e}")

                # CAA records configured
                try:
                    dns_records = cf.zones.dns_records.get(zone_id, params={"type": "CAA", "per_page": 100})
                    has_caa = len(dns_records) > 0
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_dns_caa_configured",
                        check_title="CAA records are configured to restrict certificate issuance",
                        service_area="dns_security", severity="medium",
                        status="PASS" if has_caa else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"CAA records found: {len(dns_records)}. CAA restricts which CAs can issue certificates",
                        remediation="Add CAA DNS records to specify authorized Certificate Authorities",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check CAA records for {zone_name}: {e}")

                # Dangling DNS entries (CNAME/A records pointing to non-existent resources)
                try:
                    dns_records = cf.zones.dns_records.get(zone_id, params={"per_page": 500})
                    cname_records = [r for r in dns_records if r.get("type") in ("CNAME", "A", "AAAA")]
                    proxied_count = sum(1 for r in cname_records if r.get("proxied", False))
                    unproxied_count = len(cname_records) - proxied_count

                    results.append(SaaSCheckResult(
                        check_id="cloudflare_dns_dangling_review",
                        check_title="DNS records are reviewed for dangling entries",
                        service_area="dns_security", severity="high",
                        status="PASS" if unproxied_count == 0 else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Total A/AAAA/CNAME records: {len(cname_records)}. "
                                    f"Proxied: {proxied_count}, unproxied: {unproxied_count}. "
                                    f"Unproxied records may be vulnerable to subdomain takeover",
                        remediation="Review unproxied DNS records and enable Cloudflare proxy or remove stale entries",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check dangling DNS for {zone_name}: {e}")

                # Zone transfer restrictions (inherent with Cloudflare but check AXFR settings)
                try:
                    zone_info = cf.zones.get(zone_id)
                    zone_type = zone_info.get("type", "full")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_dns_zone_transfer_restricted",
                        check_title="DNS zone is using Cloudflare nameservers (full setup)",
                        service_area="dns_security", severity="medium",
                        status="PASS" if zone_type == "full" else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Zone type: {zone_type}. Full setup uses Cloudflare nameservers, preventing unauthorized zone transfers",
                        remediation="Use full Cloudflare setup with Cloudflare nameservers for best security",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check zone transfer for {zone_name}: {e}")

        except Exception as e:
            logger.warning(f"Cloudflare DNS security checks failed: {e}")

        return results

    def _check_ssl_tls(self) -> list[dict]:
        """SSL/TLS security checks."""
        results = []

        try:
            cf = self._get_client()
            zones = self._get_zones()

            for zone in zones:
                zone_id = zone.get("id", "")
                zone_name = zone.get("name", "Unknown")

                # Minimum TLS version
                try:
                    setting = cf.zones.settings.get(zone_id, "min_tls_version")
                    min_tls = setting.get("value", "1.0")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_tls_min_version",
                        check_title="Minimum TLS version is 1.2 or higher",
                        service_area="ssl_tls", severity="high",
                        status="PASS" if min_tls in ("1.2", "1.3") else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Minimum TLS version: {min_tls}. TLS 1.0 and 1.1 have known vulnerabilities",
                        remediation="Set minimum TLS version to 1.2 in SSL/TLS > Edge Certificates",
                        remediation_url=f"https://dash.cloudflare.com/{self.account_id}/{zone_name}/ssl-tls/edge-certificates",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS", "PCI-DSS"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check min TLS version for {zone_name}: {e}")

                # HSTS enabled
                try:
                    setting = cf.zones.settings.get(zone_id, "security_header")
                    hsts_config = setting.get("value", {}).get("strict_transport_security", {})
                    hsts_enabled = hsts_config.get("enabled", False)
                    max_age = hsts_config.get("max_age", 0)
                    include_subdomains = hsts_config.get("include_subdomains", False)

                    results.append(SaaSCheckResult(
                        check_id="cloudflare_tls_hsts_enabled",
                        check_title="HTTP Strict Transport Security (HSTS) is enabled",
                        service_area="ssl_tls", severity="high",
                        status="PASS" if hsts_enabled and max_age >= 31536000 else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"HSTS enabled: {hsts_enabled}, max-age: {max_age}s, "
                                    f"include subdomains: {include_subdomains}. Recommended max-age: 31536000 (1 year)",
                        remediation="Enable HSTS with max-age of at least 1 year in SSL/TLS > Edge Certificates",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check HSTS for {zone_name}: {e}")

                # Full (Strict) SSL mode
                try:
                    setting = cf.zones.settings.get(zone_id, "ssl")
                    ssl_mode = setting.get("value", "off")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_tls_full_strict",
                        check_title="SSL mode is set to Full (Strict)",
                        service_area="ssl_tls", severity="critical",
                        status="PASS" if ssl_mode == "strict" else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"SSL mode: {ssl_mode}. Full (Strict) validates origin server certificate",
                        remediation="Set SSL/TLS encryption mode to 'Full (strict)' to validate origin certificates",
                        remediation_url=f"https://dash.cloudflare.com/{self.account_id}/{zone_name}/ssl-tls",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS", "PCI-DSS"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check SSL mode for {zone_name}: {e}")

                # Automatic HTTPS rewrites
                try:
                    setting = cf.zones.settings.get(zone_id, "automatic_https_rewrites")
                    auto_https = setting.get("value", "off")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_tls_auto_https_rewrites",
                        check_title="Automatic HTTPS Rewrites are enabled",
                        service_area="ssl_tls", severity="medium",
                        status="PASS" if auto_https == "on" else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="Automatic HTTPS Rewrites fix mixed content issues by rewriting HTTP to HTTPS",
                        remediation="Enable Automatic HTTPS Rewrites in SSL/TLS > Edge Certificates",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check auto HTTPS rewrites for {zone_name}: {e}")

                # Always Use HTTPS
                try:
                    setting = cf.zones.settings.get(zone_id, "always_use_https")
                    always_https = setting.get("value", "off")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_tls_always_https",
                        check_title="Always Use HTTPS is enabled",
                        service_area="ssl_tls", severity="high",
                        status="PASS" if always_https == "on" else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="Always Use HTTPS redirects all HTTP requests to HTTPS",
                        remediation="Enable 'Always Use HTTPS' in SSL/TLS > Edge Certificates",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check always HTTPS for {zone_name}: {e}")

        except Exception as e:
            logger.warning(f"Cloudflare SSL/TLS checks failed: {e}")

        return results

    def _check_waf_security(self) -> list[dict]:
        """WAF and security checks."""
        results = []

        try:
            cf = self._get_client()
            zones = self._get_zones()

            for zone in zones:
                zone_id = zone.get("id", "")
                zone_name = zone.get("name", "Unknown")

                # WAF managed rules enabled
                try:
                    setting = cf.zones.settings.get(zone_id, "waf")
                    waf_enabled = setting.get("value", "off") == "on"
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_waf_managed_rules",
                        check_title="WAF managed rules are enabled",
                        service_area="waf_security", severity="high",
                        status="PASS" if waf_enabled else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="WAF managed rules protect against common web vulnerabilities (SQLi, XSS, etc.)",
                        remediation="Enable WAF managed rules in Security > WAF > Managed Rules",
                        remediation_url=f"https://dash.cloudflare.com/{self.account_id}/{zone_name}/security/waf",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS", "PCI-DSS"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check WAF for {zone_name}: {e}")

                # Rate limiting configured
                try:
                    rate_limits = cf.zones.rate_limits.get(zone_id)
                    has_rate_limiting = len(rate_limits) > 0
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_waf_rate_limiting",
                        check_title="Rate limiting rules are configured",
                        service_area="waf_security", severity="medium",
                        status="PASS" if has_rate_limiting else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Rate limiting rules: {len(rate_limits)}. Rate limiting prevents abuse and DDoS attacks",
                        remediation="Configure rate limiting rules in Security > WAF > Rate limiting rules",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check rate limiting for {zone_name}: {e}")

                # Bot management (security level)
                try:
                    setting = cf.zones.settings.get(zone_id, "security_level")
                    security_level = setting.get("value", "medium")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_waf_bot_management",
                        check_title="Security level is set to medium or higher",
                        service_area="waf_security", severity="medium",
                        status="PASS" if security_level in ("medium", "high", "under_attack") else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Security level: {security_level}. Higher levels challenge more suspicious visitors",
                        remediation="Set security level to at least 'Medium' in Security > Settings",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check security level for {zone_name}: {e}")

                # DDoS protection settings (challenge TTL)
                try:
                    setting = cf.zones.settings.get(zone_id, "challenge_ttl")
                    challenge_ttl = setting.get("value", 1800)
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_waf_ddos_challenge_ttl",
                        check_title="Challenge TTL is appropriately configured",
                        service_area="waf_security", severity="low",
                        status="PASS" if challenge_ttl <= 3600 else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Challenge TTL: {challenge_ttl}s. Lower values increase security but may impact UX",
                        remediation="Set Challenge Passage TTL to 1 hour or less in Security > Settings",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check challenge TTL for {zone_name}: {e}")

                # Browser integrity check
                try:
                    setting = cf.zones.settings.get(zone_id, "browser_check")
                    browser_check = setting.get("value", "off")
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_waf_browser_check",
                        check_title="Browser Integrity Check is enabled",
                        service_area="waf_security", severity="medium",
                        status="PASS" if browser_check == "on" else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="Browser Integrity Check evaluates visitor HTTP headers for threats",
                        remediation="Enable Browser Integrity Check in Security > Settings",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check browser integrity for {zone_name}: {e}")

                # Firewall rules review
                try:
                    firewall_rules = cf.zones.firewall.rules.get(zone_id)
                    active_rules = [r for r in firewall_rules if r.get("paused") is False]
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_waf_firewall_rules",
                        check_title="Custom firewall rules are configured",
                        service_area="waf_security", severity="medium",
                        status="PASS" if active_rules else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Active firewall rules: {len(active_rules)} out of {len(firewall_rules)} total",
                        remediation="Configure custom firewall rules for application-specific protection",
                        remediation_url=f"https://dash.cloudflare.com/{self.account_id}/{zone_name}/security/waf/custom-rules",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check firewall rules for {zone_name}: {e}")

        except Exception as e:
            logger.warning(f"Cloudflare WAF security checks failed: {e}")

        return results

    def _check_access_control(self) -> list[dict]:
        """Access control checks."""
        results = []

        try:
            cf = self._get_client()

            # API token permissions review - verify current token
            try:
                token_verify = cf.user.tokens.verify.get()
                token_status = token_verify.get("status", "unknown")
                results.append(SaaSCheckResult(
                    check_id="cloudflare_ac_api_token_valid",
                    check_title="API token is valid and active",
                    service_area="access_control", severity="high",
                    status="PASS" if token_status == "active" else "FAIL",
                    resource_id=self.account_id,
                    description=f"API token status: {token_status}. Use scoped API tokens instead of global API keys",
                    remediation="Use scoped API tokens with minimum required permissions",
                    remediation_url="https://dash.cloudflare.com/profile/api-tokens",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to verify API token: {e}")

            # 2FA on account
            try:
                user_info = cf.user.get()
                two_factor = user_info.get("two_factor_authentication_enabled", False)
                results.append(SaaSCheckResult(
                    check_id="cloudflare_ac_2fa_enabled",
                    check_title="Two-factor authentication is enabled on Cloudflare account",
                    service_area="access_control", severity="critical",
                    status="PASS" if two_factor else "FAIL",
                    resource_id=self.account_id,
                    description="2FA protects the Cloudflare account from unauthorized access",
                    remediation="Enable 2FA in Cloudflare account settings",
                    remediation_url="https://dash.cloudflare.com/profile",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check 2FA status: {e}")

            # Account members review
            try:
                members = cf.accounts.members.get(self.account_id)
                admin_members = [
                    m for m in members
                    if any(
                        r.get("name") == "Administrator" or r.get("name") == "Super Administrator - All Privileges"
                        for r in m.get("roles", [])
                    )
                ]
                results.append(SaaSCheckResult(
                    check_id="cloudflare_ac_admin_members",
                    check_title="Account administrator count is reviewed",
                    service_area="access_control", severity="high",
                    status="PASS" if 1 <= len(admin_members) <= 5 else "FAIL",
                    resource_id=self.account_id,
                    description=f"Account administrators: {len(admin_members)} out of {len(members)} total members",
                    remediation="Limit administrator access. Use role-based access with minimum privileges",
                    remediation_url=f"https://dash.cloudflare.com/{self.account_id}/members",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check account members: {e}")

            # Access policies (Zero Trust)
            try:
                access_apps = cf.accounts.access.apps.get(self.account_id)
                has_access_apps = len(access_apps) > 0
                results.append(SaaSCheckResult(
                    check_id="cloudflare_ac_access_policies",
                    check_title="Cloudflare Access policies are configured",
                    service_area="access_control", severity="medium",
                    status="PASS" if has_access_apps else "FAIL",
                    resource_id=self.account_id,
                    description=f"Access applications: {len(access_apps)}. Cloudflare Access provides Zero Trust application access",
                    remediation="Configure Cloudflare Access policies for internal application protection",
                    remediation_url=f"https://one.dash.cloudflare.com/{self.account_id}/access/apps",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check access policies: {e}")

            # Zero Trust policies
            try:
                gateway_rules = cf.accounts.gateway.rules.get(self.account_id)
                has_gateway_rules = len(gateway_rules) > 0
                results.append(SaaSCheckResult(
                    check_id="cloudflare_ac_zero_trust_gateway",
                    check_title="Zero Trust Gateway policies are configured",
                    service_area="access_control", severity="medium",
                    status="PASS" if has_gateway_rules else "FAIL",
                    resource_id=self.account_id,
                    description=f"Gateway rules: {len(gateway_rules)}. Gateway policies filter DNS and HTTP traffic",
                    remediation="Configure Zero Trust Gateway policies for DNS filtering and threat protection",
                    remediation_url=f"https://one.dash.cloudflare.com/{self.account_id}/gateway/policies",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check Zero Trust policies: {e}")

        except Exception as e:
            logger.warning(f"Cloudflare access control checks failed: {e}")

        return results

    def _check_performance_security(self) -> list[dict]:
        """Performance and security checks."""
        results = []

        try:
            cf = self._get_client()
            zones = self._get_zones()

            for zone in zones:
                zone_id = zone.get("id", "")
                zone_name = zone.get("name", "Unknown")

                # Page rules security review
                try:
                    page_rules = cf.zones.pagerules.get(zone_id)
                    insecure_rules = []
                    for rule in page_rules:
                        actions = rule.get("actions", [])
                        for action in actions:
                            if action.get("id") == "disable_security":
                                insecure_rules.append(rule)
                            elif action.get("id") == "ssl" and action.get("value") == "off":
                                insecure_rules.append(rule)

                    results.append(SaaSCheckResult(
                        check_id="cloudflare_perf_page_rules_secure",
                        check_title="Page rules do not disable security features",
                        service_area="performance_security", severity="high",
                        status="PASS" if not insecure_rules else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description=f"Page rules total: {len(page_rules)}, insecure rules: {len(insecure_rules)}",
                        remediation="Review page rules and remove any that disable security features or SSL",
                        remediation_url=f"https://dash.cloudflare.com/{self.account_id}/{zone_name}/rules",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check page rules for {zone_name}: {e}")

                # HTTP/2 enabled
                try:
                    setting = cf.zones.settings.get(zone_id, "http2")
                    http2_enabled = setting.get("value", "off") == "on"
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_perf_http2_enabled",
                        check_title="HTTP/2 is enabled",
                        service_area="performance_security", severity="low",
                        status="PASS" if http2_enabled else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="HTTP/2 improves performance with multiplexing and header compression",
                        remediation="Enable HTTP/2 in Network settings",
                        compliance_frameworks=["NIST-CSF"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check HTTP/2 for {zone_name}: {e}")

                # HTTP/3 enabled
                try:
                    setting = cf.zones.settings.get(zone_id, "http3")
                    http3_enabled = setting.get("value", "off") == "on"
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_perf_http3_enabled",
                        check_title="HTTP/3 (QUIC) is enabled",
                        service_area="performance_security", severity="low",
                        status="PASS" if http3_enabled else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="HTTP/3 with QUIC provides improved performance and built-in encryption",
                        remediation="Enable HTTP/3 in Network settings",
                        compliance_frameworks=["NIST-CSF"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check HTTP/3 for {zone_name}: {e}")

                # Early Hints
                try:
                    setting = cf.zones.settings.get(zone_id, "early_hints")
                    early_hints = setting.get("value", "off") == "on"
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_perf_early_hints",
                        check_title="Early Hints (103) is enabled",
                        service_area="performance_security", severity="low",
                        status="PASS" if early_hints else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="Early Hints sends preload directives to browsers before the full response",
                        remediation="Enable Early Hints in Speed > Optimization",
                        compliance_frameworks=["NIST-CSF"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check Early Hints for {zone_name}: {e}")

                # Origin server protection (Authenticated Origin Pulls)
                try:
                    setting = cf.zones.settings.get(zone_id, "tls_client_auth")
                    origin_auth = setting.get("value", "off") == "on"
                    results.append(SaaSCheckResult(
                        check_id="cloudflare_perf_origin_protection",
                        check_title="Authenticated Origin Pulls is enabled",
                        service_area="performance_security", severity="high",
                        status="PASS" if origin_auth else "FAIL",
                        resource_id=zone_id, resource_name=zone_name,
                        description="Authenticated Origin Pulls ensures only Cloudflare can connect to your origin server",
                        remediation="Enable Authenticated Origin Pulls in SSL/TLS > Origin Server",
                        remediation_url=f"https://dash.cloudflare.com/{self.account_id}/{zone_name}/ssl-tls/origin",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Failed to check origin protection for {zone_name}: {e}")

        except Exception as e:
            logger.warning(f"Cloudflare performance security checks failed: {e}")

        return results

    def test_connection(self) -> tuple[bool, str]:
        """Test connection to Cloudflare API."""
        try:
            cf = self._get_client()
            token_verify = cf.user.tokens.verify.get()
            status = token_verify.get("status", "unknown")
            if status == "active":
                return True, "Connected to Cloudflare API successfully"
            return False, f"Token status: {status}"
        except Exception as e:
            return False, str(e)
