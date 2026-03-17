"""GitHub SaaS Security Scanner.

Implements 27 security checks across 4 auditor categories:
- Organization Security: 2FA enforcement, SSO, default permissions, secret scanning, dependency alerts
- Repository Security: Branch protection, signed commits, vulnerability alerts, code scanning, CODEOWNERS
- Access Control: Outside collaborators, stale invitations, admin count, deploy keys, PAT scope audit
- Actions Security: Actions restrictions, self-hosted runners, secrets exposure, OIDC for cloud deployments
"""
import logging

from scanner.saas.base_saas_check import BaseSaaSScanner, SaaSCheckResult

logger = logging.getLogger(__name__)

try:
    from github import Github, GithubException
except ImportError:
    Github = None
    GithubException = None
    logger.warning("PyGithub not installed. Install with: pip install PyGithub")


class GitHubScanner(BaseSaaSScanner):
    """GitHub SaaS security scanner."""

    provider_type = "github"

    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self.token = credentials["token"]
        self.organization = credentials["organization"]
        self._client = None
        self._org = None

    def _get_client(self):
        """Get authenticated GitHub client."""
        if self._client:
            return self._client
        if Github is None:
            raise ImportError("PyGithub is not installed")
        self._client = Github(self.token)
        return self._client

    def _get_org(self):
        """Get the GitHub organization object."""
        if self._org:
            return self._org
        client = self._get_client()
        self._org = client.get_organization(self.organization)
        return self._org

    def run_all_checks(self) -> list[dict]:
        """Run all GitHub security checks."""
        results = []
        check_groups = [
            self._check_org_security,
            self._check_repo_security,
            self._check_access_control,
            self._check_actions_security,
        ]

        for check_fn in check_groups:
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.error(f"GitHub check group failed: {e}")

        return results

    def _check_org_security(self) -> list[dict]:
        """Organization-level security checks."""
        results = []

        try:
            org = self._get_org()

            # 2FA enforcement
            try:
                two_factor_required = org.two_factor_requirement_enabled
                results.append(SaaSCheckResult(
                    check_id="github_org_2fa_required",
                    check_title="Organization requires two-factor authentication",
                    service_area="org_security", severity="critical",
                    status="PASS" if two_factor_required else "FAIL",
                    resource_id=self.organization,
                    description="Two-factor authentication should be required for all organization members",
                    remediation="Enable 'Require two-factor authentication' in Organization Settings > Security",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/security",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check 2FA requirement: {e}")

            # SSO configured
            try:
                # SAML SSO is available via org settings; check if enforced
                saml_enabled = getattr(org, "saml_identity_provider", None) is not None
                results.append(SaaSCheckResult(
                    check_id="github_org_sso_configured",
                    check_title="SAML SSO is configured for the organization",
                    service_area="org_security", severity="high",
                    status="PASS" if saml_enabled else "FAIL",
                    resource_id=self.organization,
                    description="SAML Single Sign-On provides centralized authentication management",
                    remediation="Configure SAML SSO with your identity provider in Organization Settings",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/security",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check SSO configuration: {e}")

            # Default repository permissions
            try:
                default_perm = org.default_repository_permission
                restrictive = default_perm in ("none", "read")
                results.append(SaaSCheckResult(
                    check_id="github_org_default_repo_permission",
                    check_title="Default repository permission is restrictive (read or none)",
                    service_area="org_security", severity="high",
                    status="PASS" if restrictive else "FAIL",
                    resource_id=self.organization,
                    description=f"Default repository permission is '{default_perm}'. Should be 'read' or 'none'",
                    remediation="Set default repository permission to 'Read' or 'No permission' in Organization Settings",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/member_privileges",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check default repo permission: {e}")

            # Base role permissions
            try:
                members_can_create_repos = org.members_can_create_repositories
                results.append(SaaSCheckResult(
                    check_id="github_org_members_create_repos",
                    check_title="Members cannot create repositories by default",
                    service_area="org_security", severity="medium",
                    status="PASS" if not members_can_create_repos else "FAIL",
                    resource_id=self.organization,
                    description="Restricting repository creation ensures governance over new projects",
                    remediation="Disable 'Allow members to create repositories' in Organization Settings",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/member_privileges",
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check member repo creation: {e}")

            # Secret scanning enabled at org level
            try:
                # Use the REST API via PyGithub to check org-level settings
                client = self._get_client()
                headers, data = client._Github__requester.requestJsonAndCheck(
                    "GET", f"/orgs/{self.organization}"
                )
                secret_scanning = data.get("secret_scanning_enabled_for_new_repositories", False)
                results.append(SaaSCheckResult(
                    check_id="github_org_secret_scanning_enabled",
                    check_title="Secret scanning is enabled for new repositories",
                    service_area="org_security", severity="high",
                    status="PASS" if secret_scanning else "FAIL",
                    resource_id=self.organization,
                    description="Secret scanning detects accidentally committed secrets and credentials",
                    remediation="Enable secret scanning for new repositories in Organization Settings > Code security",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/security_analysis",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check org secret scanning: {e}")

            # Dependency alerts enabled at org level
            try:
                client = self._get_client()
                headers, data = client._Github__requester.requestJsonAndCheck(
                    "GET", f"/orgs/{self.organization}"
                )
                dep_alerts = data.get("dependabot_alerts_enabled_for_new_repositories", False)
                results.append(SaaSCheckResult(
                    check_id="github_org_dependency_alerts_enabled",
                    check_title="Dependabot alerts are enabled for new repositories",
                    service_area="org_security", severity="high",
                    status="PASS" if dep_alerts else "FAIL",
                    resource_id=self.organization,
                    description="Dependabot alerts notify about vulnerable dependencies",
                    remediation="Enable Dependabot alerts for new repositories in Organization Settings > Code security",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/security_analysis",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check org dependency alerts: {e}")

        except Exception as e:
            logger.warning(f"GitHub org security checks failed: {e}")

        return results

    def _check_repo_security(self) -> list[dict]:
        """Repository-level security checks."""
        results = []

        try:
            org = self._get_org()
            repos = org.get_repos(type="all")

            for repo in repos:
                repo_name = repo.full_name
                repo_id = str(repo.id)

                if repo.archived:
                    continue

                # Branch protection on default branch
                try:
                    default_branch = repo.default_branch
                    branch = repo.get_branch(default_branch)
                    protection = None
                    try:
                        protection = branch.get_protection()
                    except Exception:
                        pass

                    has_protection = protection is not None

                    results.append(SaaSCheckResult(
                        check_id="github_repo_branch_protection",
                        check_title="Default branch has branch protection rules",
                        service_area="repo_security", severity="high",
                        status="PASS" if has_protection else "FAIL",
                        resource_id=repo_id, resource_name=repo_name,
                        description=f"Branch protection on '{default_branch}' branch",
                        remediation="Enable branch protection rules on the default branch",
                        remediation_url=f"https://github.com/{repo_name}/settings/branches",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                    ).to_dict())

                    if has_protection:
                        # Require pull request reviews
                        try:
                            pr_reviews = protection.required_pull_request_reviews
                            has_reviews = pr_reviews is not None
                            review_count = getattr(pr_reviews, "required_approving_review_count", 0) if has_reviews else 0
                            results.append(SaaSCheckResult(
                                check_id="github_repo_require_reviews",
                                check_title="Pull request reviews are required before merging",
                                service_area="repo_security", severity="high",
                                status="PASS" if has_reviews and review_count >= 1 else "FAIL",
                                resource_id=repo_id, resource_name=repo_name,
                                description=f"Required approving reviews: {review_count}",
                                remediation="Enable 'Require a pull request before merging' with at least 1 approving review",
                                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                            ).to_dict())
                        except Exception:
                            pass

                        # Require status checks
                        try:
                            status_checks = protection.required_status_checks
                            has_status_checks = status_checks is not None and status_checks.strict
                            results.append(SaaSCheckResult(
                                check_id="github_repo_require_status_checks",
                                check_title="Status checks are required before merging",
                                service_area="repo_security", severity="medium",
                                status="PASS" if has_status_checks else "FAIL",
                                resource_id=repo_id, resource_name=repo_name,
                                description="Status checks ensure CI/CD passes before merging",
                                remediation="Enable 'Require status checks to pass before merging'",
                                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                            ).to_dict())
                        except Exception:
                            pass

                        # Require branches to be up to date
                        try:
                            strict = getattr(protection.required_status_checks, "strict", False) if protection.required_status_checks else False
                            results.append(SaaSCheckResult(
                                check_id="github_repo_require_up_to_date",
                                check_title="Branches must be up to date before merging",
                                service_area="repo_security", severity="medium",
                                status="PASS" if strict else "FAIL",
                                resource_id=repo_id, resource_name=repo_name,
                                description="Requiring up-to-date branches prevents merging stale code",
                                remediation="Enable 'Require branches to be up to date before merging'",
                                compliance_frameworks=["NIST-CSF", "ISO-27001"],
                            ).to_dict())
                        except Exception:
                            pass

                        # Restrict force pushes
                        try:
                            allow_force = getattr(protection, "allow_force_pushes", None)
                            force_pushes_disabled = allow_force is None or not allow_force.enabled
                            results.append(SaaSCheckResult(
                                check_id="github_repo_no_force_push",
                                check_title="Force pushes are restricted on default branch",
                                service_area="repo_security", severity="high",
                                status="PASS" if force_pushes_disabled else "FAIL",
                                resource_id=repo_id, resource_name=repo_name,
                                description="Force pushes can rewrite history and destroy audit trails",
                                remediation="Disable 'Allow force pushes' in branch protection rules",
                                compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                            ).to_dict())
                        except Exception:
                            pass

                        # Signed commits required
                        try:
                            signed_commits = getattr(protection, "required_signatures", False)
                            results.append(SaaSCheckResult(
                                check_id="github_repo_signed_commits",
                                check_title="Signed commits are required on default branch",
                                service_area="repo_security", severity="medium",
                                status="PASS" if signed_commits else "FAIL",
                                resource_id=repo_id, resource_name=repo_name,
                                description="Signed commits verify author identity and prevent commit spoofing",
                                remediation="Enable 'Require signed commits' in branch protection rules",
                                compliance_frameworks=["NIST-CSF", "ISO-27001"],
                            ).to_dict())
                        except Exception:
                            pass

                except Exception as e:
                    logger.warning(f"Failed to check branch protection for {repo_name}: {e}")

                # Vulnerability alerts (Dependabot)
                try:
                    vuln_alerts = repo.get_vulnerability_alert()
                    results.append(SaaSCheckResult(
                        check_id="github_repo_vulnerability_alerts",
                        check_title="Vulnerability alerts (Dependabot) are enabled",
                        service_area="repo_security", severity="high",
                        status="PASS" if vuln_alerts else "FAIL",
                        resource_id=repo_id, resource_name=repo_name,
                        description="Vulnerability alerts notify about known security issues in dependencies",
                        remediation="Enable Dependabot vulnerability alerts in repository Settings > Security",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
                except Exception:
                    pass

                # Secret scanning per repo
                try:
                    client = self._get_client()
                    headers, data = client._Github__requester.requestJsonAndCheck(
                        "GET", f"/repos/{repo_name}"
                    )
                    secret_scanning_status = data.get("security_and_analysis", {}).get(
                        "secret_scanning", {}
                    ).get("status", "disabled")
                    results.append(SaaSCheckResult(
                        check_id="github_repo_secret_scanning",
                        check_title="Secret scanning is enabled on repository",
                        service_area="repo_security", severity="high",
                        status="PASS" if secret_scanning_status == "enabled" else "FAIL",
                        resource_id=repo_id, resource_name=repo_name,
                        description="Secret scanning detects committed secrets such as API keys and tokens",
                        remediation="Enable secret scanning in repository Settings > Code security and analysis",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                    ).to_dict())
                except Exception:
                    pass

                # Code scanning (check for code-scanning alerts API availability)
                try:
                    client = self._get_client()
                    headers, data = client._Github__requester.requestJsonAndCheck(
                        "GET", f"/repos/{repo_name}/code-scanning/alerts",
                        input={"per_page": 1}
                    )
                    code_scanning_active = True
                except Exception:
                    code_scanning_active = False

                results.append(SaaSCheckResult(
                    check_id="github_repo_code_scanning",
                    check_title="Code scanning is enabled on repository",
                    service_area="repo_security", severity="medium",
                    status="PASS" if code_scanning_active else "FAIL",
                    resource_id=repo_id, resource_name=repo_name,
                    description="Code scanning identifies security vulnerabilities in source code",
                    remediation="Enable GitHub code scanning (CodeQL) via Actions workflow",
                    remediation_url=f"https://github.com/{repo_name}/security/code-scanning",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())

                # CODEOWNERS file exists
                try:
                    codeowners_found = False
                    for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]:
                        try:
                            repo.get_contents(path)
                            codeowners_found = True
                            break
                        except Exception:
                            continue

                    results.append(SaaSCheckResult(
                        check_id="github_repo_codeowners",
                        check_title="CODEOWNERS file exists in repository",
                        service_area="repo_security", severity="low",
                        status="PASS" if codeowners_found else "FAIL",
                        resource_id=repo_id, resource_name=repo_name,
                        description="CODEOWNERS file defines code review ownership for automated review assignment",
                        remediation="Create a CODEOWNERS file in .github/, root, or docs/ directory",
                        remediation_url=f"https://github.com/{repo_name}/new/main?filename=.github/CODEOWNERS",
                        compliance_frameworks=["NIST-CSF", "ISO-27001"],
                    ).to_dict())
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"GitHub repo security checks failed: {e}")

        return results

    def _check_access_control(self) -> list[dict]:
        """Access control checks."""
        results = []

        try:
            org = self._get_org()

            # Outside collaborators audit
            try:
                outside_collabs = list(org.get_outside_collaborators())
                results.append(SaaSCheckResult(
                    check_id="github_ac_outside_collaborators",
                    check_title="Outside collaborators are reviewed and minimal",
                    service_area="access_control", severity="medium",
                    status="PASS" if len(outside_collabs) <= 10 else "FAIL",
                    resource_id=self.organization,
                    description=f"Outside collaborators: {len(outside_collabs)}. Review for necessity",
                    remediation="Review and remove unnecessary outside collaborators from the organization",
                    remediation_url=f"https://github.com/orgs/{self.organization}/outside-collaborators",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())

                for collab in outside_collabs:
                    results.append(SaaSCheckResult(
                        check_id="github_ac_outside_collaborator_review",
                        check_title="Outside collaborator access is justified",
                        service_area="access_control", severity="medium",
                        status="FAIL",
                        resource_id=str(collab.id), resource_name=collab.login,
                        description=f"Outside collaborator '{collab.login}' has access to organization repositories",
                        remediation="Verify this collaborator still requires access or convert to organization member",
                        compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check outside collaborators: {e}")

            # Stale invitations
            try:
                invitations = list(org.get_pending_invitations())
                from datetime import datetime, timezone
                stale_invitations = []
                for inv in invitations:
                    if inv.created_at:
                        age = (datetime.now(timezone.utc) - inv.created_at.replace(tzinfo=timezone.utc)).days
                        if age > 7:
                            stale_invitations.append(inv)

                results.append(SaaSCheckResult(
                    check_id="github_ac_stale_invitations",
                    check_title="No stale organization invitations (older than 7 days)",
                    service_area="access_control", severity="low",
                    status="PASS" if not stale_invitations else "FAIL",
                    resource_id=self.organization,
                    description=f"Stale invitations (>7 days): {len(stale_invitations)} out of {len(invitations)} total",
                    remediation="Review and cancel stale organization invitations",
                    remediation_url=f"https://github.com/orgs/{self.organization}/people/pending_invitations",
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check stale invitations: {e}")

            # Admin count review
            try:
                members = list(org.get_members(role="admin"))
                admin_count = len(members)
                results.append(SaaSCheckResult(
                    check_id="github_ac_admin_count",
                    check_title="Organization admin count is between 2 and 10",
                    service_area="access_control", severity="high",
                    status="PASS" if 2 <= admin_count <= 10 else "FAIL",
                    resource_id=self.organization,
                    description=f"Organization admins: {admin_count}. Recommended: 2-10",
                    remediation="Maintain 2-10 organization admins to ensure availability without excess privilege",
                    remediation_url=f"https://github.com/orgs/{self.organization}/people?query=role%3Aowner",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check admin count: {e}")

            # Deploy keys audit
            try:
                repos = org.get_repos(type="all")
                total_deploy_keys = 0
                repos_with_write_keys = []
                for repo in repos:
                    if repo.archived:
                        continue
                    try:
                        keys = list(repo.get_keys())
                        total_deploy_keys += len(keys)
                        write_keys = [k for k in keys if not k.read_only]
                        if write_keys:
                            repos_with_write_keys.append(repo.full_name)
                    except Exception:
                        continue

                results.append(SaaSCheckResult(
                    check_id="github_ac_deploy_keys_audit",
                    check_title="Deploy keys with write access are minimized",
                    service_area="access_control", severity="high",
                    status="PASS" if not repos_with_write_keys else "FAIL",
                    resource_id=self.organization,
                    description=f"Total deploy keys: {total_deploy_keys}. Repos with write deploy keys: {len(repos_with_write_keys)}",
                    remediation="Review and remove unnecessary deploy keys, especially those with write access",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to audit deploy keys: {e}")

            # Personal access tokens with excessive scope
            try:
                client = self._get_client()
                user = client.get_user()
                # Check current token scopes from response headers
                headers, _ = client._Github__requester.requestJsonAndCheck("GET", "/user")
                scopes = headers.get("x-oauth-scopes", "")
                scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
                dangerous_scopes = {"admin:org", "admin:repo_hook", "admin:org_hook", "delete_repo", "admin:gpg_key"}
                excessive_scopes = [s for s in scope_list if s in dangerous_scopes]

                results.append(SaaSCheckResult(
                    check_id="github_ac_pat_excessive_scope",
                    check_title="Configured token does not have excessive admin scopes",
                    service_area="access_control", severity="high",
                    status="PASS" if not excessive_scopes else "FAIL",
                    resource_id=user.login,
                    description=f"Token scopes: {', '.join(scope_list)}. Excessive: {', '.join(excessive_scopes) if excessive_scopes else 'none'}",
                    remediation="Use fine-grained personal access tokens with minimal required permissions",
                    remediation_url="https://github.com/settings/tokens?type=beta",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check PAT scopes: {e}")

        except Exception as e:
            logger.warning(f"GitHub access control checks failed: {e}")

        return results

    def _check_actions_security(self) -> list[dict]:
        """GitHub Actions security checks."""
        results = []

        try:
            org = self._get_org()
            client = self._get_client()

            # Actions restrictions - allowed actions policy
            try:
                headers, data = client._Github__requester.requestJsonAndCheck(
                    "GET", f"/orgs/{self.organization}/actions/permissions"
                )
                allowed_actions = data.get("allowed_actions", "all")
                results.append(SaaSCheckResult(
                    check_id="github_actions_restricted",
                    check_title="GitHub Actions are restricted to verified or selected actions",
                    service_area="actions_security", severity="high",
                    status="PASS" if allowed_actions in ("selected", "local_only") else "FAIL",
                    resource_id=self.organization,
                    description=f"Actions policy: '{allowed_actions}'. Should be 'selected' or 'local_only'",
                    remediation="Restrict Actions to selected actions from verified creators only",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/actions",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check actions restrictions: {e}")

            # Self-hosted runners security
            try:
                headers, data = client._Github__requester.requestJsonAndCheck(
                    "GET", f"/orgs/{self.organization}/actions/runners"
                )
                runners = data.get("runners", [])
                has_self_hosted = len(runners) > 0
                offline_runners = [r for r in runners if r.get("status") != "online"]

                results.append(SaaSCheckResult(
                    check_id="github_actions_self_hosted_runners",
                    check_title="Self-hosted runners inventory is reviewed",
                    service_area="actions_security", severity="medium",
                    status="PASS" if not has_self_hosted else "FAIL",
                    resource_id=self.organization,
                    description=f"Self-hosted runners: {len(runners)} (offline: {len(offline_runners)}). "
                                f"Self-hosted runners in public repos are a security risk",
                    remediation="Avoid self-hosted runners for public repositories; use ephemeral runners when possible",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())

                if offline_runners:
                    for runner in offline_runners:
                        results.append(SaaSCheckResult(
                            check_id="github_actions_runner_offline",
                            check_title="Self-hosted runner is online and healthy",
                            service_area="actions_security", severity="medium",
                            status="FAIL",
                            resource_id=str(runner.get("id", "")),
                            resource_name=runner.get("name", "Unknown"),
                            description=f"Runner '{runner.get('name')}' is offline",
                            remediation="Investigate and bring offline runners back online or remove them",
                            compliance_frameworks=["NIST-CSF", "ISO-27001"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check self-hosted runners: {e}")

            # Secrets exposure in logs - check org-level secrets
            try:
                headers, data = client._Github__requester.requestJsonAndCheck(
                    "GET", f"/orgs/{self.organization}/actions/secrets"
                )
                secrets = data.get("secrets", [])
                results.append(SaaSCheckResult(
                    check_id="github_actions_secrets_managed",
                    check_title="Organization Actions secrets are managed centrally",
                    service_area="actions_security", severity="medium",
                    status="PASS" if secrets else "FAIL",
                    resource_id=self.organization,
                    description=f"Organization-level Actions secrets: {len(secrets)}. "
                                f"Centralized secrets management reduces exposure risk",
                    remediation="Use organization-level secrets instead of repository-level secrets where possible",
                    remediation_url=f"https://github.com/organizations/{self.organization}/settings/secrets/actions",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check actions secrets: {e}")

            # OIDC for cloud deployments - check if OIDC customization exists
            try:
                headers, data = client._Github__requester.requestJsonAndCheck(
                    "GET", f"/orgs/{self.organization}/actions/oidc/customization/sub"
                )
                oidc_configured = bool(data.get("include_claim_keys", []))
                results.append(SaaSCheckResult(
                    check_id="github_actions_oidc_configured",
                    check_title="OIDC is configured for cloud deployment authentication",
                    service_area="actions_security", severity="medium",
                    status="PASS" if oidc_configured else "FAIL",
                    resource_id=self.organization,
                    description="OIDC (OpenID Connect) enables short-lived credentials for cloud deployments instead of static secrets",
                    remediation="Configure OIDC trust with cloud providers (AWS, Azure, GCP) for Actions deployments",
                    remediation_url="https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check OIDC configuration: {e}")

            # Check workflow permissions default
            try:
                headers, data = client._Github__requester.requestJsonAndCheck(
                    "GET", f"/orgs/{self.organization}/actions/permissions/workflow"
                )
                default_permissions = data.get("default_workflow_permissions", "write")
                can_approve_prs = data.get("can_approve_pull_request_reviews", True)

                results.append(SaaSCheckResult(
                    check_id="github_actions_workflow_permissions",
                    check_title="Default workflow permissions are read-only",
                    service_area="actions_security", severity="high",
                    status="PASS" if default_permissions == "read" else "FAIL",
                    resource_id=self.organization,
                    description=f"Default workflow token permissions: '{default_permissions}'. Should be 'read'",
                    remediation="Set default workflow permissions to 'Read repository contents' in Organization Settings > Actions",
                    compliance_frameworks=["NIST-CSF", "ISO-27001", "AICPA-TSC", "CIS"],
                ).to_dict())

                results.append(SaaSCheckResult(
                    check_id="github_actions_no_pr_approval",
                    check_title="Actions cannot approve pull request reviews",
                    service_area="actions_security", severity="medium",
                    status="PASS" if not can_approve_prs else "FAIL",
                    resource_id=self.organization,
                    description="GitHub Actions workflows should not be able to approve pull requests",
                    remediation="Disable 'Allow GitHub Actions to create and approve pull requests'",
                    compliance_frameworks=["NIST-CSF", "ISO-27001"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Failed to check workflow permissions: {e}")

        except Exception as e:
            logger.warning(f"GitHub Actions security checks failed: {e}")

        return results

    def test_connection(self) -> tuple[bool, str]:
        """Test connection to GitHub API."""
        try:
            org = self._get_org()
            return True, f"Connected to organization '{org.login}'"
        except Exception as e:
            return False, str(e)
