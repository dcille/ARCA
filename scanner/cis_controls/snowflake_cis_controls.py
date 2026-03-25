"""CIS Snowflake Benchmark v1.0.0 — Complete Control Registry.

This registry contains ALL controls from the CIS Snowflake Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS Snowflake Benchmark v1.0.0

The benchmark covers four key areas:
  Section 1: Identity and Access Management
  Section 2: Monitoring and Alerting
  Section 3: Networking
  Section 4: Data Protection

Total controls: 39 across 4 sections.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" (essential) or "L2" (enhanced)
# assessment_type: "automated" or "manual"

SNOWFLAKE_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Identity and Access Management
    # =========================================================================

    ("1.1", "Ensure single sign-on (SSO) is configured for your account/organization",
     "L1", "automated", "critical", "identity_and_access_management"),
    ("1.2", "Ensure Snowflake SCIM integration is configured to automatically provision and deprovision users and groups",
     "L2", "automated", "high", "identity_and_access_management"),
    ("1.3", "Ensure that Snowflake password is unset for SSO users",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.4", "Ensure multi-factor authentication (MFA) is turned on for all human users with password-based authentication",
     "L1", "automated", "critical", "identity_and_access_management"),
    ("1.5", "Ensure minimum password length is set to 14 characters or more",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.6", "Ensure that service accounts use key pair authentication",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.7", "Ensure authentication key pairs are rotated every 180 days",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.8", "Ensure that users who did not log in for 90 days are disabled",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.9", "Ensure that the idle session timeout is set to 15 minutes or less for users with the ACCOUNTADMIN and SECURITYADMIN roles",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.10", "Limit the number of users with ACCOUNTADMIN and SECURITYADMIN",
     "L1", "automated", "critical", "identity_and_access_management"),
    ("1.11", "Ensure that all users granted the ACCOUNTADMIN role have an email address assigned",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.12", "Ensure that no users have ACCOUNTADMIN or SECURITYADMIN as the default role",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.13", "Ensure that the ACCOUNTADMIN or SECURITYADMIN role is not granted to any custom role",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.14", "Ensure that Snowflake tasks are not owned by the ACCOUNTADMIN or SECURITYADMIN roles",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.15", "Ensure that Snowflake tasks do not run with the ACCOUNTADMIN or SECURITYADMIN role privileges",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.16", "Ensure that Snowflake stored procedures are not owned by the ACCOUNTADMIN or SECURITYADMIN roles",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.17", "Ensure Snowflake stored procedures do not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
     "L1", "automated", "medium", "identity_and_access_management"),

    # =========================================================================
    # Section 2: Monitoring and Alerting
    # =========================================================================

    ("2.1", "Ensure monitoring and alerting exist for ACCOUNTADMIN and SECURITYADMIN role grants",
     "L1", "manual", "high", "monitoring_and_alerting"),
    ("2.2", "Ensure monitoring and alerting exist for MANAGE GRANTS privilege grants",
     "L1", "manual", "high", "monitoring_and_alerting"),
    ("2.3", "Ensure monitoring and alerting exist for password sign-ins of SSO users",
     "L1", "manual", "medium", "monitoring_and_alerting"),
    ("2.4", "Ensure monitoring and alerting exist for password sign-in without MFA",
     "L1", "manual", "medium", "monitoring_and_alerting"),
    ("2.5", "Ensure monitoring and alerting exist for creation, update and deletion of security integrations",
     "L1", "manual", "high", "monitoring_and_alerting"),
    ("2.6", "Ensure monitoring and alerting exist for changes to network policies and associated objects",
     "L1", "manual", "high", "monitoring_and_alerting"),
    ("2.7", "Ensure monitoring and alerting exist for SCIM token creation",
     "L1", "manual", "medium", "monitoring_and_alerting"),
    ("2.8", "Ensure monitoring and alerting exists for new share exposures",
     "L1", "manual", "high", "monitoring_and_alerting"),
    ("2.9", "Ensure monitoring and alerting exists for sessions from unsupported Snowflake Connector for Python and JDBC and ODBC drivers",
     "L2", "manual", "medium", "monitoring_and_alerting"),

    # =========================================================================
    # Section 3: Networking
    # =========================================================================

    ("3.1", "Ensure that an account-level network policy has been configured to only allow access from trusted IP addresses",
     "L2", "manual", "high", "networking"),
    ("3.2", "Ensure that user-level network policies have been configured for service accounts",
     "L1", "manual", "high", "networking"),

    # =========================================================================
    # Section 4: Data Protection
    # =========================================================================

    ("4.1", "Ensure yearly rekeying is enabled for a Snowflake account",
     "L2", "automated", "medium", "data_protection"),
    ("4.2", "Ensure AES encryption key size used to encrypt files stored in internal stages is set to 256 bits",
     "L1", "automated", "medium", "data_protection"),
    ("4.3", "Ensure that the DATA_RETENTION_TIME_IN_DAYS parameter is set to 90 for critical data",
     "L2", "manual", "medium", "data_protection"),
    ("4.4", "Ensure that the MIN_DATA_RETENTION_TIME_IN_DAYS account parameter is set to 7 or higher",
     "L2", "automated", "medium", "data_protection"),
    ("4.5", "Ensure that the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION account parameter is set to true",
     "L1", "automated", "high", "data_protection"),
    ("4.6", "Ensure that the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION account parameter is set to true",
     "L1", "automated", "high", "data_protection"),
    ("4.7", "Ensure that all external stages have storage integrations",
     "L1", "automated", "high", "data_protection"),
    ("4.8", "Ensure that the PREVENT_UNLOAD_TO_INLINE_URL account parameter is set to true",
     "L1", "automated", "high", "data_protection"),
    ("4.9", "Ensure that Tri-Secret Secure is enabled for the Snowflake account",
     "L2", "manual", "high", "data_protection"),
    ("4.10", "Ensure that data masking is enabled for sensitive data",
     "L2", "manual", "high", "data_protection"),
    ("4.11", "Ensure that row-access policies are configured for sensitive data",
     "L2", "manual", "high", "data_protection"),
]


def get_snowflake_cis_registry():
    """Return the complete CIS Snowflake control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in SNOWFLAKE_CIS_CONTROLS
    ]


def get_snowflake_control_count():
    """Return total number of CIS Snowflake controls."""
    return len(SNOWFLAKE_CIS_CONTROLS)


def get_snowflake_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in SNOWFLAKE_CIS_CONTROLS if c[3] == "automated")


def get_snowflake_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in SNOWFLAKE_CIS_CONTROLS if c[3] == "manual")
