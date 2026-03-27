"""CIS IBM Cloud v2.0.0 Sections 2–6 — 33 controls (all manual).

Section 2: Storage (COS + Block + File) — 15 controls
Section 3: Logging and Monitoring — 6 controls
Section 4: IBM Cloud Databases — 3 controls
Section 5: Cloudant — 1 control
Section 6: Networking (CIS + VPC) — 8 controls
"""

import logging
from .base import IBMCloudClientCache, EvalConfig, make_manual_result

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Section 2 — Storage (15 controls, all manual)
# ═══════════════════════════════════════════════════════════════════

# ── 2.1.1.1 — COS encryption with customer managed keys ──
def evaluate_cis_2_1_1_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.1.1.1", "ibm_cis_2_1_1_1",
        "Ensure Cloud Object Storage encryption is done with customer managed keys",
        "storage", "high", cfg.account_id,
        "Requires verifying COS bucket encryption settings use customer managed keys (Key Protect/HPCS).")]


# ── 2.1.1.2 — COS encryption with BYOK ──
def evaluate_cis_2_1_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.1.1.2", "ibm_cis_2_1_1_2",
        "Ensure Cloud Object Storage Encryption is set to On with BYOK",
        "storage", "critical", cfg.account_id,
        "Requires verifying COS bucket encryption uses Bring Your Own Key (BYOK).")]


# ── 2.1.1.3 — COS encryption with KYOK ──
def evaluate_cis_2_1_1_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.1.1.3", "ibm_cis_2_1_1_3",
        "Ensure Cloud Object Storage Encryption is set to On with KYOK",
        "storage", "critical", cfg.account_id,
        "Requires verifying COS bucket encryption uses Keep Your Own Key (KYOK) via HPCS.")]


# ── 2.1.2 — COS network access restricted to specific IP range ──
def evaluate_cis_2_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.1.2", "ibm_cis_2_1_2",
        "Ensure network access for Cloud Object Storage is restricted to specific IP range",
        "storage", "high", cfg.account_id,
        "Requires verifying COS bucket firewall / Context-Based Restrictions restrict to specific IPs.")]


# ── 2.1.3 — COS private endpoints only ──
def evaluate_cis_2_1_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.1.3", "ibm_cis_2_1_3",
        "Ensure network access for COS is set to be exposed only on Private end-points",
        "storage", "medium", cfg.account_id,
        "Requires verifying COS bucket access is restricted to private endpoints only.")]


# ── 2.1.4 — COS access restricted by IAM and S3 ACL ──
def evaluate_cis_2_1_4(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.1.4", "ibm_cis_2_1_4",
        "Ensure Cloud Object Storage bucket access is restricted by using IAM and S3 access control",
        "storage", "medium", cfg.account_id,
        "Requires verifying COS bucket IAM policies and S3 ACLs are properly configured.")]


# ── 2.1.5 — COS public access disabled ──
def evaluate_cis_2_1_5(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.1.5", "ibm_cis_2_1_5",
        "Ensure Public (anonymous) Access to IBM Cloud Object Storage buckets is Disabled",
        "storage", "medium", cfg.account_id,
        "Requires verifying no COS bucket has public access enabled.")]


# ── 2.2.1.1 — Block Storage encrypted with BYOK ──
def evaluate_cis_2_2_1_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.1.1", "ibm_cis_2_2_1_1",
        "Ensure IBM Cloud Block Storage for VPC is encrypted with BYOK",
        "storage", "high", cfg.account_id,
        "Requires verifying VPC Block Storage volumes use BYOK encryption.")]


# ── 2.2.1.2 — Block Storage encrypted with KYOK ──
def evaluate_cis_2_2_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.1.2", "ibm_cis_2_2_1_2",
        "Ensure IBM Cloud Block Storage for VPC is encrypted with KYOK",
        "storage", "high", cfg.account_id,
        "Requires verifying VPC Block Storage volumes use KYOK encryption via HPCS.")]


# ── 2.2.2.1 — File Storage encrypted with provider managed keys ──
def evaluate_cis_2_2_2_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.2.1", "ibm_cis_2_2_2_1",
        "Ensure IBM Cloud File Storage for VPC is encrypted with provider managed keys",
        "storage", "high", cfg.account_id,
        "Requires verifying VPC File Storage shares are encrypted with at least provider managed keys.")]


# ── 2.2.2.2 — File Storage encrypted with BYOK ──
def evaluate_cis_2_2_2_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.2.2", "ibm_cis_2_2_2_2",
        "Ensure IBM Cloud File Storage for VPC is encrypted with BYOK",
        "storage", "high", cfg.account_id,
        "Requires verifying VPC File Storage shares use BYOK encryption.")]


# ── 2.2.2.3 — File Storage encrypted with KYOK ──
def evaluate_cis_2_2_2_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.2.3", "ibm_cis_2_2_2_3",
        "Ensure IBM Cloud File Storage for VPC is encrypted with KYOK",
        "storage", "high", cfg.account_id,
        "Requires verifying VPC File Storage shares use KYOK encryption via HPCS.")]


# ── 2.2.3 — Boot volumes encrypted with customer managed keys ──
def evaluate_cis_2_2_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.3", "ibm_cis_2_2_3",
        "Ensure boot volumes are encrypted with Customer managed keys",
        "storage", "high", cfg.account_id,
        "Requires verifying VPC instance boot volumes use customer managed key encryption.")]


# ── 2.2.4 — Secondary volumes encrypted with customer managed keys ──
def evaluate_cis_2_2_4(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.4", "ibm_cis_2_2_4",
        "Ensure secondary volumes are encrypted with customer managed keys",
        "storage", "high", cfg.account_id,
        "Requires verifying VPC instance data volumes use customer managed key encryption.")]


# ── 2.2.5 — Unattached volumes encrypted with customer managed keys ──
def evaluate_cis_2_2_5(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("2.2.5", "ibm_cis_2_2_5",
        "Ensure unattached volumes are encrypted with customer managed keys",
        "storage", "high", cfg.account_id,
        "Requires verifying unattached VPC volumes use customer managed key encryption.")]


# ═══════════════════════════════════════════════════════════════════
# Section 3 — Logging and Monitoring (6 controls, all manual)
# ═══════════════════════════════════════════════════════════════════

# ── 3.1 — Auditing configured ──
def evaluate_cis_3_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("3.1", "ibm_cis_3_1",
        "Ensure auditing is configured in the IBM Cloud account",
        "logging_monitoring", "high", cfg.account_id,
        "Requires verifying Activity Tracker / IBM Cloud Logs is provisioned and collecting events.")]


# ── 3.2 — Data retention for audit events ──
def evaluate_cis_3_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("3.2", "ibm_cis_3_2",
        "Ensure data retention for audit events",
        "logging_monitoring", "high", cfg.account_id,
        "Requires verifying audit event data retention policies meet organizational requirements.")]


# ── 3.3 — Events collected and processed for anomalies ──
def evaluate_cis_3_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("3.3", "ibm_cis_3_3",
        "Ensure events are collected and processed to identify anomalies",
        "logging_monitoring", "medium", cfg.account_id,
        "Requires verifying IBM Cloud Logs processes events for anomaly detection.")]


# ── 3.4 — Alerts on custom views ──
def evaluate_cis_3_4(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("3.4", "ibm_cis_3_4",
        "Ensure alerts are defined on custom views for unauthorized requests and critical actions",
        "logging_monitoring", "medium", cfg.account_id,
        "Requires verifying alerts are configured in IBM Cloud Logs for critical account events.")]


# ── 3.5 — Account owner login restricted by country/IP ──
def evaluate_cis_3_5(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("3.5", "ibm_cis_3_5",
        "Ensure the account owner can login only from authorized countries/IP ranges",
        "logging_monitoring", "medium", cfg.account_id,
        "Requires verifying IP-based access restrictions for the account owner via IAM settings.")]


# ── 3.6 — Activity Tracker data encrypted at rest ──
def evaluate_cis_3_6(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("3.6", "ibm_cis_3_6",
        "Ensure Activity Tracker data is encrypted at rest",
        "logging_monitoring", "high", cfg.account_id,
        "Requires verifying Activity Tracker / IBM Cloud Logs data is encrypted with customer managed keys.")]


# ═══════════════════════════════════════════════════════════════════
# Section 4 — IBM Cloud Databases (3 controls, all manual)
# ═══════════════════════════════════════════════════════════════════

# ── 4.1 — Database disk encryption with customer managed keys ──
def evaluate_cis_4_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("4.1", "ibm_cis_4_1",
        "Ensure IBM Cloud Databases disk encryption is enabled with customer managed keys",
        "database", "high", cfg.account_id,
        "Requires verifying ICD instances use customer managed key encryption for disk storage.")]


# ── 4.2 — Database private endpoints only ──
def evaluate_cis_4_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("4.2", "ibm_cis_4_2",
        "Ensure network access to IBM Cloud Databases is set to Private end points only",
        "database", "high", cfg.account_id,
        "Requires verifying ICD instances expose only private endpoints.")]


# ── 4.3 — Database incoming connections limited ──
def evaluate_cis_4_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("4.3", "ibm_cis_4_3",
        "Ensure incoming connections are limited to allowed sources",
        "database", "medium", cfg.account_id,
        "Requires verifying ICD instance allowlists restrict connections to authorized IP ranges.")]


# ═══════════════════════════════════════════════════════════════════
# Section 5 — Cloudant (1 control, manual)
# ═══════════════════════════════════════════════════════════════════

# ── 5.1 — Cloudant encryption with customer managed keys ──
def evaluate_cis_5_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("5.1", "ibm_cis_5_1",
        "Ensure IBM Cloudant encryption is enabled with customer managed keys",
        "cloudant", "high", cfg.account_id,
        "Requires verifying Cloudant instances use customer managed key encryption.")]


# ═══════════════════════════════════════════════════════════════════
# Section 6 — Networking (8 controls, all manual)
# ═══════════════════════════════════════════════════════════════════

# ── 6.1.1 — TLS 1.2 on CIS Proxy ──
def evaluate_cis_6_1_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.1.1", "ibm_cis_6_1_1",
        "Enable TLS 1.2 at minimum for all inbound traffic on IBM Cloud Internet Services Proxy",
        "networking", "high", cfg.account_id,
        "Requires verifying CIS proxy minimum TLS version is set to 1.2 or higher.")]


# ── 6.1.2 — WAF enabled on CIS ──
def evaluate_cis_6_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.1.2", "ibm_cis_6_1_2",
        "Ensure Web application firewall is ENABLED in IBM Cloud Internet Services (CIS)",
        "networking", "high", cfg.account_id,
        "Requires verifying WAF is enabled for all domains in CIS.")]


# ── 6.1.3 — DDoS protection active on CIS ──
def evaluate_cis_6_1_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.1.3", "ibm_cis_6_1_3",
        "Ensure DDoS protection is Active on IBM Cloud Internet Services",
        "networking", "high", cfg.account_id,
        "Requires verifying DDoS protection is active for all domains in CIS.")]


# ── 6.2.1 — No VPC ACL allows ingress 0.0.0.0/0 to port 22 ──
def evaluate_cis_6_2_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.2.1", "ibm_cis_6_2_1",
        "Ensure no VPC access control lists allow ingress from 0.0.0.0/0 to port 22",
        "networking", "critical", cfg.account_id,
        "Requires reviewing VPC ACL rules for SSH (port 22) open to 0.0.0.0/0.")]


# ── 6.2.2 — Default VPC security group restricts all traffic ──
def evaluate_cis_6_2_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.2.2", "ibm_cis_6_2_2",
        "Ensure the default security group of every VPC restricts all traffic",
        "networking", "critical", cfg.account_id,
        "Requires verifying default security groups in all VPCs restrict all inbound/outbound traffic.")]


# ── 6.2.3 — No VPC SG allows ingress 0.0.0.0/0 to port 3389 ──
def evaluate_cis_6_2_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.2.3", "ibm_cis_6_2_3",
        "Ensure no VPC security groups allow ingress from 0.0.0.0/0 to port 3389",
        "networking", "critical", cfg.account_id,
        "Requires reviewing VPC security group rules for RDP (port 3389) open to 0.0.0.0/0.")]


# ── 6.2.4 — No VPC SG allows ingress 0.0.0.0/0 to port 22 ──
def evaluate_cis_6_2_4(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.2.4", "ibm_cis_6_2_4",
        "Ensure no VPC security groups allow ingress from 0.0.0.0/0 to port 22",
        "networking", "critical", cfg.account_id,
        "Requires reviewing VPC security group rules for SSH (port 22) open to 0.0.0.0/0.")]


# ── 6.2.5 — No VPC ACL allows ingress 0.0.0.0/0 to port 3389 ──
def evaluate_cis_6_2_5(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("6.2.5", "ibm_cis_6_2_5",
        "Ensure no VPC access control lists allow ingress from 0.0.0.0/0 to port 3389",
        "networking", "critical", cfg.account_id,
        "Requires reviewing VPC ACL rules for RDP (port 3389) open to 0.0.0.0/0.")]
