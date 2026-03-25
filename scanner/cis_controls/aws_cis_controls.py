"""CIS Amazon Web Services Foundations Benchmark v6.0.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 62 controls (34 automated, 28 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS Amazon Web Services Foundations Benchmark v6.0.0 (2025)
Source: CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf

Total controls: 62 (34 automated, 28 manual)
"""

import json as _json


# Control registry — 62 controls
AWS_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "2.1",
    "title": "Maintain current contact details",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 19,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.2",
    "title": "Ensure security contact information is registered",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 22,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.3",
    "title": "Ensure no 'root' user account access key exists",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 24,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.4",
    "title": "Ensure MFA is enabled for the 'root' user account",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 27,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.5",
    "title": "Ensure hardware MFA is enabled for the 'root' user account",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 30,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.6",
    "title": "Eliminate use of the 'root' user for administrative and daily tasks",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 33,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.7",
    "title": "Ensure IAM password policy requires minimum length of 14 or greater",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 36,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.8",
    "title": "Ensure IAM password policy prevents password reuse",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 39,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.9",
    "title": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 41,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.10",
    "title": "Do not create access keys during initial setup for IAM users with a console password",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 45,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.11",
    "title": "Ensure credentials unused for 45 days or more are disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 49,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.12",
    "title": "Ensure there is only one active access key for any single IAM user",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 53,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.13",
    "title": "Ensure access keys are rotated every 90 days or less",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 57,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.14",
    "title": "Ensure IAM users receive permissions only through groups",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 60,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.15",
    "title": "Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 63,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.16",
    "title": "Ensure a support role has been created to manage incidents with AWS Support",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 66,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.17",
    "title": "Ensure IAM instance roles are used for AWS resource access from instances",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 69,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.18",
    "title": "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 73,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.19",
    "title": "Ensure that IAM External Access Analyzer is enabled for all regions",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 76,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.20",
    "title": "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 79,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.21",
    "title": "Ensure access to AWSCloudShellFullAccess is restricted",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 81,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.1.1",
    "title": "Ensure S3 Bucket Policy is set to deny HTTP requests",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Simple Storage Service (S3) This section contains recommendations for configuring AWS Simple Storage Service (S3) Buckets",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 85,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.1.2",
    "title": "Ensure MFA Delete is enabled on S3 buckets",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Simple Storage Service (S3) This section contains recommendations for configuring AWS Simple Storage Service (S3) Buckets",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 91,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.1.3",
    "title": "Ensure all data in Amazon S3 has been discovered, classified, and secured when necessary",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Simple Storage Service (S3) This section contains recommendations for configuring AWS Simple Storage Service (S3) Buckets",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 94,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.1.4",
    "title": "Ensure that S3 is configured with 'Block Public Access' enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Simple Storage Service (S3) This section contains recommendations for configuring AWS Simple Storage Service (S3) Buckets",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 97,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2.1",
    "title": "Ensure that encryption-at-rest is enabled for RDS instances",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Relational Database Service (RDS) This section contains recommendations for configuring AWS Relational Database Services (RDS)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 102,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2.2",
    "title": "Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Relational Database Service (RDS) This section contains recommendations for configuring AWS Relational Database Services (RDS)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 107,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2.3",
    "title": "Ensure that RDS instances are not publicly accessible",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Relational Database Service (RDS) This section contains recommendations for configuring AWS Relational Database Services (RDS)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 111,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2.4",
    "title": "Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Relational Database Service (RDS) This section contains recommendations for configuring AWS Relational Database Services (RDS)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 116,
    "dspm_relevant": true,
    "dspm_categories": [
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.3.1",
    "title": "Ensure that encryption is enabled for EFS file systems",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Elastic File System (EFS)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 120,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.1",
    "title": "Ensure CloudTrail is enabled in all regions",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 125,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.2",
    "title": "Ensure CloudTrail log file validation is enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 129,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.3",
    "title": "Ensure AWS Config is enabled in all regions",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 132,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.4",
    "title": "Ensure that server access logging is enabled on the CloudTrail S3 bucket",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "subdomain": "Establish and Maintain Detailed Enterprise Asset Inventory  Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 136,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.5",
    "title": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "subdomain": "Establish and Maintain Detailed Enterprise Asset Inventory  Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 140,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "logging",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.6",
    "title": "Ensure rotation for customer-created symmetric CMKs is enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "subdomain": "Establish and Maintain Detailed Enterprise Asset Inventory  Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 144,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.7",
    "title": "Ensure VPC flow logging is enabled in all VPCs",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "subdomain": "Establish and Maintain Detailed Enterprise Asset Inventory  Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 147,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.8",
    "title": "Ensure that object-level logging for write events is enabled for S3 buckets",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "subdomain": "Establish and Maintain Detailed Enterprise Asset Inventory  Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 152,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.9",
    "title": "Ensure that object-level logging for read events is enabled for S3 buckets",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging",
    "domain": "Logging",
    "subdomain": "Establish and Maintain Detailed Enterprise Asset Inventory  Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 156,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.1",
    "title": "Ensure unauthorized API calls are monitored",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 161,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2",
    "title": "Ensure management console sign-in without MFA is monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 165,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.3",
    "title": "Ensure usage of the 'root' account is monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 169,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.4",
    "title": "Ensure IAM policy changes are monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 173,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.5",
    "title": "Ensure CloudTrail configuration changes are monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 177,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.6",
    "title": "Ensure AWS Management Console authentication failures are monitored",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 181,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.7",
    "title": "Ensure disabling or scheduled deletion of customer created CMKs is monitored",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 185,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.8",
    "title": "Ensure S3 bucket policy changes are monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 189,
    "dspm_relevant": true,
    "dspm_categories": [
      "classification",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.9",
    "title": "Ensure AWS Config configuration changes are monitored",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 193,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.10",
    "title": "Ensure security group changes are monitored",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 197,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.11",
    "title": "Ensure Network Access Control List (NACL) changes are monitored",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 201,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.12",
    "title": "Ensure changes to network gateways are monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 205,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.13",
    "title": "Ensure route table changes are monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 209,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.14",
    "title": "Ensure VPC changes are monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 213,
    "dspm_relevant": true,
    "dspm_categories": [
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.15",
    "title": "Ensure AWS Organizations changes are monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 217,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.16",
    "title": "Ensure AWS Security Hub is enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "monitoring",
    "domain": "Monitoring",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 221,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.1",
    "title": "Ensure EBS volume encryption is enabled in all regions",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Elastic Compute Cloud (EC2) This section contains recommendations for configuring AWS Elastic Compute Cloud (EC2)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 225,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2",
    "title": "Ensure CIFS access is restricted to trusted networks to prevent unauthorized access",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Elastic Compute Cloud (EC2) This section contains recommendations for configuring AWS Elastic Compute Cloud (EC2)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 228,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.2",
    "title": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Elastic Compute Cloud (EC2) This section contains recommendations for configuring AWS Elastic Compute Cloud (EC2)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 231,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.3",
    "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Elastic Compute Cloud (EC2) This section contains recommendations for configuring AWS Elastic Compute Cloud (EC2)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 234,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.4",
    "title": "Ensure no security groups allow ingress from ::/0 to remote server administration ports",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Elastic Compute Cloud (EC2) This section contains recommendations for configuring AWS Elastic Compute Cloud (EC2)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 237,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.5",
    "title": "Ensure the default security group of every VPC restricts all traffic",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Elastic Compute Cloud (EC2) This section contains recommendations for configuring AWS Elastic Compute Cloud (EC2)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 240,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.6",
    "title": "Ensure routing tables for VPC peering are \"least access\"",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Elastic Compute Cloud (EC2) This section contains recommendations for configuring AWS Elastic Compute Cloud (EC2)",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Amazon_Web_Services_Foundations_Benchmark_v6.0.0.pdf",
    "page": 245,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  }
]
""")


def get_aws_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return AWS_CIS_CONTROLS


def get_aws_control_count() -> int:
    """Return total number of CIS controls."""
    return len(AWS_CIS_CONTROLS)


def get_aws_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in AWS_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_aws_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in AWS_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_aws_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in AWS_CIS_CONTROLS if c.get("dspm_relevant")]


def get_aws_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in AWS_CIS_CONTROLS if c.get("rr_relevant")]


def get_aws_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in AWS_CIS_CONTROLS if c["service_area"] == service_area]


def get_aws_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in AWS_CIS_CONTROLS if c["severity"] == severity]
