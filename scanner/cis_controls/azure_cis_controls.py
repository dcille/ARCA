"""CIS Microsoft Azure Foundations Benchmark v5.0.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 155 controls (93 automated, 62 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS Microsoft Azure Foundations Benchmark v5.0.0 (2025)
Source: CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf

Total controls: 155 (93 automated, 62 manual)
"""

import json as _json


# Control registry — 155 controls
AZURE_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "2.1.1",
    "title": "Ensure that Azure Databricks is deployed in a customer- managed virtual network (VNet)",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Azure Databricks",
    "description": "Networking for Azure Databricks can be set up in a few different ways. Using a\ncustomer-managed Virtual Network (VNet) (also known as VNet Injection) ensures that\ncompute clusters and control planes are securely isolated within the organization’s\nnetwork boundary. By default, Databricks creates a managed VNet, which provides\nlimited control over network security policies, firewall configurations, and routing.",
    "rationale": "Using a customer-managed VNet ensures better control over network security and\naligns with zero-trust architecture principles. It allows for:\n• Restricted outbound internet access to prevent unauthorized data exfiltration.\n• Integration with on-premises networks via VPN or ExpressRoute for hybrid\nconnectivity.\n• Fine-grained NSG policies to restrict access at the subnet level.\n• Private Link for secure API access, avoiding public internet exposure.",
    "impact": "• Requires additional configuration during Databricks workspace deployment.\n• Might increase operational overhead for network maintenance.\n• May impact connectivity if misconfigured (e.g., restrictive NSG rules or missing\nroutes).",
    "audit": "Audit from Azure Portal\n1. Go to Azure Portal → Search for Databricks Workspaces.\n2. Select the Databricks Workspace to audit.\n3. Under Networking, check if the workspace is deployed in a Customer-Managed\nVNet.\n4. If the Virtual Network field shows Databricks-Managed VNet, it is non-compliant.\n5. Verify NSG rules and Private Endpoints for fine-grained access control.\nAudit from Azure CLI\nRun the following command to check if Databricks is using a customer-managed VNet:\naz network vnet show --resource-group <resource-group-name> --name <vnet-\nname>\nEnsure that Databricks subnets are present in the VNet configuration. Validate NSG\nrules attached to the Databricks subnets.\nAudit from PowerShell\nGet-AzDatabricksWorkspace -ResourceGroupName <resource-group-name> -Name\n<databricks-workspace-name> | Select-Object VirtualNetworkId\nIf VirtualNetworkId is null or shows a Databricks-Managed VNet, it is non-compliant.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 9c25c9e4-ee12-4882-afd2-11fb9d87893f - Name: 'Azure Databricks\nWorkspaces should be in a virtual network'",
    "expected_response": "Ensure that Databricks subnets are present in the VNet configuration. Validate NSG\nWorkspaces should be in a virtual network'",
    "remediation": "Remediate from Azure Portal\n1. Delete the existing Databricks workspace (migration required).\n2. Create a new Databricks workspace with VNet Injection:\n3. Go to Azure Portal → Create Databricks Workspace.\n4. Select Advanced Networking.\n5. Choose Deploy into your own Virtual Network.\n6. Specify a customer-managed VNet and associated subnets.\n7. Enable Private Link for secure API access.\nRemediate from Azure CLI\nDeploy a new Databricks workspace in a custom VNet:\naz databricks workspace create --name <databricks-workspace-name> \\\n--resource-group <resource-group-name> \\\n--location <region> \\\n--managed-resource-group <managed-rg-name> \\\n--enable-no-public-ip true \\\n--network-security-group-rule \"NoAzureServices\" \\\n--public-network-access Disabled \\\n--custom-virtual-network-id /subscriptions/<subscription-\nid>/resourceGroups/<resource-group-\nname>/providers/Microsoft.Network/virtualNetworks/<vnet-name>\nEnsure NSG Rules are correctly configured:\naz network nsg rule create --resource-group <resource-group-name> \\\n--nsg-name <nsg-name> \\\n--name \"DenyAllOutbound\" \\\n--direction Outbound \\\n--access Deny \\\n--priority 4096\nRemediate from PowerShell\nNew-AzDatabricksWorkspace -ResourceGroupName <resource-group-name> -Name\n<databricks-workspace-name> -Location <region> -ManagedResourceGroupName\n<managed-rg-name> -CustomVirtualNetworkId \"/subscriptions/<subscription-\nid>/resourceGroups/<resource-group-\nname>/providers/Microsoft.Network/virtualNetworks/<vnet-name>\"",
    "default_value": "By default, Azure Databricks uses a Databricks-Managed VNet.",
    "detection_commands": [
      "az network vnet show --resource-group <resource-group-name> --name <vnet-",
      "Get-AzDatabricksWorkspace -ResourceGroupName <resource-group-name> -Name"
    ],
    "remediation_commands": [
      "az databricks workspace create --name <databricks-workspace-name> --resource-group <resource-group-name> --location <region> --managed-resource-group <managed-rg-name> --enable-no-public-ip true --network-security-group-rule \"NoAzureServices\" --public-network-access Disabled --custom-virtual-network-id /subscriptions/<subscription-",
      "az network nsg rule create --resource-group <resource-group-name> --nsg-name <nsg-name> --name \"DenyAllOutbound\" --direction Outbound --access Deny --priority 4096",
      "New-AzDatabricksWorkspace -ResourceGroupName <resource-group-name> -Name"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 29,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "2.1.2",
    "title": "Ensure that network security groups are configured for Databricks subnets",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Segment the Network Based on Sensitivity",
    "description": "Network Security Groups (NSGs) should be implemented to control inbound and\noutbound traffic to Azure Databricks subnets, ensuring only authorized communication.\nNSGs operate using a rule-based model that includes both explicit allow/deny rules and\nan implicit deny at the end of the rule list. This means that any traffic not explicitly\nallowed is automatically denied. To ensure secure and predictable behavior, NSGs\nshould be configured with explicit deny rules for known unwanted traffic, in addition to\nthe default implicit deny, to improve visibility and auditability of blocked traffic. This\napproach helps enforce least privilege and minimizes the risk of unauthorized access to\nDatabricks resources.",
    "rationale": "Using NSGs with both explicit allow and deny rules provides clear documentation and\ncontrol over permitted and prohibited traffic. While Azure NSGs implicitly deny all traffic\nnot explicitly allowed, defining explicit deny rules for known malicious or unnecessary\nsources enhances clarity, simplifies troubleshooting, and supports compliance audits.\nThis layered approach strengthens the security posture of Databricks environments by\nensuring only essential communication is permitted.",
    "impact": "• NSGs require ongoing maintenance to ensure rule accuracy and alignment with\nevolving business and security requirements.\n• Misconfigured NSGs—especially overly broad allow rules or missing explicit\ndenies—can inadvertently expose Databricks resources or block legitimate\ntraffic.\n• Relying solely on implicit deny may obscure the intent behind traffic restrictions,\nmaking it harder to audit or troubleshoot network behavior.",
    "audit": "Audit from Azure Portal\n1. Navigate to Virtual Networks > Subnets, and review NSG assignments.\nAudit from Azure CLI\naz network nsg list --query \"[].{Name:name, Rules:securityRules}\"\nAudit from PowerShell\nGet-AzNetworkSecurityGroup -ResourceGroupName <resource-group-name>",
    "remediation": "Remediate from Azure Portal\n1. Assign NSG to Databricks subnets under Networking > NSG Settings.",
    "default_value": "By default, Databricks subnets do not have NSGs assigned.",
    "detection_commands": [
      "az network nsg list --query \"[].{Name:name, Rules:securityRules}\"",
      "Get-AzNetworkSecurityGroup -ResourceGroupName <resource-group-name>"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-",
      "databricks-security-baseline",
      "2. https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/vnet-",
      "inject#network-security-group-rules"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 32,
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
    "cis_id": "2.1.3",
    "title": "Ensure that traffic is encrypted between cluster worker nodes",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Apply Host-based Firewalls or Port Filtering",
    "description": "By default, data exchanged between worker nodes in an Azure Databricks cluster is not\nencrypted. To ensure that data is encrypted at all times, whether at rest or in transit, you\ncan create an initialization script that configures your clusters to encrypt traffic between\nworker nodes using AES 256-bit encryption over a TLS 1.3 connection.",
    "rationale": "• Protects sensitive data during transit between cluster nodes, mitigating risks of\ndata interception or unauthorized access.\n• Aligns with organizational security policies and compliance requirements that\nmandate encryption of data in transit.\n• Enhances overall security posture by ensuring that all inter-node communications\nwithin the cluster are encrypted.",
    "impact": "• Enabling encryption may introduce a performance penalty due to the\ncomputational overhead associated with encrypting and decrypting traffic. This\ncan result in longer query execution times, especially for data-intensive\noperations.\n• Implementing encryption requires creating and managing init scripts, which adds\ncomplexity to cluster configuration and maintenance.\n• The shared encryption secret is derived from the hash of the keystore stored in\nDBFS. If the keystore is updated or rotated, all running clusters must be restarted\nto prevent authentication failures between Spark workers and drivers.",
    "audit": "Audit from Azure Portal\nReview cluster init scripts:\n1. Navigate to your Azure Databricks workspace, go to the \"Clusters\" section, select\na cluster, and check the \"Advanced Options\" for any init scripts that configure\nencryption settings.\nVerify spark configuration:\n2. Ensure that the following Spark configurations are set:\n3. spark.authenticate true\n4. spark.authenticate.enableSaslEncryption true\n5. spark.network.crypto.enabled true\n6. spark.network.crypto.keyLength 256\n7. spark.network.crypto.keyFactoryAlgorithm PBKDF2WithHmacSHA1\n8. spark.io.encryption.enabled true\nThese settings can be found in the cluster's Spark configuration properties.\nCheck keystore management:\n3. Verify that the Java KeyStore (JKS) file is securely stored in DBFS and that its\nintegrity is maintained.\n4. Ensure that the keystore password is securely managed and not hardcoded in\nscripts.",
    "expected_response": "2. Ensure that the following Spark configurations are set:\n4. Ensure that the keystore password is securely managed and not hardcoded in",
    "remediation": "Create a JKS keystore:\n1. Generate a Java KeyStore (JKS) file that will be used for SSL/TLS encryption.\n2. Upload the keystore file to a secure directory in DBFS (e.g.\n/dbfs//jetty_ssl_driver_keystore.jks).\nDevelop an init script:\n3. Create an init script that performs the following tasks:\no Retrieves the JKS keystore file and password.\no Derives a shared encryption secret from the keystore.\no Configures Spark driver and executor settings to enable encryption.\n4. Example init script:\n5. #!/bin/bash\n6. set -euo pipefail\n7. keystore_dbfs_file=\"/dbfs/<keystore-\ndirectory>/jetty_ssl_driver_keystore.jks\"\n8. max_attempts=30\n9. while [ ! -f ${keystore_dbfs_file} ]; do\n10.   if [ \"$max_attempts\" == 0 ]; then\n11.     echo \"ERROR: Unable to find the file : $keystore_dbfs_file.\nFailing the script.\"\n12.     exit 1\n13.   fi\n14.   sleep 2s\n15.   ((max_attempts--))\n16. done\n17. sasl_secret=$(sha256sum $keystore_dbfs_file | cut -d' ' -f1)\n18. if [ -z \"${sasl_secret}\" ]; then\n19.   echo \"ERROR: Unable to derive the secret. Failing the script.\"\n20.   exit 1\n21. fi\n22. local_keystore_file=\"$DB_HOME/keys/jetty_ssl_driver_keystore.jks\"\n23. local_keystore_password=\"gb1gQqZ9ZIHS\"\n24. if [[ $DB_IS_DRIVER = \"TRUE\" ]]; then\n25.   driver_conf=${DB_HOME}/driver/conf/spark-branch.conf\n26.   echo \"Configuring driver conf at $driver_conf\"\n27.   if [ ! -e $driver_conf ]; then\n28.     echo \"spark.authenticate true\" >> $driver_conf\n29.     echo \"spark.authenticate.secret $sasl_secret\" >> $driver_conf\n30.     echo \"spark.authenticate.enableSaslEncryption true\" >>\n$driver_conf\n31.     echo \"spark.network.crypto.enabled true\" >> $driver_conf\n32.     echo \"spark.network.crypto.keyLength 256\" >> $driver_conf\n33.     echo \"spark.network.crypto.keyFactoryAlgorithm PBKDF2WithHmacSHA1\"\n>> $driver_conf\n34.     echo \"spark.io.encryption.enabled true\" >> $driver_conf\n35.     echo \"spark.ssl.enabled true\" >> $driver_conf\n36.     echo \"spark.ssl.keyPassword $local_keystore_password\" >>\n$driver_conf\n37.     echo \"spark.ssl.keyStore $local_keystore_file\" >> $driver_conf\n38.     echo \"spark.ssl.keyStorePassword $local_keystore_password\" >>\n$driver_conf\n39.     echo \"spark.ssl.protocol TLSv1.3\" >> $driver_conf\n40.   fi\n41. fi\n42. executor_conf=${DB_HOME}/conf/spark.executor.extraJavaOptions\n43. echo \"Configuring executor conf at $executor_conf\"\n44. if [ ! -e $executor_conf ]; then\n45.   echo \"-Dspark.authenticate=true\" >> $executor_conf\n46.   echo \"-Dspark.authenticate.secret=$sasl_secret\" >> $executor_conf\n47.   echo \"-Dspark.authenticate.enableSaslEncryption=true\" >>\n$executor_conf\n48.   echo \"-Dspark.network.crypto.enabled=true\" >> $executor_conf\n49.   echo \"-Dspark.network.crypto.keyLength=256\" >> $executor_conf\n50.   echo \"-Dspark.network.crypto.keyFactoryAlgorithm=PBKDF2WithHmacSHA1\"\n>> $executor_conf\n51.   echo \"-Dspark.io.encryption.enabled=true\" >> $executor_conf\n52.   echo \"-Dspark.ssl.enabled=true\" >> $executor_conf\n53.   echo \"-Dspark.ssl.keyPassword=$local_keystore_password\" >>\n$executor_conf\n54.   echo \"-Dspark.ssl.keyStore=$local_keystore_file\" >> $executor_conf\n55.   echo \"-Dspark.ssl.keyStorePassword=$local_keystore_password\" >>\n$executor_conf\n56.   echo \"-Dspark.ssl.protocol=TLSv1.3\" >> $executor_conf\n57. fi\n58. Save.",
    "default_value": "By default, traffic is not encrypted between cluster worker nodes.",
    "detection_commands": [],
    "remediation_commands": [
      "Create a JKS keystore:",
      "$driver_conf",
      "$executor_conf"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/databricks/security/keys/encrypt-otw"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 34,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "2.1.4",
    "title": "Ensure that users and groups are synced from Microsoft Entra ID to Azure Databricks",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "To ensure centralized identity and access management, users and groups from\nMicrosoft Entra ID should be synchronized with Azure Databricks. This is achieved\nthrough SCIM provisioning, which automates the creation, update, and deactivation of\nusers and groups in Databricks based on Entra ID assignments. Enabling this\nintegration ensures that access controls in Databricks remain consistent with corporate\nidentity governance policies, reducing the risk of orphaned accounts, stale permissions,\nand unauthorized access.",
    "rationale": "Syncing users and groups from Microsoft Entra ID centralizes access control, enforces\nthe least privilege principle by automatically revoking unnecessary access, reduces\nadministrative overhead by eliminating manual user management, and ensures\nauditability and compliance with industry regulations.",
    "impact": "SCIM provisioning requires role mapping to avoid misconfigured user privileges.",
    "audit": "Audit from Azure Portal\nVerify SCIM provisioning is enabled:\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Enterprise applications.\n3. Click the name of the Azure Databricks SCIM application.\n4. Under Provisioning, confirm that SCIM provisioning is enabled and running.\nCheck user sync status in Azure Portal:\n5. Under Provisioning Logs, verify the last successful sync and any failed\nentries.\nCheck user sync status in Databricks:\n6. Go to Admin Console > Identity and Access Management.\n7. Confirm that Users and Groups match those assigned in Microsoft Entra ID.\nEnsure role-based access control (RBAC) mapping is correct:\n8. Verify that users are assigned appropriate Databricks roles (e.g. Admin, User,\nContributor).\n9. Confirm that groups are mapped to workspace access roles.",
    "expected_response": "Verify SCIM provisioning is enabled:\n4. Under Provisioning, confirm that SCIM provisioning is enabled and running.\nEnsure role-based access control (RBAC) mapping is correct:",
    "remediation": "Remediate from Azure Portal\nEnable provisioning in Azure Portal:\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Enterprise applications.\n3. Click the name of the Azure Databricks SCIM application.\n4. Under Provisioning, select Automatic and enter the SCIM endpoint and API\ntoken from Databricks.\nEnable provisioning in Databricks:\n5. Navigate to Admin Console > Identity and Access Management.\n6. Enable SCIM provisioning and generate an API token.\nConfigure role assignments:\n7. Ensure groups from Entra ID are mapped to appropriate Databricks roles.\n8. Restrict administrative privileges to designated security groups.\nRegularly monitor sync logs:\n9. Periodically review sync logs in Microsoft Entra ID and Databricks Admin\nConsole.\n10. Configure Azure Monitor alerts for provisioning failures.\nDisable manual user creation in Databricks:\n11. Ensure that all user management is controlled via SCIM sync from Entra ID.\n12. Disable personal access token usage for authentication.\nRemediate from Azure CLI\nEnable SCIM User and Group Provisioning in Azure Databricks:\naz ad app update --id <databricks-app-id> --set\nprovisioning.provisioningMode=Automatic",
    "default_value": "By default, Azure Databricks does not sync users and groups from Microsoft Entra ID.",
    "detection_commands": [],
    "remediation_commands": [
      "az ad app update --id <databricks-app-id> --set"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/databricks/administration-guide/users-",
      "groups/scim/aad"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 38,
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
    "cis_id": "2.1.5",
    "title": "Ensure that Unity Catalog is configured for Azure Databricks",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Unity Catalog is a centralized governance model for managing and securing data in\nAzure Databricks. It provides fine-grained access control to databases, tables, and\nviews using Microsoft Entra ID identities. Unity Catalog also enhances data lineage,\naudit logging, and compliance monitoring, making it a critical component for security\nand governance.",
    "rationale": "• Enforces centralized access control policies and reduces data security risks.\n• Enables identity-based authentication via Microsoft Entra ID.\n• Improves compliance with industry regulations (e.g. GDPR, HIPAA, SOC 2) by\nproviding audit logs and access visibility.\n• Prevents unauthorized data access through table-, row-, and column-level\nsecurity (RLS & CLS).",
    "impact": "• Improperly configured permissions may lead to data exfiltration or unauthorized\naccess.\n• Unity Catalog requires structured governance policies to be effective and prevent\noverly permissive access.",
    "audit": "Method 1: Verify unity catalog deployment:\n1. As an Azure Databricks account admin, log into the account console.\n2. Click Workspaces.\n3. Find your workspace and check the Metastore column. If a metastore name is\npresent, your workspace is attached to a Unity Catalog metastore and therefore\nenabled for Unity Catalog.\nMethod 2: Run a SQL query to confirm Unity Catalog enablement\nRun the following SQL query in the SQL query editor or a notebook that is attached to a\nUnity Catalog-enabled compute resource. No admin role is required.\nSELECT CURRENT_METASTORE();\nIf the query returns a metastore ID like the following, then your workspace is attached to\na Unity Catalog metastore and therefore enabled for Unity Catalog.",
    "expected_response": "If the query returns a metastore ID like the following, then your workspace is attached to",
    "remediation": "Use the remediation procedure written in this article: https://learn.microsoft.com/en-\nus/azure/databricks/data-governance/unity-catalog/get-started.",
    "default_value": "New workspaces have Unity Catalog enabled by default. Existing workspaces may\nrequire manual enablement.",
    "detection_commands": [
      "SELECT CURRENT_METASTORE();"
    ],
    "remediation_commands": [
      "Use the remediation procedure written in this article: https://learn.microsoft.com/en-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/databricks/data-governance/unity-",
      "catalog/",
      "2. https://learn.microsoft.com/en-us/azure/databricks/admin/users-groups/",
      "3. https://learn.microsoft.com/en-us/azure/databricks/data-governance/unity-",
      "catalog/enable-workspaces"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 41,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.6",
    "title": "Ensure that usage is restricted and expiry is enforced for Databricks personal access tokens",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Databricks personal access tokens (PATs) provide API-based authentication for users\nand applications. By default, users can generate API tokens without expiration, leading\nto potential security risks if tokens are leaked, improperly stored, or not rotated\nregularly.\nTo mitigate these risks, administrators should:\n• Restrict token creation to approved users and service principals.\n• Enforce expiration policies to prevent long-lived tokens.\n• Monitor token usage and revoke unused or compromised tokens.",
    "rationale": "Restricting usage and enforcing expiry for personal access tokens reduces exposure to\nlong-lived tokens, minimizes the risk of API abuse if compromised, and aligns with\nsecurity best practices through controlled issuance and enforced expiry.",
    "impact": "If revoked improperly, applications relying on these tokens may fail, requiring a\nremediation plan for token rotation. Increased administrative effort is required to track\nand manage API tokens effectively.",
    "audit": "Azure Databricks administrators can monitor and revoke personal access tokens within\ntheir workspace. Detailed instructions are available in the \"Monitor and Revoke\nPersonal Access Tokens\" section of the Microsoft documentation:\nhttps://learn.microsoft.com/en-us/azure/databricks/admin/access-control/tokens.\nTo evaluate the usage of personal access tokens in your Azure Databricks account, you\ncan utilize the provided notebook that lists all PATs not rotated or updated in the last 90\ndays, allowing you to identify tokens that may require revocation. This process is\ndetailed here: https://learn.microsoft.com/en-us/azure/databricks/admin/access-\ncontrol/tokens.\nImplementing diagnostic logging provides a comprehensive reference of audit log\nservices and events, enabling you to track activities related to personal access tokens.\nMore information can be found in the diagnostic log reference section:\nhttps://learn.microsoft.com/en-us/azure/databricks/admin/account-settings/audit-logs.",
    "remediation": "Remediate from Azure Portal\nDisable personal access tokens:\nIf your workspace does not require PATs, you can disable them entirely to prevent their\nuse.\n1. Navigate to your Azure Databricks workspace.\n2. Click the Settings icon and select Admin Console.\n3. Go to the Advanced tab.\n4. Under Personal Access Tokens, toggle the setting to Disabled.\nDatabricks CLI:\ndatabricks workspace-conf set-status --json '{\"enableTokens\": \"false\"}'\nControl who can create and use personal access tokens:\nDefine which users or groups are authorized to create and utilize PATs.\n1. Navigate to your Azure Databricks workspace.\n2. Click the Settings icon and select Admin Console.\n3. Go to the Advanced tab.\n4. Click on Personal Access Tokens and then Permissions.\n5. Assign the appropriate permissions (e.g. No Permissions, Can Use, Can\nManage) to users or groups.\nSet maximum lifetime for new personal access tokens:\nLimit the validity period of new tokens to reduce potential misuse.\nDatabricks CLI:\ndatabricks workspace-conf set-status --json '{\"maxTokenLifetimeDays\": \"90\"}'\nMonitor and revoke personal access tokens:\nPeriodically review active tokens and revoke any that are unnecessary or potentially\ncompromised.\nDatabricks CLI:\ndatabricks token list\ndatabricks token delete --token-id <token-id>\nTransition to OAuth for enhanced security:\nUtilize OAuth tokens for authentication, offering improved security features over PATs.",
    "default_value": "By default, personal access tokens are enabled and users can create the Personal\naccess token and their expiry time.",
    "detection_commands": [
      "Azure Databricks administrators can monitor and revoke personal access tokens within"
    ],
    "remediation_commands": [
      "use."
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/databricks/administration-guide/access-",
      "control/tokens",
      "2. https://learn.microsoft.com/en-us/azure/databricks/dev-tools/auth/"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 43,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.7",
    "title": "Ensure that diagnostic log delivery is configured for Azure Databricks",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Azure Databricks Diagnostic Logging provides insights into system operations, user\nactivities, and security events within a Databricks workspace. Enabling diagnostic logs\nhelps organizations:\n• Detect security threats by logging access, job executions, and cluster activities.\n• Ensure compliance with industry regulations such as SOC 2, HIPAA, and GDPR.\n• Monitor operational performance and troubleshoot issues proactively.",
    "rationale": "Diagnostic logging provides visibility into security and operational activities within\nDatabricks workspaces while maintaining an audit trail for forensic investigations, and it\nsupports compliance with regulatory standards that require logging and monitoring.",
    "impact": "Logs consume storage and may require additional monitoring tools, leading to\nincreased operational overhead and costs. Incomplete log configurations may result in\nmissing critical events, reducing monitoring effectiveness.",
    "audit": "Audit from Azure Portal\nCheck if diagnostic logging is enabled for the Databricks workspace:\n1. Go to Azure Databricks.\n2. Select a workspace.\n3. In the left-hand menu, select Monitoring > Diagnostic settings.\n4. Verify if a diagnostic setting is configured. If not, diagnostic logging is not\nenabled.\nEnsure that logging is enabled for the following categories:\n• accounts: User account activities.\n• Filesystem: Databricks Filesystem Logs\n• clusters: Cluster state changes and errors.\n• notebook: Execution events.\n• jobs: Job execution tracking.\nVerify that logs are being sent to one or more of the following destinations:\n• Azure Log Analytics workspace: For analysis and querying.\n• Azure Storage Account: For long-term retention.\n• Azure Event Hubs: For integration with SIEM tools.\nAudit from Azure CLI\nCheck if diagnostic logging is enabled for the Databricks workspace:\naz monitor diagnostic-settings list --resource <databricks-resource-id>\nIf the output is empty, no diagnostic settings are configured.\nVerify log categories being collected:\naz monitor diagnostic-settings show --name <setting-name> --resource\n<databricks-resource-id>\nReview the output to confirm that the necessary log categories are enabled.\nCheck if logs are stored securely in an approved location:\naz monitor diagnostic-settings list --resource <databricks-resource-id>\nReview the storageAccountId, workspaceId, and eventHubAuthorizationRuleId fields in\nthe output to confirm the log destinations.\nAudit from PowerShell\nCheck if diagnostic logging is enabled for the Databricks workspace:\nGet-AzDiagnosticSetting -ResourceId <databricks-resource-id>\nAn empty result indicates that diagnostic logging is not enabled.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 138ff14d-b687-4faa-a81c-898c91a87fa2 - Name: 'Resource logs in\nAzure Databricks Workspaces should be enabled'",
    "expected_response": "Check if diagnostic logging is enabled for the Databricks workspace:\n4. Verify if a diagnostic setting is configured. If not, diagnostic logging is not\nEnsure that logging is enabled for the following categories:\nIf the output is empty, no diagnostic settings are configured.\nReview the output to confirm that the necessary log categories are enabled.\nthe output to confirm the log destinations.\nAzure Databricks Workspaces should be enabled'",
    "remediation": "Remediate from Azure Portal\nEnable diagnostic logging for Azure Databricks:\n1. Navigate to your Azure Databricks workspace.\n2. In the left-hand menu, select Monitoring > Diagnostic settings.\n3. Click + Add diagnostic setting.\n4. Under Category details, select the log categories you wish to capture, such\nas AuditLogs, Clusters, Notebooks, and Jobs.\n5. Choose a destination for the logs:\no Log Analytics workspace: For advanced querying and monitoring.\no Storage account: For long-term retention.\no Event Hub: For integration with third-party systems.\n6. Provide a Name for the diagnostic setting.\n7. Click Save.\nImplement log retention policies:\n1. Navigate to your Log Analytics workspace.\n2. Under General, select Usage and estimated costs.\n3. Click Data Retention.\n4. Adjust the retention period slider to the desired number of days (up to 730 days).\n5. Click OK.\nMonitor logs for anomalies:\n1. Navigate to Azure Monitor.\n2. Select Alerts > + New alert rule.\n3. Under Scope, specify the Databricks resource.\n4. Define Condition based on log queries that identify anomalies (e.g.\nunauthorized access attempts).\n5. Configure Actions to notify stakeholders or trigger automated responses.\n6. Provide an Alert rule name and description.\n7. Click Create alert rule.\nRemediate from Azure CLI\nEnable diagnostic logging for Azure Databricks:\naz monitor diagnostic-settings create --name \"DatabricksLogging\" --resource\n<databricks-resource-id> --logs '[{\"category\": \"accounts\", \"enabled\": true},\n{\"category\": \"Clusters\", \"enabled\": true}, {\"category\": \"Notebooks\",\n\"enabled\": true}, {\"category\": \"Jobs\", \"enabled\": true}]' --workspace <log-\nanalytics-id>\nImplement log retention policies:\naz monitor log-analytics workspace update --resource-group <resource-group> -\n-name <log-analytics-name> --retention-time 365\nMonitor logs for anomalies:\naz monitor activity-log alert create --name \"DatabricksAnomalyAlert\" --\nresource-group <resource-group> --scopes <databricks-resource-id> --condition\n\"contains 'UnauthorizedAccess'\"",
    "additional_information": "• Ensure that the Azure Databricks workspace is on the Premium plan to utilize\ndiagnostic logging features.\n• Regularly review and update alert rules to adapt to evolving security threats and\noperational requirements.",
    "detection_commands": [
      "az monitor diagnostic-settings list --resource <databricks-resource-id>",
      "az monitor diagnostic-settings show --name <setting-name> --resource",
      "Get-AzDiagnosticSetting -ResourceId <databricks-resource-id>",
      "Azure Databricks Workspaces should be enabled'"
    ],
    "remediation_commands": [
      "az monitor diagnostic-settings create --name \"DatabricksLogging\" --resource",
      "az monitor log-analytics workspace update --resource-group <resource-group> -",
      "az monitor activity-log alert create --name \"DatabricksAnomalyAlert\" --"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/databricks/admin/account-settings/audit-",
      "log-delivery",
      "2. https://learn.microsoft.com/en-us/troubleshoot/azure/azure-monitor/log-",
      "analytics/billing/configure-data-retention",
      "3. https://docs.azure.cn/en-us/databricks/admin/account-settings/audit-logs",
      "4. https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-",
      "logs/microsoft-databricks-workspaces-logs"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 46,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.8",
    "title": "Ensure critical data in Azure Databricks is encrypted with customer-managed keys (CMK)",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Activate audit logging",
    "description": "Customer-managed keys introduce additional depth to security by providing a means to\nmanage access control for encryption keys. Where compliance and security frameworks\nindicate the need, and organizational capacity allows, sensitive data at rest can be\nencrypted using customer-managed keys (CMK) rather than Microsoft-managed keys.",
    "rationale": "By default in Azure, data at rest tends to be encrypted using Microsoft-managed keys. If\nyour organization wants to control and manage encryption keys for compliance and\ndefense-in-depth, customer-managed keys can be established.\nWhile it is possible to automate the assessment of this recommendation, the\nassessment status for this recommendation remains 'Manual' due to ideally limited\nscope. The scope of application—which workloads CMK is applied to—should be\ncarefully considered to account for organizational capacity and targeted to workloads\nwith specific need for CMK.",
    "impact": "If the key expires due to setting the 'activation date' and 'expiration date', the key must\nbe rotated manually.\nUsing customer-managed keys may also incur additional man-hour requirements to\ncreate, store, manage, and protect the keys as needed.",
    "audit": "Audit from Azure Portal\n1. Go to Azure Portal → Databricks Workspaces.\n2. Select a Databricks Workspace and go to Encryption settings.\n3. Check if customer-managed keys (CMK) are enabled under \"Managed Disk\nEncryption\".\n4. If CMK is not enabled, the workspace is non-compliant.\nAudit from Azure CLI\nRun the following command to check encryption settings for Databricks workspace:\naz databricks workspace show --name <databricks-workspace-name> --resource-\ngroup <resource-group-name> --query encryption\nEnsure that keySource is set to Microsoft.KeyVault.\nAudit from PowerShell\nGet-AzDatabricksWorkspace -ResourceGroupName \"<resource-group-name>\" -Name\n\"<databricks-workspace-name>\" | Select-Object Encryption\nVerify that encryption is set to Customer-Managed Keys (CMK).\nAudit from Databricks CLI\ndatabricks workspace get-metadata --workspace-id <workspace-id>\nEnsure that encryption settings reflect a CMK setup.",
    "expected_response": "Ensure that keySource is set to Microsoft.KeyVault.\nVerify that encryption is set to Customer-Managed Keys (CMK).\nEnsure that encryption settings reflect a CMK setup.",
    "remediation": "NOTE: These remediations assume that an Azure KeyVault already exists in the\nsubscription.\nRemediate from Azure CLI\n1. Create a dedicated key:\naz keyvault key create --vault-name <keyvault-name> --name <key-name> --\nprotection <\"software\" or \"hsm\">\n2. Assign permissions to Databricks:\naz keyvault set-policy --name <keyvault-name> --resource-group <resource-\ngroup-name> --spn <databricks-spn> --key-permissions get wrapKey unwrapKey\n3. Enable encryption with CMK:\naz databricks workspace update --name <databricks-workspace-name> --resource-\ngroup <resource-group-name> --key-source \"Microsoft.KeyVault\" --key-name\n<key-name> --keyvault-uri <keyvault-uri>\nRemediate from PowerShell\n$Key = Add-AzKeyVaultKey -VaultName <keyvault-name> -Name <key-name> -\nDestination <\"software\" or \"hsm\">\nSet-AzDatabricksWorkspace -ResourceGroupName \"<resource-group-name>\" -\nWorkspaceName \"<databricks-workspace-name>\" -EncryptionKeySource\n\"Microsoft.KeyVault\" -KeyVaultUri $Key.Id",
    "default_value": "By default, encryption type is set to Microsoft-managed keys.",
    "additional_information": "This recommendation is based on the Common Reference Recommendation Ensure\ncritical data is encrypted with customer-managed keys (CMK), from the\nCommon Reference Recommendations > Secrets and Keys > Encryption Key\nManagement > Customer Managed Keys section.",
    "detection_commands": [
      "az databricks workspace show --name <databricks-workspace-name> --resource-",
      "Get-AzDatabricksWorkspace -ResourceGroupName \"<resource-group-name>\" -Name \"<databricks-workspace-name>\" | Select-Object Encryption"
    ],
    "remediation_commands": [
      "az keyvault key create --vault-name <keyvault-name> --name <key-name> --",
      "az keyvault set-policy --name <keyvault-name> --resource-group <resource-",
      "az databricks workspace update --name <databricks-workspace-name> --resource-",
      "$Key = Add-AzKeyVaultKey -VaultName <keyvault-name> -Name <key-name> -",
      "Set-AzDatabricksWorkspace -ResourceGroupName \"<resource-group-name>\" -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-",
      "best-practices#protect-data-at-rest",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-",
      "when-required",
      "3. https://learn.microsoft.com/en-us/azure/databricks/security/keys/cmk-managed-",
      "disks-azure/cmk-managed-disks-azure"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 50,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "2.1.9",
    "title": "Ensure 'No Public IP' is set to 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Enable secure cluster connectivity (also known as no public IP) on Azure Databricks\nworkspaces to ensure that clusters do not have public IP addresses and communicate\nwith the control plane over a secure connection.",
    "rationale": "Enabling secure cluster connectivity limits exposure to the public internet, improving\nsecurity and reducing the risk of external attacks.",
    "impact": "Enabling secure cluster connectivity requires careful network configuration. Before\nsecure cluster connectivity can be enabled, Azure Databricks workspaces must be\ndeployed in a customer-managed virtual network (VNet injection)—refer to the\nrecommendation Ensure that Azure Databricks is deployed in a customer-\nmanaged virtual network (VNet).",
    "audit": "Audit from Azure Portal\n1. Go to Azure Databricks.\n2. Click the name of a workspace.\n3. Under Settings, click Networking.\n4. Under Network access, ensure that Deploy Azure Databricks workspace\nwith Secure Cluster Connectivity (No Public IP) is set to Enabled.\n5. Repeat steps 1-4 for each workspace.\nAudit from Azure CLI\nRun the following command to list workspaces:\naz databricks workspace list\nFor each workspace, run the following command to get the enableNoPublicIp setting:\naz databricks workspace show --resource-group <resource-group> --name\n<workspace> --query parameters.enableNoPublicIp.value\nEnsure that true is returned.\nAudit from PowerShell\nRun the following command to list workspaces:\nGet-AzDatabricksWorkspace\nRun the following command to get the workspace in a resource group with a given\nname:\n$workspace = Get-AzDatabricksWorkspace -ResourceGroupName <resource-group> -\nName <workspace>\nRun the following command to get the EnableNoPublicIp setting:\n$workspace.EnableNoPublicIP\nEnsure that True is returned.\nRepeat for each workspace.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 51c1490f-3319-459c-bbbc-7f391bbed753 - Name: 'Azure Databricks\nClusters should disable public IP'",
    "expected_response": "4. Under Network access, ensure that Deploy Azure Databricks workspace\nwith Secure Cluster Connectivity (No Public IP) is set to Enabled.\nEnsure that true is returned.\nEnsure that True is returned.\nClusters should disable public IP'",
    "remediation": "Remediate from Azure Portal\n1. Go to Azure Databricks.\n2. Click the name of a workspace.\n3. Under Settings, click Networking.\n4. Under Network access, next to Deploy Azure Databricks workspace with\nSecure Cluster Connectivity (No Public IP), click the radio button next\nto Enabled.\n5. Click Save.\n6. Repeat steps 1-5 for each workspace requiring remediation.\nRemediate from Azure CLI\nFor each workspace requiring remediation, run the following command to set\nenableNoPublicIp to true:\naz databricks workspace update --resource-group <resource-group> --name\n<workspace> --enable-no-public-ip true\nRemediate from PowerShell\nFor each workspace requiring remediation, run the following command to set\nEnableNoPublicIP to True:\nUpdate-AzDatabricksWorkspace -ResourceGroupName <resource-group> -Name\n<workspace> -EnableNoPublicIP",
    "default_value": "No Public IP is set to Enabled by default.",
    "detection_commands": [
      "az databricks workspace list",
      "az databricks workspace show --resource-group <resource-group> --name",
      "Get-AzDatabricksWorkspace",
      "$workspace = Get-AzDatabricksWorkspace -ResourceGroupName <resource-group> -",
      "$workspace.EnableNoPublicIP"
    ],
    "remediation_commands": [
      "az databricks workspace update --resource-group <resource-group> --name",
      "Update-AzDatabricksWorkspace -ResourceGroupName <resource-group> -Name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-",
      "us/azure/databricks/security/network/classic/secure-cluster-connectivity",
      "2. https://learn.microsoft.com/en-us/cli/azure/databricks/workspace",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.databricks"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 53,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "2.1.10",
    "title": "Ensure 'Allow Public Network Access' is set to 'Disabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Disable public network access to prevent exposure to the internet and reduce the risk of\nunauthorized access. Use private endpoints to securely manage access within trusted\nnetworks.",
    "rationale": "Disabling public network access improves security by ensuring that Azure Databricks\nworkspaces are not exposed on the public internet.",
    "impact": "NOTE: Prior to disabling public network access, it is strongly recommended that, for\neach workspace, either:\n• virtual network integration is completed as described in \"Ensure that Azure\nDatabricks is deployed in a customer-managed virtual network (VNet)\"\nOR\n• private endpoints/links are set up as described in \"Ensure private endpoints\nare used to access Azure Databricks workspaces.\"\nDisabling public network access restricts access to the service. This enhances security\nbut will require the configuration of a virtual network and/or private endpoints for any\nservices or users needing access within trusted networks.\nBefore public network access can be disabled, Azure Databricks workspaces must be\ndeployed in a customer-managed virtual network (VNet injection)—refer to the\nrecommendation Ensure that Azure Databricks is deployed in a customer-\nmanaged virtual network (VNet), and requiredNsgRules must be set to a value\nother than AllRules.",
    "audit": "Audit from Azure Portal\n1. Go to Azure Databricks.\n2. Click the name of a workspace.\n3. Under Settings click Networking.\n4. Under Network access, ensure Allow Public Network Access is set to\nDisabled.\n5. Repeat steps 1-4 for each workspace.\nAudit from Azure CLI\nRun the following command to list workspaces:\naz databricks workspace list\nFor each workspace, run the following command to get the publicNetworkAccess\nsetting:\naz databricks workspace show --resource-group <resource-group> --name\n<workspace> --query publicNetworkAccess\nEnsure that \"Disabled\" is returned.\nAudit from PowerShell\nRun the following command to list workspaces:\nGet-AzDatabricksWorkspace\nRun the following command to get the workspace in a resource group with a given\nname:\n$workspace = Get-AzDatabricksWorkspace -ResourceGroupName <resource-group> -\nName <workspace>\nRun the following command to get the PublicNetworkAccess setting:\n$workspace.PublicNetworkAccess\nEnsure that Disabled is returned.\nRepeat for each workspace.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 0e7849de-b939-4c50-ab48-fc6b0f5eeba2 - Name: 'Azure Databricks\nWorkspaces should disable public network access'",
    "expected_response": "4. Under Network access, ensure Allow Public Network Access is set to\nEnsure that \"Disabled\" is returned.\nEnsure that Disabled is returned.\nWorkspaces should disable public network access'",
    "remediation": "Remediate from Azure Portal\n1. Go to Azure Databricks.\n2. Click the name of a workspace.\n3. Under Settings click Networking.\n4. Under Network access, next to Allow Public Network Access, click the\nradio button next to Disabled.\n5. Click Save.\n6. Repeat steps 1-5 for each workspace requiring remediation.\nRemediate from Azure CLI\nFor each workspace requiring remediation, run the following command to set\npublicNetworkAccess to Disabled:\naz databricks workspace update --resource-group <resource-group> --name\n<workspace> --public-network-access Disabled\nRemediate from PowerShell\nFor each workspace requiring remediation, run the following command to set\nPublicNetworkAccess to Disabled:\nUpdate-AzDatabricksWorkspace -ResourceGroupName <resource-group> -Name\n<workspace> -PublicNetworkAccess Disabled",
    "default_value": "Allow Public Network Access is set to Enabled by default.",
    "additional_information": "This recommendation is based on the Common Reference Recommendation Ensure\npublic network access is Disabled, from the Common Reference\nRecommendations > Networking > Virtual Networks (VNets) section.",
    "detection_commands": [
      "az databricks workspace list",
      "az databricks workspace show --resource-group <resource-group> --name",
      "Get-AzDatabricksWorkspace",
      "$workspace = Get-AzDatabricksWorkspace -ResourceGroupName <resource-group> -",
      "$workspace.PublicNetworkAccess"
    ],
    "remediation_commands": [
      "az databricks workspace update --resource-group <resource-group> --name",
      "Update-AzDatabricksWorkspace -ResourceGroupName <resource-group> -Name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/cli/azure/databricks/workspace",
      "2. https://learn.microsoft.com/en-us/powershell/module/az.databricks"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 56,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "2.1.11",
    "title": "Ensure private endpoints are used to access Azure Databricks workspaces",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "analytics",
    "domain": "Analytics Services",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Use private endpoints for Azure Databricks workspaces to allow clients and services to\nsecurely access data located over a network via an encrypted Private Link. To do this,\nthe private endpoint uses an IP address from the VNet for each service. Network traffic\nbetween disparate services securely traverses encrypted over the VNet. This VNet can\nalso link addressing space, extending your network and accessing resources on it.\nSimilarly, it can be a tunnel through public networks to connect remote infrastructures\ntogether. This creates further security through segmenting network traffic and\npreventing outside sources from accessing it.",
    "rationale": "Using private endpoints for Azure Databricks workspaces ensures that all\ncommunication between clients, services, and data sources occurs over a secure,\nprivate IP space within an Azure Virtual Network (VNet). This approach eliminates\nexposure to the public internet, significantly reducing the attack surface and aligning\nwith Zero Trust principles. Additionally, integrating Databricks with a VNet enables\nnetwork segmentation, fine-grained access control, and hybrid connectivity through\nVNet peering or VPN/ExpressRoute.",
    "impact": "If an Azure Virtual Network is not implemented correctly, this may result in the loss of\ncritical network traffic.\nPrivate endpoints are charged per hour of use. Refer to https://azure.microsoft.com/en-\nus/pricing/details/private-link/ and https://azure.microsoft.com/en-us/pricing/calculator/\nto estimate potential costs.\nBefore a private endpoint can be configured, Azure Databricks workspaces:\n• must be deployed in a customer-managed virtual network (VNet injection)—refer\nto the recommendation Ensure that Azure Databricks is deployed in a\ncustomer-managed virtual network (VNet)\n• must have secure cluster connectivity enabled—refer to the recommendation\nEnsure 'Enable No Public IP' is set to 'Yes'\n• must be on the Premium pricing tier\nEnsure the requirements and concepts are considered carefully before applying this\nrecommendation. Refer to https://learn.microsoft.com/en-\nus/azure/databricks/security/network/classic/private-link for more information.",
    "audit": "Audit from Azure Portal\n1. Go to Azure Databricks.\n2. Click the name of a workspace.\n3. Under Settings, click Networking.\n4. Click Private endpoint connections.\n5. Ensure a private endpoint connection exists with a connection state of Approved.\n6. Repeat steps 1-5 for each workspace.\nAudit from Azure CLI\nRun the following command to list workspaces:\naz databricks workspace list\nFor each workspace, run the following command to get the\nprivateEndpointConnections configuration:\naz databricks workspace show --resource-group <resource-group> --name\n<workspace> --query privateEndpointConnections\nEnsure a private endpoint connection is returned with a\nprivateLinkServiceConnectionState status of Approved.\nAudit from PowerShell\nRun the following command to list workspaces:\nGet-AzDatabricksWorkspace\nRun the following command to get the workspace in a resource group with a given\nname:\n$workspace = Get-AzDatabricksWorkspace -ResourceGroupName <resource-group> -\nName <workspace>\nRun the following command to get the PrivateEndpointConnection configuration:\n$workspace.PrivateEndpointConnection | Select-Object -Property\nId,PrivateLinkServiceConnectionStateStatus\nEnsure a private endpoint connection is returned with a\nPrivateLinkServiceConnectionStateStatus of Approved.\nRepeat for each workspace.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 258823f2-4595-4b52-b333-cc96192710d8 - Name: 'Azure Databricks\nWorkspaces should use private link'",
    "expected_response": "5. Ensure a private endpoint connection exists with a connection state of Approved.\nEnsure a private endpoint connection is returned with a\nWorkspaces should use private link'",
    "remediation": "Remediate from Azure Portal\n1. Go to Azure Databricks.\n2. Click the name of a workspace.\n3. Under Settings, click Networking.\n4. Click Private endpoint connections.\n5. Click + Private endpoint.\n6. Under Project details, select a Subscription and a Resource group.\n7. Under Instance details, provide a Name, Network Interface Name, and\nselect a Region.\n8. Click Next : Resource >.\n9. Select a Target sub-resource.\n10. Click Next : Virtual Network >.\n11. Under Networking, select a Virtual network and a Subnet.\n12. Optionally, configure Private IP configuration and Application security\ngroup.\n13. Click Next : DNS >.\n14. Optionally, configure Private DNS integration.\n15. Click Next : Tags >.\n16. Optionally, configure tags.\n17. Click Next : Review + create >.\n18. Click Create.\n19. Repeat steps 1-18 for each workspace requiring remediation.\nRemediate from Azure CLI\nFor each workspace requiring remediation, run the following command to create a\nprivate endpoint connection:\naz network private-endpoint create --resource-group <resource-group> --name\n<private-endpoint> --location <location> --vnet-name <virtual-network> --\nsubnet <subnet> --private-connection-resource-id <workspace> --connection-\nname <private-endpoint-connection> --group-id <browser_authentication|\ndatabricks_ui_api>",
    "default_value": "Private endpoints are not configured for Azure Databricks workspaces by default.",
    "additional_information": "This recommendation is based on the Common Reference Recommendation Ensure\nPrivate Endpoints are used to access {service}, from the Common Reference\nRecommendations > Networking > Private Endpoints section.",
    "detection_commands": [
      "az databricks workspace list",
      "az databricks workspace show --resource-group <resource-group> --name",
      "Get-AzDatabricksWorkspace",
      "$workspace = Get-AzDatabricksWorkspace -ResourceGroupName <resource-group> -",
      "$workspace.PrivateEndpointConnection | Select-Object -Property"
    ],
    "remediation_commands": [
      "select a Region.",
      "az network private-endpoint create --resource-group <resource-group> --name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-",
      "us/azure/databricks/security/network/classic/private-link",
      "2. https://learn.microsoft.com/en-us/cli/azure/databricks/workspace",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.databricks"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 60,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "3.1.1",
    "title": "Ensure only MFA enabled identities can access privileged Virtual Machine",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "compute",
    "domain": "Compute Services",
    "subdomain": "Virtual Machines",
    "description": "Verify identities without MFA that can log in to a privileged virtual machine using\nseparate login credentials. An adversary can leverage the access to move laterally and\nperform actions with the virtual machine's managed identity. Make sure the virtual\nmachine only has necessary permissions, and revoke the admin-level permissions\naccording to the principle of least privilege.",
    "rationale": "Integrating multi-factor authentication (MFA) as part of the organizational policy can\ngreatly reduce the risk of an identity gaining control of valid credentials that may be\nused for additional tactics such as initial access, lateral movement, and collecting\ninformation. MFA can also be used to restrict access to cloud resources and APIs.\nAn Adversary may log into accessible cloud services within a compromised environment\nusing Valid Accounts that are synchronized to move laterally and perform actions with\nthe virtual machine's managed identity. The adversary may then perform management\nactions or access cloud-hosted resources as the logged-on managed identity.",
    "impact": "This recommendation requires the Entra ID P2 license to implement.\nEnsure that identities provisioned to a virtual machine utilize an RBAC/ABAC group and\nare allocated a role using Azure PIM, and that the role settings require MFA or use\nanother third-party PAM solution for accessing virtual machines.",
    "audit": "Audit from Azure Portal\n1. Log in to the Azure portal.\n2. Select the Subscription, then click on Access control (IAM).\n3. Click Role : All and click All to display the drop-down menu.\n4. Type Virtual Machine Administrator Login and select Virtual Machine\nAdministrator Login.\n5. Review the list of identities that have been assigned the Virtual Machine\nAdministrator Login role.\n6. Go to Microsoft Entra ID.\n7. For Per-user MFA:\na) Under Manage, click Users.\nb) Click Per-user MFA.\nc) Ensure that none of the identities assigned the Virtual Machine\nAdministrator Login role from step 4 have Status set to disabled.\n8. For Conditional Access:\na) Under Manage, click Security.\nb) Under Protect, click Conditional Access.\nc) Ensure that none of the identities assigned the Virtual Machine\nAdministrator Login role from step 4 are exempt from a Conditional\nAccess policy requiring MFA for all users.",
    "expected_response": "c) Ensure that none of the identities assigned the Virtual Machine",
    "remediation": "Remediate from Azure Portal\n1. Log in to the Azure portal.\n2. This can be remediated by enabling MFA for user, Removing user access or\nReducing access of managed identities attached to virtual machines.\nCase I : Enable MFA for users having access on virtual machines.\n1. Go to Microsoft Entra ID.\n2. For Per-user MFA:\n1. Under Manage, click Users.\n2. Click Per-user MFA.\n3. For each user requiring remediation, check the box next to their\nname.\n4. Click Enable MFA.\n5. Click Enable.\n3. For Conditional Access:\n1. Under Manage, click Security.\n2. Under Protect, click Conditional Access.\n3. Update the Conditional Access policy requiring MFA for all users,\nremoving each user requiring remediation from the Exclude list.\nCase II : Removing user access on a virtual machine.\n1. Select the Subscription, then click on Access control (IAM).\n2. Select Role assignments and search for Virtual Machine\nAdministrator Login or Virtual Machine User Login or any role\nthat provides access to log into virtual machines.\n3. Click on Role Name, Select Assignments, and remove identities with no\nMFA configured.\nCase III : Reducing access of managed identities attached to virtual machines.\n1. Select the Subscription, then click on Access control (IAM).\n2. Select Role Assignments from the top menu and apply filters on\nAssignment type as Privileged administrator roles and Type as\nVirtual Machines.\n3. Click on Role Name, Select Assignments, and remove identities access\nmake sure this follows the least privileges principal.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 67,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.1.1",
    "title": "Ensure that 'security defaults' is enabled in Microsoft Entra ID",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "description": "[IMPORTANT - Please read the section overview: If your organization pays for\nMicrosoft Entra ID licensing (included in Microsoft 365 E3, E5, F5, or Business\nPremium, and EM&S E3 or E5 licenses) and CAN use Conditional Access, ignore the\nrecommendations in this section and proceed to the Conditional Access section.]\nSecurity defaults in Microsoft Entra ID make it easier to be secure and help protect your\norganization. Security defaults contain preconfigured security settings for common\nattacks.\nSecurity defaults is available to everyone. The goal is to ensure that all organizations\nhave a basic level of security enabled at no extra cost. You may turn on security\ndefaults in the Azure portal.",
    "rationale": "Security defaults provide secure default settings that we manage on behalf of\norganizations to keep customers safe until they are ready to manage their own identity\nsecurity settings.\nFor example, doing the following:\n• Requiring all users and admins to register for MFA.\n• Challenging users with MFA - when necessary, based on factors such as\nlocation, device, role, and task.\n• Disabling authentication from legacy authentication clients, which can’t do MFA.",
    "impact": "This recommendation should be implemented initially and then may be overridden by\nother service/product specific CIS Benchmarks. Administrators should also be aware\nthat certain configurations in Microsoft Entra ID may impact other Microsoft services\nsuch as Microsoft 365.",
    "audit": "Audit from Azure Portal\nTo ensure security defaults is enabled in your directory:\n1. From Azure Home select the Portal Menu.\n2. Browse to Microsoft Entra ID > Properties.\n3. Select Manage security defaults.\n4. Under Security defaults, verify that Enabled (recommended) is selected.\nAudit from Powershell\nConnect-MgGraph -Scopes \"Policy.Read.All\"\n(Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy).IsEnabled\nReturned value should be true.\nAudit from Azure CLI\naz login\naz rest --method get --url\n'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcemen\ntPolicy' --query \"isEnabled\"\nReturned value should be true.",
    "expected_response": "To ensure security defaults is enabled in your directory:\nReturned value should be true.",
    "remediation": "Remediate from Azure Portal\nTo enable security defaults in your directory:\n1. From Azure Home select the Portal Menu.\n2. Browse to Microsoft Entra ID > Properties.\n3. Select Manage security defaults.\n4. Under Security defaults, select Enabled (recommended).\n5. Select Save.\nRemediate from Powershell\nConnect-MgGraph -Scopes \"Policy.ReadWrite.ApplicationConfiguration\"\nUpdate-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $true\n(Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy).IsEnabled\nRemediate from Azure CLI\naz rest --method patch --url\n'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcemen\ntPolicy' --body '{\"isEnabled\":true}'\naz rest --method get --url\n'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcemen\ntPolicy' --query \"isEnabled\"",
    "default_value": "If your tenant was created on or after October 22, 2019, security defaults may already\nbe enabled in your tenant.",
    "additional_information": "This recommendation differs from the Microsoft 365 Benchmark. This is because the\npotential impact associated with disabling Security Defaults is dependent upon the\nsecurity settings implemented in the environment. It is recommended that organizations\ndisabling Security Defaults implement appropriate security settings to replace the\nsettings configured by Security Defaults.",
    "detection_commands": [
      "Connect-MgGraph -Scopes \"Policy.Read.All\"",
      "az login az rest --method get --url 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcemen"
    ],
    "remediation_commands": [
      "Connect-MgGraph -Scopes \"Policy.ReadWrite.ApplicationConfiguration\" Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $true",
      "az rest --method patch --url 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcemen",
      "az rest --method get --url 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcemen"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults",
      "2. https://techcommunity.microsoft.com/t5/azure-active-directory-",
      "identity/introducing-security-defaults/ba-p/1061414",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-2-protect-identity-and-authentication-systems"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 73,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.2",
    "title": "Ensure that 'multifactor authentication' is 'enabled' for all users",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Establish Secure Configurations",
    "description": "[IMPORTANT - Please read the section overview: If your organization pays for\nMicrosoft Entra ID licensing (included in Microsoft 365 E3, E5, F5, or Business\nPremium, and EM&S E3 or E5 licenses) and CAN use Conditional Access, ignore the\nrecommendations in this section and proceed to the Conditional Access section.]\nEnable multifactor authentication for all users.\nNote: Since 2024, Azure has been rolling out mandatory multifactor authentication. For\nmore information:\n• https://azure.microsoft.com/en-us/blog/announcing-mandatory-multi-factor-\nauthentication-for-azure-sign-in\n• https://learn.microsoft.com/en-us/entra/identity/authentication/concept-\nmandatory-multifactor-authentication",
    "rationale": "Multifactor authentication requires an individual to present a minimum of two separate\nforms of authentication before access is granted. Multifactor authentication provides\nadditional assurance that the individual attempting to gain access is who they claim to\nbe. With multifactor authentication, an attacker would need to compromise at least two\ndifferent authentication mechanisms, increasing the difficulty of compromise and thus\nreducing the risk.",
    "impact": "Users would require two forms of authentication before any access is granted.\nAdditional administrative time will be required for managing dual forms of authentication\nwhen enabling multifactor authentication.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Users.\n3. Click Per-user MFA from the top menu.\n4. Ensure that Status is enabled for all users.\nAudit from PowerShell\nRun the following Graph PowerShell command:\nget-mguser -All | where {$_.StrongAuthenticationMethods.Count -eq 0} |\nSelect-Object -Property UserPrincipalName\nIf the output contains any UserPrincipalName, then this recommendation is non-\ncompliant.",
    "expected_response": "4. Ensure that Status is enabled for all users.\nIf the output contains any UserPrincipalName, then this recommendation is non-",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Users.\n3. Click Per-user MFA from the top menu.\n4. Click the box next to a user with Status disabled.\n5. Click Enable MFA.\n6. Click Enable.\n7. Repeat steps 1-6 for each user requiring remediation.\nOther options within Azure Portal\n• https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-\nazure-mfa\n• https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-\nmfasettings\n• https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-\nrequire-mfa-admin\n• https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-\ngetstarted#enable-multi-factor-authentication-with-conditional-access",
    "default_value": "Multifactor authentication is not enabled for all users by default. Starting in 2024,\nmultifactor authentication is enabled for administrative accounts by default.",
    "detection_commands": [
      "get-mguser -All | where {$_.StrongAuthenticationMethods.Count -eq 0} | Select-Object -Property UserPrincipalName"
    ],
    "remediation_commands": [
      "azure-mfa"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-",
      "howitworks",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "mandatory-multifactor-authentication",
      "3. https://azure.microsoft.com/en-us/blog/announcing-mandatory-multi-factor-",
      "authentication-for-azure-sign-in/",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-4-authenticate-server-and-services"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 76,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "5.1.3",
    "title": "Ensure that 'Allow users to remember multifactor authentication on devices they trust' is disabled",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Require Multi-factor Authentication",
    "description": "[IMPORTANT - Please read the section overview: If your organization pays for\nMicrosoft Entra ID licensing (included in Microsoft 365 E3, E5, F5, or Business\nPremium, and EM&S E3 or E5 licenses) and CAN use Conditional Access, ignore the\nrecommendations in this section and proceed to the Conditional Access section.]\nDo not allow users to remember multi-factor authentication on devices.",
    "rationale": "Remembering Multi-Factor Authentication (MFA) for devices and browsers allows users\nto have the option to bypass MFA for a set number of days after performing a\nsuccessful sign-in using MFA. This can enhance usability by minimizing the number of\ntimes a user may need to perform two-step verification on the same device. However, if\nan account or device is compromised, remembering MFA for trusted devices may affect\nsecurity. Hence, it is recommended that users not be allowed to bypass MFA.",
    "impact": "For every login attempt, the user will be required to perform multi-factor authentication.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, click Users\n4. Click the Per-user MFA button on the top bar\n5. Click on Service settings\n6. Ensure that Allow users to remember multi-factor authentication on\ndevices they trust is not enabled",
    "expected_response": "6. Ensure that Allow users to remember multi-factor authentication on",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, click Users\n4. Click the Per-user MFA button on the top bar\n5. Click on Service settings\n6. Uncheck the box next to Allow users to remember multi-factor\nauthentication on devices they trust\n7. Click Save",
    "default_value": "By default, Allow users to remember multi-factor authentication on\ndevices they trust is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-",
      "mfasettings#remember-multi-factor-authentication-for-devices-that-users-trust",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-",
      "identity-management#im-4-use-strong-authentication-controls-for-all-azure-",
      "active-directory-based-access",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-6-use-strong-authentication-controls"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 79,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.2.1",
    "title": "Ensure that 'trusted locations' are defined",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Conditional Access",
    "description": "Microsoft Entra ID Conditional Access allows an organization to configure Named\nlocations and configure whether those locations are trusted or untrusted. These\nsettings provide organizations the means to specify Geographical locations for use in\nconditional access policies, or define actual IP addresses and IP ranges and whether or\nnot those IP addresses and/or ranges are trusted by the organization.",
    "rationale": "Defining trusted source IP addresses or ranges helps organizations create and enforce\nConditional Access policies around those trusted or untrusted IP addresses and ranges.\nUsers authenticating from trusted IP addresses and/or ranges may have less access\nrestrictions or access requirements when compared to users that try to authenticate to\nMicrosoft Entra ID from untrusted locations or untrusted source IP addresses/ranges.\nNote on Assessment Status: Because the determination of entities to be included or\nexcluded is specific and unique to each organization, assessment status for this\nrecommendation is considered 'Manual' even though some elements for automation\n(CLI, PowerShell) are provided.",
    "impact": "When configuring Named locations, the organization can create locations using\nGeographical location data or by defining source IP addresses or ranges. Configuring\nNamed locations using a Country location does not provide the organization the ability\nto mark those locations as trusted, and any Conditional Access policy relying on those\nCountries location setting will not be able to use the All trusted locations\nsetting within the Conditional Access policy. They instead will have to rely on the\nSelect locations setting. This may add additional resource requirements when\nconfiguring and will require thorough organizational testing.\nIn general, Conditional Access policies may completely prevent users from\nauthenticating to Microsoft Entra ID, and thorough testing is recommended. To avoid\ncomplete lockout, a 'Break Glass' account with full Global Administrator rights is\nrecommended in the event all other administrators are locked out of authenticating to\nMicrosoft Entra ID. This 'Break Glass' account should be excluded from Conditional\nAccess Policies and should be configured with the longest pass phrase feasible in\naddition to a FIDO2 security key or certificate kept in a very secure physical location.\nThis account should only be used in the event of an emergency and complete\nadministrator lockout.\nNOTE: Starting July 2024, Microsoft will begin requiring MFA for All Users - including\nBreak Glass Accounts. Physical FIDO2 security keys, or a certificate kept on secure\nremovable storage can fulfill this MFA requirement. If opting for a physical device, that\ndevice should be kept in a very secure, documented physical location.",
    "audit": "Audit from Azure Portal\n1. In the Azure Portal, navigate to Microsoft Entra ID\n2. Under Manage, click Security\n3. Under Protect, click Conditional Access\n4. Under Manage, click Named locations\nEnsure there are IP ranges location settings configured and marked as Trusted\nAudit from PowerShell\nGet-MgIdentityConditionalAccessNamedLocation\nIn the output from the above command, for each Named location group, make sure at\nleast one entry contains the IsTrusted parameter with a value of True. Otherwise, if\nthere is no output as a result of the above command or all of the entries contain the\nIsTrusted parameter with an empty value, a NULL value, or a value of False, the\nresults are out of compliance with this check.",
    "expected_response": "Ensure there are IP ranges location settings configured and marked as Trusted\nIn the output from the above command, for each Named location group, make sure at\nthere is no output as a result of the above command or all of the entries contain the",
    "remediation": "Remediate from Azure Portal\n1. In the Azure Portal, navigate to Microsoft Entra ID\n2. Under Manage, click Security\n3. Under Protect, click Conditional Access\n4. Under Manage, click Named locations\n5. Within the Named locations blade, click on IP ranges location\n6. Enter a name for this location setting in the Name text box\n7. Click on the + sign\n8. Add an IP Address Range in CIDR notation inside the text box that appears\n9. Click on the Add button\n10. Repeat steps 7 through 9 for each IP Range that needs to be added\n11. If the information entered are trusted ranges, select the Mark as trusted\nlocation check box\n12. Once finished, click on Create\nRemediate from PowerShell\nCreate a new trusted IP-based Named location policy\n[System.Collections.Generic.List`1[Microsoft.Open.MSGraph.Model.IpRange]]$ipR\nanges = @()\n$ipRanges.Add(\"<first IP range in CIDR notation>\")\n$ipRanges.Add(\"<second IP range in CIDR notation>\")\n$ipRanges.Add(\"<third IP range in CIDR notation>\")\nNew-MgIdentityConditionalAccessNamedLocation -dataType\n\"#microsoft.graph.ipNamedLocation\" -DisplayName \"<name of IP Named location\npolicy>\" -IsTrusted $true -IpRanges $ipRanges\nSet an existing IP-based Named location policy to trusted\nUpdate-MgIdentityConditionalAccessNamedLocation -PolicyId \"<ID of the\npolicy>\" -dataType \"#microsoft.graph.ipNamedLocation\" -IsTrusted $true",
    "default_value": "By default, no locations are configured under the Named locations blade within the\nMicrosoft Entra ID Conditional Access blade.",
    "detection_commands": [
      "Get-MgIdentityConditionalAccessNamedLocation"
    ],
    "remediation_commands": [
      "Create a new trusted IP-based Named location policy",
      "$ipRanges.Add(\"<first IP range in CIDR notation>\") $ipRanges.Add(\"<second IP range in CIDR notation>\") $ipRanges.Add(\"<third IP range in CIDR notation>\") New-MgIdentityConditionalAccessNamedLocation -dataType \"#microsoft.graph.ipNamedLocation\" -DisplayName \"<name of IP Named location",
      "Update-MgIdentityConditionalAccessNamedLocation -PolicyId \"<ID of the"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "assignment-network",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-7-restrict-resource-access-based-on--conditions",
      "3. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/security-emergency-access"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 82,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2",
    "title": "Ensure that an exclusionary geographic Conditional Access policy is considered",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Maintain Standard Security Configurations for",
    "description": "CAUTION: If these policies are created without first auditing and testing the result,\nmisconfiguration can potentially lock out administrators or create undesired access\nissues.\nConditional Access Policies can be used to block access from geographic locations that\nare deemed out-of-scope for your organization or application. The scope and variables\nfor this policy should be carefully examined and defined.",
    "rationale": "Conditional Access, when used as a deny list for the tenant or subscription, is able to\nprevent ingress or egress of traffic to countries that are outside of the scope of interest\n(e.g.: customers, suppliers) or jurisdiction of an organization. This is an effective way to\nprevent unnecessary and long-lasting exposure to international threats such as APTs.\nNote on Assessment Status: Because the determination of entities to be included or\nexcluded is specific and unique to each organization, assessment status for this\nrecommendation is considered 'Manual' even though some elements for automation\n(CLI, PowerShell) are provided.",
    "impact": "Microsoft Entra ID P1 or P2 is required. Limiting access geographically will deny access\nto users that are traveling or working remotely in a different part of the world. A point-to-\nsite or site to site tunnel such as a VPN is recommended to address exceptions to\ngeographic access policies.",
    "audit": "Audit from Azure Portal\n1. From Azure Home open the Portal menu in the top left, and select Microsoft\nEntra ID.\n2. Scroll down in the menu on the left, and select Security.\n3. Select on the left side Conditional Access.\n4. Select Policies.\n5. Select the policy you wish to audit, then:\no Under Assignments > Users, review the users and groups for the\npersonnel the policy will apply to\no Under Assignments > Target resources, review the cloud apps or\nactions for the systems the policy will apply to\no Under Conditions > Locations, Review the Include locations for those\nthat should be blocked\no Under Conditions > Locations, Review the Exclude locations for those\nthat should be allowed (Note: locations set up in the previous\nrecommendation for Trusted Location should be in the Exclude list.)\no Under Access Controls > Grant - Confirm that Block access is\nselected.\nAudit from Azure CLI\nAs of this writing there are no subcommands for Conditional Access Policies\nwithin the Azure CLI\nAudit from PowerShell\n$conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy\nforeach($policy in $conditionalAccessPolicies) {$policy | Select-Object\n@{N='Policy ID'; E={$policy.id}}, @{N=\"Included Locations\";\nE={$policy.Conditions.Locations.IncludeLocations}}, @{N=\"Excluded Locations\";\nE={$policy.Conditions.Locations.ExcludeLocations}}, @{N=\"BuiltIn\nGrantControls\"; E={$policy.GrantControls.BuiltInControls}}}\nMake sure there is at least 1 row in the output of the above PowerShell command that\ncontains Block under the BuiltIn GrantControls column and location IDs under the\nIncluded Locations and Excluded Locations columns. If not, a policy containing\nthese options has not been created and is considered a finding.",
    "expected_response": "that should be blocked\nthat should be allowed (Note: locations set up in the previous\nrecommendation for Trusted Location should be in the Exclude list.)\nMake sure there is at least 1 row in the output of the above PowerShell command that",
    "remediation": "Remediate from Azure Portal\nPart 1 of 2 - Create the policy and enable it in Report-only mode.\n1. From Azure Home open the portal menu in the top left, and select Microsoft\nEntra ID.\n2. Scroll down in the menu on the left, and select Security.\n3. Select on the left side Conditional Access.\n4. Select Policies.\n5. Click the + New policy button, then:\n6. Provide a name for the policy.\n7. Under Assignments, select Users then:\no Under Include, select All users\no Under Exclude, check Users and groups and only select emergency\naccess accounts and service accounts (NOTE: Service accounts are\nexcluded here because service accounts are non-interactive and cannot\ncomplete MFA)\n8. Under Assignments, select Target resources then:\no Under Include, select All cloud apps\no Leave Exclude blank unless you have a well defined exception\n9. Under Conditions, select Locations then:\no Select Include, then add entries for locations for those that should be\nblocked\no Select Exclude, then add entries for those that should be allowed\n(IMPORTANT: Ensure that all Trusted Locations are in the Exclude list.)\n10. Under Access Controls, select Grant select Block Access.\n11. Set Enable policy to Report-only.\n12. Click Create.\nAllow some time to pass to ensure the sign-in logs capture relevant conditional access\nevents. These events will need to be reviewed to determine if additional considerations\nare necessary for your organization (e.g. legitimate locations are being blocked and\ninvestigation is needed for exception).\nNOTE: The policy is not yet 'live,' since Report-only is being used to audit the effect of\nthe policy.\nPart 2 of 2 - Confirm that the policy is not blocking access that should be granted, then\ntoggle to On.\n1. With your policy now in report-only mode, return to the Microsoft Entra blade and\nclick on Sign-in logs.\n2. Review the recent sign-in events - click an event then review the event details\n(specifically the Report-only tab) to ensure:\no The sign-in event you're reviewing occurred after turning on the policy in\nreport-only mode\no The policy name from step 6 above is listed in the Policy Name column\no The Result column for the new policy shows that the policy was Not\napplied (indicating the location origin was not blocked)\n3. If the above conditions are present, navigate back to the policy name in\nConditional Access and open it.\n4. Toggle the policy from Report-only to On.\n5. Click Save.\nRemediate from PowerShell\nFirst, set up the conditions objects values before updating an existing conditional\naccess policy or before creating a new one. You may need to use additional PowerShell\ncmdlets to retrieve specific IDs such as the Get-\nMgIdentityConditionalAccessNamedLocation which outputs the Location IDs for\nuse with conditional access policies.\n$conditions = New-Object -TypeName\nMicrosoft.Open.MSGraph.Model.ConditionalAccessConditionSet\n$conditions.Applications = New-Object -TypeName\nMicrosoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition\n$conditions.Applications.IncludeApplications = <\"All\" | \"Office365\" | \"app\nID\" | @(\"app ID 1\", \"app ID 2\", etc...>\n$conditions.Applications.ExcludeApplications = <\"Office365\" | \"app ID\" |\n@(\"app ID 1\", \"app ID 2\", etc...)>\n$conditions.Users = New-Object -TypeName\nMicrosoft.Open.MSGraph.Model.ConditionalAccessUserCondition\n$conditions.Users.IncludeUsers = <\"All\" | \"None\" | \"GuestsOrExternalUsers\" |\n\"Specific User ID\" | @(\"User ID 1\", \"User ID 2\", etc.)>\n$conditions.Users.ExcludeUsers = <\"GuestsOrExternalUsers\" | \"Specific User\nID\" | @(\"User ID 1\", \"User ID 2\", etc.)>\n$conditions.Users.IncludeGroups = <\"group ID\" | \"All\" | @(\"Group ID 1\",\n\"Group ID 2\", etc...)>\n$conditions.Users.ExcludeGroups = <\"group ID\" | @(\"Group ID 1\", \"Group ID 2\",\netc...)>\n$conditions.Users.IncludeRoles = <\"Role ID\" | \"All\" | @(\"Role ID 1\", \"Role ID\n2\", etc...)>\n$conditions.Users.ExcludeRoles = <\"Role ID\" | @(\"Role ID 1\", \"Role ID 2\",\netc...)>\n$conditions.Locations = New-Object -TypeName\nMicrosoft.Open.MSGraph.Model.ConditionalAccessLocationCondition\n$conditions.Locations.IncludeLocations = <\"Location ID\" | @(\"Location ID 1\",\n\"Location ID 2\", etc...) >\n$conditions.Locations.ExcludeLocations = <\"AllTrusted\" | \"Location ID\" |\n@(\"Location ID 1\", \"Location ID 2\", etc...)>\n$controls = New-Object -TypeName\nMicrosoft.Open.MSGraph.Model.ConditionalAccessGrantControls\n$controls._Operator = \"OR\"\n$controls.BuiltInControls = \"block\"\nNext, update the existing conditional access policy with the condition set options\nconfigured with the previous commands.\nUpdate-MgIdentityConditionalAccessPolicy -PolicyId <policy ID> -Conditions\n$conditions -GrantControls $controls\nTo create a new conditional access policy that complies with this best practice, run the\nfollowing commands after creating the condition set above\nNew-MgIdentityConditionalAccessPolicy -Name \"Policy Name\" -State\n<enabled|disabled> -Conditions $conditions -GrantControls $controls",
    "default_value": "This policy does not exist by default.",
    "additional_information": "These policies should be tested by using the What If tool in the References. Setting\nthese can and will create issues with logging in for users until they use an MFA device\nlinked to their accounts. Further testing can also be done via the insights and reporting\nresource in References which monitors Azure sign ins.",
    "detection_commands": [
      "$conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy"
    ],
    "remediation_commands": [
      "use with conditional access policies. $conditions = New-Object -TypeName",
      "$conditions.Applications = New-Object -TypeName",
      "$conditions.Applications.IncludeApplications = <\"All\" | \"Office365\" | \"app",
      "$conditions.Applications.ExcludeApplications = <\"Office365\" | \"app ID\" |",
      "$conditions.Users = New-Object -TypeName",
      "$conditions.Users.IncludeUsers = <\"All\" | \"None\" | \"GuestsOrExternalUsers\" | \"Specific User ID\" | @(\"User ID 1\", \"User ID 2\", etc.)> $conditions.Users.ExcludeUsers = <\"GuestsOrExternalUsers\" | \"Specific User",
      "$conditions.Users.IncludeGroups = <\"group ID\" | \"All\" | @(\"Group ID 1\", \"Group ID 2\", etc...)> $conditions.Users.ExcludeGroups = <\"group ID\" | @(\"Group ID 1\", \"Group ID 2\",",
      "$conditions.Users.IncludeRoles = <\"Role ID\" | \"All\" | @(\"Role ID 1\", \"Role ID",
      "$conditions.Users.ExcludeRoles = <\"Role ID\" | @(\"Role ID 1\", \"Role ID 2\",",
      "$conditions.Locations = New-Object -TypeName",
      "$conditions.Locations.IncludeLocations = <\"Location ID\" | @(\"Location ID 1\", \"Location ID 2\", etc...) > $conditions.Locations.ExcludeLocations = <\"AllTrusted\" | \"Location ID\" |",
      "$controls = New-Object -TypeName",
      "$controls._Operator = \"OR\" $controls.BuiltInControls = \"block\"",
      "Update-MgIdentityConditionalAccessPolicy -PolicyId <policy ID> -Conditions $conditions -GrantControls $controls",
      "New-MgIdentityConditionalAccessPolicy -Name \"Policy Name\" -State"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-",
      "by-location",
      "2. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-report-only",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-7-restrict-resource-access-based-on--conditions"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 86,
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
    "cis_id": "5.2.3",
    "title": "Ensure that an exclusionary device code flow policy is considered",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Maintain an Inventory of Network Boundaries",
    "description": "Conditional Access Policies can be used to prevent the Device code authentication flow.\nDevice code flow should be permitted only for users that regularly perform duties that\nexplicitly require the use of Device Code to authenticate, such as utilizing Azure with\nPowerShell.",
    "rationale": "Attackers use Device code flow in phishing attacks and, if successful, results in the\nattacker gaining access tokens and refresh tokens which are scoped to\n\"user_impersonation\", which can perform any action the user has permission to\nperform.",
    "impact": "Microsoft Entra ID P1 or P2 is required.\nThis policy should be tested using the Report-only mode before implementation.\nWithout a full and careful understanding of the accounts and personnel who require\nDevice code authentication flow, implementing this policy can block authentication for\nusers and devices who rely on Device code flow. For users and devices that rely on\ndevice code flow authentication, more secure alternatives should be implemented\nwherever possible.",
    "audit": "Audit from Azure Portal\n1. From Azure Home open the Portal menu in the top left and select Microsoft\nEntra ID.\n2. Scroll down in the menu on the left and select Security.\n3. Select on the left side Conditional Access.\n4. Select Policies.\n5. Select the policy you wish to audit, then:\no Under Assignments > Users, review the users and groups for the\npersonnel the policy will apply to\no Under Assignments > Target resources, review the cloud apps or\nactions for the systems the policy will apply to\no Under Conditions > Authentication Flows, review the configuration to\nensure Device code flow is selected\no Under Access Controls > Grant - Confirm that Block access is\nselected.",
    "expected_response": "ensure Device code flow is selected",
    "remediation": "Remediate from Azure Portal\nPart 1 of 2 - Create the policy and enable it in Report-only mode.\n1. From Azure Home open the portal menu in the top left and select Microsoft\nEntra ID.\n2. Scroll down in the menu on the left and select Security.\n3. Select on the left side Conditional Access.\n4. Select Policies.\n5. Click the + New policy button, then:\n6. Provide a name for the policy.\n7. Under Assignments, select Users then:\no Under Include, select All users\no Under Exclude, check Users and groups and only select emergency\naccess accounts\n8. Under Assignments, select Target resources then:\no Under Include, select All cloud apps\no Leave Exclude blank unless you have a well defined exception\n9. Under Conditions > Authentication Flows, set Configure to Yes then:\no Select Device code flow\no Select Done\n10. Under Access Controls > Grant, select Block Access.\n11. Set Enable policy to Report-only.\n12. Click Create.\nAllow some time to pass to ensure the sign-in logs capture relevant conditional access\nevents. These events will need to be reviewed to determine if additional considerations\nare necessary for your organization (e.g. many legitimate use cases of device code\nauthentication are observed).\nNOTE: The policy is not yet 'live,' since Report-only is being used to audit the effect of\nthe policy.\nPart 2 of 2 - Confirm that the policy is not blocking access that should be granted, then\ntoggle to On.\n1. With your policy now in report-only mode, return to the Microsoft Entra blade and\nclick on Sign-in logs.\n2. Review the recent sign-in events - click an event then review the event details\n(specifically the Report-only tab) to ensure:\no The sign-in event you're reviewing occurred after turning on the policy in\nreport-only mode\no The policy name from step 6 above is listed in the Policy Name column\no The Result column for the new policy shows that the policy was Not\napplied (indicating the device code authentication flow was not blocked)\n3. If the above conditions are present, navigate back to the policy name in\nConditional Access and open it.\n4. Toggle the policy from Report-only to On.\n5. Click Save.",
    "default_value": "This policy does not exist by default.",
    "additional_information": "These policies should be tested by using the What If tool in the References. Setting\nthese can and will create issues with logging in for users until they use an MFA device\nlinked to their accounts. Further testing can also be done via the insights and reporting\nresource in References which monitors Azure sign ins.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "authentication-flows#device-code-flow",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-7-restrict-resource-access-based-on--conditions",
      "3. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-report-only",
      "4. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-",
      "authentication-flows"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 91,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.4",
    "title": "Ensure that a multifactor authentication policy exists for all users",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "A Conditional Access policy can be enabled to ensure that users are required to use\nMultifactor Authentication (MFA) to login.\nNote: Since 2024, Azure has been rolling out mandatory multifactor authentication. For\nmore information:\n• https://azure.microsoft.com/en-us/blog/announcing-mandatory-multi-factor-\nauthentication-for-azure-sign-in\n• https://learn.microsoft.com/en-us/entra/identity/authentication/concept-\nmandatory-multifactor-authentication",
    "rationale": "Multifactor authentication is strongly recommended to increase the confidence that a\nclaimed identity can be proven to be the subject of the identity. This results in a stronger\nauthentication chain and reduced likelihood of exploitation.",
    "impact": "There is an increased cost associated with Conditional Access policies because of the\nrequirement of Microsoft Entra ID P1 or P2 licenses. Additional support overhead may\nalso need to be considered.",
    "audit": "Audit from Azure Portal\n1. From Azure Home open the Portal Menu in the top left, and select Microsoft\nEntra ID.\n2. Scroll down in the menu on the left, and select Security.\n3. Select on the left side Conditional Access.\n4. Select Policies.\n5. Select the policy you wish to audit.\n6. Click the blue text under Users.\n7. Under Include ensure that All Users is specified.\n8. Under Exclude ensure that no users or groups are specified. If there are users or\ngroups specified for exclusion, a very strong justification should exist for each\nexception, and all excepted account-level objects should be recorded in\ndocumentation along with the justification for comparison in future audits.",
    "expected_response": "7. Under Include ensure that All Users is specified.\n8. Under Exclude ensure that no users or groups are specified. If there are users or\ngroups specified for exclusion, a very strong justification should exist for each\nexception, and all excepted account-level objects should be recorded in",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home open Portal menu in the top left, and select Microsoft Entra\nID.\n2. Select Security.\n3. Select Conditional Access.\n4. Select Policies.\n5. Click + New policy.\n6. Enter a name for the policy.\n7. Click the blue text under Users.\n8. Under Include, select All users.\n9. Under Exclude, check Users and groups.\n10. Select users this policy should not apply to and click Select.\n11. Click the blue text under Target resources.\n12. Select All cloud apps.\n13. Click the blue text under Grant.\n14. Under Grant access, check Require multifactor authentication and click\nSelect.\n15. Set Enable policy to Report-only.\n16. Click Create.\nAfter testing the policy in report-only mode, update the Enable policy setting from\nReport-only to On.",
    "default_value": "Starting October 2024, MFA will be required for all accounts by default.",
    "additional_information": "These policies should be tested by using the What If tool in the References. Setting\nthese can and will create issues with logging in for users until they use an MFA device\nlinked to their accounts. Further testing can also be done via the insights and reporting\nresource in the References which monitors Azure sign ins.",
    "detection_commands": [],
    "remediation_commands": [
      "Select."
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-",
      "users-mfa-strength",
      "2. https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-",
      "conditional-access-what-if",
      "3. https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-",
      "conditional-access-insights-reporting",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-7-restrict-resource-access-based-on--conditions"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 94,
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
    "cis_id": "5.2.5",
    "title": "Ensure that multifactor authentication is required for risky sign-ins",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Require Multi-factor Authentication",
    "description": "Entra ID tracks the behavior of sign-in events. If the Entra ID domain is licensed with\nP2, the sign-in behavior can be used as a detection mechanism for additional scrutiny\nduring the sign-in event. If this policy is set up, then Risky Sign-in events will prompt\nusers to use multi-factor authentication (MFA) tokens on login for additional verification.",
    "rationale": "Enabling multi-factor authentication is a recommended setting to limit the potential of\naccounts being compromised and limiting access to authenticated personnel. Enabling\nthis policy allows Entra ID's risk-detection mechanisms to force additional scrutiny on\nthe login event, providing a deterrent response to potentially malicious sign-in events,\nand adding an additional authentication layer as a reaction to potentially malicious\nbehavior.",
    "impact": "Risk Policies for Conditional Access require Microsoft Entra ID P2. Additional overhead\nto support or maintain these policies may also be required if users lose access to their\nMFA tokens.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu in the top left and select Microsoft\nEntra ID.\n2. Select Security.\n3. Select on the left side Conditional Access.\n4. Select Policies.\n5. Select the policy you wish to audit.\n6. Click the blue text under Users.\n7. View under Include the corresponding users and groups to whom the policy is\napplied.\n8. View under Exclude to determine which users and groups to whom the policy is\nnot applied.",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu in the top left and select Microsoft\nEntra ID.\n2. Select Security\n3. Select Conditional Access.\n4. Select Policies.\n5. Click + New policy.\n6. Enter a name for the policy.\n7. Click the blue text under Users.\n8. Under Include, select All users.\n9. Under Exclude, check Users and groups.\n10. Select users this policy should not apply to and click Select.\n11. Click the blue text under Target resources.\n12. Select All cloud apps.\n13. Click the blue text under Conditions.\n14. Select Sign-in risk.\n15. Update the Configure toggle to Yes.\n16. Check the sign-in risk level this policy should apply to, e.g. High and Medium.\n17. Select Done.\n18. Click the blue text under Grant and check Require multifactor\nauthentication then click the Select button.\n19. Click the blue text under Session then check Sign-in frequency and select\nEvery time and click the Select button.\n20. Set Enable policy to Report-only.\n21. Click Create.\nAfter testing the policy in report-only mode, update the Enable policy setting from\nReport-only to On.",
    "default_value": "MFA is not enabled by default.",
    "additional_information": "These policies should be tested by using the What If tool in the References. Setting\nthese can and will create issues with logging in for users until they use an MFA device\nlinked to their accounts. Further testing can also be done via the insights and reporting\nresource the in References which monitors Azure sign ins.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-",
      "based-sign-in",
      "2. https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-",
      "conditional-access-what-if",
      "3. https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-",
      "conditional-access-insights-reporting",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-7-restrict-resource-access-based-on--conditions",
      "5. https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-",
      "protection#license-requirements"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 97,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.6",
    "title": "Ensure that multifactor authentication is required for Windows Azure Service Management API",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Require Multi-factor Authentication",
    "description": "This recommendation ensures that users accessing the Windows Azure Service\nManagement API (i.e. Azure Powershell, Azure CLI, Azure Resource Manager API,\netc.) are required to use multi-factor authentication (MFA) credentials when accessing\nresources through the Windows Azure Service Management API.",
    "rationale": "Administrative access to the Windows Azure Service Management API should be\nsecured with a higher level of scrutiny to authenticating mechanisms. Enabling multi-\nfactor authentication is recommended to reduce the potential for abuse of Administrative\nactions, and to prevent intruders or compromised admin credentials from changing\nadministrative settings.\nIMPORTANT: While this recommendation allows exceptions to specific Users or\nGroups, they should be very carefully tracked and reviewed for necessity on a regular\ninterval through an Access Review process. It is important that this rule be built to\ninclude \"All Users\" to ensure that all users not specifically excepted will be required to\nuse MFA to access the Azure Service Management API.",
    "impact": "Conditional Access policies require Microsoft Entra ID P1 or P2 licenses. Similarly, they\nmay require additional overhead to maintain if users lose access to their MFA. Any\nusers or groups which are granted an exception to this policy should be carefully\ntracked, be granted only minimal necessary privileges, and conditional access\nexceptions should be regularly reviewed or investigated.",
    "audit": "Audit from Azure Portal\n1. From the Azure Admin Portal dashboard, open Microsoft Entra ID.\n2. In the menu on the left of the Entra ID blade, click Security.\n3. In the menu on the left of the Security blade, click Conditional Access.\n4. In the menu on the left of the Conditional Access blade, click Policies.\n5. Click on the name of the policy you wish to audit.\n6. Click the blue text under Users.\n7. Under the Include section of Users, ensure that All Users is selected.\n8. Under the Exclude section of Users, review the Users and Groups that are\nexcluded from the policy (NOTE: this should be limited to break-glass emergency\naccess accounts, non-interactive service accounts, and other carefully\nconsidered exceptions).\n9. On the left side, click the blue text under Target resources.\n10. Under the Include section of Target Resources, ensure that the Select apps\nradio button is selected.\n11. Under Select, ensure that Windows Azure Service Management API is listed.",
    "expected_response": "7. Under the Include section of Users, ensure that All Users is selected.\nexcluded from the policy (NOTE: this should be limited to break-glass emergency\n10. Under the Include section of Target Resources, ensure that the Select apps\n11. Under Select, ensure that Windows Azure Service Management API is listed.",
    "remediation": "Remediate from Azure Portal\n1. From the Azure Admin Portal dashboard, open Microsoft Entra ID.\n2. Click Security in the Entra ID blade.\n3. Click Conditional Access in the Security blade.\n4. Click Policies in the Conditional Access blade.\n5. Click + New policy.\n6. Enter a name for the policy.\n7. Click the blue text under Users.\n8. Under Include, select All users.\n9. Under Exclude, check Users and groups.\n10. Select users or groups to be exempted from this policy (e.g. break-glass\nemergency accounts, and non-interactive service accounts) then click the\nSelect button.\n11. Click the blue text under Target resources.\n12. Under Include, click the Select apps radio button.\n13. Click the blue text under Select.\n14. Check the box next to Windows Azure Service Management APIs then click\nthe Select button.\n15. Click the blue text under Grant.\n16. Under Grant access check the box for Require multi-factor\nauthentication then click the Select button.\n17. Before creating, set Enable policy to Report-only.\n18. Click Create.\nAfter testing the policy in report-only mode, update the Enable policy setting from\nReport-only to On.",
    "default_value": "MFA is not enabled by default for administrative actions.",
    "additional_information": "These policies should be tested by using the What If tool in the References. Setting\nthese can and will create issues with administrators changing settings until they use an\nMFA device linked to their accounts. An emergency access account is recommended\nfor this eventuality if all administrators are locked out. Please see the documentation in\nthe references for further information. Similarly further testing can also be done via the\ninsights and reporting resource in References which monitors Azure sign ins.",
    "detection_commands": [],
    "remediation_commands": [
      "Select button."
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-7-restrict-resource-access-based-on--conditions",
      "2. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-users-groups",
      "3. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-",
      "require-mfa-azure-mgmt",
      "4. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-cloud-apps#windows-azure-service-management-api"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 100,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.7",
    "title": "Ensure that multifactor authentication is required to access Microsoft Admin Portals",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Use Multifactor Authentication For All Administrative",
    "description": "This recommendation ensures that users accessing Microsoft Admin Portals (i.e.\nMicrosoft 365 Admin, Microsoft 365 Defender, Exchange Admin Center, Azure Portal,\netc.) are required to use multi-factor authentication (MFA) credentials when logging into\nan Admin Portal.",
    "rationale": "Administrative Portals for Microsoft Azure should be secured with a higher level of\nscrutiny to authenticating mechanisms. Enabling multi-factor authentication is\nrecommended to reduce the potential for abuse of Administrative actions, and to\nprevent intruders or compromised admin credentials from changing administrative\nsettings.\nIMPORTANT: While this recommendation allows exceptions to specific Users or\nGroups, they should be very carefully tracked and reviewed for necessity on a regular\ninterval through an Access Review process. It is important that this rule be built to\ninclude \"All Users\" to ensure that all users not specifically excepted will be required to\nuse MFA to access Admin Portals.",
    "impact": "Conditional Access policies require Microsoft Entra ID P1 or P2 licenses. Similarly, they\nmay require additional overhead to maintain if users lose access to their MFA. Any\nusers or groups which are granted an exception to this policy should be carefully\ntracked, be granted only minimal necessary privileges, and conditional access\nexceptions should be reviewed or investigated.",
    "audit": "Audit from Azure Portal\n1. From the Azure Admin Portal dashboard, open Microsoft Entra ID.\n2. In the menu on the left of the Entra ID blade, click Security.\n3. In the menu on the left of the Security blade, click Conditional Access.\n4. In the menu on the left of the Conditional Access blade, click Policies.\n5. Click on the name of the policy you wish to audit.\n6. Click the blue text under Users.\n7. Under the Include section of Users, review Users and Groups to ensure that\nAll Users is selected.\n8. Under the Exclude section of Users, review the Users and Groups that are\nexcluded from the policy (NOTE: this should be limited to break-glass emergency\naccess accounts, non-interactive service accounts, and other carefully\nconsidered exceptions).\n9. On the left side, click the blue text under Target Resources.\n10. Under the Include section of Target resources, ensure the Select apps radio\nbutton is selected.\n11. Under Select, ensure Microsoft Admin Portals is listed.",
    "expected_response": "7. Under the Include section of Users, review Users and Groups to ensure that\nexcluded from the policy (NOTE: this should be limited to break-glass emergency\n10. Under the Include section of Target resources, ensure the Select apps radio\n11. Under Select, ensure Microsoft Admin Portals is listed.",
    "remediation": "Remediate from Azure Portal\n1. From the Azure Admin Portal dashboard, open Microsoft Entra ID.\n2. Click Security in the Entra ID blade.\n3. Click Conditional Access in the Security blade.\n4. Click Policies in the Conditional Access blade.\n5. Click + New policy.\n6. Enter a name for the policy.\n7. Click the blue text under Users.\n8. Under Include, select All users.\n9. Under Exclude, check Users and groups.\n10. Select users or groups to be exempted from this policy (e.g. break-glass\nemergency accounts, and non-interactive service accounts) then click the\nSelect button.\n11. Click the blue text under Target resources.\n12. Under Include, click the Select apps radio button.\n13. Click the blue text under Select.\n14. Check the box next to Microsoft Admin Portals then click the Select button.\n15. Click the blue text under Grant.\n16. Under Grant access check the box for Require multifactor\nauthentication then click the Select button.\n17. Before creating, set Enable policy to Report-only.\n18. Click Create.\nAfter testing the policy in report-only mode, update the Enable policy setting from\nReport-only to On.",
    "default_value": "MFA is not enabled by default for administrative actions.",
    "additional_information": "These policies should be tested by using the What If tool in the References. Setting\nthese can and will create issues with administrators changing settings until they use an\nMFA device linked to their accounts. An emergency access account is recommended\nfor this eventuality if all administrators are locked out. Please see the documentation in\nthe references for further information. Similarly further testing can also be done via the\ninsights and reporting resource in References which monitors Azure sign ins.",
    "detection_commands": [],
    "remediation_commands": [
      "Select button."
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-7-restrict-resource-access-based-on--conditions",
      "2. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-users-groups",
      "3. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-",
      "require-mfa-admin-portals"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 103,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.8",
    "title": "Ensure a Token Protection Conditional Access policy is considered",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Use Multifactor Authentication For All Administrative",
    "description": "This recommendation ensures that issued tokens are only issued to the intended\ndevice.",
    "rationale": "When properly configured, conditional access can aid in preventing attacks involving\ntoken theft, via hijacking or reply, as part of the attack flow. Although currently\nconsidered a rare event, the impact from token impersonation can be severe.",
    "impact": "A Microsoft Entra ID P1 or P2 license is required.\nStart with a Conditional Access policy in \"Report Only\" mode prior to enforcing for all\nusers.",
    "audit": "Audit from Azure Portal\n1. Sign in to the Microsoft Entra admin center as at least a Conditional Access\nAdministrator.\n2. Browse to Protection > Conditional Access > Policies.\n3. Review existing policies to ensure that at least one policy contains the following\nconfiguration:\n4. Under Assignments, review Users or workload identities and\no Under Include, ensure the scope of the users or groups is appropriate for\nyour organization\no Under Exclude, ensure only necessary users and groups (your\norganization's emergency access or break-glass accounts) are excepted.\n5. Under Target resources > Resources > Include > Select resources:\nEnsure that both Office 365 Exchange Online and Office 365 SharePoint\nOnline are selected.\n6. Under Conditions > Device Platforms: Ensure Configure is set to Yes and\nInclude indicates Windows platforms.\n7. Under Conditions > Client Apps: Ensure Configure is set to Yes and Mobile\nApps and Desktop Clients is selected under Modern Authentication Clients\n8. Under Access controls > Session, ensure that Require token protection\nfor sign-in sessions is selected.",
    "expected_response": "3. Review existing policies to ensure that at least one policy contains the following\no Under Include, ensure the scope of the users or groups is appropriate for\no Under Exclude, ensure only necessary users and groups (your\nEnsure that both Office 365 Exchange Online and Office 365 SharePoint\n6. Under Conditions > Device Platforms: Ensure Configure is set to Yes and\n7. Under Conditions > Client Apps: Ensure Configure is set to Yes and Mobile\n8. Under Access controls > Session, ensure that Require token protection",
    "remediation": "Remediate from Azure Portal\n1. Sign in to the Microsoft Entra admin center as at least a Conditional Access\nAdministrator.\n2. Browse to Protection > Conditional Access > Policies.\n3. Select New policy.\n4. Give your policy a name.\n5. Under Assignments, select Users or workload identities.\n1. Under Include, select the users or groups to apply this policy.\n2. Under Exclude, select Users and groups and choose your organization's\nemergency access or break-glass accounts (if applicable).\n6. Under Target resources > Resources > Include > Select resources\n1. Under Select, select the following applications:\n1. Office 365 Exchange Online\n2. Office 365 SharePoint Online\n2. Choose Select\n7. Under Conditions:\n1. Under Device platforms\n1. Set Configure to Yes.\n2. Include > Select device platforms > Windows.\n3. Select Done.\n2. Under Client apps:\n1. Set Configure to Yes\n2. Under Modern authentication clients, only select Mobile apps and\ndesktop clients.\n3. Select Done\n8. Under Access controls > Session, select Require token protection for\nsign-in sessions and select Select.\n9. Confirm your settings and set Enable policy to On.\n10. Select Create to enable your policy.",
    "default_value": "A Token Protection Conditional Access policy does not exist by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-",
      "protection",
      "2. https://www.microsoft.com/en-gb/security/business/microsoft-entra-pricing"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 106,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.3.1",
    "title": "Ensure that Azure admin accounts are not used for daily operations",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Periodic Identity Reviews",
    "description": "Microsoft Azure admin accounts should not be used for routine, non-administrative\ntasks.",
    "rationale": "Using admin accounts for daily operations increases the risk of accidental\nmisconfigurations and security breaches.",
    "impact": "Minor administrative overhead includes managing separate accounts, enforcing stricter\naccess controls, and potential licensing costs for advanced security features.",
    "audit": "Audit from Azure Portal\nMonitor:\n1. Go to Monitor.\n2. Click Activity log.\n3. Review the activity log and ensure that admin accounts are not being used for\ndaily operations.\nMicrosoft Entra ID:\n1. Go to Microsoft Entra ID.\n2. Under Monitoring, click Sign-in logs.\n3. Review the sign-in logs and ensure that admin accounts are not being accessed\nmore frequently than necessary.",
    "expected_response": "3. Review the activity log and ensure that admin accounts are not being used for\n3. Review the sign-in logs and ensure that admin accounts are not being accessed",
    "remediation": "If admin accounts are being used for daily operations, consider the following:\n• Monitor and alert on unusual activity.\n• Enforce the principle of least privilege.\n• Revoke any unnecessary administrative access.\n• Use Conditional Access to limit access to resources.\n• Ensure that administrators have separate admin and user accounts.\n• Use Microsoft Entra ID Protection to detect, investigate, and remediate identity-\nbased risks.\n• Use Privileged Identity Management (PIM) in Microsoft Entra ID to limit standing\nadministrator access to privileged roles, discover who has access, and review\nprivileged access.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/security/privileged-access-workstations/critical-",
      "impact-accounts"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 110,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "5.3.2",
    "title": "Ensure that guest users are reviewed on a regular basis",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "Microsoft Entra ID has native and extended identity functionality allowing you to invite\npeople from outside your organization to be guest users in your cloud account and sign\nin with their own work, school, or social identities.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Evaluating the appropriateness of guest users\nrequires a manual review, as it depends on the specific needs and context of each\norganization and environment.",
    "rationale": "Guest users are typically added outside your employee on-boarding/off-boarding\nprocess and could potentially be overlooked indefinitely. To prevent this, guest users\nshould be reviewed on a regular basis. During this audit, guest users should also be\ndetermined to not have administrative privileges.",
    "impact": "Before removing guest users, determine their use and scope. Like removing any user,\nthere may be unforeseen consequences to systems if an account is removed without\ncareful consideration.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Click on Add filter\n5. Select User type\n6. Select Guest from the Value dropdown\n7. Click Apply\n8. Audit the listed guest users\nAudit from Azure CLI\naz ad user list --query \"[?userType=='Guest']\"\nEnsure all users listed are still required and not inactive.\nAudit from Azure PowerShell\nGet-AzureADUser |Where-Object {$_.UserType -like \"Guest\"} |Select-Object\nDisplayName, UserPrincipalName, UserType -Unique\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: e9ac8f8e-ce22-4355-8f04-99b911d6be52 - Name: 'Guest accounts\nwith read permissions on Azure resources should be removed'\n• Policy ID: 94e1c2ac-cbbe-4cac-a2b5-389c812dee87 - Name: 'Guest accounts\nwith write permissions on Azure resources should be removed'\n• Policy ID: 339353f6-2387-4a45-abe4-7f529d121046 - Name: 'Guest accounts\nwith owner permissions on Azure resources should be removed'",
    "expected_response": "Ensure all users listed are still required and not inactive.\nwith read permissions on Azure resources should be removed'\nwith write permissions on Azure resources should be removed'\nwith owner permissions on Azure resources should be removed'",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Click on Add filter\n5. Select User type\n6. Select Guest from the Value dropdown\n7. Click Apply\n8. Check the box next to all Guest users that are no longer required or are inactive\n9. Click Delete\n10. Click OK\nRemediate from Azure CLI\nBefore deleting the user, set it to inactive using the ID from the Audit Procedure to\ndetermine if there are any dependent systems.\naz ad user update --id <exampleaccountid@domain.com> --account-enabled\n{false}\nAfter determining that there are no dependent systems, delete the user.\nRemove-AzureADUser -ObjectId <exampleaccountid@domain.com>\nRemediate from Azure PowerShell\nBefore deleting the user, set it to inactive using the ID from the Audit Procedure to\ndetermine if there are any dependent systems.\nSet-AzureADUser -ObjectId \"<exampleaccountid@domain.com>\" -AccountEnabled\nfalse\nAfter determining that there are no dependent systems, delete the user.\nPS C:\\>Remove-AzureADUser -ObjectId <exampleaccountid@domain.com>",
    "default_value": "By default no guest users are created.",
    "additional_information": "It is good practice to use a dynamic security group to manage guest users.\nTo create the dynamic security group:\n1. Navigate to the 'Microsoft Entra ID' blade in the Azure Portal\n2. Select the 'Groups' item\n3. Create new\n4. Type of 'dynamic'\n5. Use the following dynamic selection rule. \"(user.userType -eq \"Guest\")\"\n6. Once the group has been created, select access reviews option and create a\nnew access review with a period of monthly and send to relevant administrators\nfor review.",
    "detection_commands": [
      "az ad user list --query \"[?userType=='Guest']\"",
      "Get-AzureADUser |Where-Object {$_.UserType -like \"Guest\"} |Select-Object"
    ],
    "remediation_commands": [
      "az ad user update --id <exampleaccountid@domain.com> --account-enabled",
      "Remove-AzureADUser -ObjectId <exampleaccountid@domain.com>",
      "Set-AzureADUser -ObjectId \"<exampleaccountid@domain.com>\" -AccountEnabled"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/external-id/user-properties",
      "2. https://learn.microsoft.com/en-us/entra/fundamentals/how-to-create-delete-",
      "users#delete-a-user",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-4-review-and-reconcile-user-access-regularly",
      "4. https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing",
      "5. https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-",
      "inactive-user-accounts",
      "6. https://learn.microsoft.com/en-us/entra/fundamentals/users-restore"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 112,
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
    "cis_id": "5.3.3",
    "title": "Ensure that use of the 'User Access Administrator' role is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Disable Any Unassociated Accounts",
    "description": "The User Access Administrator role grants the ability to view all resources and manage\naccess assignments at any subscription or management group level within the tenant.\nDue to its high privilege level, this role assignment should be removed immediately after\ncompleting the necessary changes at the root scope to minimize security risks.",
    "rationale": "The User Access Administrator role provides extensive access control privileges.\nUnnecessary assignments heighten the risk of privilege escalation and unauthorized\naccess. Removing the role immediately after use minimizes security exposure.",
    "impact": "Increased administrative effort to manage and remove role assignments appropriately.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Subscriptions.\n3. Select a subscription.\n4. Select Access control (IAM).\n5. Look for the following banner at the top of the page: Action required: X\nusers have elevated access in your tenant. You should take\nimmediate action and remove all role assignments with elevated\naccess. If the banner is displayed, the User Access Administrator is\nassigned.\nAudit from Azure CLI\nRun the following command:\naz role assignment list --role \"User Access Administrator\" --scope \"/\"\nEnsure that the command does not return any User Access Administrator role\nassignment information.",
    "expected_response": "users have elevated access in your tenant. You should take\nEnsure that the command does not return any User Access Administrator role",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Subscriptions.\n3. Select a subscription.\n4. Select Access control (IAM).\n5. Look for the following banner at the top of the page: Action required: X\nusers have elevated access in your tenant. You should take\nimmediate action and remove all role assignments with elevated\naccess.\n6. Click View role assignments.\n7. Click Remove.\nRemediate from Azure CLI\nRun the following command:\naz role assignment delete --role \"User Access Administrator\" --scope \"/\"",
    "detection_commands": [
      "az role assignment list --role \"User Access Administrator\" --scope \"/\""
    ],
    "remediation_commands": [
      "az role assignment delete --role \"User Access Administrator\" --scope \"/\""
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles",
      "2. https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-",
      "access-global-admin"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 116,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.3.4",
    "title": "Ensure that all 'privileged' role assignments are periodically reviewed",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "description": "Periodic review of privileged role assignments is performed to ensure that the privileged\nroles assigned to users are accurate and appropriate.",
    "rationale": "Privileged roles are crown jewel assets that can be used by malicious insiders, threat\nactors, and even through mistake to significantly damage an organization in numerous\nways. These roles should be periodically reviewed to:\n• identify lingering permissions assignment (e.g. an administrator has been\nterminated, the administrator account is being retained, but the permissions are\nno longer necessary and has not been properly addressed by process)\n• detect lateral movement through privilege escalation (e.g. an account with\nadministrative permission has been compromised and is elevating other\naccounts in an attempt to circumvent detection mechanisms)",
    "impact": "Increased administrative effort to manage and remove role assignments appropriately.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Subscriptions.\n3. Select a subscription.\n4. Select Access control (IAM).\n5. Look for the number under the word Privileged accompanied by a link titled\nView Assignments. Click the View assignments link.\n6. For each privileged role listed, evaluate whether the assignment is appropriate\nand current for each User, Group, or App assigned to each privileged role.\nNOTE: The judgement of what constitutes 'appropriate and current' assignments\nrequires a clear understanding of your organization's personnel, systems, policy, and\nsecurity requirements. This cannot be effectively prescribed in procedure.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 118,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.3.5",
    "title": "Ensure disabled user accounts do not have read, write, or owner permissions",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "description": "Ensure that any roles granting read, write, or owner permissions are removed from\ndisabled Azure user accounts.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Removing role assignments from disabled user\naccounts depends on the context and requirements of each organization and\nenvironment.",
    "rationale": "Disabled accounts should not retain access to resources, as this poses a security risk.\nRemoving role assignments mitigates potential unauthorized access and enforces the\nprinciple of least privilege.",
    "impact": "Ensure disabled accounts are not relied on for break glass or automated processes\nbefore removing roles to avoid service disruption.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Users.\n3. Click Add filter.\n4. Click Account enabled.\n5. Click the toggle switch to set the value to No.\n6. Click Apply.\n7. Click the Display name of a disabled user account.\n8. Click Azure role assignments.\n9. Ensure that no read, write, or owner roles are assigned to the user account.\n10. Repeat steps 7-9 for each disabled user account.\nAudit from PowerShell\nRun the following command to connect to Microsoft Entra ID:\nConnect-AzureAD\nRun the following command to list users:\nGet-AzureADUser\nRun the following command to get a user:\n$user = Get-AzureADUser -ObjectId <object-id>\nRun the following command to get the AccountEnabled setting for the user:\n$user.AccountEnabled\nIf AccountEnabled is False, run the following command to get the role assignments for\nthe user:\nGet-AzRoleAssignment -ObjectId $user.ObjectId\nEnsure that no read, write, or owner roles are assigned to the user.\nRepeat for each user.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 0cfea604-3201-4e14-88fc-fae4c427a6c5 - Name: 'Blocked accounts\nwith owner permissions on Azure resources should be removed'\n• Policy ID: 8d7e1fde-fe26-4b5f-8108-f8e432cbc2be - Name: 'Blocked accounts\nwith read and write permissions on Azure resources should be removed'",
    "expected_response": "9. Ensure that no read, write, or owner roles are assigned to the user account.\nEnsure that no read, write, or owner roles are assigned to the user.\nwith owner permissions on Azure resources should be removed'\nwith read and write permissions on Azure resources should be removed'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Users.\n3. Click Add filter.\n4. Click Account enabled.\n5. Click the toggle switch to set the value to No.\n6. Click Apply.\n7. Click the Display name of a disabled user account with read, write, or owner\nroles assigned.\n8. Click Azure role assignments.\n9. Click the name of a read, write, or owner role.\n10. Click Assignments.\n11. Click Remove in the row for the disabled user account.\n12. Click Yes.\n13. Repeat steps 7-12 for disabled user accounts requiring remediation.\nRemediate from PowerShell\nFor each account requiring remediation, run the following command to remove an\nassigned role:\nRemove-AzRoleAssignment -ObjectId $user.ObjectId -RoleDefinitionName <role-\ndefinition-name>",
    "default_value": "Disabled user accounts retain their prior role assignments.",
    "detection_commands": [
      "Get-AzureADUser",
      "$user = Get-AzureADUser -ObjectId <object-id>",
      "$user.AccountEnabled",
      "Get-AzRoleAssignment -ObjectId $user.ObjectId"
    ],
    "remediation_commands": [
      "Remove-AzRoleAssignment -ObjectId $user.ObjectId -RoleDefinitionName <role-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azaduser",
      "2. https://learn.microsoft.com/en-us/powershell/module/az.resources/get-",
      "azroleassignment",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.resources/remove-",
      "azroleassignment"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 120,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": false
  },
  {
    "cis_id": "5.3.6",
    "title": "Ensure 'Tenant Creator' role assignments are periodically reviewed",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Establish and Maintain an Inventory of Accounts",
    "description": "Perform a periodic review of the Tenant Creator role assignment to ensure that the\nassignments are accurate and appropriate.\nThis recommendation should be applied alongside the recommendation \"Ensure that\n'Restrict non-admin users from creating tenants' is set to 'Yes'\".",
    "rationale": "Unnecessary assignments increase the risk of privilege escalation and unauthorized\naccess.",
    "impact": "Verify that the Tenant Creator role is no longer required by any assignments before\nremoval to avoid disruption of critical functions.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Roles and administrators.\n3. In the search bar, type Tenant Creator.\n4. Click the role.\n5. Review the assignments and ensure that they are appropriate.",
    "expected_response": "5. Review the assignments and ensure that they are appropriate.",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Manage, click Roles and administrators.\n3. In the search bar, type Tenant Creator.\n4. Click the role.\n5. Click the name of an assignment.\n6. Check the box next to the Tenant Creator role.\n7. Click X Remove assignments.\n8. Click Yes.\n9. Repeat steps 1-8 for each assignment requiring remediation.",
    "default_value": "The Tenant Creator role is not assigned by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/active-directory-b2c/tenant-management-",
      "check-tenant-creation-permission",
      "2. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference#tenant-creator"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 123,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.3.7",
    "title": "Ensure all non-privileged role assignments are periodically reviewed",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "Perform a periodic review of non-privileged role assignments to ensure that the non-\nprivileged roles assigned to users are appropriate.\nNote: Determining 'appropriate' assignments requires a clear understanding of your\norganization's personnel, systems, policies, and security requirements. This cannot be\neffectively prescribed in a procedure.",
    "rationale": "To ensure the principle of least privilege is followed, non-privileged role assignments\nshould be reviewed periodically to confirm that users are granted only the minimum\nlevel of permissions they need to perform their tasks.",
    "impact": "Increased administrative effort to manage and remove role assignments appropriately.",
    "audit": "Audit from Azure Portal\n1. Go to Subscriptions.\n2. Click the name of a subscription.\n3. Click Access control (IAM).\n4. Click Role assignments.\n5. Click Job function roles.\n6. For each role, ensure the assignments are appropriate.\n7. Repeat steps 1-6 for each subscription.",
    "expected_response": "6. For each role, ensure the assignments are appropriate.",
    "remediation": "Remediate from Azure Portal\n1. Go to Subscriptions.\n2. Click the name of a subscription.\n3. Click Access control (IAM).\n4. Click Role assignments.\n5. Click Job function roles.\n6. Check the box next to any inappropriate assignments.\n7. Click Delete.\n8. Click Yes.\n9. Repeat steps 1-8 for each subscription.",
    "default_value": "Users do not have non-privileged roles assigned to them by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/role-based-access-control/role-",
      "assignments"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 125,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.4",
    "title": "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "description": "Require administrators or appropriately delegated users to create new tenants.",
    "rationale": "It is recommended to only allow an administrator to create new tenants. This prevent\nusers from creating new Microsoft Entra ID or Azure AD B2C tenants and ensures that\nonly authorized users are able to do so.",
    "impact": "Enforcing this setting will ensure that only authorized users are able to create new\ntenants.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select User settings\n5. Ensure that Restrict non-admin users from creating tenants is set to\nYes\nAudit from PowerShell\nImport-Module Microsoft.Graph.Identity.SignIns\nConnect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'\nGet-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty\nDefaultUserRolePermissions | Format-List\nReview the \"DefaultUserRolePermissions\" section of the output. Ensure that\nAllowedToCreateTenants is not \"True\".",
    "expected_response": "5. Ensure that Restrict non-admin users from creating tenants is set to\nReview the \"DefaultUserRolePermissions\" section of the output. Ensure that",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select User settings\n5. Set Restrict non-admin users from creating tenants to Yes\n6. Click Save\nRemediate from PowerShell\nImport-Module Microsoft.Graph.Identity.SignIns\nConnect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'\nSelect-MgProfile -Name beta\n$params = @{\nDefaultUserRolePermissions = @{\nAllowedToCreateTenants = $false\n}\n}\nUpdate-MgPolicyAuthorizationPolicy -AuthorizationPolicyId  -BodyParameter\n$params",
    "detection_commands": [
      "Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization' Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty"
    ],
    "remediation_commands": [
      "Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization' Select-MgProfile -Name beta $params = @{",
      "Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId -BodyParameter $params"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions",
      "2. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference#tenant-creator",
      "3. https://blog.admindroid.com/disable-users-creating-new-azure-ad-tenants-in-",
      "microsoft-365/"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 127,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.5",
    "title": "Ensure that 'Number of methods required to reset' is set to '2'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Ensures that two alternate forms of identification are provided before allowing a\npassword reset.",
    "rationale": "A Self-service Password Reset (SSPR) through Azure Multi-factor Authentication (MFA)\nensures the user's identity is confirmed using two separate methods of identification.\nWith multiple methods set, an attacker would have to compromise both methods before\nthey could maliciously reset a user's password.",
    "impact": "There may be administrative overhead, as users who lose access to their secondary\nauthentication methods will need an administrator with permissions to remove it. There\nwill also need to be organization-wide security policies and training to teach\nadministrators to verify the identity of the requesting user so that social engineering\ncannot render this setting useless.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select Password reset\n5. Select Authentication methods\n6. Ensure that Number of methods required to reset is set to 2",
    "expected_response": "6. Ensure that Number of methods required to reset is set to 2",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select Password reset\n5. Select Authentication methods\n6. Set the Number of methods required to reset to 2\n7. Click Save",
    "default_value": "By default, the Number of methods required to reset is 1.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "registration-mfa-sspr-combined",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-6-use-strong-authentication-controls",
      "4. https://learn.microsoft.com/en-us/entra/identity/authentication/passwords-",
      "faq#password-reset-registration",
      "5. https://support.microsoft.com/en-us/account-billing/reset-your-work-or-school-",
      "password-using-security-info-23dde81f-08bb-4776-ba72-e6b72b9dda9e",
      "6. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-methods"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 129,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.6",
    "title": "Ensure that account 'Lockout threshold' is less than or equal to '10'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Require Multi-factor Authentication",
    "description": "The account lockout threshold determines how many failed login attempts are permitted\nprior to placing the account in a locked-out state and initiating a variable lockout\nduration.",
    "rationale": "Account lockout is a method of protecting against brute-force and password spray\nattacks. Once the lockout threshold has been exceeded, the account enters a locked-\nout state which prevents all login attempts for a variable duration. The lockout in\ncombination with a reasonable duration reduces the total number of failed login\nattempts that a malicious actor can execute in a given period of time.",
    "impact": "If account lockout threshold is set too low (less than 3), users may experience frequent\nlockout events and the resulting security alerts may contribute to alert fatigue.\nIf account lockout threshold is set too high (more than 10), malicious actors can\nprogrammatically execute more password attempts in a given period of time.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Security.\n4. Under Manage, select Authentication methods.\n5. Under Manage, select Password protection.\n6. Ensure that Lockout threshold is set to 10 or fewer.\nAudit from PowerShell\nConnect-MgGraph -Scopes \"Policy.ReadWrite.AuthenticationMethod\"\n$p = (Get-MgPolicyAuthenticationMethodsPolicy).PasswordProtection\nif ($p.LockoutThreshold -gt 10) {\nUpdate-MgPolicyAuthenticationMethodsPolicy -BodyParameter @{\npasswordProtection = @{\nlockoutThreshold = 10\nlockoutDuration = [Math]::Max($p.LockoutDuration, 60)\n}\n}\n}\nDisconnect-MgGraph\nAudit from Azure CLI\naz rest --method get \\\n--url\n'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' \\\n--query 'passwordProtection.lockoutThreshold'",
    "expected_response": "6. Ensure that Lockout threshold is set to 10 or fewer.",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Security.\n4. Under Manage, select Authentication methods.\n5. Under Manage, select Password protection.\n6. Set the Lockout threshold to 10 or fewer.\n7. Click Save.\nRemediate from PowerShell\nConnect-MgGraph -Scopes \"Policy.ReadWrite.AuthenticationMethod\"\nUpdate-MgPolicyAuthenticationMethodsPolicy -PasswordProtection @{\nLockoutThreshold = 10\nLockoutDuration = \"PT1M\"\n}\nRemediate from Azure CLI\naz rest --method patch \\\n--url\n'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' \\\n--headers 'Content-Type=application/json' \\\n--body\n'{\"passwordProtection\":{\"lockoutThreshold\":10,\"lockoutDuration\":\"PT1M\"}}'",
    "default_value": "By default, Lockout threshold is set to 10.",
    "additional_information": "NOTE: The variable number for failed login attempts allowed before lockout is\nprescribed by many security and compliance frameworks. The appropriate setting for\nthis variable should be determined by the most restrictive security or compliance\nframework that your organization follows.",
    "detection_commands": [
      "Connect-MgGraph -Scopes \"Policy.ReadWrite.AuthenticationMethod\" $p = (Get-MgPolicyAuthenticationMethodsPolicy).PasswordProtection",
      "Update-MgPolicyAuthenticationMethodsPolicy -BodyParameter @{",
      "az rest --method get --url 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' --query 'passwordProtection.lockoutThreshold'"
    ],
    "remediation_commands": [
      "Connect-MgGraph -Scopes \"Policy.ReadWrite.AuthenticationMethod\" Update-MgPolicyAuthenticationMethodsPolicy -PasswordProtection @{",
      "az rest --method patch --url 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' --headers 'Content-Type=application/json' --body '{\"passwordProtection\":{\"lockoutThreshold\":10,\"lockoutDuration\":\"PT1M\"}}'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-",
      "smart-lockout#manage-microsoft-entra-smart-lockout-values"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 131,
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
    "cis_id": "5.7",
    "title": "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Enforce Automatic Device Lockout on Portable End-",
    "description": "The account lockout duration value determines how long an account retains the status\nof lockout, and therefore how long before a user can continue to attempt to login after\npassing the lockout threshold.",
    "rationale": "Account lockout is a method of protecting against brute-force and password spray\nattacks. Once the lockout threshold has been exceeded, the account enters a locked-\nout state which prevents all login attempts for a variable duration. The lockout in\ncombination with a reasonable duration reduces the total number of failed login\nattempts that a malicious actor can execute in a given period of time.",
    "impact": "If account lockout duration is set too low (less than 60 seconds), malicious actors can\nperform more password spray and brute-force attempts over a given period of time.\nIf the account lockout duration is set too high (more than 300 seconds) users may\nexperience inconvenient delays during lockout.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Security.\n4. Under Manage, select Authentication methods.\n5. Under Manage, select Password protection.\n6. Ensure that Lockout duration in seconds is set to 60 or higher.",
    "expected_response": "6. Ensure that Lockout duration in seconds is set to 60 or higher.",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Security.\n4. Under Manage, select Authentication methods.\n5. Under Manage, select Password protection.\n6. Set the Lockout duration in seconds to 60 or higher.\n7. Click Save.",
    "default_value": "By default, Lockout duration in seconds is set to 60.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-",
      "smart-lockout#manage-microsoft-entra-smart-lockout-values"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 134,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "5.8",
    "title": "Ensure that a 'Custom banned password list' is set to 'Enforce'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Enforce Automatic Device Lockout on Portable End-",
    "description": "Microsoft Azure applies a default global banned password list to all user and admin\naccounts that are created and managed directly in Microsoft Entra ID.\nThe Microsoft Entra password policy does not apply to user accounts that are\nsynchronized from an on-premises Active Directory environment, unless Microsoft Entra\nID Connect is used and EnforceCloudPasswordPolicyForPasswordSyncedUsers is\nenabled.\nReview the Default Value section for more detail on the password policy.\nFor increased password security, a custom banned password list is recommended",
    "rationale": "Implementing a custom banned password list gives your organization further control\nover the password policy. Disallowing easy-to-guess passwords increases the security\nof your Azure resources.",
    "impact": "Increasing password complexity may increase user account administration overhead.\nUtilizing the default global banned password list and a custom list requires a Microsoft\nEntra ID P1 or P2 license. On-premises Active Directory Domain Services users who\naren't synchronized to Microsoft Entra ID still benefit from Microsoft Entra ID Password\nProtection based on the existing licensing of synchronized users.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Security.\n4. Under Manage, select Authentication methods.\n5. Under Manage, select Password protection.\n6. Ensure Enforce custom list is set to Yes.\n7. Review the list of words banned from use in passwords.",
    "expected_response": "6. Ensure Enforce custom list is set to Yes.",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Security.\n4. Under Manage, select Authentication methods.\n5. Under Manage, select Password protection.\n6. Set the Enforce custom list option to Yes.\n7. Click in the Custom banned password list text box.\n8. Add a list of words, one per line, to prevent users from using in passwords.\n9. Click Save.",
    "default_value": "By default the custom banned password list is not 'Enabled'. Organization-specific terms\ncan be added to the custom banned password list, such as the following examples:\n• Brand names\n• Product names\n• Locations, such as company headquarters\n• Company-specific terms\n• Abbreviations that have specific company meaning\n• Months and weekdays with your company's local languages\nThe default global banned password list is already applied to your resources which\napplies the following basic requirements:\nCharacters allowed:\n• Uppercase characters (A - Z)\n• Lowercase characters (a - z)\n• Numbers (0 - 9)\n• Symbols:\n• @ # $ % ^ & * - _ ! + = [ ] { } | \\ : ' , . ? / ` ~ \" ( ) ; < >\n• blank space\nCharacters not allowed:\n• Unicode characters\nPassword length:\nPasswords require:\n• A minimum of eight characters\n• A maximum of 256 characters\nPassword complexity:\nPasswords require three out of four of the following categories:\n• Uppercase characters\n• Lowercase characters\n• Numbers\n• Symbols\nNote: Password complexity check isn't required for Education tenants.\nPassword not recently used:\n• When a user changes or resets their password, the new password can't be the\nsame as the current or recently used passwords.\n• Password isn't banned by Entra ID Password Protection.\n• The password can't be on the global list of banned passwords for Azure AD\nPassword Protection, or on the customizable list of banned passwords specific to\nyour organization.\nEvaluation\nNew passwords are evaluated for strength and complexity by validating against the\ncombined list of terms from the global and custom banned password lists. Even if a\nuser's password contains a banned password, the password may be accepted if the\noverall password is otherwise strong enough.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-",
      "ban-bad-combined-policy",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-",
      "ban-bad",
      "3. https://learn.microsoft.com/en-us/powershell/module/azuread/",
      "4. https://www.microsoft.com/en-us/research/publication/password-guidance/",
      "5. https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-",
      "custom-password-protection",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-6-use-strong-authentication-controls"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 136,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.9",
    "title": "Ensure that 'Number of days before users are asked to re- confirm their authentication information' is not set to '0'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Use Unique Passwords",
    "description": "Ensure that the number of days before users are asked to re-confirm their\nauthentication information is not set to 0.",
    "rationale": "This setting is necessary if 'Require users to register when signing in' is enabled. If\nauthentication re-confirmation is disabled, registered users will never be prompted to re-\nconfirm their existing authentication information. If the authentication information for a\nuser changes, such as a phone number or email, then the password reset information\nfor that user reverts to the previously registered authentication information.",
    "impact": "Users will be prompted to re-confirm their authentication information after the number of\ndays specified.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Users.\n4. Select Password reset.\n5. Under Manage, select Registration.\n6. Ensure that Number of days before users are asked to re-confirm\ntheir authentication information is not set to 0.",
    "expected_response": "6. Ensure that Number of days before users are asked to re-confirm",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Entra ID.\n3. Under Manage, select Users.\n4. Select Password reset.\n5. Under Manage, select Registration.\n6. Set the Number of days before users are asked to re-confirm their\nauthentication information to your organization-defined frequency.\n7. Click Save.",
    "default_value": "By default, the Number of days before users are asked to re-confirm their\nauthentication information is set to \"180 days\".",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-",
      "howitworks#registration",
      "2. https://support.microsoft.com/en-us/account-billing/reset-your-work-or-school-",
      "password-using-security-info-23dde81f-08bb-4776-ba72-e6b72b9dda9e",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "4. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-methods"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 140,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.10",
    "title": "Ensure that 'Notify users on password resets?' is set to 'Yes'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Ensure All Accounts Have An Expiration Date",
    "description": "Ensure that users are notified on their primary and alternate emails on password resets.",
    "rationale": "User notification on password reset is a proactive way of confirming password reset\nactivity. It helps the user to recognize unauthorized password reset activities.",
    "impact": "Users will receive emails alerting them to password changes to both their primary and\nalternate emails.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select Password reset\n5. Under Manage, select Notifications\n6. Ensure that Notify users on password resets? is set to Yes",
    "expected_response": "6. Ensure that Notify users on password resets? is set to Yes",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select Password reset\n5. Under Manage, select Notifications\n6. Set Notify users on password resets? to Yes\n7. Click Save",
    "default_value": "By default, Notify users on password resets? is set to \"Yes\".",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-",
      "sspr#set-up-notifications-and-customizations",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-",
      "howitworks#notifications",
      "3. https://support.microsoft.com/en-us/account-billing/reset-your-work-or-school-",
      "password-using-security-info-23dde81f-08bb-4776-ba72-e6b72b9dda9e",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 142,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.11",
    "title": "Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Ensure that all Global Administrators are notified if any other administrator resets their\npassword.",
    "rationale": "Administrator accounts are sensitive. Any password reset activity notification, when sent\nto all Administrators, ensures that all Global Administrators can passively confirm if such\na reset is a common pattern within their group. For example, if all Administrators change\ntheir password every 30 days, any password reset activity before that may require\nadministrator(s) to evaluate any unusual activity and confirm its origin.",
    "impact": "All Global Administrators will receive a notification from Azure every time a password is\nreset. This is useful for auditing procedures to confirm that there are no out of the\nordinary password resets for Administrators. There is additional overhead, however, in\nthe time required for Global Administrators to audit the notifications. This setting is only\nuseful if all Global Administrators pay attention to the notifications and audit each one.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select Password reset\n5. Under Manage, select Notifications\n6. Ensure that Notify all admins when other admins reset their\npassword? is set to Yes",
    "expected_response": "6. Ensure that Notify all admins when other admins reset their\npassword? is set to Yes",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select Password reset\n5. Under Manage, select Notifications\n6. Set Notify all admins when other admins reset their password? to\nYes\n7. Click Save",
    "default_value": "By default, Notify all admins when other admins reset their password? is set\nto \"No\".",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-",
      "howitworks#notifications",
      "2. https://support.microsoft.com/en-us/account-billing/reset-your-work-or-school-",
      "password-using-security-info-23dde81f-08bb-4776-ba72-e6b72b9dda9e",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "5. https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-",
      "sspr#set-up-notifications-and-customizations"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 144,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.12",
    "title": "Ensure that 'User consent for applications' is set to 'Do not allow user consent'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Log and Alert on Changes to Administrative Group",
    "description": "Require administrators to provide consent for applications before use.",
    "rationale": "If Microsoft Entra ID is running as an identity provider for third-party applications,\npermissions and consent should be limited to administrators or pre-approved. Malicious\napplications may attempt to exfiltrate data or abuse privileged user accounts.",
    "impact": "Enforcing this setting may create additional requests that administrators need to review.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Enterprise applications\n4. Under Security, select Consent and permissions\n5. Under Manage, select User consent settings\n6. Ensure User consent for applications is set to Do not allow user\nconsent\nAudit from PowerShell\nConnect-MgGraph\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object\n-ExpandProperty PermissionGrantPoliciesAssigned\nIf the command returns no values in response, the configuration complies with the\nrecommendation.",
    "expected_response": "6. Ensure User consent for applications is set to Do not allow user\nIf the command returns no values in response, the configuration complies with the",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Enterprise applications\n4. Under Security, select Consent and permissions\n5. Under Manage, select User consent settings\n6. Set User consent for applications to Do not allow user consent\n7. Click Save",
    "default_value": "By default, Users consent for applications is set to Allow user consent for\napps.",
    "detection_commands": [
      "Connect-MgGraph"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-",
      "consent?pivots=ms-powershell#configure-user-consent-to-applications",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 147,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.13",
    "title": "Ensure that 'User consent for applications' is set to 'Allow user consent for apps from verified publishers, for selected permissions'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Address unapproved software",
    "description": "Allow users to provide consent for selected permissions when a request is coming from\na verified publisher.",
    "rationale": "If Microsoft Entra ID is running as an identity provider for third-party applications,\npermissions and consent should be limited to administrators or pre-approved. Malicious\napplications may attempt to exfiltrate data or abuse privileged user accounts.",
    "impact": "Enforcing this setting may create additional requests that administrators need to review.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Enterprise applications\n4. Under Security, select Consent and permissions`\n5. Under Manage, select User consent settings\n6. Under User consent for applications, ensure Allow user consent for\napps from verified publishers, for selected permissions is selected\nAudit from PowerShell\nConnect-MgGraph\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object\n-ExpandProperty PermissionGrantPoliciesAssigned\nThe command should return either ManagePermissionGrantsForSelf.microsoft-\nuser-default-low or a custom app consent policy id if one is in use.",
    "expected_response": "6. Under User consent for applications, ensure Allow user consent for\nThe command should return either ManagePermissionGrantsForSelf.microsoft-",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Enterprise applications\n4. Under Security, select Consent and permissions`\n5. Under Manage, select User consent settings\n6. Under User consent for applications, select Allow user consent for\napps from verified publishers, for selected permissions\n7. Click Save",
    "default_value": "By default, User consent for applications is set to Allow user consent for\napps.",
    "detection_commands": [
      "Connect-MgGraph"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-",
      "consent?pivots=ms-graph#configure-user-consent-to-applications",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "5. https://learn.microsoft.com/en-",
      "us/powershell/module/microsoft.graph.identity.signins/get-",
      "mgpolicyauthorizationpolicy?view=graph-powershell-1.0"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 149,
    "dspm_relevant": false,
    "rr_relevant": false
  },
  {
    "cis_id": "5.14",
    "title": "Ensure that 'Users can register applications' is set to 'No'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Utilize Application Whitelisting",
    "description": "Require administrators or appropriately delegated users to register third-party\napplications.",
    "rationale": "It is recommended to only allow an administrator to register custom-developed\napplications. This ensures that the application undergoes a formal security review and\napproval process prior to exposing Microsoft Entra ID data. Certain users like\ndevelopers or other high-request users may also be delegated permissions to prevent\nthem from waiting on an administrative user. Your organization should review your\npolicies and decide your needs.",
    "impact": "Enforcing this setting will create additional requests for approval that will need to be\naddressed by an administrator. If permissions are delegated, a user may approve a\nmalevolent third party application, potentially giving it access to your data.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select User settings\n5. Ensure that Users can register applications is set to No\nAudit from PowerShell\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Format-List\nAllowedToCreateApps\nCommand should return the value of False",
    "expected_response": "5. Ensure that Users can register applications is set to No\nCommand should return the value of False",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select User settings\n5. Set Users can register applications to No\n6. Click Save\nRemediate from PowerShell\n$param = @{ AllowedToCreateApps = \"$false\" }\nUpdate-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $param",
    "default_value": "By default, Users can register applications is set to \"Yes\".",
    "detection_commands": [],
    "remediation_commands": [
      "$param = @{ AllowedToCreateApps = \"$false\" } Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $param"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/delegate-app-roles#restrict-who-can-create-applications",
      "2. https://learn.microsoft.com/en-us/entra/identity-platform/how-applications-are-",
      "added#who-has-permission-to-add-applications-to-my-azure-ad-instance",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "5. https://learn.microsoft.com/en-",
      "us/powershell/module/microsoft.graph.identity.signins/get-",
      "mgpolicyauthorizationpolicy?view=graph-powershell-1.0"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 152,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.15",
    "title": "Ensure that 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Address unapproved software",
    "description": "Limit guest user permissions.",
    "rationale": "Limiting guest access ensures that guest accounts do not have permission for certain\ndirectory tasks, such as enumerating users, groups or other directory resources, and\ncannot be assigned to administrative roles in your directory. Guest access has three\nlevels of restriction.\n1. Guest users have the same access as members (most inclusive),\n2. Guest users have limited access to properties and memberships of directory\nobjects (default value),\n3. Guest user access is restricted to properties and memberships of their own\ndirectory objects (most restrictive).\nThe recommended option is the 3rd, most restrictive: \"Guest user access is restricted to\ntheir own directory object\".",
    "impact": "This may create additional requests for permissions to access resources that\nadministrators will need to approve.\nAccording to https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-\npermissions#services-currently-not-supported\nService without current support might have compatibility issues with the new guest\nrestriction setting.\n• Forms\n• Project\n• Yammer\n• Planner in SharePoint",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select External Identities\n4. Select External collaboration settings\n5. Under Guest user access, ensure that Guest user access restrictions is\nset to Guest user access is restricted to properties and\nmemberships of their own directory objects\nAudit from PowerShell\nEnter the following:\nConnect-MgGraph\n(Get-MgPolicyAuthorizationPolicy).GuestUserRoleId\nWhich will give a result like:\nId                                                : authorizationPolicy\nOdataType                                         :\nDescription                                       : Used to manage\nauthorization related settings across the company.\nDisplayName                                       : Authorization Policy\nEnabledPreviewFeatures                            : {}\nGuestUserRoleId                                   : 10dae51f-b6af-4016-8d66-\n8c2a99b929b3\nPermissionGrantPolicyIdsAssignedToDefaultUserRole : {user-default-legacy}\nIf the GuestUserRoleID property does not equal 2af84b1e-32c8-42b7-82bc-\ndaa82404023b then it is not set to most restrictive.",
    "expected_response": "5. Under Guest user access, ensure that Guest user access restrictions is\nIf the GuestUserRoleID property does not equal 2af84b1e-32c8-42b7-82bc-",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select External Identities\n4. Select External collaboration settings\n5. Under Guest user access, set Guest user access restrictions to Guest\nuser access is restricted to properties and memberships of their\nown directory objects\n6. Click Save\nRemediate from PowerShell\n1. Enter the following to update the policy ID:\n2. Update-MgPolicyAuthorizationPolicy -GuestUserRoleId \"2af84b1e-32c8-\n42b7-82bc-daa82404023b\"\n3. Check the GuestUserRoleId again:\n4. (Get-MgPolicyAuthorizationPolicy).GuestUserRoleId\n5. Ensure that the GuestUserRoleId is equal to the earlier entered value of\n2af84b1e-32c8-42b7-82bc-daa82404023b.",
    "default_value": "By default, Guest user access restrictions is set to Guest users have limited\naccess to properties and memberships of directory objects.",
    "detection_commands": [
      "Connect-MgGraph"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/fundamentals/users-default-",
      "permissions#member-and-guest-users",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "5. https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-",
      "permissions"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 155,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "5.16",
    "title": "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles [...]' or 'No one [..]'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Restrict invitations to either users with specific administrative roles or no one.",
    "rationale": "Restricting invitations to users with specific administrator roles ensures that only\nauthorized accounts have access to cloud resources. This helps to maintain \"Need to\nKnow\" permissions and prevents inadvertent access to data.\nBy default the setting Guest invite restrictions is set to Anyone in the\norganization can invite guest users including guests and non-admins.\nThis would allow anyone within the organization to invite guests and non-admins to the\ntenant, posing a security risk.",
    "impact": "With the option of Only users assigned to specific admin roles can invite\nguest users selected, users with specific admin roles will be in charge of sending\ninvitations to the external users, requiring additional overhead by them to manage user\naccounts. This will mean coordinating with other departments as they are onboarding\nnew users.",
    "audit": "Note: This setting has 4 levels of restriction, which include:\n• Anyone in the organization can invite guest users including guests and non-\nadmins (most inclusive),\n• Member users and users assigned to specific admin roles can invite guest users\nincluding guests with member permissions,\n• Only users assigned to specific admin roles can invite guest users,\n• No one in the organization can invite guest users including admins (most\nrestrictive).\nAudit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select External Identities\n4. Select External collaboration settings\n5. Under Guest invite settings, ensure that Guest invite restrictions is\nset to either Only users assigned to specific admin roles can invite\nguest users or No one in the organization [...]\nAudit from Powershell\nEnter the following:\nConnect-MgGraph\n(Get-MgPolicyAuthorizationPolicy).AllowInvitesFrom\nIf the resulting value is adminsAndGuestInviters or none the configuration complies.",
    "expected_response": "5. Under Guest invite settings, ensure that Guest invite restrictions is",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select External Identities\n4. Select External collaboration settings\n5. Under Guest invite settings, set Guest invite restrictions to either\nOnly users assigned to specific admin roles can invite guest\nusers or No one in the organization [...]\n6. Click Save\nRemediate from Powershell\nEnter the following:\nConnect-MgGraph\nUpdate-MgPolicyAuthorizationPolicy -AllowInvitesFrom \"adminsAndGuestInviters\"\nAlternatively, to set this to the most restrictive No one in the organization [...]\nenter the following:\nConnect-MgGraph\nUpdate-MgPolicyAuthorizationPolicy -AllowInvitesFrom \"none\"",
    "default_value": "By default, Guest invite restrictions is set to Anyone in the organization\ncan invite guest users including guests and non-admins",
    "detection_commands": [
      "Connect-MgGraph"
    ],
    "remediation_commands": [
      "Connect-MgGraph Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom \"adminsAndGuestInviters\"",
      "Connect-MgGraph Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom \"none\""
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-",
      "configure",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements",
      "5. https://learn.microsoft.com/en-",
      "us/powershell/module/microsoft.graph.identity.signins/update-",
      "mgpolicyauthorizationpolicy?view=graph-powershell-1.0"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 159,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.17",
    "title": "Ensure that 'Restrict access to Microsoft Entra admin center' is set to 'Yes'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Restrict access to the Microsoft Entra ID administration center to administrators only.\nNOTE: This only affects access to the Entra ID administrator's web portal. This setting\ndoes not prohibit privileged users from using other methods such as Rest API or\nPowershell to obtain sensitive information from Microsoft Entra ID.",
    "rationale": "The Microsoft Entra ID administrative center has sensitive data and permission settings.\nAll non-administrators should be prohibited from accessing any Microsoft Entra ID data\nin the administration center to avoid exposure.",
    "impact": "All administrative tasks will need to be done by Administrators, causing additional\noverhead in management of users and resources.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select User settings\n5. Under Administration centre, ensure that Restrict access to Microsoft\nEntra admin center is set to Yes",
    "expected_response": "5. Under Administration centre, ensure that Restrict access to Microsoft\nEntra admin center is set to Yes",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Users\n4. Under Manage, select User settings\n5. Under Administration centre, set Restrict access to Microsoft Entra\nadmin center to Yes\n6. Click Save",
    "default_value": "By default, Restrict access to Microsoft Entra admin center is set to No",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 162,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.18",
    "title": "Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "Restrict access to group web interface in the Access Panel portal.",
    "rationale": "Self-service group management enables users to create and manage security groups or\nOffice 365 groups in Microsoft Entra ID. Unless a business requires this day-to-day\ndelegation for some users, self-service group management should be disabled. Any\nuser can access the Access Panel, where they can reset their passwords, view their\ninformation, etc. By default, users are also allowed to access the Group feature, which\nshows groups, members, related resources (SharePoint URL, Group email address,\nYammer URL, and Teams URL). By setting this feature to 'Yes', users will no longer\nhave access to the web interface, but still have access to the data using the API. This is\nuseful to prevent non-technical users from enumerating groups-related information, but\ntechnical users will still be able to access this information using APIs.",
    "impact": "Setting to Yes could create administrative overhead by customers seeking certain group\nmemberships that will have to be manually managed by administrators with appropriate\npermissions.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Self Service Group Management, ensure that Restrict user\nability to access groups features in My Groups is set to Yes",
    "expected_response": "5. Under Self Service Group Management, ensure that Restrict user\nability to access groups features in My Groups is set to Yes",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Self Service Group Management, set Restrict user ability to\naccess groups features in My Groups to Yes\n6. Click Save",
    "default_value": "By default, Restrict user ability to access groups features in the Access\nPane is set to No",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-",
      "management",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 164,
    "dspm_relevant": false,
    "rr_relevant": false
  },
  {
    "cis_id": "5.19",
    "title": "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Restrict security group creation to administrators only.",
    "rationale": "When creating security groups is enabled, all users in the directory are allowed to\ncreate new security groups and add members to those groups. Unless a business\nrequires this day-to-day delegation, security group creation should be restricted to\nadministrators only.",
    "impact": "Enabling this setting could create a number of requests that would need to be managed\nby an administrator.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Security Groups, ensure that Users can create security groups\nin Azure portals, API or PowerShell is set to No",
    "expected_response": "5. Under Security Groups, ensure that Users can create security groups\nin Azure portals, API or PowerShell is set to No",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Security Groups, set Users can create security groups in Azure\nportals, API or PowerShell to No\n6. Click Save",
    "default_value": "By default, Users can create security groups in Azure portals, API or\nPowerShell is set to Yes",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-",
      "management#making-a-group-available-for-end-user-self-service",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 166,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "5.20",
    "title": "Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Restrict security group management to administrators only.",
    "rationale": "Restricting security group management to administrators only prohibits users from\nmaking changes to security groups. This ensures that security groups are appropriately\nmanaged and their management is not delegated to non-administrators.",
    "impact": "Group Membership for user accounts will need to be handled by Admins and cause\nadministrative overhead.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Self Service Group Management, ensure that Owners can manage\ngroup membership requests in My Groups is set to No",
    "expected_response": "5. Under Self Service Group Management, ensure that Owners can manage\ngroup membership requests in My Groups is set to No",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Self Service Group Management, set Owners can manage group\nmembership requests in My Groups to No\n6. Click Save",
    "default_value": "By default, Owners can manage group membership requests in My Groups is set\nto No.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-",
      "management#making-a-group-available-for-end-user-self-service",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-8-determine-access-process-for-cloud-provider-support",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 168,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "5.21",
    "title": "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "e3_e5_f5_or_business_premium_and_em_s_e3_or_e5_licenses_and_can",
    "domain": "E3, E5, F5, or Business Premium, and EM&S E3 or E5 licenses) and CAN",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Restrict Microsoft 365 group creation to administrators only.",
    "rationale": "Restricting Microsoft 365 group creation to administrators only ensures that creation of\nMicrosoft 365 groups is controlled by the administrator. Appropriate groups should be\ncreated and managed by the administrator and group creation rights should not be\ndelegated to any other user.",
    "impact": "Enabling this setting could create a number of requests that would need to be managed\nby an administrator.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Microsoft 365 Groups, ensure that Users can create Microsoft\n365 groups in Azure portals, API or PowerShell is set to No",
    "expected_response": "5. Under Microsoft 365 Groups, ensure that Users can create Microsoft\n365 groups in Azure portals, API or PowerShell is set to No",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Groups\n4. Under Settings, select General\n5. Under Microsoft 365 Groups, set Users can create Microsoft 365\ngroups in Azure portals, API or PowerShell to No\n6. Click Save",
    "default_value": "By default, Users can create Microsoft 365 groups in Azure portals, API\nor PowerShell is set to Yes.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-",
      "groups",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 170,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.22",
    "title": "Ensure that 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "groups_in_azure_portals_api_or_powershell_is_set_to_no",
    "domain": "groups in Azure portals, API or PowerShell is set to No",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "NOTE: This recommendation is only relevant if your subscription is using Per-User\nMFA. If your organization is licensed to use Conditional Access, the preferred method of\nrequiring MFA to join devices to Entra ID is to use a Conditional Access policy (see\nadditional information below for link).\nJoining or registering devices to Microsoft Entra ID should require multi-factor\nauthentication.",
    "rationale": "Multi-factor authentication is recommended when adding devices to Microsoft Entra ID.\nWhen set to Yes, users who are adding devices from the internet must first use the\nsecond method of authentication before their device is successfully added to the\ndirectory. This ensures that rogue devices are not added to the domain using a\ncompromised user account.",
    "impact": "A slight impact of additional overhead, as Administrators will now have to approve every\naccess to the domain.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Devices\n4. Under Manage, select Device settings\n5. Under Microsoft Entra join and registration settings, ensure that\nRequire Multifactor Authentication to register or join devices\nwith Microsoft Entra is set to Yes",
    "expected_response": "5. Under Microsoft Entra join and registration settings, ensure that\nwith Microsoft Entra is set to Yes",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Devices\n4. Under Manage, select Device settings\n5. Under Microsoft Entra join and registration settings, set Require\nMultifactor Authentication to register or join devices with\nMicrosoft Entra to Yes\n6. Click Save",
    "default_value": "By default, Require Multifactor Authentication to register or join\ndevices with Microsoft Entra is set to No.",
    "additional_information": "If Conditional Access is available, this recommendation should be bypassed in favor of\nthe Conditional Access implementation of requiring Multifactor Authentication to register\nor join devices with Microsoft Entra.\nhttps://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-\ndevice-registration",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-",
      "users-device-registration",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-6-use-strong-authentication-controls"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 172,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.23",
    "title": "Ensure that no custom subscription administrator roles exist",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "groups_in_azure_portals_api_or_powershell_is_set_to_no",
    "domain": "groups in Azure portals, API or PowerShell is set to No",
    "subdomain": "Require Multi-factor Authentication",
    "description": "The principle of least privilege should be followed and only necessary privileges should\nbe assigned instead of allowing full administrative access.",
    "rationale": "Custom roles in Azure with administrative access can obfuscate the permissions\ngranted and introduce complexity and blind spots to the management of privileged\nidentities. For less mature security programs without regular identity audits, the creation\nof Custom roles should be avoided entirely. For more mature security programs with\nregular identity audits, Custom Roles should be audited for use and assignment, used\nminimally, and the principle of least privilege should be observed when granting\npermissions",
    "impact": "Subscriptions will need to be handled by Administrators with permissions.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Subscriptions.\n3. Select a subscription.\n4. Select Access control (IAM).\n5. Select Roles.\n6. Click Type and select Custom role from the drop-down menu.\n7. Select View next to a role.\n8. Select JSON.\n9. Check for assignableScopes set to the subscription, and actions set to *.\n10. Repeat steps 7-9 for each custom role.\nAudit from Azure CLI\nList custom roles:\naz role definition list --custom-role-only True\nCheck for entries with assignableScope of the subscription, and an action of *\nAudit from PowerShell\nConnect-AzAccount\nGet-AzRoleDefinition |Where-Object {($_.IsCustom -eq $true) -and\n($_.Actions.contains('*'))}\nCheck the output for AssignableScopes value set to the subscription.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: a451c1ef-c6ca-483d-87ed-f49761e3ffb5 - Name: 'Audit usage of\ncustom RBAC roles'",
    "expected_response": "Check the output for AssignableScopes value set to the subscription.",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Subscriptions.\n3. Select a subscription.\n4. Select Access control (IAM).\n5. Select Roles.\n6. Click Type and select Custom role from the drop-down menu.\n7. Check the box next to each role which grants subscription administrator\nprivileges.\n8. Select Delete.\n9. Select Yes.\nRemediate from Azure CLI\nList custom roles:\naz role definition list --custom-role-only True\nCheck for entries with assignableScope of the subscription, and an action of *.\nTo remove a violating role:\naz role definition delete --name <role name>\nNote that any role assignments must be removed before a custom role can be deleted.\nEnsure impact is assessed before deleting a custom role granting subscription\nadministrator privileges.",
    "default_value": "By default, no custom owner roles are created.",
    "detection_commands": [
      "az role definition list --custom-role-only True",
      "Get-AzRoleDefinition |Where-Object {($_.IsCustom -eq $true) -and"
    ],
    "remediation_commands": [
      "az role definition list --custom-role-only True",
      "az role definition delete --name <role name>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/add-",
      "change-subscription-administrator",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-7-follow-just-enough-administration-least-privilege-principle"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 175,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "5.24",
    "title": "Ensure that a custom role is assigned permissions for administering resource locks",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "groups_in_azure_portals_api_or_powershell_is_set_to_no",
    "domain": "groups in Azure portals, API or PowerShell is set to No",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "description": "Resource locking is a powerful protection mechanism that can prevent inadvertent\nmodification or deletion of resources within Azure subscriptions and resource groups,\nand it is a recommended NIST configuration.",
    "rationale": "Given that the resource lock functionality is outside of standard Role-Based Access\nControl (RBAC), it would be prudent to create a resource lock administrator role to\nprevent inadvertent unlocking of resources.",
    "impact": "By adding this role, specific permissions may be granted for managing only resource\nlocks rather than needing to provide the broad Owner or User Access Administrator\nrole, reducing the risk of the user being able to cause unintentional damage.",
    "audit": "Audit from Azure Portal\n1. In the Azure portal, navigate to a subscription or resource group.\n2. Click Access control (IAM).\n3. Click Roles.\n4. Click Type : All.\n5. Click to view the drop-down menu.\n6. Select Custom role.\n7. Click View in the Details column of a custom role.\n8. Review the role permissions.\n9. Click Assignments and review the assignments.\n10. Click the X to exit the custom role details page.\n11. Repeat steps 7-10. Ensure that at least one custom role exists that assigns the\nMicrosoft.Authorization/locks permission to appropriate members.\n12. Repeat steps 1-11 for each subscription or resource group.",
    "expected_response": "11. Repeat steps 7-10. Ensure that at least one custom role exists that assigns the",
    "remediation": "Remediate from Azure Portal\n1. In the Azure portal, navigate to a subscription or resource group.\n2. Click Access control (IAM).\n3. Click + Add.\n4. Click Add custom role.\n5. In the Custom role name field enter Resource Lock Administrator.\n6. In the Description field enter Can Administer Resource Locks.\n7. For Baseline permissions select Start from scratch.\n8. Click Next.\n9. Click Add permissions.\n10. In the Search for a permission box, type\nMicrosoft.Authorization/locks.\n11. Click the result.\n12. Check the box next to Permission.\n13. Click Add.\n14. Click Review + create.\n15. Click Create.\n16. Click OK.\n17. Click + Add.\n18. Click Add role assignment.\n19. In the Search by role name, description, permission, or ID box, type\nResource Lock Administrator.\n20. Select the role.\n21. Click Next.\n22. Click + Select members.\n23. Select appropriate members.\n24. Click Select.\n25. Click Review + assign.\n26. Click Review + assign again.\n27. Repeat steps 1-26 for each subscription or resource group requiring remediation.\nRemediate from PowerShell:\nBelow is a PowerShell definition for a resource lock administrator role created at an\nAzure Management group level\nImport-Module Az.Accounts\nConnect-AzAccount\n$role = Get-AzRoleDefinition \"User Access Administrator\"\n$role.Id = $null\n$role.Name = \"Resource Lock Administrator\"\n$role.Description = \"Can Administer Resource Locks\"\n$role.Actions.Clear()\n$role.Actions.Add(\"Microsoft.Authorization/locks/*\")\n$role.AssignableScopes.Clear()\n* Scope at the Management group level Management group\n$role.AssignableScopes.Add(\"/providers/Microsoft.Management/managementGroups/\nMG-Name\")\nNew-AzRoleDefinition -Role $role\nGet-AzureRmRoleDefinition \"Resource Lock Administrator\"",
    "default_value": "A role for administering resource locks does not exist by default.",
    "detection_commands": [],
    "remediation_commands": [
      "Azure Management group level",
      "$role = Get-AzRoleDefinition \"User Access Administrator\" $role.Id = $null $role.Name = \"Resource Lock Administrator\" $role.Description = \"Can Administer Resource Locks\" $role.Actions.Clear() $role.Actions.Add(\"Microsoft.Authorization/locks/*\") $role.AssignableScopes.Clear()",
      "$role.AssignableScopes.Add(\"/providers/Microsoft.Management/managementGroups/",
      "New-AzRoleDefinition -Role $role Get-AzureRmRoleDefinition \"Resource Lock Administrator\""
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles",
      "2. https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-7-follow-just-enough-administration-least-privilege-principle",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-3-manage-lifecycle-of-identities-and-entitlements",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "7. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 178,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.25",
    "title": "Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' is set to 'Permit no one'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "groups_in_azure_portals_api_or_powershell_is_set_to_no",
    "domain": "groups in Azure portals, API or PowerShell is set to No",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Users who are set as subscription owners are able to make administrative changes to\nthe subscriptions and move them into and out of Microsoft Entra ID.",
    "rationale": "Permissions to move subscriptions in and out of a Microsoft Entra tenant must only be\ngiven to appropriate administrative personnel. A subscription that is moved into a\nMicrosoft Entra tenant may be within a folder to which other users have elevated\npermissions. This prevents loss of data or unapproved changes of the objects within by\npotential bad actors.",
    "impact": "Subscriptions will need to have these settings turned off to be moved.",
    "audit": "Audit from Azure Portal\n1. From the Azure Portal Home select the portal menu\n2. Select Subscriptions\n3. In the Advanced options drop-down menu, select Manage Policies\n4. Ensure Subscription leaving Microsoft Entra tenant and Subscription\nentering Microsoft Entra tenant are set to Permit no one",
    "expected_response": "4. Ensure Subscription leaving Microsoft Entra tenant and Subscription\nentering Microsoft Entra tenant are set to Permit no one",
    "remediation": "Remediate from Azure Portal\n1. From the Azure Portal Home select the portal menu\n2. Select Subscriptions\n3. In the Advanced options drop-down menu, select Manage Policies\n4. Set Subscription leaving Microsoft Entra tenant and Subscription\nentering Microsoft Entra tenant to Permit no one\n5. Click Save changes",
    "default_value": "By default Subscription leaving Microsoft Entra tenant and Subscription\nentering Microsoft Entra tenant are set to Allow everyone (default)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/cost-management-",
      "billing/manage/manage-azure-subscription-policy",
      "2. https://learn.microsoft.com/en-us/entra/fundamentals/how-subscriptions-",
      "associated-directory",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-2-protect-identity-and-authentication-systems"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 182,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.26",
    "title": "Ensure fewer than 5 users have global administrator assignment",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "groups_in_azure_portals_api_or_powershell_is_set_to_no",
    "domain": "groups in Azure portals, API or PowerShell is set to No",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "This recommendation aims to maintain a balance between security and operational\nefficiency by ensuring that a minimum of 2 and a maximum of 4 users are assigned the\nGlobal Administrator role in Microsoft Entra ID. Having at least two Global\nAdministrators ensures redundancy, while limiting the number to four reduces the risk of\nexcessive privileged access.",
    "rationale": "The Global Administrator role has extensive privileges across all services in Microsoft\nEntra ID. The Global Administrator role should never be used in regular daily activities;\nadministrators should have a regular user account for daily activities, and a separate\naccount for administrative responsibilities. Limiting the number of Global Administrators\nhelps mitigate the risk of unauthorized access, reduces the potential impact of human\nerror, and aligns with the principle of least privilege to reduce the attack surface of an\nAzure tenant. Conversely, having at least two Global Administrators ensures that\nadministrative functions can be performed without interruption in case of unavailability of\na single admin.\nFor any accounts assigned the Global Administrator role, at least one strong\nauthentication method such as a FIDO2 key or certificate is strongly advised. Additional\ndetail on strong passwordless authentication methods is provided in the\nrecommendation titled \"Ensure passwordless authentication methods are considered\"\nand a link can be found in references for more detail about emergency access\naccounts.",
    "impact": "Implementing this recommendation may require changes in administrative workflows or\nthe redistribution of roles and responsibilities. Adequate training and awareness should\nbe provided to all Global Administrators.\nNOTE: If an organization's tenant is using a third-party identity provider, the audit and\nremediation procedures presented here may not be relevant. The principle of the\nrecommendation is still relevant, and compensating controls that are relevant to the\nthird-party identity provider should be implemented.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Roles and administrators\n4. Under Administrative Roles, select Global Administrator\n5. Ensure less than 5 users are actively assigned the role.\n6. Ensure that at least 2 users are actively assigned the role.",
    "expected_response": "5. Ensure less than 5 users are actively assigned the role.\n6. Ensure that at least 2 users are actively assigned the role.",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Under Manage, select Roles and administrators\n4. Under Administrative Roles, select Global Administrator\nIf more than 4 users are assigned:\n1. Remove Global Administrator role for users which do not or no longer require the\nrole.\n2. Assign Global Administrator role via PIM which can be activated when required.\n3. Assign more granular roles to users to conduct their duties.\nIf only one user is assigned:\n1. Provide the Global Administrator role to a trusted user or create a break glass\nadmin account.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-",
      "practices#5-limit-the-number-of-global-administrators-to-less-than-5",
      "2. https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-",
      "roles?view=o365-worldwide#security-guidelines-for-assigning-roles",
      "3. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/security-emergency-access",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 184,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.27",
    "title": "Ensure there are between 2 and 3 subscription owners",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "groups_in_azure_portals_api_or_powershell_is_set_to_no",
    "domain": "groups in Azure portals, API or PowerShell is set to No",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "description": "The Owner role in Azure grants full control over all resources in a subscription, including\nthe ability to assign roles to others.",
    "rationale": "Limit the number of security principals (users, groups, service principals, and managed\nidentities) assigned the Owner role to between 2 and 3. If groups are used, ensure their\nmembership is tightly controlled and regularly reviewed to avoid privilege sprawl.",
    "impact": "Implementation may require changes in administrative workflows or the redistribution of\nroles and responsibilities. The recommendation to have between 2 and 3 Owners per\nsubscription must account for all security principals that can be assigned the Owner\nrole, not just individual users. This includes:\n• User accounts\n• Entra ID groups\n• Service principals (used by applications or automation)\n• Managed identities (system-assigned or user-assigned)",
    "audit": "Audit from Azure Portal\n1. Go to Subscriptions.\n2. Click the name of a subscription.\n3. Click Access Controls (IAM).\n4. Click Role assignments.\n5. Click Role : All.\n6. Click the arrow next to All.\n7. Click Owner.\n8. Ensure a minimum of 2 and a maximum of 3 members are returned.\n9. Repeat steps 1-8 for each subscription.\nAudit from Azure CLI\nRun the following command to list members with role Owner at a given subscription\nscope:\naz role assignment list --role Owner --scope /subscriptions/<subscription-id>\n--query \"[].{PrincipalName:principalName, Type:principalType}\"\nEnsure a minimum of 2 and a maximum of 3 members are returned.\nFor each Owner assignment, check: If principalType == Group, review group\nmembership. If principalType == ServicePrincipal or ManagedIdentity, validate\nnecessity and scope.\nRepeat for each subscription.\nAudit from PowerShell\nRun the following command to list members with role Owner at a given subscription\nscope:\nGet-AzRoleAssignment -RoleDefinitionName Owner -Scope\n/subscriptions/<subscription-id>\nEnsure a minimum of 2 and a maximum of 3 members are returned.\nRepeat for each subscription.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 09024ccc-0c5f-475e-9457-b7c0d9ed487b - Name: 'There should be\nmore than one owner assigned to your subscription'\n• Policy ID: 4f11b553-d42e-4e3a-89be-32ca364cad4c - Name: 'A maximum of 3\nowners should be designated for your subscription'",
    "expected_response": "8. Ensure a minimum of 2 and a maximum of 3 members are returned.\nEnsure a minimum of 2 and a maximum of 3 members are returned.\n• Policy ID: 09024ccc-0c5f-475e-9457-b7c0d9ed487b - Name: 'There should be\nowners should be designated for your subscription'",
    "remediation": "Remediate from Azure Portal\n1. Go to Subscriptions.\n2. Click the name of a subscription.\n3. Click Access Controls (IAM).\n4. Click Role assignments.\n5. Click Role : All.\n6. Click the arrow next to All.\n7. Click Owner.\n8. Check the box next to members from whom the owner role should be removed.\n9. Click Delete.\n10. Click Yes.\n11. Repeat steps 1-10 for each subscription requiring remediation.\nRemediate from Azure CLI\nRun the following command to delete role assignments by role assignment id:\naz role assignment delete --ids <role-assignment-ids>",
    "default_value": "A subscription has 1 owner by default.",
    "detection_commands": [
      "az role assignment list --role Owner --scope /subscriptions/<subscription-id> --query \"[].{PrincipalName:principalName, Type:principalType}\"",
      "Get-AzRoleAssignment -RoleDefinitionName Owner -Scope"
    ],
    "remediation_commands": [
      "az role assignment delete --ids <role-assignment-ids>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/cli/azure/role/assignment",
      "2. https://learn.microsoft.com/en-us/powershell/module/az.resources/get-",
      "azroleassignment",
      "3. https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-",
      "roles/privileged#owner",
      "4. https://learn.microsoft.com/en-us/azure/role-based-access-control/role-",
      "assignments-portal-subscription-admin"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 187,
    "dspm_relevant": false,
    "rr_relevant": false
  },
  {
    "cis_id": "5.28",
    "title": "Ensure passwordless authentication methods are considered",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "groups_in_azure_portals_api_or_powershell_is_set_to_no",
    "domain": "groups in Azure portals, API or PowerShell is set to No",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "description": "Passwordless authentication methods improve security and user experience by\nreplacing passwords with something you have (e.g., a hardware key), something you\nare (biometrics), or something you know, offering a convenient and secure way to\naccess resources.\nMicrosoft Entra ID and Azure Government integrate the following passwordless\nauthentication options:\n• Windows Hello for Business\n• Platform Credential for macOS\n• Platform single sign-on (PSSO) for macOS with smart card authentication\n• Microsoft Authenticator\n• Passkeys (FIDO2)\n• Certificate-based authentication",
    "rationale": "Using passwordless authentication makes sign-in easier and more secure by removing\npasswords, helping to protect organizations from attacks and improving the user\nexperience.",
    "impact": "Implementing passwordless authentication requires administrative effort and may incur\ncosts for some methods. It has the potential to save time and money by improving user\nconvenience and productivity and by reducing the need for password support.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Click Authentication methods.\n3. Under Manage, click Policies.\n4. If appropriate for your organization, ensure a passwordless authentication\nmethod policy is configured.",
    "expected_response": "4. If appropriate for your organization, ensure a passwordless authentication\nmethod policy is configured.",
    "remediation": "1. Review the passwordless authentication method options:\nhttps://learn.microsoft.com/en-us/entra/identity/authentication/concept-\nauthentication-passwordless.\n2. Choose a passwordless authentication method: https://learn.microsoft.com/en-\nus/entra/identity/authentication/concept-authentication-passwordless#choose-a-\npasswordless-method.\n3. Implement the chosen passwordless authentication method.\n1. Microsoft Authenticator: https://learn.microsoft.com/en-\nus/entra/identity/authentication/how-to-enable-authenticator-passkey.\n2. Passkeys (FIDO2): https://learn.microsoft.com/en-\nus/entra/identity/authentication/how-to-enable-passkey-fido2.",
    "default_value": "Passwordless authentication is not enabled by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-methods",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-passwordless"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 190,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "6.1.1.1",
    "title": "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Logging and Monitoring",
    "description": "Enable Diagnostic settings for exporting activity logs. Diagnostic settings are available\nfor each individual resource within a subscription. Settings should be configured for all\nappropriate resources for your environment.",
    "rationale": "A diagnostic setting controls how a diagnostic log is exported. By default, logs are\nretained only for 90 days. Diagnostic settings should be defined so that logs can be\nexported and stored for a longer duration to analyze security activities within an Azure\nsubscription.",
    "audit": "Audit from Azure Portal\nTo identify Diagnostic Settings on a subscription:\n1. Go to Monitor\n2. Click Activity Log\n3. Click Export Activity Logs\n4. Select a Subscription\n5. Ensure a Diagnostic setting exists for the selected Subscription\nTo identify Diagnostic Settings on specific resources:\n1. Go to Monitoring\n2. Click Diagnostic settings\n3. Ensure a Diagnostic setting exists for all appropriate resources.\nAudit from Azure CLI\nTo identify Diagnostic Settings on a subscription:\naz monitor diagnostic-settings subscription list --subscription\n<subscription-id>\nTo identify Diagnostic Settings on a resource\naz monitor diagnostic-settings list --resource <resource-id>\nAudit from PowerShell\nTo identify Diagnostic Settings on a Subscription:\nGet-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription-id>\nTo identify Diagnostic Settings on a specific resource:\nGet-AzDiagnosticSetting -ResourceId <resource-id>",
    "expected_response": "5. Ensure a Diagnostic setting exists for the selected Subscription\n3. Ensure a Diagnostic setting exists for all appropriate resources.",
    "remediation": "Remediate from Azure Portal\nTo enable Diagnostic Settings on a Subscription:\n1. Go to Monitor\n2. Click on Activity log\n3. Click on Export Activity Logs\n4. Click + Add diagnostic setting\n5. Enter a Diagnostic setting name\n6. Select Categories for the diagnostic setting\n7. Select the appropriate Destination details (this may be Log Analytics,\nStorage Account, Event Hub, or Partner solution)\n8. Click Save\nTo enable Diagnostic Settings on a specific resource:\n1. Go to Monitoring\n2. Click Diagnostic settings\n3. Select Add diagnostic setting\n4. Enter a Diagnostic setting name\n5. Select the appropriate log, metric, and destination (this may be Log Analytics,\nStorage Account, Event Hub, or Partner solution)\n6. Click Save\nRepeat these step for all resources as needed.\nRemediate from Azure CLI\nTo configure Diagnostic Settings on a Subscription:\naz monitor diagnostic-settings subscription create --subscription\n<subscription id> --name <diagnostic settings name> --location <location> <[-\n-event-hub <event hub ID> --event-hub-auth-rule <event hub auth rule ID>] [--\nstorage-account <storage account ID>] [--workspace <log analytics workspace\nID>] --logs \"<JSON encoded categories>\" (e.g.\n[{category:Security,enabled:true},{category:Administrative,enabled:true},{cat\negory:Alert,enabled:true},{category:Policy,enabled:true}])\nTo configure Diagnostic Settings on a specific resource:\naz monitor diagnostic-settings create --subscription <subscription ID> --\nresource <resource ID> --name <diagnostic settings name> <[--event-hub <event\nhub ID> --event-hub-rule <event hub auth rule ID>] [--storage-account\n<storage account ID>] [--workspace <log analytics workspace ID>] --logs\n<resource specific JSON encoded log settings> --metrics <metric settings\n(shorthand|json-file|yaml-file)>\nRemediate from PowerShell\nTo configure Diagnostic Settings on a subscription:\n$logCategories = @();\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Administrative -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Security -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory ServiceHealth -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Alert -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Recommendation -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Policy -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Autoscale -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory ResourceHealth -Enabled $true\nNew-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription ID> -Name\n<Diagnostic settings name> <[-EventHubAuthorizationRule <event hub auth rule\nID> -EventHubName <event hub name>] [-StorageAccountId <storage account ID>]\n[-WorkSpaceId <log analytics workspace ID>] [-MarketplacePartner ID <full ARM\nMarketplace resource ID>]> -Log $logCategories\nTo configure Diagnostic Settings on a specific resource:\n$logCategories = @()\n$logCategories +=  New-AzDiagnosticSettingLogSettingsObject -Category\n<resource specific log category> -Enabled $true\nRepeat command and variable assignment for each Log category specific to the\nresource where this Diagnostic Setting will get configured.\n$metricCategories = @()\n$metricCategories += New-AzDiagnosticSettingMetricSettingsObject -Enabled\n$true [-Category <resource specific metric category | AllMetrics>] [-\nRetentionPolicyDay <Integer>] [-RetentionPolicyEnabled $true]\nRepeat command and variable assignment for each Metric category or use the\n'AllMetrics' category.\nNew-AzDiagnosticSetting -ResourceId <resource ID> -Name <Diagnostic settings\nname> -Log $logCategories -Metric $metricCategories [-\nEventHubAuthorizationRuleId <event hub auth rule ID> -EventHubName <event hub\nname>] [-StorageAccountId <storage account ID>] [-WorkspaceId <log analytics\nworkspace ID>] [-MarketplacePartnerId <full ARM marketplace resource ID>]>",
    "default_value": "By default, diagnostic setting is not set.",
    "detection_commands": [
      "az monitor diagnostic-settings subscription list --subscription",
      "az monitor diagnostic-settings list --resource <resource-id>",
      "Get-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription-id>",
      "Get-AzDiagnosticSetting -ResourceId <resource-id>"
    ],
    "remediation_commands": [
      "az monitor diagnostic-settings subscription create --subscription",
      "az monitor diagnostic-settings create --subscription <subscription ID> --",
      "$logCategories = @(); $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -",
      "$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -",
      "New-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription ID> -Name",
      "$logCategories = @() $logCategories += New-AzDiagnosticSettingLogSettingsObject -Category",
      "$metricCategories = @() $metricCategories += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true [-Category <resource specific metric category | AllMetrics>] [-",
      "New-AzDiagnosticSetting -ResourceId <resource ID> -Name <Diagnostic settings"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/data-",
      "sources",
      "2. https://learn.microsoft.com/en-us/cli/azure/monitor/diagnostic-",
      "settings?view=azure-cli-latest",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 195,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention"
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
    "cis_id": "6.1.1.2",
    "title": "Ensure Diagnostic Setting captures appropriate categories",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Central Log Management",
    "description": "Prerequisite: A Diagnostic Setting must exist. If a Diagnostic Setting does not exist, the\nnavigation and options within this recommendation will not be available. Please review\nthe recommendation at the beginning of this subsection titled: \"Ensure that a 'Diagnostic\nSetting' exists.\"\nThe diagnostic setting should be configured to log the appropriate activities from the\ncontrol/management plane.",
    "rationale": "A diagnostic setting controls how the diagnostic log is exported. Capturing the\ndiagnostic setting categories for appropriate control/management plane activities allows\nproper alerting.",
    "audit": "Audit from Azure Portal\n1. Go to Monitor.\n2. Click Activity log.\n3. Click on Export Activity Logs.\n4. Select the appropriate Subscription.\n5. Click Edit setting next to a diagnostic setting.\n6. Ensure that the following categories are checked: Administrative, Alert,\nPolicy, and Security.\nAudit from Azure CLI\nEnsure the categories 'Administrative', 'Alert', 'Policy', and 'Security'\nset to: 'enabled: true'\naz monitor diagnostic-settings subscription list --subscription <subscription\nID>\nAudit from PowerShell\nEnsure the categories Administrative, Alert, Policy, and Security are set to Enabled:True\nGet-AzSubscriptionDiagnosticSetting -Subscription <subscriptionID>\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 3b980d31-7904-4bb7-8575-5665739a8052 - Name: 'An activity log\nalert should exist for specific Security operations'\n• Policy ID: b954148f-4c11-4c38-8221-be76711e194a - Name: 'An activity log\nalert should exist for specific Administrative operations'\n• Policy ID: c5447c04-a4d7-4ba8-a263-c9ee321a6858 - Name: 'An activity log\nalert should exist for specific Policy operations'",
    "expected_response": "6. Ensure that the following categories are checked: Administrative, Alert,\nEnsure the categories 'Administrative', 'Alert', 'Policy', and 'Security'\nEnsure the categories Administrative, Alert, Policy, and Security are set to Enabled:True\nalert should exist for specific Security operations'\nalert should exist for specific Administrative operations'\nalert should exist for specific Policy operations'",
    "remediation": "Remediate from Azure Portal\n1. Go to Monitor.\n2. Click Activity log.\n3. Click on Export Activity Logs.\n4. Select the Subscription from the drop down menu.\n5. Click Edit setting next to a diagnostic setting.\n6. Check the following categories: Administrative, Alert, Policy, and\nSecurity.\n7. Choose the destination details according to your organization's needs.\n8. Click Save.\nRemediate from Azure CLI\naz monitor diagnostic-settings subscription create --subscription\n<subscription id> --name <diagnostic settings name> --location <location> <[-\n-event-hub <event hub ID> --event-hub-auth-rule <event hub auth rule ID>] [--\nstorage-account <storage account ID>] [--workspace <log analytics workspace\nID>] --logs\n\"[{category:Security,enabled:true},{category:Administrative,enabled:true},{ca\ntegory:Alert,enabled:true},{category:Policy,enabled:true}]\"\nRemediate from PowerShell\n$logCategories = @();\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Administrative -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Security -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Alert -Enabled $true\n$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -\nCategory Policy -Enabled $true\nNew-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription ID> -Name\n<Diagnostic settings name> <[-EventHubAuthorizationRule <event hub auth rule\nID> -EventHubName <event hub name>] [-StorageAccountId <storage account ID>]\n[-WorkSpaceId <log analytics workspace ID>] [-MarketplacePartner ID <full ARM\nMarketplace resource ID>]> -Log $logCategories",
    "default_value": "When the diagnostic setting is created using Azure Portal, by default no categories are\nselected.",
    "detection_commands": [
      "az monitor diagnostic-settings subscription list --subscription <subscription",
      "Get-AzSubscriptionDiagnosticSetting -Subscription <subscriptionID>"
    ],
    "remediation_commands": [
      "az monitor diagnostic-settings subscription create --subscription",
      "$logCategories = @(); $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -",
      "$logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -",
      "New-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription ID> -Name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-",
      "settings",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-",
      "manager-diagnostic-settings",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation",
      "4. https://learn.microsoft.com/en-us/cli/azure/monitor/diagnostic-",
      "settings?view=azure-cli-latest",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.monitor/new-",
      "azsubscriptiondiagnosticsetting?view=azps-13.4.0"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 200,
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
    "cis_id": "6.1.1.3",
    "title": "Ensure the storage account containing the container with activity logs is encrypted with customer-managed key (CMK)",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Customer-managed keys introduce additional depth to security by providing a means to\nmanage access control for encryption keys. Where compliance and security frameworks\nindicate the need, and organizational capacity allows, sensitive data at rest can be\nencrypted using customer-managed keys (CMK) rather than Microsoft-managed keys.",
    "rationale": "By default in Azure, data at rest tends to be encrypted using Microsoft-managed keys. If\nyour organization wants to control and manage encryption keys for compliance and\ndefense-in-depth, customer-managed keys can be established.\nConfiguring the storage account with the activity log export container to use CMKs\nprovides additional confidentiality controls on log data, as a given user must have read\npermission on the corresponding storage account and must be granted decrypt\npermission by the CMK.\nWhile it is possible to automate the assessment of this recommendation, the\nassessment status for this recommendation remains 'Manual' due to ideally limited\nscope. The scope of application—which workloads CMK is applied to—should be\ncarefully considered to account for organizational capacity and targeted to workloads\nwith specific need for CMK.",
    "impact": "If the key expires due to setting the 'activation date' and 'expiration date', the key must\nbe rotated manually.\nUsing customer-managed keys may also incur additional man-hour requirements to\ncreate, store, manage, and protect the keys as needed.",
    "audit": "Audit from Azure Portal\n1. Go to Monitor.\n2. Select Activity log.\n3. Select Export Activity Logs.\n4. Select a Subscription.\n5. Note the name of the Storage Account for the diagnostic setting.\n6. Navigate to Storage accounts.\n7. Click on the storage account name noted in Step 5.\n8. Under Security + networking, click Encryption.\n9. Ensure Customer-managed keys is selected and a key is set.\nAudit from Azure CLI\n1. Get storage account id configured with log profile:\naz monitor diagnostic-settings subscription list --subscription <subscription\nid> --query 'value[*].storageAccountId'\n2. Ensure the storage account is encrypted with CMK:\naz storage account list --query \"[?name=='<Storage Account Name>']\"\nIn command output ensure keySource is set to Microsoft.Keyvault and\nkeyVaultProperties is not set to null\nAudit from PowerShell\nGet-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage\naccount name>|select-object -ExpandProperty encryption|format-list\nEnsure the value of KeyVaultProperties is not null or empty, and ensure KeySource\nis not set to Microsoft.Storage.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: fbb99e8e-e444-4da0-9ff1-75c92f5a85b2 - Name: 'Storage account\ncontaining the container with activity logs must be encrypted with BYOK'",
    "expected_response": "9. Ensure Customer-managed keys is selected and a key is set.\n2. Ensure the storage account is encrypted with CMK:\nIn command output ensure keySource is set to Microsoft.Keyvault and\nEnsure the value of KeyVaultProperties is not null or empty, and ensure KeySource\ncontaining the container with activity logs must be encrypted with BYOK'",
    "remediation": "Remediate from Azure Portal\n1. Go to Monitor.\n2. Select Activity log.\n3. Select Export Activity Logs.\n4. Select a Subscription.\n5. Note the name of the Storage Account for the diagnostic setting.\n6. Navigate to Storage accounts.\n7. Click on the storage account.\n8. Under Security + networking, click Encryption.\n9. Next to Encryption type, select Customer-managed keys.\n10. Complete the steps to configure a customer-managed key for encryption of the\nstorage account.\nRemediate from Azure CLI\naz storage account update --name <name of the storage account> --resource-\ngroup <resource group for a storage account> --encryption-key-\nsource=Microsoft.Keyvault --encryption-key-vault <Key Vault URI> --\nencryption-key-name <KeyName> --encryption-key-version <Key Version>\nRemediate from PowerShell\nSet-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage\naccount name> -KeyvaultEncryption -KeyVaultUri <key vault URI> -KeyName <key\nname>",
    "default_value": "By default, encryption type is set to Microsoft-managed keys.",
    "additional_information": "This recommendation is based on the Common Reference Recommendation Ensure\ncritical data is encrypted with customer-managed keys (CMK), from the\nCommon Reference Recommendations > Secrets and Keys > Encryption Key\nManagement > Customer Managed Keys section.",
    "detection_commands": [
      "az monitor diagnostic-settings subscription list --subscription <subscription",
      "az storage account list --query \"[?name=='<Storage Account Name>']\"",
      "Get-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage"
    ],
    "remediation_commands": [
      "az storage account update --name <name of the storage account> --resource-",
      "Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-",
      "best-practices#protect-data-at-rest",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-",
      "when-required",
      "3. https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-",
      "log?tabs=cli#managing-legacy-log-profiles"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 204,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "classification",
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
    "cis_id": "6.1.1.4",
    "title": "Ensure that logging for Azure Key Vault is 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Enable AuditEvent logging for key vault instances to ensure interactions with key vaults\nare logged and available.",
    "rationale": "Monitoring how and when key vaults are accessed, and by whom, enables an audit trail\nof interactions with confidential information, keys, and certificates managed by Azure\nKey Vault. Enabling logging for Key Vault saves information in a user provided\ndestination of either an Azure storage account or Log Analytics workspace. The same\ndestination can be used for collecting logs for multiple Key Vaults.",
    "audit": "Audit from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, under Monitoring, go to Diagnostic settings.\n3. Click Edit setting next to a diagnostic setting.\n4. Ensure that a destination is configured.\n5. Under Category groups, ensure that audit and allLogs are checked.\nAudit from Azure CLI\nList all key vaults\naz keyvault list\nFor each keyvault id\naz monitor diagnostic-settings list --resource <id>\nEnsure that storageAccountId reflects your desired destination and that\ncategoryGroup and enabled are set as follows in the sample outputs below.\n\"logs\": [\n{\n\"categoryGroup\": \"audit\",\n\"enabled\": true,\n},\n{\n\"categoryGroup\": \"allLogs\",\n\"enabled\": true,\n}\nAudit from PowerShell\nList the key vault(s) in the subscription\nGet-AzKeyVault\nFor each key vault, run the following:\nGet-AzDiagnosticSetting -ResourceId <key_vault_id>\nEnsure that StorageAccountId, ServiceBusRuleId, MarketplacePartnerId, or\nWorkspaceId is set as appropriate. Also, ensure that enabled is set to true, and that\ncategoryGroup reflects both audit and allLogs category groups.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: cf820ca0-f99e-4f3e-84fb-66e913812d21 - Name: 'Resource logs in\nKey Vault should be enabled'",
    "expected_response": "4. Ensure that a destination is configured.\n5. Under Category groups, ensure that audit and allLogs are checked.\nEnsure that storageAccountId reflects your desired destination and that\nEnsure that StorageAccountId, ServiceBusRuleId, MarketplacePartnerId, or\nWorkspaceId is set as appropriate. Also, ensure that enabled is set to true, and that\nKey Vault should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Key vaults.\n2. Select a Key vault.\n3. Under Monitoring, select Diagnostic settings.\n4. Click Edit setting to update an existing diagnostic setting, or Add diagnostic\nsetting to create a new one.\n5. If creating a new diagnostic setting, provide a name.\n6. Configure an appropriate destination.\n7. Under Category groups, check audit and allLogs.\n8. Click Save.\nRemediate from Azure CLI\nTo update an existing Diagnostic Settings\naz monitor diagnostic-settings update --name \"<diagnostic_setting_name>\" --\nresource <key_vault_id>\nTo create a new Diagnostic Settings\naz monitor diagnostic-settings create --name \"<diagnostic_setting_name>\" --\nresource <key_vault_id> --logs\n\"[{category:audit,enabled:true},{category:allLogs,enabled:true}]\" --metrics\n\"[{category:AllMetrics,enabled:true}]\" <[--event-hub <event_hub_ID> --event-\nhub-rule <event_hub_auth_rule_ID> | --storage-account <storage_account_ID> |-\n-workspace <log_analytics_workspace_ID> | --marketplace-partner-id\n<solution_resource_ID>]>\nRemediate from PowerShell\nCreate the Log settings object\n$logSettings = @()\n$logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -\nCategory audit\n$logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -\nCategory allLogs\nCreate the Metric settings object\n$metricSettings = @()\n$metricSettings += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true\n-Category AllMetrics\nCreate the Diagnostic Settings for each Key Vault\nNew-AzDiagnosticSetting -Name \"<diagnostic_setting_name>\" -ResourceId\n<key_vault_id> -Log $logSettings -Metric $metricSettings [-StorageAccountId\n<storage_account_ID> | -EventHubName <event_hub_name> -\nEventHubAuthorizationRuleId <event_hub_auth_rule_ID> | -WorkSpaceId <log\nanalytics workspace ID> | -MarketPlacePartnerId <full resource ID for third-\nparty solution>]",
    "default_value": "By default, Diagnostic AuditEvent logging is not enabled for Key Vault instances.",
    "additional_information": "DEPRECATION WARNING\nRetention rules for Key Vault logging is being migrated to Azure Storage Lifecycle\nManagement. Retention rules should be set based on the needs of your organization\nand security or compliance frameworks. Please visit https://learn.microsoft.com/en-\nus/azure/azure-monitor/essentials/migrate-to-azure-storage-lifecycle-policy?tabs=portal\nfor detail on migrating your retention rules.\nMicrosoft has provided the following deprecation timeline:\nMarch 31, 2023 – The Diagnostic Settings Storage Retention feature will no longer be\navailable to configure new retention rules for log data. This includes using the portal,\nCLI PowerShell, and ARM and Bicep templates. If you have configured retention\nsettings, you'll still be able to see and change them in the portal.\nMarch 31, 2024 – You will no longer be able to use the API (CLI, Powershell, or\ntemplates), or Azure portal to configure retention setting unless you're changing them to\n0. Existing retention rules will still be respected.\nSeptember 30, 2025 – All retention functionality for the Diagnostic Settings Storage\nRetention feature will be disabled across all environments.",
    "detection_commands": [
      "az keyvault list",
      "az monitor diagnostic-settings list --resource <id>",
      "Get-AzKeyVault",
      "Get-AzDiagnosticSetting -ResourceId <key_vault_id>"
    ],
    "remediation_commands": [
      "az monitor diagnostic-settings update --name \"<diagnostic_setting_name>\" --",
      "az monitor diagnostic-settings create --name \"<diagnostic_setting_name>\" --",
      "Create the Log settings object $logSettings = @() $logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -",
      "$logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -",
      "Create the Metric settings object $metricSettings = @() $metricSettings += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true",
      "Create the Diagnostic Settings for each Key Vault New-AzDiagnosticSetting -Name \"<diagnostic_setting_name>\" -ResourceId"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/howto-logging",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-8-ensure-security-of-key-and-certificate-repository",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 208,
    "dspm_relevant": true,
    "dspm_categories": [
      "logging",
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
    "cis_id": "6.1.1.5",
    "title": "Ensure that Network Security Group Flow logs are captured and sent to Log Analytics",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Ensure that network flow logs are captured and fed into a central log analytics\nworkspace.\nRetirement Notice\nOn September 30, 2027, network security group (NSG) flow logs will be retired. As of\nJune 30, 2025, creating new NSG flow logs is no longer possible. Azure recommends\nmigrating to virtual network flow logs. Review https://azure.microsoft.com/en-\nus/updates?id=Azure-NSG-flow-logs-Retirement for more information.\nFor virtual network flow logs, consider applying the recommendation, Ensure that\nvirtual network flow logs are captured and sent to Log Analytics, from\nthis section.",
    "rationale": "Network Flow Logs provide valuable insight into the flow of traffic around your network\nand feed into both Azure Monitor and Azure Sentinel (if in use), permitting the\ngeneration of visual flow diagrams to aid with analyzing for lateral movement, etc.",
    "impact": "The impact of configuring NSG Flow logs is primarily one of cost and configuration. If\ndeployed, it will create storage accounts that hold minimal amounts of data on a 5-day\nlifecycle before feeding to Log Analytics Workspace. This will increase the amount of\ndata stored and used by Azure Monitor.",
    "audit": "Audit from Azure Portal\n1. Navigate to Network Watcher.\n2. Under Logs, select Flow logs.\n3. Click Add filter.\n4. From the Filter drop-down, select Flow log type.\n5. From the Value drop-down, check Network security group only.\n6. Click Apply.\n7. Ensure that at least one network security group flow log is listed and is\nconfigured to send logs to a Log Analytics Workspace.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 27960feb-a23c-4577-8d36-ef8b5f35e0be - Name: 'All flow log\nresources should be in enabled state'\n• Policy ID: c251913d-7d24-4958-af87-478ed3b9ba41 - Name: 'Flow logs should\nbe configured for every network security group'\n• Policy ID: 4c3c6c5f-0d47-4402-99b8-aa543dd8bcee - Name: 'Flow logs should\nbe configured for every virtual network'",
    "expected_response": "7. Ensure that at least one network security group flow log is listed and is\nresources should be in enabled state'\n• Policy ID: c251913d-7d24-4958-af87-478ed3b9ba41 - Name: 'Flow logs should\n• Policy ID: 4c3c6c5f-0d47-4402-99b8-aa543dd8bcee - Name: 'Flow logs should",
    "remediation": "As of June 30, 2025, creating new NSG flow logs is no longer possible. Azure\nrecommends migrating to virtual network flow logs. Consider applying the\nrecommendation, Ensure that virtual network flow logs are captured and\nsent to Log Analytics, from this section.",
    "default_value": "By default Network Security Group logs are not sent to Log Analytics.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-tutorial",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-4-enable-network-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 212,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.1.6",
    "title": "Ensure that logging for Azure AppService 'HTTP logs' is enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Deploy NetFlow Collection on Networking",
    "description": "Enable AppServiceHTTPLogs diagnostic log category for Azure App Service instances\nto ensure all http requests are captured and centrally logged.",
    "rationale": "Capturing web requests can be important supporting information for security analysts\nperforming monitoring and incident response activities. Once logging, these logs can be\ningested into SIEM or other central aggregation point for the organization.",
    "impact": "Log consumption and processing will incur additional cost.",
    "audit": "Audit from Azure Portal\n1. Go to App Services.\nFor each App Service:\n2. Under Monitoring, go to Diagnostic settings.\n3. Ensure a diagnostic setting exists that logs HTTP logs to a destination aligned to\nyour environment's approach to log consumption (event hub, storage account,\netc. dependent on what is consuming the logs such as SIEM or other log\naggregation utility).\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 91a78b24-f231-4a8a-8da9-02c35b2b6510 - Name: 'App Service apps\nshould have resource logs enabled'\n• Policy ID: d639b3af-a535-4bef-8dcf-15078cddf5e2 - Name: 'App Service app\nslots should have resource logs enabled'",
    "expected_response": "3. Ensure a diagnostic setting exists that logs HTTP logs to a destination aligned to\nshould have resource logs enabled'\nslots should have resource logs enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to App Services.\nFor each App Service:\n2. Under Monitoring, go to Diagnostic settings.\n3. To update an existing diagnostic setting, click Edit setting against the setting.\nTo create a new diagnostic setting, click Add diagnostic setting and provide\na name for the new setting.\n4. Check the checkbox next to HTTP logs.\n5. Configure a destination based on your specific logging consumption capability\n(for example Stream to an event hub and then consuming with SIEM integration\nfor Event Hub logging).\n6. Click Save.",
    "default_value": "Not configured.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 214,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.1.7",
    "title": "Ensure that virtual network flow logs are captured and sent to Log Analytics",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Log all URL requests",
    "description": "Ensure that virtual network flow logs are captured and fed into a central log analytics\nworkspace.",
    "rationale": "Virtual network flow logs provide critical visibility into traffic patterns. Sending logs to a\nLog Analytics workspace enables centralized analysis, correlation, and alerting for\nfaster threat detection and response.",
    "impact": "• Virtual network flow logs are charged per gigabyte of network flow logs collected\nand come with a free tier of 5 GB/month per subscription.\n• If traffic analytics is enabled with virtual network flow logs, traffic analytics pricing\napplies at per gigabyte processing rates.\n• The storage of logs is charged separately.",
    "audit": "Audit from Azure Portal\n1. Go to Network Watcher.\n2. Under Logs, select Flow logs.\n3. Click Add filter.\n4. From the Filter drop-down menu, select Flow log type.\n5. From the Value drop-down menu, check Virtual network only.\n6. Click Apply.\n7. Ensure that at least one virtual network flow log is listed and is configured to\nsend logs to a Log Analytics Workspace.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 2f080164-9f4d-497e-9db6-416dc9f7b48a - Name: 'Network Watcher\nflow logs should have traffic analytics enabled'\n• Policy ID: 4c3c6c5f-0d47-4402-99b8-aa543dd8bcee - Name: 'Audit flow logs\nconfiguration for every virtual network'",
    "expected_response": "7. Ensure that at least one virtual network flow log is listed and is configured to\nflow logs should have traffic analytics enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Network Watcher.\n2. Under Logs, click Flow logs.\n3. Click + Create.\n4. Select a subscription.\n5. Next to Flow log type, select Virtual network.\n6. Click + Select target resource.\n7. Select Virtual network.\n8. Select a virtual network.\n9. Click Confirm selection.\n10. Select a storage account, or create a new storage account.\n11. Set the retention in days for the storage account.\n12. Click Next.\n13. Under Analytics, for Flow logs version, select Version 2.\n14. Check the box next to Enable traffic analytics.\n15. Select a processing interval.\n16. Select a Log Analytics Workspace.\n17. Click Next.\n18. Optionally, add Tags.\n19. Click Review + create.\n20. Click Create.\n21. Repeat steps 1-20 for each subscription or virtual network requiring remediation.",
    "additional_information": "On September 30, 2027, network security group (NSG) flow logs will be retired. As of\nJune 30, 2025, creating new NSG flow logs is no longer possible. Azure recommends\nmigrating to virtual network flow logs. After retirement, traffic analytics using NSG flow\nlogs will no longer be supported, and existing NSG flow log resources will be deleted.\nPreviously collected NSG flow log records will remain available per their retention\npolicies. Review https://azure.microsoft.com/en-us/updates?id=Azure-NSG-flow-logs-\nRetirement for more information.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview",
      "2. https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-cli"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 216,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.1.8",
    "title": "Ensure that a Microsoft Entra diagnostic setting exists to send Microsoft Graph activity logs to an appropriate destination",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Deploy NetFlow Collection on Networking",
    "description": "Ensure that a Microsoft Entra diagnostic setting is configured to send Microsoft Graph\nactivity logs to a suitable destination, such as a Log Analytics workspace, storage\naccount, or event hub. This enables centralized monitoring and analysis of all HTTP\nrequests that the Microsoft Graph service receives and processes for a tenant.",
    "rationale": "Microsoft Graph activity logs provide visibility into HTTP requests made to the Microsoft\nGraph service, helping detect unauthorized access, suspicious activity, and security\nthreats. Configuring diagnostic settings in Microsoft Entra ensures these logs are\ncollected and sent to an appropriate destination for monitoring, analysis, and retention.",
    "impact": "A Microsoft Entra ID P1 or P2 tenant license is required to access the Microsoft Graph\nactivity logs.\nThe amount of data logged and, thus, the cost incurred can vary significantly depending\non the tenant size and the applications in your tenant that interact with the Microsoft\nGraph APIs.\nSee the following pricing calculations for respective services:\n• Log Analytics: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-\nlogs#pricing-model.\n• Azure Storage: https://azure.microsoft.com/en-us/pricing/details/storage/blobs/.\n• Event Hubs: https://azure.microsoft.com/en-us/pricing/details/event-hubs/.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Monitoring, click Diagnostic settings.\n3. Next to each diagnostic setting, click Edit setting, and review the selected log\ncategories and destination details.\n4. Ensure that at least one diagnostic setting is configured to send\nMicrosoftGraphActivityLogs to an appropriate destination.",
    "expected_response": "4. Ensure that at least one diagnostic setting is configured to send",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Monitoring, click Diagnostic settings.\n3. Click + Add diagnostic setting.\n4. Provide a Diagnostic setting name.\n5. Under Logs > Categories, check the box next to\nMicrosoftGraphActivityLogs.\n6. Configure an appropriate destination for the logs.\n7. Click Save.",
    "default_value": "By default, Microsoft Entra diagnostic settings do not exist.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-",
      "configure-diagnostic-settings",
      "2. https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview",
      "3. https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-logs#pricing-",
      "model",
      "4. https://azure.microsoft.com/en-us/pricing/details/storage/blobs/",
      "5. https://azure.microsoft.com/en-us/pricing/details/event-hubs/"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 219,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.1.9",
    "title": "Ensure that a Microsoft Entra diagnostic setting exists to send Microsoft Entra activity logs to an appropriate destination",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Activate audit logging",
    "description": "Ensure that a Microsoft Entra diagnostic setting is configured to send Microsoft Entra\nactivity logs to a suitable destination, such as a Log Analytics workspace, storage\naccount, or event hub. This enables centralized monitoring and analysis of Microsoft\nEntra activity logs.",
    "rationale": "Microsoft Entra activity logs enables you to assess many aspects of your Microsoft\nEntra tenant. Configuring diagnostic settings in Microsoft Entra ensures these logs are\ncollected and sent to an appropriate destination for monitoring, analysis, and retention.",
    "impact": "To export sign-in data, your organization needs an Azure AD P1 or P2 license.\nThe amount of data logged and, thus, the cost incurred can vary significantly depending\non the tenant size.\nSee the following pricing calculations for respective services:\n• Log Analytics: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-\nlogs#pricing-model.\n• Azure Storage: https://azure.microsoft.com/en-us/pricing/details/storage/blobs/.\n• Event Hubs: https://azure.microsoft.com/en-us/pricing/details/event-hubs/.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Monitoring, click Diagnostic settings.\n3. Next to each diagnostic setting, click Edit setting, and review the selected log\ncategories and destination details.\n4. Ensure that at least one diagnostic setting is configured to send the following\nlogs to an appropriate destination:\no AuditLogs\no SignInLogs\no NonInteractiveUserSignInLogs\no ServicePrincipalSignInLogs\no ManagedIdentitySignInLogs\no ProvisioningLogs\no ADFSSignInLogs\no RiskyUsers\no UserRiskEvents\no NetworkAccessTrafficLogs\no RiskyServicePrincipals\no ServicePrincipalRiskEvents\no EnrichedOffice365AuditLogs\no MicrosoftGraphActivityLogs\no RemoteNetworkHealthLogs\no NetworkAccessAlerts",
    "expected_response": "4. Ensure that at least one diagnostic setting is configured to send the following",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Entra ID.\n2. Under Monitoring, click Diagnostic settings.\n3. Click + Add diagnostic setting.\n4. Provide a Diagnostic setting name.\n5. Under Logs > Categories, check the box next to each of the following logs:\no AuditLogs\no SignInLogs\no NonInteractiveUserSignInLogs\no ServicePrincipalSignInLogs\no ManagedIdentitySignInLogs\no ProvisioningLogs\no ADFSSignInLogs\no RiskyUsers\no UserRiskEvents\no NetworkAccessTrafficLogs\no RiskyServicePrincipals\no ServicePrincipalRiskEvents\no EnrichedOffice365AuditLogs\no MicrosoftGraphActivityLogs\no RemoteNetworkHealthLogs\no NetworkAccessAlerts\n6. Configure an appropriate destination for the logs.\n7. Click Save.",
    "default_value": "By default, Microsoft Entra diagnostic settings do not exist.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-",
      "configure-diagnostic-settings",
      "2. https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-access-",
      "activity-logs"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 221,
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
    "cis_id": "6.1.1.10",
    "title": "Ensure that Intune logs are captured and sent to Log Analytics",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Ensure that Intune logs are captured and fed into a central log analytics workspace.",
    "rationale": "Intune includes built-in logs that provide information about your environments. Sending\nlogs to a Log Analytics workspace enables centralized analysis, correlation, and alerting\nfor faster threat detection and response.",
    "impact": "A Microsoft Intune plan is required to access Intune: https://www.microsoft.com/en-\nus/security/business/microsoft-intune-pricing.\nThe amount of data logged and, thus, the cost incurred can vary significantly depending\non the tenant size.\nFor information on Log Analytics workspace costs, visit: https://learn.microsoft.com/en-\nus/azure/azure-monitor/logs/cost-logs.",
    "audit": "Audit from Azure Portal\n1. Go to Intune.\n2. Click Reports.\n3. Under Azure monitor, click Diagnostic settings.\n4. Next to each diagnostic setting, click Edit setting, and review the selected log\ncategories and destination details.\n5. Ensure that at least one diagnostic setting is configured to send the following\nlogs to a Log Analytics workspace:\no AuditLogs\no OperationalLogs\no DeviceComplianceOrg\no Devices\no Windows365AuditLogs",
    "expected_response": "5. Ensure that at least one diagnostic setting is configured to send the following",
    "remediation": "Remediate from Azure Portal\n1. Go to Intune.\n2. Click Reports.\n3. Under Azure monitor, click Diagnostic settings.\n4. Click + Add diagnostic setting.\n5. Provide a Diagnostic setting name.\n6. Under Logs > Categories, check the box next to each of the following logs:\no AuditLogs\no OperationalLogs\no DeviceComplianceOrg\no Devices\no Windows365AuditLogs\n7. Under Destination details, check the box next to Send to Log Analytics\nworkspace.\n8. Select a Subscription.\n9. Select a Log Analytics workspace.\n10. Click Save.",
    "default_value": "By default, Intune diagnostic settings do not exist.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/review-logs-",
      "using-azure-monitor",
      "2. https://www.microsoft.com/en-us/security/business/microsoft-intune-pricing",
      "3. https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-logs"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 224,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.1",
    "title": "Ensure that Activity Log Alert exists for Create Policy Assignment",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Activate audit logging",
    "description": "Create an activity log alert for the Create Policy Assignment event.",
    "rationale": "Monitoring for create policy assignment events gives insight into changes done in\n\"Azure policy - assignments\" and can reduce the time it takes to detect unsolicited\nchanges.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Authorization/policyAssignments/write.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Create policy assignment' and does not filter on Level, Status or\nCaller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription ID> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Authorization/policyAssignments/write in the output. If it's\nmissing, generate a finding.\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Authorization/policyAssignments/write\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nIf the output is empty, an alert rule for Create Policy Assignments is not\nconfigured.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: c5447c04-a4d7-4ba8-a263-c9ee321a6858 - Name: 'An activity log\nalert should exist for specific Policy operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Authorization/policyAssignments/write in the output. If it's\n{$_.ConditionAllOf.Equal -match\nIf the output is empty, an alert rule for Create Policy Assignments is not\nalert should exist for specific Policy operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Create policy assignment (Policy assignment).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Authorization/policyAssignments/write> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription ID> --action-group <action group ID>\nRemediate from PowerShell\nCreate the conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Authorization/policyAssignments/write -Field operationName\nGet the Action Group information and store it in a variable, then create a new Action\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope variable.\n$scope = \"/subscriptions/<subscription ID>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Authorization/policyAssignments/write\nNew-AzActivityLogAlert -Name \"<activity alert rule name>\" -ResourceGroupName\n\"<resource group name>\" -Condition $conditions -Scope $scope -Location global\n-Action $actionObject -Subscription <subscription ID> -Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription ID> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope variable. $scope = \"/subscriptions/<subscription ID>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity alert rule name>\" -ResourceGroupName \"<resource group name>\" -Condition $conditions -Scope $scope -Location global"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation",
      "6. https://learn.microsoft.com/en-us/rest/api/policy/policy-assignments",
      "7. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-log-",
      "alert-rule"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 228,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.2",
    "title": "Ensure that Activity Log Alert exists for Delete Policy Assignment",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the Delete Policy Assignment event.",
    "rationale": "Monitoring for delete policy assignment events gives insight into changes done in \"azure\npolicy - assignments\" and can reduce the time it takes to detect unsolicited changes.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Authorization/policyAssignments/delete.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Delete policy assignment' and does not filter on Level, Status or\nCaller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription ID> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Authorization/policyAssignments/delete in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Authorization/policyAssignments/delete\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: c5447c04-a4d7-4ba8-a263-c9ee321a6858 - Name: 'An activity log\nalert should exist for specific Policy operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Authorization/policyAssignments/delete in the output\n{$_.ConditionAllOf.Equal -match\nalert should exist for specific Policy operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Delete policy assignment (Policy assignment).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Authorization/policyAssignments/delete and\nlevel=<verbose | information | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the conditions object\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Authorization/policyAssignments/delete -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Action\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope variable.\n$scope = \"/subscriptions/<subscription id>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Authorization/policyAssignments/delete.\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "additional_information": "This log alert also applies for Azure Blueprints.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription ID> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the conditions object $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope variable. $scope = \"/subscriptions/<subscription id>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "2. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation",
      "5. https://azure.microsoft.com/en-us/products/blueprints/"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 232,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.3",
    "title": "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an Activity Log Alert for the Create or Update Network Security Group event.",
    "rationale": "Monitoring for Create or Update Network Security Group events gives insight into\nnetwork access changes and may reduce the time it takes to detect suspicious activity.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Network/networkSecurityGroups/write.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Create or Update Network Security Group' and does not filter on\nLevel, Status or Caller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription ID> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Network/networkSecurityGroups/write in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Network/networkSecurityGroups/write\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: b954148f-4c11-4c38-8221-be76711e194a - Name: 'An activity log\nalert should exist for specific Administrative operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Network/networkSecurityGroups/write in the output\n{$_.ConditionAllOf.Equal -match\nalert should exist for specific Administrative operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Create or Update Network Security Group (Network Security\nGroup).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Network/networkSecurityGroups/write and level=verbose\n--scope \"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\"\n--subscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Network/networkSecurityGroups/write -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription id>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Network/networkSecurityGroups/write\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription ID> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription id>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 236,
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
    "cis_id": "6.1.2.4",
    "title": "Ensure that Activity Log Alert exists for Delete Network Security Group",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the Delete Network Security Group event.",
    "rationale": "Monitoring for \"Delete Network Security Group\" events gives insight into network access\nchanges and may reduce the time it takes to detect suspicious activity.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Network/networkSecurityGroups/delete.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Delete Network Security Group' and does not filter on Level,\nStatus or Caller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription ID> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Network/networkSecurityGroups/delete in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Network/networkSecurityGroups/delete\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: b954148f-4c11-4c38-8221-be76711e194a - Name: 'An activity log\nalert should exist for specific Administrative operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Network/networkSecurityGroups/delete in the output\n{$_.ConditionAllOf.Equal -match\nalert should exist for specific Administrative operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Delete Network Security Group (Network Security Group).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Network/networkSecurityGroups/delete and\nlevel=<verbose | information | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Network/networkSecurityGroups/delete -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription id>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Network/networkSecurityGroups/delete\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription ID> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription id>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 240,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.5",
    "title": "Ensure that Activity Log Alert exists for Create or Update Security Solution",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the Create or Update Security Solution event.",
    "rationale": "Monitoring for Create or Update Security Solution events gives insight into changes to\nthe active security solutions and may reduce the time it takes to detect suspicious\nactivity.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Security/securitySolutions/write.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Create or Update Security Solutions' and does not filter on\nLevel, Status or Caller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription Id> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Security/securitySolutions/write in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Security/securitySolutions/write\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 3b980d31-7904-4bb7-8575-5665739a8052 - Name: 'An activity log\nalert should exist for specific Security operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Security/securitySolutions/write in the output\n{$_.ConditionAllOf.Equal -match\nalert should exist for specific Security operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Create or Update Security Solutions (Security Solutions).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Security/securitySolutions/write and level=<verbose |\ninformation | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Security/securitySolutions/write -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription ID>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Security/securitySolutions/write\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription Id> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription ID>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 244,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.6",
    "title": "Ensure that Activity Log Alert exists for Delete Security Solution",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the Delete Security Solution event.",
    "rationale": "Monitoring for Delete Security Solution events gives insight into changes to the active\nsecurity solutions and may reduce the time it takes to detect suspicious activity.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Security/securitySolutions/delete.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Delete Security Solutions' and does not filter on Level, Status or\nCaller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription Id> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Security/securitySolutions/delete in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Security/securitySolutions/delete\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 3b980d31-7904-4bb7-8575-5665739a8052 - Name: 'An activity log\nalert should exist for specific Security operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Security/securitySolutions/delete in the output\n{$_.ConditionAllOf.Equal -match\nalert should exist for specific Security operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Delete Security Solutions (Security Solutions).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Security/securitySolutions/delete and level=<verbose\n| information | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Security/securitySolutions/delete -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription ID>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Security/securitySolutions/delete\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription Id> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription ID>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 248,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.7",
    "title": "Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the Create or Update SQL Server Firewall Rule event.",
    "rationale": "Monitoring for Create or Update SQL Server Firewall Rule events gives insight into\nnetwork access changes and may reduce the time it takes to detect suspicious activity.",
    "impact": "There will be a substantial increase in log size if there are a large number of\nadministrative actions on a server.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Sql/servers/firewallRules/write.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Create/Update server firewall rule' and does not filter on Level,\nStatus or Caller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription Id> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Sql/servers/firewallRules/write in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Sql/servers/firewallRules/write\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: b954148f-4c11-4c38-8221-be76711e194a - Name: 'An activity log\nalert should exist for specific Administrative operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Sql/servers/firewallRules/write in the output\n{$_.ConditionAllOf.Equal -match\nalert should exist for specific Administrative operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Create/Update server firewall rule (Server Firewall Rule).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Sql/servers/firewallRules/write and level=<verbose |\ninformation | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Sql/servers/firewallRules/write -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription ID>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Sql/servers/firewallRules/write\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription Id> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription ID>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 252,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.8",
    "title": "Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the \"Delete SQL Server Firewall Rule.\"",
    "rationale": "Monitoring for Delete SQL Server Firewall Rule events gives insight into SQL network\naccess changes and may reduce the time it takes to detect suspicious activity.",
    "impact": "There will be a substantial increase in log size if there are a large number of\nadministrative actions on a server.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Sql/servers/firewallRules/delete.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Delete server firewall rule' and does not filter on Level, Status\nor Caller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription Id> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Sql/servers/firewallRules/delete in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Sql/servers/firewallRules/delete\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: b954148f-4c11-4c38-8221-be76711e194a - Name: 'An activity log\nalert should exist for specific Administrative operations'",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Sql/servers/firewallRules/delete in the output\n{$_.ConditionAllOf.Equal -match\nalert should exist for specific Administrative operations'",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Delete server firewall rule (Server Firewall Rule).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Sql/servers/firewallRules/delete and level=<verbose |\ninformation | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Sql/servers/firewallRules/delete -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription ID>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Sql/servers/firewallRules/delete\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription Id> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription ID>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 256,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.9",
    "title": "Ensure that Activity Log Alert exists for Create or Update Public IP Address rule",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the Create or Update Public IP Addresses rule.",
    "rationale": "Monitoring for Create or Update Public IP Address events gives insight into network\naccess changes and may reduce the time it takes to detect suspicious activity.",
    "impact": "There will be a substantial increase in log size if there are a large number of\nadministrative actions on a server.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Network/publicIPAddresses/write.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Create or Update Public Ip Address' and does not filter on Level,\nStatus or Caller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription Id> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Network/publicIPAddresses/write in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Network/publicIPAddresses/write\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Network/publicIPAddresses/write in the output\n{$_.ConditionAllOf.Equal -match",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Create or Update Public Ip Address (Public Ip Address).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Network/publicIPAddresses/write and level=<verbose |\ninformation | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Network/publicIPAddresses/write -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription ID>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Network/publicIPAddresses/write\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription Id> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription ID>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 260,
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
    "cis_id": "6.1.2.10",
    "title": "Ensure that Activity Log Alert exists for Delete Public IP Address rule",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for the Delete Public IP Address rule.",
    "rationale": "Monitoring for Delete Public IP Address events gives insight into network access\nchanges and may reduce the time it takes to detect suspicious activity.",
    "impact": "There will be a substantial increase in log size if there are a large number of\nadministrative actions on a server.",
    "audit": "Audit from Azure Portal\n1. Navigate to the Monitor blade.\n2. Click on Alerts.\n3. In the Alerts window, click on Alert rules.\n4. Ensure an alert rule exists where the Condition column contains Operation\nname=Microsoft.Network/publicIPAddresses/delete.\n5. Click on the Alert Name associated with the previous step.\n6. Ensure the Condition panel displays the text Whenever the Activity Log\nhas an event with Category='Administrative', Operation\nname='Delete Public Ip Address' and does not filter on Level, Status or\nCaller.\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nappropriate personnel in your organization.\nAudit from Azure CLI\naz monitor activity-log alert list --subscription <subscription Id> --query\n\"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"\nLook for Microsoft.Network/publicIPAddresses/delete in the output\nAudit from PowerShell\nGet-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object\n{$_.ConditionAllOf.Equal -match\n\"Microsoft.Network/publicIPAddresses/delete\"}|select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf",
    "expected_response": "4. Ensure an alert rule exists where the Condition column contains Operation\n6. Ensure the Condition panel displays the text Whenever the Activity Log\n7. Ensure the Actions panel displays an Action group is assigned to notify the\nLook for Microsoft.Network/publicIPAddresses/delete in the output\n{$_.ConditionAllOf.Equal -match",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the Monitor blade.\n2. Select Alerts.\n3. Select Create.\n4. Select Alert rule.\n5. Choose a subscription.\n6. Select Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Delete Public Ip Address (Public Ip Address).\n10. Click Apply.\n11. Select the Actions tab.\n12. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n13. Follow the prompts to choose or create an action group.\n14. Select the Details tab.\n15. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n16. Click Review + create.\n17. Click Create.\nRemediate from Azure CLI\naz monitor activity-log alert create --resource-group \"<resource group name>\"\n--condition category=Administrative and\noperationName=Microsoft.Network/publicIPAddresses/delete and level=<verbose |\ninformation | warning | error | critical> --scope\n\"/subscriptions/<subscription ID>\" --name \"<activity log rule name>\" --\nsubscription <subscription id> --action-group <action group ID>\nRemediate from PowerShell\nCreate the Conditions object.\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Administrative -Field category\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Microsoft.Network/publicIPAddresses/delete -Field operationName\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nEqual Verbose -Field level\nRetrieve the Action Group information and store in a variable, then create the Actions\nobject.\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -\nName <action group name>\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object\n$scope = \"/subscriptions/<subscription ID>\"\nCreate the Activity Log Alert Rule for\nMicrosoft.Network/publicIPAddresses/delete\nNew-AzActivityLogAlert -Name \"<activity log alert rule name>\" -\nResourceGroupName \"<resource group name>\" -Condition $conditions -Scope\n$scope -Location global -Action $actionObject -Subscription <subscription ID>\n-Enabled $true",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription Id> --query \"[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}\"",
      "Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --resource-group \"<resource group name>\" --condition category=Administrative and",
      "Create the Conditions object. $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -",
      "$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object $scope = \"/subscriptions/<subscription ID>\" Create the Activity Log Alert Rule for",
      "New-AzActivityLogAlert -Name \"<activity log alert rule name>\" -",
      "$scope -Location global -Action $actionObject -Subscription <subscription ID>"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/updates?id=classic-alerting-monitoring-",
      "retirement",
      "2. https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-",
      "activity-log-alert-rule",
      "3. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/create-or-",
      "update",
      "4. https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-",
      "subscription-id",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 264,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2.11",
    "title": "Ensure that an Activity Log Alert exists for Service Health",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Create an activity log alert for Service Health.",
    "rationale": "Monitoring for Service Health events provides insight into service issues, planned\nmaintenance, security advisories, and other changes that may affect the Azure services\nand regions in use.",
    "impact": "There is no charge for creating activity log alert rules.",
    "audit": "Audit from Azure Portal\n1. Go to Monitor.\n2. Click Alerts.\n3. Click Alert rules.\n4. Ensure an alert rule exists for a subscription with Condition set to Service\nnames=All, Event types=All and Target resource type set to\nSubscription.\n5. If an alert rule is found for step 4, click the name of the alert rule.\n6. Ensure the Actions panel displays an action group configured to notify\nappropriate personnel.\n7. Repeat steps 1-6 for each subscription.\nAudit from Azure CLI\nRun the following command to list activity log alerts:\naz monitor activity-log alert list --subscription <subscription-id>\nFor each activity log alert, run the following command:\naz monitor activity-log alert show --subscription <subscription-id> --\nresource-group <resource-group> --activity-log-alert-name <activity-log-\nalert>\nEnsure an alert exists for ServiceHealth with scopes set to a subscription ID.\nRepeat for each subscription.\nAudit from PowerShell\nRun the following command to locate ServiceHealth alert rules for a subscription:\nGet-AzActivityLogAlert -SubscriptionId <subscription-id> | where-object\n{$_.ConditionAllOf.Equal -match \"ServiceHealth\"} | select-object\nLocation,Name,Enabled,ResourceGroupName,ConditionAllOf\nEnsure that at least one ServiceHealth alert rule is returned.\nRepeat for each subscription.",
    "expected_response": "4. Ensure an alert rule exists for a subscription with Condition set to Service\n6. Ensure the Actions panel displays an action group configured to notify\nEnsure an alert exists for ServiceHealth with scopes set to a subscription ID.\n{$_.ConditionAllOf.Equal -match \"ServiceHealth\"} | select-object\nEnsure that at least one ServiceHealth alert rule is returned.",
    "remediation": "Remediate from Azure Portal\n1. Go to Monitor.\n2. Click Alerts.\n3. Click + Create.\n4. Select Alert rule from the drop-down menu.\n5. Choose a subscription.\n6. Click Apply.\n7. Select the Condition tab.\n8. Click See all signals.\n9. Select Service health.\n10. Click Apply.\n11. Open the drop-down menu next to Event types.\n12. Check the box next to Select all.\n13. Select the Actions tab.\n14. Click Select action groups to select an existing action group, or Create\naction group to create a new action group.\n15. Follow the prompts to choose or create an action group.\n16. Select the Details tab.\n17. Select a Resource group, provide an Alert rule name and an optional Alert\nrule description.\n18. Click Review + create.\n19. Click Create.\n20. Repeat steps 1-19 for each subscription requiring remediation.\nRemediate from Azure CLI\nFor each subscription requiring remediation, run the following command to create a\nServiceHealth alert rule for a subscription:\naz monitor activity-log alert create --subscription <subscription-id> --\nresource-group <resource-group> --name <alert-rule> --condition\ncategory=ServiceHealth and properties.incidentType=Incident --scope\n/subscriptions/<subscription-id> --action-group <action-group>\nRemediate from PowerShell\nCreate the Conditions object:\n$conditions = @()\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nField category -Equal ServiceHealth\n$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -\nField properties.incidentType -Equal Incident\nRetrieve the Action Group information and store in a variable:\n$actionGroup = Get-AzActionGroup -ResourceGroupName <resource-group> -Name\n<action-group>\nCreate the Actions object:\n$actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id\nCreate the Scope object:\n$scope = \"/subscriptions/<subscription-id>\"\nCreate the activity log alert rule:\nNew-AzActivityLogAlert -Name <alert-rule> -ResourceGroupName <resource-group>\n-Condition $conditions -Scope $scope -Location global -Action $actionObject -\nSubscription <subscription-id> -Enabled $true\nRepeat for each subscription requiring remediation.",
    "default_value": "By default, no monitoring alerts are created.",
    "detection_commands": [
      "az monitor activity-log alert list --subscription <subscription-id>",
      "az monitor activity-log alert show --subscription <subscription-id> --",
      "Get-AzActivityLogAlert -SubscriptionId <subscription-id> | where-object"
    ],
    "remediation_commands": [
      "az monitor activity-log alert create --subscription <subscription-id> --",
      "Create the Conditions object: $conditions = @() $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -",
      "$actionGroup = Get-AzActionGroup -ResourceGroupName <resource-group> -Name",
      "Create the Actions object: $actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id Create the Scope object: $scope = \"/subscriptions/<subscription-id>\" Create the activity log alert rule: New-AzActivityLogAlert -Name <alert-rule> -ResourceGroupName <resource-group>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/service-health/overview",
      "2. https://learn.microsoft.com/en-us/azure/service-health/alerts-activity-log-service-",
      "notifications-portal",
      "3. https://azure.microsoft.com/en-us/pricing/details/monitor/#faq",
      "4. https://learn.microsoft.com/en-us/cli/azure/monitor/activity-log/alert",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.monitor/get-",
      "azactivitylogalert",
      "6. https://learn.microsoft.com/en-us/powershell/module/az.monitor/new-",
      "azactivitylogalert"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 268,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "6.1.3.1",
    "title": "Ensure Application Insights are Configured",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Application Insights within Azure act as an Application Performance Monitoring solution\nproviding valuable data into how well an application performs and additional information\nwhen performing incident response. The types of log data collected include application\nmetrics, telemetry data, and application trace logging data providing organizations with\ndetailed information about application activity and application transactions. Both data\nsets help organizations adopt a proactive and retroactive means to handle security and\nperformance related metrics within their modern applications.",
    "rationale": "Configuring Application Insights provides additional data not found elsewhere within\nAzure as part of a much larger logging and monitoring program within an organization's\nInformation Security practice. The types and contents of these logs will act as both a\npotential cost saving measure (application performance) and a means to potentially\nconfirm the source of a potential incident (trace logging). Metrics and Telemetry data\nprovide organizations with a proactive approach to cost savings by monitoring an\napplication's performance, while the trace logging data provides necessary details in a\nreactive incident response scenario by helping organizations identify the potential\nsource of an incident within their application.",
    "impact": "Because Application Insights relies on a Log Analytics Workspace, an organization will\nincur additional expenses when using this service.",
    "audit": "Audit from Azure Portal\n1. Navigate to Application Insights.\n2. Ensure an Application Insights service is configured and exists.\nAudit from Azure CLI\naz monitor app-insights component show --query \"[].{ID:appId, Name:name,\nTenant:tenantId, Location:location, Provisioning_State:provisioningState}\"\nEnsure the above command produces output, otherwise Application Insights has\nnot been configured.\nAudit from PowerShell\nGet-AzApplicationInsights|select\nlocation,name,appid,provisioningState,tenantid",
    "expected_response": "2. Ensure an Application Insights service is configured and exists.\nEnsure the above command produces output, otherwise Application Insights has",
    "remediation": "Remediate from Azure Portal\n1. Navigate to Application Insights.\n2. Under the Basics tab within the PROJECT DETAILS section, select the\nSubscription.\n3. Select the Resource group.\n4. Within the INSTANCE DETAILS, enter a Name.\n5. Select a Region.\n6. Next to Resource Mode, select Workspace-based.\n7. Within the WORKSPACE DETAILS, select the Subscription for the log analytics\nworkspace.\n8. Select the appropriate Log Analytics Workspace.\n9. Click Next:Tags >.\n10. Enter the appropriate Tags as Name, Value pairs.\n11. Click Next:Review+Create.\n12. Click Create.\nRemediate from Azure CLI\naz monitor app-insights component create --app <app name> --resource-group\n<resource group name> --location <location> --kind \"web\" --retention-time\n<INT days to retain logs> --workspace <log analytics workspace ID> --\nsubscription <subscription ID>\nRemediate from PowerShell\nNew-AzApplicationInsights -Kind \"web\" -ResourceGroupName <resource group\nname> -Name <app insights name> -location <location> -RetentionInDays <INT\ndays to retain logs> -SubscriptionID <subscription ID> -WorkspaceResourceId\n<log analytics workspace ID>",
    "default_value": "Application Insights are not enabled by default.",
    "detection_commands": [
      "az monitor app-insights component show --query \"[].{ID:appId, Name:name,",
      "Get-AzApplicationInsights|select"
    ],
    "remediation_commands": [
      "az monitor app-insights component create --app <app name> --resource-group",
      "New-AzApplicationInsights -Kind \"web\" -ResourceGroupName <resource group"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 273,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.4",
    "title": "Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "management_governance",
    "domain": "Management and Governance Services",
    "subdomain": "Activate audit logging",
    "description": "Resource Logs capture activity to the data access plane while the Activity log is a\nsubscription-level log for the control plane. Resource-level diagnostic logs provide\ninsight into operations that were performed within that resource itself; for example,\nreading or updating a secret from a Key Vault. Currently, 95 Azure resources support\nAzure Monitoring (See the more information section for a complete list), including\nNetwork Security Groups, Load Balancers, Key Vault, AD, Logic Apps, and CosmosDB.\nThe content of these logs varies by resource type.\nA number of back-end services were not configured to log and store Resource Logs for\ncertain activities or for a sufficient length. It is crucial that monitoring is correctly\nconfigured to log all relevant activities and retain those logs for a sufficient length of\ntime. Given that the mean time to detection in an enterprise is 240 days, a minimum\nretention period of two years is recommended.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Determining whether resource logging should be\nenabled for specific resources depends on the context and requirements of each\norganization and environment.",
    "rationale": "A lack of monitoring reduces the visibility into the data plane, and therefore an\norganization's ability to detect reconnaissance, authorization attempts or other malicious\nactivity. Unlike Activity Logs, Resource Logs are not enabled by default. Specifically,\nwithout monitoring it would be impossible to tell which entities had accessed a data\nstore that was breached. In addition, alerts for failed attempts to access APIs for Web\nServices or Databases are only possible when logging is enabled.\nThis recommendation's Level 1 profile is dependent upon the free level of retention of\n30 days. More than 30 days retention of resource logs will increase the cost of this\nrecommendation.",
    "impact": "Costs for monitoring varies with Log Volume. Not every resource needs to have logging\nenabled. It is important to determine the security classification of the data being\nprocessed by the given resource and adjust the logging based on which events need to\nbe tracked. This is typically determined by governance and compliance requirements.",
    "audit": "Audit from Azure Portal\nThe specific steps for configuring resources within the Azure console vary depending on\nresource, but typically the steps are:\n1. Go to the resource\n2. Click on Diagnostic settings\n3. In the blade that appears, click \"Add diagnostic setting\"\n4. Configure the diagnostic settings\n5. Click on Save\nAudit from Azure CLI\nList all resources for a subscription\naz resource list --subscription <subscription id>\nFor each resource run the following\naz monitor diagnostic-settings list --resource <resource ID>\nAn empty result means a diagnostic settings is not configured for that resource. An\nerror message means a diagnostic settings is not supported for that resource.\nAudit from PowerShell\nGet a list of resources in a subscription context and store in a variable\n$resources = Get-AzResource\nLoop through each resource to determine if a diagnostic setting is configured or not.\nforeach ($resource in $resources) {$diagnosticSetting = Get-\nAzDiagnosticSetting -ResourceId $resource.id -ErrorAction \"SilentlyContinue\";\nif ([string]::IsNullOrEmpty($diagnosticSetting)) {$message = \"Diagnostic\nSettings not configured for resource: \" + $resource.Name;Write-Output\n$message}else{$diagnosticSetting}}\nA result of Diagnostic Settings not configured for resource: <resource\nname> means a diagnostic settings is not configured for that resource. Otherwise,\nthe output of the above command will show configured Diagnostic Settings for a\nresource.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: cf820ca0-f99e-4f3e-84fb-66e913812d21 - Name: 'Resource logs in\nKey Vault should be enabled'\n• Policy ID: 91a78b24-f231-4a8a-8da9-02c35b2b6510 - Name: 'App Service apps\nshould have resource logs enabled'\n• Policy ID: 428256e6-1fac-4f48-a757-df34c2b3336d - Name: 'Resource logs in\nBatch accounts should be enabled'\n• Policy ID: 057ef27e-665e-4328-8ea3-04b3122bd9fb - Name: 'Resource logs in\nAzure Data Lake Store should be enabled'\n• Policy ID: c95c74d9-38fe-4f0d-af86-0c7d626a315c - Name: 'Resource logs in\nData Lake Analytics should be enabled'\n• Policy ID: 83a214f7-d01a-484b-91a9-ed54470c9a6a - Name: 'Resource logs in\nEvent Hub should be enabled'\n• Policy ID: 383856f8-de7f-44a2-81fc-e5135b5c2aa4 - Name: 'Resource logs in\nIoT Hub should be enabled'\n• Policy ID: 34f95f76-5386-4de7-b824-0d8478470c9d - Name: 'Resource logs in\nLogic Apps should be enabled'\n• Policy ID: b4330a05-a843-4bc8-bf9a-cacce50c67f4 - Name: 'Resource logs in\nSearch services should be enabled'\n• Policy ID: f8d36e2f-389b-4ee4-898d-21aeb69a0f45 - Name: 'Resource logs in\nService Bus should be enabled'\n• Policy ID: f9be5368-9bf5-4b84-9e0a-7850da98bb46 - Name: 'Resource logs in\nAzure Stream Analytics should be enabled'\n• Policy ID: 8a04f872-51e9-4313-97fb-fc1c3543011c - Name: 'Azure Application\nGateway should have Resource logs enabled'",
    "expected_response": "Loop through each resource to determine if a diagnostic setting is configured or not.\nSettings not configured for resource: \" + $resource.Name;Write-Output\nthe output of the above command will show configured Diagnostic Settings for a\nKey Vault should be enabled'\nshould have resource logs enabled'\nBatch accounts should be enabled'\nAzure Data Lake Store should be enabled'\nData Lake Analytics should be enabled'\nEvent Hub should be enabled'\nIoT Hub should be enabled'\nLogic Apps should be enabled'\nSearch services should be enabled'\nService Bus should be enabled'\nAzure Stream Analytics should be enabled'\nGateway should have Resource logs enabled'",
    "remediation": "Azure Subscriptions should log every access and operation for all resources. Logs\nshould be sent to Storage and a Log Analytics Workspace or equivalent third-party\nsystem. Logs should be kept in readily-accessible storage for a minimum of one year,\nand then moved to inexpensive cold storage for a duration of time as necessary. If\nretention policies are set but storing logs in a Storage Account is disabled (for example,\nif only Event Hubs or Log Analytics options are selected), the retention policies have no\neffect. Enable all monitoring at first, and then be more aggressive moving data to cold\nstorage if the volume of data becomes a cost concern.\nRemediate from Azure Portal\nThe specific steps for configuring resources within the Azure console vary depending on\nresource, but typically the steps are:\n1. Go to the resource\n2. Click on Diagnostic settings\n3. In the blade that appears, click \"Add diagnostic setting\"\n4. Configure the diagnostic settings\n5. Click on Save\nRemediate from Azure CLI\nFor each resource, run the following making sure to use a resource appropriate JSON\nencoded category for the --logs option.\naz monitor diagnostic-settings create --name <diagnostic settings name> --\nresource <resource ID> --logs \"[{category:<resource specific\ncategory>,enabled:true,rentention-policy:{enabled:true,days:180}}]\" --metrics\n\"[{category:AllMetrics,enabled:true,retention-\npolicy:{enabled:true,days:180}}]\" <[--event-hub <event hub ID> --event-hub-\nrule <event hub auth rule ID> | --storage-account <storage account ID> |--\nworkspace <log analytics workspace ID> | --marketplace-partner-id <full\nresource ID of third-party solution>]>\nRemediate from PowerShell\nCreate the log settings object\n$logSettings = @()\n$logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -\nRetentionPolicyDay 180 -RetentionPolicyEnabled $true -Category <resource\nspecific category>\n$logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -\nRetentionPolicyDay 180 -RetentionPolicyEnabled $true -Category <resource\nspecific category number 2>\nCreate the metric settings object\n$metricSettings = @()\n$metricSettings += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true\n-RetentionPolicyDay 180 -RetentionPolicyEnabled $true -Category AllMetrics\nCreate the diagnostic setting for a specific resource\nNew-AzDiagnosticSetting -Name \"<diagnostic settings name>\" -ResourceId\n<resource ID> -Log $logSettings -Metric $metricSettings",
    "default_value": "By default, Azure Monitor Resource Logs are 'Disabled' for all resources.",
    "additional_information": "For an up-to-date list of Azure resources which support Azure Monitor, refer to the\n\"Supported Log Categories\" reference.",
    "detection_commands": [
      "az resource list --subscription <subscription id>",
      "az monitor diagnostic-settings list --resource <resource ID>",
      "$resources = Get-AzResource",
      "AzDiagnosticSetting -ResourceId $resource.id -ErrorAction \"SilentlyContinue\";",
      "$message}else{$diagnosticSetting}}",
      "Azure Data Lake Store should be enabled'",
      "Azure Stream Analytics should be enabled'"
    ],
    "remediation_commands": [
      "Azure Subscriptions should log every access and operation for all resources. Logs",
      "az monitor diagnostic-settings create --name <diagnostic settings name> --",
      "Create the log settings object $logSettings = @() $logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -",
      "$logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -",
      "Create the metric settings object $metricSettings = @() $metricSettings += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true",
      "Create the diagnostic setting for a specific resource New-AzDiagnosticSetting -Name \"<diagnostic settings name>\" -ResourceId"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-3-enable-logging-for-security-investigation",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-5-centralize-security-log-management-and-analysis",
      "3. https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/monitor-azure-",
      "resource",
      "4. Supported Log Categories: https://learn.microsoft.com/en-us/azure/azure-",
      "monitor/reference/logs-index",
      "5. Logs and Audit - Fundamentals: https://learn.microsoft.com/en-",
      "us/azure/security/fundamentals/log-audit",
      "6. Collecting Logs: https://learn.microsoft.com/en-us/azure/azure-",
      "monitor/essentials/activity-log",
      "7. Key Vault Logging: https://learn.microsoft.com/en-us/azure/key-",
      "vault/general/logging",
      "8. Monitor Diagnostic Settings: https://learn.microsoft.com/en-",
      "us/cli/azure/monitor/diagnostic-settings",
      "9. Overview of Diagnostic Logs: https://learn.microsoft.com/en-us/azure/azure-",
      "monitor/fundamentals/data-sources",
      "10. Supported Services for Diagnostic Logs: https://learn.microsoft.com/en-",
      "us/azure/azure-monitor/essentials/resource-logs-schema",
      "11. Diagnostic Logs for CDNs: https://learn.microsoft.com/en-us/azure/cdn/cdn-",
      "azure-diagnostic-logs"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 276,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
      "logging",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.5",
    "title": "Ensure that SKU Basic/Consumption is not used on artifacts that need to be monitored (Particularly for Production Workloads)",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Central Log Management",
    "description": "The use of Basic or Free SKUs in Azure whilst cost effective have significant limitations\nin terms of what can be monitored and what support can be realized from Microsoft.\nTypically, these SKUs do not have a service SLA and Microsoft may refuse to provide\nsupport for them. Consequently Basic/Free SKUs should never be used for production\nworkloads.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Determining appropriate SKUs depends on the\ncontext and requirements of each organization and environment.",
    "rationale": "Typically, production workloads need to be monitored and should have an SLA with\nMicrosoft, using Basic SKUs for any deployed product will mean that that these\ncapabilities do not exist.\nThe following resource types should use standard SKUs as a minimum.\n• Public IP Addresses\n• Network Load Balancers\n• REDIS Cache\n• SQL PaaS Databases\n• VPN Gateways",
    "impact": "The impact of enforcing Standard SKUs is twofold\n1. There will be a cost increase\n2. The monitoring and service level agreements will be available and will support\nthe production service.\nAll resources should be either tagged or in separate Management Groups/Subscriptions",
    "audit": "This needs to be audited by Azure Policy (one for each resource type) and denied for\neach artifact that is production.\nAudit from Azure Portal\n1. Open Azure Resource Graph Explorer\n2. Click New query\n3. Paste the following into the query window:\nResources\n| where sku contains 'Basic' or sku contains 'consumption'\n| order by type\n4. Click Run query then evaluate the results in the results window.\n5. Ensure that no production artifacts are returned.\nAudit from Azure CLI\naz graph query -q \"Resources | where sku contains 'Basic' or sku contains\n'consumption' | order by type\"\nAlternatively, to filter on a specific resource group:\naz graph query -q \"Resources | where resourceGroup == '<resourceGroupName>' |\nwhere sku contains 'Basic' or sku contains 'consumption' | order by type\"\nEnsure that no production artifacts are returned.\nAudit from PowerShell\nGet-AzResource | ?{ $_.Sku -EQ \"Basic\"}\nEnsure that no production artifacts are returned.",
    "expected_response": "5. Ensure that no production artifacts are returned.\nEnsure that no production artifacts are returned.",
    "remediation": "Each resource has its own process for upgrading from basic to standard SKUs that\nshould be followed if required.\n• Public IP Address: https://learn.microsoft.com/en-us/azure/virtual-network/ip-\nservices/public-ip-upgrade.\n• Basic Load Balancer: https://learn.microsoft.com/en-us/azure/load-balancer/load-\nbalancer-basic-upgrade-guidance.\n• Azure Cache for Redis: https://learn.microsoft.com/en-us/azure/azure-cache-for-\nredis/cache-how-to-scale.\n• Azure SQL Database: https://learn.microsoft.com/en-us/azure/azure-\nsql/database/scale-resources.\n• VPN Gateway: https://learn.microsoft.com/en-us/azure/vpn-gateway/gateway-\nsku-resize.",
    "default_value": "Policy should enforce standard SKUs for the following artifacts:\n• Public IP Addresses\n• Network Load Balancers\n• REDIS Cache\n• SQL PaaS Databases\n• VPN Gateways",
    "detection_commands": [
      "az graph query -q \"Resources | where sku contains 'Basic' or sku contains 'consumption' | order by type\"",
      "az graph query -q \"Resources | where resourceGroup == '<resourceGroupName>' |",
      "Get-AzResource | ?{ $_.Sku -EQ \"Basic\"}"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://azure.microsoft.com/en-us/support/plans",
      "2. https://azure.microsoft.com/en-us/support/plans/response/",
      "3. https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-",
      "upgrade",
      "4. https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-basic-",
      "upgrade-guidance",
      "5. https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-",
      "scale",
      "6. https://learn.microsoft.com/en-us/azure/azure-sql/database/scale-resources",
      "7. https://learn.microsoft.com/en-us/azure/vpn-gateway/gateway-sku-resize"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 282,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "6.2",
    "title": "Ensure that Resource Locks are set for Mission-Critical Azure Resources",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Ensure Software is Supported by Vendor",
    "description": "Resource Manager Locks provide a way for administrators to lock down Azure\nresources to prevent deletion of, or modifications to, a resource. These locks sit outside\nof the Role Based Access Controls (RBAC) hierarchy and, when applied, will place\nrestrictions on the resource for all users. These locks are very useful when there is an\nimportant resource in a subscription that users should not be able to delete or change.\nLocks can help prevent accidental and malicious changes or deletion.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Determining resources that require resource locks\ndepends on the context and requirements of each organization and environment.",
    "rationale": "As an administrator, it may be necessary to lock a subscription, resource group, or\nresource to prevent other users in the organization from accidentally deleting or\nmodifying critical resources. The lock level can be set to to CanNotDelete or ReadOnly\nto achieve this purpose.\n• CanNotDelete means authorized users can still read and modify a resource, but\nthey cannot delete the resource.\n• ReadOnly means authorized users can read a resource, but they cannot delete\nor update the resource. Applying this lock is similar to restricting all authorized\nusers to the permissions granted by the Reader role.",
    "impact": "There can be unintended outcomes of locking a resource. Applying a lock to a parent\nservice will cause it to be inherited by all resources within. Conversely, applying a lock\nto a resource may not apply to connected storage, leaving it unlocked. Please see the\ndocumentation for further information.",
    "audit": "Audit from Azure Portal\n1. Navigate to the specific Azure Resource or Resource Group.\n2. Click on Locks.\n3. Ensure the lock is defined with name and description, with type Read-only or\nDelete as appropriate.\nAudit from Azure CLI\nReview the list of all locks set currently:\naz lock list --resource-group <resourcegroupname> --resource-name\n<resourcename> --namespace <Namespace> --resource-type <type> --parent \"\"\nAudit from PowerShell\nRun the following command to list all resources.\nGet-AzResource\nFor each resource, run the following command to check for Resource Locks.\nGet-AzResourceLock -ResourceName <Resource Name> -ResourceType <Resource\nType> -ResourceGroupName <Resource Group Name>\nReview the output of the Properties setting. Compliant settings will have the\nCanNotDelete or ReadOnly value.",
    "expected_response": "3. Ensure the lock is defined with name and description, with type Read-only or\nReview the output of the Properties setting. Compliant settings will have the",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the specific Azure Resource or Resource Group.\n2. For each mission critical resource, click on Locks.\n3. Click Add.\n4. Give the lock a name and a description, then select the type, Read-only or\nDelete as appropriate.\n5. Click OK.\nRemediate from Azure CLI\nTo lock a resource, provide the name of the resource, its resource type, and its\nresource group name.\naz lock create --name <LockName> --lock-type <CanNotDelete/Read-only> --\nresource-group <resourceGroupName> --resource-name <resourceName> --resource-\ntype <resourceType>\nRemediate from PowerShell\nGet-AzResourceLock -ResourceName <Resource Name> -ResourceType <Resource\nType> -ResourceGroupName <Resource Group Name> -Locktype <CanNotDelete/Read-\nonly>",
    "default_value": "By default, no locks are set.",
    "detection_commands": [
      "az lock list --resource-group <resourcegroupname> --resource-name",
      "Get-AzResource",
      "Get-AzResourceLock -ResourceName <Resource Name> -ResourceType <Resource"
    ],
    "remediation_commands": [
      "az lock create --name <LockName> --lock-type <CanNotDelete/Read-only> --",
      "Get-AzResourceLock -ResourceName <Resource Name> -ResourceType <Resource"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/azure-resource-",
      "manager/management/lock-resources",
      "2. https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-",
      "zone/design-area/management-platform#inventory-and-visibility-",
      "recommendations",
      "3. https://learn.microsoft.com/en-",
      "us/azure/governance/blueprints/concepts/resource-locking",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-",
      "management#am-4-limit-access-to-asset-management"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 285,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "7.1",
    "title": "Ensure that RDP access from the Internet is evaluated and restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking Services",
    "description": "Network security groups should be periodically evaluated for port misconfigurations.\nWhere RDP is not explicitly required and narrowly configured for resources attached to\na network security group, Internet-level access to Azure resources should be restricted\nor eliminated.",
    "rationale": "The potential security problem with using RDP over the Internet is that attackers can\nuse various brute force techniques to gain access to Azure Virtual Machines. Once the\nattackers gain access, they can use a virtual machine as a launch point for\ncompromising other machines on an Azure Virtual Network or even attack networked\ndevices outside of Azure.",
    "audit": "Audit from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Ensure that no inbound security rule exists that matches the following:\no Port: 3389 or range including 3389\no Protocol: TCP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Repeat steps 1-4 for each network security group.\nTo audit from Azure Resource Graph:\n1. Go to Resource Graph Explorer.\n2. Click New query.\n3. Paste the following into the query window:\n4. resources | where type =~ \"microsoft.network/networksecuritygroups\" |\nproject id, name, securityRule = properties.securityRules | mv-expand\nsecurityRule | extend access = securityRule.properties.access,\ndirection = securityRule.properties.direction, protocol =\nsecurityRule.properties.protocol, destinationPort =\ncase(isempty(securityRule.properties.destinationPortRange),\nsecurityRule.properties.destinationPortRanges,\nsecurityRule.properties.destinationPortRange), sourceAddress =\ncase(isempty(securityRule.properties.sourceAddressPrefix),\nsecurityRule.properties.sourceAddressPrefixes,\nsecurityRule.properties.sourceAddressPrefix) | where access =~ \"Allow\"\nand direction =~ \"Inbound\" and protocol in~ (\"tcp\", \"*\") | mv-expand\ndestinationPort | mv-expand sourceAddress | extend destinationPortMin =\ntoint(split(destinationPort, \"-\")[0]), destinationPortMax =\ntoint(split(destinationPort, \"-\")[-1]) | where (destinationPortMin <=\n3389 and destinationPortMax >= 3389) or destinationPort == \"\" | where\nsourceAddress in~ (\"*\", \"0.0.0.0\", \"internet\", \"any\") or sourceAddress\nendswith \"/0\"\n5. Click Run query.\n6. Ensure that no results are returned.\nAudit from Azure CLI\nList network security groups with non-default security rules:\naz network nsg list --query [*].[name,securityRules]\nEnsure that no network security group has an inbound security rule that matches the\nfollowing:\n\"access\" : \"Allow\"\n\"destinationPortRange\" : \"3389\", \"*\", or \"<range-including-3389>\"\n\"direction\" : \"Inbound\"\n\"protocol\" : \"TCP\" or \"*\"\n\"sourceAddressPrefix\" : \"0.0.0.0/0\", \"Internet\", or \"*\"\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 22730e10-96f6-4aac-ad84-9383d35b5917 - Name: 'Management\nports should be closed on your virtual machines'",
    "expected_response": "4. Ensure that no inbound security rule exists that matches the following:\n6. Ensure that no results are returned.\nEnsure that no network security group has an inbound security rule that matches the\nports should be closed on your virtual machines'",
    "remediation": "Remediate from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Check the box next to any inbound security rule matching:\no Port: 3389 or range including 3389\no Protocol: TCP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Click Delete.\n6. Click Yes.\n7. Repeat steps 1-6 for each network security group requiring remediation.\nRemediate from Azure CLI\nFor each network security group rule requiring remediation, run the following command\nto delete the rule:\naz network nsg rule delete --resource-group <resource-group> --nsg-name\n<network-security-group> --name <rule>",
    "default_value": "By default, RDP access from internet is not enabled.",
    "detection_commands": [
      "az network nsg list --query [*].[name,securityRules]"
    ],
    "remediation_commands": [
      "az network nsg rule delete --resource-group <resource-group> --nsg-name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-",
      "practices#disable-rdpssh-access-to-virtual-machines",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-1-establish-network-segmentation-boundaries",
      "3. Express Route: https://learn.microsoft.com/en-us/azure/expressroute/",
      "4. Site-to-Site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-",
      "site-to-site-portal",
      "5. Point-to-Site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-",
      "site-certificate-gateway"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 289,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "7.2",
    "title": "Ensure that SSH access from the Internet is evaluated and restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_3389_or_destinationport_where",
    "domain": "and destinationPortMax >= 3389) or destinationPort == \"\" | where",
    "subdomain": "Ensure Only Approved Ports, Protocols and",
    "description": "Network security groups should be periodically evaluated for port misconfigurations.\nWhere SSH is not explicitly required and narrowly configured for resources attached to\na network security group, Internet-level access to Azure resources should be restricted\nor eliminated.",
    "rationale": "The potential security problem with using SSH over the Internet is that attackers can\nuse various brute force techniques to gain access to Azure Virtual Machines. Once the\nattackers gain access, they can use a virtual machine as a launch point for\ncompromising other machines on the Azure Virtual Network or even attack networked\ndevices outside of Azure.",
    "audit": "Audit from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Ensure that no inbound security rule exists that matches the following:\no Port: 22 or range including 22\no Protocol: TCP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Repeat steps 1-4 for each network security group.\nTo audit from Azure Resource Graph:\n1. Go to Resource Graph Explorer.\n2. Click New query.\n3. Paste the following into the query window:\n4. resources | where type =~ \"microsoft.network/networksecuritygroups\" |\nproject id, name, securityRule = properties.securityRules | mv-expand\nsecurityRule | extend access = securityRule.properties.access,\ndirection = securityRule.properties.direction, protocol =\nsecurityRule.properties.protocol, destinationPort =\ncase(isempty(securityRule.properties.destinationPortRange),\nsecurityRule.properties.destinationPortRanges,\nsecurityRule.properties.destinationPortRange), sourceAddress =\ncase(isempty(securityRule.properties.sourceAddressPrefix),\nsecurityRule.properties.sourceAddressPrefixes,\nsecurityRule.properties.sourceAddressPrefix) | where access =~ \"Allow\"\nand direction =~ \"Inbound\" and protocol in~ (\"tcp\", \"*\") | mv-expand\ndestinationPort | mv-expand sourceAddress | extend destinationPortMin =\ntoint(split(destinationPort, \"-\")[0]), destinationPortMax =\ntoint(split(destinationPort, \"-\")[-1]) | where (destinationPortMin <=\n22 and destinationPortMax >= 22) or destinationPort == \"\" | where\nsourceAddress in~ (\"*\", \"0.0.0.0\", \"internet\", \"any\") or sourceAddress\nendswith \"/0\"\n5. Click Run query.\n6. Ensure that no results are returned.\nAudit from Azure CLI\nList network security groups with non-default security rules:\naz network nsg list --query [*].[name,securityRules]\nEnsure that no network security group has an inbound security rule that matches the\nfollowing:\n\"access\" : \"Allow\"\n\"destinationPortRange\" : \"22\", \"*\", or \"<range-including-22>\"\n\"direction\" : \"Inbound\"\n\"protocol\" : \"TCP\" or \"*\"\n\"sourceAddressPrefix\" : \"0.0.0.0/0\", \"Internet\", or \"*\"\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 22730e10-96f6-4aac-ad84-9383d35b5917 - Name: 'Management\nports should be closed on your virtual machines'",
    "expected_response": "4. Ensure that no inbound security rule exists that matches the following:\n6. Ensure that no results are returned.\nEnsure that no network security group has an inbound security rule that matches the\nports should be closed on your virtual machines'",
    "remediation": "Remediate from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Check the box next to any inbound security rule matching:\no Port: 22 or range including 22\no Protocol: TCP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Click Delete.\n6. Click Yes.\n7. Repeat steps 1-6 for each network security group requiring remediation.\nRemediate from Azure CLI\nFor each network security group rule requiring remediation, run the following command\nto delete the rule:\naz network nsg rule delete --resource-group <resource-group> --nsg-name\n<network-security-group> --name <rule>",
    "default_value": "By default, SSH access from internet is not enabled.",
    "detection_commands": [
      "az network nsg list --query [*].[name,securityRules]"
    ],
    "remediation_commands": [
      "az network nsg rule delete --resource-group <resource-group> --nsg-name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-",
      "practices#disable-rdpssh-access-to-virtual-machines",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-1-establish-network-segmentation-boundaries",
      "3. Express Route: https://learn.microsoft.com/en-us/azure/expressroute/",
      "4. Site-to-Site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-",
      "site-to-site-portal",
      "5. Point-to-Site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-",
      "site-certificate-gateway"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 293,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "7.3",
    "title": "Ensure that UDP access from the Internet is evaluated and restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_22_or_destinationport_where",
    "domain": "and destinationPortMax >= 22) or destinationPort == \"\" | where",
    "subdomain": "Ensure Only Approved Ports, Protocols and",
    "description": "Network security groups should be periodically evaluated for port misconfigurations.\nWhere UDP is not explicitly required and narrowly configured for resources attached to\na network security group, Internet-level access to Azure resources should be restricted\nor eliminated.",
    "rationale": "The potential security problem with broadly exposing UDP services over the Internet is\nthat attackers can use DDoS amplification techniques to reflect spoofed UDP traffic\nfrom Azure Virtual Machines. The most common types of these attacks exploit exposed\nDNS, NTP, SSDP, SNMP, CLDAP, and other UDP-based services as amplification\nsources to disrupt services on other machines within the Azure Virtual Network, or even\nattack networked devices outside of Azure.",
    "audit": "Audit from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Ensure that no inbound security rule exists that matches the following:\no Port: 53, 123, 161, 389, or 1900, or range including 53, 123, 161, 389, or\n1900, or other vulnerable UDP-based services\no Protocol: UDP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Repeat steps 1-4 for each network security group.\nTo audit from Azure Resource Graph:\n1. Go to Resource Graph Explorer.\n2. Click New query.\n3. Paste the following into the query window:\n4. resources | where type =~ \"microsoft.network/networksecuritygroups\" |\nproject id, name, securityRule = properties.securityRules | mv-expand\nsecurityRule | extend access = securityRule.properties.access,\ndirection = securityRule.properties.direction, protocol =\nsecurityRule.properties.protocol, destinationPort =\ncase(isempty(securityRule.properties.destinationPortRange),\nsecurityRule.properties.destinationPortRanges,\nsecurityRule.properties.destinationPortRange), sourceAddress =\ncase(isempty(securityRule.properties.sourceAddressPrefix),\nsecurityRule.properties.sourceAddressPrefixes,\nsecurityRule.properties.sourceAddressPrefix) | where access =~ \"Allow\"\nand direction =~ \"Inbound\" and protocol in~ (\"udp\", \"*\") | mv-expand\ndestinationPort | mv-expand sourceAddress | extend destinationPortMin =\ntoint(split(destinationPort, \"-\")[0]), destinationPortMax =\ntoint(split(destinationPort, \"-\")[-1]) | where (destinationPortMin <=\n53 and destinationPortMax >= 53) or (destinationPortMin <= 123 and\ndestinationPortMax >= 123) or (destinationPortMin <= 161 and\ndestinationPortMax >= 161) or (destinationPortMin <= 389 and\ndestinationPortMax >= 389) or (destinationPortMin <= 1900 and\ndestinationPortMax >= 1900) or destinationPort == \"\" | where\nsourceAddress in~ (\"*\", \"0.0.0.0\", \"internet\", \"any\") or sourceAddress\nendswith \"/0\"\n5. Click Run query.\n6. Ensure that no results are returned.\nAudit from Azure CLI\nList network security groups with non-default security rules:\naz network nsg list --query [*].[name,securityRules]\nEnsure that no network security group has an inbound security rule that matches the\nfollowing:\n\"access\" : \"Allow\"\n\"destinationPortRange\" : \"53\", \"123\", \"161\", \"389\", \"1900\", \"*\" or \"<range-\nincluding-53-123-161-389-1900-or-other-vulnerable-udp-based-services>\"\n\"direction\" : \"Inbound\"\n\"protocol\" : \"UDP\" or \"*\"\n\"sourceAddressPrefix\" : \"0.0.0.0/0\", \"Internet\", or \"*\"\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 9daedab3-fb2d-461e-b861-71790eead4f6 - Name: 'All network ports\nshould be restricted on network security groups associated to your virtual\nmachine'",
    "expected_response": "4. Ensure that no inbound security rule exists that matches the following:\n6. Ensure that no results are returned.\nEnsure that no network security group has an inbound security rule that matches the\nshould be restricted on network security groups associated to your virtual",
    "remediation": "Remediate from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Check the box next to any inbound security rule matching:\no Port: Port: 53, 123, 161, 389, or 1900, or range including 53, 123, 161,\n389, or 1900, or other vulnerable UDP-based services\no Protocol: UDP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Click Delete.\n6. Click Yes.\n7. Repeat steps 1-6 for each network security group requiring remediation.\nRemediate from Azure CLI\nFor each network security group rule requiring remediation, run the following command\nto delete the rule:\naz network nsg rule delete --resource-group <resource-group> --nsg-name\n<network-security-group> --name <rule>",
    "default_value": "By default, UDP access from internet is not enabled.",
    "detection_commands": [
      "az network nsg list --query [*].[name,securityRules]"
    ],
    "remediation_commands": [
      "az network nsg rule delete --resource-group <resource-group> --nsg-name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-",
      "practices#secure-your-critical-azure-service-resources-to-only-your-virtual-",
      "networks",
      "2. https://learn.microsoft.com/en-us/azure/ddos-protection/fundamental-best-",
      "practices",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-1-establish-network-segmentation-boundaries",
      "4. ExpressRoute: https://learn.microsoft.com/en-us/azure/expressroute/",
      "5. Site-to-site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-",
      "site-to-site-portal",
      "6. Point-to-site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-",
      "site-certificate-gateway"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 297,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "7.4",
    "title": "Ensure that HTTP(S) access from the Internet is evaluated and restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_53_or_destinationportmin_123_and",
    "domain": "and destinationPortMax >= 53) or (destinationPortMin <= 123 and",
    "subdomain": "Ensure Only Approved Ports, Protocols and",
    "description": "Network security groups should be periodically evaluated for port misconfigurations.\nWhere HTTP(S) is not explicitly required and narrowly configured for resources\nattached to a network security group, Internet-level access to Azure resources should\nbe restricted or eliminated.",
    "rationale": "The potential security problem with using HTTP(S) over the Internet is that attackers\ncan use various brute force techniques to gain access to Azure resources. Once the\nattackers gain access, they can use the resource as a launch point for compromising\nother resources within the Azure tenant.",
    "audit": "Audit from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Ensure that no inbound security rule exists that matches the following:\no Port: 80, 443, or range including 80 or 443\no Protocol: TCP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Repeat steps 1-4 for each network security group.\nTo audit from Azure Resource Graph:\n1. Go to Resource Graph Explorer.\n2. Click New query.\n3. Paste the following into the query window:\n4. resources | where type =~ \"microsoft.network/networksecuritygroups\" |\nproject id, name, securityRule = properties.securityRules | mv-expand\nsecurityRule | extend access = securityRule.properties.access,\ndirection = securityRule.properties.direction, protocol =\nsecurityRule.properties.protocol, destinationPort =\ncase(isempty(securityRule.properties.destinationPortRange),\nsecurityRule.properties.destinationPortRanges,\nsecurityRule.properties.destinationPortRange), sourceAddress =\ncase(isempty(securityRule.properties.sourceAddressPrefix),\nsecurityRule.properties.sourceAddressPrefixes,\nsecurityRule.properties.sourceAddressPrefix) | where access =~ \"Allow\"\nand direction =~ \"Inbound\" and protocol in~ (\"tcp\", \"*\") | mv-expand\ndestinationPort | mv-expand sourceAddress | extend destinationPortMin =\ntoint(split(destinationPort, \"-\")[0]), destinationPortMax =\ntoint(split(destinationPort, \"-\")[-1]) | where (destinationPortMin <=\n80 and destinationPortMax >= 80) or (destinationPortMin <= 443 and\ndestinationPortMax >= 443) or destinationPort == \"\" | where\nsourceAddress in~ (\"*\", \"0.0.0.0\", \"internet\", \"any\") or sourceAddress\nendswith \"/0\"\n5. Click Run query.\n6. Ensure that no results are returned.\nAudit from Azure CLI\nList network security groups non-default security rules:\naz network nsg list --query [*].[name,securityRules]\nEnsure that no network security group has an inbound security rule that matches the\nfollowing:\n\"access\" : \"Allow\"\n\"destinationPortRange\" : \"80\", \"443\", \"*\", or \"<range-including-80-or-443>\"\n\"direction\" : \"Inbound\"\n\"protocol\" : \"TCP\" or \"*\"\n\"sourceAddressPrefix\" : \"0.0.0.0/0\", \"Internet\", or \"*\"\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 9daedab3-fb2d-461e-b861-71790eead4f6 - Name: 'All network ports\nshould be restricted on network security groups associated to your virtual\nmachine'",
    "expected_response": "4. Ensure that no inbound security rule exists that matches the following:\n6. Ensure that no results are returned.\nEnsure that no network security group has an inbound security rule that matches the\nshould be restricted on network security groups associated to your virtual",
    "remediation": "Remediate from Azure Portal\n1. Go to Network security groups.\n2. Click the name of a network security group.\n3. Under Settings, click Inbound security rules.\n4. Check the box next to any inbound security rule matching:\no Port: 80, 443, or range including 80 or 443\no Protocol: TCP or Any\no Source: 0.0.0.0/0, Internet, or Any\no Action: Allow\n5. Click Delete.\n6. Click Yes.\n7. Repeat steps 1-6 for each network security group requiring remediation.\nRemediate from Azure CLI\nFor each network security group rule requiring remediation, run the following command\nto delete the rule:\naz network nsg rule delete --resource-group <resource-group> --nsg-name\n<network-security-group> --name <rule>",
    "default_value": "By default, HTTP(S) access from internet is not enabled.",
    "detection_commands": [
      "az network nsg list --query [*].[name,securityRules]"
    ],
    "remediation_commands": [
      "az network nsg rule delete --resource-group <resource-group> --nsg-name"
    ],
    "references": [
      "1. Express Route: https://learn.microsoft.com/en-us/azure/expressroute/",
      "2. Site-to-Site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-",
      "site-to-site-portal",
      "3. Point-to-Site VPN: https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-",
      "site-certificate-gateway",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-1-establish-network-segmentation-boundaries"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 301,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "7.5",
    "title": "Ensure that network security group flow log retention days is set to greater than or equal to 90",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Ensure Only Approved Ports, Protocols and",
    "description": "Network security group flow logs should be enabled and the retention period set to\ngreater than or equal to 90 days.\nRetirement Notice\nOn September 30, 2027, network security group (NSG) flow logs will be retired. As of\nJune 30, 2025, creating new NSG flow logs is no longer possible. Azure recommends\nmigrating to virtual network flow logs. Review https://azure.microsoft.com/en-\nus/updates?id=Azure-NSG-flow-logs-Retirement for more information.\nFor virtual network flow logs, consider applying the recommendation Ensure that\nvirtual network flow log retention days is set to greater than or\nequal to 90 in this section.",
    "rationale": "Flow logs enable capturing information about IP traffic flowing in and out of network\nsecurity groups. Logs can be used to check for anomalies and give insight into\nsuspected breaches.",
    "impact": "This will keep IP traffic logs for 90 days or longer. As a level 2, first determine your need\nto retain data, then apply your selection here. As this is data stored for a longer period,\nyour monthly storage costs will increase depending on your data use.",
    "audit": "Audit from Azure Portal\n1. Go to Network Watcher.\n2. Under Logs, select Flow logs.\n3. Click the name of a network security group flow log.\n4. Ensure that Status is set to On.\n5. Ensure that Retention days is set to 0, 90, or a number greater than 90. If\nRetention days is set to 0, the logs are retained indefinitely with no retention\npolicy.\n6. Repeat steps 1-5 for each network security group flow log.\nAudit from Azure CLI\nRun the following command to list network watchers:\naz network watcher list\nRun the following command to list the name and retention policy of flow logs in a\nnetwork watcher:\naz network watcher flow-log list --location <location> --query\n[*].[name,retentionPolicy]\nFor each network security group flow log, ensure that enabled is set to true, and days\nis set to 0, 90, or a number greater than 90. If days is set to 0, the logs are retained\nindefinitely with no retention policy.",
    "expected_response": "4. Ensure that Status is set to On.\n5. Ensure that Retention days is set to 0, 90, or a number greater than 90. If\nRetention days is set to 0, the logs are retained indefinitely with no retention\nFor each network security group flow log, ensure that enabled is set to true, and days\nis set to 0, 90, or a number greater than 90. If days is set to 0, the logs are retained",
    "remediation": "Remediate from Azure Portal\n1. Go to Network Watcher.\n2. Under Logs, select Flow logs.\n3. Click the name of a network security group flow log.\n4. Set Status to On.\n5. Set Retention days to 0, 90, or a number greater than 90. If Retention days\nis set to 0, the logs are retained indefinitely with no retention policy.\n6. Click Save.\n7. Repeat steps 1-6 for each network security flow log requiring remediation.\nRemediate from Azure CLI\nFor each network security group flow log requiring remediation, run the following\ncommand to enable the flow log and set retention to 0, 90, or a number greater than\n90:\naz network watcher flow-log configure --nsg <network-security-group> --\nenabled true --resource-group <resource-group> --retention <number-of-days> -\n-storage-account <storage-account>",
    "default_value": "By default, network security group flow logs are disabled.",
    "detection_commands": [
      "az network watcher list",
      "az network watcher flow-log list --location <location> --query"
    ],
    "remediation_commands": [
      "az network watcher flow-log configure --nsg <network-security-group> --"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/watcher/flow-log",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-6-configure-log-storage-retention",
      "4. https://learn.microsoft.com/en-gb/azure/network-watcher/nsg-flow-logs-migrate"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 304,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention"
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
    "cis_id": "7.6",
    "title": "Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Ensure adequate storage for logs",
    "description": "Enable Network Watcher for physical regions in Azure subscriptions.",
    "rationale": "Network diagnostic and visualization tools available with Network Watcher help users\nunderstand, diagnose, and gain insights to the network in Azure.",
    "impact": "There are additional costs per transaction to run and store network data. For high-\nvolume networks these charges will add up quickly.",
    "audit": "Audit from Azure Portal\n1. Use the Search bar to search for and click on the Network Watcher service.\n2. From the Overview menu item, review each Network Watcher listed, and ensure\nthat a network watcher is listed for each region in use by the subscription.\nAudit from Azure CLI\naz network watcher list --query\n\"[].{Location:location,State:provisioningState}\" -o table\nThis will list all network watchers and their provisioning state. Ensure\nprovisioningState is Succeeded for each network watcher.\naz account list-locations --query\n\"[?metadata.regionType=='Physical'].{Name:name,DisplayName:regionalDisplayNam\ne}\" -o table\nThis will list all physical regions that exist in the subscription. Compare this list to the\nprevious one to ensure that for each region in use, a network watcher exists with\nprovisioningState set to Succeeded.\nAudit from PowerShell\nGet a list of Network Watchers\nGet-AzNetworkWatcher\nMake sure each watcher is set with the ProvisioningState setting set to Succeeded\nand all Locations that are in use by the subscription are using a watcher.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: b6e2945c-0b7b-40f5-9233-7a5323b5cdc6 - Name: 'Network Watcher\nshould be enabled'",
    "expected_response": "2. From the Overview menu item, review each Network Watcher listed, and ensure\nThis will list all network watchers and their provisioning state. Ensure\nprevious one to ensure that for each region in use, a network watcher exists with\nshould be enabled'",
    "remediation": "Opting out of Network Watcher automatic enablement is a permanent change. Once\nyou opt-out you cannot opt-in without contacting support.\nTo manually enable Network Watcher in each region where you want to use Network\nWatcher capabilities, follow the steps below.\nRemediate from Azure Portal\n1. Use the Search bar to search for and click on the Network Watcher service.\n2. Click Create.\n3. Select a Region from the drop-down menu.\n4. Click Add.\nRemediate from Azure CLI\naz network watcher configure --locations <region> --enabled true --resource-\ngroup <resource_group>",
    "default_value": "Network Watcher is automatically enabled. When you create or update a virtual network\nin your subscription, Network Watcher will be enabled automatically in your Virtual\nNetwork's region. There is no impact to your resources or associated charge for\nautomatically enabling Network Watcher.",
    "detection_commands": [
      "az network watcher list --query \"[].{Location:location,State:provisioningState}\" -o table",
      "az account list-locations --query \"[?metadata.regionType=='Physical'].{Name:name,DisplayName:regionalDisplayNam",
      "Get-AzNetworkWatcher"
    ],
    "remediation_commands": [
      "az network watcher configure --locations <region> --enabled true --resource-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-",
      "overview",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/watcher",
      "3. https://learn.microsoft.com/en-us/cli/azure/network/watcher#az-network-watcher-",
      "configure",
      "4. https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-create",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-4-enable-network-logging-for-security-investigation",
      "6. https://azure.microsoft.com/en-us/pricing/details/network-watcher/"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 307,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "7.7",
    "title": "Ensure that Public IP addresses are Evaluated on a Periodic Basis",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Document Traffic Configuration Rules",
    "description": "Public IP Addresses provide tenant accounts with Internet connectivity for resources\ncontained within the tenant. During the creation of certain resources in Azure, a Public\nIP Address may be created. All Public IP Addresses within the tenant should be\nperiodically reviewed for accuracy and necessity.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Evaluating the appropriateness of public IP\naddresses requires a manual review, as it depends on the specific needs and context of\neach organization and environment.",
    "rationale": "Public IP Addresses allocated to the tenant should be periodically reviewed for\nnecessity. Public IP Addresses that are not intentionally assigned and controlled\npresent a publicly facing vector for threat actors and significant risk to the tenant.",
    "audit": "Audit from Azure Portal\n1. Open the All Resources blade\n2. Click on Add Filter\n3. In the Add Filter window, select the following: Filter: Type Operator: Equals\nValue: Public IP address\n4. Click the Apply button\n5. For each Public IP address in the list, use Overview (or Properties) to review the\n\"Associated to:\" field and determine if the associated resource is still relevant\nto your tenant environment. If the associated resource is relevant, ensure that\nadditional controls exist to mitigate risk (e.g. Firewalls, VPNs, Traffic Filtering,\nVirtual Gateway Appliances, Web Application Firewalls, etc.) on all subsequently\nattached resources.\nAudit from Azure CLI\nList all Public IP addresses:\naz network public-ip list\nFor each Public IP address in the output, review the \"name\" property and determine if\nthe associated resource is still relevant to your tenant environment. If the associated\nresource is relevant, ensure that additional controls exist to mitigate risk (e.g. Firewalls,\nVPNs, Traffic Filtering, Virtual Gateway Appliances, Web Application Firewalls, etc.) on\nall subsequently attached resources.",
    "expected_response": "3. In the Add Filter window, select the following: Filter: Type Operator: Equals\nto your tenant environment. If the associated resource is relevant, ensure that\nFor each Public IP address in the output, review the \"name\" property and determine if\nresource is relevant, ensure that additional controls exist to mitigate risk (e.g. Firewalls,",
    "remediation": "Remediation will vary significantly depending on your organization's security\nrequirements for the resources attached to each individual Public IP address.",
    "default_value": "During Virtual Machine and Application creation, a setting may create and attach a\npublic IP.",
    "detection_commands": [
      "az network public-ip list"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/cli/azure/network/public-ip",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 310,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": false
  },
  {
    "cis_id": "7.8",
    "title": "Ensure that virtual network flow log retention days is set to greater than or equal to 90",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Ensure Network Infrastructure is Up-to-Date",
    "description": "Ensure that virtual network flow logs are retained for greater than or equal to 90 days.",
    "rationale": "Virtual network flow logs provide critical visibility into traffic patterns. Logs can be used\nto check for anomalies and give insight into suspected breaches.",
    "impact": "• Virtual network flow logs are charged per gigabyte of network flow logs collected\nand come with a free tier of 5 GB/month per subscription.\n• If traffic analytics is enabled with virtual network flow logs, traffic analytics pricing\napplies at per gigabyte processing rates.\n• The storage of logs is charged separately, and the cost will depend on the\namount of logs and the retention period.",
    "audit": "Audit from Azure Portal\n1. Go to Network Watcher.\n2. Under Logs, select Flow logs.\n3. Click Add filter.\n4. From the Filter drop-down menu, select Flow log type.\n5. From the Value drop-down menu, check Virtual network only.\n6. Click Apply.\n7. Click the name of a virtual network flow log.\n8. Under Storage Account, ensure that Retention days is set to 0, 90, or a\nnumber greater than 90. If Retention days is set to 0, the logs are retained\nindefinitely with no retention policy.\n9. Repeat steps 7 and 8 for each virtual network flow log.\nAudit from Azure CLI\nRun the following command to list network watchers:\naz network watcher list\nRun the following command to list the name and retention policy of flow logs in a\nnetwork watcher:\naz network watcher flow-log list --location <location> --query\n[*].[name,retentionPolicy]\nFor each flow log, ensure that days is set to 0, 90, or a number greater than 90. If days\nis set to 0, the logs are retained indefinitely with no retention policy.\nRepeat for each network watcher.",
    "expected_response": "8. Under Storage Account, ensure that Retention days is set to 0, 90, or a\nnumber greater than 90. If Retention days is set to 0, the logs are retained\nFor each flow log, ensure that days is set to 0, 90, or a number greater than 90. If days\nis set to 0, the logs are retained indefinitely with no retention policy.",
    "remediation": "Remediate from Azure Portal\n1. Go to Network Watcher.\n2. Under Logs, select Flow logs.\n3. Click Add filter.\n4. From the Filter drop-down menu, select Flow log type.\n5. From the Value drop-down menu, check Virtual network only.\n6. Click Apply.\n7. Click the name of a virtual network flow log.\n8. Under Storage Account, set Retention days to 0, 90, or a number greater\nthan 90. If Retention days is set to 0, the logs are retained indefinitely with no\nretention policy.\n9. Repeat steps 7 and 8 for each virtual network flow log requiring remediation.\nRemediate from Azure CLI\nRun the following command update the retention policy for a flow log in a network\nwatcher, setting retention to 0, 90, or a number greater than 90:\naz network watcher flow-log update --location <location> --name <flow-log> --\nretention <number-of-days>\nRepeat for each virtual network flow log requiring remediation.",
    "default_value": "When a virtual network flow log is created using the Azure CLI, retention days is set to 0\nby default. When creating via the Azure Portal, retention days must be specified by the\ncreator.",
    "additional_information": "As network security group flow logs are on the retirement path, Azure recommends\nmigrating to virtual network flow logs.",
    "detection_commands": [
      "az network watcher list",
      "az network watcher flow-log list --location <location> --query"
    ],
    "remediation_commands": [
      "az network watcher flow-log update --location <location> --name <flow-log> --"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-manage",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/watcher/flow-log"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 312,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "7.9",
    "title": "Ensure 'Authentication type' is set to 'Azure Active Directory' only for Azure VPN Gateway point-to-site configuration",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Ensure adequate storage for logs",
    "description": "Enable only 'Azure Active Directory' (Microsoft Entra ID) authentication for Azure VPN\nGateway point-to-site connections.",
    "rationale": "Microsoft Entra ID authentication provides strong security and centralized identity\nmanagement, and reduces risks associated with static credentials and certificate\nmanagement.",
    "impact": "Azure VPN Gateways incur hourly charges, with additional costs for point-to-site\nconnections and data transfer. Pricing varies by SKU and usage. Refer to\nhttps://azure.microsoft.com/en-us/pricing/details/vpn-gateway/ for details.",
    "audit": "Audit from Azure Portal\n1. Go to Virtual network gateways.\n2. Under VPN gateway, click VPN gateways.\n3. Click the name of a VPN gateway.\n4. Under Settings, click Point-to-site configuration.\n5. Ensure Authentication type is set to Azure Active Directory only.\n6. Repeat steps 1-5 for each VPN gateway.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 21a6bc25-125e-4d13-b82d-2e19b7208ab7 - Name: 'VPN gateways\nshould use only Azure Active Directory (Azure AD) authentication for point-to-site\nusers'",
    "expected_response": "5. Ensure Authentication type is set to Azure Active Directory only.\nshould use only Azure Active Directory (Azure AD) authentication for point-to-site",
    "remediation": "Remediate from Azure Portal\n1. Go to Virtual network gateways.\n2. Under VPN gateway, click VPN gateways.\n3. Click the name of a VPN gateway.\n4. Under Settings, click Point-to-site configuration.\n5. Ensure Authentication type click to expand the drop-down menu.\n6. Check the box next to Azure Active Directory, and uncheck the boxes next\nto Azure certificate and RADIUS authentication.\n7. Provide a Tenant, Audience, and Issuer for the Azure Active Directory\nconfiguration.\n8. Click Save.\n9. Repeat steps 1-8 for each VPN gateway requiring remediation.",
    "default_value": "'Authentication type' is selected during creation of point-to-site configuration.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-",
      "vpngateways",
      "2. https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-site-entra-gateway",
      "3. https://learn.microsoft.com/en-us/azure/vpn-gateway/openvpn-azure-ad-tenant"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 315,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "7.10",
    "title": "Ensure Azure Web Application Firewall (WAF) is enabled on Azure Application Gateway",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Azure Web Application Firewall helps protect applications from common exploits and\nattacks by inspecting and filtering incoming traffic.",
    "rationale": "Using Azure Web Application Firewall with Azure Application Gateway reduces\nexposure to external threats by mitigating attacks on public facing applications.",
    "impact": "The WAF V2 tier for Azure Application Gateways costs more than the Basic and\nStandard V2 tiers. Pricing includes a fixed hourly charge plus a charge per capacity-\nunit hour. Refer to https://azure.microsoft.com/en-gb/pricing/details/application-gateway/\nfor details.",
    "audit": "Audit from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. In the Overview, under Essentials, ensure Tier is set to WAF V2.\n4. Repeat steps 1-3 for each application gateway.\nAudit from Azure CLI\nRun the following command to list application gateways:\naz network application-gateway list\nFor each application gateway, run the following command to get the firewall policy id:\naz network application-gateway show --resource-group <resource-group> --name\n<application-gateway> --query firewallPolicy.id\nEnsure a firewall policy id is returned.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 564feb30-bf6a-4854-b4bb-0d2d2d1e6c66 - Name: 'Web Application\nFirewall (WAF) should be enabled for Application Gateway'",
    "expected_response": "3. In the Overview, under Essentials, ensure Tier is set to WAF V2.\nEnsure a firewall policy id is returned.\nFirewall (WAF) should be enabled for Application Gateway'",
    "remediation": "Note: Basic tier application gateways cannot be upgraded to the WAF V2 tier. Create a\nnew WAF V2 tier application gateway to replace a Basic tier application gateway.\nRemediate from Azure Portal\nTo remediate a Standard V2 tier application gateway:\n1. Go to Application gateways.\n2. Click Add filter.\n3. From the Filter drop-down menu, select SKU size.\n4. Check the box next to Standard_v2 only.\n5. Click Apply.\n6. Click the name of an application gateway.\n7. Under Settings, click Web application firewall.\n8. Under Configure, next to Tier, click WAF V2.\n9. Select an existing or create a new WAF policy.\n10. Click Save.\n11. Repeat steps 1-10 for each Standard V2 tier application gateway requiring\nremediation.",
    "default_value": "Azure Web Application Firewall is enabled by default for the WAF V2 tier of Azure\nApplication Gateway. It is not available in the Basic tier. Application gateways deployed\nusing the Standard V2 tier can be upgraded to the WAF V2 tier to enable Azure Web\nApplication Firewall.",
    "detection_commands": [
      "az network application-gateway list",
      "az network application-gateway show --resource-group <resource-group> --name"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/application-gateway/features",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway",
      "3. https://azure.microsoft.com/en-us/pricing/details/application-gateway"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 317,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "7.11",
    "title": "Ensure subnets are associated with network security groups",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Deploy Application Layer Filtering Proxy Server",
    "description": "Protect subnet resources by ensuring subnets are associated with network security\ngroups, which can filter inbound and outbound traffic using security rules.",
    "rationale": "Unprotected subnets can expose resources to unauthorized access.",
    "impact": "Minor administrative effort is required to ensure subnets are associated with network\nsecurity groups. There is no cost to create or use network security groups.",
    "audit": "Audit from Azure Portal\n1. Go to Virtual networks.\n2. Click the name of a virtual network.\n3. Under Settings, click Subnets.\n4. Click the name of a subnet.\n5. Under Security, ensure Network security group is not set to None.\n6. Repeat steps 1-5 for each virtual network and subnet.\nAudit from Azure CLI\nRun the following command to list virtual networks:\naz network vnet list\nFor each virtual network, run the following command to list subnets:\naz network vnet show --resource-group <resource-group> --name <virtual-\nnetwork> --query subnets\nFor each subnet, run the following command to get the network security group id:\naz network vnet subnet show --resource-group <resource-group> --vnet-name\n<virtual-network> --name <subnet> --query networkSecurityGroup.id\nEnsure a network security group id is returned.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: e71308d3-144b-4262-b144-efdc3cc90517 - Name: 'Subnets should\nbe associated with a Network Security Group'",
    "expected_response": "5. Under Security, ensure Network security group is not set to None.\nEnsure a network security group id is returned.\n• Policy ID: e71308d3-144b-4262-b144-efdc3cc90517 - Name: 'Subnets should",
    "remediation": "Remediate from Azure Portal\n1. Go to Virtual networks.\n2. Click the name of a virtual network.\n3. Under Settings, click Subnets.\n4. Click the name of a subnet.\n5. Under Security, next to Network security group, click None to display the\ndrop-down menu.\n6. Select a network security group.\n7. Click Save.\n8. Repeat steps 1-7 for each virtual network and subnet requiring remediation.\nRemediate from Azure CLI\nFor each subnet requiring remediation, run the following command to associate it with a\nnetwork security group:\naz network vnet subnet update --resource-group <resource-group> --vnet-name\n<virtual-network> --name <subnet> --network-security-group <network-security-\ngroup>",
    "default_value": "By default, a subnet is not associated with a network security group.",
    "detection_commands": [
      "az network vnet list",
      "az network vnet show --resource-group <resource-group> --name <virtual-",
      "az network vnet subnet show --resource-group <resource-group> --vnet-name"
    ],
    "remediation_commands": [
      "drop-down menu.",
      "az network vnet subnet update --resource-group <resource-group> --vnet-name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-",
      "overview",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/vnet"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 320,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "7.12",
    "title": "Ensure the SSL policy's 'Min protocol version' is set to 'TLSv1_2' or higher on Azure Application Gateway",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Apply Host-based Firewalls or Port Filtering",
    "description": "The TLS (Transport Layer Security) protocol secures the transmission of data over the\ninternet using standard encryption technology. Application gateways use TLS 1.2 for the\nMin protocol version by default and allow for the use of TLS versions 1.0, 1.1, and\n1.3. NIST strongly suggests the use of TLS 1.2 and recommends the adoption of TLS\n1.3.",
    "rationale": "TLS 1.0 and 1.1 are outdated and vulnerable to security risks. Since TLS 1.2 and TLS\n1.3 provide enhanced security and improved performance, it is highly recommended to\nuse TLS 1.2 or higher whenever possible.",
    "impact": "Using the latest TLS version may affect compatibility with clients and backend services.",
    "audit": "Audit from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Listeners.\n4. Under SSL Policy, ensure Min protocol version is set to TLSv1_2 or higher.\n5. Repeat steps 1-4 for each application gateway.\nAudit from Azure CLI\nRun the following command to list application gateways:\naz network application-gateway list\nFor each application gateway, run the following command to get the SSL policy:\naz network application-gateway ssl-policy show --resource-group <resource-\ngroup> --gateway-name <application-gateway>\nFor each SSL policy, run the following command to get the minProtocolVersion:\naz network application-gateway ssl-policy predefined show --name <ssl-policy>\n--query minProtocolVersion\nEnsure \"TLSv1_2\" or higher is returned.",
    "expected_response": "4. Under SSL Policy, ensure Min protocol version is set to TLSv1_2 or higher.\nEnsure \"TLSv1_2\" or higher is returned.",
    "remediation": "Remediate from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Listeners.\n4. Under SSL Policy, next to the Selected SSL Policy name, click change.\n5. Select an appropriate SSL policy with a Min protocol version of TLSv1_2 or\nhigher.\n6. Click Save.\n7. Repeat steps 1-6 for each application gateway requiring remediation.\nRemediate from Azure CLI\nRun the following command to list available SSL policy options:\naz network application-gateway ssl-policy list-options\nRun the following command to list available predefined SSL policies:\naz network application-gateway ssl-policy predefined list\nFor each application gateway requiring remediation, run the following command to set a\npredefined SSL policy:\naz network application-gateway ssl-policy set --resource-group <resource-\ngroup> --gateway-name <application-gateway> --name <ssl-policy> --policy-type\nPredefined\nAlternatively, run the following command to set a custom SSL policy:\naz network application-gateway ssl-policy set --resource-group <resource-\ngroup> --gateway-name <application-gateway> --policy-type Custom --min-\nprotocol-version <min-protocol-version> --cipher-suites <cipher-suites>",
    "default_value": "Min protocol version is set to TLSv1_2 by default.",
    "detection_commands": [
      "az network application-gateway list",
      "az network application-gateway ssl-policy show --resource-group <resource-",
      "az network application-gateway ssl-policy predefined show --name <ssl-policy> --query minProtocolVersion"
    ],
    "remediation_commands": [
      "az network application-gateway ssl-policy list-options",
      "az network application-gateway ssl-policy predefined list",
      "az network application-gateway ssl-policy set --resource-group <resource-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-",
      "ssl-policy-overview",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 323,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "7.13",
    "title": "Ensure 'HTTP2' is set to 'Enabled' on Azure Application Gateway",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "Enable HTTP/2 for improved performance, efficiency, and security.\nHTTP/2 protocol support is available to clients that connect to application gateway\nlisteners only. Communication with backend server pools is always HTTP/1.1.",
    "rationale": "Enabling HTTP/2 supports use of modern encrypted connections.",
    "impact": "Clients and backend services that do not support HTTP/2 will fall back to HTTP/1.1.",
    "audit": "Audit from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Configuration.\n4. Ensure HTTP2 is set to Enabled.\n5. Repeat steps 1-4 for each application gateway.\nAudit from Azure CLI\nRun the following command to list application gateways:\naz network application-gateway list\nFor each application gateway, run the following command to get the HTTP2 setting:\naz network application-gateway show --resource-group <resource-group> --name\n<application-gateway> --query enableHttp2\nEnsure true is returned.\nAudit from PowerShell\nRun the following command to list application gateways:\nGet-AzApplicationGateway\nRun the following command to get the application gateway in a resource group with a\ngiven name:\n$gateway = Get-AzApplicationGateway -ResourceGroupName <resource-group> -Name\n<application-gateway>\nRun the following command to get the HTTP2 setting:\n$gateway.EnableHttp2\nEnsure True is returned.\nRepeat for each application gateway.",
    "expected_response": "4. Ensure HTTP2 is set to Enabled.\nEnsure true is returned.\nEnsure True is returned.",
    "remediation": "Remediate from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Configuration.\n4. Under HTTP2, click Enabled.\n5. Click Save.\n6. Repeat steps 1-5 for each application gateway requiring remediation.\nRemediate from Azure CLI\nFor each application gateway requiring remediation, run the following command to\nenable HTTP2:\naz network application-gateway update --resource-group <resource-group> --\nname <application-gateway> --http2 Enabled\nRemediate from PowerShell\nRun the following command to get the application gateway in a resource group with a\ngiven name:\n$gateway = Get-AzApplicationGateway -ResourceGroupName <resource-group> -Name\n<application-gateway>\nRun the following command to enable HTTP2:\n$gateway.EnableHttp2 = $true\nRun the following command to apply the update:\nSet-AzApplicationGateway -ApplicationGateway $gateway\nRepeat for each application gateway requiring remediation.",
    "default_value": "HTTP2 is enabled by default.",
    "detection_commands": [
      "az network application-gateway list",
      "az network application-gateway show --resource-group <resource-group> --name",
      "Get-AzApplicationGateway",
      "$gateway = Get-AzApplicationGateway -ResourceGroupName <resource-group> -Name",
      "$gateway.EnableHttp2"
    ],
    "remediation_commands": [
      "az network application-gateway update --resource-group <resource-group> --",
      "$gateway = Get-AzApplicationGateway -ResourceGroupName <resource-group> -Name",
      "$gateway.EnableHttp2 = $true",
      "Set-AzApplicationGateway -ApplicationGateway $gateway"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/application-gateway/features#websocket-",
      "and-http2-traffic",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.network/get-",
      "azapplicationgateway",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.network/set-",
      "azapplicationgateway"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 326,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "7.14",
    "title": "Ensure request body inspection is enabled in Azure Web Application Firewall policy on Azure Application Gateway",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Ensure Software is Supported by Vendor",
    "description": "Enable request body inspection so that the Web Application Firewall evaluates the\ncontents of HTTP message bodies for potential threats.",
    "rationale": "Enabling request body inspection strengthens security by allowing the Web Application\nFirewall to detect common attacks, such as SQL injection and cross-site scripting.",
    "impact": "Minor performance impact on the Web Application Firewall. Additional effort may be\nrequired to monitor findings.",
    "audit": "Audit from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Web application firewall.\n4. Under Associated web application firewall policy, click the policy\nname.\n5. Under Settings, click Policy settings.\n6. Ensure the box next to Enforce request body inspection is checked.\n7. Repeat steps 1-6 for each application gateway.\nAudit from Azure CLI\nRun the following command to list application gateways:\naz network application-gateway list\nFor each application gateway, run the following command to get the firewall policy id:\naz network application-gateway show --resource-group <resource-group> --name\n<application-gateway> --query firewallPolicy.id\nFor each firewall policy, run the following command to get the request body inspection\nsetting:\naz network application-gateway waf-policy show --ids <firewall-policy> --\nquery policySettings.requestBodyCheck\nEnsure true is returned.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: ca85ef9a-741d-461d-8b7a-18c2da82c666 - Name: 'Azure Web\nApplication Firewall on Azure Application Gateway should have request body\ninspection enabled'",
    "expected_response": "6. Ensure the box next to Enforce request body inspection is checked.\nEnsure true is returned.\nApplication Firewall on Azure Application Gateway should have request body",
    "remediation": "Remediate from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Web application firewall.\n4. Under Associated web application firewall policy, click the policy\nname.\n5. Under Settings, click Policy settings.\n6. Check the box next to Enforce request body inspection.\n7. Click Save.\n8. Repeat steps 1-7 for each application gateway and firewall policy requiring\nremediation.\nRemediate from Azure CLI\nFor each firewall policy requiring remediation, run the following command to enable\nrequest body inspection:\naz network application-gateway waf-policy update --ids <firewall-policy> --\npolicy-settings request-body-check=true",
    "default_value": "Request body inspection is enabled by default on Azure Application Gateways with Web\nApplication Firewall.",
    "detection_commands": [
      "az network application-gateway list",
      "az network application-gateway show --resource-group <resource-group> --name",
      "az network application-gateway waf-policy show --ids <firewall-policy> --"
    ],
    "remediation_commands": [
      "az network application-gateway waf-policy update --ids <firewall-policy> --"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-gb/azure/web-application-firewall/ag/application-",
      "gateway-waf-request-size-limits#request-body-inspection",
      "2. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway",
      "3. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-",
      "policy"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 329,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "7.15",
    "title": "Ensure bot protection is enabled in Azure Web Application Firewall policy on Azure Application Gateway",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Deploy Application Layer Filtering Proxy Server",
    "description": "Enable bot protection on the Web Application Firewall to block or log requests from\nknown malicious IP addresses identified through the Microsoft Threat Intelligence feed.",
    "rationale": "Internet traffic from bots can scrape, scan, and search for application vulnerabilities.\nEnabling bot protection stops requests from known malicious IP addresses and\nenhances the overall security of your application by reducing exposure to automated\nattacks.",
    "impact": "May require monitoring to identify false positives.",
    "audit": "Audit from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Web application firewall.\n4. Under Associated web application firewall policy, click the policy\nname.\n5. Under Settings, click Managed rules.\n6. Ensure a Rule Id containing Microsoft_BotManagerRuleSet is listed.\n7. Click the > to expand the row.\n8. Ensure the Status for Malicious Bots is set to Enabled.\n9. Repeat steps 1-8 for each application gateway.\nAudit from Azure CLI\nRun the following command to list application gateways:\naz network application-gateway list\nFor each application gateway, run the following command to get the firewall policy id:\naz network application-gateway show --resource-group <resource-group> --name\n<application-gateway> --query firewallPolicy.id\nFor each firewall policy, run the following command to get the managed rule sets:\naz network application-gateway waf-policy show --ids <firewall-policy> --\nquery managedRules.managedRuleSets\nEnsure a managed rule set with ruleSetType of Microsoft_BotManagerRuleSet is\nreturned, and that no ruleGroupOverrides for ruleGroupName KnownBadBots with\nstate Disabled are returned.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: ebea0d86-7fbd-42e3-8a46-27e7568c2525 - Name: 'Bot Protection\nshould be enabled for Azure Application Gateway WAF'",
    "expected_response": "6. Ensure a Rule Id containing Microsoft_BotManagerRuleSet is listed.\n8. Ensure the Status for Malicious Bots is set to Enabled.\nEnsure a managed rule set with ruleSetType of Microsoft_BotManagerRuleSet is\nshould be enabled for Azure Application Gateway WAF'",
    "remediation": "Remediate from Azure Portal\n1. Go to Application gateways.\n2. Click the name of an application gateway.\n3. Under Settings, click Web application firewall.\n4. Under Associated web application firewall policy, click the policy\nname.\n5. Under Settings, click Managed rules.\n6. Click Assign.\n7. Under Bot Management ruleset, click to display the drop-down menu.\n8. Select a Microsoft_BotManagerRuleSet.\n9. Click Save.\n10. Click X to close the panel.\n11. Repeat steps 1-10 for each application gateway and firewall policy requiring\nremediation.\nRemediate from Azure CLI\nFor each firewall policy requiring remediation, run the following command to enable bot\nprotection:\naz network application-gateway waf-policy managed-rule rule-set add --\nresource-group <resource-group> --policy-name <firewall-policy> --type\nMicrosoft_BotManagerRuleSet --version <0.1|1.0|1.1>",
    "default_value": "Bot protection is disabled by default on Azure Application Gateways with Web\nApplication Firewall.",
    "detection_commands": [
      "az network application-gateway list",
      "az network application-gateway show --resource-group <resource-group> --name",
      "az network application-gateway waf-policy show --ids <firewall-policy> --"
    ],
    "remediation_commands": [
      "az network application-gateway waf-policy managed-rule rule-set add --"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/bot-",
      "protection-overview",
      "2. https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/bot-protection",
      "3. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway",
      "4. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-",
      "policy",
      "5. https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-",
      "policy/managed-rule/rule-set"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 332,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "7.16",
    "title": "Ensure Azure Network Security Perimeter is used to secure Azure platform-as-a-service resources",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "and_destinationportmax_80_or_destinationportmin_443_and",
    "domain": "and destinationPortMax >= 80) or (destinationPortMin <= 443 and",
    "subdomain": "Deploy Application Layer Filtering Proxy Server",
    "description": "Azure Network Security Perimeter creates a logical boundary around Azure platform-as-\na-service (PaaS) resources outside of virtual networks. By default, the network security\nperimeter denies public access to associated PaaS resources, with the ability to define\nexplicit rules for inbound and outbound traffic.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Determining appropriate network security perimeter\nprofiles and resource assignments depends on the context and requirements of each\norganization and environment.",
    "rationale": "Network security perimeter denies public access to PaaS resources, reducing exposure\nand mitigating data exfiltration risks.",
    "impact": "Implementation requires administrative effort to configure and maintain network security\nperimeter profiles and resource assignments. Azure does not list any additional charges\nfor using network security perimeters.",
    "audit": "Audit from Azure Portal\n1. Go to Resource groups.\n2. Click the name of a resource group.\n3. Take note of PaaS resources.\n4. Go to Network Security Perimeters.\n5. Click the name of a network security perimeter.\n6. Under Settings, click Associated resources.\n7. Take note of the associated resources.\n8. Repeat steps 1-7 and ensure each PaaS resource is associated with a network\nsecurity perimeter.\nAudit from Azure CLI\nRun the following command to list resource groups:\naz group list\nFor each resource group, run the following command to list resources:\naz resource list --resource-group <resource-group>\nTake note of PaaS resources.\nFor each resource group, run the following command to list network security perimeters:\naz network perimeter list --resource-group <resource-group>\nFor each network security perimeter, run the following command to list resources:\naz network perimeter association list --resource-group <resource-group> --\nperimeter-name <network-security-perimeter>\nEnsure each PaaS resource is associated with a network security perimeter.",
    "expected_response": "8. Repeat steps 1-7 and ensure each PaaS resource is associated with a network\nEnsure each PaaS resource is associated with a network security perimeter.",
    "remediation": "Remediate from Azure Portal\nCreate and associate PaaS resources with a new network security perimeter:\n1. Go to Network Security Perimeters.\n2. Click + Create.\n3. Select a Subscription and Resource group, provide a Name, select a Region,\nand provide a Profile name.\n4. Click Next.\n5. Click + Add.\n6. Check the box next to a PaaS resource to associate it with the network security\nperimeter.\n7. Click Select.\n8. Click Next.\n9. Configure appropriate Inbound access rules for your organization.\n10. Click Next.\n11. Configure appropriate Outbound access rules for your organization.\n12. Click Review + create.\n13. Click Create.\nAssociate PaaS resources with an existing network security perimeter:\n1. Go to Network Security Perimeters.\n2. Click the name of a network security perimeter.\n3. Under Settings, click Associated resources.\n4. Click + Add.\n5. Select Associate resources with a new profile or Associate resources\nwith an existing profile.\n6. To associate resources with a new profile:\n1. Provide a Name.\n2. Click Next.\n3. Click + Add.\n4. Check the box next to a PaaS resource to associate it with the network\nsecurity perimeter.\n5. Click Select.\n6. Click Next.\n7. Configure appropriate Inbound access rules for your organization.\n8. Click Next.\n9. Configure appropriate Outbound access rules for your organization.\n10. Click Review + create.\n11. Click Create.\n7. To associate resources with an existing profile:\n1. Next to Profile, click Select to display the drop-down menu.\n2. Select a profile.\n3. Click + Add.\n4. Check the box next to a PaaS resource to associate it with the network\nsecurity perimeter.\n5. Click Select.\n6. Click Associate.\nRemediate from Azure CLI\nUse az network perimeter profile list or az network perimeter profile\ncreate to list existing or create a new network security perimeter profile.\nFor each PaaS resource requiring association with a network security perimeter, run the\nfollowing command:\naz network perimeter association create --resource-group <resource-group> --\nperimeter-name <network-security-perimeter> --association-name <association>\n--private-link-resource \"{id:<paas-resource-id>}\" --profile \"{<profile-id>}\"",
    "default_value": "PaaS resources are not associated with a network security perimeter by default.",
    "additional_information": "The current list of resources that can be associated with a network security perimeter\nare as follows:\n• Azure Monitor\n• Azure AI Search\n• Cosmos DB\n• Event Hubs\n• Key Vault\n• SQL DB\n• Storage\n• Azure OpenAI Service\nWhile network security perimeter is generally available, Cosmos DB, SQL DB, and\nAzure OpenAI Service are in public preview.",
    "detection_commands": [
      "az group list",
      "az resource list --resource-group <resource-group>",
      "az network perimeter list --resource-group <resource-group>",
      "az network perimeter association list --resource-group <resource-group> --"
    ],
    "remediation_commands": [
      "Create and associate PaaS resources with a new network security perimeter:",
      "Use az network perimeter profile list or az network perimeter profile create to list existing or create a new network security perimeter profile.",
      "az network perimeter association create --resource-group <resource-group> --"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/private-link/network-security-perimeter-",
      "concepts",
      "2. https://learn.microsoft.com/en-us/azure/private-link/create-network-security-",
      "perimeter-portal",
      "3. https://learn.microsoft.com/en-us/cli/azure/group",
      "4. https://learn.microsoft.com/en-us/cli/azure/resource",
      "5. https://learn.microsoft.com/en-us/cli/azure/network/perimeter"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 335,
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
    "cis_id": "8.1.1.1",
    "title": "Ensure Microsoft Defender CSPM is set to 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Microsoft Defender for Cloud",
    "description": "Enable Microsoft Defender CSPM to continuously assess cloud resources for security\nmisconfigurations, compliance risks, and exposure to threats.",
    "rationale": "Microsoft Defender CSPM provides detailed visibility into the security state of assets\nand workloads and offers hardening guidance to help improve security posture.",
    "impact": "Enabling Microsoft Defender CSPM incurs hourly charges for each billable compute,\ndatabase, and storage resource. This can lead to significant costs in larger\nenvironments. Careful planning and cost analysis are recommended before enabling\nthe service. Refer to https://azure.microsoft.com/en-us/pricing/details/defender-for-\ncloud/#pricing for pricing information.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment settings.\n3. Click the name of a subscription.\n4. Select the Defender plans blade.\n5. Under Cloud Security Posture Management (CSPM), in the row for\nDefender CSPM, ensure Status is set to On.\nAudit from Azure CLI\nRun the following command to get the CloudPosture plan pricing tier:\naz security pricing show --name CloudPosture --query pricingTier\nEnsure \"Standard\" is returned.\nAudit from PowerShell\nRun the following command to get the CloudPosture plan pricing tier:\nGet-AzSecurityPricing -Name CloudPosture | Select-Object PricingTier\nEnsure Standard is returned.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 1f90fc71-a595-4066-8974-d4d0802e8ef0 - Name: 'Microsoft Defender\nCSPM should be enabled'",
    "expected_response": "Defender CSPM, ensure Status is set to On.\nEnsure \"Standard\" is returned.\nEnsure Standard is returned.\nCSPM should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment settings.\n3. Click the name of a subscription.\n4. Select the Defender plans blade.\n5. Under Cloud Security Posture Management (CSPM), in the row for\nDefender CSPM, set the toggle switch for Status to On.\n6. Click Save.\nRemediate from Azure CLI\nRun the following command to enable Defender CSPM:\naz security pricing create --name CloudPosture --tier Standard --extensions\nname=ApiPosture isEnabled=true\nRemediate from PowerShell\nRun the following command to enable Defender CSPM:\nSet-AzSecurityPricing -Name CloudPosture -PricingTier Standard -Extension\n'[{\"name\":\"ApiPosture\",\"isEnabled\":\"True\"}]'",
    "default_value": "Defender CSPM is disabled by default.",
    "detection_commands": [
      "az security pricing show --name CloudPosture --query pricingTier",
      "Get-AzSecurityPricing -Name CloudPosture | Select-Object PricingTier"
    ],
    "remediation_commands": [
      "az security pricing create --name CloudPosture --tier Standard --extensions",
      "Set-AzSecurityPricing -Name CloudPosture -PricingTier Standard -Extension '[{\"name\":\"ApiPosture\",\"isEnabled\":\"True\"}]'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-",
      "security-posture-management",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-cspm-",
      "plan",
      "3. https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/#pricing",
      "4. https://learn.microsoft.com/en-us/cli/azure/security/pricing",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "6. https://learn.microsoft.com/en-us/powershell/module/az.security/set-",
      "azsecuritypricing"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 342,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.2.1",
    "title": "Ensure Microsoft Defender for APIs is set to 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Establish Secure Configurations",
    "description": "Microsoft Defender for APIs offers full lifecycle protection, detection, and response\ncoverage for APIs.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Due to its potentially high cost, Microsoft Defender\nfor APIs may not be suitable for all environments and should be evaluated carefully\nbefore implementation.",
    "rationale": "Microsoft Defender for APIs helps provide visibility into business-critical APIs, assess\nand improve their security posture, prioritize vulnerability remediation, and detect\nthreats in real time.",
    "impact": "Microsoft Defender for APIs uses a tiered pricing model, billed per subscription per\nhour, with each tier allowing a set limit of API calls. In high-traffic environments, this\nmay result in significant or prohibitive costs. Careful evaluation of API usage patterns\nand pricing tiers is essential before enabling the service. Refer to\nhttps://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/#pricing for pricing\ninformation.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment settings.\n3. Click the name of a subscription.\n4. Select the Defender plans blade.\n5. Under Cloud Workload Protection (CWP), in the row for APIs, ensure the\nStatus is set to On.\nAudit from Azure CLI\nRun the following command to get the Api plan pricing tier:\naz security pricing show --name Api --query pricingTier\nEnsure \"Standard\" is returned.\nAudit from PowerShell\nRun the following command to get the Api plan pricing tier:\nGet-AzSecurityPricing -Name Api | Select-Object PricingTier\nEnsure Standard is returned.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 7926a6d1-b268-4586-8197-e8ae90c877d7 - Name: 'Microsoft\nDefender for APIs should be enabled'",
    "expected_response": "5. Under Cloud Workload Protection (CWP), in the row for APIs, ensure the\nStatus is set to On.\nEnsure \"Standard\" is returned.\nEnsure Standard is returned.\nDefender for APIs should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment settings.\n3. Click the name of a subscription.\n4. Select the Defender plans blade.\n5. Under Cloud Workload Protection (CWP), in the row for APIs, set the toggle\nswitch for Status to On.\n6. Select a plan.\n7. Click Save to save the plan selection.\n8. Click Save to enable Defender for APIs.\nRemediate from Azure CLI\nRun the following command to enable Defender for APIs:\naz security pricing create --name Api --tier Standard --subplan <subplan>\nValid subplan values: P1, P2, P3, P4, and P5.\nRemediate from PowerShell\nRun the following command to enable Defender for APIs:\nSet-AzSecurityPricing -Name Api -PricingTier Standard -SubPlan <subplan>\nValid SubPlan values: P1, P2, P3, P4, and P5.",
    "default_value": "Defender for APIs is disabled by default.",
    "detection_commands": [
      "az security pricing show --name Api --query pricingTier",
      "Get-AzSecurityPricing -Name Api | Select-Object PricingTier"
    ],
    "remediation_commands": [
      "az security pricing create --name Api --tier Standard --subplan <subplan>",
      "Set-AzSecurityPricing -Name Api -PricingTier Standard -SubPlan <subplan>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-apis-",
      "introduction",
      "2. https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/#pricing",
      "3. https://learn.microsoft.com/en-us/cli/azure/security/pricing",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.security/set-",
      "azsecuritypricing"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 346,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.3.1",
    "title": "Ensure that Defender for Servers is set to 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Establish a Process to Accept and Address Reports of",
    "description": "The Defender for Servers plan in Microsoft Defender for Cloud reduces security risk by\nproviding actionable recommendations to improve and remediate machine security\nposture. Defender for Servers also helps to protect machines against real-time security\nthreats and attacks.\nDefender for Servers offers two paid plans:\nPlan 1\nThe following components are enabled by default:\n• Log Analytics agent (deprecated)\n• Endpoint protection\nPlan 1 also offers the following components, disabled by default:\n• Vulnerability assessment for machines\n• Guest Configuration agent (preview)\nPlan 2\nThe following components are enabled by default:\n• Log Analytics agent (deprecated)\n• Vulnerability assessment for machines\n• Endpoint protection\n• Agentless scanning for machines\nPlan 2 also offers the following components, disabled by default:\n• Guest Configuration agent (preview)\n• File Integrity Monitoring",
    "rationale": "Enabling Defender for Servers allows for greater defense-in-depth, with threat detection\nprovided by the Microsoft Security Response Center (MSRC).",
    "impact": "Enabling Defender for Servers in Microsoft Defender for Cloud incurs an additional cost\nper resource. Refer to https://azure.microsoft.com/en-us/pricing/details/defender-for-\ncloud/ and https://azure.microsoft.com/en-us/pricing/calculator/ to estimate potential\ncosts.\n• Plan 1: Subscription only\n• Plan 2: Subscription and workspace",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment settings.\n3. Click on a subscription name.\n4. Select Defender plans in the left pane.\n5. Under Cloud Workload Protection (CWP), locate Servers in the Plan\ncolumn, ensure Status is set to On.\n6. Repeat steps 1-5 for each subscription.\nAudit from Azure CLI\nRun the following command:\naz security pricing show -n VirtualMachines --query pricingTier\nIf the tenant is licensed and enabled, the output will indicate Standard.\nAudit from PowerShell\nRun the following command:\nGet-AzSecurityPricing -Name 'VirtualMachines' |Select-Object Name,PricingTier\nIf the tenant is licensed and enabled, the -PricingTier parameter will indicate\nStandard.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 4da35fc9-c9e7-4960-aec9-797fe7d9051d - Name: 'Azure Defender\nfor servers should be enabled'",
    "expected_response": "column, ensure Status is set to On.\nIf the tenant is licensed and enabled, the output will indicate Standard.\nfor servers should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment settings.\n3. Click on a subscription name.\n4. Click Defender plans in the left pane.\n5. Under Cloud Workload Protection (CWP), locate Servers in the Plan\ncolumn, set Status to On.\n6. Select Save.\n7. Repeat steps 1-6 for each subscription requiring remediation.\nRemediate from Azure CLI\nRun the following command:\naz security pricing create -n VirtualMachines --tier 'standard'\nRemediate from PowerShell\nRun the following command:\nSet-AzSecurityPricing -Name 'VirtualMachines' -PricingTier 'Standard'",
    "default_value": "By default, the Defender for Servers plan is disabled.",
    "detection_commands": [
      "az security pricing show -n VirtualMachines --query pricingTier",
      "Get-AzSecurityPricing -Name 'VirtualMachines' |Select-Object Name,PricingTier"
    ],
    "remediation_commands": [
      "az security pricing create -n VirtualMachines --tier 'standard'",
      "Set-AzSecurityPricing -Name 'VirtualMachines' -PricingTier 'Standard'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-servers-",
      "overview",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-",
      "servers",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list",
      "4. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/update",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "6. https://learn.microsoft.com/en-us/powershell/module/az.security/set-",
      "azsecuritypricing",
      "7. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-",
      "security#es-1-use-endpoint-detection-and-response-edr"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 350,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.3.2",
    "title": "Ensure that 'Vulnerability assessment for machines' component status is set to 'On'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "description": "Enable vulnerability assessment for machines on both Azure and hybrid (Arc enabled)\nmachines.",
    "rationale": "Vulnerability assessment for machines scans for various security-related configurations\nand events such as system updates, OS vulnerabilities, and endpoint protection, then\nproduces alerts on threat and vulnerability findings.",
    "impact": "Microsoft Defender for Servers plan 2 licensing is required, and configuration of Azure\nArc introduces complexity beyond this recommendation.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Defender for Cloud\n3. Under Management, select Environment Settings\n4. Select a subscription\n5. Click on Settings & monitoring\n6. Ensure that Vulnerability assessment for machines is set to On\nRepeat the above for any additional subscriptions.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 501541f7-f7e7-4cd6-868c-4190fdad3ac9 - Name: 'A vulnerability\nassessment solution should be enabled on your virtual machines'",
    "expected_response": "6. Ensure that Vulnerability assessment for machines is set to On\nassessment solution should be enabled on your virtual machines'",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Defender for Cloud\n3. Under Management, select Environment Settings\n4. Select a subscription\n5. Click on Settings & Monitoring\n6. Set the Status of Vulnerability assessment for machines to On\n7. Click Continue\nRepeat the above for any additional subscriptions.",
    "default_value": "By default, Automatic provisioning of monitoring agent is set to Off.",
    "additional_information": "While this feature is generally available as of publication, it is not yet available for Azure\nGovernment tenants.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-",
      "components",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/auto-provisioning-",
      "settings/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/auto-provisioning-",
      "settings/create",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-",
      "vulnerability-management#pv-5-perform-vulnerability-assessments"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 354,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.3.3",
    "title": "Ensure that 'Endpoint protection' component status is set to 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "The Endpoint protection component enables Microsoft Defender for Endpoint (formerly\n'Advanced Threat Protection' or 'ATP' or 'WDATP' - see additional info) to communicate\nwith Microsoft Defender for Cloud.\nIMPORTANT: When enabling integration between DfE & DfC it needs to be taken into\naccount that this will have some side effects that may be undesirable.\n1. For server 2019 & above if defender is installed (default for these server SKUs)\nthis will trigger a deployment of the new unified agent and link to any of the\nextended configuration in the Defender portal.\n2. If the new unified agent is required for server SKUs of Win 2016 or Linux and\nlower there is additional integration that needs to be switched on and agents\nneed to be aligned.",
    "rationale": "Microsoft Defender for Endpoint integration brings comprehensive Endpoint Detection\nand Response (EDR) capabilities within Microsoft Defender for Cloud. This integration\nhelps to spot abnormalities, as well as detect and respond to advanced attacks on\nendpoints monitored by Microsoft Defender for Cloud.\nMDE works only with Standard Tier subscriptions.",
    "impact": "Endpoint protection requires licensing and is included in these plans:\n• Defender for Servers plan 1\n• Defender for Servers plan 2",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment Settings.\n4. Click on the subscription name.\n5. Click Settings & monitoring.\n6. Ensure the Status for Endpoint protection is set to On.\nAudit from Azure CLI\nEnsure the output of the below command is True\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X GET -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/<subscriptionID>/providers/Microso\nft.Security/settings?api-version=2022-05-01' | jq '.|.value[] |\nselect(.name==\"WDATP\")'|jq '.properties.enabled'\nAudit from PowerShell\nRun the following commands to login and audit this check\nConnect-AzAccount\nSet-AzContext -Subscription <subscriptionID>\nGet-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq\n\"WDATP\"}\nPowerShell Output - Non-Compliant\nName  Enabled\n----  -------\nWDATP    False\nPowerShell Output - Compliant\nName  Enabled\n----  -------\nWDATP    True",
    "expected_response": "6. Ensure the Status for Endpoint protection is set to On.\nEnsure the output of the below command is True\nPowerShell Output - Non-Compliant\nPowerShell Output - Compliant",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Go to Microsoft Defender for Cloud.\n3. Under Management, select Environment Settings.\n4. Click on the subscription name.\n5. Click Settings & monitoring.\n6. Set the Status for Endpoint protection to On.\n7. Click Continue.\nRemediate from Azure CLI\nUse the below command to enable Standard pricing tier for Storage Accounts\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/<subscriptionID>/providers/Microso\nft.Security/settings/WDATP?api-version=2022-05-01 -d@\"input.json\"'\nWhere input.json contains the Request body json data as mentioned below.\n{\n\"id\":\n\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/settings/\nWDATP\",\n\"kind\": \"DataExportSettings\",\n\"type\": \"Microsoft.Security/settings\",\n\"properties\": {\n\"enabled\": true\n}\n}",
    "default_value": "By default, Endpoint protection is off.",
    "additional_information": "IMPORTANT: When enabling integration between DfE & DfC it needs to be taken into\naccount that this will have some side effects that may be undesirable.\n1. For server 2019 & above if defender is installed (default for these server SKUs)\nthis will trigger a deployment of the new unified agent and link to any of the\nextended configuration in the Defender portal.\n2. If the new unified agent is required for server SKUs of Win 2016 or Linux and\nlower there is additional integration that needs to be switched on and agents\nneed to be aligned.\nNOTE: \"Microsoft Defender for Endpoint (MDE)\" was formerly known as \"Windows\nDefender Advanced Threat Protection (WDATP).\" There are a number of places (e.g.\nAzure CLI) where the \"WDATP\" acronym is still used within Azure.",
    "detection_commands": [
      "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1",
      "select(.name==\"WDATP\")'|jq '.properties.enabled'",
      "Set-AzContext -Subscription <subscriptionID> Get-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq \"WDATP\"}"
    ],
    "remediation_commands": [
      "Use the below command to enable Standard pricing tier for Storage Accounts az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/integration-defender-",
      "for-endpoint",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/settings/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/settings/update",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-",
      "security#es-1-use-endpoint-detection-and-response-edr",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-",
      "security#es-2-use-modern-anti-malware-software"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 357,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.3.4",
    "title": "Ensure that 'Agentless scanning for machines' component status is set to 'On'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Using disk snapshots, the agentless scanner scans for installed software,\nvulnerabilities, and plain text secrets.",
    "rationale": "The Microsoft Defender for Cloud agentless machine scanner provides threat detection,\nvulnerability detection, and discovery of sensitive information.",
    "impact": "Agentless scanning for machines requires licensing and is included in these plans:\n• Defender CSPM\n• Defender for Servers plan 2",
    "audit": "Audit from Azure Portal\n1. From the Azure Portal Home page, select Microsoft Defender for Cloud\n2. Under Management select Environment Settings\n3. Select a subscription\n4. Under Settings > Defender Plans, click Settings & monitoring\n5. Under the Component column, locate the row for Agentless scanning for\nmachines\n6. Ensure that On is selected\nRepeat the above for any additional subscriptions.",
    "expected_response": "6. Ensure that On is selected",
    "remediation": "Audit from Azure Portal\n1. From the Azure Portal Home page, select Microsoft Defender for Cloud\n2. Under Management select Environment Settings\n3. Select a subscription\n4. Under Settings > Defender Plans, click Settings & monitoring\n5. Under the Component column, locate the row for Agentless scanning for\nmachines\n6. Select On\n7. Click Continue in the top left\nRepeat the above for any additional subscriptions.",
    "default_value": "By default, Agentless scanning for machines is off.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-",
      "data-collection",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-",
      "response#ir-2-preparation---setup-incident-notification",
      "3. https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-agentless-",
      "scanning-vms"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 361,
    "dspm_relevant": true,
    "dspm_categories": [
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.3.5",
    "title": "Ensure that 'File Integrity Monitoring' component status is set to 'On'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "File Integrity Monitoring (FIM) is a feature that monitors critical system files in Windows\nor Linux for potential signs of attack or compromise.",
    "rationale": "FIM provides a detection mechanism for compromised files. When FIM is enabled,\ncritical system files are monitored for changes that might indicate a threat actor is\nattempting to modify system files for lateral compromise within a host operating system.",
    "impact": "File Integrity Monitoring requires licensing and is included in the following plan:\n• Defender for Servers plan 2",
    "audit": "Audit from Azure Portal\n1. From the Azure Portal Home page, select Microsoft Defender for Cloud\n2. Under Management select Environment Settings\n3. Select a subscription\n4. Under Settings > Defender Plans, click Settings & monitoring\n5. Under the Component column, locate the row for File Integrity Monitoring\n6. Ensure that On is selected\nRepeat the above for any additional subscriptions.",
    "expected_response": "6. Ensure that On is selected",
    "remediation": "Remediate from Azure Portal\n1. From the Azure Portal Home page, select Microsoft Defender for Cloud\n2. Under Management select Environment Settings\n3. Select a subscription\n4. Under Settings > Defender Plans, click Settings & monitoring\n5. Under the Component column, locate the row for File Integrity Monitoring\n6. Select On\n7. Click Continue in the top left\nRepeat the above for any additional subscriptions.",
    "default_value": "By default, File Integrity Monitoring is Off.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-",
      "monitoring-overview",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-",
      "response#ir-2-preparation---setup-incident-notification",
      "3. https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-",
      "monitoring-enable-defender-endpoint"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 363,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.4.1",
    "title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Microsoft Defender for Containers helps improve, monitor, and maintain the security of\ncontainerized assets—including Kubernetes clusters, nodes, workloads, container\nregistries, and images—across multi-cloud and on-premises environments.\nBy default, when enabling the plan through the Azure Portal, Microsoft Defender for\nContainers automatically configures the following components:\n• Agentless scanning for machines\n• Defender sensor for runtime protection\n• Azure Policy for enforcing security best practices\n• K8S API access for monitoring and threat detection\n• Registry access for vulnerability assessment\nNote: Microsoft Defender for Container Registries ('ContainerRegistry') is deprecated\nand has been replaced by Microsoft Defender for Containers ('Containers').",
    "rationale": "Enabling Microsoft Defender for Containers enhances defense-in-depth by providing\nadvanced threat detection, vulnerability assessment, and security monitoring for\ncontainerized environments, leveraging insights from the Microsoft Security Response\nCenter (MSRC).",
    "impact": "Microsoft Defender for Containers incurs a charge per vCore. Refer to\nhttps://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/ and\nhttps://azure.microsoft.com/en-us/pricing/calculator/ to estimate potential costs.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment settings.\n3. Click the name of a subscription.\n4. Under Settings, click Defender plans.\n5. Under Cloud Workload Protection (CWP), in the row for Containers, ensure\nthat the Status is set to On and Monitoring coverage displays Full.\n6. Repeat steps 1-5 for each subscription.\nAudit from Azure CLI\nFor Microsoft Defender for Container Registries (deprecated), run the following\ncommand:\naz security pricing show --name \"ContainerRegistry\" --query pricingTier\nEnsure that the command returns Standard.\nFor Microsoft Defender for Containers, run the following command:\naz security pricing show --name \"Containers\" --query\n[pricingTier,extensions[*].[name,isEnabled]]\nEnsure that the command returns Standard, and that each of the extensions\n(ContainerRegistriesVulnerabilityAssessments, AgentlessDiscoveryForKubernetes,\nAgentlessVmScanning, ContainerSensor) returns True.\nRepeat for each subscription.\nAudit from PowerShell\nFor Microsoft Defender for Container Registries (deprecated), run the following\ncommand:\nGet-AzSecurityPricing -Name 'ContainerRegistry' | Select-Object\nName,PricingTier\nEnsure the command returns PricingTier Standard.\nFor Microsoft Defender for Containers, run the following command:\nGet-AzSecurityPricing -Name 'Containers'\nEnsure that PricingTier is set to Standard, and that each of the extensions\n(ContainerRegistriesVulnerabilityAssessments, AgentlessDiscoveryForKubernetes,\nAgentlessVmScanning, ContainerSensor) has isEnabled set to True.\nRepeat for each subscription.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 1c988dd6-ade4-430f-a608-2a3e5b0a6d38 - Name: 'Microsoft\nDefender for Containers should be enabled'",
    "expected_response": "5. Under Cloud Workload Protection (CWP), in the row for Containers, ensure\nthat the Status is set to On and Monitoring coverage displays Full.\nEnsure that the command returns Standard.\nEnsure that the command returns Standard, and that each of the extensions\nAgentlessVmScanning, ContainerSensor) returns True.\nEnsure the command returns PricingTier Standard.\nEnsure that PricingTier is set to Standard, and that each of the extensions\nDefender for Containers should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment settings.\n3. Click the name of a subscription.\n4. Under Settings, click Defender plans.\n5. Under Cloud Workload Protection (CWP), in the row for Containers, click\nOn in the Status column.\n6. If Monitoring coverage displays Partial, click Settings under Partial.\n7. Set the status of each of the components to On.\n8. Click Continue.\n9. Click Save.\n10. Repeat steps 1-9 for each subscription.\nRemediate from Azure CLI\nNote: Microsoft Defender for Container Registries ('ContainerRegistry') is deprecated\nand has been replaced by Microsoft Defender for Containers ('Containers').\nRun the below command to enable the Microsoft Defender for Containers plan and its\ncomponents:\naz security pricing create -n 'Containers' --tier 'standard' --extensions\nname=ContainerRegistriesVulnerabilityAssessments isEnabled=True --extensions\nname=AgentlessDiscoveryForKubernetes isEnabled=True --extensions\nname=AgentlessVmScanning isEnabled=True --extensions name=ContainerSensor\nisEnabled=True\nRemediate from PowerShell\nNote: Microsoft Defender for Container Registries ('ContainerRegistry') is deprecated\nand has been replaced by Microsoft Defender for Containers ('Containers').\nRun the below command to enable the Microsoft Defender for Containers plan and its\ncomponents:\nSet-AzSecurityPricing -Name 'Containers' -PricingTier 'Standard' -Extension\n'[{\"name\":\"ContainerRegistriesVulnerabilityAssessments\",\"isEnabled\":\"True\"},{\n\"name\":\"AgentlessDiscoveryForKubernetes\",\"isEnabled\":\"True\"},{\"name\":\"Agentle\nssVmScanning\",\"isEnabled\":\"True\"},{\"name\":\"ContainerSensor\",\"isEnabled\":\"True\n\"}]'",
    "default_value": "The Microsoft Defender for Containers plan is disabled by default.",
    "additional_information": "The Azure Policy 'Microsoft Defender for Containers should be enabled' checks only\nthat the pricingTier for Containers is set to Standard. It does not check the status\nof the plan's components.",
    "detection_commands": [
      "az security pricing show --name \"ContainerRegistry\" --query pricingTier",
      "az security pricing show --name \"Containers\" --query",
      "Get-AzSecurityPricing -Name 'ContainerRegistry' | Select-Object",
      "Get-AzSecurityPricing -Name 'Containers'"
    ],
    "remediation_commands": [
      "az security pricing create -n 'Containers' --tier 'standard' --extensions",
      "Set-AzSecurityPricing -Name 'Containers' -PricingTier 'Standard' -Extension '[{\"name\":\"ContainerRegistriesVulnerabilityAssessments\",\"isEnabled\":\"True\"},{ \"name\":\"AgentlessDiscoveryForKubernetes\",\"isEnabled\":\"True\"},{\"name\":\"Agentle"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/cli/azure/security/pricing",
      "2. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.security/set-",
      "azsecuritypricing",
      "4. https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-",
      "containers-introduction",
      "5. https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-",
      "containers-azure",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 366,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.5.1",
    "title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Turning on Microsoft Defender for Storage enables threat detection for Storage,\nproviding threat intelligence, anomaly detection, and behavior analytics in the Microsoft\nDefender for Cloud.",
    "rationale": "Enabling Microsoft Defender for Storage allows for greater defense-in-depth, with threat\ndetection provided by the Microsoft Security Response Center (MSRC).",
    "impact": "Turning on Microsoft Defender for Storage incurs an additional cost per resource.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Ensure Status is set to On for Storage.\nAudit from Azure CLI\nEnsure the output of the below command is Standard\naz security pricing show -n StorageAccounts\nAudit from PowerShell\nGet-AzSecurityPricing -Name 'StorageAccounts' | Select-Object\nName,PricingTier\nEnsure output for Name PricingTier is StorageAccounts Standard\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 640d2586-54d2-465f-877f-9ffc1d2109f4 - Name: 'Microsoft Defender\nfor Storage should be enabled'",
    "expected_response": "5. Ensure Status is set to On for Storage.\nEnsure the output of the below command is Standard\nEnsure output for Name PricingTier is StorageAccounts Standard\nfor Storage should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Set Status to On for Storage.\n6. Select Save.\nRemediate from Azure CLI\nEnsure the output of the below command is Standard\naz security pricing create -n StorageAccounts --tier 'standard'\nRemediate from PowerShell\nSet-AzSecurityPricing -Name 'StorageAccounts' -PricingTier 'Standard'",
    "default_value": "By default, Microsoft Defender plan is off.",
    "detection_commands": [
      "az security pricing show -n StorageAccounts",
      "Get-AzSecurityPricing -Name 'StorageAccounts' | Select-Object"
    ],
    "remediation_commands": [
      "az security pricing create -n StorageAccounts --tier 'standard'",
      "Set-AzSecurityPricing -Name 'StorageAccounts' -PricingTier 'Standard'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/update",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 371,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.5.2",
    "title": "Ensure Advanced Threat Protection Alerts for Storage Accounts Are Monitored",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "After enabling Microsoft Defender for Storage, configure an alert monitoring and\nresponse process to ensure that alerts are actioned in a timely manner. Integrate with\nSIEM solutions like Microsoft Sentinel, or configure email/webhook notifications to\nsecurity teams.",
    "rationale": "Enabling Microsoft Defender for Storage without a monitoring process limits its value.\nContinuous monitoring and alert triage ensure that detected threats are acted upon\nquickly, reducing risk exposure.",
    "impact": "Requires integration effort with SIEM or alerting tools and a defined incident response\nprocess.\nThe amount of data logged and, thus, the cost incurred can vary significantly depending\non the tenant size and the applications in your tenant that interact with the Microsoft\nGraph APIs.\nSee the following pricing calculations for respective services:\n• Log Analytics: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-\nlogs#pricing-model.\n• Azure Storage: https://azure.microsoft.com/en-us/pricing/details/storage/blobs/.\n• Event Hubs: https://azure.microsoft.com/en-us/pricing/details/event-hubs/.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment Settings.\n3. Expand the Tenant Root Group(s) to reveal subscriptions.\nFor each subscription listed:\n1. Click the subscription name to open the Defender Plans settings\n2. In the settings on the left, click Continuous Export\nEnsure that Export enabled is set to On and delivering at least Security Alerts\n(Medium and High) to an Event Hub or Log Analytics Workspace which is tied to a\nSIEM that is configured to monitor and alert for security alerts.",
    "expected_response": "Ensure that Export enabled is set to On and delivering at least Security Alerts\nSIEM that is configured to monitor and alert for security alerts.",
    "remediation": "Connect Microsoft Defender for Cloud to a SIEM such as Microsoft Sentinel or another\nlog analytics solution.\nRemediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, click Environment Settings.\n3. Expand the Tenant Root Group(s) to reveal subscriptions.\nFor each subscription listed:\n1. Click the subscription name to open the Defender Plans settings\n2. In the settings on the left, click Continuous Export\n3. Select either Event Hub, Log Analytics Workspace, or both depending on\nyour environment.\n4. Set Export enabled to On\n5. Under Exported data types, ensure that at least Security Alerts (Medium\nand High) is checked.\n6. Under Export target, set the target Event Hub or Log Analytics Workspace which\nis tied to a SIEM that is configured to monitor and alert for security alerts.\nEnsure security alerts are included in the security operations workflow and incident\nresponse plan.",
    "default_value": "By default, continuous export is off.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/azure/defender-for-cloud/alerts-overview",
      "2. https://learn.microsoft.com/azure/sentinel/connect-defender-for-cloud",
      "3. https://learn.microsoft.com/en-us/azure/defender-for-cloud/continuous-export"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 374,
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
    "cis_id": "8.1.6.1",
    "title": "Ensure That Microsoft Defender for App Services Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Enable Detailed Logging",
    "description": "Turning on Microsoft Defender for App Service enables threat detection for App Service,\nproviding threat intelligence, anomaly detection, and behavior analytics in the Microsoft\nDefender for Cloud.",
    "rationale": "Enabling Microsoft Defender for App Service allows for greater defense-in-depth, with\nthreat detection provided by the Microsoft Security Response Center (MSRC).",
    "impact": "Turning on Microsoft Defender for App Service incurs an additional cost per resource.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud\n2. Under Management, select Environment Settings\n3. Click on the subscription name\n4. Select Defender plans\n5. Ensure Status is On for App Service\nAudit from Azure CLI\nRun the following command:\naz security pricing show -n AppServices\nEnsure -PricingTier is set to Standard\nAudit from PowerShell\nRun the following command:\nGet-AzSecurityPricing -Name 'AppServices' |Select-Object Name,PricingTier\nEnsure the -PricingTier is set to Standard\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 2913021d-f2fd-4f3d-b958-22354e2bdbcb - Name: 'Azure Defender for\nApp Service should be enabled'",
    "expected_response": "5. Ensure Status is On for App Service\nEnsure -PricingTier is set to Standard\nEnsure the -PricingTier is set to Standard\nApp Service should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud\n2. Under Management, select Environment Settings\n3. Click on the subscription name\n4. Select Defender plans\n5. Set App Service Status to On\n6. Select Save\nRemediate from Azure CLI\nRun the following command:\naz security pricing create -n Appservices --tier 'standard'\nRemediate from PowerShell\nRun the following command:\nSet-AzSecurityPricing -Name \"AppServices\" -PricingTier \"Standard\"",
    "default_value": "By default, Microsoft Defender plan is off.",
    "detection_commands": [
      "az security pricing show -n AppServices",
      "Get-AzSecurityPricing -Name 'AppServices' |Select-Object Name,PricingTier"
    ],
    "remediation_commands": [
      "az security pricing create -n Appservices --tier 'standard'",
      "Set-AzSecurityPricing -Name \"AppServices\" -PricingTier \"Standard\""
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/update",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 377,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.7.1",
    "title": "Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Microsoft Defender for Azure Cosmos DB scans all incoming network requests for\nthreats to your Azure Cosmos DB resources.",
    "rationale": "In scanning Azure Cosmos DB requests within a subscription, requests are compared to\na heuristic list of potential security threats. These threats could be a result of a security\nbreach within your services, thus scanning for them could prevent a potential security\nthreat from being introduced.",
    "impact": "Enabling Microsoft Defender for Azure Cosmos DB requires enabling Microsoft\nDefender for your subscription. Both will incur additional charges.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. On the Database row click on Select types >.\n6. Ensure the toggle switch next to Azure Cosmos DB is set to On.\nAudit from Azure CLI\nEnsure the output of the below command is Standard\naz security pricing show -n CosmosDbs --query pricingTier\nAudit from PowerShell\nGet-AzSecurityPricing -Name 'CosmosDbs' | Select-Object Name,PricingTier\nEnsure output of -PricingTier is Standard\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: adbe85b5-83e6-4350-ab58-bf3a4f736e5e - Name: 'Microsoft\nDefender for Azure Cosmos DB should be enabled'",
    "expected_response": "6. Ensure the toggle switch next to Azure Cosmos DB is set to On.\nEnsure the output of the below command is Standard\nEnsure output of -PricingTier is Standard\nDefender for Azure Cosmos DB should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. On the Database row click on Select types >.\n6. Set the toggle switch next to Azure Cosmos DB to On.\n7. Click Continue.\n8. Click Save.\nRemediate from Azure CLI\nRun the following command:\naz security pricing create -n 'CosmosDbs' --tier 'standard'\nRemediate from PowerShell\nUse the below command to enable Standard pricing tier for Azure Cosmos DB\nSet-AzSecurityPricing -Name 'CosmosDbs' -PricingTier 'Standard",
    "default_value": "By default, Microsoft Defender for Azure Cosmos DB is not enabled.",
    "detection_commands": [
      "az security pricing show -n CosmosDbs --query pricingTier",
      "Get-AzSecurityPricing -Name 'CosmosDbs' | Select-Object Name,PricingTier"
    ],
    "remediation_commands": [
      "az security pricing create -n 'CosmosDbs' --tier 'standard'",
      "Use the below command to enable Standard pricing tier for Azure Cosmos DB Set-AzSecurityPricing -Name 'CosmosDbs' -PricingTier 'Standard"
    ],
    "references": [
      "1. https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-",
      "subscription",
      "3. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-",
      "cosmos-db-security-baseline",
      "5. https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-",
      "databases-plan",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 381,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.7.2",
    "title": "Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Turning on Microsoft Defender for Open-source relational databases enables threat\ndetection for Open-source relational databases, providing threat intelligence, anomaly\ndetection, and behavior analytics in the Microsoft Defender for Cloud.",
    "rationale": "Enabling Microsoft Defender for Open-source relational databases allows for greater\ndefense-in-depth, with threat detection provided by the Microsoft Security Response\nCenter (MSRC).",
    "impact": "Turning on Microsoft Defender for Open-source relational databases incurs an\nadditional cost per resource.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Click Select types > in the row for Databases.\n6. Ensure the toggle switch next to Open-source relational databases is set to\nOn.\nAudit from Azure CLI\nRun the following command:\naz security pricing show -n OpenSourceRelationalDatabases --query pricingTier\nAudit from PowerShell\nGet-AzSecurityPricing | Where-Object {$_.Name -eq\n'OpenSourceRelationalDatabases'} | Select-Object Name, PricingTier\nEnsure output for Name PricingTier is OpenSourceRelationalDatabases Standard\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 0a9fbe0d-c5c4-4da8-87d8-f4fd77338835 - Name: 'Azure Defender for\nopen-source relational databases should be enabled'",
    "expected_response": "6. Ensure the toggle switch next to Open-source relational databases is set to\nEnsure output for Name PricingTier is OpenSourceRelationalDatabases Standard\nopen-source relational databases should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Click Select types > in the row for Databases.\n6. Set the toggle switch next to Open-source relational databases to On.\n7. Select Continue.\n8. Select Save.\nRemediate from Azure CLI\nRun the following command:\naz security pricing create -n 'OpenSourceRelationalDatabases' --tier\n'standard'\nRemediate from PowerShell\nUse the below command to enable Standard pricing tier for Open-source relational\ndatabases\nset-azsecuritypricing -name \"OpenSourceRelationalDatabases\" -pricingtier\n\"Standard\"",
    "default_value": "By default, Microsoft Defender plan is off.",
    "detection_commands": [
      "az security pricing show -n OpenSourceRelationalDatabases --query pricingTier",
      "Get-AzSecurityPricing | Where-Object {$_.Name -eq 'OpenSourceRelationalDatabases'} | Select-Object Name, PricingTier"
    ],
    "remediation_commands": [
      "az security pricing create -n 'OpenSourceRelationalDatabases' --tier 'standard'",
      "Use the below command to enable Standard pricing tier for Open-source relational",
      "set-azsecuritypricing -name \"OpenSourceRelationalDatabases\" -pricingtier \"Standard\""
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/update",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 384,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.7.3",
    "title": "Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Turning on Microsoft Defender for Azure SQL Databases enables threat detection for\nManaged Instance Azure SQL databases, providing threat intelligence, anomaly\ndetection, and behavior analytics in Microsoft Defender for Cloud.",
    "rationale": "Enabling Microsoft Defender for Azure SQL Databases allows for greater defense-in-\ndepth, includes functionality for discovering and classifying sensitive data, surfacing and\nmitigating potential database vulnerabilities, and detecting anomalous activities that\ncould indicate a threat to your database.",
    "impact": "Turning on Microsoft Defender for Azure SQL Databases incurs an additional cost per\nresource.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Click Select types > in the row for Databases.\n6. Ensure the toggle switch next to Azure SQL Databases is set to On.\nAudit from Azure CLI\nRun the following command:\naz security pricing show -n SqlServers\nEnsure -PricingTier is set to Standard\nAudit from PowerShell\nRun the following command:\nGet-AzSecurityPricing -Name 'SqlServers' | Select-Object Name,PricingTier\nEnsure the -PricingTier is set to Standard\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 7fe3b40f-802b-4cdd-8bd4-fd799c948cc2 - Name: 'Azure Defender for\nAzure SQL Database servers should be enabled'\n• Policy ID: abfb7388-5bf4-4ad7-ba99-2cd2f41cebb9 - Name: 'Azure Defender for\nSQL should be enabled for unprotected SQL Managed Instances'\n• Policy ID: 3bc8a0d5-38e0-4a3d-a657-2cb64468fc34 - Name: 'Azure Defender\nfor SQL should be enabled for unprotected MySQL flexible servers'\n• Policy ID: d38668f5-d155-42c7-ab3d-9b57b50f8fbf - Name: 'Azure Defender for\nSQL should be enabled for unprotected PostgreSQL flexible servers'\n• Policy ID: d31e5c31-63b2-4f12-887b-e49456834fa1 - Name: 'Microsoft\nDefender for SQL should be enabled for unprotected Synapse workspaces'\n• Policy ID: 938c4981-c2c9-4168-9cd6-972b8675f906 - Name: 'Microsoft\nDefender for SQL status should be protected for Arc-enabled SQL Servers'",
    "expected_response": "6. Ensure the toggle switch next to Azure SQL Databases is set to On.\nEnsure -PricingTier is set to Standard\nEnsure the -PricingTier is set to Standard\nAzure SQL Database servers should be enabled'\nSQL should be enabled for unprotected SQL Managed Instances'\nfor SQL should be enabled for unprotected MySQL flexible servers'\nSQL should be enabled for unprotected PostgreSQL flexible servers'\nDefender for SQL should be enabled for unprotected Synapse workspaces'\nDefender for SQL status should be protected for Arc-enabled SQL Servers'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Click Select types > in the row for Databases.\n6. Set the toggle switch next to Azure SQL Databases to On.\n7. Select Continue.\n8. Select Save.\nRemediate from Azure CLI\nRun the following command:\naz security pricing create -n SqlServers --tier 'standard'\nRemediate from PowerShell\nRun the following command:\nSet-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Standard'",
    "default_value": "By default, Microsoft Defender plan is off.",
    "detection_commands": [
      "az security pricing show -n SqlServers",
      "Get-AzSecurityPricing -Name 'SqlServers' | Select-Object Name,PricingTier",
      "Azure SQL Database servers should be enabled'"
    ],
    "remediation_commands": [
      "az security pricing create -n SqlServers --tier 'standard'",
      "Set-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Standard'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/update",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 387,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.7.4",
    "title": "Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Turning on Microsoft Defender for SQL servers on machines enables threat detection\nfor SQL servers on machines, providing threat intelligence, anomaly detection, and\nbehavior analytics in Microsoft Defender for Cloud.",
    "rationale": "Enabling Microsoft Defender for SQL servers on machines allows for greater defense-\nin-depth, functionality for discovering and classifying sensitive data, surfacing and\nmitigating potential database vulnerabilities, and detecting anomalous activities that\ncould indicate a threat to your database.",
    "impact": "Turning on Microsoft Defender for SQL servers on machines incurs an additional cost\nper resource.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Click Select types > in the row for Databases.\n6. Ensure the toggle switch next to SQL servers on machines is set to On.\nAudit from Azure CLI\nEnsure Defender for SQL is licensed with the following command:\naz security pricing show -n SqlServerVirtualMachines\nEnsure the 'PricingTier' is set to 'Standard'\nAudit from PowerShell\nRun the following command:\nGet-AzSecurityPricing -Name 'SqlServerVirtualMachines' | Select-Object\nName,PricingTier\nEnsure the 'PricingTier' is set to 'Standard'\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 6581d072-105e-4418-827f-bd446d56421b - Name: 'Azure Defender\nfor SQL servers on machines should be enabled'\n• Policy ID: abfb4388-5bf4-4ad7-ba82-2cd2f41ceae9 - Name: 'Azure Defender for\nSQL should be enabled for unprotected Azure SQL servers'",
    "expected_response": "6. Ensure the toggle switch next to SQL servers on machines is set to On.\nEnsure Defender for SQL is licensed with the following command:\nEnsure the 'PricingTier' is set to 'Standard'\nfor SQL servers on machines should be enabled'\nSQL should be enabled for unprotected Azure SQL servers'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Click Select types > in the row for Databases.\n6. Set the toggle switch next to SQL servers on machines to On.\n7. Select Continue.\n8. Select Save.\nRemediate from Azure CLI\nRun the following command:\naz security pricing create -n SqlServerVirtualMachines --tier 'standard'\nRemediate from PowerShell\nRun the following command:\nSet-AzSecurityPricing -Name 'SqlServerVirtualMachines' -PricingTier\n'Standard'",
    "default_value": "By default, Microsoft Defender plan is off.",
    "detection_commands": [
      "az security pricing show -n SqlServerVirtualMachines",
      "Get-AzSecurityPricing -Name 'SqlServerVirtualMachines' | Select-Object"
    ],
    "remediation_commands": [
      "az security pricing create -n SqlServerVirtualMachines --tier 'standard'",
      "Set-AzSecurityPricing -Name 'SqlServerVirtualMachines' -PricingTier 'Standard'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-",
      "usage",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/update",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 390,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.8.1",
    "title": "Ensure That Microsoft Defender for Key Vault Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Turning on Microsoft Defender for Key Vault enables threat detection for Key Vault,\nproviding threat intelligence, anomaly detection, and behavior analytics in the Microsoft\nDefender for Cloud.",
    "rationale": "Enabling Microsoft Defender for Key Vault allows for greater defense-in-depth, with\nthreat detection provided by the Microsoft Security Response Center (MSRC).",
    "impact": "Turning on Microsoft Defender for Key Vault incurs an additional cost per resource.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Ensure Status is set to On for Key Vault.\nAudit from Azure CLI\nEnsure the output of the below command is Standard\naz security pricing show -n 'KeyVaults' --query 'pricingTier'\nAudit from PowerShell\nGet-AzSecurityPricing -Name 'KeyVaults' | Select-Object Name,PricingTier\nEnsure output for PricingTier is Standard\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 0e6763cc-5078-4e64-889d-ff4d9a839047 - Name: 'Azure Defender\nfor Key Vault should be enabled'",
    "expected_response": "5. Ensure Status is set to On for Key Vault.\nEnsure the output of the below command is Standard\nEnsure output for PricingTier is Standard\nfor Key Vault should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Select On under Status for Key Vault.\n6. Select Save.\nRemediate from Azure CLI\nEnable Standard pricing tier for Key Vault:\naz security pricing create -n 'KeyVaults' --tier 'Standard'\nRemediate from PowerShell\nEnable Standard pricing tier for Key Vault:\nSet-AzSecurityPricing -Name 'KeyVaults' -PricingTier 'Standard'",
    "default_value": "By default, Microsoft Defender plan is off.",
    "detection_commands": [
      "az security pricing show -n 'KeyVaults' --query 'pricingTier'",
      "Get-AzSecurityPricing -Name 'KeyVaults' | Select-Object Name,PricingTier"
    ],
    "remediation_commands": [
      "az security pricing create -n 'KeyVaults' --tier 'Standard'",
      "Set-AzSecurityPricing -Name 'KeyVaults' -PricingTier 'Standard'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/update",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.security/get-",
      "azsecuritypricing",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 394,
    "dspm_relevant": true,
    "dspm_categories": [
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.9.1",
    "title": "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Microsoft Defender for Resource Manager scans incoming administrative requests to\nchange your infrastructure from both CLI and the Azure portal.",
    "rationale": "Scanning resource requests lets you be alerted every time there is suspicious activity in\norder to prevent a security threat from being introduced.",
    "impact": "Enabling Microsoft Defender for Resource Manager requires enabling Microsoft\nDefender for your subscription. Both will incur additional charges.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Ensure Status is set to On for Resource Manager.\nAudit from Azure CLI\nEnsure the output of the below command is Standard\naz security pricing show -n 'Arm' --query 'pricingTier'\nAudit from PowerShell\nGet-AzSecurityPricing -Name 'Arm' | Select-Object Name,PricingTier\nEnsure the output of PricingTier is Standard\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: c3d20c29-b36d-48fe-808b-99a87530ad99 - Name: 'Azure Defender\nfor Resource Manager should be enabled'",
    "expected_response": "5. Ensure Status is set to On for Resource Manager.\nEnsure the output of the below command is Standard\nEnsure the output of PricingTier is Standard\nfor Resource Manager should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender for Cloud.\n2. Under Management, select Environment Settings.\n3. Click on the subscription name.\n4. Select the Defender plans blade.\n5. Select On under Status for Resource Manager.\n6. Select Save.\nRemediate from Azure CLI\nUse the below command to enable Standard pricing tier for Defender for Resource\nManager\naz security pricing create -n 'Arm' --tier 'Standard'\nRemediate from PowerShell\nUse the below command to enable Standard pricing tier for Defender for Resource\nManager\nSet-AzSecurityPricing -Name 'Arm' -PricingTier 'Standard'",
    "default_value": "By default, Microsoft Defender for Resource Manager is not enabled.",
    "detection_commands": [
      "az security pricing show -n 'Arm' --query 'pricingTier'",
      "Get-AzSecurityPricing -Name 'Arm' | Select-Object Name,PricingTier"
    ],
    "remediation_commands": [
      "Use the below command to enable Standard pricing tier for Defender for Resource",
      "az security pricing create -n 'Arm' --tier 'Standard'",
      "Set-AzSecurityPricing -Name 'Arm' -PricingTier 'Standard'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-",
      "subscription",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-",
      "resource-manager-introduction",
      "3. https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/",
      "4. https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 398,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.10",
    "title": "Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Ensure that the latest OS patches for all virtual machines are applied.",
    "rationale": "Windows and Linux virtual machines should be kept updated to:\n• Address a specific bug or flaw\n• Improve an OS or application’s general stability\n• Fix a security vulnerability\nMicrosoft Defender for Cloud retrieves a list of available security and critical updates\nfrom Windows Update or Windows Server Update Services (WSUS), depending on\nwhich service is configured on a Windows VM. The security center also checks for the\nlatest updates in Linux systems. If a VM is missing a system update, the security center\nwill recommend system updates be applied.",
    "impact": "Running Microsoft Defender for Cloud incurs additional charges for each resource\nmonitored. Please see attached reference for exact charges per hour.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Defender for Cloud\n3. Then the Recommendations blade\n4. Ensure that there are no recommendations for System updates should be\ninstalled on your machines (powered by Update Center)\nAlternatively, you can employ your own patch assessment and management tool to\nperiodically assess, report and install the required security patches for your OS.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: f85bf3e0-d513-442e-89c3-1784ad63382b - Name: 'System updates\nshould be installed on your machines (powered by Update Center)'\n• Policy ID: bd876905-5b84-4f73-ab2d-2e7a7c4568d9 - Name: 'Machines should\nbe configured to periodically check for missing system updates'",
    "expected_response": "4. Ensure that there are no recommendations for System updates should be\nshould be installed on your machines (powered by Update Center)'\n• Policy ID: bd876905-5b84-4f73-ab2d-2e7a7c4568d9 - Name: 'Machines should",
    "remediation": "Follow Microsoft Azure documentation to apply security patches from the security\ncenter. Alternatively, you can employ your own patch assessment and management tool\nto periodically assess, report, and install the required security patches for your OS.",
    "default_value": "By default, patches are not automatically deployed.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-",
      "vulnerability-management#pv-6-rapidly-and-automatically-remediate-",
      "vulnerabilities",
      "2. https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 401,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.11",
    "title": "Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Deploy Automated Operating System Patch",
    "description": "The Microsoft Cloud Security Benchmark (or \"MCSB\") is an Azure Policy Initiative\ncontaining many security policies to evaluate resource configuration against best\npractice recommendations. If a policy in the MCSB is set with effect type Disabled, it is\nnot evaluated and may prevent administrators from being informed of valuable security\nrecommendations.",
    "rationale": "A security policy defines the desired configuration of resources in your environment and\nhelps ensure compliance with company or regulatory security requirements. The MCSB\nPolicy Initiative a set of security recommendations based on best practices and is\nassociated with every subscription by default. When a policy \"Effect\" is set to Audit,\npolicies in the MCSB ensure that Defender for Cloud evaluates relevant resources for\nsupported recommendations. To ensure that policies within the MCSB are not being\nmissed when the Policy Initiative is evaluated, none of the policies should have an\nEffect of Disabled.",
    "impact": "Policies within the MCSB default to an effect of Audit and will evaluate—but not\nenforce—policy recommendations. Ensuring these policies are set to Audit simply\nensures that the evaluation occurs to allow administrators to understand where an\nimprovement may be possible. Administrators will need to determine if the\nrecommendations are relevant and desirable for their environment, then manually take\naction to resolve the status if desired.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment settings.\n4. Click on the appropriate Management Group or Subscription.\n5. Click on Security policies in the left column.\n6. Click on Microsoft cloud security benchmark.\n7. Click Add filter and select Effect.\n8. Check the Disabled box to search for all disabled policies.\n9. Click Apply.\n10. Ensure that no policies are displayed, signifying that there are no disabled\npolicies.\n11. Repeat steps 1-10 for each Management Group or Subscription.",
    "expected_response": "10. Ensure that no policies are displayed, signifying that there are no disabled",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment settings.\n4. Click on the appropriate Management Group or Subscription.\n5. Click on Security policies in the left column.\n6. Click on Microsoft cloud security benchmark\n7. Click Add Filter and select Effect\n8. Check the Disabled box to search for all disabled policies\n9. Click Apply\n10. Click the blue ellipsis ... to the right of a policy name.\n11. Click Manage effect and parameters.\n12. Under Policy effect, select the radio button next to Audit.\n13. Click Save.\n14. Click Refresh.\n15. Repeat steps 10-14 until all disabled policies are updated.\n16. Repeat steps 1-15 for each Management Group or Subscription requiring\nremediation.",
    "default_value": "By default, the MCSB policy initiative is assigned on all subscriptions, and most policies\nwill have an effect of Audit. Some policies will have a default effect of Disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/security-policy-",
      "concept",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-cloud/implement-security-",
      "recommendations",
      "3. https://learn.microsoft.com/en-us/rest/api/policy/policy-assignments/get",
      "4. https://learn.microsoft.com/en-us/rest/api/policy/policy-assignments/create",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-7-define-and-implement-logging-threat-detection-and-incident-",
      "response-strategy"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 404,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.12",
    "title": "Ensure That 'All users with the following roles' is set to 'Owner'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Implement Automated Configuration Monitoring",
    "description": "Enable security alert emails to subscription owners.",
    "rationale": "Enabling security alert emails to subscription owners ensures that they receive security\nalert emails from Microsoft. This ensures that they are aware of any potential security\nissues and can mitigate the risk in a timely fashion.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Defender for Cloud\n3. Under Management, select Environment Settings\n4. Click on the appropriate Management Group, Subscription, or Workspace\n5. Click on Email notifications\n6. Ensure that All users with the following roles is set to Owner\nAudit from Azure CLI\nEnsure the command below returns state of On and that Owner appears in roles.\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X GET -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se\ncurityContacts?api-version=2020-01-01-preview'| jq '.[] |\nselect(.name==\"default\").properties.notificationsByRole'",
    "expected_response": "6. Ensure that All users with the following roles is set to Owner\nEnsure the command below returns state of On and that Owner appears in roles.",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Defender for Cloud\n3. Under Management, select Environment Settings\n4. Click on the appropriate Management Group, Subscription, or Workspace\n5. Click on Email notifications\n6. In the drop down of the All users with the following roles field select\nOwner\n7. Click Save\nRemediate from Azure CLI\nUse the below command to set Send email also to subscription owners to On.\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se\ncurityContacts/default1?api-version=2017-08-01-preview -d@\"input.json\"'\nWhere input.json contains the data below, replacing validEmailAddress with a\nsingle email address or multiple comma-separated email addresses:\n{\n\"id\":\n\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/securityC\nontacts/default1\",\n\"name\": \"default1\",\n\"type\": \"Microsoft.Security/securityContacts\",\n\"properties\": {\n\"email\": \"<validEmailAddress>\",\n\"alertNotifications\": \"On\",\n\"alertsToAdmins\": \"On\",\n\"notificationsByRole\": \"Owner\"\n}\n}",
    "default_value": "By default, Owner is selected",
    "additional_information": "Excluding any entries in the input.json properties block disables the specific setting by\ndefault.",
    "detection_commands": [
      "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1",
      "select(.name==\"default\").properties.notificationsByRole'"
    ],
    "remediation_commands": [
      "Use the below command to set Send email also to subscription owners to On. az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-",
      "notifications",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-",
      "response#ir-2-preparation---setup-incident-notification"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 407,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.13",
    "title": "Ensure 'Additional email addresses' is Configured with a Security Contact Email",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "Microsoft Defender for Cloud emails the subscription owners whenever a high-severity\nalert is triggered for their subscription. You should provide a security contact email\naddress as an additional email address.",
    "rationale": "Microsoft Defender for Cloud emails the Subscription Owner to notify them about\nsecurity alerts. Adding your Security Contact's email address to the 'Additional email\naddresses' field ensures that your organization's Security Team is included in these\nalerts. This ensures that the proper people are aware of any potential compromise in\norder to mitigate the risk in a timely fashion.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment Settings.\n4. Click on the appropriate Management Group, Subscription, or Workspace.\n5. Click on Email notifications.\n6. Ensure that a valid security contact email address is listed in the Additional\nemail addresses field.\nAudit from Azure CLI\nEnsure the output of the below command is not empty and is set with appropriate email\nids:\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X GET -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se\ncurityContacts?api-version=2020-01-01-preview' | jq '.|.[] |\nselect(.name==\"default\")'|jq '.properties.emails'\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 4f4f78b8-e367-4b10-a341-d9a4ad5cf1c7 - Name: 'Subscriptions\nshould have a contact email address for security issues'",
    "expected_response": "6. Ensure that a valid security contact email address is listed in the Additional\nEnsure the output of the below command is not empty and is set with appropriate email\nshould have a contact email address for security issues'",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment Settings.\n4. Click on the appropriate Management Group, Subscription, or Workspace.\n5. Click on Email notifications.\n6. Enter a valid security contact email address (or multiple addresses separated by\ncommas) in the Additional email addresses field.\n7. Click Save.\nRemediate from Azure CLI\nUse the below command to set Security contact emails to On.\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se\ncurityContacts/default?api-version=2020-01-01-preview -d@\"input.json\"'\nWhere input.json contains the data below, replacing validEmailAddress with a\nsingle email address or multiple comma-separated email addresses:\n{\n\"id\":\n\"/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/securityC\nontacts/default\",\n\"name\": \"default\",\n\"type\": \"Microsoft.Security/securityContacts\",\n\"properties\": {\n\"email\": \"<validEmailAddress>\",\n\"alertNotifications\": \"On\",\n\"alertsToAdmins\": \"On\"\n}\n}",
    "default_value": "By default, there are no additional email addresses entered.",
    "additional_information": "Excluding any entries in the input.json properties block disables the specific setting\nby default.",
    "detection_commands": [
      "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1",
      "select(.name==\"default\")'|jq '.properties.emails'"
    ],
    "remediation_commands": [
      "Use the below command to set Security contact emails to On. az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-",
      "notifications",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-",
      "response#ir-2-preparation---setup-incident-notification"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 410,
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
    "cis_id": "8.1.14",
    "title": "Ensure that 'Notify about alerts with the following severity (or higher)' is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "Enables emailing security alerts to the subscription owner or other designated security\ncontact.",
    "rationale": "Enabling security alert emails ensures that security alert emails are sent by Microsoft.\nThis ensures that the right people are aware of any potential security issues and can\nmitigate the risk.",
    "impact": "Enabling security alert emails can cause alert fatigue, increasing the risk of missing\nimportant alerts. Select an appropriate severity level to manage notifications. Azure\naims to reduce alert fatigue by limiting the daily email volume per severity level. Learn\nmore: https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-\nnotifications#email-frequency.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment settings.\n4. Click on the appropriate Subscription.\n5. Click on Email notifications.\n6. Under Notification types, ensure that the box next to Notify about\nalerts with the following severity (or higher) is checked, and an\nappropriate severity level is selected.\n7. Repeat steps 1-6 for each Subscription.\nAudit from Azure CLI\nIncluding a Subscription ID at the $0 in /subscriptions/$0/providers, ensure the\nbelow command returns \"state\": \"On\", and that \"minimalSeverity\" is set to an\nappropriate severity level:\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X GET -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se\ncurityContacts?api-version=2020-01-01-preview' | jq '.|.[] |\nselect(.name==\"default\")'|jq '.properties.alertNotifications'\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 6e2593d9-add6-4083-9c9b-4b7d2188c899 - Name: 'Email notification\nfor high severity alerts should be enabled'\n• Policy ID: 0b15565f-aa9e-48ba-8619-45960f2c314d - Name: 'Email notification\nto subscription owner for high severity alerts should be enabled'",
    "expected_response": "6. Under Notification types, ensure that the box next to Notify about\nIncluding a Subscription ID at the $0 in /subscriptions/$0/providers, ensure the\nbelow command returns \"state\": \"On\", and that \"minimalSeverity\" is set to an\nfor high severity alerts should be enabled'\nto subscription owner for high severity alerts should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment settings.\n4. Click on the appropriate Subscription.\n5. Click on Email notifications.\n6. Under Notification types, check box next to Notify about alerts with\nthe following severity (or higher) and select an appropriate severity\nlevel from the drop-down menu.\n7. Click Save.\n8. Repeat steps 1-7 for each Subscription requiring remediation.\nRemediate from Azure CLI\nUse the below command to enable Send email notification for high severity\nalerts:\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X PUT -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/<$0>/providers/Microsoft.Security/\nsecurityContacts/default1?api-version=2017-08-01-preview -d@\"input.json\"'\nWhere input.json contains the data below, replacing validEmailAddress with a\nsingle email address or multiple comma-separated email addresses:\n{\n\"id\":\n\"/subscriptions/<subscriptionId>/providers/Microsoft.Security/securityContact\ns/default\",\n\"name\": \"default\",\n\"type\": \"Microsoft.Security/securityContacts\",\n\"properties\": {\n\"email\": \"<validEmailAddress>\",\n\"alertNotifications\": \"On\",\n\"alertsToAdmins\": \"On\"\n}\n}",
    "default_value": "By default, subscription owners receive email notifications for high-severity alerts.",
    "additional_information": "Excluding any entries in the input.json properties block disables the specific setting\nby default. This recommendation has been updated to reflect recent changes to\nMicrosoft REST APIs for getting and updating security contact information.",
    "detection_commands": [
      "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1",
      "select(.name==\"default\")'|jq '.properties.alertNotifications'"
    ],
    "remediation_commands": [
      "Use the below command to enable Send email notification for high severity",
      "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-",
      "notifications",
      "2. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts",
      "3. https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-",
      "response#ir-2-preparation---setup-incident-notification"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 413,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.15",
    "title": "Ensure that 'Notify about attack paths with the following risk level (or higher)' is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Regularly Tune SIEM",
    "description": "Enables emailing attack paths to the subscription owner or other designated security\ncontact.",
    "rationale": "Enabling attack path emails ensures that attack path emails are sent by Microsoft. This\nensures that the right people are aware of any potential security issues and can mitigate\nthe risk.",
    "impact": "Enabling attack path emails can cause alert fatigue, increasing the risk of missing\nimportant alerts. Select an appropriate risk level to manage notifications. Azure aims to\nreduce alert fatigue by limiting the daily email volume per risk level. Learn more:\nhttps://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-\nnotifications#email-frequency.",
    "audit": "Audit from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment settings.\n4. Click on the appropriate Subscription.\n5. Click on Email notifications.\n6. Under Notification types, ensure that the box next to Notify about attack\npaths with the following risk level (or higher) is checked, and an\nappropriate risk level is selected.\n7. Repeat steps 1-6 for each Subscription.\nAudit from Azure CLI\nIncluding a Subscription ID at the $0 in /subscriptions/$0/providers, ensure the\nbelow command returns \"sourceType\": \"AttackPath\", and that\n\"minimalRiskLevel\" is set to an appropriate risk level:\naz account get-access-token --query\n\"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1\nbash -c 'curl -X GET -H \"Authorization: Bearer $1\" -H \"Content-Type:\napplication/json\"\nhttps://management.azure.com/subscriptions/$0/providers/Microsoft.Security/se\ncurityContacts?api-version=2023-12-01-preview' | jq '.|.[]'",
    "expected_response": "6. Under Notification types, ensure that the box next to Notify about attack\nIncluding a Subscription ID at the $0 in /subscriptions/$0/providers, ensure the\nbelow command returns \"sourceType\": \"AttackPath\", and that\n\"minimalRiskLevel\" is set to an appropriate risk level:",
    "remediation": "Remediate from Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Microsoft Defender for Cloud.\n3. Under Management, select Environment settings.\n4. Click on the appropriate Subscription.\n5. Click on Email notifications.\n6. Under Notification types, check the box next to Notify about attack paths\nwith the following risk level (or higher), and select an appropriate\nrisk level from the drop-down menu.\n7. Repeat steps 1-6 for each Subscription.",
    "detection_commands": [
      "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-",
      "notifications",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-cloud/how-to-manage-",
      "attack-path",
      "3. https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-attack-path"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 417,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.1.16",
    "title": "Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Regularly Tune SIEM",
    "description": "An organization's attack surface is the collection of assets with a public network\nidentifier or URI that an external threat actor can see or access from outside your cloud.\nIt is the set of points on the boundary of a system, a system element, system\ncomponent, or an environment where an attacker can try to enter, cause an effect on, or\nextract data from, that system, system element, system component, or environment.\nThe larger the attack surface, the harder it is to protect.\nThis tool can be configured to scan your organization's online infrastructure such as\nspecified domains, hosts, CIDR blocks, and SSL certificates, and store them in an\nInventory. Inventory items can be added, reviewed, approved, and removed, and may\ncontain enrichments (\"insights\") and additional information collected from the tool's\ndifferent scan engines and open-source intelligence sources.\nA Defender EASM workspace will generate an Inventory of publicly exposed assets by\ncrawling and scanning the internet using Seeds you provide when setting up the tool.\nSeeds can be FQDNs, IP CIDR blocks, and WHOIS records.\nDefender EASM will generate Insights within 24-48 hours after Seeds are provided, and\nthese insights include vulnerability data (CVEs), ports and protocols, and weak or\nexpired SSL certificates that could be used by an attacker for reconnaissance or\nexploitation.\nResults are classified High/Medium/Low and some of them include proposed\nmitigations.",
    "rationale": "This tool can monitor the externally exposed resources of an organization, provide\nvaluable insights, and export these findings in a variety of formats (including CSV) for\nuse in vulnerability management operations and red/purple team exercises.",
    "impact": "Microsoft Defender EASM workspaces are currently available as Azure Resources with\na 30-day free trial period but can quickly accrue significant charges. The costs are\ncalculated daily as (Number of \"billable\" inventory items) x (item cost per day).\nEstimated cost is not provided within the tool, and users are strongly advised to contact\ntheir Microsoft sales representative for pricing and set a calendar reminder for the end\nof the trial period.\nIf the workspace is deleted by the last day of a free trial period, no charges are billed.",
    "audit": "Audit from Azure Portal\n1. Go to Microsoft Defender EASM.\n2. Ensure that at least one Microsoft Defender EASM workspace is listed.\n3. Click the name of a workspace.\n4. Ensure the workspace is configured appropriately for your environment and\norganization.\n5. Repeat steps 3-4 for each workspace.",
    "expected_response": "2. Ensure that at least one Microsoft Defender EASM workspace is listed.\n4. Ensure the workspace is configured appropriately for your environment and",
    "remediation": "Remediate from Azure Portal\n1. Go to Microsoft Defender EASM.\n2. Click + Create.\n3. Under Project details, select a subscription.\n4. Select or create a resource group.\n5. Under Instance details, enter a name for the workspace.\n6. Select a region.\n7. Click Review + create.\n8. Click Create.\n9. Once the deployment has completed, go to Microsoft Defender EASM.\n10. Click the workspace name.\n11. Configure the workspace appropriately for your environment and organization.",
    "default_value": "Microsoft Defender EASM is an optional, paid Azure Resource that must be created and\nconfigured inside a Subscription and Resource Group.",
    "additional_information": "Microsoft added its Defender for External Attack Surface management (EASM) offering\nto Azure following its 2022 acquisition of EASM SaaS tool company RiskIQ.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/external-attack-surface-management/",
      "2. https://learn.microsoft.com/en-us/azure/external-attack-surface-",
      "management/deploying-the-defender-easm-azure-resource",
      "3. https://www.microsoft.com/en-us/security/blog/2022/08/02/microsoft-announces-",
      "new-solutions-for-threat-intelligence-and-attack-surface-management/"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 419,
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
    "cis_id": "8.2.1",
    "title": "Ensure That Microsoft Defender for IoT Hub Is Set To 'On'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Microsoft Defender for IoT",
    "description": "Microsoft Defender for IoT acts as a central security hub for IoT devices within your\norganization.",
    "rationale": "IoT devices are very rarely patched and can be potential attack vectors for enterprise\nnetworks. Updating their network configuration to use a central security hub allows for\ndetection of these breaches.",
    "impact": "Enabling Microsoft Defender for IoT will incur additional charges dependent on the level\nof usage.",
    "audit": "Audit from Azure Portal\n1. Go to IoT Hub.\n2. Select an IoT Hub to validate.\n3. Select Overview in Defender for IoT.\n4. The Threat prevention and Threat detection screen will appear, if Defender for\nIoT is Enabled.",
    "expected_response": "IoT is Enabled.",
    "remediation": "Remediate from Azure Portal\n1. Go to IoT Hub.\n2. Select an IoT Hub to validate.\n3. Select Overview in Defender for IoT.\n4. Click on Secure your IoT solution, and complete the onboarding.",
    "default_value": "By default, Microsoft Defender for IoT is not enabled.",
    "additional_information": "There are additional configurations for Microsoft Defender for IoT that allow for types of\ndeployments called hybrid or local. Both run on your physical infrastructure. These are\ncomplicated setups and are primarily outside of the scope of a purely Azure benchmark.\nPlease see the references to consider these options for your organization.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-",
      "defender-iot#overview",
      "2. https://learn.microsoft.com/en-us/azure/defender-for-iot/",
      "3. https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-",
      "defender-iot-pricing",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/microsoft-",
      "defender-for-iot-security-baseline",
      "5. https://learn.microsoft.com/en-us/cli/azure/iot",
      "6. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-",
      "detection#lt-1-enable-threat-detection-capabilities",
      "7. https://learn.microsoft.com/en-us/azure/defender-for-iot/device-",
      "builders/quickstart-onboard-iot-hub"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 423,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.3.1",
    "title": "Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Key Vault",
    "description": "Ensure that all Keys in Role Based Access Control (RBAC) Azure Key Vaults have an\nexpiration date set.",
    "rationale": "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft\nAzure environment. The exp (expiration date) attribute identifies the expiration date on\nor after which the key MUST NOT be used for encryption of new data, wrapping of new\nkeys, and signing. By default, keys never expire. It is thus recommended that keys be\nrotated in the key vault and set an explicit expiration date for all keys to help enforce the\nkey rotation. This ensures that the keys cannot be used beyond their assigned lifetimes.",
    "impact": "Keys cannot be used beyond their assigned expiration dates respectively. Keys need to\nbe rotated periodically wherever they are used.",
    "audit": "Audit from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Keys.\n3. In the main pane, ensure that an appropriate Expiration date is set for any\nkeys that are Enabled.\nAudit from Azure CLI\nGet a list of all the key vaults in your Azure environment by running the following\ncommand:\naz keyvault list\nThen for each key vault listed ensure that the output of the below command contains\nKey ID (kid), enabled status as true and Expiration date (expires) is not empty or null:\naz keyvault key list --vault-name <VaultName> --query\n'[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'\nAudit from PowerShell\nRetrieve a list of Azure Key vaults:\nGet-AzKeyVault\nFor each Key vault run the following command to determine which vaults are configured\nto use RBAC.\nGet-AzKeyVault -VaultName <VaultName>\nFor each Key vault with the EnableRbacAuthorizatoin setting set to True, run the\nfollowing command.\nGet-AzKeyVaultKey -VaultName <VaultName>\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0 - Name: 'Key Vault keys\nshould have an expiration date'",
    "expected_response": "3. In the main pane, ensure that an appropriate Expiration date is set for any\nThen for each key vault listed ensure that the output of the below command contains\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nshould have an expiration date'",
    "remediation": "Remediate from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Keys.\n3. In the main pane, ensure that an appropriate Expiration date is set for any\nkeys that are Enabled.\nRemediate from Azure CLI\nUpdate the Expiration date for the key using the below command:\naz keyvault key set-attributes --name <keyName> --vault-name <vaultName> --\nexpires Y-m-d'T'H:M:S'Z'\nNote: To view the expiration date on all keys in a Key Vault using Microsoft API, the\n\"List\" Key permission is required.\nTo update the expiration date for the keys:\n1. Go to the Key vault, click on Access Control (IAM).\n2. Click on Add role assignment and assign the role of Key Vault Crypto Officer to\nthe appropriate user.\nRemediate from PowerShell\nSet-AzKeyVaultKeyAttribute -VaultName <VaultName> -Name <KeyName> -Expires\n<DateTime>",
    "default_value": "By default, keys do not expire.",
    "detection_commands": [
      "az keyvault list",
      "az keyvault key list --vault-name <VaultName> --query '[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'",
      "Get-AzKeyVault",
      "Get-AzKeyVault -VaultName <VaultName>",
      "Get-AzKeyVaultKey -VaultName <VaultName>"
    ],
    "remediation_commands": [
      "az keyvault key set-attributes --name <keyName> --vault-name <vaultName> --",
      "Set-AzKeyVaultKeyAttribute -VaultName <VaultName> -Name <KeyName> -Expires"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts",
      "2. https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-",
      "certificates",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-6-use-a-secure-key-management-process",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.keyvault/set-",
      "azkeyvaultkeyattribute"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 426,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.2",
    "title": "Ensure that the Expiration Date is set for all Keys in Non- RBAC Key Vaults",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Ensure that all Keys in Non Role Based Access Control (RBAC) Azure Key Vaults have\nan expiration date set.",
    "rationale": "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft\nAzure environment. The exp (expiration date) attribute identifies the expiration date on\nor after which the key MUST NOT be used for a cryptographic operation. By default,\nkeys never expire. It is thus recommended that keys be rotated in the key vault and set\nan explicit expiration date for all keys. This ensures that the keys cannot be used\nbeyond their assigned lifetimes.",
    "impact": "Keys cannot be used beyond their assigned expiration dates respectively. Keys need to\nbe rotated periodically wherever they are used.",
    "audit": "Audit from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Keys.\n3. In the main pane, ensure that the status of the key is Enabled.\n4. For each enabled key, ensure that an appropriate Expiration date is set.\nAudit from Azure CLI\nGet a list of all the key vaults in your Azure environment by running the following\ncommand:\naz keyvault list\nFor each key vault, ensure that the output of the below command contains Key ID (kid),\nenabled status as true and Expiration date (expires) is not empty or null:\naz keyvault key list --vault-name <KEYVAULTNAME> --query\n'[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'\nAudit from PowerShell\nRetrieve a list of Azure Key vaults:\nGet-AzKeyVault\nFor each Key vault, run the following command to determine which vaults are\nconfigured to not use RBAC:\nGet-AzKeyVault -VaultName <Vault Name>\nFor each Key vault with the EnableRbacAuthorizatoin setting set to False or empty,\nrun the following command.\nGet-AzKeyVaultKey -VaultName <Vault Name>\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0 - Name: 'Key Vault keys\nshould have an expiration date'",
    "expected_response": "3. In the main pane, ensure that the status of the key is Enabled.\n4. For each enabled key, ensure that an appropriate Expiration date is set.\nFor each key vault, ensure that the output of the below command contains Key ID (kid),\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nshould have an expiration date'",
    "remediation": "Remediate from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Keys.\n3. In the main pane, ensure that the status of the key is Enabled.\n4. For each enabled key, ensure that an appropriate Expiration date is set.\nRemediate from Azure CLI\nUpdate the Expiration date for the key using the below command:\naz keyvault key set-attributes --name <keyName> --vault-name <vaultName> --\nexpires Y-m-d'T'H:M:S'Z'\nNote: To view the expiration date on all keys in a Key Vault using Microsoft API, the\n\"List\" Key permission is required.\nTo update the expiration date for the keys:\n1. Go to Key vault, click on Access policies.\n2. Click on Create and add an access policy with the Update permission (in the\nKey Permissions - Key Management Operations section).\nRemediate from PowerShell\nSet-AzKeyVaultKeyAttribute -VaultName <Vault Name> -Name <Key Name> -Expires\n<DateTime>",
    "default_value": "By default, keys do not expire.",
    "detection_commands": [
      "az keyvault list",
      "az keyvault key list --vault-name <KEYVAULTNAME> --query '[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'",
      "Get-AzKeyVault",
      "Get-AzKeyVault -VaultName <Vault Name>",
      "Get-AzKeyVaultKey -VaultName <Vault Name>"
    ],
    "remediation_commands": [
      "az keyvault key set-attributes --name <keyName> --vault-name <vaultName> --",
      "Set-AzKeyVaultKeyAttribute -VaultName <Vault Name> -Name <Key Name> -Expires"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts",
      "2. https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-",
      "certificates",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-6-use-a-secure-key-management-process",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.keyvault/set-",
      "azkeyvaultkeyattribute"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 430,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.3",
    "title": "Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Ensure that all Secrets in Role Based Access Control (RBAC) Azure Key Vaults have\nan expiration date set.",
    "rationale": "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure\nenvironment. Secrets in the Azure Key Vault are octet sequences with a maximum size\nof 25k bytes each. The exp (expiration date) attribute identifies the expiration date on or\nafter which the secret MUST NOT be used. By default, secrets never expire. It is thus\nrecommended to rotate secrets in the key vault and set an explicit expiration date for all\nsecrets. This ensures that the secrets cannot be used beyond their assigned lifetimes.",
    "impact": "Secrets cannot be used beyond their assigned expiry date respectively. Secrets need to\nbe rotated periodically wherever they are used.",
    "audit": "Audit from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Secrets.\n3. In the main pane, ensure that the status of the secret is Enabled.\n4. For each enabled secret, ensure that an appropriate Expiration date is set.\nAudit from Azure CLI\nEnsure that the output of the below command contains ID (id), enabled status as true\nand Expiration date (expires) is not empty or null:\naz keyvault secret list --vault-name <KEYVAULTNAME> --query\n'[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'\nAudit from PowerShell\nRetrieve a list of Key vaults:\nGet-AzKeyVault\nFor each Key vault, run the following command to determine which vaults are\nconfigured to use RBAC:\nGet-AzKeyVault -VaultName <Vault Name>\nFor each Key vault with the EnableRbacAuthorization setting set to True, run the\nfollowing command:\nGet-AzKeyVaultSecret -VaultName <Vault Name>\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 98728c90-32c7-4049-8429-847dc0f4fe37 - Name: 'Key Vault secrets\nshould have an expiration date'",
    "expected_response": "3. In the main pane, ensure that the status of the secret is Enabled.\n4. For each enabled secret, ensure that an appropriate Expiration date is set.\nEnsure that the output of the below command contains ID (id), enabled status as true\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nshould have an expiration date'",
    "remediation": "Remediate from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Secrets.\n3. In the main pane, ensure that the status of the secret is Enabled.\n4. For each enabled secret, ensure that an appropriate Expiration date is set.\nRemediate from Azure CLI\nUpdate the Expiration date for the secret using the below command:\naz keyvault secret set-attributes --name <secret_name> --vault-name\n<vault_name> --expires Y-m-d'T'H:M:S'Z'\nNote: To view the expiration date on all secrets in a Key Vault using Microsoft API, the\nList Secret permission is required.\nTo update the expiration date for the secrets:\n1. Go to the Key vault, click on Access Control (IAM).\n2. Click on Add role assignment and assign the role of Key Vault Secrets\nOfficer to the appropriate user.\nRemediate from PowerShell\nSet-AzKeyVaultSecretAttribute -VaultName <vault_name> -Name <secret_name> -\nExpires <date_time>",
    "default_value": "By default, secrets do not expire.",
    "detection_commands": [
      "az keyvault secret list --vault-name <KEYVAULTNAME> --query '[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'",
      "Get-AzKeyVault",
      "Get-AzKeyVault -VaultName <Vault Name>",
      "Get-AzKeyVaultSecret -VaultName <Vault Name>"
    ],
    "remediation_commands": [
      "az keyvault secret set-attributes --name <secret_name> --vault-name",
      "Set-AzKeyVaultSecretAttribute -VaultName <vault_name> -Name <secret_name> -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts",
      "2. https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-",
      "certificates",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-6-use-a-secure-key-management-process",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.keyvault/set-",
      "azkeyvaultsecretattribute"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 434,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.4",
    "title": "Ensure that the Expiration Date is set for all Secrets in Non- RBAC Key Vaults",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Ensure that all Secrets in Non Role Based Access Control (RBAC) Azure Key Vaults\nhave an expiration date set.",
    "rationale": "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure\nenvironment. Secrets in the Azure Key Vault are octet sequences with a maximum size\nof 25k bytes each. The exp (expiration date) attribute identifies the expiration date on or\nafter which the secret MUST NOT be used. By default, secrets never expire. It is thus\nrecommended to rotate secrets in the key vault and set an explicit expiration date for all\nsecrets. This ensures that the secrets cannot be used beyond their assigned lifetimes.",
    "impact": "Secrets cannot be used beyond their assigned expiry date respectively. Secrets need to\nbe rotated periodically wherever they are used.",
    "audit": "Audit from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Secrets.\n3. In the main pane, ensure that the status of the secret is Enabled.\n4. Set an appropriate Expiration date on all secrets.\nAudit from Azure CLI\nGet a list of all the key vaults in your Azure environment by running the following\ncommand:\naz keyvault list\nFor each key vault, ensure that the output of the below command contains ID (id),\nenabled status as true and Expiration date (expires) is not empty or null:\naz keyvault secret list --vault-name <KEYVALUTNAME> --query\n'[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'\nAudit from PowerShell\nRetrieve a list of Key vaults:\nGet-AzKeyVault\nFor each Key vault run the following command to determine which vaults are configured\nto use RBAC:\nGet-AzKeyVault -VaultName <Vault Name>\nFor each Key Vault with the EnableRbacAuthorization setting set to False or empty,\nrun the following command.\nGet-AzKeyVaultSecret -VaultName <Vault Name>\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 98728c90-32c7-4049-8429-847dc0f4fe37 - Name: 'Key Vault secrets\nshould have an expiration date'",
    "expected_response": "3. In the main pane, ensure that the status of the secret is Enabled.\nFor each key vault, ensure that the output of the below command contains ID (id),\nMake sure the Expires setting is configured with a value as appropriate wherever the\nEnabled setting is set to True.\nshould have an expiration date'",
    "remediation": "Remediate from Azure Portal\n1. Go to Key vaults.\n2. For each Key vault, click on Secrets.\n3. In the main pane, ensure that the status of the secret is Enabled.\n4. Set an appropriate Expiration date on all secrets.\nRemediate from Azure CLI\nUpdate the Expiration date for the secret using the below command:\naz keyvault secret set-attributes --name <secret_name> --vault-name\n<vault_name> --expires Y-m-d'T'H:M:S'Z'\nNote: To view the expiration date on all secrets in a Key Vault using Microsoft API, the\nList Secret permission is required.\nTo update the expiration date for the secrets:\n1. Go to Key vault, click on Access policies.\n2. Click on Create and add an access policy with the Update permission (in the\nSecret Permissions - Secret Management Operations section).\nRemediate from PowerShell\nFor each Key vault with the EnableRbacAuthorization setting set to False or empty,\nrun the following command.\nSet-AzKeyVaultSecret -VaultName <vault_name> -Name <secret_name> -Expires\n<date_time>",
    "default_value": "By default, secrets do not expire.",
    "detection_commands": [
      "az keyvault list",
      "az keyvault secret list --vault-name <KEYVALUTNAME> --query '[*].{\"kid\":kid,\"enabled\":attributes.enabled,\"expires\":attributes.expires}'",
      "Get-AzKeyVault",
      "Get-AzKeyVault -VaultName <Vault Name>",
      "Get-AzKeyVaultSecret -VaultName <Vault Name>"
    ],
    "remediation_commands": [
      "az keyvault secret set-attributes --name <secret_name> --vault-name",
      "Set-AzKeyVaultSecret -VaultName <vault_name> -Name <secret_name> -Expires"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts",
      "2. https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-",
      "certificates",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-6-use-a-secure-key-management-process",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.keyvault/set-",
      "azkeyvaultsecret"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 437,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.5",
    "title": "Ensure 'Purge protection' is set to 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Key vaults contain object keys, secrets, and certificates. Deletion of a key vault can\ncause immediate data loss or loss of security functions (authentication, validation,\nverification, non-repudiation, etc.) supported by the key vault objects.\nIt is recommended the key vault be made recoverable by enabling the \"purge\nprotection\" function. This is to prevent the loss of encrypted data, including storage\naccounts, SQL databases, and/or dependent services provided by key vault objects\n(keys, secrets, certificates, etc.).\nNOTE: In February 2025, Microsoft enabled soft delete protection on all key vaults.\nUsers can no longer opt out of or turn off soft delete.\nWARNING: A current limitation is that role assignments disappear when a key vault is\ndeleted. All role assignments will need to be recreated after recovery.",
    "rationale": "Users may accidentally run delete/purge commands on a key vault, or an attacker or\nmalicious user may do so deliberately in order to cause disruption. Deleting or purging a\nkey vault leads to immediate data loss, as keys encrypting data and secrets/certificates\nallowing access/services will become inaccessible.\nEnabling purge protection ensures that even if a key vault is deleted, the key vault and\nits objects remain recoverable during the configurable retention period. If no action is\ntaken, the key vault and its objects will be purged once the retention period elapses.",
    "impact": "Once purge protection is enabled for a key vault, it cannot be disabled.",
    "audit": "Audit from Azure Portal\n1. Go to Key Vaults.\n2. Click the name of a key vault.\n3. Under Settings, click Properties.\n4. Next to Purge protection, ensure that Enable purge protection (enforce\na mandatory retention period for deleted vaults and vault\nobjects) is selected.\n5. Repeat steps 1-4 for each key vault.\nAudit from Azure CLI\nRun the following command to list key vaults:\naz resource list --query \"[?type=='Microsoft.KeyVault/vaults']\"\nFor each key vault, run the following command to get the purge protection setting:\naz resource show --resource-group <resource-group> --name <key-vault> --\nresource-type \"Microsoft.KeyVault/vaults\" --query\nproperties.enablePurgeProtection\nEnsure that true is returned.\nAudit from PowerShell\nRun the following command to list key vaults:\nGet-AzKeyVault\nFor each key vault, run the following command to get the key vault details:\nGet-AzKeyVault -ResourceGroupName <resource-group> -VaultName <key-vault>\nEnsure Purge Protection Enabled? is set to True.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 0b60c0b2-2dc2-4e1c-b5c9-abbed971de53 - Name: 'Key vaults should\nhave deletion protection enabled'",
    "expected_response": "4. Next to Purge protection, ensure that Enable purge protection (enforce\nEnsure that true is returned.\nEnsure Purge Protection Enabled? is set to True.\n• Policy ID: 0b60c0b2-2dc2-4e1c-b5c9-abbed971de53 - Name: 'Key vaults should",
    "remediation": "Note: Once enabled, purge protection cannot be disabled.\nRemediate from Azure Portal\n1. Go to Key Vaults.\n2. Click the name of a key vault.\n3. Under Settings, click Properties.\n4. Select the radio button next to Enable purge protection (enforce a\nmandatory retention period for deleted vaults and vault objects).\n5. Click Save.\n6. Repeat steps 1-5 for each key vault requiring remediation.\nRemediate from Azure CLI\nFor each key vault requiring remediation, run the following command to enable purge\nprotection:\naz resource update --resource-group <resource-group> --name <key-vault> --\nresource-type \"Microsoft.KeyVault/vaults\" --set\nproperties.enablePurgeProtection=true\nRemediate from PowerShell\nFor each key vault requiring remediation, run the following command to enable purge\nprotection:\nUpdate-AzKeyVault -ResourceGroupName <resource-group> -VaultName <key-vault>\n-EnablePurgeProtection",
    "default_value": "Purge protection is disabled by default.",
    "detection_commands": [
      "az resource list --query \"[?type=='Microsoft.KeyVault/vaults']\"",
      "az resource show --resource-group <resource-group> --name <key-vault> --",
      "Get-AzKeyVault",
      "Get-AzKeyVault -ResourceGroupName <resource-group> -VaultName <key-vault>"
    ],
    "remediation_commands": [
      "az resource update --resource-group <resource-group> --name <key-vault> --",
      "Update-AzKeyVault -ResourceGroupName <resource-group> -VaultName <key-vault>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-8-define-and-implement-backup-and-recovery-strategy",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-8-ensure-security-of-key-and-certificate-repository"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 441,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
      "backup",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.6",
    "title": "Ensure that Role Based Access Control for Azure Key Vault is enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Perform Complete System Backups",
    "description": "The recommended way to access Key Vaults is to use the Azure Role-Based Access\nControl (RBAC) permissions model.\nAzure RBAC is an authorization system built on Azure Resource Manager that provides\nfine-grained access management of Azure resources. It allows users to manage Key,\nSecret, and Certificate permissions. It provides one place to manage all permissions\nacross all key vaults.",
    "rationale": "The new RBAC permissions model for Key Vaults enables a much finer grained access\ncontrol for key vault secrets, keys, certificates, etc., than the vault access policy. This in\nturn will permit the use of privileged identity management over these roles, thus\nsecuring the key vaults with JIT Access management.",
    "impact": "Implementation needs to be properly designed from the ground up, as this is a\nfundamental change to the way key vaults are accessed/managed. Changing\npermissions to key vaults will result in loss of service as permissions are re-applied. For\nthe least amount of downtime, map your current groups and users to their\ncorresponding permission needs.",
    "audit": "Audit from Azure Portal\n1. From Azure Home open the Portal Menu in the top left corner\n2. Select Key Vaults\n3. Select a Key Vault to audit\n4. Select Access configuration\n5. Ensure the Permission Model radio button is set to Azure role-based access\ncontrol\nAudit from Azure CLI\nRun the following command for each Key Vault in each Resource Group:\naz keyvault show --resource-group <resource_group> --name <vault_name>\nEnsure the enableRbacAuthorization setting is set to true within the output of the\nabove command.\nAudit from PowerShell\nRun the following PowerShell command:\nGet-AzKeyVault -Vaultname <vault_name> -ResourceGroupName <resource_group>\nEnsure the Enabled For RBAC Authorization setting is set to True\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 12d4fa5e-1f9f-4c21-97a9-b99b3c6611b5 - Name: 'Azure Key Vault\nshould use RBAC permission model'",
    "expected_response": "5. Ensure the Permission Model radio button is set to Azure role-based access\nEnsure the enableRbacAuthorization setting is set to true within the output of the\nEnsure the Enabled For RBAC Authorization setting is set to True\nshould use RBAC permission model'",
    "remediation": "Remediate from Azure Portal\nKey Vaults can be configured to use Azure role-based access control on creation.\nFor existing Key Vaults:\n1. From Azure Home open the Portal Menu in the top left corner\n2. Select Key Vaults\n3. Select a Key Vault to audit\n4. Select Access configuration\n5. Set the Permission model radio button to Azure role-based access control,\ntaking note of the warning message\n6. Click Save\n7. Select Access Control (IAM)\n8. Select the Role Assignments tab\n9. Reapply permissions as needed to groups or users\nRemediate from Azure CLI\nTo enable RBAC Authorization for each Key Vault, run the following Azure CLI\ncommand:\naz keyvault update --resource-group <resource_group> --name <vault_name> --\nenable-rbac-authorization true\nRemediate from PowerShell\nTo enable RBAC authorization on each Key Vault, run the following PowerShell\ncommand:\nUpdate-AzKeyVault -ResourceGroupName <resource_group> -VaultName <vault_name>\n-EnableRbacAuthorization $True",
    "default_value": "The default value for Access control in Key Vaults is Vault Policy.",
    "detection_commands": [
      "az keyvault show --resource-group <resource_group> --name <vault_name>",
      "Get-AzKeyVault -Vaultname <vault_name> -ResourceGroupName <resource_group>"
    ],
    "remediation_commands": [
      "az keyvault update --resource-group <resource_group> --name <vault_name> --",
      "Update-AzKeyVault -ResourceGroupName <resource_group> -VaultName <vault_name>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration#vault-",
      "access-policy-to-azure-rbac-migration-steps",
      "2. https://learn.microsoft.com/en-us/azure/role-based-access-control/role-",
      "assignments-portal",
      "3. https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-8-ensure-security-of-key-and-certificate-repository"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 445,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
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
    "cis_id": "8.3.7",
    "title": "Ensure Public Network Access is Disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Disable public network access to prevent exposure to the internet and reduce the risk of\nunauthorized access. Use private endpoints to securely manage access within trusted\nnetworks.\nWhen a private endpoint is configured on a key vault, connections from Azure resources\nwithin the same subnet will use its private IP address. However, network traffic from the\npublic internet can still connect to the key vault's public endpoint\n(mykeyvault.vault.azure.net) using its public IP address unless public network access is\ndisabled.\nDisabling public network access removes the vault's public endpoint from Azure public\nDNS, reducing its exposure to the public internet. With a private endpoint configured,\nnetwork traffic will use the vault's private endpoint IP address for all requests\n(mykeyvault.vault.privatelink.azure.net).",
    "rationale": "Disabling public network access improves security by ensuring that a service is not\nexposed on the public internet.\nRemoving a point of interconnection from the internet edge to your key vault can\nstrengthen the network security boundary of your system and reduce the risk of\nexposing the control plane or vault objects to untrusted clients.\nAlthough Azure resources are never truly isolated from the public internet, disabling the\npublic endpoint removes a line of sight from the public internet and increases the effort\nrequired for an attack.",
    "impact": "NOTE: Prior to disabling public network access, it is strongly recommended that, for\neach key vault, either:\n• virtual network integration is completed\nOR\n• private endpoints/links are set up as described in \"Ensure Private Endpoints\nare used to access Azure Key Vault.\"\nDisabling public network access restricts access to the service. This enhances security\nbut will require the configuration of a virtual network and/or private endpoints for any\nservices or users needing access within trusted networks.",
    "audit": "Audit from Azure Portal\n1. Go to Key vaults.\n2. Click the name of a key vault.\n3. Under Settings, click Networking.\n4. Under Firewalls and virtual networks, ensure that Allow access from:\nis set to Disable public access.\n5. Repeat steps 1-4 for each key vault.\nAudit from Azure CLI\nRun the following command to list key vaults:\naz keyvault list\nFor each key vault, run the following command to get the public network access setting:\naz keyvault show --resource-group <resource-group> --name <key-vault> --query\nproperties.publicNetworkAccess\nEnsure that \"Disabled\" is returned.\nAudit from PowerShell\nRun the following command to list key vaults:\nGet-AzKeyVault\nRun the following command to get the key vault in a resource group with a given name:\n$vault = Get-AzKeyVault -ResourceGroupName <resource-group> -Name <key-vault>\nRun the following command to get the public network access setting for the key vault:\n$vault.PublicNetworkAccess\nEnsure that Disabled is returned.\nRepeat for each key vault.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 405c5871-3e91-4644-8a63-58e19d68ff5b - Name: 'Azure Key Vault\nshould disable public network access'",
    "expected_response": "4. Under Firewalls and virtual networks, ensure that Allow access from:\nis set to Disable public access.\nEnsure that \"Disabled\" is returned.\nEnsure that Disabled is returned.\nshould disable public network access'",
    "remediation": "Remediate from Azure Portal\n1. Go to Key vaults.\n2. Click the name of a key vault.\n3. Under Settings, click Networking.\n4. Under Firewalls and virtual networks, next to Allow access from:, click\nthe radio button next to Disable public access.\n5. Click Apply.\n6. Repeat steps 1-5 for each key vault requiring remediation.\nRemediate from Azure CLI\nFor each key vault requiring remediation, run the following command to disable public\nnetwork access:\naz keyvault update --resource-group <resource-group> --name <key-vault> --\npublic-network-access Disabled\nRemediate from PowerShell\nFor each key vault requiring remediation, run the following command to disable public\nnetwork access:\nUpdate-AzKeyVault -ResourceGroupName <resource-group> -VaultName <vault-name>\n-PublicNetworkAccess \"Disabled\"",
    "default_value": "Public network access is enabled by default.",
    "additional_information": "This recommendation is based on the Common Reference Recommendation Ensure\npublic network access is Disabled, from the Common Reference\nRecommendations > Networking > Virtual Networks (VNets) section.",
    "detection_commands": [
      "az keyvault list",
      "az keyvault show --resource-group <resource-group> --name <key-vault> --query",
      "Get-AzKeyVault",
      "$vault = Get-AzKeyVault -ResourceGroupName <resource-group> -Name <key-vault>",
      "$vault.PublicNetworkAccess"
    ],
    "remediation_commands": [
      "az keyvault update --resource-group <resource-group> --name <key-vault> --",
      "Update-AzKeyVault -ResourceGroupName <resource-group> -VaultName <vault-name>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
      "2. https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 448,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.8",
    "title": "Ensure Private Endpoints are used to access Azure Key Vault",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Use private endpoints to allow clients and services to securely access data located over\na network via an encrypted Private Link. To do this, the private endpoint uses an IP\naddress from the VNet for each service. Network traffic between disparate services\nsecurely traverses encrypted over the VNet. This VNet can also link addressing space,\nextending your network and accessing resources on it. Similarly, it can be a tunnel\nthrough public networks to connect remote infrastructures together. This creates further\nsecurity through segmenting network traffic and preventing outside sources from\naccessing it.\nPrivate endpoints will secure network traffic from Azure Key Vault to the resources\nrequesting secrets and keys.",
    "rationale": "Securing traffic between services through encryption protects the data from easy\ninterception and reading.\nPrivate endpoints will keep network requests to Azure Key Vault limited to the endpoints\nattached to the resources that are whitelisted to communicate with each other.\nAssigning the Key Vault to a network without an endpoint will allow other resources on\nthat network to view all traffic from the Key Vault to its destination. In spite of the\ncomplexity in configuration, this is recommended for high security secrets.",
    "impact": "If an Azure Virtual Network is not implemented correctly, this may result in the loss of\ncritical network traffic.\nPrivate endpoints are charged per hour of use. Refer to https://azure.microsoft.com/en-\nus/pricing/details/private-link/ and https://azure.microsoft.com/en-us/pricing/calculator/\nto estimate potential costs.",
    "audit": "Audit from Azure Portal\n1. From Azure Home open the Portal Menu in the top left.\n2. Select Key Vaults.\n3. Select a Key Vault to audit.\n4. Select Networking in the left column.\n5. Select Private endpoint connections from the top row.\n6. View if there is an endpoint attached.\nAudit from Azure CLI\nRun the following command within a subscription for each Key Vault you wish to audit.\naz keyvault show --name <keyVaultName>\nEnsure that privateEndpointConnections is not null.\nAudit from PowerShell\nRun the following command within a subscription for each Key Vault you wish to audit.\nGet-AzPrivateEndpointConnection -PrivateLinkResourceId\n'/subscriptions/<subscriptionNumber>/resourceGroups/<resourceGroup>/providers\n/Microsoft.KeyVault/vaults/<keyVaultName>/'\nEnsure that the response contains details of a private endpoint.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: a6abeaec-4d90-4a02-805f-6b26c4d3fbe9 - Name: 'Azure Key Vaults\nshould use private link'",
    "expected_response": "Ensure that privateEndpointConnections is not null.\nEnsure that the response contains details of a private endpoint.\nshould use private link'",
    "remediation": "Please see the additional information about the requirements needed before\nstarting this remediation procedure.\nRemediate from Azure Portal\n1. From Azure Home open the Portal Menu in the top left.\n2. Select Key Vaults.\n3. Select a Key Vault to audit.\n4. Select Networking in the left column.\n5. Select Private endpoint connections from the top row.\n6. Select + Create.\n7. Select the subscription the Key Vault is within, and other desired configuration.\n8. Select Next.\n9. For resource type select Microsoft.KeyVault/vaults.\n10. Select the Key Vault to associate the Private Endpoint with.\n11. Select Next.\n12. In the Virtual Networking field, select the network to assign the Endpoint.\n13. Select other configuration options as desired, including an existing or new\napplication security group.\n14. Select Next.\n15. Select the private DNS the Private Endpoints will use.\n16. Select Next.\n17. Optionally add Tags.\n18. Select Next : Review + Create.\n19. Review the information and select Create. Follow the Audit Procedure to\ndetermine if it has successfully applied.\n20. Repeat steps 3-19 for each Key Vault.\nRemediate from Azure CLI\n1. To create an endpoint, run the following command:\naz network private-endpoint create --resource-group <resourceGroup --vnet-\nname <vnetName> --subnet <subnetName> --name <PrivateEndpointName>  --\nprivate-connection-resource-id \"/subscriptions/<AZURE SUBSCRIPTION\nID>/resourceGroups/<resourceGroup>/providers/Microsoft.KeyVault/vaults/<keyVa\nultName>\" --group-ids vault --connection-name <privateLinkConnectionName> --\nlocation <azureRegion> --manual-request\n2. To manually approve the endpoint request, run the following command:\naz keyvault private-endpoint-connection approve --resource-group\n<resourceGroup> --vault-name <keyVaultName> –name <privateLinkName>\n3. Determine the Private Endpoint's IP address to connect the Key Vault to the\nPrivate DNS you have previously created:\n4. Look for the property networkInterfaces then id; the value must be placed in the\nvariable <privateEndpointNIC> within step 7.\naz network private-endpoint show -g <resourceGroupName> -n\n<privateEndpointName>\n5. Look for the property networkInterfaces then id; the value must be placed on\n<privateEndpointNIC> in step 7.\naz network nic show --ids <privateEndpointName>\n6. Create a Private DNS record within the DNS Zone you created for the Private\nEndpoint:\naz network private-dns record-set a add-record -g <resourcecGroupName> -z\n\"privatelink.vaultcore.azure.net\" -n <keyVaultName> -a <privateEndpointNIC>\n7. nslookup the private endpoint to determine if the DNS record is correct:\nnslookup <keyVaultName>.vault.azure.net\nnslookup <keyVaultName>.privatelink.vaultcore.azure.n",
    "default_value": "By default, Private Endpoints are not created for services.",
    "additional_information": "This recommendation assumes that you have created a Resource Group containing a\nVirtual Network that the services are already associated with and configured private\nDNS. A Bastion on the virtual network is also required, and the service to which you are\nconnecting must already have a Private Endpoint. For information concerning the\ninstallation of these services, please see the attached documentation.\nMicrosoft's own documentation lists the requirements as: A Key Vault. An Azure virtual\nnetwork. A subnet in the virtual network. Owner or contributor permissions for both the\nKey Vault and the virtual network.\nThis recommendation is based on the Common Reference Recommendation Ensure\nPrivate Endpoints are used to access {service}, from the Common Reference\nRecommendations > Networking > Private Endpoints section.",
    "detection_commands": [
      "az keyvault show --name <keyVaultName>",
      "Get-AzPrivateEndpointConnection -PrivateLinkResourceId '/subscriptions/<subscriptionNumber>/resourceGroups/<resourceGroup>/providers"
    ],
    "remediation_commands": [
      "az network private-endpoint create --resource-group <resourceGroup --vnet-",
      "az keyvault private-endpoint-connection approve --resource-group",
      "az network private-endpoint show -g <resourceGroupName> -n",
      "az network nic show --ids <privateEndpointName>",
      "az network private-dns record-set a add-record -g <resourcecGroupName> -z \"privatelink.vaultcore.azure.net\" -n <keyVaultName> -a <privateEndpointNIC>"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview",
      "2. https://learn.microsoft.com/en-us/azure/storage/common/storage-private-",
      "endpoints",
      "3. https://azure.microsoft.com/en-us/pricing/details/private-link/",
      "4. https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service",
      "5. https://learn.microsoft.com/en-us/azure/virtual-network/quick-create-portal",
      "6. https://learn.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-",
      "storage-portal",
      "7. https://learn.microsoft.com/en-us/azure/bastion/bastion-overview",
      "8. https://learn.microsoft.com/en-us/azure/dns/private-dns-getstarted-cli#create-an-",
      "additional-dns-record",
      "9. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-8-ensure-security-of-key-and-certificate-repository"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 452,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "key_management"
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
    "cis_id": "8.3.9",
    "title": "Ensure automatic key rotation is enabled within Azure Key Vault",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Segment the Network Based on Sensitivity",
    "description": "Automated cryptographic key rotation in Key Vault allows users to configure Key Vault\nto automatically generate a new key version at a specified frequency. A key rotation\npolicy can be defined for each individual key.",
    "rationale": "Automatic key rotation reduces risk by ensuring that keys are rotated without manual\nintervention.\nAzure and NIST recommend that keys be rotated every two years or less. Refer to\n'Table 1: Suggested cryptoperiods for key types' on page 46 of the following document\nfor more information:\nhttps://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf.",
    "impact": "There is an additional cost for each scheduled key rotation.",
    "audit": "Audit from Azure Portal\n1. Go to Key Vaults.\n2. Select a Key Vault.\n3. Under Objects, select Keys.\n4. Select a key.\n5. From the top row, select Rotation policy.\n6. Ensure Enable auto rotation is set to Enabled.\n7. Ensure the Rotation time is set to an appropriate value.\n8. Repeat steps 1-7 for each Key Vault and Key.\nAudit from Azure CLI\nRun the following command:\naz keyvault key rotation-policy show --vault-name <vault-name> --name <key-\nname>\nEnsure that the response contains a lifetimeAction of Rotate and that\ntimeAfterCreate is set to an appropriate value.\nAudit from PowerShell\nRun the following command:\nGet-AzKeyVaultKeyRotationPolicy -VaultName <vault-name> -Name <key-name>\nEnsure that the response contains a LifetimeAction of Rotate and that\nTimeAfterCreate is set to an appropriate value.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: d8cf8476-a2ec-4916-896e-992351803c44 - Name: 'Keys should have\na rotation policy ensuring that their rotation is scheduled within the specified\nnumber of days after creation.'",
    "expected_response": "6. Ensure Enable auto rotation is set to Enabled.\n7. Ensure the Rotation time is set to an appropriate value.\nEnsure that the response contains a lifetimeAction of Rotate and that\ntimeAfterCreate is set to an appropriate value.\nEnsure that the response contains a LifetimeAction of Rotate and that\nTimeAfterCreate is set to an appropriate value.\n• Policy ID: d8cf8476-a2ec-4916-896e-992351803c44 - Name: 'Keys should have",
    "remediation": "Note: Azure CLI and PowerShell use the ISO8601 duration format for time spans. The\nformat is P<timespanInISO8601Format>(Y,M,D). The leading P is required and is\nreferred to as period. The (Y,M,D) are for the duration of Year, Month, and Day,\nrespectively. A time frame of 2 years, 2 months, 2 days would be P2Y2M2D. For Azure\nCLI and PowerShell, it is easiest to supply the policy flags in a .json file, for\nexample:\n{\n\"lifetimeActions\": [\n{\n\"trigger\": {\n\"timeAfterCreate\": \"P<timespanInISO8601Format>(Y,M,D)\",\n\"timeBeforeExpiry\" : null\n},\n\"action\": {\n\"type\": \"Rotate\"\n}\n},\n{\n\"trigger\": {\n\"timeBeforeExpiry\" : \"P<timespanInISO8601Format>(Y,M,D)\"\n},\n\"action\": {\n\"type\": \"Notify\"\n}\n}\n],\n\"attributes\": {\n\"expiryTime\": \"P<timespanInISO8601Format>(Y,M,D)\"\n}\n}\nRemediate from Azure Portal\n1. Go to Key Vaults.\n2. Select a Key Vault.\n3. Under Objects, select Keys.\n4. Select a key.\n5. From the top row, select Rotation policy.\n6. Select an appropriate Expiry time.\n7. Set Enable auto rotation to Enabled.\n8. Set an appropriate Rotation option and Rotation time.\n9. Optionally, set a Notification time.\n10. Click Save.\n11. Repeat steps 1-10 for each Key Vault and Key.\nRemediate from Azure CLI\nRun the following command for each key to enable automatic rotation:\naz keyvault key rotation-policy update --vault-name <vault-name> --name <key-\nname> --value <path/to/policy.json>\nRemediate from PowerShell\nRun the following command for each key to enable automatic rotation:\nSet-AzKeyVaultKeyRotationPolicy -VaultName <vault-name> -Name <key-name> -\nPolicyPath <path/to/policy.json>",
    "default_value": "By default, automatic key rotation is not enabled.",
    "detection_commands": [
      "az keyvault key rotation-policy show --vault-name <vault-name> --name <key-",
      "Get-AzKeyVaultKeyRotationPolicy -VaultName <vault-name> -Name <key-name>"
    ],
    "remediation_commands": [
      "az keyvault key rotation-policy update --vault-name <vault-name> --name <key-",
      "Set-AzKeyVaultKeyRotationPolicy -VaultName <vault-name> -Name <key-name> -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-",
      "rotation",
      "2. https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-",
      "keys-overview#update-the-key-version",
      "3. https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-",
      "customer-managed-keys-powershell#set-up-an-azure-key-vault-and-",
      "diskencryptionset-optionally-with-automatic-key-rotation",
      "4. https://azure.microsoft.com/en-us/updates?id=public-preview-automatic-key-",
      "rotation-of-customermanaged-keys-for-encrypting-azure-managed-disks",
      "5. https://learn.microsoft.com/en-us/cli/azure/keyvault/key/rotation-policy",
      "6. https://learn.microsoft.com/en-us/powershell/module/az.keyvault/set-",
      "azkeyvaultkeyrotationpolicy",
      "7. https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/timespan",
      "8. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-6-use-a-secure-key-management-process",
      "9. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 457,
    "dspm_relevant": true,
    "dspm_categories": [
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.10",
    "title": "Ensure that Azure Key Vault Managed HSM is used when required",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Azure Key Vault Managed HSM is a fully managed, highly available, single-tenant cloud\nservice that safeguards cryptographic keys using FIPS 140-2 Level 3 validated HSMs.\nNote: While an automated assessment procedure exists for this recommendation, the\nassessment status remains manual, as this recommendation to use Managed HSM\napplies only to scenarios where specific regulatory and compliance requirements\nmandate the use of a dedicated hardware security module.",
    "rationale": "Managed HSM is a fully managed, highly available, single-tenant service that ensures\nFIPS 140-2 Level 3 compliance. It provides centralized key management, isolated\naccess control, and private endpoints for secure access. Integrated with Azure services,\nit supports migration from Key Vault, ensures data residency, and offers monitoring and\nauditing for enhanced security.",
    "impact": "Managed HSM incurs a cost per month for each actively used HSM-protected key,\ndepending on the key type and quantity. Each key version is billed separately.\nAdditionally, there is an hourly usage fee per Managed HSM pool. Refer to\nhttps://azure.microsoft.com/en-us/pricing/details/key-vault/ to estimate potential costs.",
    "audit": "Audit from Azure CLI\nRun the following command to list key vaults:\naz keyvault list --query [*].[name,type]\nEnsure that at least one key vault with type Microsoft.KeyVault/managedHSMs exists.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 587c79fe-dd04-4a5e-9d0b-f89598c7261b - Name: 'Keys should be\nbacked by a hardware security module (HSM)'",
    "expected_response": "Ensure that at least one key vault with type Microsoft.KeyVault/managedHSMs exists.\n• Policy ID: 587c79fe-dd04-4a5e-9d0b-f89598c7261b - Name: 'Keys should be",
    "remediation": "Remediate from Azure CLI\nRun the following command to set oid to be the OID of the signed-in user:\n$oid = az ad signed-in-user show --query id -o tsv\nAlternatively, prepare a space-separated list of OIDs to be provided as the\nadministrators of the HSM.\nRun the following command to create a Managed HSM:\naz keyvault create --resource-group <resource-group> --hsm-name <hsm-name> --\nretention-days <retention-days> --administrators $oid\nThe command can take several minutes to complete.\nAfter the HSM has been created, it must be activated before it can be used. Activation\nrequires providing a minimum of three and a maximum of ten RSA key pairs, as well as\nthe minimum number of keys required to decrypt the security domain (called a quorum).\nOpenSSL can be used to generate the self-signed certificates, for example:\nopenssl req -newkey rsa:2048 -nodes -keyout cert_1.key -x509 -days 365 -out\ncert_1.cer\nRun the following command to download the security domain and activate the Managed\nHSM:\naz keyvault security-domain download --hsm-name <managed-hsm> --sd-wrapping-\nkeys <key-1> <key-2> <key-3> --sd-quorum <quorum> --security-domain-file\n<managed-hsm-security-domain>.json\nStore the security domain file and the RSA key pairs securely. They will be required for\ndisaster recovery or for creating another Managed HSM that shares the same security\ndomain so that the two can share keys.\nThe Managed HSM will now be in an active state and ready for use.",
    "detection_commands": [
      "az keyvault list --query [*].[name,type]"
    ],
    "remediation_commands": [
      "$oid = az ad signed-in-user show --query id -o tsv",
      "az keyvault create --resource-group <resource-group> --hsm-name <hsm-name> --",
      "az keyvault security-domain download --hsm-name <managed-hsm> --sd-wrapping-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/security/fundamentals/key-management-",
      "choose",
      "2. https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview",
      "3. https://azure.microsoft.com/en-us/pricing/details/key-vault/",
      "4. https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-cli",
      "5. https://learn.microsoft.com/en-us/cli/azure/keyvault"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 461,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "8.3.11",
    "title": "Ensure certificate 'Validity Period (in months)' is less than or equal to '12'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Physically or Logically Segregate High Risk",
    "description": "Restrict the validity period of certificates stored in Azure Key Vault to 12 months or less.",
    "rationale": "Limiting certificate validity reduces the risk of misuse if compromised and helps ensure\ntimely renewal, improving security and reliability.",
    "impact": "Minor administrative effort required to ensure certificate renewal and lifecycle\nmanagement.",
    "audit": "Audit from Azure Portal\n1. Go to Key vaults.\n2. Click the name of a key vault.\n3. Under Objects, click Certificates.\n4. Click the name of a certificate.\n5. Click Issuance Policy.\n6. Ensure that Validity Period (in months) is set to 12 or less.\n7. Repeat steps 1-6 for each key vault and certificate.\nAudit from Azure CLI\nRun the following command to list key vaults:\naz keyvault list\nFor each key vault, run the following command to list certificates:\naz keyvault certificate list --vault-name <key-vault-name>\nFor each certificate, run the following command to get the certificate policy's\nvalidityInMonths setting:\naz keyvault certificate show --id <certificate-id> --query\npolicy.x509CertificateProperties.validityInMonths\nEnsure that 12 or less is returned.\nAudit from PowerShell\nRun the following command to list key vaults:\nGet-AzKeyVault\nRun the following command to get the key vault with a given name:\n$vault = Get-AzKeyVault -Name <key-vault-name>\nRun the following command to list certificates in the key vault:\nGet-AzKeyVaultCertificate -VaultName $vault.VaultName\nRun the following command to get the policy of a certificate with a given name:\n$certificate = Get-AzKeyVaultCertificatePolicy -VaultName $vault.VaultName -\nName <certificate-name>\nRun the following command to get the certificate policy's ValidityInMonths setting:\n$certificate.ValidityInMonths\nEnsure that 12 or less is returned.\nRepeat for each key vault and certificate.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 0a075868-4c26-42ef-914c-5bc007359560 - Name: 'Certificates\nshould have the specified maximum validity period'",
    "expected_response": "6. Ensure that Validity Period (in months) is set to 12 or less.\nEnsure that 12 or less is returned.\nshould have the specified maximum validity period'",
    "remediation": "Remediate from Azure Portal\n1. Go to Key vaults.\n2. Click the name of a key vault.\n3. Under Objects, click Certificates.\n4. Click the name of a certificate.\n5. Click Issuance Policy.\n6. Set Validity Period (in months) to an integer between 1 and 12, inclusive.\n7. Click Save.\n8. Repeat steps 1-7 for each key vault and certificate requiring remediation.\nRemediate from PowerShell\nFor each certificate requiring remediation, run the following command to set\nValidityInMonths to an integer between 1 and 12, inclusive:\nSet-AzKeyVaultCertificatePolicy -VaultName $vault.VaultName -Name\n<certificate-name> -ValidityInMonths <validity-in-months>",
    "default_value": "Validity Period (in months) is set to 12 by default.",
    "detection_commands": [
      "az keyvault list",
      "az keyvault certificate list --vault-name <key-vault-name>",
      "az keyvault certificate show --id <certificate-id> --query",
      "Get-AzKeyVault",
      "$vault = Get-AzKeyVault -Name <key-vault-name>",
      "Get-AzKeyVaultCertificate -VaultName $vault.VaultName",
      "$certificate = Get-AzKeyVaultCertificatePolicy -VaultName $vault.VaultName -",
      "$certificate.ValidityInMonths"
    ],
    "remediation_commands": [
      "Set-AzKeyVaultCertificatePolicy -VaultName $vault.VaultName -Name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates",
      "2. https://learn.microsoft.com/en-us/cli/azure/keyvault",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.keyvault"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 464,
    "dspm_relevant": true,
    "dspm_categories": [
      "key_management"
    ],
    "rr_relevant": false
  },
  {
    "cis_id": "8.4.1",
    "title": "Ensure an Azure Bastion Host Exists",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Azure Bastion",
    "description": "The Azure Bastion service allows secure remote access to Azure Virtual Machines over\nthe Internet without exposing remote access protocol ports and services directly to the\nInternet. The Azure Bastion service provides this access using TLS over 443/TCP, and\nsubscribes to hardened configurations within an organization's Azure Active Directory\nservice.",
    "rationale": "The Azure Bastion service allows organizations a more secure means of accessing\nAzure Virtual Machines over the Internet without assigning public IP addresses to those\nVirtual Machines. The Azure Bastion service provides Remote Desktop Protocol (RDP)\nand Secure Shell (SSH) access to Virtual Machines using TLS within a web browser,\nthus preventing organizations from opening up 3389/TCP and 22/TCP to the Internet on\nAzure Virtual Machines. Additional benefits of the Bastion service includes Multi-Factor\nAuthentication, Conditional Access Policies, and any other hardening measures\nconfigured within Azure Active Directory using a central point of access.",
    "impact": "The Azure Bastion service incurs additional costs and requires a specific virtual network\nconfiguration. The Standard tier offers additional configuration options compared to the\nBasic tier and may incur additional costs for those added features.",
    "audit": "Audit from Azure Portal\n1. Click on Bastions\n2. Ensure there is at least one Bastion host listed under the Name column\nAudit from Azure CLI\naz network bastion list --subscription <subscription ID>\nEnsure the output of the above command is not empty.\nAudit from PowerShell\nRetrieve the Bastion host(s) information for a specific Resource Group\nGet-AzBastion -ResourceGroupName <resource group name>\nEnsure the output of the above command is not empty.",
    "expected_response": "2. Ensure there is at least one Bastion host listed under the Name column\nEnsure the output of the above command is not empty.",
    "remediation": "Remediate from Azure Portal\n1. Click on Bastions\n2. Select the Subscription\n3. Select the Resource group\n4. Type a Name for the new Bastion host\n5. Select a Region\n6. Choose Standard next to Tier\n7. Use the slider to set the Instance count\n8. Select the Virtual network or Create new\n9. Select the Subnet named AzureBastionSubnet. Create a Subnet named\nAzureBastionSubnet using a /26 CIDR range if it doesn't already exist.\n10. Select the appropriate Public IP address option.\n11. If Create new is selected for the Public IP address option, provide a Public\nIP address name.\n12. If Use existing is selected for Public IP address option, select an IP\naddress from Choose public IP address\n13. Click Next: Tags >\n14. Configure the appropriate Tags\n15. Click Next: Advanced >\n16. Select the appropriate Advanced options\n17. Click Next: Review + create >\n18. Click Create\nRemediate from Azure CLI\naz network bastion create --location <location> --name <name of bastion host>\n--public-ip-address <public IP address name or ID> --resource-group <resource\ngroup name or ID> --vnet-name <virtual network containing subnet called\n\"AzureBastionSubnet\"> --scale-units <integer> --sku Standard [--disable-copy-\npaste true|false] [--enable-ip-connect true|false] [--enable-tunneling\ntrue|false]\nRemediate from PowerShell\nCreate the appropriate Virtual network settings and Public IP Address settings.\n$subnetName = \"AzureBastionSubnet\"\n$subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix\n<IP address range in CIDR notation making sure to use a /26>\n$virtualNet = New-AzVirtualNetwork -Name <virtual network name> -\nResourceGroupName <resource group name> -Location <location> -AddressPrefix\n<IP address range in CIDR notation> -Subnet $subnet\n$publicip = New-AzPublicIpAddress -ResourceGroupName <resource group name> -\nName <public IP address name> -Location <location> -AllocationMethod Dynamic\n-Sku Standard\nCreate the Azure Bastion service using the information within the created variables\nfrom above.\nNew-AzBastion -ResourceGroupName <resource group name> -Name <bastion name> -\nPublicIpAddress $publicip -VirtualNetwork $virtualNet -Sku \"Standard\" -\nScaleUnit <integer>",
    "default_value": "By default, the Azure Bastion service is not configured.",
    "detection_commands": [
      "az network bastion list --subscription <subscription ID>",
      "Get-AzBastion -ResourceGroupName <resource group name>"
    ],
    "remediation_commands": [
      "AzureBastionSubnet using a /26 CIDR range if it doesn't already exist.",
      "az network bastion create --location <location> --name <name of bastion host> --public-ip-address <public IP address name or ID> --resource-group <resource",
      "Create the appropriate Virtual network settings and Public IP Address settings. $subnetName = \"AzureBastionSubnet\" $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix",
      "$virtualNet = New-AzVirtualNetwork -Name <virtual network name> -",
      "$publicip = New-AzPublicIpAddress -ResourceGroupName <resource group name> -",
      "Create the Azure Bastion service using the information within the created variables",
      "New-AzBastion -ResourceGroupName <resource group name> -Name <bastion name> -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/bastion/bastion-overview#sku",
      "2. https://learn.microsoft.com/en-us/powershell/module/az.network/get-",
      "azbastion?view=azps-9.2.0",
      "3. https://learn.microsoft.com/en-us/cli/azure/network/bastion?view=azure-cli-latest"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 468,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "8.5",
    "title": "Ensure Azure DDoS Network Protection is enabled on virtual networks",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Services",
    "subdomain": "Document Traffic Configuration Rules",
    "description": "Azure DDoS Network Protection defends resources in virtual networks against\ndistributed denial-of-service (DDoS) attacks.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Determining the appropriateness of enabling Azure\nDDoS Network Protection depends on the context and requirements of each\norganization and environment.",
    "rationale": "Virtual networks and resources are protected against attacks, helping to ensure\nreliability and availability for critical workloads.",
    "impact": "Azure DDoS Network Protection incurs a significant fixed monthly charge, with\nadditional charges if more than 100 public IP resources are protected. Careful\nconsideration and analysis should be applied before enabling DDoS protection. Refer to\nhttps://azure.microsoft.com/en-us/pricing/details/ddos-protection for detailed pricing\ninformation.",
    "audit": "Audit from Azure Portal\n1. Go to Virtual networks.\n2. Click the name of a virtual network.\n3. Under Settings, click DDoS protection.\n4. Ensure DDoS Network Protection is set to Enable.\n5. Repeat steps 1-4 for each virtual network.\nAudit from Azure CLI\nRun the following command to list virtual networks:\naz network vnet list\nFor each virtual network, run the following command to get the DDoS protection setting:\naz network vnet show --resource-group <resource-group> --name <virtual-\nnetwork> --query enableDdosProtection\nEnsure true is returned.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: a7aca53f-2ed4-4466-a25e-0b45ade68efd - Name: 'Azure DDoS\nProtection should be enabled'",
    "expected_response": "4. Ensure DDoS Network Protection is set to Enable.\nEnsure true is returned.\nProtection should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Virtual networks.\n2. Click the name of a virtual network.\n3. Under Settings, click DDoS protection.\n4. Next to DDoS Network Protection, click Enable.\n5. Provide a DDoS protection plan resource ID, or select a DDoS protection plan\nfrom the drop-down menu.\n6. Click Save.\n7. Repeat steps 1-6 for each virtual network requiring remediation.\nRemediate from Azure CLI\nFor each virtual network requiring remediation, run the following command to enable\nDDoS protection:\naz network vnet update --resource-group <resource-group> --name <virtual-\nnetwork> --ddos-protection true --ddos-protection-plan <ddos-protection-plan>",
    "default_value": "DDoS protection is disabled by default.",
    "detection_commands": [
      "az network vnet list",
      "az network vnet show --resource-group <resource-group> --name <virtual-"
    ],
    "remediation_commands": [
      "az network vnet update --resource-group <resource-group> --name <virtual-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview",
      "2. https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection",
      "3. https://azure.microsoft.com/en-us/pricing/details/ddos-protection",
      "4. https://learn.microsoft.com/en-us/cli/azure/network/vnet"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 471,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "9.1.1",
    "title": "Ensure soft delete for Azure File Shares is Enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage Services",
    "subdomain": "Azure Files",
    "description": "Azure Files offers soft delete for file shares, allowing you to easily recover your data\nwhen it is mistakenly deleted by an application or another storage account user.",
    "rationale": "Important data could be accidentally deleted or removed by a malicious actor. With soft\ndelete enabled, the data is retained for the defined retention period before permanent\ndeletion, allowing for recovery of the data.",
    "impact": "When a file share is soft-deleted, the used portion of the storage is charged for the\nindicated soft-deleted period. All other meters are not charged unless the share is\nrestored.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account with file shares, under Data storage, click on File\nshares.\n3. Under File share settings, ensure the value for Soft delete shows a\nnumber of days between 1 and 365, inclusive.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nRun the following command to determine if a storage account has file shares:\naz storage share list --account-name <storage-account>\nFor each storage account with file shares, run the following command:\naz storage account file-service-properties show --resource-group <resource-\ngroup> --account-name <storage-account>\nEnsure that under shareDeleteRetentionPolicy, enabled is set to true, and days is\nset to an appropriate value between 1 and 365, inclusive.\nAudit from PowerShell\nRun the following command to list storage accounts:\nGet-AzStorageAccount -ResourceGroupName <resource-group>\nWith a storage account context set, run the following command to determine if a storage\naccount has file shares:\nGet-AzStorageShare\nFor each storage account with file shares, run the following command:\nGet-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -\nAccountName <storage-account>\nEnsure that ShareDeleteRetentionPolicy.Enabled is set to True and\nShareDeleteRetentionPolicy.Days is set to an appropriate value between 1 and\n365, inclusive.",
    "expected_response": "3. Under File share settings, ensure the value for Soft delete shows a\nEnsure that under shareDeleteRetentionPolicy, enabled is set to true, and days is\nEnsure that ShareDeleteRetentionPolicy.Enabled is set to True and\nShareDeleteRetentionPolicy.Days is set to an appropriate value between 1 and",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account with file shares, under Data storage, click File\nshares.\n3. Under File share settings, click the value next to Soft delete.\n4. Under Soft delete for all file shares, click the toggle to set it to\nEnabled.\n5. Under Retention policies, set an appropriate number of days to retain soft\ndeleted data between 1 and 365, inclusive.\n6. Click Save.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to enable\nsoft delete for file shares and set an appropriate number of days for deleted data to be\nretained, between 1 and 365, inclusive:\naz storage account file-service-properties update --account-name <storage-\naccount> --enable-delete-retention true --delete-retention-days <retention-\ndays>\nRemediate from PowerShell\nFor each storage account requiring remediation, run the following command to enable\nsoft delete for file shares and set an appropriate number of days for deleted data to be\nretained, between 1 and 365, inclusive:\nUpdate-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -\nAccountName <storage-account> -EnableShareDeleteRetentionPolicy $true -\nShareRetentionDays <retention-days>",
    "default_value": "Soft delete is enabled by default at the storage account file share setting level.",
    "detection_commands": [
      "az storage account list",
      "az storage share list --account-name <storage-account>",
      "az storage account file-service-properties show --resource-group <resource-",
      "Get-AzStorageAccount -ResourceGroupName <resource-group>",
      "Get-AzStorageShare",
      "Get-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -"
    ],
    "remediation_commands": [
      "az storage account file-service-properties update --account-name <storage-",
      "Update-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/files/storage-files-enable-soft-",
      "delete",
      "2. https://learn.microsoft.com/en-us/cli/azure/storage/account/file-service-properties",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.storage/get-",
      "azstoragefileserviceproperty",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.storage/update-",
      "azstoragefileserviceproperty",
      "5. https://learn.microsoft.com/en-us/azure/storage/files/storage-files-prevent-file-",
      "share-deletion"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 477,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "9.1.2",
    "title": "Ensure 'SMB protocol version' is set to 'SMB 3.1.1' or higher for SMB file shares",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage Services",
    "subdomain": "Ensure Protection of Backups",
    "description": "Ensure that SMB file shares are configured to use the latest supported SMB protocol\nversion. Keeping the SMB protocol updated helps mitigate risks associated with older\nSMB versions, which may contain vulnerabilities and lack essential security controls.",
    "rationale": "Using the latest supported SMB protocol version enhances the security of SMB file\nshares by preventing the exploitation of known vulnerabilities in outdated SMB versions.",
    "impact": "Using the latest SMB protocol version may impact client compatibility.",
    "audit": "Audit from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account.\n3. Under Data storage, click File shares.\n4. Under File share settings, click the link next to Security.\n5. Under SMB protocol versions, ensure that SMB3.1.1 is the only checked\nprotocol version.\n6. Repeat steps 1-5 for each storage account.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nFor each storage account, run the following command:\naz storage account file-service-properties show --resource-group <resource-\ngroup> --account-name <storage-account>\nEnsure that under protocolSettings > smb, versions is set to SMB3.1.1; only.\nAudit from PowerShell\nRun the following command to list storage accounts:\nGet-AzStorageAccount\nRun the following command to get the file service properties for a storage account in a\nresource group with a given name:\n$storageaccountfileservice = Get-AzStorageFileServiceProperty -\nResourceGroupName <resource-group> -AccountName <storage-account>\nRun the following command to get the SMB protocol version setting:\n$storageaccountfileservice.ProtocolSettings.Smb.Versions\nEnsure that the command returns SMB3.1.1 only.\nRepeat for each storage account.",
    "expected_response": "5. Under SMB protocol versions, ensure that SMB3.1.1 is the only checked\nEnsure that under protocolSettings > smb, versions is set to SMB3.1.1; only.\nEnsure that the command returns SMB3.1.1 only.",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account.\n3. Under Data storage, click File shares.\n4. Under File share settings, click the link next to Security.\n5. If Profile is set to Maximum compatibility, click the drop-down menu and\nselect Maximum security or Custom.\n6. If selecting Custom, under SMB protocol versions, uncheck the boxes next to\nSMB 2.1 and SMB 3.0.\n7. Click Save.\n8. Repeat steps 1-7 for each storage account requiring remediation.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to set the\nSMB protocol version:\naz storage account file-service-properties update --resource-group <resource-\ngroup> --account-name <storage-account> --versions SMB3.1.1\nRemediate from PowerShell\nFor each storage account requiring remediation, run the following command to set the\nSMB protocol version:\nUpdate-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -\nStorageAccountName <storage-account> -SmbProtocolVersion SMB3.1.1",
    "default_value": "By default, all SMB versions are allowed.",
    "detection_commands": [
      "az storage account list",
      "az storage account file-service-properties show --resource-group <resource-",
      "Get-AzStorageAccount",
      "$storageaccountfileservice = Get-AzStorageFileServiceProperty -",
      "$storageaccountfileservice.ProtocolSettings.Smb.Versions"
    ],
    "remediation_commands": [
      "select Maximum security or Custom.",
      "az storage account file-service-properties update --resource-group <resource-",
      "Update-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-",
      "files#recommendations-for-smb-file-shares",
      "2. https://learn.microsoft.com/en-us/azure/storage/files/files-smb-protocol#smb-",
      "security-settings",
      "3. https://learn.microsoft.com/en-us/cli/azure/storage/account/file-service-properties",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.storage/get-",
      "azstoragefileserviceproperty",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.storage/update-",
      "azstoragefileserviceproperty"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 480,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "9.1.3",
    "title": "Ensure 'SMB channel encryption' is set to 'AES-256-GCM' or higher for SMB file shares",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage Services",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Implement SMB channel encryption with AES-256-GCM for SMB file shares to ensure\ndata confidentiality and integrity in transit. This method offers strong protection against\neavesdropping and man-in-the-middle attacks, safeguarding sensitive information.",
    "rationale": "AES-256-GCM encryption enhances the security of data transmitted over SMB\nchannels by safeguarding it from unauthorized interception and tampering.",
    "impact": "Using the AES-256-GCM SMB channel encryption may impact client compatibility.",
    "audit": "Audit from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account.\n3. Under Data storage, click File shares.\n4. Under File share settings, click the link next to Security.\n5. Under SMB channel encryption, ensure that AES-256-GCM, or higher, is the\nonly checked SMB channel encryption setting.\n6. Repeat steps 1-5 for each storage account.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nFor each storage account, run the following command:\naz storage account file-service-properties show --resource-group <resource-\ngroup> --account-name <storage-account>\nEnsure that under protocolSettings > smb, channelEncryption is set to AES-256-\nGCM;, or higher, only.\nAudit from PowerShell\nRun the following command to list storage accounts:\nGet-AzStorageAccount\nRun the following command to get the file service properties for a storage account in a\nresource group with a given name:\n$storageaccountfileservice = Get-AzStorageFileServiceProperty -\nResourceGroupName <resource-group> -AccountName <storage-account>\nRun the following command to get the SMB channel encryption setting:\n$storageaccountfileservice.ProtocolSettings.Smb.ChannelEncryption\nEnsure that the command returns AES-256-GCM, or higher, only.\nRepeat for each storage account.",
    "expected_response": "5. Under SMB channel encryption, ensure that AES-256-GCM, or higher, is the\nEnsure that under protocolSettings > smb, channelEncryption is set to AES-256-\nEnsure that the command returns AES-256-GCM, or higher, only.",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account.\n3. Under Data storage, click File shares.\n4. Under File share settings, click the link next to Security.\n5. If Profile is set to Maximum compatibility, click the drop-down menu and\nselect Maximum security or Custom.\n6. If selecting Custom, under SMB channel encryption, uncheck the boxes next\nto AES-128-CCM and AES-128-GCM.\n7. Click Save.\n8. Repeat steps 1-7 for each storage account requiring remediation.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to set the\nSMB channel encryption:\naz storage account file-service-properties update --resource-group <resource-\ngroup> --account-name <storage-account> --channel-encryption AES-256-GCM\nRemediate from PowerShell\nFor each storage account requiring remediation, run the following command to set the\nSMB channel encryption:\nUpdate-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -\nStorageAccountName <storage-account> -SmbChannelEncryption AES-256-GCM",
    "default_value": "By default, the following SMB channel encryption algorithms are allowed:\n• AES-128-CCM\n• AES-128-GCM\n• AES-256-GCM",
    "detection_commands": [
      "az storage account list",
      "az storage account file-service-properties show --resource-group <resource-",
      "Get-AzStorageAccount",
      "$storageaccountfileservice = Get-AzStorageFileServiceProperty -",
      "$storageaccountfileservice.ProtocolSettings.Smb.ChannelEncryption"
    ],
    "remediation_commands": [
      "select Maximum security or Custom.",
      "az storage account file-service-properties update --resource-group <resource-",
      "Update-AzStorageFileServiceProperty -ResourceGroupName <resource-group> -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-",
      "files#recommendations-for-smb-file-shares",
      "2. https://learn.microsoft.com/en-us/azure/storage/files/files-smb-",
      "protocol?tabs=azure-portal#smb-security-settings",
      "3. https://learn.microsoft.com/en-us/cli/azure/storage/account/file-service-properties",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.storage/get-",
      "azstoragefileserviceproperty",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.storage/update-",
      "azstoragefileserviceproperty"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 483,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "9.2.1",
    "title": "Ensure that soft delete for blobs on Azure Blob Storage storage accounts is Enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage Services",
    "subdomain": "Azure Blob Storage",
    "description": "Blobs in Azure storage accounts may contain sensitive or personal data, such as ePHI\nor financial information. Data that is erroneously modified or deleted by an application or\na user can lead to data loss or unavailability.\nIt is recommended that soft delete be enabled on Azure storage accounts with blob\nstorage to allow for the preservation and recovery of data when blobs or blob snapshots\nare deleted.",
    "rationale": "Blobs can be deleted incorrectly. An attacker or malicious user may do this deliberately\nin order to cause disruption. Deleting an Azure storage blob results in immediate data\nloss. Enabling this configuration for Azure storage accounts ensures that even if blobs\nare deleted from the storage account, the blobs are recoverable for a specific period of\ntime, which is defined in the \"Retention policies,\" ranging from 7 to 365 days.",
    "impact": "All soft-deleted data is billed at the same rate as active data. Additional costs may be\nincurred for deleted blobs until the soft delete period ends and the data is permanently\nremoved.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each Storage Account with blob storage, under Data management, go to\nData protection.\n3. Ensure that Enable soft delete for blobs is checked.\n4. Ensure that the retention period is a sufficient length for your organization.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nRun the following command to determine if a storage account has containers:\naz storage container list --account-name <storage-account>\nFor each storage account with containers, ensure that the output of the below command\ncontains \"enabled\": true and days is not null:\naz storage blob service-properties delete-policy show --account-name\n<storage-account>",
    "expected_response": "3. Ensure that Enable soft delete for blobs is checked.\n4. Ensure that the retention period is a sufficient length for your organization.\nFor each storage account with containers, ensure that the output of the below command",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each Storage Account with blob storage, under Data management, go to\nData protection.\n3. Check the box next to Enable soft delete for blobs.\n4. Set the retention period to a sufficient length for your organization.\n5. Click Save.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to enable\nsoft delete for blobs:\naz storage blob service-properties delete-policy update --days-retained\n<retention-days> --account-name <storage-account> --enable true",
    "default_value": "Soft delete for blob storage is enabled by default on storage accounts created via the\nAzure Portal, and disabled by default on storage accounts created via Azure CLI or\nPowerShell.",
    "detection_commands": [
      "az storage account list",
      "az storage container list --account-name <storage-account>",
      "az storage blob service-properties delete-policy show --account-name"
    ],
    "remediation_commands": [
      "az storage blob service-properties delete-policy update --days-retained"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 487,
    "dspm_relevant": true,
    "dspm_categories": [
      "classification",
      "retention",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "9.2.2",
    "title": "Ensure that soft delete for containers on Azure Blob Storage storage accounts is Enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage Services",
    "subdomain": "Ensure Protection of Backups",
    "description": "Containers in Azure storage accounts may contain sensitive or personal data, such as\nePHI or financial information. Data that is erroneously modified or deleted by an\napplication or a user can lead to data loss or unavailability.\nIt is recommended that soft delete for containers be enabled on Azure storage accounts\nwith blob storage to allow for the preservation and recovery of data when containers are\ndeleted.",
    "rationale": "Containers can be deleted incorrectly. An attacker or malicious user may do this\ndeliberately in order to cause disruption. Deleting a container results in immediate data\nloss. Enabling this configuration for Azure storage accounts ensures that even if\ncontainers are deleted from the storage account, the containers are recoverable for a\nspecific period of time, which is defined in the \"Retention policies,\" ranging from 7 to\n365 days.",
    "impact": "All soft-deleted data is billed at the same rate as active data. Additional costs may be\nincurred for deleted containers until the soft delete period ends and the data is\npermanently removed.",
    "audit": "Audit from Azure Portal\n1. Go to Storage accounts.\n2. For each Storage Account with blob storage, under Data management, go to\nData protection.\n3. Ensure that Enable soft delete for containers is checked.\n4. Ensure that the retention period is a sufficient length for your organization.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nRun the following command to determine if a storage account has containers:\naz storage container list --account-name <storage-account>\nFor each storage account with containers, run the following command to get the\nretention settings:\naz storage account blob-service-properties show --resource-group <resource-\ngroup> --account-name <storage-account> --query\ncontainerDeleteRetentionPolicy\nEnsure that enabled is set to true and days is not null.",
    "expected_response": "3. Ensure that Enable soft delete for containers is checked.\n4. Ensure that the retention period is a sufficient length for your organization.\nEnsure that enabled is set to true and days is not null.",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage accounts.\n2. For each Storage Account with blob storage, under Data management, go to\nData protection.\n3. Check the box next to Enable soft delete for containers.\n4. Set the retention period to a sufficient length for your organization.\n5. Click Save.\nRemediate from Azure CLI\nRun the following command to update container retention:\naz storage account blob-service-properties update --resource-group <resource-\ngroup> --account-name <storage-account> --enable-container-delete-retention\ntrue --container-delete-retention-days <retention-days>",
    "default_value": "Soft delete for containers is enabled by default on storage accounts created via the\nAzure Portal, and disabled by default on storage accounts created via Azure CLI or\nPowerShell.",
    "detection_commands": [
      "az storage account list",
      "az storage container list --account-name <storage-account>",
      "az storage account blob-service-properties show --resource-group <resource-"
    ],
    "remediation_commands": [
      "az storage account blob-service-properties update --resource-group <resource-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-",
      "overview",
      "2. https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-",
      "enable"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 490,
    "dspm_relevant": true,
    "dspm_categories": [
      "classification",
      "retention",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "9.2.3",
    "title": "Ensure 'Versioning' is set to 'Enabled' on Azure Blob Storage storage accounts",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Ensure Protection of Backups",
    "description": "Enabling blob versioning allows for the automatic retention of previous versions of\nobjects. With blob versioning enabled, earlier versions of a blob are accessible for data\nrecovery in the event of modifications or deletions.",
    "rationale": "Blob versioning safeguards data integrity and enables recovery by retaining previous\nversions of stored objects, facilitating quick restoration from accidental deletion,\nmodification, or malicious activity.",
    "impact": "Enabling blob versioning for a storage account creates a new version with each write\noperation to a blob, which can increase storage costs. To control these costs, a lifecycle\nmanagement policy can be applied to automatically delete older versions.",
    "audit": "Audit from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account with blob storage.\n3. In the Overview page, on the Properties tab, under Blob service, ensure\nVersioning is set to Enabled.\n4. Repeat steps 1-3 for each storage account with blob storage.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nRun the following command to determine if a storage account has containers:\naz storage container list --account-name <storage-account>\nFor each storage account with containers, ensure that the output of the below command\ncontains \"isVersioningEnabled\": true:\naz storage account blob-service-properties show --account-name <storage-\naccount>\nAudit from PowerShell\nRun the following command to list storage accounts:\nGet-AzStorageAccount\nRun the following command to create an Azure Storage context for a storage account:\n$context = New-AzStorageContext -StorageAccountName <storage-account>\nRun the following command to list containers for the storage account:\nGet-AzStorageContainer -Context $context\nIf the storage account has containers, run the following command to get the blob service\nproperties of the storage account:\n$account = Get-AzStorageBlobServiceProperty -ResourceGroupName <resource-\ngroup> -AccountName <storage-account>\nRun the following command to get the blob versioning setting for the storage account:\n$account.IsVersioningEnabled\nEnsure that the command returns True.\nRepeat for each storage account.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: c36a325b-ae04-4863-ad4f-19c6678f8e08 - Name: 'Configure your\nStorage account to enable blob versioning'",
    "expected_response": "3. In the Overview page, on the Properties tab, under Blob service, ensure\nVersioning is set to Enabled.\nFor each storage account with containers, ensure that the output of the below command\nEnsure that the command returns True.",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account with blob storage.\n3. In the Overview page, on the Properties tab, under Blob service, click\nDisabled next to Versioning.\n4. Under Tracking, check the box next to Enable versioning for blobs.\n5. Select the radio button next to Keep all versions or Delete versions after\n(in days).\n6. If selecting to delete versions, enter a number of in the box after which to delete\nblob versions.\n7. Click Save.\n8. Repeat steps 1-7 for each storage account with blob storage.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to enable\nblob versioning:\naz storage account blob-service-properties update --account-name <storage-\naccount> --enable-versioning true\nRemediate from PowerShell\nFor each storage account requiring remediation, run the following command to enable\nblob versioning:\nUpdate-AzStorageBlobServiceProperty -ResourceGroupName <resource-group> -\nStorageAccountName <storage-account> -IsVersioningEnabled $true",
    "default_value": "Blob versioning is disabled by default on storage accounts.",
    "detection_commands": [
      "az storage account list",
      "az storage container list --account-name <storage-account>",
      "az storage account blob-service-properties show --account-name <storage-",
      "Get-AzStorageAccount",
      "$context = New-AzStorageContext -StorageAccountName <storage-account>",
      "Get-AzStorageContainer -Context $context",
      "$account = Get-AzStorageBlobServiceProperty -ResourceGroupName <resource-",
      "$account.IsVersioningEnabled"
    ],
    "remediation_commands": [
      "az storage account blob-service-properties update --account-name <storage-",
      "Update-AzStorageBlobServiceProperty -ResourceGroupName <resource-group> -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/cli/azure/storage/account",
      "2. https://learn.microsoft.com/en-us/cli/azure/storage/account/blob-service-",
      "properties",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.storage/get-",
      "azstorageaccount",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.storage/new-",
      "azstoragecontext",
      "5. https://learn.microsoft.com/en-us/powershell/module/az.storage/get-",
      "azstoragecontainer",
      "6. https://learn.microsoft.com/en-us/powershell/module/az.storage/get-",
      "azstorageblobserviceproperty",
      "7. https://learn.microsoft.com/en-us/powershell/module/az.storage/update-",
      "azstorageblobserviceproperty",
      "8. https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview",
      "9. https://learn.microsoft.com/en-us/azure/storage/blobs/lifecycle-management-",
      "overview"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 493,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.1.1",
    "title": "Ensure that 'Enable key rotation reminders' is enabled for each Storage Account",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Storage Accounts",
    "description": "Access Keys authenticate application access requests to data contained in Storage\nAccounts. A periodic rotation of these keys is recommended to ensure that potentially\ncompromised keys cannot result in a long-term exploitable credential. The \"Rotation\nReminder\" is an automatic reminder feature for a manual procedure.",
    "rationale": "Reminders such as those generated by this recommendation will help maintain a\nregular and healthy cadence for activities which improve the overall efficacy of a\nsecurity program.\nCryptographic key rotation periods will vary depending on your organization's security\nrequirements and the type of data which is being stored in the Storage Account. For\nexample, PCI DSS mandates that cryptographic keys be replaced or rotated 'regularly,'\nand advises that keys for static data stores be rotated every 'few months.'\nFor the purposes of this recommendation, 90 days will be prescribed for the reminder.\nReview and adjustment of the 90 day period is recommended, and may even be\nnecessary. Your organization's security requirements should dictate the appropriate\nsetting.",
    "impact": "This recommendation only creates a periodic reminder to regenerate access keys.\nRegenerating access keys can affect services in Azure as well as the organization's\napplications that are dependent on the storage account. All clients that use the access\nkey to access the storage account must be updated to use the new key.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts\n2. For each Storage Account, under Security + networking, go to Access keys\n3. If the button Edit rotation reminder is displayed, the Storage Account is\ncompliant. Click Edit rotation reminder and review the Remind me every\nfield for a desirable periodic setting that fits your security program's needs. If the\nbutton Set rotation reminder is displayed, the Storage Account is not\ncompliant.\nAudit from Powershell\n$rgName = <resource group name for the storage>\n$accountName = <storage account name>\n$account = Get-AzStorageAccount -ResourceGroupName $rgName -Name $accountName\nWrite-Output $accountName ->\nWrite-Output \"Expiration Reminder set to:\n$($account.KeyPolicy.KeyExpirationPeriodInDays) Days\"\nWrite-Output \"Key1 Last Rotated:\n$($account.KeyCreationTime.Key1.ToShortDateString())\"\nWrite-Output \"Key2 Last Rotated:\n$($account.KeyCreationTime.Key2.ToShortDateString())\"\nKey rotation is recommended if the creation date for any key is empty.\nIf the reminder is set, the period in days will be returned. The recommended period is 90\ndays.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 044985bb-afe1-42cd-8a36-9d5d42424537 - Name: 'Storage account\nkeys should not be expired'",
    "expected_response": "Write-Output $accountName ->\nWrite-Output \"Expiration Reminder set to:\nWrite-Output \"Key1 Last Rotated:\nWrite-Output \"Key2 Last Rotated:\nkeys should not be expired'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts\n2. For each Storage Account that is not compliant, under Security +\nnetworking, go to Access keys\n3. Click Set rotation reminder\n4. Check Enable key rotation reminders\n5. In the Send reminders field select Custom, then set the Remind me every field\nto 90 and the period drop down to Days\n6. Click Save\nRemediate from Powershell\n$rgName = <resource group name for the storage>\n$accountName = <storage account name>\n$account = Get-AzStorageAccount -ResourceGroupName $rgName -Name $accountName\nif ($account.KeyCreationTime.Key1 -eq $null -or $account.KeyCreationTime.Key2\n-eq $null){\nWrite-output (\"You must regenerate both keys at least once before\nsetting expiration policy\")\n} else {\n$account = Set-AzStorageAccount -ResourceGroupName $rgName -Name\n$accountName -KeyExpirationPeriodInDay 90\n}\n$account.KeyPolicy.KeyExpirationPeriodInDays",
    "default_value": "By default, Key rotation reminders are not configured.",
    "detection_commands": [
      "$rgName = <resource group name for the storage> $accountName = <storage account name> $account = Get-AzStorageAccount -ResourceGroupName $rgName -Name $accountName"
    ],
    "remediation_commands": [
      "$rgName = <resource group name for the storage> $accountName = <storage account name> $account = Get-AzStorageAccount -ResourceGroupName $rgName -Name $accountName",
      "$account = Set-AzStorageAccount -ResourceGroupName $rgName -Name $accountName -KeyExpirationPeriodInDay 90",
      "$account.KeyPolicy.KeyExpirationPeriodInDays"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-",
      "manage",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-3-manage-application-identities-securely-and-automatically",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "5. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-8-restrict-the-exposure-of-credentials-and-secrets",
      "6. https://www.pcidssguide.com/pci-dss-key-rotation-requirements/",
      "7. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 499,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "9.3.1.2",
    "title": "Ensure that Storage Account access keys are periodically regenerated",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "For increased security, regenerate storage account access keys periodically.",
    "rationale": "When a storage account is created, Azure generates two 512-bit storage access keys\nwhich are used for authentication when the storage account is accessed. Rotating these\nkeys periodically ensures that any inadvertent access or exposure does not result from\nthe compromise of these keys.\nCryptographic key rotation periods will vary depending on your organization's security\nrequirements and the type of data which is being stored in the Storage Account. For\nexample, PCI DSS mandates that cryptographic keys be replaced or rotated 'regularly,'\nand advises that keys for static data stores be rotated every 'few months.'\nFor the purposes of this recommendation, 90 days will be prescribed for the reminder.\nReview and adjustment of the 90 day period is recommended, and may even be\nnecessary. Your organization's security requirements should dictate the appropriate\nsetting.",
    "impact": "Regenerating access keys can affect services in Azure as well as the organization's\napplications that are dependent on the storage account. All clients who use the access\nkey to access the storage account must be updated to use the new key.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each Storage Account, under Security + networking, go to Access keys.\n3. Review the date and days in the Last rotated field for each key.\nIf the Last rotated field indicates a number or days greater than 90 [or greater than\nyour organization's period of validity], the key should be rotated.\nAudit from Azure CLI\n1. Get a list of storage accounts\naz storage account list --subscription <subscription-id>\nMake a note of id, name and resourceGroup.\n2. For every storage account make sure that key is regenerated in the past 90 days.\naz monitor activity-log list --namespace Microsoft.Storage --offset 90d --\nquery \"[?contains(authorization.action, 'regenerateKey')]\" --resource-id\n<resource id>\nThe output should contain\n\"authorization\"/\"scope\": <your_storage_account> AND \"authorization\"/\"action\":\n\"Microsoft.Storage/storageAccounts/regeneratekey/action\" AND\n\"status\"/\"localizedValue\": \"Succeeded\" \"status\"/\"Value\": \"Succeeded\"\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 044985bb-afe1-42cd-8a36-9d5d42424537 - Name: 'Storage account\nkeys should not be expired'",
    "expected_response": "your organization's period of validity], the key should be rotated.\nThe output should contain\nkeys should not be expired'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each Storage Account with outdated keys, under Security + networking,\ngo to Access keys.\n3. Click Rotate key next to the outdated key, then click Yes to the prompt\nconfirming that you want to regenerate the access key.\nAfter Azure regenerates the Access Key, you can confirm that Access keys reflects a\nLast rotated date of (0 days ago).",
    "default_value": "By default, access keys are not regenerated periodically.",
    "detection_commands": [
      "az storage account list --subscription <subscription-id>",
      "az monitor activity-log list --namespace Microsoft.Storage --offset 90d --"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-",
      "manage",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-",
      "access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-",
      "management#im-2-protect-identity-and-authentication-systems",
      "4. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy",
      "5. https://www.pcidssguide.com/pci-dss-key-rotation-requirements/",
      "6. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 502,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "9.3.1.3",
    "title": "Ensure 'Allow storage account key access' for Azure Storage Accounts is 'Disabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Every secure request to an Azure Storage account must be authorized. By default,\nrequests can be authorized with either Microsoft Entra credentials or by using the\naccount access key for Shared Key authorization.",
    "rationale": "Microsoft Entra ID provides superior security and ease of use compared to Shared Key\nand is recommended by Microsoft. To require clients to use Microsoft Entra ID for\nauthorizing requests, you can disallow requests to the storage account that are\nauthorized with Shared Key.",
    "impact": "When you disallow Shared Key authorization for a storage account, any requests to the\naccount that are authorized with Shared Key, including shared access signatures\n(SAS), will be denied. Client applications that currently access the storage account\nusing the Shared Key will no longer function.",
    "audit": "Audit from Azure Portal\n1. Go to Storage accounts.\n2. Click on a storage account.\n3. Under Settings, click Configuration.\n4. Under Allow storage account key access, ensure that the radio button next\nto Disabled is selected.\n5. Repeat steps 1-4 for each storage account.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nFor each storage account, run the following command:\naz storage account show --resource-group <resource-group> --name <storage-\naccount>\nEnsure that allowSharedKeyAccess is set to false.\nAudit from PowerShell\nRun the following command to list storage accounts:\nGet-AzStorageAccount\nRun the following command to get the storage account in a resource group with a given\nname:\n$storageAccount = Get-AzStorageAccount -ResourceGroupName <resource-group> -\nName <storage-account>\nRun the following command to get the shared key access setting for the storage\naccount:\n$storageAccount.allowSharedKeyAccess\nEnsure that the command returns False.\nRepeat for each storage account.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54 - Name: 'Storage accounts\nshould prevent shared key access'",
    "expected_response": "4. Under Allow storage account key access, ensure that the radio button next\nEnsure that allowSharedKeyAccess is set to false.\nEnsure that the command returns False.\nshould prevent shared key access'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage accounts.\n2. Click on a storage account.\n3. Under Settings, click Configuration.\n4. Under Allow storage account key access, click the radio button next to\nDisabled.\n5. Click Save.\n6. Repeat steps 1-5 for each storage account requiring remediation.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to disallow\nshared key authorization:\naz storage account update --resource-group <resource-group> --name <storage-\naccount> --allow-shared-key-access false\nRemediate from PowerShell\nFor each storage account requiring remediation, run the following command to disallow\nshared key authorization:\nSet-AzStorageAccount -ResourceGroupName <resource-group> -Name <storage-\naccount> -AllowSharedKeyAccess $false",
    "default_value": "The AllowSharedKeyAccess property of a storage account is not set by default and\ndoes not return a value until you explicitly set it. The storage account permits requests\nthat are authorized with the Shared Key when the property value is null or when it is\ntrue.",
    "detection_commands": [
      "az storage account list",
      "az storage account show --resource-group <resource-group> --name <storage-",
      "Get-AzStorageAccount",
      "$storageAccount = Get-AzStorageAccount -ResourceGroupName <resource-group> -",
      "$storageAccount.allowSharedKeyAccess"
    ],
    "remediation_commands": [
      "az storage account update --resource-group <resource-group> --name <storage-",
      "Set-AzStorageAccount -ResourceGroupName <resource-group> -Name <storage-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/shared-key-",
      "authorization-prevent",
      "2. https://learn.microsoft.com/en-us/cli/azure/storage/account",
      "3. https://learn.microsoft.com/en-us/powershell/module/az.storage/get-",
      "azstorageaccount",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.storage/set-",
      "azstorageaccount"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 505,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.2.1",
    "title": "Ensure Private Endpoints are used to access Storage Accounts",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Establish Process for Revoking Access",
    "description": "Use private endpoints for your Azure Storage accounts to allow clients and services to\nsecurely access data located over a network via an encrypted Private Link. To do this,\nthe private endpoint uses an IP address from the VNet for each service. Network traffic\nbetween disparate services securely traverses encrypted over the VNet. This VNet can\nalso link addressing space, extending your network and accessing resources on it.\nSimilarly, it can be a tunnel through public networks to connect remote infrastructures\ntogether. This creates further security through segmenting network traffic and\npreventing outside sources from accessing it.",
    "rationale": "Securing traffic between services through encryption protects the data from easy\ninterception and reading.",
    "impact": "If an Azure Virtual Network is not implemented correctly, this may result in the loss of\ncritical network traffic.\nPrivate endpoints are charged per hour of use. Refer to https://azure.microsoft.com/en-\nus/pricing/details/private-link/ and https://azure.microsoft.com/en-us/pricing/calculator/\nto estimate potential costs.",
    "audit": "Audit from Azure Portal\n1. Open the Storage Accounts blade.\n2. For each listed Storage Account, perform the following check:\n3. Under the Security + networking heading, click on Networking.\n4. Click on the Private endpoint connections tab at the top of the networking\nwindow.\n5. Ensure that for each VNet that the Storage Account must be accessed from, a\nunique Private Endpoint is deployed and the Connection state for each Private\nEndpoint is Approved.\nRepeat the procedure for each Storage Account.\nAudit from PowerShell\n$storageAccount = Get-AzStorageAccount -ResourceGroup '<ResourceGroupName>' -\nName '<storageaccountname>'\nGet-AzPrivateEndpoint -ResourceGroup '<ResourceGroupName>'|Where-Object\n{$_.PrivateLinkServiceConnectionsText -match $storageAccount.id}\nIf the results of the second command returns information, the Storage Account is using\na Private Endpoint and complies with this Benchmark, otherwise if the results of the\nsecond command are empty, the Storage Account generates a finding.\nAudit from Azure CLI\naz storage account show --name '<storage account name>' --query\n\"privateEndpointConnections[0].id\"\nIf the above command returns data, the Storage Account complies with this Benchmark,\notherwise if the results are empty, the Storage Account generates a finding.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 6edd7eda-6dd8-40f7-810d-67160c639cd9 - Name: 'Storage accounts\nshould use private link'",
    "expected_response": "5. Ensure that for each VNet that the Storage Account must be accessed from, a\nIf the results of the second command returns information, the Storage Account is using\nIf the above command returns data, the Storage Account complies with this Benchmark,\nshould use private link'",
    "remediation": "Remediate from Azure Portal\n1. Open the Storage Accounts blade\n2. For each listed Storage Account, perform the following:\n3. Under the Security + networking heading, click on Networking\n4. Click on the Private endpoint connections tab at the top of the networking\nwindow\n5. Click the + Private endpoint button\n6. In the 1 - Basics tab/step:\no Enter a name that will be easily recognizable as associated with the\nStorage Account (Note: The \"Network Interface Name\" will be\nautomatically completed, but you can customize it if needed.)\no Ensure that the Region matches the region of the Storage Account\no Click Next\n7. In the 2 - Resource tab/step:\no Select the target sub-resource based on what type of storage\nresource is being made available\no Click Next\n8. In the 3 - Virtual Network tab/step:\no Select the Virtual network that your Storage Account will be connecting\nto\no Select the Subnet that your Storage Account will be connecting to\no (Optional) Select other network settings as appropriate for your\nenvironment\no Click Next\n9. In the 4 - DNS tab/step:\no (Optional) Select other DNS settings as appropriate for your environment\no Click Next\n10. In the 5 - Tags tab/step:\no (Optional) Set any tags that are relevant to your organization\no Click Next\n11. In the 6 - Review + create tab/step:\no A validation attempt will be made and after a few moments it should\nindicate Validation Passed - if it does not pass, double-check your\nsettings before beginning more in depth troubleshooting.\no If validation has passed, click Create then wait for a few minutes for the\nscripted deployment to complete.\nRepeat the above procedure for each Private Endpoint required within every Storage\nAccount.\nRemediate from PowerShell\n$storageAccount = Get-AzStorageAccount -ResourceGroupName\n'<ResourceGroupName>' -Name '<storageaccountname>'\n$privateEndpointConnection = @{\nName = 'connectionName'\nPrivateLinkServiceId = $storageAccount.Id\nGroupID =\n\"blob|blob_secondary|file|file_secondary|table|table_secondary|queue|queue_se\ncondary|web|web_secondary|dfs|dfs_secondary\"\n}\n$privateLinkServiceConnection = New-AzPrivateLinkServiceConnection\n@privateEndpointConnection\n$virtualNetDetails = Get-AzVirtualNetwork -ResourceGroupName\n'<ResourceGroupName>' -Name '<name>'\n$privateEndpoint = @{\nResourceGroupName = '<ResourceGroupName>'\nName = '<PrivateEndpointName>'\nLocation = '<location>'\nSubnet = $virtualNetDetails.Subnets[0]\nPrivateLinkServiceConnection =\n$privateLinkServiceConnection\n}\nNew-AzPrivateEndpoint @privateEndpoint\nRemediate from Azure CLI\naz network private-endpoint create --resource-group <ResourceGroupName> --\nlocation <location> --name <private endpoint name> --vnet-name <VNET Name> --\nsubnet <subnet name> --private-connection-resource-id <storage account ID> --\nconnection-name <private link service connection name> --group-id\n<blob|blob_secondary|file|file_secondary|table|table_secondary|queue|queue_se\ncondary|web|web_secondary|dfs|dfs_secondary>",
    "default_value": "By default, Private Endpoints are not created for Storage Accounts.",
    "additional_information": "A NAT gateway is the recommended solution for outbound internet access.\nThis recommendation is based on the Common Reference Recommendation Ensure\nPrivate Endpoints are used to access {service}, from the Common Reference\nRecommendations > Networking > Private Endpoints section.",
    "detection_commands": [
      "$storageAccount = Get-AzStorageAccount -ResourceGroup '<ResourceGroupName>' -",
      "Get-AzPrivateEndpoint -ResourceGroup '<ResourceGroupName>'|Where-Object",
      "az storage account show --name '<storage account name>' --query \"privateEndpointConnections[0].id\""
    ],
    "remediation_commands": [
      "$storageAccount = Get-AzStorageAccount -ResourceGroupName '<ResourceGroupName>' -Name '<storageaccountname>' $privateEndpointConnection = @{",
      "$privateLinkServiceConnection = New-AzPrivateLinkServiceConnection",
      "$virtualNetDetails = Get-AzVirtualNetwork -ResourceGroupName '<ResourceGroupName>' -Name '<name>' $privateEndpoint = @{",
      "$privateLinkServiceConnection",
      "New-AzPrivateEndpoint @privateEndpoint",
      "az network private-endpoint create --resource-group <ResourceGroupName> --"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/storage-private-",
      "endpoints",
      "2. https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview",
      "3. https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-portal",
      "4. https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-cli",
      "5. https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-",
      "powershell",
      "6. https://learn.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-",
      "storage-portal",
      "7. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-2-secure-cloud-native-services-with-network-controls"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 510,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4"
    ]
  },
  {
    "cis_id": "9.3.2.2",
    "title": "Ensure that 'Public Network Access' is 'Disabled' for storage accounts",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Segment the Network Based on Sensitivity",
    "description": "Disable public network access to prevent exposure to the internet and reduce the risk of\nunauthorized access. Use private endpoints to securely manage access within trusted\nnetworks.\nDisallowing public network access for a storage account overrides the public access\nsettings for individual containers in that storage account.",
    "rationale": "Disabling public network access improves security by ensuring that a storage account is\nnot exposed on the public internet.\nThe default network configuration for a storage account permits a user with appropriate\npermissions to configure public network access to containers and blobs in a storage\naccount. Keep in mind that public access to a container is always turned off by default\nand must be explicitly configured to permit anonymous requests. It grants read-only\naccess to these resources without sharing the account key, and without requiring a\nshared access signature. It is recommended not to provide public network access to\nstorage accounts until, and unless, it is strongly desired. A shared access signature\ntoken or Azure AD RBAC should be used for providing controlled and timed access to\nblob containers.",
    "impact": "NOTE: Prior to disabling public network access, it is strongly recommended that, for\neach storage account, either:\n• virtual network integration is completed\nOR\n• private endpoints/links are set up as described in \"Ensure Private Endpoints\nare used to access Storage Accounts.\"\nDisabling public network access restricts direct access to the service. This enhances\nsecurity but will require the configuration of a virtual network and/or private endpoints for\nany services or users needing access within trusted networks.\nAccess will have to be managed using shared access signatures or via Azure AD\nRBAC.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under the Security + networking section, click\nNetworking.\n3. Ensure the Public network access setting is set to Disabled.\nAudit from Azure CLI\nEnsure publicNetworkAccess is Disabled\naz storage account show --name <storage-account> --resource-group <resource-\ngroup> --query \"{publicNetworkAccess:publicNetworkAccess}\"\nAudit from PowerShell\nFor each Storage Account, ensure PublicNetworkAccess is Disabled\nGet-AzStorageAccount -Name <storage account name> -ResourceGroupName\n<resource group name> |select PublicNetworkAccess\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: b2982f36-99f2-4db5-8eff-283140c09693 - Name: 'Storage accounts\nshould disable public network access'",
    "expected_response": "3. Ensure the Public network access setting is set to Disabled.\nEnsure publicNetworkAccess is Disabled\nFor each Storage Account, ensure PublicNetworkAccess is Disabled\nshould disable public network access'",
    "remediation": "Remediate from Azure Portal\nFirst, follow Microsoft documentation and create shared access signature tokens for\nyour blob containers. Then,\n1. Go to Storage Accounts.\n2. For each storage account, under the Security + networking section, click\nNetworking.\n3. Set Public network access to Disabled.\n4. Click Save.\nRemediate from Azure CLI\nSet 'Public Network Access' to Disabled on the storage account\naz storage account update --name <storage-account> --resource-group\n<resource-group> --public-network-access Disabled\nRemediate from PowerShell\nFor each Storage Account, run the following to set the PublicNetworkAccess setting to\nDisabled\nSet-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage\naccount name> -PublicNetworkAccess Disabled",
    "default_value": "By default, Public Network Access is set to Enabled from all networks for the\nStorage Account.",
    "additional_information": "This recommendation is based on the Common Reference Recommendation Ensure\npublic network access is Disabled, from the Common Reference\nRecommendations > Networking > Virtual Networks (VNets) section.",
    "detection_commands": [
      "az storage account show --name <storage-account> --resource-group <resource-",
      "Get-AzStorageAccount -Name <storage account name> -ResourceGroupName"
    ],
    "remediation_commands": [
      "az storage account update --name <storage-account> --resource-group",
      "Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-",
      "configure",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-2-secure-cloud-native-services-with-network-controls",
      "4. https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-",
      "access",
      "5. https://learn.microsoft.com/en-us/azure/storage/common/storage-network-",
      "security"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 515,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.2.3",
    "title": "Ensure default network access rule for storage accounts is set to deny",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Restricting default network access helps to provide a new layer of security, since\nstorage accounts accept connections from clients on any network. To limit access to\nselected networks, the default action must be changed.",
    "rationale": "NOTE: This recommendation is only applicable if Public Network Access has not been\ndisabled due to necessity or exception.\nStorage accounts should be configured to deny access to traffic from all networks\n(including internet traffic). Access can be granted to traffic from specific Azure Virtual\nnetworks, allowing a secure network boundary for specific applications to be built.\nAccess can also be granted to public internet IP address ranges to enable connections\nfrom specific internet or on-premises clients. When network rules are configured, only\napplications from allowed networks can access a storage account. When calling from an\nallowed network, applications continue to require proper authorization (a valid access\nkey or SAS token) to access the storage account.",
    "impact": "All allowed networks will need to be whitelisted on each specific network, creating\nadministrative overhead. This may result in loss of network connectivity, so do not turn\non for critical resources during business hours.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Security + networking, click Networking.\n3. Click the Firewalls and virtual networks heading.\n4. Ensure that Public network access is not set to Enabled from all\nnetworks.\nAudit from Azure CLI\nEnsure defaultAction is not set to Allow.\naz storage account list --query '[*].networkRuleSet'\nAudit from PowerShell\nConnect-AzAccount\nSet-AzContext -Subscription <subscription ID>\nGet-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name\n<storage account name> |Select-Object DefaultAction\nPowerShell Result - Non-Compliant\nDefaultAction       : Allow\nPowerShell Result - Compliant\nDefaultAction       : Deny\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 34c877ad-507e-4c82-993e-3452a6e0ad3c - Name: 'Storage accounts\nshould restrict network access'\n• Policy ID: 2a1a9cdf-e04d-429a-8416-3bfb72a1b26f - Name: 'Storage accounts\nshould restrict network access using virtual network rules'",
    "expected_response": "4. Ensure that Public network access is not set to Enabled from all\nEnsure defaultAction is not set to Allow.\nshould restrict network access'\nshould restrict network access using virtual network rules'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Security + networking, click Networking.\n3. Click the Firewalls and virtual networks heading.\n4. Set Public network access to Enabled from selected virtual networks\nand IP addresses.\n5. Add rules to allow traffic from specific networks and IP addresses.\n6. Click Save.\nRemediate from Azure CLI\nUse the below command to update default-action to Deny.\naz storage account update --name <StorageAccountName> --resource-group\n<resourceGroupName> --default-action Deny",
    "default_value": "By default, Storage Accounts will accept connections from clients on any network.",
    "additional_information": "This recommendation is based on the Common Reference Recommendation Ensure\nNetwork Access Rules are set to Deny-by-default, from the Common\nReference Recommendations > Networking > Virtual Networks (VNets)\nsection.",
    "detection_commands": [
      "az storage account list --query '[*].networkRuleSet'",
      "Set-AzContext -Subscription <subscription ID> Get-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name"
    ],
    "remediation_commands": [
      "Use the below command to update default-action to Deny. az storage account update --name <StorageAccountName> --resource-group"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/storage-network-",
      "security",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-",
      "strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-",
      "duties-strategy",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-2-secure-cloud-native-services-with-network-controls"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 519,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.3.1",
    "title": "Ensure that 'Default to Microsoft Entra authorization in the Azure portal' is set to 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Monitor and Block Unauthorized Network Traffic",
    "description": "When this property is enabled, the Azure portal authorizes requests to blobs, files,\nqueues, and tables with Microsoft Entra ID by default.",
    "rationale": "Microsoft Entra ID provides superior security and ease of use over Shared Key.",
    "audit": "Audit from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account.\n3. Under Settings, click Configuration.\n4. Ensure that Default to Microsoft Entra authorization in the Azure\nportal is set to Enabled.\n5. Repeat steps 1-4 for each storage account.\nAudit from Azure CLI\nRun the following command to get the name and defaultToOAuthAuthentication\nsetting for each storage account:\naz storage account list --query [*].[name,defaultToOAuthAuthentication]\nEnsure that true is returned for each storage account.",
    "expected_response": "4. Ensure that Default to Microsoft Entra authorization in the Azure\nportal is set to Enabled.\nEnsure that true is returned for each storage account.",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage accounts.\n2. Click the name of a storage account.\n3. Under Settings, click Configuration.\n4. Under Default to Microsoft Entra authorization in the Azure\nportal, click the radio button next to Enabled.\n5. Click Save.\n6. Repeat steps 1-5 for each storage account requiring remediation.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to enable\ndefaultToOAuthAuthentication:\naz storage account update --resource-group <resource-group> --name <storage-\naccount> --set defaultToOAuthAuthentication=true",
    "default_value": "By default, defaultToOAuthAuthentication is disabled.",
    "detection_commands": [
      "az storage account list --query [*].[name,defaultToOAuthAuthentication]"
    ],
    "remediation_commands": [
      "az storage account update --resource-group <resource-group> --name <storage-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-",
      "portal#default-to-microsoft-entra-authorization-in-the-azure-portal",
      "2. https://learn.microsoft.com/en-us/cli/azure/storage/account"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 523,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.4",
    "title": "Ensure that 'Secure transfer required' is set to 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Enable data encryption in transit.",
    "rationale": "The secure transfer option enhances the security of a storage account by only allowing\nrequests to the storage account by a secure connection. For example, when calling\nREST APIs to access storage accounts, the connection must use HTTPS. Any requests\nusing HTTP will be rejected when 'secure transfer required' is enabled. When using the\nAzure files service, connection without encryption will fail, including scenarios using\nSMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client.\nBecause Azure storage doesn’t support HTTPS for custom domain names, this option is\nnot applied when using a custom domain name.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Settings, click Configuration.\n3. Ensure that Secure transfer required is set to Enabled.\nAudit from Azure CLI\nUse the below command to ensure the Secure transfer required is enabled for all\nthe Storage Accounts by ensuring the output contains true for each of the Storage\nAccounts.\naz storage account list --query \"[*].[name,enableHttpsTrafficOnly]\"\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 404c3081-a854-4457-ae30-26a93ef643f9 - Name: 'Secure transfer to\nstorage accounts should be enabled'",
    "expected_response": "3. Ensure that Secure transfer required is set to Enabled.\nUse the below command to ensure the Secure transfer required is enabled for all\nthe Storage Accounts by ensuring the output contains true for each of the Storage\nstorage accounts should be enabled'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Settings, click Configuration.\n3. Set Secure transfer required to Enabled.\n4. Click Save.\nRemediate from Azure CLI\nUse the below command to enable Secure transfer required for a Storage\nAccount\naz storage account update --name <storageAccountName> --resource-group\n<resourceGroupName> --https-only true",
    "default_value": "By default, Secure transfer required is set to Disabled.",
    "detection_commands": [
      "Use the below command to ensure the Secure transfer required is enabled for all",
      "az storage account list --query \"[*].[name,enableHttpsTrafficOnly]\""
    ],
    "remediation_commands": [
      "Use the below command to enable Secure transfer required for a Storage",
      "az storage account update --name <storageAccountName> --resource-group"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations",
      "2. https://learn.microsoft.com/en-us/cli/azure/storage/account",
      "3. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-3-encrypt-sensitive-data-in-transit"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 525,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.5",
    "title": "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "NOTE: This recommendation assumes that the Public network access parameter is\nset to Enabled from selected virtual networks and IP addresses. Please\nensure the prerequisite recommendation has been implemented before proceeding:\n• Ensure Default Network Access Rule for Storage Accounts is Set to Deny\nIf the Allow Azure services on the trusted services list to access this\nstorage account exception is enabled, the following services are granted access to\nthe storage account:\n• Azure Backup,\n• Azure Data Box,\n• Azure DevTest Labs,\n• Azure Event Grid,\n• Azure Event Hubs,\n• Azure File Sync,\n• Azure HDInsight,\n• Azure Import/Export,\n• Azure Monitor,\n• Azure Networking Services, and\n• Azure Site Recovery (when registered in the subscription).",
    "rationale": "NOTE: If none of the services listed in the Description are in use in your environment,\nyou may wish to make an exception to this recommendation and disable 'Allow Azure\nservices on the trusted services list to access this storage account.'\nTurning on firewall rules for a storage account will block access to incoming requests for\ndata, including from other Azure services.\nSome Azure services that interact with storage accounts operate from networks that\ncan't be granted access through network rules. To help this type of service work as\nintended, allow the set of trusted Azure services to bypass the network rules. These\nservices will then use strong authentication to access the storage account.",
    "impact": "This creates authentication credentials for services that need access to storage\nresources so that services will no longer need to communicate via network request.\nThere may be a temporary loss of communication as you set each Storage Account. It\nis recommended to not do this on mission-critical resources during business hours.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Security + networking, click Networking.\n3. Click on the Firewalls and virtual networks heading.\n4. Under Exceptions, ensure that Allow Azure services on the trusted\nservices list to access this storage account is checked.\nAudit from Azure CLI\nEnsure bypass contains AzureServices\naz storage account list --query '[*].networkRuleSet'\nAudit from PowerShell\nConnect-AzAccount\nSet-AzContext -Subscription <subscription ID>\nGet-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name\n<storage account name> |Select-Object Bypass\nIf the response from the above command is None, the storage account configuration is\nout of compliance with this check. If the response is AzureServices, the storage\naccount configuration is in compliance with this check.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: c9d007d0-c057-4772-b18c-01e546713bcd - Name: 'Storage accounts\nshould allow access from trusted Microsoft services'",
    "expected_response": "4. Under Exceptions, ensure that Allow Azure services on the trusted\nEnsure bypass contains AzureServices\nshould allow access from trusted Microsoft services'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Security + networking, click Networking.\n3. Click on the Firewalls and virtual networks heading.\n4. Under Exceptions, check the box next to Allow Azure services on the\ntrusted services list to access this storage account.\n5. Click Save.\nRemediate from Azure CLI\nUse the below command to update bypass to Azure services.\naz storage account update --name <StorageAccountName> --resource-group\n<resourceGroupName> --bypass AzureServices",
    "default_value": "By default, Storage Accounts will accept connections from clients on any network.",
    "detection_commands": [
      "az storage account list --query '[*].networkRuleSet'",
      "Set-AzContext -Subscription <subscription ID> Get-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name"
    ],
    "remediation_commands": [
      "Use the below command to update bypass to Azure services. az storage account update --name <StorageAccountName> --resource-group"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/storage-network-",
      "security",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-",
      "security#ns-2-secure-cloud-native-services-with-network-controls"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 527,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "9.3.6",
    "title": "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Monitor and Block Unauthorized Network Traffic",
    "description": "In some cases, Azure Storage sets the minimum TLS version to be version 1.0 by\ndefault. TLS 1.0 is a legacy version and has known vulnerabilities. This minimum TLS\nversion can be configured to be later protocols such as TLS 1.2.",
    "rationale": "TLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS\nprotocol. Continued use of this legacy protocol affects the security of data in transit.",
    "impact": "When set to TLS 1.2 all requests must leverage this version of the protocol. Applications\nleveraging legacy versions of the protocol will fail.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Settings, click Configuration.\n3. Ensure that the Minimum TLS version is set to Version 1.2.\nAudit from Azure CLI\nGet a list of all storage accounts and their resource groups\naz storage account list | jq '.[] | {name, resourceGroup}'\nThen query the minimumTLSVersion field\naz storage account show \\\n--name <storage-account> \\\n--resource-group <resource-group> \\\n--query minimumTlsVersion \\\n--output tsv\nAudit from PowerShell\nTo get the minimum TLS version, run the following command:\n(Get-AzStorageAccount -Name <STORAGEACCOUNTNAME>  -ResourceGroupName\n<RESOURCEGROUPNAME>).MinimumTlsVersion\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: fe83a0eb-a853-422d-aac2-1bffd182c5d0 - Name: 'Storage accounts\nshould have the specified minimum TLS version'",
    "expected_response": "3. Ensure that the Minimum TLS version is set to Version 1.2.\n--output tsv\nshould have the specified minimum TLS version'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Settings, click Configuration.\n3. Set the Minimum TLS version to Version 1.2.\n4. Click Save.\nRemediate from Azure CLI\naz storage account update \\\n--name <storage-account> \\\n--resource-group <resource-group> \\\n--min-tls-version TLS1_2\nRemediate from PowerShell\nTo set the minimum TLS version, run the following command:\nSet-AzStorageAccount -AccountName <STORAGEACCOUNTNAME> `\n-ResourceGroupName <RESOURCEGROUPNAME> `\n-MinimumTlsVersion TLS1_2",
    "default_value": "If a storage account is created through the portal, the MinimumTlsVersion property for\nthat storage account will be set to TLS 1.2.\nIf a storage account is created through PowerShell or CLI, the MinimumTlsVersion\nproperty for that storage account will not be set, and defaults to TLS 1.0.",
    "detection_commands": [
      "az storage account list | jq '.[] | {name, resourceGroup}'",
      "az storage account show --name <storage-account> --resource-group <resource-group> --query minimumTlsVersion --output tsv"
    ],
    "remediation_commands": [
      "az storage account update --name <storage-account> --resource-group <resource-group> --min-tls-version TLS1_2",
      "Set-AzStorageAccount -AccountName <STORAGEACCOUNTNAME> `"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-",
      "configure-minimum-version",
      "2. https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-",
      "protection#dp-3-encrypt-sensitive-data-in-transit"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 531,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.7",
    "title": "Ensure 'Cross Tenant Replication' is not enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "Cross Tenant Replication in Azure allows data to be replicated across multiple Azure\ntenants. While this feature can be beneficial for data sharing and availability, it also\nposes a significant security risk if not properly managed. Unauthorized data access,\ndata leakage, and compliance violations are potential risks. Disabling Cross Tenant\nReplication ensures that data is not inadvertently replicated across different tenant\nboundaries without explicit authorization.",
    "rationale": "Disabling Cross Tenant Replication minimizes the risk of unauthorized data access and\nensures that data governance policies are strictly adhered to. This control is especially\ncritical for organizations with stringent data security and privacy requirements, as it\nprevents the accidental sharing of sensitive information.",
    "impact": "Disabling Cross Tenant Replication may affect data availability and sharing across\ndifferent Azure tenants. Ensure that this change aligns with your organizational data\nsharing and availability requirements.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Data management, click Object replication.\n3. Click Advanced settings.\n4. Ensure Allow cross-tenant replication is not checked.\nAudit from Azure CLI\naz storage account list --query \"[*].[name,allowCrossTenantReplication]\"\nThe value of false should be returned for each storage account listed.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 92a89a79-6c52-4a7e-a03f-61306fc49312 - Name: 'Storage accounts\nshould prevent cross tenant object replication'",
    "expected_response": "4. Ensure Allow cross-tenant replication is not checked.\nThe value of false should be returned for each storage account listed.\nshould prevent cross tenant object replication'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Data management, click Object replication.\n3. Click Advanced settings.\n4. Uncheck Allow cross-tenant replication.\n5. Click OK.\nRemediate from Azure CLI\nReplace the information within <> with appropriate values:\naz storage account update --name <storageAccountName> --resource-group\n<resourceGroupName> --allow-cross-tenant-replication false",
    "default_value": "For new storage accounts created after Dec 15, 2023 cross tenant replication is not\nenabled.",
    "detection_commands": [
      "az storage account list --query \"[*].[name,allowCrossTenantReplication]\""
    ],
    "remediation_commands": [
      "az storage account update --name <storageAccountName> --resource-group"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-prevent-",
      "cross-tenant-policies"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 534,
    "dspm_relevant": true,
    "dspm_categories": [
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.8",
    "title": "Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Only Allow Access to Authorized Cloud Storage or",
    "description": "The Azure Storage setting ‘Allow Blob Anonymous Access’ (aka\n\"allowBlobPublicAccess\") controls whether anonymous access is allowed for blob data\nin a storage account. When this property is set to True, it enables public read access to\nblob data, which can be convenient for sharing data but may carry security risks. When\nset to False, it disallows public access to blob data, providing a more secure storage\nenvironment.",
    "rationale": "If \"Allow Blob Anonymous Access\" is enabled, blobs can be accessed by adding the\nblob name to the URL to see the contents. An attacker can enumerate a blob using\nmethods, such as brute force, and access them.\nExfiltration of data by brute force enumeration of items from a storage account may\noccur if this setting is set to 'Enabled'.",
    "impact": "Additional consideration may be required for exceptional circumstances where elements\nof a storage account require public accessibility. In these circumstances, it is highly\nrecommended that all data stored in the public facing storage account be reviewed for\nsensitive or potentially compromising data, and that sensitive or compromising data is\nnever stored in these storage accounts.",
    "audit": "Audit from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Settings, click Configuration.\n3. Ensure Allow Blob Anonymous Access is set to Disabled.\nAudit from Azure CLI\nFor every storage account in scope:\naz storage account show --name \"<yourStorageAccountName>\" --query\nallowBlobPublicAccess\nEnsure that every storage account in scope returns false for the\n\"allowBlobPublicAccess\" setting.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: 4fa4b6c0-31ca-4c0d-b10d-24b96f62a751 - Name: 'Storage account\npublic access should be disallowed'",
    "expected_response": "3. Ensure Allow Blob Anonymous Access is set to Disabled.\nEnsure that every storage account in scope returns false for the\npublic access should be disallowed'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage Accounts.\n2. For each storage account, under Settings, click Configuration.\n3. Set Allow Blob Anonymous Access to Disabled.\n4. Click Save.\nRemediate from Powershell\nFor every storage account in scope, run the following:\n$storageAccount = Get-AzStorageAccount -ResourceGroupName\n\"<yourResourceGroup>\" -Name \"<yourStorageAccountName>\"\n$storageAccount.AllowBlobPublicAccess = $false\nSet-AzStorageAccount -InputObject $storageAccount",
    "default_value": "Disabled",
    "detection_commands": [
      "az storage account show --name \"<yourStorageAccountName>\" --query"
    ],
    "remediation_commands": [
      "$storageAccount = Get-AzStorageAccount -ResourceGroupName \"<yourResourceGroup>\" -Name \"<yourStorageAccountName>\" $storageAccount.AllowBlobPublicAccess = $false Set-AzStorageAccount -InputObject $storageAccount"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-",
      "prevent?tabs=portal",
      "2. https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-",
      "prevent?source=recommendations&tabs=portal"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 537,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.9",
    "title": "Ensure Azure Resource Manager Delete locks are applied to Azure Storage Accounts",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Azure Resource Manager CannotDelete (Delete) locks can prevent users from\naccidentally or maliciously deleting a storage account. This feature ensures that while\nthe Storage account can still be modified or used, deletion of the Storage account\nresource requires removal of the lock by a user with appropriate permissions.\nThis feature is a protective control for the availability of data. By ensuring that a storage\naccount or its parent resource group cannot be deleted without first removing the lock,\nthe risk of data loss is reduced.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Determining storage accounts that require\nCannotDelete locks depends on the context and requirements of each organization and\nenvironment.",
    "rationale": "Applying a Delete lock on storage accounts protects the availability of data by\npreventing the accidental or unauthorized deletion of the entire storage account. It is a\nfundamental protective control that can prevent data loss",
    "impact": "• Prevents the deletion of the Storage account Resource entirely.\n• Prevents the deletion of the parent Resource Group containing the locked\nStorage account resource.\n• Does not prevent other control plane operations, including modification of\nconfigurations, network settings, containers, and access.\n• Does not prevent deletion of containers or other objects within the storage\naccount.",
    "audit": "Audit from Azure Portal\n1. Navigate to the storage account in the Azure portal.\n2. For each storage account, under Settings, click Locks.\n3. Ensure that a Delete lock exists on the storage account.\nAudit from Azure CLI\naz lock list --resource-group <resource-group> \\\n--resource-name <storage-account> \\\n--resource-type \"Microsoft.Storage/storageAccounts\"\nAudit from PowerShell\nGet-AzResourceLock -ResourceGroupName <RESOURCEGROUPNAME> `\n-ResourceName <STORAGEACCOUNTNAME> `\n-ResourceType \"Microsoft.Storage/storageAccounts\"\nAudit from Azure Policy\nThere is currently no built-in Microsoft policy to audit resource locks on storage\naccounts. Custom and community policy definitions can check for the existence of a\n“Microsoft.Authorization/locks” resource with an AuditIfNotExists effect.",
    "expected_response": "3. Ensure that a Delete lock exists on the storage account.",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the storage account in the Azure portal.\n2. Under the Settings section, select Locks.\n3. Select Add.\n4. Provide a Name, and choose Delete for the type of lock.\n5. Add a note about the lock if desired.\nRemediate from Azure CLI\nReplace the information within <> with appropriate values:\naz lock create --name <lock> \\\n--resource-group <resource-group> \\\n--resource <storage-account> \\\n--lock-type CanNotDelete \\\n--resource-type Microsoft.Storage/storageAccounts\nRemediate from PowerShell\nReplace the information within <> with appropriate values:\nNew-AzResourceLock -LockLevel CanNotDelete `\n-LockName <lock> `\n-ResourceName <storage-account> `\n-ResourceType Microsoft.Storage/storageAccounts `\n-ResourceGroupName <resource-group>",
    "default_value": "By default, no locks are applied to Azure resources, including storage accounts. Locks\nmust be manually configured after resource creation.",
    "detection_commands": [
      "az lock list --resource-group <resource-group> --resource-name <storage-account> --resource-type \"Microsoft.Storage/storageAccounts\"",
      "Get-AzResourceLock -ResourceGroupName <RESOURCEGROUPNAME> `"
    ],
    "remediation_commands": [
      "az lock create --name <lock> --resource-group <resource-group> --resource <storage-account> --lock-type CanNotDelete --resource-type Microsoft.Storage/storageAccounts",
      "New-AzResourceLock -LockLevel CanNotDelete `"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/lock-account-resource",
      "2. https://learn.microsoft.com/en-us/azure/azure-resource-",
      "manager/management/lock-resources"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 540,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": false
  },
  {
    "cis_id": "9.3.10",
    "title": "Ensure Azure Resource Manager ReadOnly locks are considered for Azure Storage Accounts",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "description": "Adding an Azure Resource Manager ReadOnly lock can prevent users from accidentally\nor maliciously deleting a storage account, modifying its properties and containers, or\ncreating access assignments. The lock must be removed before the storage account\ncan be deleted or updated. It provides more protection than a CannotDelete-type of\nresource manager lock.\nThis feature prevents POST operations on a storage account and containers to the Azure\nResource Manager control plane, management.azure.com. Blocked operations include\nlistKeys which prevents clients from obtaining the account shared access keys.\nMicrosoft does not recommend ReadOnly locks for storage accounts with Azure Files\nand Table service containers.\nThis Azure Resource Manager REST API documentation (spec) provides information\nabout the control plane POST operations for Microsoft.Storage resources.\nWhile an automated assessment procedure exists for this recommendation, the\nassessment status remains manual. Determining storage accounts that require\nReadOnly locks depends on the context and requirements of each organization and\nenvironment.",
    "rationale": "Applying a ReadOnly lock on storage accounts protects the confidentiality and\navailability of data by preventing the accidental or unauthorized deletion of the entire\nstorage account and modification of the account, container properties, or access\npermissions. It can offer enhanced protection for blob and queue workloads with\ntradeoffs in usability and compatibility for clients using account shared access keys.",
    "impact": "• Prevents the deletion of the Storage account Resource entirely.\n• Prevents the deletion of the parent Resource Group containing the locked\nStorage account resource.\n• Prevents clients from obtaining the storage account shared access keys using a\nlistKeys operation.\n• Requires Entra credentials to access blob and queue data in the Portal.\n• Data in Azure Files or the Table service may be inaccessible to clients using the\naccount shared access keys.\n• Prevents modification of account properties, network settings, containers, and\nRBAC assignments.\n• Does not prevent access using existing account shared access keys issued to\nclients.\n• Does not prevent deletion of containers or other objects within the storage\naccount.",
    "audit": "Audit from Azure Portal\n1. Navigate to the storage account in the Azure portal.\n2. For each storage account, under Settings, click Locks.\n3. Ensure that a ReadOnly lock exists on the storage account.\nAudit from Azure CLI\naz lock list --resource-group <resource-group> \\\n--resource-name <storage-account> \\\n--resource-type \"Microsoft.Storage/storageAccounts\"\nAudit from PowerShell\nGet-AzResourceLock -ResourceGroupName <RESOURCEGROUPNAME> `\n-ResourceName <STORAGEACCOUNTNAME> `\n-ResourceType \"Microsoft.Storage/storageAccounts\"\nAudit from Azure Policy\nThere is currently no built-in Microsoft policy to audit resource locks on storage\naccounts. Custom and community policy definitions can check for the existence of a\n“Microsoft.Authorization/locks” resource with an AuditIfNotExists effect.",
    "expected_response": "3. Ensure that a ReadOnly lock exists on the storage account.",
    "remediation": "Remediate from Azure Portal\n1. Navigate to the storage account in the Azure portal.\n2. Under the Settings section, select Locks.\n3. Select Add.\n4. Provide a Name, and choose ReadOnly for the type of lock.\n5. Add a note about the lock if desired.\nRemediate from Azure CLI\nReplace the information within <> with appropriate values:\naz lock create --name <lock> \\\n--resource-group <resource-group> \\\n--resource <storage-account> \\\n--lock-type ReadOnly \\\n--resource-type Microsoft.Storage/storageAccounts\nRemediate from PowerShell\nReplace the information within <> with appropriate values:\nNew-AzResourceLock -LockLevel ReadOnly `\n-LockName <lock> `\n-ResourceName <storage-account> `\n-ResourceType Microsoft.Storage/storageAccounts `\n-ResourceGroupName <resource-group>",
    "default_value": "By default, no locks are applied to Azure resources, including storage accounts. Locks\nmust be manually configured after resource creation.",
    "detection_commands": [
      "az lock list --resource-group <resource-group> --resource-name <storage-account> --resource-type \"Microsoft.Storage/storageAccounts\"",
      "Get-AzResourceLock -ResourceGroupName <RESOURCEGROUPNAME> `"
    ],
    "remediation_commands": [
      "az lock create --name <lock> --resource-group <resource-group> --resource <storage-account> --lock-type ReadOnly --resource-type Microsoft.Storage/storageAccounts",
      "New-AzResourceLock -LockLevel ReadOnly `"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/lock-account-resource",
      "2. https://learn.microsoft.com/en-us/azure/azure-resource-",
      "manager/management/lock-resources",
      "3. https://github.com/Azure/azure-rest-api-specs/tree/main/specification/storage"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 544,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "9.3.11",
    "title": "Ensure Redundancy is set to 'geo-redundant storage (GRS)' on critical Azure Storage Accounts",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "description": "Geo-redundant storage (GRS) in Azure replicates data three times within the primary\nregion using locally redundant storage (LRS) and asynchronously copies it to a\nsecondary region hundreds of miles away. This setup ensures high availability and\nresilience by providing 16 nines (99.99999999999999%) durability over a year,\nsafeguarding data against regional outages.",
    "rationale": "Enabling GRS protects critical data from regional failures by maintaining a copy in a\ngeographically separate location. This significantly reduces the risk of data loss,\nsupports business continuity, and meets high availability requirements for disaster\nrecovery.",
    "impact": "Enabling geo-redundant storage on Azure storage accounts increases costs due to\ncross-region data replication.",
    "audit": "Audit from Azure Portal\n1. Go to Storage accounts.\n2. Click on a storage account.\n3. Under Data management, click Redundancy.\n4. Ensure that Redundancy is set to Geo-redundant storage (GRS).\n5. Repeat steps 1-4 for each storage account.\nAudit from Azure CLI\nRun the following command to list storage accounts:\naz storage account list\nFor each storage account, run the following command:\naz storage account show --resource-group <resource-group> --name <storage-\naccount>\nUnder sku, ensure that name is set to Standard_GRS.\nAudit from PowerShell\nRun the following command to list storage accounts:\nGet-AzStorageAccount\nRun the following command to get the storage account in a resource group with a given\nname:\n$storageAccount = Get-AzStorageAccount -ResourceGroupName <resource-group> -\nName <storage-account>\nRun the following command to get the redundancy setting for the storage account:\n$storageAccount.SKU.Name\nEnsure that the command returns Standard_GRS.\nRepeat for each storage account.\nAudit from Azure Policy\nIf referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the\nassociated Policy definition in Azure.\nIf referencing a printed copy, you can search Policy IDs from this URL:\nhttps://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions\n• Policy ID: bf045164-79ba-4215-8f95-f8048dc1780b - Name: 'Geo-redundant\nstorage should be enabled for Storage Accounts'",
    "expected_response": "4. Ensure that Redundancy is set to Geo-redundant storage (GRS).\nUnder sku, ensure that name is set to Standard_GRS.\nEnsure that the command returns Standard_GRS.\nstorage should be enabled for Storage Accounts'",
    "remediation": "Remediate from Azure Portal\n1. Go to Storage accounts.\n2. Click on a storage account.\n3. Under Data management, click Redundancy.\n4. From the Redundancy drop-down menu, select Geo-redundant storage\n(GRS).\n5. Click Save.\n6. Repeat steps 1-5 for each storage account requiring remediation.\nRemediate from Azure CLI\nFor each storage account requiring remediation, run the following command to enable\ngeo-redundant storage:\naz storage account update --resource-group <resource-group> --name <storage-\naccount> --sku Standard_GRS\nRemediate from PowerShell\nFor each storage account requiring remediation, run the following command to enable\ngeo-redundant storage:\nSet-AzStorageAccount -ResourceGroupName <resource-group> -Name <storage-\naccount> -SkuName \"Standard_GRS\"",
    "default_value": "When creating a storage account in the Azure Portal, the default redundancy setting is\ngeo-redundant storage (GRS). Using the Azure CLI, the default is read-access geo-\nredundant storage (RA-GRS). In PowerShell, a redundancy level must be explicitly\nspecified during account creation.",
    "additional_information": "When choosing the best redundancy option, weigh the trade-offs between lower costs\nand higher availability. Key factors to consider include:\n• The method of data replication within the primary region.\n• The replication of data from a primary to a geographically distant secondary\nregion for protection against regional disasters (geo-replication).\n• The necessity for read access to replicated data in the secondary region during\nan outage in the primary region (geo-replication with read access).",
    "detection_commands": [
      "az storage account list",
      "az storage account show --resource-group <resource-group> --name <storage-",
      "Get-AzStorageAccount",
      "$storageAccount = Get-AzStorageAccount -ResourceGroupName <resource-group> -",
      "$storageAccount.SKU.Name"
    ],
    "remediation_commands": [
      "az storage account update --resource-group <resource-group> --name <storage-",
      "Set-AzStorageAccount -ResourceGroupName <resource-group> -Name <storage-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy",
      "2. https://learn.microsoft.com/en-us/azure/storage/common/redundancy-migration",
      "3. https://learn.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-",
      "latest#az-storage-account-update",
      "4. https://learn.microsoft.com/en-us/powershell/module/az.storage/set-",
      "azstorageaccount",
      "5. https://learn.microsoft.com/en-us/azure/storage/common/storage-disaster-",
      "recovery-guidance"
    ],
    "source_pdf": "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0.pdf",
    "page": 547,
    "dspm_relevant": true,
    "dspm_categories": [
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  }
]
""")


def get_azure_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return AZURE_CIS_CONTROLS


def get_azure_control_count() -> int:
    """Return total number of CIS controls."""
    return len(AZURE_CIS_CONTROLS)


def get_azure_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in AZURE_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_azure_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in AZURE_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_azure_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in AZURE_CIS_CONTROLS if c.get("dspm_relevant")]


def get_azure_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in AZURE_CIS_CONTROLS if c.get("rr_relevant")]


def get_azure_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in AZURE_CIS_CONTROLS if c["service_area"] == service_area]


def get_azure_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in AZURE_CIS_CONTROLS if c["severity"] == severity]
