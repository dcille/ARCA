"""Domain D5: Platform Hardening — 15 rules (weight 10%).

Maps to NIST CSF 2.0 PR.PS (Platform Security).
"""

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity

D5_RULES: list[RRRule] = [
    RRRule(
        rule_id="RR-HDN-001",
        name="Compliance con CIS Benchmark Level 1",
        description="El porcentaje de compliance con CIS Benchmark Level 1 del proveedor cloud "
                    "debe ser ≥80%. Usa resultados existentes del CSPM.",
        domain=Domain.D5,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["compliance_result"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "aws": ["__cis_benchmark_compliance__"],
            "azure": ["__cis_benchmark_compliance__"],
            "gcp": ["__cis_benchmark_compliance__"],
        },
        is_composite=True,
        remediation={
            "aws": "Revisar findings de CIS AWS Benchmark. Priorizar controles Level 1 fallidos. Implementar remediaciones de CIS.",
            "azure": "Revisar findings de CIS Azure Benchmark. Remediar controles Level 1. Usar Azure Policy para enforcement.",
            "gcp": "Revisar findings de CIS GCP Benchmark. Remediar controles Level 1. Usar Organization Policies.",
        },
        ransomware_context="El CIS Benchmark cubre configuraciones base que previenen vectores de entrada de ransomware. Un compliance ≥80% indica una postura de seguridad sólida.",
    ),

    RRRule(
        rule_id="RR-HDN-002",
        name="Vulnerability scanning activo en workloads",
        description="VMs y containers deben tener vulnerability scanning activo. "
                    "No deben existir vulnerabilidades críticas sin remediar >30 días.",
        domain=Domain.D5,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ec2_instance", "virtual_machine", "compute_instance"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-02",
        check_ids={
            "aws": ["inspector_enabled", "ecr_image_scanning_enabled"],
            "azure": ["defender_for_servers_enabled", "acr_vulnerability_scanning"],
            "gcp": ["gcp_security_command_center_enabled", "gcp_artifact_registry_scanning"],
        },
        remediation={
            "aws": "Habilitar Amazon Inspector para EC2 y ECR. Configurar scan automático y remediation workflows.",
            "azure": "Habilitar Microsoft Defender for Servers. Configurar vulnerability assessment para VMs y container registries.",
            "gcp": "Habilitar Security Command Center. Configurar Container Analysis para Artifact Registry.",
        },
        ransomware_context="Las vulnerabilidades no parcheadas son explotadas por ransomware para obtener acceso inicial o escalar privilegios. El scanning activo permite priorizar parches críticos.",
    ),

    RRRule(
        rule_id="RR-HDN-003",
        name="Container image scanning habilitado",
        description="Container registries deben tener image scanning automático habilitado "
                    "para detectar vulnerabilidades antes del deployment.",
        domain=Domain.D5,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ecr_repository", "acr_registry", "artifact_registry"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-02",
        check_ids={
            "aws": ["ecr_image_scanning_enabled"],
            "azure": ["acr_vulnerability_scanning"],
            "gcp": ["gcp_artifact_registry_scanning"],
        },
        remediation={
            "aws": "Habilitar ECR image scanning on push. Configurar scan frequency. Implementar policy que bloquee imágenes con vulns críticas.",
            "azure": "Habilitar vulnerability scanning en ACR con Microsoft Defender. Configurar admission policies en AKS.",
            "gcp": "Habilitar Container Analysis en Artifact Registry. Usar Binary Authorization para enforcement.",
        },
        ransomware_context="Imágenes de container con vulnerabilidades pueden ser explotadas para obtener acceso al cluster y desde ahí ejecutar ransomware contra los datos.",
    ),

    RRRule(
        rule_id="RR-HDN-004",
        name="Servicios de seguridad nativos habilitados",
        description="Servicios de detección de amenazas del proveedor deben estar activos: "
                    "GuardDuty (AWS), Defender for Cloud (Azure), Security Command Center (GCP).",
        domain=Domain.D5,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["security_service"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["guardduty_enabled"],
            "azure": ["defender_for_cloud_enabled"],
            "gcp": ["gcp_security_command_center_enabled"],
        },
        remediation={
            "aws": "Habilitar GuardDuty en todas las regiones y cuentas. Configurar delegated administrator en Organizations.",
            "azure": "Habilitar Microsoft Defender for Cloud en todas las suscripciones. Activar plans para cada tipo de recurso.",
            "gcp": "Habilitar Security Command Center Premium a nivel de organización. Activar todas las fuentes de findings.",
        },
        ransomware_context="Servicios como GuardDuty/Defender/SCC detectan actividad sospechosa asociada a ransomware: crypto mining, acceso inusual a KMS, eliminación masiva de recursos.",
    ),

    RRRule(
        rule_id="RR-HDN-005",
        name="AMI/Image hardening aplicado",
        description="Las imágenes base de VMs deben estar hardened siguiendo CIS benchmarks "
                    "o guías de hardening del proveedor.",
        domain=Domain.D5,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ami", "vm_image", "compute_image"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "aws": ["ec2_ami_hardened"],
            "azure": ["vm_image_hardened"],
            "gcp": ["gcp_compute_image_hardened"],
        },
        remediation={
            "aws": "Usar CIS Hardened AMIs o crear AMI pipeline con hardening automático. Usar EC2 Image Builder.",
            "azure": "Usar Azure Marketplace hardened images o crear custom images con hardening. Usar Azure Image Builder.",
            "gcp": "Usar Shielded VMs. Crear custom images con CIS hardening aplicado. Usar Packer pipeline.",
        },
        ransomware_context="Imágenes sin hardening tienen servicios y puertos innecesarios expuestos que amplían la superficie de ataque para la entrada y propagación de ransomware.",
    ),

    RRRule(
        rule_id="RR-HDN-006",
        name="Serverless functions con configuración segura",
        description="Funciones serverless deben tener IAM role restrictivo, sin variables de entorno "
                    "con secrets, y con runtime actualizado.",
        domain=Domain.D5,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["lambda_function", "azure_function", "cloud_function"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "aws": ["lambda_function_no_admin_role", "lambda_runtime_supported"],
            "azure": ["function_app_runtime_updated"],
            "gcp": ["gcp_cloud_function_runtime_updated"],
        },
        remediation={
            "aws": "Asignar IAM roles con least privilege a Lambda functions. Usar Secrets Manager para secrets. Actualizar runtimes.",
            "azure": "Actualizar runtime stack de Azure Functions. Usar Managed Identity. Almacenar secrets en Key Vault.",
            "gcp": "Actualizar runtimes de Cloud Functions. Usar Secret Manager. Asignar service accounts con least privilege.",
        },
        ransomware_context="Funciones serverless comprometidas pueden ser usadas como vector de persistencia y propagación de ransomware dentro de la infraestructura cloud.",
    ),

    RRRule(
        rule_id="RR-HDN-007",
        name="API throttling y rate limiting configurado",
        description="APIs expuestas deben tener rate limiting para prevenir abuso automatizado "
                    "que puede ser parte de un ataque de ransomware.",
        domain=Domain.D5,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["api_gateway"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["apigateway_throttling_enabled"],
            "azure": ["apim_rate_limiting_configured"],
            "gcp": ["gcp_api_gateway_quota_configured"],
        },
        remediation={
            "aws": "Configurar usage plans y throttling en API Gateway: requests/second y burst limits.",
            "azure": "Configurar rate-limit policies en API Management. Usar quotas por subscription y por operation.",
            "gcp": "Configurar quota policies en API Gateway o Cloud Endpoints.",
        },
        ransomware_context="APIs sin rate limiting pueden ser abusadas para exfiltrar datos masivamente o ejecutar operaciones destructivas en masa como parte de un ataque de ransomware.",
    ),

    RRRule(
        rule_id="RR-HDN-008",
        name="Resource tagging compliance",
        description="Los recursos cloud deben tener tags obligatorios (environment, owner, criticality) "
                    "para clasificación y priorización en incidentes.",
        domain=Domain.D5,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["all"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "aws": ["tagging_compliance"],
            "azure": ["tagging_compliance"],
            "gcp": ["gcp_labeling_compliance"],
        },
        is_composite=True,
        remediation={
            "aws": "Implementar AWS Tag Policies en Organizations. Requerir tags: Environment, Owner, Criticality, DataClassification.",
            "azure": "Crear Azure Policy para requerir tags obligatorios. Usar tag inheritance policies.",
            "gcp": "Usar labels obligatorios. Implementar Organization Policy constraints para labeling compliance.",
        },
        ransomware_context="El tagging permite identificar rápidamente qué recursos son críticos durante un ataque de ransomware, priorizando su protección y recuperación.",
    ),

    RRRule(
        rule_id="RR-HDN-009",
        name="Drift detection activo",
        description="Debe existir detección de drift en configuraciones de infraestructura "
                    "para detectar cambios no autorizados que pueden indicar compromiso.",
        domain=Domain.D5,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["config_rule"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-03",
        check_ids={
            "aws": ["config_enabled", "cloudformation_drift_detection"],
            "azure": ["policy_compliance_monitoring"],
            "gcp": ["gcp_config_monitoring_enabled"],
        },
        remediation={
            "aws": "Habilitar AWS Config en todas las regiones. Configurar CloudFormation drift detection. Usar Config rules para compliance.",
            "azure": "Configurar Azure Policy compliance monitoring. Habilitar Change Analysis. Usar Activity Log alerts.",
            "gcp": "Habilitar Cloud Asset Inventory. Configurar alertas para cambios en configuraciones críticas.",
        },
        ransomware_context="El drift detection identifica cambios no autorizados en la infraestructura, que pueden ser indicadores tempranos de que un atacante está preparando un ataque de ransomware.",
    ),

    RRRule(
        rule_id="RR-HDN-010",
        name="Secure defaults enforcement",
        description="Configuraciones por defecto inseguras deben ser sobrescritas: "
                    "public access disabled, encryption enabled, logging enabled.",
        domain=Domain.D5,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["account_setting"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "aws": ["s3_account_level_public_access_block", "ec2_ebs_default_encryption"],
            "azure": ["security_center_default_policy"],
            "gcp": ["gcp_compute_default_service_account_no_admin"],
        },
        remediation={
            "aws": "Configurar account-level defaults: S3 Block Public Access, EBS encryption, IMDSv2 required.",
            "azure": "Configurar Azure Policy default initiative. Habilitar Defender for Cloud defaults.",
            "gcp": "Configurar Organization Policies para defaults seguros. Restringir default service account.",
        },
        ransomware_context="Configuraciones inseguras por defecto crean vulnerabilidades que los atacantes explotan para obtener acceso inicial y desplegar ransomware.",
    ),

    RRRule(
        rule_id="RR-HDN-011",
        name="EOL software detection",
        description="No deben existir workloads con software end-of-life (OS, runtimes, databases) "
                    "que no reciben parches de seguridad.",
        domain=Domain.D5,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ec2_instance", "virtual_machine", "compute_instance"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-02",
        check_ids={
            "aws": ["ec2_no_eol_os", "lambda_runtime_supported", "rds_engine_not_eol"],
            "azure": ["vm_no_eol_os", "app_service_runtime_not_eol"],
            "gcp": ["gcp_compute_no_eol_os", "gcp_sql_engine_not_eol"],
        },
        remediation={
            "aws": "Actualizar instancias con OS/runtimes EOL. Planificar migraciones para RDS engines próximos a EOL.",
            "azure": "Actualizar VMs con OS EOL. Migrar App Services a runtimes soportados.",
            "gcp": "Actualizar instancias con OS EOL. Migrar Cloud SQL a versiones soportadas.",
        },
        ransomware_context="Software EOL sin parches de seguridad es un blanco fácil para exploits que permiten la entrada de ransomware en la infraestructura.",
    ),

    RRRule(
        rule_id="RR-HDN-012",
        name="IMDSv2 required para EC2 instances",
        description="EC2 instances deben requerir IMDSv2 (Instance Metadata Service v2) "
                    "para prevenir SSRF attacks que obtienen credenciales temporales.",
        domain=Domain.D5,
        severity=Severity.HIGH,
        cloud_providers=["aws"],
        resource_types=["ec2_instance"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "aws": ["ec2_imdsv2_required"],
        },
        remediation={
            "aws": "Configurar IMDSv2 required: aws ec2 modify-instance-metadata-options --http-tokens required. Aplicar como default a nivel de cuenta.",
        },
        ransomware_context="SSRF attacks contra IMDSv1 permiten obtener credenciales IAM temporales que pueden usarse para cifrar S3, eliminar backups y ejecutar ransomware.",
    ),

    RRRule(
        rule_id="RR-HDN-013",
        name="Serial port y project-wide SSH keys disabled (GCP)",
        description="GCP compute instances no deben tener serial port access habilitado "
                    "ni usar project-wide SSH keys que amplían superficie de ataque.",
        domain=Domain.D5,
        severity=Severity.MEDIUM,
        cloud_providers=["gcp"],
        resource_types=["compute_instance"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "gcp": ["gcp_compute_no_serial_port", "gcp_compute_no_project_wide_ssh"],
        },
        remediation={
            "gcp": "Deshabilitar serial port access: metadata serial-port-enable=false. Deshabilitar project-wide SSH keys por instancia.",
        },
        ransomware_context="Serial port access y project-wide SSH keys son vectores de acceso lateral que ransomware puede explotar para propagarse entre instancias.",
    ),

    RRRule(
        rule_id="RR-HDN-014",
        name="Shielded VMs habilitadas",
        description="VMs deben usar Shielded VM features (Secure Boot, vTPM, Integrity Monitoring) "
                    "para proteger contra rootkits y boot-level malware.",
        domain=Domain.D5,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ec2_instance", "virtual_machine", "compute_instance"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-01",
        check_ids={
            "aws": ["ec2_nitro_enclave_capable"],
            "azure": ["vm_trusted_launch_enabled"],
            "gcp": ["gcp_compute_shielded_vm"],
        },
        remediation={
            "aws": "Usar instancias Nitro-based. Considerar Nitro Enclaves para workloads sensibles.",
            "azure": "Habilitar Trusted Launch para VMs con Secure Boot y vTPM.",
            "gcp": "Habilitar Shielded VM: Secure Boot, vTPM, Integrity Monitoring al crear instancias.",
        },
        ransomware_context="Shielded VMs protegen contra rootkits y boot-level malware que pueden persistir entre reinicios, algo usado por ransomware avanzado para mantener presencia.",
    ),

    RRRule(
        rule_id="RR-HDN-015",
        name="IaC scanning integrado en pipeline",
        description="Infrastructure as Code debe ser escaneado en CI/CD pipeline para detectar "
                    "misconfigurations antes del deployment.",
        domain=Domain.D5,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ci_cd_pipeline"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-03",
        check_ids={
            "aws": [],
            "azure": [],
            "gcp": [],
        },
        is_manual=True,
        remediation={
            "aws": "Integrar herramientas de IaC scanning (Checkov, tfsec, cfn-lint) en CI/CD pipeline. Bloquear deployments con findings críticos.",
            "azure": "Integrar IaC scanning (Checkov, tfsec) en Azure DevOps/GitHub Actions pipeline.",
            "gcp": "Integrar IaC scanning en Cloud Build pipeline. Usar Checkov o similar.",
        },
        ransomware_context="IaC scanning en pipeline previene que configuraciones inseguras lleguen a producción, cerrando vectores de entrada para ransomware antes del deployment.",
    ),
]
