"""Domain D2: Data Protection & Encryption — 15 rules (weight 20%).

Maps to NIST CSF 2.0 PR.DS (Data Security).
"""

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity

D2_RULES: list[RRRule] = [
    RRRule(
        rule_id="RR-ENC-001",
        name="Cifrado en reposo activado en todos los servicios de almacenamiento",
        description="Todos los recursos de almacenamiento (S3, EBS, RDS, Azure Blob, Azure Disk, Cloud Storage, Cloud SQL) "
                    "deben tener encryption at rest habilitado.",
        domain=Domain.D2,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "ebs_volume", "rds_instance", "blob_storage", "managed_disk", "cloud_storage", "cloud_sql"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["s3_bucket_encryption_enabled", "ec2_ebs_encryption_enabled", "rds_encryption_at_rest"],
            "azure": ["storage_encryption_enabled", "vm_disk_encryption"],
            "gcp": ["gcp_storage_bucket_encryption", "gcp_sql_encryption_enabled"],
        },
        remediation={
            "aws": "Habilitar SSE en S3 buckets (SSE-S3 mínimo, SSE-KMS preferido). Habilitar EBS encryption by default en Account Settings. Habilitar encryption en RDS.",
            "azure": "Verificar Storage Service Encryption (SSE) activo. Habilitar Azure Disk Encryption para VMs. Verificar TDE en Azure SQL.",
            "gcp": "Cloud Storage tiene CSEK/CMEK disponible. Verificar encryption en Cloud SQL y Compute Engine disks.",
        },
        ransomware_context="El cifrado at rest protege los datos contra acceso directo si el atacante obtiene acceso al almacenamiento subyacente, pero no previene cifrado por ransomware sobre datos ya cifrados.",
    ),

    RRRule(
        rule_id="RR-ENC-002",
        name="Uso de Customer Managed Keys (CMK) en servicios críticos",
        description="Servicios de almacenamiento con datos clasificados como críticos deben usar CMK "
                    "en lugar de claves gestionadas por el proveedor para mayor control.",
        domain=Domain.D2,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["kms_key", "key_vault", "cloud_kms"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["s3_bucket_cmk_encryption", "rds_cmk_encryption", "ebs_cmk_encryption"],
            "azure": ["storage_cmk_encryption", "vm_disk_cmk"],
            "gcp": ["gcp_storage_cmek_enabled", "gcp_sql_cmek_enabled"],
        },
        remediation={
            "aws": "Crear KMS keys y configurar S3/RDS/EBS para usar SSE-KMS con CMK. Definir key policies restrictivas.",
            "azure": "Crear keys en Azure Key Vault. Configurar Storage accounts y Managed Disks para usar CMK.",
            "gcp": "Crear keys en Cloud KMS. Configurar Cloud Storage y Cloud SQL para usar CMEK.",
        },
        ransomware_context="CMK permite revocar el acceso a las claves de cifrado durante un ataque, impidiendo que el atacante descifre los datos exfiltrados y limitando el impacto del ransomware.",
    ),

    RRRule(
        rule_id="RR-ENC-003",
        name="Rotación automática de claves KMS habilitada",
        description="Las claves de cifrado gestionadas por el cliente deben tener rotación automática habilitada "
                    "para limitar el impacto de compromiso de claves.",
        domain=Domain.D2,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["kms_key"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["kms_key_rotation_enabled"],
            "azure": ["keyvault_key_rotation_enabled"],
            "gcp": ["gcp_kms_key_rotation_enabled"],
        },
        remediation={
            "aws": "Habilitar automatic key rotation en AWS KMS: aws kms enable-key-rotation --key-id <key>.",
            "azure": "Configurar rotation policy en Azure Key Vault keys con periodo máximo de 365 días.",
            "gcp": "Configurar automatic rotation en Cloud KMS con rotation period de máximo 365 días.",
        },
        ransomware_context="La rotación de claves limita la ventana de exposición si una clave KMS es comprometida durante un ataque de ransomware, reduciendo los datos que el atacante puede descifrar.",
    ),

    RRRule(
        rule_id="RR-ENC-004",
        name="Cifrado en tránsito forzado (TLS/HTTPS)",
        description="Todas las comunicaciones deben usar TLS/HTTPS. Bucket policies deben requerir SSL, "
                    "load balancers deben usar HTTPS listeners.",
        domain=Domain.D2,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "load_balancer", "storage_account"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-02",
        check_ids={
            "aws": ["s3_bucket_ssl_required", "elb_https_listener", "rds_ssl_enforced"],
            "azure": ["storage_https_only", "app_service_https_only"],
            "gcp": ["gcp_storage_uniform_access", "gcp_sql_ssl_enforced"],
        },
        remediation={
            "aws": "Agregar bucket policy con aws:SecureTransport condition. Configurar HTTPS listeners en ALB/NLB. Forzar SSL en RDS.",
            "azure": "Habilitar 'Secure transfer required' en Storage Accounts. Configurar HTTPS Only en App Services.",
            "gcp": "Configurar SSL enforcement en Cloud SQL. Usar HTTPS load balancers. Configurar HTTPS redirect.",
        },
        ransomware_context="Sin TLS/HTTPS, las comunicaciones pueden ser interceptadas para obtener credenciales o tokens que faciliten el acceso inicial para desplegar ransomware.",
    ),

    RRRule(
        rule_id="RR-ENC-005",
        name="Key Vault/KMS access policies restrictivas",
        description="El acceso a servicios de gestión de claves debe estar restringido. "
                    "Solo servicios y usuarios autorizados deben poder usar/gestionar claves.",
        domain=Domain.D2,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["kms_key", "key_vault"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["kms_key_policy_restrictive"],
            "azure": ["keyvault_access_policy_restrictive", "keyvault_rbac_enabled"],
            "gcp": ["gcp_kms_key_access_restricted"],
        },
        remediation={
            "aws": "Revisar KMS key policies. Eliminar principals con kms:* y reemplazar por permisos específicos (kms:Encrypt, kms:Decrypt).",
            "azure": "Migrar a RBAC para Key Vault. Eliminar access policies excesivas. Asignar roles específicos (Key Vault Crypto User).",
            "gcp": "Revisar IAM bindings en Cloud KMS keyrings. Asignar roles específicos (cloudkms.cryptoKeyEncrypterDecrypter).",
        },
        ransomware_context="Si el atacante obtiene acceso a las claves KMS, puede cifrar datos con nuevas claves y eliminar las originales, haciendo irrecuperables los datos. Access policies restrictivas limitan este riesgo.",
    ),

    RRRule(
        rule_id="RR-ENC-006",
        name="Protección contra eliminación de claves KMS",
        description="Las claves KMS deben tener protección contra eliminación accidental o maliciosa "
                    "(key deletion pending period, soft delete).",
        domain=Domain.D2,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["kms_key"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["kms_key_deletion_protection"],
            "azure": ["keyvault_soft_delete_enabled", "keyvault_purge_protection_enabled"],
            "gcp": ["gcp_kms_key_destroy_protection"],
        },
        remediation={
            "aws": "Configurar waiting period máximo (30 días) para ScheduleKeyDeletion. Usar SCP para denegar kms:ScheduleKeyDeletion.",
            "azure": "Habilitar Soft Delete y Purge Protection en Azure Key Vault. Retention period mínimo 90 días.",
            "gcp": "Configurar key version destroy scheduled duration. Implementar Organization Policy para prevenir key destruction.",
        },
        ransomware_context="CRÍTICO: En un ataque de ransomware, el atacante intentará eliminar las claves KMS para hacer los backups cifrados irrecuperables. La protección contra eliminación es esencial.",
    ),

    RRRule(
        rule_id="RR-ENC-007",
        name="Cifrado de base de datos habilitado (TDE)",
        description="Bases de datos relacionales deben tener Transparent Data Encryption (TDE) o equivalente activo.",
        domain=Domain.D2,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["rds_instance", "sql_database", "cloud_sql"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["rds_encryption_at_rest"],
            "azure": ["sql_tde_enabled", "sql_database_encryption"],
            "gcp": ["gcp_sql_encryption_enabled"],
        },
        remediation={
            "aws": "Habilitar encryption en RDS instances (requiere recreación si no fue habilitado en creación). Usar KMS CMK.",
            "azure": "Verificar TDE habilitado en Azure SQL Database (default desde 2017). Configurar CMK si requerido.",
            "gcp": "Cloud SQL tiene encryption at rest por defecto. Configurar CMEK para control adicional.",
        },
        ransomware_context="TDE protege los datos de bases de datos en disco. Sin cifrado, un atacante con acceso al storage puede leer datos sensibles directamente antes de cifrarlos con ransomware.",
    ),

    RRRule(
        rule_id="RR-ENC-008",
        name="Secrets almacenados en servicio de gestión de secretos",
        description="Credenciales, API keys y secrets no deben estar en código fuente o variables de entorno "
                    "sino en un servicio dedicado (Secrets Manager, Key Vault).",
        domain=Domain.D2,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["secrets_manager", "key_vault_secret"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["secretsmanager_secrets_rotated"],
            "azure": ["keyvault_secrets_expiration"],
            "gcp": ["gcp_secret_manager_configured"],
        },
        remediation={
            "aws": "Migrar secrets a AWS Secrets Manager. Configurar rotación automática. Eliminar hardcoded secrets.",
            "azure": "Almacenar secrets en Azure Key Vault. Configurar expiration dates. Usar Managed Identity para acceso.",
            "gcp": "Usar Secret Manager para almacenar secrets. Configurar rotación y acceso via IAM.",
        },
        ransomware_context="Secrets hardcodeados en código o variables de entorno son fáciles de exfiltrar durante un ataque y permiten al atacante acceder a más servicios para ampliar el impacto del ransomware.",
    ),

    RRRule(
        rule_id="RR-ENC-009",
        name="Certificados sin expiración próxima",
        description="Certificados SSL/TLS en uso no deben estar próximos a expirar (<30 días) ni expirados.",
        domain=Domain.D2,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["certificate"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-02",
        check_ids={
            "aws": ["acm_certificate_not_expiring"],
            "azure": ["keyvault_certificate_not_expiring"],
            "gcp": ["gcp_certificate_not_expiring"],
        },
        remediation={
            "aws": "Usar ACM con auto-renewal para certificados. Configurar CloudWatch alarms para certificados próximos a expirar.",
            "azure": "Configurar certificate auto-renewal en Key Vault. Crear alertas para certificados próximos a expirar.",
            "gcp": "Usar Google-managed SSL certificates para auto-renewal. Monitorear certificados self-managed.",
        },
        ransomware_context="Certificados expirados pueden causar interrupciones de servicio que ocultan los indicadores de un ataque de ransomware en progreso.",
    ),

    RRRule(
        rule_id="RR-ENC-010",
        name="EBS/Disk encryption habilitado por defecto en la región",
        description="El cifrado de volúmenes debe estar habilitado por defecto a nivel de cuenta/región "
                    "para prevenir creación de volúmenes sin cifrar.",
        domain=Domain.D2,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure"],
        resource_types=["account_setting"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["ec2_ebs_default_encryption"],
            "azure": ["vm_disk_encryption_default"],
        },
        remediation={
            "aws": "Habilitar EBS encryption by default: EC2 > EBS > Settings > Always encrypt new EBS volumes. Hacer por cada región.",
            "azure": "Configurar Azure Policy para requerir disk encryption en todas las VMs nuevas.",
        },
        ransomware_context="Sin cifrado por defecto, los nuevos volúmenes creados durante la recuperación de un ataque podrían quedar sin cifrar, creando nuevas vulnerabilidades.",
    ),

    RRRule(
        rule_id="RR-ENC-011",
        name="Snapshots y AMIs cifrados",
        description="Snapshots de disco e imágenes de máquina (AMIs) deben estar cifrados "
                    "para proteger datos en reposo y en copias.",
        domain=Domain.D2,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["snapshot", "ami"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["ec2_snapshot_encrypted", "ec2_ami_encrypted"],
            "azure": ["vm_snapshot_encrypted"],
            "gcp": ["gcp_compute_snapshot_encrypted"],
        },
        remediation={
            "aws": "Copiar snapshots no cifrados a versiones cifradas. Configurar default encryption para que nuevos snapshots sean cifrados.",
            "azure": "Verificar que snapshots usen encryption. Usar Azure Disk Encryption para cifrar antes de snapshot.",
            "gcp": "Verificar que snapshots heredan encryption del disco origen. Usar CMEK para control adicional.",
        },
        ransomware_context="Snapshots sin cifrar pueden ser copiados y accedidos por el atacante para exfiltrar datos antes del cifrado por ransomware.",
    ),

    RRRule(
        rule_id="RR-ENC-012",
        name="S3/Storage no permite acceso HTTP sin cifrar",
        description="Storage buckets no deben permitir operaciones sin SSL/TLS. "
                    "Todo acceso debe ser via HTTPS.",
        domain=Domain.D2,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "storage_account"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-02",
        check_ids={
            "aws": ["s3_bucket_ssl_required"],
            "azure": ["storage_https_only"],
            "gcp": ["gcp_storage_uniform_access"],
        },
        remediation={
            "aws": "Agregar bucket policy: {\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}.",
            "azure": "Habilitar 'Secure transfer required' en propiedades del Storage Account.",
            "gcp": "Configurar Uniform bucket-level access. Cloud Storage usa HTTPS por defecto.",
        },
        ransomware_context="Acceso HTTP sin cifrar al storage permite interceptar datos en tránsito y credenciales, facilitando la exfiltración de datos previa al ataque de ransomware.",
    ),

    RRRule(
        rule_id="RR-ENC-013",
        name="DLP o clasificación de datos configurada",
        description="Debe existir un mecanismo de clasificación de datos o DLP configurado "
                    "para identificar datos sensibles en almacenamiento cloud.",
        domain=Domain.D2,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["dlp_config"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-03",
        check_ids={
            "aws": ["macie_enabled"],
            "azure": ["purview_dlp_configured"],
            "gcp": ["gcp_dlp_configured", "gcp_bigquery_classification"],
        },
        remediation={
            "aws": "Habilitar Amazon Macie para descubrimiento automático de datos sensibles en S3.",
            "azure": "Configurar Microsoft Purview Data Loss Prevention policies para clasificar y proteger datos sensibles.",
            "gcp": "Configurar Cloud DLP para escanear y clasificar datos en Cloud Storage, BigQuery y Datastore.",
        },
        ransomware_context="DLP ayuda a identificar dónde están los datos sensibles, permitiendo priorizar su protección contra ransomware y detectar exfiltración previa al cifrado.",
    ),

    RRRule(
        rule_id="RR-ENC-014",
        name="Versioning habilitado en storage buckets",
        description="Object versioning debe estar habilitado en buckets de almacenamiento para permitir "
                    "recuperación de objetos eliminados o sobrescritos por ransomware.",
        domain=Domain.D2,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "blob_container", "cloud_storage"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["s3_bucket_versioning_enabled"],
            "azure": ["storage_blob_versioning_enabled"],
            "gcp": ["gcp_storage_versioning_enabled"],
        },
        remediation={
            "aws": "Habilitar versioning en S3 buckets: aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled.",
            "azure": "Habilitar blob versioning en Storage Account > Data protection > Enable versioning for blobs.",
            "gcp": "Habilitar object versioning: gsutil versioning set on gs://<bucket-name>.",
        },
        ransomware_context="CRÍTICO: El versioning permite recuperar versiones anteriores de objetos cifrados por ransomware. Sin versioning, los datos sobrescritos por ransomware son irrecuperables.",
    ),

    RRRule(
        rule_id="RR-ENC-015",
        name="Lifecycle policies configuradas para datos de almacenamiento",
        description="Storage buckets deben tener lifecycle policies que muevan datos a tiers de menor costo "
                    "y prevengan acumulación descontrolada que amplíe superficie de ataque.",
        domain=Domain.D2,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "blob_container", "cloud_storage"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["s3_bucket_lifecycle_configured"],
            "azure": ["storage_lifecycle_management"],
            "gcp": ["gcp_storage_lifecycle_configured"],
        },
        remediation={
            "aws": "Configurar S3 Lifecycle rules para transicionar a Glacier y expirar objetos obsoletos.",
            "azure": "Configurar Lifecycle management policies en Storage Account para tiering y deletion automáticos.",
            "gcp": "Configurar Object Lifecycle Management rules para cambio de storage class y deletion.",
        },
        ransomware_context="Lifecycle policies ayudan a gestionar la retención de versiones de objetos, asegurando que existan copias recuperables de datos afectados por ransomware.",
    ),
]
