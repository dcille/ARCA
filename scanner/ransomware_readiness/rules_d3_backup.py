"""Domain D3: Backup & Recovery Readiness — 20 rules (weight 20%).

Maps to NIST CSF 2.0 PR.DS (Data Security) + PR.IR (Incident Response).
This is a critical domain for ransomware readiness — immutable, isolated,
tested backups are the primary defense against ransomware data destruction.
"""

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity

D3_RULES: list[RRRule] = [
    RRRule(
        rule_id="RR-BKP-001",
        name="Backups inmutables configurados para datos críticos",
        description="Object Lock (AWS S3), Immutable Blob Storage (Azure), Bucket Lock (GCP) deben estar "
                    "habilitados en buckets con datos críticos para prevenir eliminación por ransomware.",
        domain=Domain.D3,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "blob_container", "cloud_storage"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["s3_bucket_object_lock_enabled"],
            "azure": ["storage_immutable_blob_storage"],
            "gcp": ["gcp_storage_bucket_lock"],
        },
        remediation={
            "aws": "Habilitar S3 Object Lock en modo Compliance: aws s3api put-object-lock-configuration. Requiere bucket con versioning.",
            "azure": "Configurar Immutable Blob Storage con time-based retention policy en modo locked.",
            "gcp": "Configurar Bucket Lock con retention policy: gsutil retention set <duration> gs://<bucket>.",
        },
        ransomware_context="CRÍTICO: Los backups inmutables son la defensa principal contra ransomware. Object Lock impide que el atacante elimine o sobrescriba los backups incluso con credenciales administrativas.",
    ),

    RRRule(
        rule_id="RR-BKP-002",
        name="Retención de backups mínima configurada (≥30 días)",
        description="Las políticas de retención de backups deben cumplir mínimo 30 días para datos críticos, "
                    "permitiendo tiempo suficiente para detectar y recuperarse de un ataque.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["backup_vault", "backup_policy"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["backup_retention_minimum_30d", "rds_backup_retention_adequate"],
            "azure": ["backup_retention_minimum_30d"],
            "gcp": ["gcp_backup_retention_minimum_30d"],
        },
        remediation={
            "aws": "Configurar AWS Backup plan rules con retention period ≥30 días. Actualizar RDS automated backup retention.",
            "azure": "Configurar Azure Backup policies con retention ≥30 días en Recovery Services vault.",
            "gcp": "Configurar backup retention en servicios individuales (Cloud SQL ≥30d, GKE backup plans).",
        },
        ransomware_context="El ransomware puede permanecer latente semanas antes de activarse. Retención ≥30 días asegura que existan copias de datos de antes de la infección.",
    ),

    RRRule(
        rule_id="RR-BKP-003",
        name="Backups cross-region o cross-account habilitados",
        description="Copias de backup deben existir en una región o cuenta diferente a la de origen. "
                    "Un atacante con acceso a una cuenta puede destruir backups locales.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["backup_vault", "replication_config"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["backup_cross_region_enabled", "backup_cross_account_enabled"],
            "azure": ["backup_geo_redundant_enabled"],
            "gcp": ["gcp_backup_multi_region"],
        },
        is_composite=True,
        remediation={
            "aws": "Configurar AWS Backup con copy actions a otra región y/o cuenta. Usar AWS Backup Vault en cuenta dedicada.",
            "azure": "Habilitar GRS (Geo-Redundant Storage) en Recovery Services vaults. Configurar Cross Region Restore.",
            "gcp": "Configurar multi-region storage para backups. Usar proyecto dedicado para backups aislados.",
        },
        ransomware_context="Si el atacante compromete una cuenta/región, los backups locales pueden ser eliminados. Los backups cross-region/cross-account sobreviven a este escenario.",
    ),

    RRRule(
        rule_id="RR-BKP-004",
        name="Protección contra eliminación de backups (deletion protection)",
        description="Backup vaults y snapshots deben tener deletion protection o MFA Delete "
                    "habilitado para prevenir eliminación por atacantes con credenciales comprometidas.",
        domain=Domain.D3,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["backup_vault", "snapshot"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["backup_vault_deletion_protection", "s3_bucket_mfa_delete"],
            "azure": ["backup_soft_delete_enabled"],
            "gcp": ["gcp_backup_deletion_protection"],
        },
        remediation={
            "aws": "Habilitar Vault Lock en AWS Backup. Habilitar MFA Delete en S3 buckets de backup. Usar SCP para denegar DeleteBackupVault.",
            "azure": "Habilitar Soft Delete para backups en Recovery Services vault (14 días mínimo de retención).",
            "gcp": "Configurar retention policies con lock. Usar Organization Policy para prevenir eliminación de backups.",
        },
        ransomware_context="CRÍTICO: El primer objetivo del ransomware moderno es eliminar los backups. Deletion protection y MFA Delete son la barrera que lo impide.",
    ),

    RRRule(
        rule_id="RR-BKP-005",
        name="Snapshots de base de datos automatizados",
        description="Bases de datos gestionadas deben tener automated backups habilitados con retención adecuada "
                    "para point-in-time recovery.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["rds_instance", "sql_database", "cloud_sql"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["rds_automated_backups_enabled", "rds_backup_retention_adequate"],
            "azure": ["sql_automated_backups_enabled"],
            "gcp": ["gcp_sql_automated_backups_enabled"],
        },
        remediation={
            "aws": "Habilitar automated backups en RDS: ModifyDBInstance --backup-retention-period 30.",
            "azure": "Azure SQL tiene automated backups por defecto. Verificar retention period (7-35 días) en long-term retention.",
            "gcp": "Habilitar automated backups en Cloud SQL: gcloud sql instances patch --backup-start-time --enable-bin-log.",
        },
        ransomware_context="Los snapshots automatizados de bases de datos garantizan puntos de recuperación recientes, minimizando la pérdida de datos tras un ataque de ransomware.",
    ),

    RRRule(
        rule_id="RR-BKP-006",
        name="Backups cifrados",
        description="Todos los backups deben estar cifrados con KMS/CMK para proteger datos "
                    "en caso de acceso no autorizado a los backup storage.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["backup_vault", "snapshot"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-01",
        check_ids={
            "aws": ["backup_vault_encrypted", "rds_snapshot_encrypted"],
            "azure": ["backup_encryption_enabled"],
            "gcp": ["gcp_backup_encryption_enabled"],
        },
        remediation={
            "aws": "Configurar encryption en AWS Backup vault con KMS CMK. Verificar que snapshots RDS están cifrados.",
            "azure": "Azure Backup usa encryption por defecto. Verificar uso de CMK en Recovery Services vault.",
            "gcp": "Verificar que backups heredan encryption. Configurar CMEK para backup buckets.",
        },
        ransomware_context="Backups sin cifrar pueden ser leídos por el atacante para exfiltrar datos antes de cifrarlos con ransomware (doble extorsión).",
    ),

    RRRule(
        rule_id="RR-BKP-007",
        name="Point-in-time recovery habilitado para bases de datos",
        description="Bases de datos deben tener PITR (Point-In-Time Recovery) habilitado para recuperar "
                    "a cualquier momento antes del ataque de ransomware.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["rds_instance", "dynamodb_table", "cloud_sql"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["rds_pitr_enabled", "dynamodb_pitr_enabled"],
            "azure": ["sql_pitr_enabled"],
            "gcp": ["gcp_sql_pitr_enabled"],
        },
        remediation={
            "aws": "Habilitar PITR en RDS (automated backups con retention). Habilitar PITR en DynamoDB tables.",
            "azure": "Verificar point-in-time restore configurado en Azure SQL (disponible dentro del retention period).",
            "gcp": "Habilitar point-in-time recovery en Cloud SQL: habilitar binary logging y automated backups.",
        },
        ransomware_context="PITR permite recuperar la base de datos al momento exacto antes del ataque, minimizando la pérdida de transacciones y reduciendo el RTO.",
    ),

    RRRule(
        rule_id="RR-BKP-008",
        name="Soft delete habilitado en servicios de almacenamiento",
        description="Soft delete permite recuperar objetos/blobs eliminados durante un periodo configurable, "
                    "protegiendo contra eliminación masiva por ransomware.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "blob_container", "cloud_storage"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["s3_bucket_versioning_enabled"],  # S3 uses versioning + lifecycle as soft delete
            "azure": ["storage_soft_delete_enabled", "storage_container_soft_delete"],
            "gcp": ["gcp_storage_soft_delete_enabled"],
        },
        remediation={
            "aws": "Habilitar versioning en S3 (actúa como soft delete). Configurar lifecycle rules para versiones antiguas.",
            "azure": "Habilitar Soft Delete para blobs (14 días mínimo) y containers en Storage Account > Data protection.",
            "gcp": "Habilitar soft delete policy en Cloud Storage buckets con retention period adecuado.",
        },
        ransomware_context="Soft delete permite recuperar objetos eliminados por ransomware durante el periodo de retención, actuando como una red de seguridad adicional.",
    ),

    RRRule(
        rule_id="RR-BKP-009",
        name="Versioning habilitado en object storage de backup",
        description="Object versioning debe estar activo en buckets que almacenan backups "
                    "para mantener versiones anteriores a la infección.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "cloud_storage"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["s3_bucket_versioning_enabled"],
            "azure": ["storage_blob_versioning_enabled"],
            "gcp": ["gcp_storage_versioning_enabled"],
        },
        remediation={
            "aws": "Habilitar versioning en S3 backup buckets. Combinado con Object Lock proporciona protección completa.",
            "azure": "Habilitar blob versioning en Storage Accounts de backup.",
            "gcp": "Habilitar object versioning en Cloud Storage buckets de backup.",
        },
        ransomware_context="El versioning mantiene todas las versiones anteriores de los objetos, permitiendo recuperar la versión pre-infección de cada archivo afectado por ransomware.",
    ),

    RRRule(
        rule_id="RR-BKP-010",
        name="EBS/Disk snapshot lifecycle policies configuradas",
        description="Los snapshots de discos deben tener lifecycle policies automáticas para "
                    "garantizar snapshots regulares y limpieza de snapshots obsoletos.",
        domain=Domain.D3,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ebs_volume", "managed_disk"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["ec2_dlm_policy_configured", "ebs_snapshot_lifecycle"],
            "azure": ["vm_snapshot_policy_configured"],
            "gcp": ["gcp_compute_snapshot_schedule"],
        },
        remediation={
            "aws": "Crear DLM (Data Lifecycle Manager) policies para snapshots automáticos de EBS volumes.",
            "azure": "Crear Azure Backup policies o snapshot policies para Managed Disks.",
            "gcp": "Crear snapshot schedules en Compute Engine para discos persistentes.",
        },
        ransomware_context="Snapshot lifecycle policies automáticas garantizan que siempre existan copias recientes de los discos, incluso si el equipo olvida crear snapshots manuales.",
    ),

    RRRule(
        rule_id="RR-BKP-011",
        name="VM snapshot policies configuradas",
        description="VMs críticas deben tener políticas de snapshot automáticas para recuperación rápida.",
        domain=Domain.D3,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["ec2_instance", "virtual_machine", "compute_instance"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["ec2_instance_backup_enabled"],
            "azure": ["vm_backup_enabled"],
            "gcp": ["gcp_compute_instance_backup"],
        },
        remediation={
            "aws": "Incluir EC2 instances en AWS Backup plan. Crear backup rules con schedule y retention adecuados.",
            "azure": "Habilitar Azure Backup para VMs en Recovery Services vault. Configurar backup policy.",
            "gcp": "Crear snapshot schedules para discos de VMs críticas. Considerar VM Manager para gestión centralizada.",
        },
        ransomware_context="Las VMs son a menudo el primer objetivo del ransomware. Snapshots automáticas permiten restaurar la VM completa a un estado pre-infección.",
    ),

    RRRule(
        rule_id="RR-BKP-012",
        name="Kubernetes backup configurado",
        description="Clusters Kubernetes deben tener backup de recursos y persistent volumes "
                    "via Velero, Kasten, o solución nativa del proveedor.",
        domain=Domain.D3,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["eks_cluster", "aks_cluster", "gke_cluster"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["eks_backup_configured"],
            "azure": ["aks_backup_configured"],
            "gcp": ["gcp_gke_backup_configured"],
        },
        remediation={
            "aws": "Implementar Velero con S3 backend para backup de EKS. O usar AWS Backup for EKS.",
            "azure": "Configurar Azure Backup para AKS o implementar Velero con Azure Blob Storage backend.",
            "gcp": "Usar Backup for GKE (nativo). Configurar backup plans para clusters y namespaces críticos.",
        },
        ransomware_context="Los clusters Kubernetes pueden ser reconstruidos, pero los persistent volumes contienen datos de negocio. Sin backup de K8s, la recuperación es mucho más lenta.",
    ),

    RRRule(
        rule_id="RR-BKP-013",
        name="Backup monitoring y alertas configuradas",
        description="Debe existir monitoreo activo de fallos en backups con alertas "
                    "para detectar inmediatamente si los backups dejan de funcionar.",
        domain=Domain.D3,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["backup_vault", "monitoring_alert"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["backup_monitoring_alerts"],
            "azure": ["backup_monitoring_alerts"],
            "gcp": ["gcp_backup_monitoring_alerts"],
        },
        remediation={
            "aws": "Configurar AWS Backup vault notifications via SNS. Crear CloudWatch alarms para backup job failures.",
            "azure": "Configurar alertas en Azure Monitor para backup job failures en Recovery Services vault.",
            "gcp": "Configurar Cloud Monitoring alerts para fallos en backup jobs y snapshot creation.",
        },
        ransomware_context="Si los backups fallan silenciosamente, puede que no haya copias recuperables cuando ocurra el ataque de ransomware. El monitoreo detecta fallos de backup a tiempo.",
    ),

    RRRule(
        rule_id="RR-BKP-014",
        name="Backup isolation — cuenta/proyecto dedicado para backups",
        description="Los backups críticos deben almacenarse en una cuenta/proyecto separado "
                    "con acceso restringido para aislamiento ante compromiso de la cuenta principal.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["backup_vault", "account"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["backup_cross_account_enabled"],
            "azure": ["backup_separate_subscription"],
            "gcp": ["gcp_backup_separate_project"],
        },
        is_composite=True,
        remediation={
            "aws": "Crear cuenta AWS dedicada para backups en AWS Organizations. Configurar copy actions cross-account en AWS Backup.",
            "azure": "Crear suscripción dedicada para Recovery Services. Configurar Cross-subscription backup.",
            "gcp": "Crear proyecto GCP dedicado para backups. Configurar permisos mínimos y replicación cross-project.",
        },
        ransomware_context="CRÍTICO: El aislamiento de backups en cuenta/proyecto separado impide que un atacante con acceso a la cuenta de producción pueda eliminar los backups.",
    ),

    RRRule(
        rule_id="RR-BKP-015",
        name="RTO/RPO documentados y validados",
        description="Recovery Time Objective (RTO) y Recovery Point Objective (RPO) deben estar documentados "
                    "y los backups configurados para cumplirlos.",
        domain=Domain.D3,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": [],
            "azure": [],
            "gcp": [],
        },
        is_manual=True,
        remediation={
            "aws": "Documentar RTO/RPO por servicio. Validar que backup frequency y retention cumplen RPO. Realizar restore drills.",
            "azure": "Documentar RTO/RPO por servicio. Validar configuración de backup contra los objetivos definidos.",
            "gcp": "Documentar RTO/RPO por servicio. Verificar que backup schedules cumplen con los objetivos.",
        },
        ransomware_context="Sin RTO/RPO documentados, la recuperación de ransomware será caótica y más lenta. Saber cuánto se puede perder (RPO) y cuánto tarda recuperar (RTO) es esencial.",
    ),

    RRRule(
        rule_id="RR-BKP-016",
        name="Pruebas de restauración de backup realizadas",
        description="Los backups deben ser probados periódicamente (mínimo trimestralmente) "
                    "restaurando a un entorno de test para validar integridad.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": [],
            "azure": [],
            "gcp": [],
        },
        is_manual=True,
        remediation={
            "aws": "Programar restore drills trimestrales. Documentar resultados. Automatizar con AWS Backup restore testing.",
            "azure": "Realizar pruebas de restauración trimestrales en Recovery Services. Documentar RTO logrado.",
            "gcp": "Ejecutar restore tests trimestrales. Documentar tiempos de recuperación y validar integridad de datos.",
        },
        ransomware_context="Un backup nunca probado puede fallar cuando más se necesita. Las pruebas de restauración validan que la recuperación de ransomware realmente funciona.",
    ),

    RRRule(
        rule_id="RR-BKP-017",
        name="Disaster recovery plan documentado y actualizado",
        description="Debe existir un plan de disaster recovery documentado que incluya "
                    "procedimientos específicos de recuperación ante ransomware.",
        domain=Domain.D3,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-04",
        check_ids={
            "aws": [],
            "azure": [],
            "gcp": [],
        },
        is_manual=True,
        remediation={
            "aws": "Crear DR plan con runbooks específicos por servicio AWS. Incluir escenario de ransomware. Revisar semestralmente.",
            "azure": "Documentar DR plan con Azure Site Recovery. Incluir procedimientos de ransomware recovery.",
            "gcp": "Crear DR plan con procedimientos GCP. Incluir escenario de ransomware con pasos de aislamiento y recovery.",
        },
        ransomware_context="Un DR plan específico para ransomware acelera la respuesta: el equipo sabe exactamente qué hacer, en qué orden, y qué restaurar primero.",
    ),

    RRRule(
        rule_id="RR-BKP-018",
        name="DynamoDB/NoSQL backup configurado",
        description="Bases de datos NoSQL deben tener backup automático y PITR configurados.",
        domain=Domain.D3,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["dynamodb_table", "cosmos_db", "firestore"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["dynamodb_pitr_enabled", "dynamodb_backup_enabled"],
            "azure": ["cosmos_db_backup_configured"],
            "gcp": ["gcp_firestore_backup_configured"],
        },
        remediation={
            "aws": "Habilitar PITR en DynamoDB tables: aws dynamodb update-continuous-backups --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true.",
            "azure": "Verificar backup mode en Cosmos DB (Continuous o Periodic). Configurar continuous backup preferido.",
            "gcp": "Configurar Firestore export schedules via Cloud Functions o Cloud Scheduler.",
        },
        ransomware_context="Las bases de datos NoSQL contienen datos de aplicación críticos. Sin backup, un ataque de ransomware puede causar pérdida permanente de datos de negocio.",
    ),

    RRRule(
        rule_id="RR-BKP-019",
        name="Serverless function code y config con backup",
        description="Código y configuración de funciones serverless deben estar versionadas "
                    "y respaldadas (IaC en repositorio o backup dedicado).",
        domain=Domain.D3,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["lambda_function", "azure_function", "cloud_function"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["lambda_versioning_enabled"],
            "azure": ["function_app_backup_configured"],
            "gcp": ["gcp_cloud_function_versioned"],
        },
        remediation={
            "aws": "Usar Lambda versioning y aliases. Mantener código en repositorio git. Desplegar via IaC (CloudFormation/Terraform).",
            "azure": "Configurar backup para Azure Functions App Service. Mantener código en repositorio.",
            "gcp": "Mantener Cloud Functions código en repositorio. Usar versioning y traffic splitting.",
        },
        ransomware_context="El ransomware puede modificar código de funciones serverless para persistir o propagarse. Versioning y backup del código permiten restaurar funciones limpias.",
    ),

    RRRule(
        rule_id="RR-BKP-020",
        name="Backup vault access policies restrictivas",
        description="El acceso a backup vaults debe ser restringido. Solo roles de backup dedicados "
                    "deben poder gestionar y restaurar backups.",
        domain=Domain.D3,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["backup_vault"],
        nist_category="PR.DS",
        nist_subcategory="PR.DS-11",
        check_ids={
            "aws": ["backup_vault_access_policy_restrictive"],
            "azure": ["backup_rbac_configured"],
            "gcp": ["gcp_backup_access_restricted"],
        },
        remediation={
            "aws": "Configurar vault access policy restrictiva en AWS Backup. Separar roles de backup admin y restore operator.",
            "azure": "Configurar RBAC en Recovery Services vault. Asignar roles específicos (Backup Operator, Backup Reader).",
            "gcp": "Restringir acceso a backup resources via IAM. Crear custom roles para backup management.",
        },
        ransomware_context="Si las access policies del backup vault son permisivas, el atacante puede eliminar o modificar los backups desde la cuenta comprometida.",
    ),
]
