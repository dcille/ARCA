"""Domain D6: Logging & Monitoring — 10 rules (weight 5%).

Maps to NIST CSF 2.0 PR.PS (Platform Security) / DE.CM (Continuous Monitoring).
"""

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity

D6_RULES: list[RRRule] = [
    RRRule(
        rule_id="RR-LOG-001",
        name="Logging de auditoría habilitado en todas las cuentas",
        description="CloudTrail (AWS), Activity Log (Azure), Cloud Audit Logs (GCP) deben estar "
                    "habilitados en todas las cuentas con multi-region trail.",
        domain=Domain.D6,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["cloudtrail", "activity_log", "audit_log"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["cloudtrail_enabled", "cloudtrail_multiregion"],
            "azure": ["logging_activity_log_enabled"],
            "gcp": ["gcp_logging_audit_logs_enabled"],
        },
        remediation={
            "aws": "Crear CloudTrail trail multi-region con management events habilitados. Enviar a S3 bucket centralizado.",
            "azure": "Verificar Activity Log habilitado (default). Configurar diagnostic settings para enviar a Log Analytics workspace.",
            "gcp": "Cloud Audit Logs están habilitados por defecto. Verificar que Admin Activity y Data Access logs están configurados.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-002",
        name="Logs protegidos contra eliminación y modificación",
        description="Log files deben tener validation habilitada, almacenamiento inmutable, "
                    "y WORM policies para prevenir tampering por atacantes.",
        domain=Domain.D6,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["cloudtrail", "log_storage"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["cloudtrail_log_validation_enabled", "cloudtrail_s3_bucket_immutable"],
            "azure": ["logging_immutable_storage"],
            "gcp": ["gcp_logging_bucket_locked"],
        },
        remediation={
            "aws": "Habilitar CloudTrail log file validation. Configurar S3 bucket de logs con Object Lock. Usar SCP para prevenir trail deletion.",
            "azure": "Configurar Immutable Blob Storage para log storage accounts. Usar resource locks en diagnostic settings.",
            "gcp": "Configurar locked retention policy en Cloud Logging buckets. Usar Organization Policy para prevenir log deletion.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-003",
        name="Alertas configuradas para eventos críticos de seguridad",
        description="Deben existir alertas para: desactivación de logging, cambios en IAM root, "
                    "eliminación de backups, cambios en KMS keys, creación de admin users.",
        domain=Domain.D6,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["cloudwatch_alarm", "monitor_alert", "monitoring_alert"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["cloudwatch_alarm_root_usage", "cloudwatch_alarm_iam_changes",
                     "cloudwatch_alarm_cloudtrail_changes"],
            "azure": ["monitor_alert_security_events"],
            "gcp": ["gcp_logging_ownership_changes", "gcp_logging_audit_config_changes",
                     "gcp_logging_custom_role_changes"],
        },
        is_composite=True,
        remediation={
            "aws": "Crear CloudWatch metric filters y alarms para: root login, IAM policy changes, CloudTrail changes, KMS key deletion.",
            "azure": "Crear Azure Monitor alert rules para: Activity Log security events, role assignment changes, resource deletions.",
            "gcp": "Crear log-based alerting policies para: ownership changes, audit config changes, custom role changes, firewall changes.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-004",
        name="Retención de logs adecuada (≥365 días)",
        description="Los logs de auditoría deben tener retención mínima de 365 días "
                    "para investigación forense post-incidente.",
        domain=Domain.D6,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["log_group", "log_analytics", "logging_bucket"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["cloudwatch_log_group_retention_365d", "cloudtrail_s3_lifecycle_retention"],
            "azure": ["log_analytics_retention_365d"],
            "gcp": ["gcp_logging_retention_365d"],
        },
        remediation={
            "aws": "Configurar CloudWatch Log Group retention a 365 días mínimo. Configurar S3 lifecycle para CloudTrail logs.",
            "azure": "Configurar retention en Log Analytics workspace a 365 días. Configurar archive policies.",
            "gcp": "Configurar custom retention en Cloud Logging buckets a 365 días. Usar log sinks a Cloud Storage para archival.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-005",
        name="Logging centralizado configurado",
        description="Logs de todas las cuentas/suscripciones/proyectos deben centralizarse "
                    "en un repositorio central para correlación y análisis.",
        domain=Domain.D6,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["log_archive"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["cloudtrail_organization_trail", "cloudwatch_cross_account_logging"],
            "azure": ["logging_centralized_workspace"],
            "gcp": ["gcp_logging_organization_sink"],
        },
        remediation={
            "aws": "Crear Organization Trail en cuenta de logging dedicada. Configurar cross-account CloudWatch Logs.",
            "azure": "Crear Log Analytics workspace central. Configurar diagnostic settings de todas las suscripciones al workspace central.",
            "gcp": "Crear organization-level log sink a Cloud Storage/BigQuery en proyecto de logging dedicado.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-006",
        name="VPC Flow Logs con retención adecuada",
        description="VPC Flow Logs deben estar habilitados con retención mínima de 90 días "
                    "para análisis forense de movimiento lateral.",
        domain=Domain.D6,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["vpc", "flow_log"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["vpc_flow_logs_enabled"],
            "azure": ["network_nsg_flow_logs_enabled"],
            "gcp": ["gcp_network_flow_logs_enabled"],
        },
        remediation={
            "aws": "Habilitar VPC Flow Logs con retención de 90 días en CloudWatch o lifecycle policy en S3.",
            "azure": "Configurar NSG Flow Logs con retención de 90 días en Network Watcher.",
            "gcp": "Habilitar VPC Flow Logs en subnets con log retention configurado.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-007",
        name="DNS query logging habilitado",
        description="DNS query logging ayuda a detectar comunicaciones C2 de ransomware "
                    "y exfiltración via DNS tunneling.",
        domain=Domain.D6,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["dns_resolver"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["route53_query_logging_enabled"],
            "azure": ["dns_query_logging_enabled"],
            "gcp": ["gcp_dns_logging_enabled"],
        },
        remediation={
            "aws": "Habilitar Route 53 Resolver query logging. Enviar a CloudWatch Logs para análisis.",
            "azure": "Configurar DNS Analytics en Azure Monitor. Habilitar diagnostic logging en DNS zones.",
            "gcp": "Habilitar DNS logging en Cloud DNS policies. Exportar logs para análisis.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-008",
        name="S3/Storage access logging habilitado",
        description="Access logging debe estar habilitado en storage buckets que contienen "
                    "datos sensibles o backups.",
        domain=Domain.D6,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "storage_account"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["s3_bucket_logging_enabled"],
            "azure": ["storage_logging_enabled"],
            "gcp": ["gcp_storage_access_logging"],
        },
        remediation={
            "aws": "Habilitar S3 server access logging en buckets de datos y backups. Configurar target bucket dedicado.",
            "azure": "Habilitar Storage Analytics logging y diagnostic settings en Storage Accounts.",
            "gcp": "Cloud Storage access logs son via Cloud Audit Logs (habilitado por defecto para admin operations).",
        },
    ),

    RRRule(
        rule_id="RR-LOG-009",
        name="SIEM integration o log analysis configurado",
        description="Los logs deben estar integrados con un SIEM o plataforma de análisis "
                    "para correlación y detección de incidentes.",
        domain=Domain.D6,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["siem_integration"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": [],
            "azure": ["sentinel_enabled"],
            "gcp": [],
        },
        is_manual=True,
        remediation={
            "aws": "Integrar CloudTrail y CloudWatch Logs con SIEM (Splunk, Sentinel, etc.) via S3 export o Kinesis.",
            "azure": "Habilitar Microsoft Sentinel. Conectar Activity Logs, Defender alerts, y otros data connectors.",
            "gcp": "Exportar Cloud Logging a SIEM via Pub/Sub o BigQuery. Integrar con Chronicle SIEM.",
        },
    ),

    RRRule(
        rule_id="RR-LOG-010",
        name="Alertas de cambio en configuración de logging",
        description="Deben existir alertas que detecten inmediatamente si alguien desactiva o modifica "
                    "la configuración de logging (primer paso de muchos ataques).",
        domain=Domain.D6,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["monitoring_alert"],
        nist_category="PR.PS",
        nist_subcategory="PR.PS-04",
        check_ids={
            "aws": ["cloudwatch_alarm_cloudtrail_changes", "cloudtrail_s3_bucket_deletion_alert"],
            "azure": ["monitor_alert_diagnostic_setting_changes"],
            "gcp": ["gcp_logging_audit_config_changes"],
        },
        remediation={
            "aws": "Crear CloudWatch alarm para StopLogging, DeleteTrail, UpdateTrail events. Configurar SNS notification.",
            "azure": "Crear Azure Monitor alert para cambios en diagnostic settings y Activity Log configuration.",
            "gcp": "Crear alerting policy para cambios en Cloud Audit Log configuration y sink modifications.",
        },
    ),
]
