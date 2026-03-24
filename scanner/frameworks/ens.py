"""ENS -- Esquema Nacional de Seguridad (Real Decreto 311/2022).

Marco de cumplimiento que mapea las medidas de seguridad del ENS a controles
de seguridad en la nube para AWS, Azure, GCP, OCI y Alibaba Cloud.
"""

FRAMEWORK = {
    "ENS": {
        "name": "Esquema Nacional de Seguridad (RD 311/2022)",
        "description": (
            "Marco regulatorio español que establece la política de seguridad "
            "para la protección adecuada de la información y los servicios "
            "prestados por las Administraciones Públicas y entidades del "
            "sector público. Actualizado por el Real Decreto 311/2022."
        ),
        "category": "regulatory",
        "controls": [
            # ── Marco Organizativo (org) ────────────────────────────────────
            {
                "id": "org.1",
                "title": "Política de seguridad",
                "description": (
                    "Todos los órganos superiores de las AAPP deberán disponer "
                    "formalmente de su política de seguridad aprobada por el "
                    "titular del órgano."
                ),
                "checks": {
                    "aws": ["organizations_scp_enabled", "config_recorder_enabled"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_security_initiative"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_resource_hierarchy"],
                },
            },
            {
                "id": "org.2",
                "title": "Normativa de seguridad",
                "description": (
                    "Se dispondrá de una serie de documentos que describan la "
                    "normativa de seguridad del organismo."
                ),
                "checks": {
                    "aws": ["config_rules_active", "organizations_scp_enabled"],
                    "azure": ["azure_policy_assignments_exist", "azure_management_groups_configured"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_resource_hierarchy"],
                },
            },
            {
                "id": "org.3",
                "title": "Procedimientos de seguridad",
                "description": (
                    "Se dispondrá de procedimientos documentados para la "
                    "gestión de la seguridad."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_multiregion"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
                },
            },
            {
                "id": "org.4",
                "title": "Proceso de autorización",
                "description": (
                    "Se establecerá un proceso formal de autorizaciones que "
                    "cubra todos los elementos del sistema de información."
                ),
                "checks": {
                    "aws": ["iam_access_analyzer_enabled", "iam_no_star_policies"],
                    "azure": ["azure_ad_pim_enabled", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_iam_recommender_enabled", "gcp_iam_no_primitive_roles"],
                },
            },
            # ── Marco Operacional — Planificación (op.pl) ───────────────────
            {
                "id": "op.pl.1",
                "title": "Análisis de riesgos",
                "description": (
                    "Se realizará un análisis de riesgos que identifique "
                    "amenazas y vulnerabilidades a los que están expuestos "
                    "los sistemas de información."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "inspector_enabled", "securityhub_enabled"],
                    "azure": ["azure_defender_enabled", "azure_defender_vulnerability_assessment"],
                    "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
                },
            },
            {
                "id": "op.pl.2",
                "title": "Arquitectura de seguridad",
                "description": (
                    "Se definirá la arquitectura de seguridad del sistema "
                    "de información, incluyendo los puntos de interconexión."
                ),
                "checks": {
                    "aws": ["vpc_default_security_group_closed", "vpc_public_private_subnets"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_firewall_configured"],
                    "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_vpc_private_google_access"],
                },
            },
            {
                "id": "op.pl.3",
                "title": "Adquisición de nuevos componentes",
                "description": (
                    "Todo elemento del sistema de información será evaluado "
                    "previamente a su adquisición o incorporación."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "config_rules_active"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_asset_inventory_enabled"],
                },
            },
            {
                "id": "op.pl.4",
                "title": "Dimensionamiento / gestión de la capacidad",
                "description": (
                    "Se planificará y gestionará la capacidad de los sistemas "
                    "de información para asegurar su disponibilidad."
                ),
                "checks": {
                    "aws": ["cloudwatch_alarm_actions", "autoscaling_configured"],
                    "azure": ["azure_autoscale_configured", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_compute_autoscaler_configured", "gcp_monitoring_alert_policies"],
                },
            },
            # ── Marco Operacional — Control de acceso (op.acc) ──────────────
            {
                "id": "op.acc.1",
                "title": "Identificación",
                "description": (
                    "Los usuarios serán identificados de forma única en el "
                    "sistema."
                ),
                "checks": {
                    "aws": ["iam_no_root_access_key", "iam_users_in_groups"],
                    "azure": ["azure_ad_individual_accounts", "azure_ad_no_guest_admin"],
                    "gcp": ["gcp_iam_no_sa_admin_privilege", "gcp_iam_workload_identity"],
                },
            },
            {
                "id": "op.acc.2",
                "title": "Requisitos de acceso",
                "description": (
                    "Se limitará el acceso a los recursos según los requisitos "
                    "de cada puesto de trabajo."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_user_no_attached_policies"],
                    "azure": ["azure_rbac_least_privilege", "azure_iam_no_custom_owner_roles"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_no_public_access"],
                },
            },
            {
                "id": "op.acc.3",
                "title": "Segregación de funciones y tareas",
                "description": (
                    "Se implementará la segregación de funciones para prevenir "
                    "errores y fraudes."
                ),
                "checks": {
                    "aws": ["iam_policies_attached_to_groups", "iam_access_analyzer_enabled"],
                    "azure": ["azure_ad_pim_enabled", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_iam_separation_of_duties", "gcp_iam_recommender_enabled"],
                },
            },
            {
                "id": "op.acc.4",
                "title": "Proceso de gestión de derechos de acceso",
                "description": (
                    "Se establecerá un proceso formal para la gestión de "
                    "altas, bajas y modificaciones de acceso."
                ),
                "checks": {
                    "aws": ["iam_user_unused_credentials", "iam_access_key_rotation"],
                    "azure": ["azure_ad_stale_accounts", "azure_ad_access_reviews"],
                    "gcp": ["gcp_iam_unused_sa_keys", "gcp_iam_user_sa_key_rotation"],
                },
            },
            {
                "id": "op.acc.5",
                "title": "Mecanismo de autenticación (usuarios externos)",
                "description": (
                    "Se utilizarán mecanismos de autenticación acordes al "
                    "nivel de seguridad del sistema."
                ),
                "checks": {
                    "aws": ["iam_mfa_enabled_for_console", "iam_root_mfa_enabled"],
                    "azure": ["azure_ad_mfa_enabled", "azure_ad_conditional_access"],
                    "gcp": ["gcp_iam_2fa_enforced", "gcp_org_policy_constraints"],
                },
            },
            {
                "id": "op.acc.6",
                "title": "Mecanismo de autenticación (usuarios del organismo)",
                "description": (
                    "Los usuarios internos utilizarán mecanismos de autenticación "
                    "robustos para acceder al sistema."
                ),
                "checks": {
                    "aws": ["iam_password_policy_strong", "iam_mfa_enabled_for_console"],
                    "azure": ["azure_ad_password_policy", "azure_ad_mfa_enabled"],
                    "gcp": ["gcp_iam_2fa_enforced", "gcp_compute_os_login"],
                },
            },
            {
                "id": "op.acc.7",
                "title": "Acceso local (local logon)",
                "description": (
                    "Se controlará el acceso local a los sistemas de información."
                ),
                "checks": {
                    "aws": ["ec2_no_public_ip", "ssm_managed_instances"],
                    "azure": ["azure_vm_no_public_ip", "azure_jit_vm_access"],
                    "gcp": ["gcp_compute_no_public_ip", "gcp_compute_os_login"],
                },
            },
            {
                "id": "op.acc.8",
                "title": "Acceso remoto (remote access)",
                "description": (
                    "Se controlará y protegerá el acceso remoto a los "
                    "sistemas de información."
                ),
                "checks": {
                    "aws": ["ec2_no_unrestricted_ssh", "vpc_vpn_encryption"],
                    "azure": ["azure_nsg_unrestricted_port_22", "azure_vpn_gateway_encryption"],
                    "gcp": ["gcp_compute_firewall_no_ssh_open", "gcp_vpn_tunnel_encryption"],
                },
            },
            # ── Marco Operacional — Explotación (op.exp) ────────────────────
            {
                "id": "op.exp.1",
                "title": "Inventario de activos",
                "description": (
                    "Se mantendrá un inventario actualizado de todos los "
                    "activos del sistema de información."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "ssm_managed_instances"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_resource_graph"],
                    "gcp": ["gcp_asset_inventory_enabled", "gcp_logging_audit_logs_enabled"],
                },
            },
            {
                "id": "op.exp.2",
                "title": "Configuración de seguridad",
                "description": (
                    "Se configurarán los equipos previamente a su entrada "
                    "en servicio de forma segura."
                ),
                "checks": {
                    "aws": ["config_rules_active", "ec2_imdsv2_required"],
                    "azure": ["azure_policy_compliance_rate", "azure_vm_managed_disks"],
                    "gcp": ["gcp_compute_shielded_vm", "gcp_org_policy_constraints"],
                },
            },
            {
                "id": "op.exp.3",
                "title": "Gestión de la configuración de seguridad",
                "description": (
                    "Se gestionará de forma continua la configuración de "
                    "seguridad de los componentes del sistema."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "config_rules_active"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_scc_enabled"],
                },
            },
            {
                "id": "op.exp.4",
                "title": "Mantenimiento y actualizaciones de seguridad",
                "description": (
                    "Se aplicarán las actualizaciones de seguridad de forma "
                    "controlada y en plazo."
                ),
                "checks": {
                    "aws": ["ssm_patch_compliance", "rds_auto_minor_version_upgrade"],
                    "azure": ["azure_vm_auto_updates", "azure_sql_auto_patching"],
                    "gcp": ["gcp_os_patch_management", "gcp_sql_maintenance_window"],
                },
            },
            {
                "id": "op.exp.5",
                "title": "Gestión de cambios",
                "description": (
                    "Se gestionarán los cambios en el sistema de forma "
                    "controlada y documentada."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_iam_changes_alarm"],
                    "azure": ["azure_monitor_iam_changes", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_logging_iam_changes", "gcp_asset_inventory_enabled"],
                },
            },
            {
                "id": "op.exp.6",
                "title": "Protección frente a código dañino",
                "description": (
                    "Se dispondrá de mecanismos de prevención y detección "
                    "frente a código dañino (malware)."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "guardduty_malware_protection"],
                    "azure": ["azure_endpoint_protection_installed", "azure_vm_antimalware_extension"],
                    "gcp": ["gcp_scc_enabled", "gcp_compute_shielded_vm"],
                },
            },
            {
                "id": "op.exp.7",
                "title": "Gestión de incidentes",
                "description": (
                    "Se dispondrá de procedimientos de gestión de incidentes "
                    "de seguridad."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "securityhub_enabled", "sns_topics_configured"],
                    "azure": ["azure_sentinel_automation_rules", "azure_action_groups_configured"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_logging_alert_policies"],
                },
            },
            {
                "id": "op.exp.8",
                "title": "Registro de la actividad de los usuarios",
                "description": (
                    "Se registrará la actividad de los usuarios de manera "
                    "que se pueda identificar quién hizo qué y cuándo."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation"],
                    "azure": ["azure_monitor_log_profile", "azure_monitor_activity_log"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_admin_activity"],
                },
            },
            {
                "id": "op.exp.9",
                "title": "Registro de la gestión de incidentes",
                "description": (
                    "Se registrarán todas las actuaciones relacionadas con "
                    "la gestión de incidentes."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudwatch_alarm_actions"],
                    "azure": ["azure_sentinel_automation_rules", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
                },
            },
            {
                "id": "op.exp.10",
                "title": "Protección de los registros de actividad",
                "description": (
                    "Se protegerán los registros de actividad frente a "
                    "manipulación no autorizada."
                ),
                "checks": {
                    "aws": ["cloudtrail_log_validation", "s3_object_lock_enabled", "cloudtrail_s3_bucket_not_public"],
                    "azure": ["azure_storage_immutability_policy", "azure_storage_no_public_access"],
                    "gcp": ["gcp_logging_log_bucket_locked", "gcp_storage_retention_policy"],
                },
            },
            # ── Marco Operacional — Continuidad (op.cont) ──────────────────
            {
                "id": "op.cont.1",
                "title": "Análisis de impacto",
                "description": (
                    "Se realizará un análisis de impacto que permita "
                    "determinar los requisitos de disponibilidad."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "config_recorder_enabled"],
                    "azure": ["azure_recovery_services_configured", "azure_defender_enabled"],
                    "gcp": ["gcp_scc_enabled", "gcp_sql_ha_configured"],
                },
            },
            {
                "id": "op.cont.2",
                "title": "Plan de continuidad",
                "description": (
                    "Se dispondrá de un plan de continuidad que establezca "
                    "las acciones a ejecutar en caso de interrupción."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_multi_az", "s3_cross_region_replication"],
                    "azure": ["azure_backup_vault_exists", "azure_sql_geo_replication"],
                    "gcp": ["gcp_sql_ha_configured", "gcp_storage_multi_region"],
                },
            },
            {
                "id": "op.cont.3",
                "title": "Pruebas periódicas",
                "description": (
                    "Se realizarán pruebas periódicas del plan de continuidad "
                    "para verificar su eficacia."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_automated_backups"],
                    "azure": ["azure_recovery_services_configured", "azure_backup_vault_exists"],
                    "gcp": ["gcp_sql_automated_backups", "gcp_gke_backup_enabled"],
                },
            },
            # ── Marco Operacional — Monitorización (op.mon) ─────────────────
            {
                "id": "op.mon.1",
                "title": "Detección de intrusión",
                "description": (
                    "Se dispondrá de sistemas de detección de intrusión "
                    "para detectar actividades no autorizadas."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "waf_web_acl_configured"],
                    "azure": ["azure_defender_enabled", "azure_waf_enabled"],
                    "gcp": ["gcp_scc_enabled", "gcp_cloud_armor_enabled"],
                },
            },
            {
                "id": "op.mon.2",
                "title": "Sistema de métricas",
                "description": (
                    "Se recopilarán y analizarán métricas de seguridad de "
                    "forma periódica."
                ),
                "checks": {
                    "aws": ["securityhub_enabled", "cloudwatch_alarm_actions"],
                    "azure": ["azure_defender_enabled", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_scc_enabled", "gcp_monitoring_alert_policies"],
                },
            },
            {
                "id": "op.mon.3",
                "title": "Vigilancia",
                "description": (
                    "Se establecerán mecanismos de vigilancia sobre los "
                    "servicios prestados por terceros."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "guardduty_enabled"],
                    "azure": ["azure_monitor_log_profile", "azure_sentinel_automation_rules"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
                },
            },
            # ── Medidas de Protección — Instalaciones (mp.if) ───────────────
            {
                "id": "mp.if.1",
                "title": "Áreas separadas y con control de acceso",
                "description": (
                    "Los equipos estarán instalados en áreas separadas "
                    "con acceso controlado."
                ),
                "checks": {
                    "aws": ["vpc_public_private_subnets", "vpc_default_security_group_closed"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_vm_no_public_ip"],
                    "gcp": ["gcp_compute_no_public_ip", "gcp_vpc_private_google_access"],
                },
            },
            {
                "id": "mp.if.2",
                "title": "Identificación de las personas",
                "description": (
                    "Se controlarán y registrarán los accesos a las zonas "
                    "donde se ubican los equipos."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "iam_no_root_access_key"],
                    "azure": ["azure_monitor_activity_log", "azure_ad_individual_accounts"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_iam_workload_identity"],
                },
            },
            # ── Medidas de Protección — Información (mp.info) ───────────────
            {
                "id": "mp.info.1",
                "title": "Datos de carácter personal",
                "description": (
                    "Cuando se traten datos de carácter personal se aplicará "
                    "la legislación de protección de datos vigente (RGPD/LOPDGDD)."
                ),
                "checks": {
                    "aws": ["macie_enabled", "s3_bucket_public_access_blocked"],
                    "azure": ["azure_purview_enabled", "azure_storage_no_public_access"],
                    "gcp": ["gcp_dlp_enabled", "gcp_storage_no_public_access"],
                },
            },
            {
                "id": "mp.info.2",
                "title": "Calificación de la información",
                "description": (
                    "La información se calificará de acuerdo con su nivel "
                    "de sensibilidad y se tratará según dicha calificación."
                ),
                "checks": {
                    "aws": ["macie_enabled", "config_recorder_enabled"],
                    "azure": ["azure_purview_enabled", "azure_information_protection"],
                    "gcp": ["gcp_dlp_enabled", "gcp_asset_inventory_enabled"],
                },
            },
            {
                "id": "mp.info.3",
                "title": "Cifrado",
                "description": (
                    "La información se cifrará tanto en tránsito como en reposo."
                ),
                "checks": {
                    "aws": ["s3_default_encryption", "rds_encryption_at_rest", "ebs_encryption_enabled", "elb_tls_listener"],
                    "azure": ["azure_storage_encryption_cmk", "azure_sql_tde_enabled", "azure_storage_https_only"],
                    "gcp": ["gcp_storage_cmek", "gcp_sql_encryption_cmek", "gcp_sql_ssl_enforced"],
                },
            },
            {
                "id": "mp.info.4",
                "title": "Firma electrónica",
                "description": (
                    "Se empleará firma electrónica para garantizar la "
                    "autenticidad, integridad y no repudio."
                ),
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "cloudtrail_log_validation"],
                    "azure": ["azure_keyvault_key_rotation", "azure_keyvault_rbac_enabled"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_kms_separation_of_duties"],
                },
            },
            {
                "id": "mp.info.5",
                "title": "Sellos de tiempo",
                "description": (
                    "Se emplearán sellos de tiempo para evidenciar el momento "
                    "de las transacciones."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation"],
                    "azure": ["azure_monitor_log_profile", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"],
                },
            },
            {
                "id": "mp.info.6",
                "title": "Limpieza de documentos",
                "description": (
                    "Se eliminarán los metadatos y datos ocultos de los "
                    "documentos antes de su distribución."
                ),
                "checks": {
                    "aws": ["macie_enabled", "s3_bucket_policy_restrictive"],
                    "azure": ["azure_purview_enabled", "azure_sql_data_masking"],
                    "gcp": ["gcp_dlp_enabled", "gcp_bigquery_column_security"],
                },
            },
            {
                "id": "mp.info.7",
                "title": "Copias de seguridad (backup)",
                "description": (
                    "Se realizarán copias de seguridad que permitan recuperar "
                    "datos perdidos parcial o totalmente."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_automated_backups", "dynamodb_pitr_enabled"],
                    "azure": ["azure_backup_vault_exists", "azure_sql_long_term_retention"],
                    "gcp": ["gcp_sql_automated_backups", "gcp_storage_versioning"],
                },
            },
            # ── Medidas de Protección — Servicios (mp.s) ────────────────────
            {
                "id": "mp.s.1",
                "title": "Protección del correo electrónico",
                "description": (
                    "Se protegerá el correo electrónico frente a amenazas "
                    "como phishing, spam y malware."
                ),
                "checks": {
                    "aws": ["ses_identity_verified", "guardduty_enabled"],
                    "azure": ["azure_defender_enabled", "azure_sentinel_automation_rules"],
                    "gcp": ["gcp_scc_enabled", "gcp_logging_admin_activity"],
                },
            },
            {
                "id": "mp.s.2",
                "title": "Protección de servicios y aplicaciones web",
                "description": (
                    "Se protegerán los servicios y aplicaciones web frente "
                    "a los ataques comunes."
                ),
                "checks": {
                    "aws": ["waf_web_acl_configured", "cloudfront_waf_enabled"],
                    "azure": ["azure_waf_enabled", "azure_frontdoor_waf_enabled"],
                    "gcp": ["gcp_cloud_armor_enabled", "gcp_cloud_armor_rules_configured"],
                },
            },
            {
                "id": "mp.s.3",
                "title": "Protección frente a la denegación de servicio",
                "description": (
                    "Se protegerán los servicios frente a ataques de "
                    "denegación de servicio (DoS/DDoS)."
                ),
                "checks": {
                    "aws": ["shield_advanced_enabled", "waf_web_acl_configured"],
                    "azure": ["azure_ddos_protection", "azure_waf_enabled"],
                    "gcp": ["gcp_cloud_armor_enabled", "gcp_cloud_armor_ddos_protection"],
                },
            },
            {
                "id": "mp.s.4",
                "title": "Medios alternativos",
                "description": (
                    "Se dispondrá de medios alternativos de prestación del "
                    "servicio en caso de indisponibilidad."
                ),
                "checks": {
                    "aws": ["rds_multi_az", "s3_cross_region_replication", "autoscaling_configured"],
                    "azure": ["azure_sql_geo_replication", "azure_traffic_manager_configured"],
                    "gcp": ["gcp_sql_ha_configured", "gcp_lb_backend_health"],
                },
            },
            # ── Medidas de Protección — Comunicaciones (mp.com) ─────────────
            {
                "id": "mp.com.1",
                "title": "Perímetro seguro",
                "description": (
                    "Se mantendrá un perímetro de seguridad para controlar "
                    "las comunicaciones con el exterior."
                ),
                "checks": {
                    "aws": ["vpc_default_security_group_closed", "vpc_security_groups_restrictive"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_firewall_configured"],
                    "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_vpc_default_firewall_rules"],
                },
            },
            {
                "id": "mp.com.2",
                "title": "Protección de la confidencialidad",
                "description": (
                    "Se protegerá la confidencialidad de la información "
                    "cuando se transmita por redes de comunicaciones."
                ),
                "checks": {
                    "aws": ["elb_tls_listener", "s3_ssl_requests_only", "vpc_vpn_encryption"],
                    "azure": ["azure_storage_https_only", "azure_vpn_gateway_encryption"],
                    "gcp": ["gcp_sql_ssl_enforced", "gcp_vpn_tunnel_encryption"],
                },
            },
            {
                "id": "mp.com.3",
                "title": "Protección de la autenticidad y de la integridad",
                "description": (
                    "Se protegerá la autenticidad e integridad de la "
                    "información cuando se transmita por redes."
                ),
                "checks": {
                    "aws": ["elb_tls_listener", "cloudfront_tls_minimum_version"],
                    "azure": ["azure_appservice_tls_minimum", "azure_storage_https_only"],
                    "gcp": ["gcp_lb_ssl_policy", "gcp_compute_ssl_minimum_version"],
                },
            },
            {
                "id": "mp.com.4",
                "title": "Segregación de redes",
                "description": (
                    "Se segregarán las redes de manera que se contenga "
                    "el tráfico y se controlen los flujos."
                ),
                "checks": {
                    "aws": ["vpc_public_private_subnets", "vpc_flow_logs_enabled"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_nsg_flow_logs_enabled"],
                    "gcp": ["gcp_vpc_flow_logs_enabled", "gcp_compute_firewall_no_open_ports"],
                },
            },
            # ── Medidas de Protección — Soportes (mp.si) ────────────────────
            {
                "id": "mp.si.1",
                "title": "Etiquetado",
                "description": (
                    "Los soportes de información se etiquetarán de acuerdo "
                    "con la información que contengan."
                ),
                "checks": {
                    "aws": ["s3_bucket_tagging", "ec2_instance_tagging"],
                    "azure": ["azure_resource_tagging", "azure_storage_tagging"],
                    "gcp": ["gcp_resource_labeling", "gcp_storage_labeling"],
                },
            },
            {
                "id": "mp.si.2",
                "title": "Criptografía",
                "description": (
                    "Se aplicará criptografía para proteger la información "
                    "almacenada en soportes."
                ),
                "checks": {
                    "aws": ["ebs_encryption_enabled", "s3_default_encryption"],
                    "azure": ["azure_disk_encryption", "azure_storage_encryption_cmk"],
                    "gcp": ["gcp_compute_disk_cmek", "gcp_storage_cmek"],
                },
            },
            {
                "id": "mp.si.3",
                "title": "Custodia",
                "description": (
                    "Se aplicará la debida diligencia y control en la "
                    "custodia de los soportes de información."
                ),
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "s3_bucket_policy_restrictive"],
                    "azure": ["azure_storage_no_public_access", "azure_resource_locks"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_storage_uniform_bucket_access"],
                },
            },
            {
                "id": "mp.si.4",
                "title": "Transporte",
                "description": (
                    "Se protegerán los soportes de información durante "
                    "su transporte."
                ),
                "checks": {
                    "aws": ["s3_ssl_requests_only", "elb_tls_listener"],
                    "azure": ["azure_storage_https_only", "azure_appservice_https_only"],
                    "gcp": ["gcp_sql_ssl_enforced", "gcp_storage_https_only"],
                },
            },
            {
                "id": "mp.si.5",
                "title": "Borrado y destrucción",
                "description": (
                    "Se aplicarán mecanismos de borrado seguro y destrucción "
                    "de soportes cuando dejen de ser necesarios."
                ),
                "checks": {
                    "aws": ["s3_lifecycle_policy", "ebs_snapshot_lifecycle"],
                    "azure": ["azure_storage_lifecycle_management", "azure_storage_soft_delete"],
                    "gcp": ["gcp_storage_lifecycle_policy", "gcp_compute_snapshot_policy"],
                },
            },
        ],
    },
}
