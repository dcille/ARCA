"""Domain D1: Identity & Access Management — 25 rules (weight 25%).

Maps to NIST CSF 2.0 PR.AA (Identity Management, Authentication, Access Control).
"""

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity

D1_RULES: list[RRRule] = [
    # ── RR-IAM-001: MFA for console users ────────────────────────
    RRRule(
        rule_id="RR-IAM-001",
        name="MFA habilitado para todos los usuarios con acceso a consola",
        description="Verifica que el 100% de los usuarios IAM con acceso a consola tienen MFA activo. "
                    "Sin MFA, credenciales comprometidas permiten acceso directo al entorno cloud.",
        domain=Domain.D1,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_user"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-01",
        check_ids={
            "aws": ["iam_user_mfa_enabled"],
            "azure": ["iam_mfa_enabled_all_users"],
            "gcp": ["gcp_iam_mfa_enabled"],
        },
        remediation={
            "aws": "Habilitar MFA virtual o hardware para cada usuario IAM con acceso a consola via IAM > Users > Security credentials > Assign MFA device.",
            "azure": "Configurar MFA en Entra ID > Security > MFA > Additional cloud-based MFA settings. Activar per-user MFA o Conditional Access policy.",
            "gcp": "Activar 2-Step Verification en Admin Console > Security > Authentication > 2-step verification. Aplicar a toda la organización.",
        },
    ),

    # ── RR-IAM-002: MFA for root/owner ───────────────────────────
    RRRule(
        rule_id="RR-IAM-002",
        name="MFA habilitado para cuenta root/propietario",
        description="La cuenta root (AWS), Global Admin (Azure) o Super Admin (GCP) debe tener MFA activo. "
                    "Compromiso de esta cuenta otorga control total del entorno.",
        domain=Domain.D1,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_root"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-01",
        check_ids={
            "aws": ["iam_root_mfa_enabled"],
            "azure": ["iam_global_admin_mfa"],
            "gcp": ["gcp_iam_super_admin_mfa"],
        },
        remediation={
            "aws": "Habilitar MFA hardware (YubiKey preferido) en la cuenta root: AWS Console > My Security Credentials > Multi-factor authentication.",
            "azure": "Configurar MFA para todos los Global Administrators via Conditional Access o per-user MFA en Entra ID.",
            "gcp": "Activar 2-Step Verification con llave de seguridad física para cuentas Super Admin en admin.google.com.",
        },
    ),

    # ── RR-IAM-003: Access key rotation ──────────────────────────
    RRRule(
        rule_id="RR-IAM-003",
        name="No existen access keys de larga duración sin rotación",
        description="Access keys (AWS) o service account keys (GCP) activas por más de 90 días "
                    "representan un riesgo de credenciales comprometidas no detectadas.",
        domain=Domain.D1,
        severity=Severity.HIGH,
        cloud_providers=["aws", "gcp"],
        resource_types=["iam_access_key", "service_account_key"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-02",
        check_ids={
            "aws": ["iam_access_keys_rotated_90_days", "iam_no_active_access_keys_root"],
            "gcp": ["gcp_iam_service_account_key_rotation"],
        },
        remediation={
            "aws": "Rotar access keys cada 90 días: IAM > Users > Security credentials > Create access key (nueva) > Deactivate old key > Delete.",
            "gcp": "Eliminar service account keys de más de 90 días y migrar a Workload Identity Federation: gcloud iam service-accounts keys delete.",
        },
    ),

    # ── RR-IAM-004: Least privilege ──────────────────────────────
    RRRule(
        rule_id="RR-IAM-004",
        name="Principio de mínimo privilegio en políticas IAM",
        description="Identifica políticas con Action:* o Resource:* (AWS), roles Owner/Contributor sin scope (Azure), "
                    "o roles/owner sin condiciones (GCP). Admin access debe ser mínimo.",
        domain=Domain.D1,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_policy", "iam_role"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_no_star_policies", "iam_policy_no_admin_access"],
            "azure": ["iam_no_owner_role_all_resources", "iam_custom_role_least_privilege"],
            "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_no_owner_role"],
        },
        remediation={
            "aws": "Reemplazar políticas con Action:*/Resource:* por políticas específicas. Usar IAM Access Analyzer para identificar permisos no utilizados.",
            "azure": "Reemplazar rol Owner por roles más específicos (Contributor con exclusiones). Usar PIM para acceso just-in-time.",
            "gcp": "Reemplazar roles primitivos (Owner/Editor) por roles predefinidos específicos. Usar IAM Recommender para right-sizing.",
        },
    ),

    # ── RR-IAM-005: Service account privileges ───────────────────
    RRRule(
        rule_id="RR-IAM-005",
        name="Service accounts sin privilegios excesivos",
        description="Service accounts, roles de servicio o machine identities no deben tener permisos administrativos "
                    "innecesarios para su función.",
        domain=Domain.D1,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["service_account", "iam_role"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_role_no_admin_policy"],
            "azure": ["iam_service_principal_least_privilege"],
            "gcp": ["gcp_iam_service_account_no_admin", "gcp_iam_service_account_no_keys"],
        },
        remediation={
            "aws": "Revisar roles de servicio con AdministratorAccess. Crear políticas custom con solo los permisos necesarios.",
            "azure": "Auditar Service Principals con roles Owner/Contributor. Asignar roles específicos por recurso.",
            "gcp": "Revisar service accounts con roles Owner/Editor. Usar roles predefinidos específicos por servicio.",
        },
    ),

    # ── RR-IAM-006: Session duration ─────────────────────────────
    RRRule(
        rule_id="RR-IAM-006",
        name="Sesiones con duración limitada para roles privilegiados",
        description="Roles administrativos deben tener duración de sesión máxima reducida (<1h para admin). "
                    "Sesiones largas amplían la ventana de ataque post-compromiso.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure"],
        resource_types=["iam_role", "session_policy"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-03",
        check_ids={
            "aws": ["iam_role_max_session_duration"],
            "azure": ["iam_conditional_access_session_controls"],
        },
        remediation={
            "aws": "Configurar MaxSessionDuration a 3600 (1h) para roles administrativos via update-role.",
            "azure": "Configurar Conditional Access > Session > Sign-in frequency a 1 hora para roles administrativos.",
        },
    ),

    # ── RR-IAM-007: Cross-account access ─────────────────────────
    RRRule(
        rule_id="RR-IAM-007",
        name="Acceso cross-account revisado y controlado",
        description="Trust policies que permiten AssumeRole desde cuentas externas deben ser explícitas y justificadas. "
                    "Acceso cross-account no controlado permite movimiento lateral entre cuentas.",
        domain=Domain.D1,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_role", "trust_policy"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_cross_account_access_controlled"],
            "azure": ["iam_cross_tenant_access_restricted"],
            "gcp": ["gcp_iam_cross_project_access"],
        },
        remediation={
            "aws": "Revisar trust policies de roles IAM. Eliminar principals de cuentas externas no autorizadas. Usar AWS Organizations SCPs para restringir.",
            "azure": "Configurar Cross-tenant access settings en Entra ID. Restringir invitaciones externas y B2B access.",
            "gcp": "Revisar IAM bindings con miembros de otros proyectos/organizaciones. Usar Organization Policy constraints.",
        },
    ),

    # ── RR-IAM-008: SCPs / Organization policies ─────────────────
    RRRule(
        rule_id="RR-IAM-008",
        name="Políticas de organización restrictivas implementadas",
        description="SCPs (AWS), Azure Policy (Azure) u Organization Policies (GCP) deben estar implementadas "
                    "para prevenir acciones peligrosas incluso por administradores.",
        domain=Domain.D1,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["organization_policy"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-06",
        check_ids={
            "aws": ["iam_organizations_scp_enabled"],
            "azure": ["iam_azure_policy_assignments"],
            "gcp": ["gcp_iam_organization_policy_enforced"],
        },
        remediation={
            "aws": "Implementar SCPs en AWS Organizations que denieguen: desactivación de CloudTrail, eliminación de backups, cambios en KMS.",
            "azure": "Crear Azure Policy assignments que denieguen acciones críticas y requieran configuraciones de seguridad.",
            "gcp": "Configurar Organization Policy constraints: restrict resource locations, disable service account key creation.",
        },
    ),

    # ── RR-IAM-009: Federated identity ───────────────────────────
    RRRule(
        rule_id="RR-IAM-009",
        name="Identidad federada configurada con hardening",
        description="Si se usa SSO/SAML/OIDC, la configuración debe incluir session timeouts, "
                    "certificate validation y attribute mapping seguros.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["identity_provider", "saml_provider"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-01",
        check_ids={
            "aws": ["iam_saml_provider_configured"],
            "azure": ["iam_federation_hardened"],
            "gcp": ["gcp_iam_workforce_identity"],
        },
        remediation={
            "aws": "Revisar SAML providers en IAM. Verificar certificate expiration, session duration, y que attribute mapping no otorgue admin.",
            "azure": "Revisar federated domains en Entra ID. Configurar token signing certificates y session controls.",
            "gcp": "Configurar Workforce Identity Federation con providers verificados. Limitar attribute conditions.",
        },
    ),

    # ── RR-IAM-010: Conditional access ───────────────────────────
    RRRule(
        rule_id="RR-IAM-010",
        name="Políticas de acceso condicional implementadas",
        description="Acceso a recursos cloud debe estar condicionado por ubicación, dispositivo, riesgo de sesión "
                    "u otros factores contextuales.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["conditional_access_policy"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-03",
        check_ids={
            "aws": ["iam_ip_condition_policies"],
            "azure": ["iam_conditional_access_policies_enabled"],
            "gcp": ["gcp_iam_access_context_manager"],
        },
        remediation={
            "aws": "Agregar condiciones aws:SourceIp, aws:MultiFactorAuthPresent en IAM policies para roles críticos.",
            "azure": "Crear Conditional Access policies en Entra ID para requerir MFA, dispositivo compliant, ubicación de confianza.",
            "gcp": "Configurar Access Context Manager con access levels basados en IP, dispositivo y geolocalización.",
        },
    ),

    # ── RR-IAM-011: JIT access ───────────────────────────────────
    RRRule(
        rule_id="RR-IAM-011",
        name="Acceso just-in-time para roles privilegiados",
        description="Los roles administrativos no deben estar asignados permanentemente. "
                    "Debe existir un mecanismo de elevación temporal (PIM, JIT).",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_role", "pim_assignment"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_no_permanent_admin_access"],
            "azure": ["iam_pim_enabled_for_admins"],
            "gcp": ["gcp_iam_no_permanent_owner"],
        },
        remediation={
            "aws": "Implementar AWS SSO Permission Sets con duración limitada. Usar temporary credentials via STS AssumeRole.",
            "azure": "Activar PIM (Privileged Identity Management) para roles Global Admin, Owner, Contributor. Requerir aprobación y MFA.",
            "gcp": "Implementar PAM (Privileged Access Manager) o usar temporal IAM bindings con condiciones de tiempo.",
        },
    ),

    # ── RR-IAM-012: Credential anomalies ─────────────────────────
    RRRule(
        rule_id="RR-IAM-012",
        name="Anomalías de credenciales detectadas y revisadas",
        description="Verificar que no existen credenciales con patrones anómalos: usuarios sin login reciente "
                    "pero con keys activas, credenciales compartidas, o múltiples keys activas.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "gcp"],
        resource_types=["iam_credential_report"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-02",
        check_ids={
            "aws": ["iam_credential_report_no_anomalies", "iam_unused_credentials_disabled"],
            "gcp": ["gcp_iam_unused_service_accounts"],
        },
        remediation={
            "aws": "Generar IAM Credential Report. Desactivar usuarios sin login >90 días con keys activas. Eliminar keys duplicadas.",
            "gcp": "Usar IAM Recommender para identificar service accounts y permisos no utilizados. Desactivar cuentas inactivas.",
        },
    ),

    # ── RR-IAM-013: Unused permissions cleanup ───────────────────
    RRRule(
        rule_id="RR-IAM-013",
        name="Permisos no utilizados identificados y eliminados",
        description="Permisos IAM otorgados pero no utilizados en >90 días deben ser revocados "
                    "para reducir la superficie de ataque.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_policy", "iam_role"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_unused_permissions_cleanup"],
            "azure": ["iam_unused_role_assignments"],
            "gcp": ["gcp_iam_recommender_applied"],
        },
        remediation={
            "aws": "Usar IAM Access Analyzer para generar políticas basadas en actividad real. Aplicar permission boundaries.",
            "azure": "Usar Access Reviews en Entra ID para identificar y revocar asignaciones no utilizadas.",
            "gcp": "Aplicar recomendaciones de IAM Recommender. Revocar roles no utilizados en >90 días.",
        },
    ),

    # ── RR-IAM-014: Break-glass account ──────────────────────────
    RRRule(
        rule_id="RR-IAM-014",
        name="Cuenta break-glass configurada y protegida",
        description="Debe existir una cuenta de emergencia (break-glass) con acceso administrativo completo, "
                    "protegida con MFA hardware y con uso monitoreado.",
        domain=Domain.D1,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_user"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-01",
        check_ids={
            "aws": ["iam_break_glass_account_exists"],
            "azure": ["iam_emergency_access_accounts"],
            "gcp": ["gcp_iam_break_glass_account"],
        },
        remediation={
            "aws": "Crear usuario IAM dedicado break-glass con MFA hardware. Almacenar credenciales en caja fuerte física. Monitorear uso con CloudTrail.",
            "azure": "Crear 2 cuentas emergency access en Entra ID excluidas de Conditional Access. Asignar Global Admin. Monitorear uso.",
            "gcp": "Crear cuenta Super Admin dedicada con 2FA hardware. Almacenar credenciales offline. Configurar alertas de uso.",
        },
    ),

    # ── RR-IAM-015: API key restrictions ─────────────────────────
    RRRule(
        rule_id="RR-IAM-015",
        name="API keys restringidas por alcance y aplicación",
        description="API keys (GCP) deben estar restringidas a APIs específicas y aplicaciones/IPs autorizadas.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["gcp"],
        resource_types=["api_key"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-02",
        check_ids={
            "gcp": ["gcp_iam_api_key_restricted", "gcp_iam_api_key_rotated"],
        },
        remediation={
            "gcp": "Restringir API keys por API target y application restrictions (HTTP referrers, IP addresses) en Credentials page.",
        },
    ),

    # ── RR-IAM-016: Workload Identity Federation ─────────────────
    RRRule(
        rule_id="RR-IAM-016",
        name="Workload Identity Federation preferida sobre service account keys",
        description="Workloads externos deben usar federación de identidad (WIF en GCP, IRSA en AWS) "
                    "en lugar de long-lived service account keys.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "gcp"],
        resource_types=["service_account", "workload_identity"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-02",
        check_ids={
            "aws": ["iam_irsa_enabled_eks"],
            "gcp": ["gcp_iam_workload_identity_federation"],
        },
        remediation={
            "aws": "Migrar de access keys a IRSA (IAM Roles for Service Accounts) para workloads EKS. Usar Instance Profiles para EC2.",
            "gcp": "Migrar de service account keys a Workload Identity Federation. Configurar WIF pools para CI/CD y workloads externos.",
        },
    ),

    # ── RR-IAM-017: Password policy ──────────────────────────────
    RRRule(
        rule_id="RR-IAM-017",
        name="Política de contraseñas robusta configurada",
        description="La política de contraseñas debe requerir mínimo 14 caracteres, complejidad, "
                    "y prevenir reutilización.",
        domain=Domain.D1,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["password_policy"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-01",
        check_ids={
            "aws": ["iam_password_policy_min_length_14", "iam_password_policy_reuse_prevention",
                     "iam_password_policy_symbol", "iam_password_policy_uppercase",
                     "iam_password_policy_lowercase", "iam_password_policy_number"],
            "azure": ["iam_password_policy_configured"],
            "gcp": ["gcp_iam_password_policy_enforced"],
        },
        remediation={
            "aws": "Configurar IAM Password Policy: min 14 chars, require uppercase/lowercase/numbers/symbols, prevent reuse (24 passwords).",
            "azure": "Configurar Password Protection en Entra ID. Habilitar custom banned passwords y smart lockout.",
            "gcp": "Configurar Password Policy en Admin Console > Security > Password management con requisitos fuertes.",
        },
    ),

    # ── RR-IAM-018: Root account not used for daily operations ───
    RRRule(
        rule_id="RR-IAM-018",
        name="Cuenta root/owner no utilizada para operaciones diarias",
        description="La cuenta root no debe tener access keys activas y no debe ser usada para operaciones regulares.",
        domain=Domain.D1,
        severity=Severity.CRITICAL,
        cloud_providers=["aws"],
        resource_types=["iam_root"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_no_active_access_keys_root", "iam_root_no_recent_usage"],
        },
        remediation={
            "aws": "Eliminar access keys de root: IAM > My Security Credentials > Access keys > Delete. Usar usuarios IAM para operaciones diarias.",
        },
    ),

    # ── RR-IAM-019: IAM users with multiple active keys ──────────
    RRRule(
        rule_id="RR-IAM-019",
        name="Usuarios sin múltiples access keys activas simultáneamente",
        description="Cada usuario IAM debe tener máximo una access key activa para facilitar la auditoría y rotación.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws"],
        resource_types=["iam_access_key"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-02",
        check_ids={
            "aws": ["iam_user_single_active_key"],
        },
        remediation={
            "aws": "Auditar usuarios con 2 keys activas. Desactivar y eliminar la key más antigua. Mantener máximo 1 key activa.",
        },
    ),

    # ── RR-IAM-020: Inline policies avoided ──────────────────────
    RRRule(
        rule_id="RR-IAM-020",
        name="Políticas inline evitadas en favor de managed policies",
        description="Usar managed policies en lugar de inline policies para mejor auditoría, "
                    "reutilización y control centralizado de permisos.",
        domain=Domain.D1,
        severity=Severity.LOW,
        cloud_providers=["aws"],
        resource_types=["iam_policy"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_no_inline_policies"],
        },
        remediation={
            "aws": "Migrar inline policies a managed policies. Usar aws iam list-user-policies para identificar y recrear como managed.",
        },
    ),

    # ── RR-IAM-021: Permission boundaries ────────────────────────
    RRRule(
        rule_id="RR-IAM-021",
        name="Permission boundaries aplicados a roles delegados",
        description="Roles que pueden crear otros roles o usuarios deben tener permission boundaries "
                    "para limitar la escalación de privilegios.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws"],
        resource_types=["iam_role"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_permission_boundaries_applied"],
        },
        remediation={
            "aws": "Crear permission boundary policy que limite permisos máximos. Aplicar a roles de desarrollo y delegados via --permissions-boundary.",
        },
    ),

    # ── RR-IAM-022: Groups for permission assignment ─────────────
    RRRule(
        rule_id="RR-IAM-022",
        name="Permisos asignados mediante grupos, no directamente a usuarios",
        description="Los permisos IAM deben ser asignados a grupos y los usuarios agregados a grupos, "
                    "no asignar políticas directamente a usuarios individuales.",
        domain=Domain.D1,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure"],
        resource_types=["iam_user", "iam_group"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-05",
        check_ids={
            "aws": ["iam_user_no_direct_policies"],
            "azure": ["iam_group_based_assignment"],
        },
        remediation={
            "aws": "Crear IAM Groups por función (admins, developers, readonly). Mover políticas de usuarios a grupos. Agregar usuarios a grupos.",
            "azure": "Usar grupos de seguridad de Entra ID para asignar roles. Evitar asignaciones directas a usuarios individuales.",
        },
    ),

    # ── RR-IAM-023: Inactive users disabled ──────────────────────
    RRRule(
        rule_id="RR-IAM-023",
        name="Usuarios inactivos deshabilitados",
        description="Usuarios sin actividad en >90 días deben ser deshabilitados para reducir "
                    "la superficie de ataque de credenciales abandonadas.",
        domain=Domain.D1,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["iam_user"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-02",
        check_ids={
            "aws": ["iam_unused_credentials_disabled"],
            "azure": ["iam_inactive_users_disabled"],
            "gcp": ["gcp_iam_unused_service_accounts"],
        },
        remediation={
            "aws": "Generar Credential Report. Desactivar console access y keys para usuarios sin actividad >90 días.",
            "azure": "Configurar Access Reviews automáticos en Entra ID para revisar y revocar acceso de usuarios inactivos.",
            "gcp": "Usar IAM Recommender para identificar service accounts inactivas. Desactivar con gcloud iam service-accounts disable.",
        },
    ),

    # ── RR-IAM-024: Support role access restricted ───────────────
    RRRule(
        rule_id="RR-IAM-024",
        name="Acceso de soporte del proveedor restringido",
        description="El acceso de soporte del proveedor cloud (AWS Support, Azure Support) "
                    "debe estar controlado y limitado a casos específicos.",
        domain=Domain.D1,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["support_access"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-06",
        check_ids={
            "aws": ["iam_support_role_configured"],
            "azure": ["iam_customer_lockbox_enabled"],
            "gcp": ["gcp_iam_access_transparency"],
        },
        remediation={
            "aws": "Crear rol IAM dedicado para soporte con políticas AWSSupportAccess. No usar root para tickets de soporte.",
            "azure": "Habilitar Customer Lockbox para requerir aprobación antes de que soporte de Microsoft acceda a datos.",
            "gcp": "Habilitar Access Transparency logging. Configurar Access Approval para requerir aprobación explícita.",
        },
    ),

    # ── RR-IAM-025: Security contacts configured ─────────────────
    RRRule(
        rule_id="RR-IAM-025",
        name="Contactos de seguridad configurados en la cuenta",
        description="La cuenta cloud debe tener contactos de seguridad configurados para recibir "
                    "notificaciones de incidentes de seguridad del proveedor.",
        domain=Domain.D1,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["account_contact"],
        nist_category="PR.AA",
        nist_subcategory="PR.AA-06",
        check_ids={
            "aws": ["iam_security_contact_configured"],
            "azure": ["iam_security_contact_email"],
            "gcp": ["gcp_iam_essential_contacts"],
        },
        remediation={
            "aws": "Configurar contactos de seguridad en AWS Account > Alternate contacts > Security contact.",
            "azure": "Configurar email de contacto de seguridad en Defender for Cloud > Environment settings > Email notifications.",
            "gcp": "Configurar Essential Contacts para la categoría SECURITY en la organización/proyecto.",
        },
    ),
]
