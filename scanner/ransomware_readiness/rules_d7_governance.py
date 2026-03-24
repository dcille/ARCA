"""Domain D7: Awareness & Governance — 5 rules (weight 5%).

Maps to NIST CSF 2.0 PR.AT (Awareness & Training) + GV (Governance).
These rules require manual operator input — they are not auto-scanned.
"""

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity

D7_RULES: list[RRRule] = [
    RRRule(
        rule_id="RR-GOV-001",
        name="Plan de respuesta a ransomware documentado",
        description="Debe existir un plan de respuesta a incidentes específico para ransomware "
                    "que incluya procedimientos de contención, erradicación y recuperación.",
        domain=Domain.D7,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="GV",
        nist_subcategory="GV.RM-04",
        check_ids={"aws": [], "azure": [], "gcp": []},
        is_manual=True,
        remediation={
            "aws": "Crear ransomware response plan basado en NISTIR 8374. Incluir: detección, contención de cuentas, preservación forense, restauración de backups, comunicación.",
            "azure": "Crear ransomware response plan específico para Azure. Incluir procedimientos de aislamiento de suscripciones y restauración.",
            "gcp": "Crear ransomware response plan específico para GCP. Incluir procedimientos de aislamiento de proyectos y restauración.",
        },
        ransomware_context="Un plan de respuesta específico para ransomware reduce drásticamente el tiempo de recuperación. Sin plan, las decisiones se toman bajo presión, aumentando errores y daños.",
    ),

    RRRule(
        rule_id="RR-GOV-002",
        name="Último tabletop exercise de ransomware realizado (<6 meses)",
        description="Se debe realizar un ejercicio de simulación (tabletop) de ataque ransomware "
                    "al menos cada 6 meses para validar el plan y la capacidad de respuesta.",
        domain=Domain.D7,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="PR.AT",
        nist_subcategory="PR.AT-01",
        check_ids={"aws": [], "azure": [], "gcp": []},
        is_manual=True,
        remediation={
            "aws": "Programar tabletop exercise trimestral. Incluir escenarios: compromiso de credenciales, cifrado de S3/EBS, eliminación de backups.",
            "azure": "Programar tabletop exercise trimestral con escenarios Azure-specific: compromiso de Entra ID, cifrado de Storage.",
            "gcp": "Programar tabletop exercise trimestral con escenarios GCP-specific: compromiso de service account, cifrado de Cloud Storage.",
        },
        ransomware_context="Los tabletop exercises validan que el equipo sabe ejecutar el plan de respuesta a ransomware. Sin práctica, el plan puede fallar cuando más se necesita.",
    ),

    RRRule(
        rule_id="RR-GOV-003",
        name="Security awareness training completado por el equipo",
        description="El personal técnico y no técnico debe haber completado training de security awareness "
                    "que incluya identificación de phishing y ransomware en los últimos 12 meses.",
        domain=Domain.D7,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="PR.AT",
        nist_subcategory="PR.AT-01",
        check_ids={"aws": [], "azure": [], "gcp": []},
        is_manual=True,
        remediation={
            "aws": "Implementar programa de security awareness training anual. Incluir módulos de phishing, ransomware, social engineering. Verificar completion >90%.",
            "azure": "Implementar security training usando Microsoft Security Awareness toolkit o plataforma equivalente.",
            "gcp": "Implementar security training que cubra amenazas cloud-specific. Incluir phishing simulations.",
        },
        ransomware_context="El phishing es el vector de entrada #1 para ransomware. Security awareness training reduce significativamente la probabilidad de que un empleado caiga en phishing.",
    ),

    RRRule(
        rule_id="RR-GOV-004",
        name="Roles y responsabilidades de IR definidos",
        description="Los roles y responsabilidades para respuesta a incidentes de ransomware "
                    "deben estar claramente definidos con contactos actualizados.",
        domain=Domain.D7,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="GV",
        nist_subcategory="GV.RR-01",
        check_ids={"aws": [], "azure": [], "gcp": []},
        is_manual=True,
        remediation={
            "aws": "Documentar RACI matrix para IR. Definir: Incident Commander, Technical Lead, Communications Lead, Legal, Executive sponsor.",
            "azure": "Documentar roles IR con contactos. Integrar con Azure IR contacts en Defender for Cloud.",
            "gcp": "Documentar roles IR con contactos. Configurar Essential Contacts para categoría SECURITY.",
        },
        ransomware_context="Durante un ataque de ransomware, cada minuto cuenta. Si los roles no están claros, la respuesta se retrasa y el atacante tiene más tiempo para causar daño.",
    ),

    RRRule(
        rule_id="RR-GOV-005",
        name="Plan de comunicación para incidentes de ransomware",
        description="Debe existir un plan de comunicación pre-aprobado para incidentes de ransomware "
                    "que incluya templates para stakeholders internos, clientes, reguladores y medios.",
        domain=Domain.D7,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["documentation"],
        nist_category="GV",
        nist_subcategory="GV.RR-02",
        check_ids={"aws": [], "azure": [], "gcp": []},
        is_manual=True,
        remediation={
            "aws": "Crear plan de comunicación con templates: notificación interna, notificación a clientes, comunicado público, notificación a reguladores.",
            "azure": "Crear communication plan con escalation matrix. Preparar templates pre-aprobados por legal.",
            "gcp": "Crear communication plan con templates y lista de distribución. Incluir procedimiento de notificación a Google si aplica.",
        },
        ransomware_context="La comunicación descoordinada durante un ataque de ransomware puede causar más daño reputacional que el propio ataque. Templates pre-aprobados aceleran la respuesta.",
    ),
]
