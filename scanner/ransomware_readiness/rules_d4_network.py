"""Domain D4: Network Segmentation — 15 rules (weight 15%).

Maps to NIST CSF 2.0 PR.IR (Incident Response / Network Resilience).
"""

from scanner.ransomware_readiness.framework import RRRule, Domain, Severity

D4_RULES: list[RRRule] = [
    RRRule(
        rule_id="RR-NET-001",
        name="No hay security groups/NSGs con 0.0.0.0/0 en puertos sensibles",
        description="Ningún SG, NSG o firewall rule debe permitir ingress desde 0.0.0.0/0 o ::/0 "
                    "en puertos RDP (3389), SSH (22), SMB (445), WinRM (5985/5986).",
        domain=Domain.D4,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["security_group", "nsg", "firewall_rule"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["ec2_sg_no_public_ssh", "ec2_sg_no_public_rdp", "ec2_sg_no_public_smb"],
            "azure": ["network_nsg_no_public_ssh", "network_nsg_no_public_rdp"],
            "gcp": ["gcp_network_no_public_ssh", "gcp_network_no_public_rdp"],
        },
        remediation={
            "aws": "Eliminar reglas inbound con 0.0.0.0/0 en puertos 22,3389,445,5985-5986. Usar bastion host o SSM Session Manager.",
            "azure": "Eliminar reglas NSG allow inbound desde Any en puertos de gestión. Usar Azure Bastion para acceso.",
            "gcp": "Eliminar firewall rules con 0.0.0.0/0 en puertos sensibles. Usar IAP (Identity-Aware Proxy) para acceso.",
        },
    ),

    RRRule(
        rule_id="RR-NET-002",
        name="Principio deny-by-default en reglas de red",
        description="Security groups no deben tener reglas allow-all. NACLs/NSGs deben tener deny rules apropiadas.",
        domain=Domain.D4,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["security_group", "nacl", "nsg"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["ec2_sg_no_allow_all_ingress", "ec2_sg_no_allow_all_egress"],
            "azure": ["network_nsg_deny_by_default"],
            "gcp": ["gcp_network_deny_by_default"],
        },
        remediation={
            "aws": "Eliminar reglas SG con all traffic allowed (0.0.0.0/0 all ports). Aplicar reglas específicas por servicio y puerto.",
            "azure": "Configurar NSG default rules deny. Agregar solo allow rules específicas necesarias.",
            "gcp": "Configurar firewall rules con prioridad deny-all al final. Solo permitir tráfico específico necesario.",
        },
    ),

    RRRule(
        rule_id="RR-NET-003",
        name="Servicios de almacenamiento no expuestos públicamente",
        description="S3 buckets, Azure Blob containers, GCS buckets no deben tener public access. "
                    "Block public access debe estar configurado a nivel de cuenta.",
        domain=Domain.D4,
        severity=Severity.CRITICAL,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["s3_bucket", "blob_container", "cloud_storage"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["s3_bucket_no_public_access", "s3_account_level_public_access_block"],
            "azure": ["storage_no_public_access", "storage_no_anonymous_access"],
            "gcp": ["gcp_storage_no_public_access", "gcp_storage_uniform_access"],
        },
        remediation={
            "aws": "Habilitar S3 Block Public Access a nivel de cuenta: aws s3control put-public-access-block. Verificar bucket policies.",
            "azure": "Deshabilitar Blob anonymous access en Storage Account. Configurar firewall rules para restringir red access.",
            "gcp": "Habilitar Uniform bucket-level access. Eliminar allUsers y allAuthenticatedUsers de IAM bindings.",
        },
    ),

    RRRule(
        rule_id="RR-NET-004",
        name="Uso de Private Endpoints para servicios PaaS críticos",
        description="Servicios PaaS críticos (databases, storage, key management) deben accederse "
                    "via private endpoint en lugar de endpoint público.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["vpc_endpoint", "private_endpoint", "private_service_connect"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["vpc_endpoint_s3", "vpc_endpoint_dynamodb", "rds_no_public_access"],
            "azure": ["storage_private_endpoint", "sql_private_endpoint"],
            "gcp": ["gcp_sql_no_public_ip", "gcp_private_service_connect"],
        },
        remediation={
            "aws": "Crear VPC Endpoints para S3, DynamoDB, KMS. Deshabilitar public access en RDS. Usar PrivateLink para otros servicios.",
            "azure": "Crear Private Endpoints para Storage, SQL, Key Vault. Deshabilitar public access en estos servicios.",
            "gcp": "Configurar Private Google Access. Usar Private Service Connect. Deshabilitar public IPs en Cloud SQL.",
        },
    ),

    RRRule(
        rule_id="RR-NET-005",
        name="VPC Flow Logs habilitados",
        description="VPC Flow Logs deben estar habilitados en todas las VPCs/subnets para "
                    "detectar tráfico lateral anómalo durante un ataque.",
        domain=Domain.D4,
        severity=Severity.HIGH,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["vpc", "subnet", "vnet"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["vpc_flow_logs_enabled"],
            "azure": ["network_nsg_flow_logs_enabled"],
            "gcp": ["gcp_network_flow_logs_enabled"],
        },
        remediation={
            "aws": "Habilitar VPC Flow Logs para todas las VPCs: aws ec2 create-flow-logs. Enviar a CloudWatch Logs o S3.",
            "azure": "Habilitar NSG Flow Logs en Network Watcher. Configurar retención y envío a Log Analytics.",
            "gcp": "Habilitar VPC Flow Logs en cada subnet: gcloud compute networks subnets update --enable-flow-logs.",
        },
    ),

    RRRule(
        rule_id="RR-NET-006",
        name="WAF configurado en endpoints públicos",
        description="Endpoints web públicos deben estar protegidos por WAF para prevenir "
                    "exploits web que pueden ser vector inicial de ransomware.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["alb", "cloudfront", "application_gateway", "cloud_armor"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-02",
        check_ids={
            "aws": ["waf_web_acl_associated", "cloudfront_waf_enabled"],
            "azure": ["waf_application_gateway_enabled"],
            "gcp": ["gcp_cloud_armor_enabled"],
        },
        remediation={
            "aws": "Asociar AWS WAF Web ACL a ALBs y CloudFront distributions. Usar managed rule groups (AWSManagedRulesCommonRuleSet).",
            "azure": "Configurar Azure WAF en Application Gateway. Usar OWASP rule set. Habilitar bot protection.",
            "gcp": "Configurar Cloud Armor security policies. Asociar a backend services de load balancers.",
        },
    ),

    RRRule(
        rule_id="RR-NET-007",
        name="Segmentación entre ambientes (dev/staging/prod)",
        description="Los ambientes de desarrollo, staging y producción deben estar segmentados "
                    "en VPCs/VNets separadas para limitar blast radius.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["vpc", "vnet"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["vpc_environment_segmentation"],
            "azure": ["network_environment_segmentation"],
            "gcp": ["gcp_network_environment_segmentation"],
        },
        is_composite=True,
        remediation={
            "aws": "Crear VPCs separadas por ambiente (dev, staging, prod). Usar Transit Gateway para routing controlado entre ambientes.",
            "azure": "Crear VNets separadas por ambiente. Usar VNet Peering con NSG rules restrictivas entre ambientes.",
            "gcp": "Crear VPC networks o proyectos separados por ambiente. Usar VPC peering o Shared VPC con firewall rules.",
        },
    ),

    RRRule(
        rule_id="RR-NET-008",
        name="Egress filtering configurado",
        description="El tráfico de salida debe estar filtrado para prevenir exfiltración de datos "
                    "y comunicación con servidores C2 de ransomware.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["security_group", "nsg", "firewall_rule"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["ec2_sg_restricted_egress"],
            "azure": ["network_nsg_restricted_egress"],
            "gcp": ["gcp_network_restricted_egress"],
        },
        remediation={
            "aws": "Configurar egress rules restrictivas en SGs. Usar AWS Network Firewall para inspección de egress. Implementar proxy para internet access.",
            "azure": "Configurar Azure Firewall con egress filtering. Usar FQDN filtering para limitar destinos permitidos.",
            "gcp": "Configurar egress firewall rules. Usar Cloud NAT con logging. Implementar proxy para internet access.",
        },
    ),

    RRRule(
        rule_id="RR-NET-009",
        name="DNS security configurado",
        description="DNS resolution debe estar protegida contra DNS tunneling y exfiltración "
                    "via DNS queries maliciosos.",
        domain=Domain.D4,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["dns_resolver", "dns_firewall"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-02",
        check_ids={
            "aws": ["route53_resolver_dnssec", "route53_dns_firewall"],
            "azure": ["dns_security_configured"],
            "gcp": ["gcp_dns_security_configured"],
        },
        remediation={
            "aws": "Habilitar Route 53 Resolver DNS Firewall. Configurar DNSSEC en hosted zones públicas.",
            "azure": "Configurar Azure DNS Private Resolver. Habilitar DNSSEC para zones públicas.",
            "gcp": "Habilitar DNSSEC en Cloud DNS. Configurar DNS policies para logging y forwarding seguro.",
        },
    ),

    RRRule(
        rule_id="RR-NET-010",
        name="Load balancers con configuración segura",
        description="Load balancers deben usar TLS 1.2+, security policies actualizadas, "
                    "y access logs habilitados.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["alb", "nlb", "application_gateway", "load_balancer"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-02",
        check_ids={
            "aws": ["elb_tls_12_minimum", "elb_access_logs_enabled"],
            "azure": ["app_gateway_tls_policy"],
            "gcp": ["gcp_network_ssl_policy", "gcp_logging_lb_logging"],
        },
        remediation={
            "aws": "Configurar TLS 1.2 minimum en ALB/NLB listeners. Habilitar access logs. Usar security policy ELBSecurityPolicy-TLS13.",
            "azure": "Configurar TLS 1.2 minimum policy en Application Gateway. Habilitar diagnostic logs.",
            "gcp": "Configurar SSL policy con TLS 1.2 minimum. Habilitar logging en backend services.",
        },
    ),

    RRRule(
        rule_id="RR-NET-011",
        name="API Gateway con autenticación configurada",
        description="API Gateways deben tener autenticación habilitada y throttling configurado "
                    "para prevenir abuso de APIs expuestas.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["api_gateway"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-02",
        check_ids={
            "aws": ["apigateway_auth_configured", "apigateway_throttling_enabled"],
            "azure": ["apim_auth_configured"],
            "gcp": ["gcp_api_gateway_auth_configured"],
        },
        remediation={
            "aws": "Configurar authorization (API Key, IAM, Cognito, Lambda authorizer) en API Gateway. Habilitar throttling y WAF.",
            "azure": "Configurar authentication policies en API Management. Habilitar rate limiting y OAuth2 validation.",
            "gcp": "Configurar API Gateway con authentication (API Key, Firebase Auth, Service Account). Habilitar quota policies.",
        },
    ),

    RRRule(
        rule_id="RR-NET-012",
        name="Inventario de IPs públicas controlado",
        description="Las IPs públicas asignadas deben ser inventariadas y justificadas. "
                    "IPs públicas innecesarias amplían la superficie de ataque.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["elastic_ip", "public_ip", "external_ip"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["ec2_public_ip_inventory", "ec2_unused_eips"],
            "azure": ["network_public_ip_inventory"],
            "gcp": ["gcp_compute_public_ip_inventory"],
        },
        remediation={
            "aws": "Auditar Elastic IPs. Liberar EIPs no asociadas. Revisar EC2 instances con public IP directa y migrar a ALB/NAT.",
            "azure": "Auditar Public IP addresses. Disociar y eliminar IPs públicas no necesarias. Usar Private Endpoints.",
            "gcp": "Auditar external IP addresses. Eliminar IPs estáticas no utilizadas. Usar Cloud NAT en lugar de IPs públicas directas.",
        },
    ),

    RRRule(
        rule_id="RR-NET-013",
        name="Security groups no utilizados eliminados",
        description="Security groups sin recursos asociados deben ser eliminados para reducir "
                    "configuraciones obsoletas y potenciales errores de asignación.",
        domain=Domain.D4,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["security_group", "nsg"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["ec2_unused_security_groups"],
            "azure": ["network_unused_nsgs"],
            "gcp": ["gcp_network_unused_firewall_rules"],
        },
        remediation={
            "aws": "Identificar SGs sin ENIs asociadas. Eliminar SGs no utilizados (excepto default SG de cada VPC).",
            "azure": "Identificar NSGs sin NICs o subnets asociadas. Eliminar NSGs no utilizados.",
            "gcp": "Identificar firewall rules sin instancias target. Eliminar reglas obsoletas.",
        },
    ),

    RRRule(
        rule_id="RR-NET-014",
        name="Network peering/VPN configurado con controles de seguridad",
        description="Peering connections y VPNs deben tener route tables restrictivas y "
                    "no permitir transitive routing no controlado.",
        domain=Domain.D4,
        severity=Severity.MEDIUM,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["vpc_peering", "vnet_peering", "vpn_gateway"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["vpc_peering_route_tables_restrictive"],
            "azure": ["network_peering_controlled"],
            "gcp": ["gcp_network_peering_controlled"],
        },
        remediation={
            "aws": "Revisar VPC peering connections. Configurar route tables para limitar tráfico a subnets específicas.",
            "azure": "Revisar VNet peering. Deshabilitar 'Allow forwarded traffic' donde no sea necesario.",
            "gcp": "Revisar VPC peering. Configurar export/import custom routes selectivamente.",
        },
    ),

    RRRule(
        rule_id="RR-NET-015",
        name="No hay default VPC/network en uso",
        description="La VPC/network default no debe ser utilizada para workloads. "
                    "Debe usarse VPCs custom con diseño de red seguro.",
        domain=Domain.D4,
        severity=Severity.LOW,
        cloud_providers=["aws", "azure", "gcp"],
        resource_types=["vpc", "network"],
        nist_category="PR.IR",
        nist_subcategory="PR.IR-01",
        check_ids={
            "aws": ["vpc_default_not_used"],
            "azure": ["network_custom_vnet_used"],
            "gcp": ["gcp_network_no_default_network"],
        },
        remediation={
            "aws": "Migrar workloads de default VPC a custom VPCs. Eliminar default VPC en regiones no utilizadas.",
            "azure": "Crear VNets custom con address space planificado. No usar la VNet creada por defecto.",
            "gcp": "Eliminar default network. Crear VPC networks custom con subnets planificadas.",
        },
    ),
]
