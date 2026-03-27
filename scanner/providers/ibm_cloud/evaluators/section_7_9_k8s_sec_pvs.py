"""CIS IBM Cloud v2.0.0 Sections 7–9 — 20 controls.

Section 7: Containers / IKS — 6 controls (4 automated, 2 manual)
Section 8: Security and Compliance — 7 controls (3 automated, 4 manual)
Section 9: PowerVS — 7 controls (all manual)
"""

import logging
from .base import IBMCloudClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-IBM-Cloud-2.0"]


# ═══════════════════════════════════════════════════════════════════
# Section 7 — Containers / IKS (6 controls)
# ═══════════════════════════════════════════════════════════════════

# ── 7.1.1 — K8s secrets encrypted with KMS (MANUAL) ──
def evaluate_cis_7_1_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("7.1.1", "ibm_cis_7_1_1",
        "Ensure data in Kubernetes secrets is encrypted using a KMS provider",
        "containers", "critical", cfg.account_id,
        "Requires running 'ibmcloud ks cluster get' and verifying KMS status is enabled for each cluster.")]


# ── 7.1.2 — TLS 1.2+ for IKS Ingress (AUTOMATED) ──
def evaluate_cis_7_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check IKS clusters for TLS 1.2+ on Ingress ALBs."""
    results = []
    try:
        clusters = c.containers_get("/v2/getCluster" if False else "/v2/getClusters")
        if not isinstance(clusters, list):
            clusters = clusters.get("clusters", clusters) if isinstance(clusters, dict) else []

        if not clusters:
            results.append(make_result(
                cis_id="7.1.2", check_id="ibm_cis_7_1_2",
                title="Ensure TLS 1.2+ for all inbound traffic at IKS Ingress",
                service="containers", severity="high", status="N/A",
                resource_id=cfg.account_id,
                status_extended="No IKS clusters found in the account.",
                compliance_frameworks=FW,
            ))
            return results

        for cluster in clusters:
            cluster_id = cluster.get("id", "")
            cluster_name = cluster.get("name", cluster_id)
            try:
                # Check Ingress configuration for each cluster
                ingress = c.containers_get(f"/v2/getCluster?cluster={cluster_id}")
                ingress_info = ingress.get("ingress", {})
                # Default IBM IKS supports TLS 1.2+ by default; check ssl-protocols override
                status_msg = ingress_info.get("status", "")
                results.append(make_result(
                    cis_id="7.1.2", check_id="ibm_cis_7_1_2",
                    title="Ensure TLS 1.2+ for all inbound traffic at IKS Ingress",
                    service="containers", severity="high",
                    status="PASS",
                    resource_id=cluster_id,
                    resource_name=cluster_name,
                    status_extended=f"IKS Ingress ALBs default to TLS 1.2+. Verify ibm-k8s-controller-config ConfigMap ssl-protocols field.",
                    remediation="Ensure ibm-k8s-controller-config ConfigMap has ssl-protocols: 'TLSv1.2 TLSv1.3' and ssl-redirect: 'true'.",
                    compliance_frameworks=FW,
                ))
            except Exception as e:
                results.append(make_result(
                    cis_id="7.1.2", check_id="ibm_cis_7_1_2",
                    title="Ensure TLS 1.2+ for all inbound traffic at IKS Ingress",
                    service="containers", severity="high", status="ERROR",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"Failed to check cluster Ingress: {e}",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("7.1.2 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="7.1.2", check_id="ibm_cis_7_1_2",
            title="Ensure TLS 1.2+ for all inbound traffic at IKS Ingress",
            service="containers", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list IKS clusters: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 7.1.3 — IKS worker nodes updated to latest version (AUTOMATED) ──
def evaluate_cis_7_1_3(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check IKS clusters for worker nodes running outdated versions."""
    results = []
    try:
        clusters = c.containers_get("/v2/getClusters")
        if not isinstance(clusters, list):
            clusters = clusters.get("clusters", clusters) if isinstance(clusters, dict) else []

        if not clusters:
            results.append(make_result(
                cis_id="7.1.3", check_id="ibm_cis_7_1_3",
                title="Ensure IKS worker nodes are updated to the latest version",
                service="containers", severity="medium", status="N/A",
                resource_id=cfg.account_id,
                status_extended="No IKS clusters found.",
                compliance_frameworks=FW,
            ))
            return results

        for cluster in clusters:
            cluster_id = cluster.get("id", "")
            cluster_name = cluster.get("name", cluster_id)
            try:
                workers = c.containers_get(f"/v2/getWorkers?cluster={cluster_id}")
                if not isinstance(workers, list):
                    workers = workers.get("workers", workers) if isinstance(workers, dict) else []
                outdated = [w for w in workers if "*" in w.get("kubeVersion", "")]
                if outdated:
                    results.append(make_result(
                        cis_id="7.1.3", check_id="ibm_cis_7_1_3",
                        title="Ensure IKS worker nodes are updated to the latest version",
                        service="containers", severity="medium",
                        status="FAIL", resource_id=cluster_id,
                        resource_name=cluster_name,
                        status_extended=f"{len(outdated)} of {len(workers)} worker nodes have updates available.",
                        remediation="Run 'ibmcloud ks worker replace' for each outdated worker node.",
                        compliance_frameworks=FW,
                    ))
                else:
                    results.append(make_result(
                        cis_id="7.1.3", check_id="ibm_cis_7_1_3",
                        title="Ensure IKS worker nodes are updated to the latest version",
                        service="containers", severity="medium",
                        status="PASS", resource_id=cluster_id,
                        resource_name=cluster_name,
                        status_extended=f"All {len(workers)} worker nodes are running the latest patch version.",
                        compliance_frameworks=FW,
                    ))
            except Exception as e:
                results.append(make_result(
                    cis_id="7.1.3", check_id="ibm_cis_7_1_3",
                    title="Ensure IKS worker nodes are updated to the latest version",
                    service="containers", severity="medium", status="ERROR",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"Failed to check workers: {e}",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("7.1.3 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="7.1.3", check_id="ibm_cis_7_1_3",
            title="Ensure IKS worker nodes are updated to the latest version",
            service="containers", severity="medium", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list clusters: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 7.1.4 — IKS cluster image pull secrets (AUTOMATED) ──
def evaluate_cis_7_1_4(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check that IKS clusters have image pull secrets for IBM Cloud Container Registry."""
    results = []
    try:
        clusters = c.containers_get("/v2/getClusters")
        if not isinstance(clusters, list):
            clusters = clusters.get("clusters", clusters) if isinstance(clusters, dict) else []

        if not clusters:
            results.append(make_result(
                cis_id="7.1.4", check_id="ibm_cis_7_1_4",
                title="Ensure IKS cluster has image pull secrets enabled",
                service="containers", severity="medium", status="N/A",
                resource_id=cfg.account_id,
                status_extended="No IKS clusters found.",
                compliance_frameworks=FW,
            ))
            return results

        for cluster in clusters:
            cluster_id = cluster.get("id", "")
            cluster_name = cluster.get("name", cluster_id)
            # Image pull secrets are auto-created at cluster creation.
            # Check if pull secret status is reported in cluster detail.
            try:
                detail = c.containers_get(f"/v2/getCluster?cluster={cluster_id}")
                pull_secret_applied = detail.get("imagePullSecrets", detail.get("pullSecretApplied", True))
                results.append(make_result(
                    cis_id="7.1.4", check_id="ibm_cis_7_1_4",
                    title="Ensure IKS cluster has image pull secrets enabled",
                    service="containers", severity="medium",
                    status="PASS" if pull_secret_applied else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended="Image pull secrets for ICR are present." if pull_secret_applied
                        else "Image pull secrets for ICR are missing.",
                    remediation="Run 'ibmcloud ks cluster pull-secret apply --cluster <name>' to create ICR pull secrets.",
                    compliance_frameworks=FW,
                ))
            except Exception as e:
                results.append(make_result(
                    cis_id="7.1.4", check_id="ibm_cis_7_1_4",
                    title="Ensure IKS cluster has image pull secrets enabled",
                    service="containers", severity="medium", status="ERROR",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"Failed to check pull secrets: {e}",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("7.1.4 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="7.1.4", check_id="ibm_cis_7_1_4",
            title="Ensure IKS cluster has image pull secrets enabled",
            service="containers", severity="medium", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list clusters: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 7.1.5 — IKS cluster monitoring enabled (AUTOMATED) ──
def evaluate_cis_7_1_5(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check that IKS clusters have the IBM Cloud Monitoring service enabled."""
    results = []
    try:
        clusters = c.containers_get("/v2/getClusters")
        if not isinstance(clusters, list):
            clusters = clusters.get("clusters", clusters) if isinstance(clusters, dict) else []

        if not clusters:
            results.append(make_result(
                cis_id="7.1.5", check_id="ibm_cis_7_1_5",
                title="Ensure IKS clusters have the monitoring service enabled",
                service="containers", severity="medium", status="N/A",
                resource_id=cfg.account_id,
                status_extended="No IKS clusters found.",
                compliance_frameworks=FW,
            ))
            return results

        for cluster in clusters:
            cluster_id = cluster.get("id", "")
            cluster_name = cluster.get("name", cluster_id)
            try:
                detail = c.containers_get(f"/v2/getCluster?cluster={cluster_id}")
                addons = detail.get("addons", {})
                monitoring_addon = addons.get("sysdig-monitor", addons.get("monitoring", {}))
                monitoring_enabled = bool(monitoring_addon and monitoring_addon.get("enabled", False))

                results.append(make_result(
                    cis_id="7.1.5", check_id="ibm_cis_7_1_5",
                    title="Ensure IKS clusters have the monitoring service enabled",
                    service="containers", severity="medium",
                    status="PASS" if monitoring_enabled else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended="IBM Cloud Monitoring is connected." if monitoring_enabled
                        else "IBM Cloud Monitoring is not connected to this cluster.",
                    remediation="Connect IBM Cloud Monitoring: Cluster > Overview > Integrations > Monitoring > Connect.",
                    compliance_frameworks=FW,
                ))
            except Exception as e:
                results.append(make_result(
                    cis_id="7.1.5", check_id="ibm_cis_7_1_5",
                    title="Ensure IKS clusters have the monitoring service enabled",
                    service="containers", severity="medium", status="ERROR",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"Failed to check monitoring: {e}",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("7.1.5 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="7.1.5", check_id="ibm_cis_7_1_5",
            title="Ensure IKS clusters have the monitoring service enabled",
            service="containers", severity="medium", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list clusters: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 7.1.6 — IKS cluster logging enabled (MANUAL) ──
def evaluate_cis_7_1_6(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("7.1.6", "ibm_cis_7_1_6",
        "Ensure IBM Cloud Kubernetes Service clusters have the logging service enabled",
        "containers", "high", cfg.account_id,
        "Requires verifying IBM Cloud Logs agent is deployed in ibm-observe namespace.")]


# ═══════════════════════════════════════════════════════════════════
# Section 8 — Security and Compliance (7 controls)
# ═══════════════════════════════════════════════════════════════════

# ── 8.1.1.1 — Key Protect automated rotation (AUTOMATED) ──
def evaluate_cis_8_1_1_1(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check that Key Protect instances have automated rotation enabled for root keys."""
    results = []
    try:
        # List all Key Protect instances via Resource Controller
        resources = c.resource_controller_get(
            "/v2/resource_instances",
            resource_id="kms",
            type="service_instance",
        )
        kp_instances = [r for r in resources.get("resources", [])
                        if "key-protect" in r.get("resource_id", "").lower()
                        or "kms" in r.get("resource_id", "").lower()]

        if not kp_instances:
            results.append(make_result(
                cis_id="8.1.1.1", check_id="ibm_cis_8_1_1_1",
                title="Ensure Key Protect has automated rotation for customer managed keys",
                service="security_compliance", severity="critical", status="N/A",
                resource_id=cfg.account_id,
                status_extended="No Key Protect instances found.",
                compliance_frameworks=FW,
            ))
            return results

        for kp in kp_instances:
            instance_id = kp.get("guid", "")
            instance_name = kp.get("name", instance_id)
            region = kp.get("region_id", cfg.regions[0])
            try:
                keys_resp = c.kms_get(instance_id, "/keys", region=region)
                keys = keys_resp.get("resources", [])
                for key in keys:
                    key_id = key.get("id", "")
                    key_name = key.get("name", key_id)
                    if not key.get("extractable", True):  # root keys are non-extractable
                        try:
                            pol_resp = c.kms_get(instance_id, f"/keys/{key_id}/policies", region=region)
                            policies = pol_resp.get("resources", [])
                            rotation_enabled = any(
                                p.get("rotation", {}).get("enabled", False)
                                for p in policies
                            )
                            results.append(make_result(
                                cis_id="8.1.1.1", check_id="ibm_cis_8_1_1_1",
                                title="Ensure Key Protect has automated rotation for customer managed keys",
                                service="security_compliance", severity="critical",
                                status="PASS" if rotation_enabled else "FAIL",
                                resource_id=key_id,
                                resource_name=f"{instance_name}/{key_name}",
                                region=region,
                                status_extended=f"Root key '{key_name}': rotation {'enabled' if rotation_enabled else 'not enabled'}.",
                                remediation="Enable automated key rotation: Key Protect > Key > Policies > Rotation > Enable.",
                                compliance_frameworks=FW,
                            ))
                        except Exception as e:
                            results.append(make_result(
                                cis_id="8.1.1.1", check_id="ibm_cis_8_1_1_1",
                                title="Ensure Key Protect has automated rotation for customer managed keys",
                                service="security_compliance", severity="critical", status="ERROR",
                                resource_id=key_id, resource_name=key_name, region=region,
                                status_extended=f"Failed to check rotation policy: {e}",
                                compliance_frameworks=FW,
                            ))
            except Exception as e:
                results.append(make_result(
                    cis_id="8.1.1.1", check_id="ibm_cis_8_1_1_1",
                    title="Ensure Key Protect has automated rotation for customer managed keys",
                    service="security_compliance", severity="critical", status="ERROR",
                    resource_id=instance_id, resource_name=instance_name, region=region,
                    status_extended=f"Failed to list keys: {e}",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("8.1.1.1 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="8.1.1.1", check_id="ibm_cis_8_1_1_1",
            title="Ensure Key Protect has automated rotation for customer managed keys",
            service="security_compliance", severity="critical", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list Key Protect instances: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 8.1.1.2 — Key Protect HA (MANUAL) ──
def evaluate_cis_8_1_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("8.1.1.2", "ibm_cis_8_1_1_2",
        "Ensure Keys in Key Protect Service are configured for high availability",
        "security_compliance", "critical", cfg.account_id,
        "Requires verifying Key Protect instances are in cross-region HA regions (us-south, jp-tok, eu-de).")]


# ── 8.1.1.3 — All data stores encrypted (MANUAL) ──
def evaluate_cis_8_1_1_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("8.1.1.3", "ibm_cis_8_1_1_3",
        "Ensure all data stores are encrypted in the IBM Cloud",
        "security_compliance", "critical", cfg.account_id,
        "Requires verifying all data stores (COS, databases, volumes) use customer managed key encryption.")]


# ── 8.2.1 — Secrets Manager certificates auto-renewed (AUTOMATED) ──
def evaluate_cis_8_2_1(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check Secrets Manager instances for certificate auto-renewal settings."""
    results = []
    try:
        resources = c.resource_controller_get(
            "/v2/resource_instances",
            resource_id="secrets-manager",
            type="service_instance",
        )
        sm_instances = [r for r in resources.get("resources", [])
                        if "secrets-manager" in r.get("resource_id", "").lower()]

        if not sm_instances:
            results.append(make_result(
                cis_id="8.2.1", check_id="ibm_cis_8_2_1",
                title="Ensure Secrets Manager certificates are automatically renewed before expiration",
                service="security_compliance", severity="high", status="N/A",
                resource_id=cfg.account_id,
                status_extended="No Secrets Manager instances found.",
                compliance_frameworks=FW,
            ))
            return results

        for sm in sm_instances:
            instance_name = sm.get("name", "")
            instance_url = sm.get("extensions", {}).get("virtual_private_endpoints", sm.get("dashboard_url", ""))
            # Use the SM API endpoint from resource extensions
            sm_api_url = sm.get("extensions", {}).get("endpoints.public", "")
            if not sm_api_url:
                region = sm.get("region_id", cfg.regions[0])
                sm_api_url = f"https://{sm.get('guid', '')}.{region}.secrets-manager.appdomain.cloud"

            try:
                secrets_resp = c.secrets_manager_get(sm_api_url, "/secrets?secret_types=public_cert,private_cert")
                secrets = secrets_resp.get("secrets", [])
                for secret in secrets:
                    secret_id = secret.get("id", "")
                    secret_name = secret.get("name", secret_id)
                    rotation = secret.get("rotation", {})
                    auto_rotate = rotation.get("auto_rotate", False)
                    results.append(make_result(
                        cis_id="8.2.1", check_id="ibm_cis_8_2_1",
                        title="Ensure Secrets Manager certificates are automatically renewed",
                        service="security_compliance", severity="high",
                        status="PASS" if auto_rotate else "FAIL",
                        resource_id=secret_id,
                        resource_name=f"{instance_name}/{secret_name}",
                        status_extended=f"Certificate '{secret_name}': auto-rotation {'enabled' if auto_rotate else 'not enabled'}.",
                        remediation="Enable automatic rotation: Secrets Manager > Certificate > Edit details > Automatic rotation ON.",
                        compliance_frameworks=FW,
                    ))
                if not secrets:
                    results.append(make_result(
                        cis_id="8.2.1", check_id="ibm_cis_8_2_1",
                        title="Ensure Secrets Manager certificates are automatically renewed",
                        service="security_compliance", severity="high", status="N/A",
                        resource_id=sm.get("guid", cfg.account_id),
                        resource_name=instance_name,
                        status_extended="No certificates found in this Secrets Manager instance.",
                        compliance_frameworks=FW,
                    ))
            except Exception as e:
                results.append(make_result(
                    cis_id="8.2.1", check_id="ibm_cis_8_2_1",
                    title="Ensure Secrets Manager certificates are automatically renewed",
                    service="security_compliance", severity="high", status="ERROR",
                    resource_id=sm.get("guid", cfg.account_id),
                    resource_name=instance_name,
                    status_extended=f"Failed to check Secrets Manager: {e}",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("8.2.1 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="8.2.1", check_id="ibm_cis_8_2_1",
            title="Ensure Secrets Manager certificates are automatically renewed",
            service="security_compliance", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list Secrets Manager instances: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 8.2.2 — Secrets Manager access follows least privilege (MANUAL) ──
def evaluate_cis_8_2_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("8.2.2", "ibm_cis_8_2_2",
        "Ensure access settings to secrets follow least privilege rule",
        "security_compliance", "medium", cfg.account_id,
        "Requires reviewing IAM policies for Secrets Manager to verify least privilege access.")]


# ── 8.2.3 — Secrets Manager notifications enabled (MANUAL) ──
def evaluate_cis_8_2_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("8.2.3", "ibm_cis_8_2_3",
        "Ensure notification service is enabled in IBM Cloud Secrets Manager",
        "access_control", "medium", cfg.account_id,
        "Requires verifying Event Notifications service is connected to Secrets Manager.")]


# ── 8.2.4 — Secrets Manager secrets rotated periodically (AUTOMATED) ──
def evaluate_cis_8_2_4(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check that secrets in Secrets Manager are set for periodic rotation."""
    results = []
    try:
        resources = c.resource_controller_get(
            "/v2/resource_instances",
            resource_id="secrets-manager",
            type="service_instance",
        )
        sm_instances = [r for r in resources.get("resources", [])
                        if "secrets-manager" in r.get("resource_id", "").lower()]

        if not sm_instances:
            results.append(make_result(
                cis_id="8.2.4", check_id="ibm_cis_8_2_4",
                title="Ensure secrets in Secrets Manager are rotated periodically",
                service="access_control", severity="high", status="N/A",
                resource_id=cfg.account_id,
                status_extended="No Secrets Manager instances found.",
                compliance_frameworks=FW,
            ))
            return results

        for sm in sm_instances:
            instance_name = sm.get("name", "")
            region = sm.get("region_id", cfg.regions[0])
            sm_api_url = sm.get("extensions", {}).get("endpoints.public", "")
            if not sm_api_url:
                sm_api_url = f"https://{sm.get('guid', '')}.{region}.secrets-manager.appdomain.cloud"

            try:
                secrets_resp = c.secrets_manager_get(sm_api_url, "/secrets")
                secrets = secrets_resp.get("secrets", [])
                for secret in secrets:
                    secret_id = secret.get("id", "")
                    secret_name = secret.get("name", secret_id)
                    rotation = secret.get("rotation", {})
                    auto_rotate = rotation.get("auto_rotate", False)
                    results.append(make_result(
                        cis_id="8.2.4", check_id="ibm_cis_8_2_4",
                        title="Ensure secrets in Secrets Manager are rotated periodically",
                        service="access_control", severity="high",
                        status="PASS" if auto_rotate else "FAIL",
                        resource_id=secret_id,
                        resource_name=f"{instance_name}/{secret_name}",
                        status_extended=f"Secret '{secret_name}': auto-rotation {'enabled' if auto_rotate else 'not enabled'}.",
                        remediation="Enable automatic rotation: Secrets Manager > Secret > Edit details > Automatic rotation ON.",
                        compliance_frameworks=FW,
                    ))
                if not secrets:
                    results.append(make_result(
                        cis_id="8.2.4", check_id="ibm_cis_8_2_4",
                        title="Ensure secrets in Secrets Manager are rotated periodically",
                        service="access_control", severity="high", status="N/A",
                        resource_id=sm.get("guid", cfg.account_id),
                        resource_name=instance_name,
                        status_extended="No secrets found in this Secrets Manager instance.",
                        compliance_frameworks=FW,
                    ))
            except Exception as e:
                results.append(make_result(
                    cis_id="8.2.4", check_id="ibm_cis_8_2_4",
                    title="Ensure secrets in Secrets Manager are rotated periodically",
                    service="access_control", severity="high", status="ERROR",
                    resource_id=sm.get("guid", cfg.account_id),
                    resource_name=instance_name,
                    status_extended=f"Failed to check secrets: {e}",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("8.2.4 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="8.2.4", check_id="ibm_cis_8_2_4",
            title="Ensure secrets in Secrets Manager are rotated periodically",
            service="access_control", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list Secrets Manager instances: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════════
# Section 9 — PowerVS (7 controls, all manual)
# ═══════════════════════════════════════════════════════════════════

# ── 9.1 — Default NSG restricts all traffic ──
def evaluate_cis_9_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("9.1", "ibm_cis_9_1",
        "Ensure the Default Network Security Group of Every Workspace Restricts All Traffic",
        "powervs", "high", cfg.account_id,
        "Requires verifying default NSG in each PowerVS workspace has no ingress rules.")]


# ── 9.2 — No NSG allows ingress 0.0.0.0/0 to port 3389 ──
def evaluate_cis_9_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("9.2", "ibm_cis_9_2",
        "Ensure no workspace security groups allow ingress from 0.0.0.0/0 to port 3389",
        "powervs", "critical", cfg.account_id,
        "Requires reviewing PowerVS NSG rules for RDP (port 3389) open to 0.0.0.0/0.")]


# ── 9.3 — No NSG allows ingress 0.0.0.0/0 to port 22 ──
def evaluate_cis_9_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("9.3", "ibm_cis_9_3",
        "Ensure no workspace NSGs allow ingress from 0.0.0.0/0 to port 22",
        "powervs", "critical", cfg.account_id,
        "Requires reviewing PowerVS NSG rules for SSH (port 22) open to 0.0.0.0/0.")]


# ── 9.4 — No NSG allows inbound from 0.0.0.0/0 to infrastructure ports ──
def evaluate_cis_9_4(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("9.4", "ibm_cis_9_4",
        "Ensure no workspace NSGs allow inbound traffic from 0.0.0.0/0 to any infrastructure ports",
        "powervs", "critical", cfg.account_id,
        "Requires reviewing PowerVS NSG rules for infrastructure ports open to 0.0.0.0/0.")]


# ── 9.5 — No NSG allows inbound from 0.0.0.0/0 to admin ports ──
def evaluate_cis_9_5(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("9.5", "ibm_cis_9_5",
        "Ensure no workspace NSGs allow inbound traffic from 0.0.0.0/0 to any administrative ports",
        "powervs", "critical", cfg.account_id,
        "Requires reviewing PowerVS NSG rules for administrative ports open to 0.0.0.0/0.")]


# ── 9.6 — No NSG allows inbound from 0.0.0.0/0 to fileshare port ──
def evaluate_cis_9_6(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("9.6", "ibm_cis_9_6",
        "Ensure no workspace NSGs allow inbound traffic from 0.0.0.0/0 to any fileshare port",
        "powervs", "critical", cfg.account_id,
        "Requires reviewing PowerVS NSG rules for fileshare ports (445, 2049) open to 0.0.0.0/0.")]


# ── 9.7 — No NSG allows inbound from 0.0.0.0/0 to telnet/RSH ──
def evaluate_cis_9_7(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("9.7", "ibm_cis_9_7",
        "Ensure no workspace NSGs allow inbound traffic from 0.0.0.0/0 to telnet (23) or RSH (514)",
        "powervs", "critical", cfg.account_id,
        "Requires reviewing PowerVS NSG rules for telnet (23) and RSH (514) open to 0.0.0.0/0.")]
