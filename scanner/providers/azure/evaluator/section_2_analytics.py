"""CIS Azure v5.0 Section 2: Analytics Services (Azure Databricks) evaluators.

Controls 2.1.1–2.1.11. Uses azure.mgmt.databricks + azure.mgmt.monitor SDKs.
"""

import logging
from .base import AzureClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Azure-5.0", "MCSB-Azure-1.0"]


def _get_databricks_client(clients: AzureClientCache):
    from azure.mgmt.databricks import AzureDatabricksManagementClient
    return clients._get_or_create(
        "databricks",
        lambda: AzureDatabricksManagementClient(clients.credential, clients.subscription_id),
    )


def _list_workspaces(clients):
    try:
        db = _get_databricks_client(clients)
        return list(db.workspaces.list_by_subscription())
    except Exception as e:
        logger.warning("Could not list Databricks workspaces: %s", e)
        return []


# 2.1.1 — Databricks deployed in customer-managed VNet
def evaluate_cis_2_1_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for ws in _list_workspaces(clients):
        params = ws.parameters
        custom_vnet = False
        if params:
            cvn = getattr(params, "custom_virtual_network_id", None)
            custom_vnet = cvn is not None and cvn.value is not None if cvn else False
        results.append(make_result(
            cis_id="2.1.1", check_id="azure_cis_2_1_1",
            title="Ensure Databricks is deployed in customer-managed VNet",
            service="analytics", severity="high",
            status="PASS" if custom_vnet else "FAIL",
            resource_id=ws.id, resource_name=ws.name, region=ws.location,
            status_extended=f"Workspace {ws.name}: customer-managed VNet = {custom_vnet}",
            remediation="Redeploy Databricks workspace with VNet injection into a customer-managed VNet.",
            compliance_frameworks=FW,
        ))
    if not results:
        results.append(make_result(
            cis_id="2.1.1", check_id="azure_cis_2_1_1",
            title="Ensure Databricks is deployed in customer-managed VNet",
            service="analytics", severity="high", status="PASS",
            resource_id=config.subscription_id,
            status_extended="No Databricks workspaces found.",
            compliance_frameworks=FW,
        ))
    return results


# 2.1.2 — NSGs configured for Databricks subnets
def evaluate_cis_2_1_2(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for ws in _list_workspaces(clients):
        params = ws.parameters
        has_nsg = False
        if params:
            cvn = getattr(params, "custom_virtual_network_id", None)
            if cvn and cvn.value:
                # If VNet injection is used, check subnets for NSGs
                try:
                    vnet_id = cvn.value
                    parts = vnet_id.split("/")
                    rg = parts[4]
                    vnet_name = parts[-1]
                    vnet = clients.network.virtual_networks.get(rg, vnet_name)
                    for subnet in vnet.subnets or []:
                        if "databricks" in (subnet.name or "").lower():
                            if subnet.network_security_group:
                                has_nsg = True
                except Exception:
                    pass
        results.append(make_result(
            cis_id="2.1.2", check_id="azure_cis_2_1_2",
            title="Ensure NSGs are configured for Databricks subnets",
            service="analytics", severity="high",
            status="PASS" if has_nsg else "FAIL",
            resource_id=ws.id, resource_name=ws.name, region=ws.location,
            status_extended=f"Workspace {ws.name}: Databricks subnet NSGs = {has_nsg}",
            remediation="Assign NSGs to Databricks public and private subnets.",
            compliance_frameworks=FW,
        ))
    return results


# 2.1.3 — Encrypted traffic between cluster workers (MANUAL)
def evaluate_cis_2_1_3(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="2.1.3", check_id="azure_cis_2_1_3",
        title="Ensure traffic is encrypted between cluster worker nodes",
        service="analytics", severity="high",
        subscription_id=config.subscription_id,
        reason="Requires verifying init scripts configure TLS 1.3 encryption between Spark workers. No API available.",
    )]


# 2.1.4 — SCIM provisioning from Entra ID (MANUAL)
def evaluate_cis_2_1_4(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="2.1.4", check_id="azure_cis_2_1_4",
        title="Ensure users/groups are synced from Entra ID to Databricks",
        service="analytics", severity="medium",
        subscription_id=config.subscription_id,
        reason="Requires verifying SCIM provisioning configuration in Entra ID Enterprise Applications.",
    )]


# 2.1.5 — Unity Catalog configured (MANUAL)
def evaluate_cis_2_1_5(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="2.1.5", check_id="azure_cis_2_1_5",
        title="Ensure Unity Catalog is configured for Azure Databricks",
        service="analytics", severity="high",
        subscription_id=config.subscription_id,
        reason="Requires checking Databricks account console for metastore attachment. No Azure management API.",
    )]


# 2.1.6 — PAT restrictions (MANUAL)
def evaluate_cis_2_1_6(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="2.1.6", check_id="azure_cis_2_1_6",
        title="Ensure PAT usage is restricted and expiry is enforced",
        service="analytics", severity="high",
        subscription_id=config.subscription_id,
        reason="Requires Databricks workspace admin console or Databricks CLI to verify PAT policies.",
    )]


# 2.1.7 — Diagnostic log delivery configured
def evaluate_cis_2_1_7(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for ws in _list_workspaces(clients):
        try:
            diag = list(clients.monitor.diagnostic_settings.list(resource_uri=ws.id))
            has_diag = len(diag) > 0
            results.append(make_result(
                cis_id="2.1.7", check_id="azure_cis_2_1_7",
                title="Ensure diagnostic log delivery is configured for Databricks",
                service="analytics", severity="high",
                status="PASS" if has_diag else "FAIL",
                resource_id=ws.id, resource_name=ws.name, region=ws.location,
                status_extended=f"Workspace {ws.name}: diagnostic settings = {len(diag)}",
                remediation="Configure diagnostic settings to send logs to Log Analytics, Storage, or Event Hub.",
                compliance_frameworks=FW,
            ))
        except Exception:
            results.append(make_result(
                cis_id="2.1.7", check_id="azure_cis_2_1_7",
                title="Ensure diagnostic log delivery is configured for Databricks",
                service="analytics", severity="high", status="ERROR",
                resource_id=ws.id, resource_name=ws.name,
                status_extended=f"Could not query diagnostic settings for {ws.name}",
                compliance_frameworks=FW,
            ))
    return results


# 2.1.8 — CMK encryption for critical data (MANUAL)
def evaluate_cis_2_1_8(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for ws in _list_workspaces(clients):
        enc = ws.encryption
        cmk = enc and getattr(enc, "key_source", None) == "Microsoft.Keyvault" if enc else False
        results.append(make_result(
            cis_id="2.1.8", check_id="azure_cis_2_1_8",
            title="Ensure critical data in Databricks is encrypted with CMK",
            service="analytics", severity="high",
            status="PASS" if cmk else "MANUAL",
            resource_id=ws.id, resource_name=ws.name, region=ws.location,
            status_extended=f"Workspace {ws.name}: CMK encryption = {cmk}. CIS recommends manual scoping.",
            remediation="Configure CMK encryption using Azure Key Vault for sensitive workloads.",
            compliance_frameworks=FW,
        ))
    return results


# 2.1.9 — No Public IP (Secure Cluster Connectivity)
def evaluate_cis_2_1_9(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for ws in _list_workspaces(clients):
        params = ws.parameters
        no_public_ip = False
        if params:
            npip = getattr(params, "enable_no_public_ip", None)
            no_public_ip = npip.value if npip and npip.value else False
        results.append(make_result(
            cis_id="2.1.9", check_id="azure_cis_2_1_9",
            title="Ensure 'No Public IP' is enabled for Databricks",
            service="analytics", severity="medium",
            status="PASS" if no_public_ip else "FAIL",
            resource_id=ws.id, resource_name=ws.name, region=ws.location,
            status_extended=f"Workspace {ws.name}: enableNoPublicIp = {no_public_ip}",
            remediation="Enable Secure Cluster Connectivity (No Public IP) on the Databricks workspace.",
            compliance_frameworks=FW,
        ))
    return results


# 2.1.10 — Public Network Access disabled
def evaluate_cis_2_1_10(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for ws in _list_workspaces(clients):
        pna = getattr(ws, "public_network_access", None)
        disabled = pna == "Disabled"
        results.append(make_result(
            cis_id="2.1.10", check_id="azure_cis_2_1_10",
            title="Ensure public network access is disabled for Databricks",
            service="analytics", severity="high",
            status="PASS" if disabled else "FAIL",
            resource_id=ws.id, resource_name=ws.name, region=ws.location,
            status_extended=f"Workspace {ws.name}: publicNetworkAccess = {pna or 'Enabled (default)'}",
            remediation="Disable public network access on the Databricks workspace.",
            compliance_frameworks=FW,
        ))
    return results


# 2.1.11 — Private endpoints for Databricks
def evaluate_cis_2_1_11(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    results = []
    for ws in _list_workspaces(clients):
        pe_conns = getattr(ws, "private_endpoint_connections", None) or []
        approved = [p for p in pe_conns
                    if getattr(getattr(p, "private_link_service_connection_state", None), "status", "") == "Approved"]
        results.append(make_result(
            cis_id="2.1.11", check_id="azure_cis_2_1_11",
            title="Ensure private endpoints are used for Databricks",
            service="analytics", severity="high",
            status="PASS" if approved else "FAIL",
            resource_id=ws.id, resource_name=ws.name, region=ws.location,
            status_extended=f"Workspace {ws.name}: approved private endpoints = {len(approved)}",
            remediation="Configure private endpoints for the Databricks workspace.",
            compliance_frameworks=FW,
        ))
    return results
