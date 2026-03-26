"""CIS Azure v5.0 Section 3: Compute Services evaluators.

Control 3.1.1 only. MFA for privileged VM access — manual.
"""

from .base import AzureClientCache, EvalConfig, make_manual_result


def evaluate_cis_3_1_1(clients: AzureClientCache, config: EvalConfig) -> list[dict]:
    return [make_manual_result(
        cis_id="3.1.1", check_id="azure_cis_3_1_1",
        title="Ensure only MFA enabled identities can access privileged Virtual Machine",
        service="compute", severity="high",
        subscription_id=config.subscription_id,
        reason="Requires verifying Entra ID Conditional Access policies for VM Administrator Login role and cross-referencing MFA status. Needs Entra P2 license.",
    )]
