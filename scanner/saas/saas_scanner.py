"""SaaS Scanner Factory - creates appropriate scanner based on provider type."""
from scanner.saas.base_saas_check import BaseSaaSScanner


class SaaSScannerFactory:
    """Factory for creating SaaS-specific scanners."""

    @staticmethod
    def create(provider_type: str, credentials: dict) -> BaseSaaSScanner:
        scanners = {
            "servicenow": "scanner.saas.servicenow.servicenow_scanner.ServiceNowScanner",
            "m365": "scanner.saas.m365.m365_scanner.M365Scanner",
            "salesforce": "scanner.saas.salesforce.salesforce_scanner.SalesforceScanner",
            "snowflake": "scanner.saas.snowflake.snowflake_scanner.SnowflakeScanner",
        }

        scanner_path = scanners.get(provider_type)
        if not scanner_path:
            raise ValueError(f"Unsupported SaaS provider: {provider_type}")

        module_path, class_name = scanner_path.rsplit(".", 1)
        import importlib
        module = importlib.import_module(module_path)
        scanner_class = getattr(module, class_name)
        return scanner_class(credentials)
