"""Test SaaS connections before scanning."""
import logging

logger = logging.getLogger(__name__)


async def test_saas_connection(provider_type: str, credentials: dict) -> tuple[bool, str]:
    """Test connection to a SaaS provider."""
    testers = {
        "servicenow": _test_servicenow,
        "m365": _test_m365,
        "salesforce": _test_salesforce,
        "snowflake": _test_snowflake,
    }

    tester = testers.get(provider_type)
    if not tester:
        return False, f"Unknown provider: {provider_type}"

    try:
        return await tester(credentials)
    except Exception as e:
        logger.error(f"Connection test failed for {provider_type}: {e}")
        return False, str(e)


async def _test_servicenow(credentials: dict) -> tuple[bool, str]:
    import httpx
    instance = credentials["instance_name"]
    url = f"https://{instance}.service-now.com/api/now/table/sys_properties?sysparm_limit=1"
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            url,
            auth=(credentials["username"], credentials["password"]),
        )
    if response.status_code == 200:
        return True, "Successfully connected to ServiceNow"
    return False, f"ServiceNow returned status {response.status_code}"


async def _test_m365(credentials: dict) -> tuple[bool, str]:
    import httpx
    token_url = f"https://login.microsoftonline.com/{credentials['tenant_id']}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            token_url,
            data={
                "client_id": credentials["client_id"],
                "client_secret": credentials["client_secret"],
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
    if response.status_code == 200 and "access_token" in response.json():
        return True, "Successfully authenticated with Microsoft 365"
    return False, f"M365 authentication failed: {response.status_code}"


async def _test_salesforce(credentials: dict) -> tuple[bool, str]:
    import httpx
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            "https://login.salesforce.com/services/oauth2/token",
            data={
                "grant_type": "password",
                "client_id": credentials["client_id"],
                "client_secret": credentials["client_secret"],
                "username": credentials["username"],
                "password": credentials["password"] + credentials.get("security_token", ""),
            },
        )
    if response.status_code == 200 and "access_token" in response.json():
        return True, "Successfully authenticated with Salesforce"
    return False, f"Salesforce authentication failed: {response.status_code}"


async def _test_snowflake(credentials: dict) -> tuple[bool, str]:
    try:
        import snowflake.connector
        conn = snowflake.connector.connect(
            user=credentials["username"],
            password=credentials["password"],
            account=credentials["account_id"],
            warehouse=credentials.get("warehouse_name"),
            role="PUBLIC",
        )
        conn.cursor().execute("SELECT CURRENT_VERSION()")
        conn.close()
        return True, "Successfully connected to Snowflake"
    except Exception as e:
        return False, f"Snowflake connection failed: {str(e)}"
