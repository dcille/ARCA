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
        "github": _test_github,
        "google_workspace": _test_google_workspace,
        "cloudflare": _test_cloudflare,
        "openstack": _test_openstack,
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


async def _test_github(credentials: dict) -> tuple[bool, str]:
    import httpx
    headers = {
        "Authorization": f"token {credentials['personal_access_token']}",
        "Accept": "application/vnd.github.v3+json",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get("https://api.github.com/user", headers=headers)
    if response.status_code == 200:
        username = response.json().get("login", "unknown")
        return True, f"Successfully authenticated with GitHub as {username}"
    return False, f"GitHub authentication failed: {response.status_code}"


async def _test_google_workspace(credentials: dict) -> tuple[bool, str]:
    import httpx
    import json
    import time
    import hashlib
    import base64

    try:
        sa_info = json.loads(credentials["service_account_json"])
        # Validate required fields are present in the service account JSON
        required_fields = ["client_email", "token_uri", "private_key"]
        for field in required_fields:
            if field not in sa_info:
                return False, f"Service account JSON missing required field: {field}"

        # Use Google OAuth2 token endpoint to verify credentials
        async with httpx.AsyncClient(timeout=15) as client:
            # Build a JWT for service account auth
            import jwt as pyjwt

            now = int(time.time())
            payload = {
                "iss": sa_info["client_email"],
                "sub": credentials["delegated_admin_email"],
                "scope": "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "aud": sa_info["token_uri"],
                "iat": now,
                "exp": now + 3600,
            }
            signed_jwt = pyjwt.encode(payload, sa_info["private_key"], algorithm="RS256")
            response = await client.post(
                sa_info["token_uri"],
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": signed_jwt,
                },
            )
        if response.status_code == 200 and "access_token" in response.json():
            return True, "Successfully authenticated with Google Workspace"
        return False, f"Google Workspace authentication failed: {response.status_code}"
    except json.JSONDecodeError:
        return False, "Invalid service account JSON format"
    except ImportError:
        return False, "PyJWT library required for Google Workspace authentication"
    except Exception as e:
        return False, f"Google Workspace connection failed: {str(e)}"


async def _test_cloudflare(credentials: dict) -> tuple[bool, str]:
    import httpx
    headers = {
        "Authorization": f"Bearer {credentials['api_token']}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            "https://api.cloudflare.com/client/v4/user/tokens/verify",
            headers=headers,
        )
    if response.status_code == 200:
        data = response.json()
        if data.get("success"):
            return True, "Successfully authenticated with Cloudflare"
    return False, f"Cloudflare authentication failed: {response.status_code}"


async def _test_openstack(credentials: dict) -> tuple[bool, str]:
    import httpx
    auth_payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": credentials["username"],
                        "password": credentials["password"],
                        "domain": {"name": credentials.get("user_domain_name", "Default")},
                    }
                },
            },
            "scope": {
                "project": {
                    "name": credentials["project_name"],
                    "domain": {"name": credentials.get("project_domain_name", "Default")},
                }
            },
        }
    }
    auth_url = credentials["auth_url"].rstrip("/")
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            f"{auth_url}/auth/tokens",
            json=auth_payload,
        )
    if response.status_code in (200, 201) and "X-Subject-Token" in response.headers:
        return True, "Successfully authenticated with OpenStack"
    return False, f"OpenStack authentication failed: {response.status_code}"
