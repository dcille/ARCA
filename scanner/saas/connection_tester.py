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
    """Test M365 connection: Graph token + /organization call + Fabric token + permission spot-checks."""
    import httpx

    tenant_id = credentials.get("tenant_id", "")
    client_id = credentials.get("client_id", "")
    client_secret = credentials.get("client_secret", "")

    if not all([tenant_id, client_id, client_secret]):
        return False, "Missing required credentials (tenant_id, client_id, client_secret)"

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    hints = [
        "Verify Tenant ID is correct (Entra admin center > Overview)",
        "Verify Client ID matches the registered app",
        "Verify Client Secret is the Value (not Secret ID) and has not expired",
        "Ensure admin consent has been granted for all API permissions",
        "Check that the app registration is not disabled",
        "If Fabric checks fail: ensure Power BI Tenant.Read.All is granted",
    ]

    async with httpx.AsyncClient(timeout=20) as client:
        # Step 1: Acquire Graph token
        token_resp = await client.post(
            token_url,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        if token_resp.status_code != 200 or "access_token" not in token_resp.json():
            detail = token_resp.json().get("error_description", f"HTTP {token_resp.status_code}")
            return False, f"Graph authentication failed: {detail}. Hints: {hints[0]}; {hints[1]}; {hints[2]}"

        graph_token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {graph_token}"}

        # Step 2: Verify Graph access by calling GET /organization
        org_resp = await client.get(
            "https://graph.microsoft.com/v1.0/organization", headers=headers
        )
        if org_resp.status_code != 200:
            return False, (
                f"Graph token acquired but GET /organization failed (HTTP {org_resp.status_code}). "
                f"Ensure Directory.Read.All permission is granted with admin consent."
            )

        org_name = ""
        org_data = org_resp.json().get("value", [])
        if org_data:
            org_name = org_data[0].get("displayName", tenant_id)

        # Step 3: Spot-check key permissions (non-blocking — report warnings)
        warnings: list[str] = []
        permission_checks = [
            ("identity/conditionalAccess/policies?$top=1", "Policy.Read.All", "Section 5"),
            ("domains?$top=1", "Domain.Read.All", "Section 2"),
        ]
        for endpoint, scope_name, section in permission_checks:
            try:
                r = await client.get(
                    f"https://graph.microsoft.com/v1.0/{endpoint}", headers=headers
                )
                if r.status_code == 403:
                    warnings.append(f"{scope_name} not granted ({section})")
            except Exception:
                pass

        # Step 4: Check beta SharePoint admin endpoint
        try:
            spo_resp = await client.get(
                "https://graph.microsoft.com/beta/admin/sharepoint/settings", headers=headers
            )
            if spo_resp.status_code == 403:
                warnings.append("SharePointTenantSettings.Read.All not granted (Section 7)")
        except Exception:
            pass

        # Step 5: Try Fabric/Power BI token (separate scope)
        fabric_ok = False
        try:
            fabric_resp = await client.post(
                token_url,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://analysis.windows.net/powerbi/api/.default",
                    "grant_type": "client_credentials",
                },
            )
            if fabric_resp.status_code == 200 and "access_token" in fabric_resp.json():
                fabric_ok = True
            else:
                warnings.append("Fabric/Power BI token failed — Tenant.Read.All may not be granted (Section 9)")
        except Exception:
            warnings.append("Fabric/Power BI token request failed (Section 9)")

        # Build result message
        msg = f"Connected to Microsoft 365 tenant: {org_name}"
        if fabric_ok:
            msg += " | Fabric API: OK"
        if warnings:
            msg += f" | Warnings: {'; '.join(warnings)}"

        return True, msg


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
    """Test Snowflake connection: SELECT CURRENT_VERSION() to verify connectivity.

    Supports both password and key-pair authentication.
    Accepts both new field names (account, warehouse, role) and legacy aliases
    (account_id, warehouse_name).
    """
    failure_hints = [
        "Verify account identifier includes region (e.g. xy12345.us-east-1)",
        "Check username and password/key are correct",
        "Ensure the user is not disabled or locked",
        "Verify network connectivity to <account>.snowflakecomputing.com:443",
        "If using key-pair: ensure private key is PKCS8 PEM format",
        "If using custom role: ensure IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE is granted",
    ]
    try:
        import snowflake.connector
        from typing import Any

        # Resolve field names (new names take priority over legacy aliases)
        account = credentials.get("account") or credentials.get("account_id", "")
        warehouse = credentials.get("warehouse") or credentials.get("warehouse_name")
        role = credentials.get("role", "ACCOUNTADMIN")
        auth_method = credentials.get("auth_method", "password")

        params: dict[str, Any] = dict(
            user=credentials["username"],
            account=account,
        )
        if warehouse:
            params["warehouse"] = warehouse
        if role:
            params["role"] = role

        # Authentication
        if auth_method == "key_pair" and credentials.get("private_key"):
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            private_key_pem = credentials["private_key"]
            if isinstance(private_key_pem, str):
                private_key_pem = private_key_pem.encode("utf-8")
            p_key = load_pem_private_key(private_key_pem, password=None)
            params["private_key"] = p_key
        else:
            params["password"] = credentials.get("password", "")

        conn = snowflake.connector.connect(**params)
        cur = conn.cursor()
        cur.execute("SELECT CURRENT_VERSION()")
        version = cur.fetchone()[0]
        cur.close()
        conn.close()
        return True, f"Connected to Snowflake account '{account}' (version {version})"
    except Exception as e:
        hint_text = " | Hints: " + "; ".join(failure_hints[:3])
        return False, f"Snowflake connection failed: {str(e)}{hint_text}"


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

    try:
        sa_raw = credentials["service_account_key"]
        if isinstance(sa_raw, dict):
            sa_info = sa_raw
        else:
            sa_info = json.loads(sa_raw)

        # Validate required fields are present in the service account JSON
        required_fields = ["client_email", "token_uri", "private_key"]
        for field in required_fields:
            if field not in sa_info:
                return False, f"Service account JSON missing required field: {field}"

        admin_email = credentials.get("admin_email", "")
        if not admin_email:
            return False, "Admin email (Super Admin) is required for domain-wide delegation"

        domain = credentials.get("domain", "")
        if not domain:
            return False, "Primary Google Workspace domain is required"

        # Use Google OAuth2 token endpoint to verify credentials
        async with httpx.AsyncClient(timeout=15) as client:
            # Build a JWT for service account auth
            import jwt as pyjwt

            now = int(time.time())
            payload = {
                "iss": sa_info["client_email"],
                "sub": admin_email,
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
            return True, f"Successfully connected to Google Workspace domain '{domain}'"
        error_detail = ""
        try:
            error_detail = response.json().get("error_description", "")
        except Exception:
            pass
        hints = []
        if "unauthorized_client" in error_detail.lower():
            hints.append("Verify the service account has domain-wide delegation enabled in Admin Console > API controls")
        if "invalid_grant" in error_detail.lower():
            hints.append("Check that the admin email is a Super Admin and domain-wide delegation scopes are authorized")
        hint_text = ". ".join(hints) if hints else error_detail
        return False, f"Google Workspace authentication failed ({response.status_code}). {hint_text}"
    except json.JSONDecodeError:
        return False, "Invalid service account JSON format. Paste the full contents of the JSON key file."
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
