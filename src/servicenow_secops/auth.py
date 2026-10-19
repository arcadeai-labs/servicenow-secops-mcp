"""Service-account auth for ServiceNow via the OAuth client-credentials grant.

Arcade's OAuth providers only run the authorization-code flow, which makes the
connection act as whoever signed in. This server instead mints its own token for a
dedicated ServiceNow service account, using client credentials stored as Arcade
secrets. ServiceNow binds a client-credentials OAuth client to one "OAuth
Application User", so every write lands in ServiceNow as that account; Arcade's
own logs still record which user and agent invoked the tool.
"""

import asyncio
import re
import time

import httpx
from arcade_mcp_server import Context
from arcade_mcp_server.exceptions import ToolExecutionError

INSTANCE_URL_SECRET_NAME = "SERVICENOW_INSTANCE_URL"
CLIENT_ID_SECRET_NAME = "SERVICENOW_CLIENT_ID"
CLIENT_SECRET_SECRET_NAME = "SERVICENOW_CLIENT_SECRET"

SERVICE_ACCOUNT_SECRETS = [
    INSTANCE_URL_SECRET_NAME,
    CLIENT_ID_SECRET_NAME,
    CLIENT_SECRET_SECRET_NAME,
]

_TIMEOUT = 30.0
# Refresh a little before ServiceNow's stated expiry so an in-flight call never
# carries a token that expires mid-request.
_EXPIRY_SKEW_SECONDS = 60

# (instance_url, client_id) -> (access_token, expires_at_epoch)
_token_cache: dict[tuple[str, str], tuple[str, float]] = {}
_token_lock = asyncio.Lock()


def _require_secret(context: Context, key: str) -> str:
    try:
        value = context.get_secret(key)
    except ValueError:
        value = ""
    if not value or not value.strip():
        raise ToolExecutionError(
            message="The ServiceNow service account is not configured.",
            developer_message=f"The '{key}' secret is not set for this server.",
        )
    return value.strip()


def get_instance_url(context: Context) -> str:
    """Normalize the instance secret to an origin like 'https://acme.service-now.com'.

    Accepts a bare instance name ("acme"), a host, or a full URL.
    """
    host = _require_secret(context, INSTANCE_URL_SECRET_NAME).lower()
    host = re.sub(r"^https?://", "", host)
    host = host.split("/", 1)[0].strip(".")
    if "." not in host:
        host = f"{host}.service-now.com"
    return f"https://{host}"


def invalidate_token(context: Context) -> None:
    """Drop the cached token, e.g. after ServiceNow rejects it with a 401."""
    key = (get_instance_url(context), _require_secret(context, CLIENT_ID_SECRET_NAME))
    _token_cache.pop(key, None)


async def service_account_token(context: Context) -> str:
    """Return a cached access token, minting a new one when it is missing or near expiry."""
    instance_url = get_instance_url(context)
    client_id = _require_secret(context, CLIENT_ID_SECRET_NAME)
    key = (instance_url, client_id)

    cached = _token_cache.get(key)
    if cached and cached[1] > time.time():
        return cached[0]

    async with _token_lock:
        cached = _token_cache.get(key)
        if cached and cached[1] > time.time():
            return cached[0]

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{instance_url}/oauth_token.do",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": _require_secret(context, CLIENT_SECRET_SECRET_NAME),
                },
                headers={"Accept": "application/json"},
                timeout=_TIMEOUT,
            )

        if not response.is_success:
            raise ToolExecutionError(
                message="Could not sign in to ServiceNow as the service account.",
                developer_message=(
                    f"Client-credentials token request returned HTTP {response.status_code}: "
                    f"{response.text[:500]}. Check the client ID/secret, that the OAuth client "
                    "has the client_credentials grant enabled, and that it is bound to an "
                    "OAuth Application User."
                ),
            )

        body = response.json()
        token = body["access_token"]
        expires_in = int(body.get("expires_in", 1800))
        _token_cache[key] = (token, time.time() + max(0, expires_in - _EXPIRY_SKEW_SECONDS))
        return token
