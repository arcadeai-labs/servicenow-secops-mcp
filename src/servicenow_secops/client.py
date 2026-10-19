"""Shared HTTP access for the ServiceNow REST API, authenticated as the service account.

ServiceNow's failure envelope is relayed to the caller, 429 is retryable, and a 401
drops the cached token so the retry mints a fresh one.
"""

from typing import Any

import httpx
from arcade_mcp_server import Context
from arcade_mcp_server.exceptions import RetryableToolError, ToolExecutionError

from servicenow_secops.auth import get_instance_url, invalidate_token, service_account_token

_TIMEOUT = 30.0


def _error_message(response: httpx.Response) -> str | None:
    """Combine ServiceNow's error.message and error.detail; detail usually names the cause."""
    try:
        body = response.json()
    except ValueError:
        return None
    error = body.get("error") or {}
    message = error.get("message") if isinstance(error.get("message"), str) else None
    detail = error.get("detail") if isinstance(error.get("detail"), str) else None
    if message and detail and detail != message:
        return f"{message}: {detail}"
    return message or detail


async def servicenow_request(
    context: Context,
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    not_found_ok: bool = False,
) -> httpx.Response:
    """Call the ServiceNow REST API as the service account and return the raw response."""
    url = f"{get_instance_url(context)}{path}"
    headers = {
        "Authorization": f"Bearer {await service_account_token(context)}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        response = await client.request(
            method, url, params=params, json=json_body, headers=headers, timeout=_TIMEOUT
        )

    if response.status_code == 429:
        raise RetryableToolError(
            message="ServiceNow is rate limiting requests. Please retry after a short wait.",
            developer_message=f"HTTP 429 (Retry-After={response.headers.get('Retry-After')!r}).",
            retry_after_ms=60_000,
        )

    if response.status_code == 401:
        # A cached token can be revoked before its stated expiry; drop it so the next
        # call mints a fresh one rather than failing until the cache entry ages out.
        invalidate_token(context)
        raise RetryableToolError(
            message="ServiceNow rejected the service account's token. Retry once.",
            developer_message=f"ServiceNow returned 401 for {method} {path}.",
        )

    if not_found_ok and response.status_code == 404:
        return response

    if response.status_code == 403:
        raise ToolExecutionError(
            message=(
                "The ServiceNow service account is not allowed to do this. "
                f"{_error_message(response) or ''}"
            ).strip(),
            developer_message=(
                f"HTTP 403 for {method} {path}. Check the service account's SIR roles "
                "and the ACLs on the table/field involved."
            ),
        )

    if response.status_code == 400:
        raise ToolExecutionError(
            message=_error_message(response) or "ServiceNow rejected the request.",
            developer_message=f"HTTP 400 for {method} {path}: {response.text[:500]}",
        )

    response.raise_for_status()
    return response


def result_of(response: httpx.Response) -> Any:
    return response.json().get("result")
