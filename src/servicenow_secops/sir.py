"""Lookups shared by the SIR tools: incident resolution, choice lists, and tags."""

import re
from typing import Any

from arcade_mcp_server import Context
from arcade_mcp_server.exceptions import RetryableToolError, ToolExecutionError

from servicenow_secops.client import result_of, servicenow_request
from servicenow_secops.constants import (
    APPLIED_TAG_RECORD_ID_FIELD,
    APPLIED_TAG_RECORD_TABLE_FIELD,
    APPLIED_TAG_TABLE,
    APPLIED_TAG_TAG_FIELD,
    CHOICE_FALLBACK_TABLES,
    SECURITY_TAG_TABLE,
    SIR_TABLE,
)

_SYS_ID = re.compile(r"^[0-9a-f]{32}$")


async def resolve_sir_sys_id(context: Context, incident: str) -> str:
    """Accept a SIR number (e.g. 'SIR0010001') or a 32-character sys_id."""
    incident = incident.strip()
    if _SYS_ID.match(incident.lower()):
        return incident.lower()

    response = await servicenow_request(
        context,
        "GET",
        f"/api/now/table/{SIR_TABLE}",
        params={
            "sysparm_query": f"number={incident.upper()}",
            "sysparm_fields": "sys_id",
            "sysparm_limit": 1,
        },
    )
    rows = result_of(response) or []
    if not rows:
        raise ToolExecutionError(
            message=f"Security incident '{incident}' was not found.",
            developer_message=f"No {SIR_TABLE} row with number={incident.upper()}.",
        )
    return rows[0]["sys_id"]


# Where a choice list came from. "configured" is the instance's full choice list
# from sys_choice. "observed" is only the values existing incidents hold, used when
# the account can't read sys_choice (it needs roles such as personalize_choices,
# which can also edit choice lists, so a least-privilege account won't have them).
CONFIGURED = "configured"
OBSERVED = "observed"

# A dependent choice field, and the field whose value it depends on.
_DEPENDS_ON = {"subcategory": "category"}


async def list_choices(
    context: Context, element: str, dependent_value: str | None = None
) -> tuple[list[dict[str, str]], str]:
    """Choices for a SIR field, and whether they're the configured list or observed values."""
    try:
        for table in (SIR_TABLE, *CHOICE_FALLBACK_TABLES):
            query = f"name={table}^element={element}^inactive=false"
            if dependent_value is not None:
                query += f"^dependent_value={dependent_value}"
            response = await servicenow_request(
                context,
                "GET",
                "/api/now/table/sys_choice",
                params={
                    "sysparm_query": f"{query}^ORDERBYsequence",
                    "sysparm_fields": "label,value,dependent_value",
                    "sysparm_limit": 500,
                },
            )
            rows = result_of(response) or []
            if rows:
                return [
                    {
                        "label": row["label"],
                        "value": row["value"],
                        "depends_on": row.get("dependent_value") or "",
                    }
                    for row in rows
                ], CONFIGURED
    except ToolExecutionError:
        pass  # sys_choice isn't readable by this account; use observed values
    return await _observed_choices(context, element, dependent_value), OBSERVED


async def _observed_choices(
    context: Context, element: str, dependent_value: str | None
) -> list[dict[str, str]]:
    """Distinct values existing incidents hold for a field, via the Aggregate API."""
    params = {
        "sysparm_group_by": element,
        "sysparm_count": "true",
        "sysparm_display_value": "all",
    }
    parent = _DEPENDS_ON.get(element)
    if parent and dependent_value is not None:
        params["sysparm_query"] = f"{parent}={dependent_value}"
    response = await servicenow_request(
        context, "GET", f"/api/now/stats/{SIR_TABLE}", params=params
    )
    choices = []
    for bucket in result_of(response) or []:
        for group in bucket.get("groupby_fields") or []:
            value = str(group.get("value") or "")
            if value:
                choices.append(
                    {
                        "label": str(group.get("display_value") or value),
                        "value": value,
                        "depends_on": dependent_value or "",
                    }
                )
    return choices


def match_choice(
    field: str, given: str, choices: list[dict[str, str]], source: str = CONFIGURED
) -> str:
    """Map a caller-supplied label or value to the stored value, or explain the valid options."""
    wanted = given.strip().lower()
    for choice in choices:
        if wanted in (choice["value"].lower(), choice["label"].lower()):
            return choice["value"]
    valid = ", ".join(f"{c['label']} ({c['value']})" for c in choices) or "none found"
    hint = (
        " These are the values existing incidents use; the instance may define others."
        if source == OBSERVED
        else ""
    )
    raise RetryableToolError(
        message=f"'{given}' is not a valid {field}.",
        developer_message=f"No {source} choice for {SIR_TABLE}.{field} matched {given!r}.",
        additional_prompt_content=f"Valid values for {field}: {valid}.{hint}",
    )


async def list_security_tags(context: Context) -> list[dict[str, str]]:
    response = await servicenow_request(
        context,
        "GET",
        f"/api/now/table/{SECURITY_TAG_TABLE}",
        params={"sysparm_fields": "sys_id,name", "sysparm_limit": 1000},
    )
    return [{"sys_id": row["sys_id"], "name": row["name"]} for row in result_of(response) or []]


async def tags_on_incident(context: Context, sir_sys_id: str) -> list[dict[str, Any]]:
    response = await servicenow_request(
        context,
        "GET",
        f"/api/now/table/{APPLIED_TAG_TABLE}",
        params={
            "sysparm_query": (
                f"{APPLIED_TAG_RECORD_TABLE_FIELD}={SIR_TABLE}"
                f"^{APPLIED_TAG_RECORD_ID_FIELD}={sir_sys_id}"
            ),
            "sysparm_fields": f"sys_id,{APPLIED_TAG_TAG_FIELD}",
            "sysparm_display_value": "all",
            "sysparm_limit": 200,
        },
    )
    return [
        {
            "tag_sys_id": row[APPLIED_TAG_TAG_FIELD]["value"],
            "name": row[APPLIED_TAG_TAG_FIELD]["display_value"],
        }
        for row in result_of(response) or []
    ]
