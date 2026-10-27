"""Lookups shared by the SIR tools: incident resolution, choice lists, and applied tags."""

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
    SIR_TABLE,
)

_SYS_ID = re.compile(r"^[0-9a-f]{32}$")
_RANK_PREFIX = re.compile(r"^\d+\s*-\s*")


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


# Where a choice list came from. "configured" is the instance's full choice list,
# read from the UI Meta API (which any user who can read the table can call) or,
# failing that, sys_choice (which needs roles such as personalize_choices). "observed"
# is a last resort: only the values existing incidents hold, which can miss valid ones.
CONFIGURED = "configured"
OBSERVED = "observed"

# A dependent choice field, and the field whose value it depends on.
_DEPENDS_ON = {"subcategory": "category"}


async def list_choices(
    context: Context, element: str, dependent_value: str | None = None
) -> tuple[list[dict[str, str]], str]:
    """Choices for a SIR field, and whether they're the configured list or observed values."""
    rows = await _ui_meta_choices(context, element, dependent_value)
    if rows is not None:
        return rows, CONFIGURED
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
            found = result_of(response) or []
            if found:
                return [
                    {
                        "label": row["label"],
                        "value": row["value"],
                        "depends_on": row.get("dependent_value") or "",
                    }
                    for row in found
                ], CONFIGURED
    except ToolExecutionError:
        pass  # sys_choice isn't readable by this account; use observed values
    return await _observed_choices(context, element, dependent_value), OBSERVED


async def _ui_meta_choices(
    context: Context, element: str, dependent_value: str | None
) -> list[dict[str, str]] | None:
    """The field's configured choices from the UI Meta API, or None if it isn't usable.

    The API returns every choice for a dependent field; each carries the parent
    values it belongs to, so subcategories are filtered by category here.
    """
    try:
        response = await servicenow_request(
            context, "GET", f"/api/now/ui/meta/{SIR_TABLE}", not_found_ok=True
        )
    except ToolExecutionError:
        return None
    if response.status_code != 200:
        return None
    column = ((result_of(response) or {}).get("columns") or {}).get(element) or {}
    rows = []
    for choice in column.get("choices") or []:
        value = str(choice.get("value") or "")
        if not value or choice.get("missing"):
            continue  # "-- None --" and choices no longer defined
        parents = [p for p in (choice.get("parameters") or {}).get("dependent_values") or [] if p]
        if dependent_value is not None and parents and dependent_value not in parents:
            continue
        rows.append(
            {
                "label": str(choice.get("label") or value),
                "value": value,
                "depends_on": ",".join(parents),
            }
        )
    return rows or None


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
        label = choice["label"].lower()
        # Some SIR labels carry a rank prefix ("2 - High"); accept the bare word too.
        if wanted in (choice["value"].lower(), label, _RANK_PREFIX.sub("", label)):
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


def encode_query_value(value: str) -> str:
    """Escape a value for a ServiceNow encoded query, where '^' separates conditions."""
    return value.replace("^", "^^")


async def _lookup(
    context: Context, table: str, queries: list[str], fields: str
) -> list[dict[str, Any]]:
    """Rows from the first query that matches anything, tried in order."""
    for query in queries:
        response = await servicenow_request(
            context,
            "GET",
            f"/api/now/table/{table}",
            params={"sysparm_query": query, "sysparm_fields": fields, "sysparm_limit": 10},
        )
        rows = result_of(response) or []
        if rows:
            return rows
    return []


async def resolve_group(context: Context, group: str) -> dict[str, str]:
    """Accept an assignment group's name or sys_id; return its sys_id and name."""
    given = group.strip()
    value = encode_query_value(given)
    queries = [f"sys_id={given.lower()}"] if _SYS_ID.match(given.lower()) else []
    queries += [f"active=true^name={value}", f"active=true^nameLIKE{value}"]
    rows = await _lookup(context, "sys_user_group", queries, "sys_id,name")
    return _single("assignment group", given, rows, lambda r: r["name"])


async def resolve_user(context: Context, user: str) -> dict[str, str]:
    """Accept a user's user_name, email, full name or sys_id; return its sys_id and name."""
    given = user.strip()
    value = encode_query_value(given)
    queries = [f"sys_id={given.lower()}"] if _SYS_ID.match(given.lower()) else []
    queries += [
        f"active=true^user_name={value}",
        f"active=true^email={value}",
        f"active=true^name={value}",
        f"active=true^nameLIKE{value}",
    ]
    rows = await _lookup(context, "sys_user", queries, "sys_id,name,user_name")
    return _single("user", given, rows, lambda r: f"{r['name']} ({r['user_name']})")


def _single(kind: str, given: str, rows: list[dict[str, Any]], describe: Any) -> dict[str, str]:
    if len(rows) == 1:
        return {"sys_id": rows[0]["sys_id"], "name": rows[0]["name"]}
    if not rows:
        raise RetryableToolError(
            message=f"No active {kind} matches '{given}'.",
            developer_message=f"No active {kind} matched {given!r}.",
            additional_prompt_content=f"Check the spelling, or pass the {kind}'s exact name.",
        )
    options = "; ".join(describe(r) for r in rows)
    raise RetryableToolError(
        message=f"'{given}' matches more than one {kind}.",
        developer_message=f"{len(rows)} {kind} rows matched {given!r}.",
        additional_prompt_content=f"Pass one of these exactly: {options}.",
    )


async def is_group_member(context: Context, user_sys_id: str, group_sys_id: str) -> bool | None:
    """Whether the user belongs to the group, or None if memberships can't be read."""
    try:
        response = await servicenow_request(
            context,
            "GET",
            "/api/now/table/sys_user_grmember",
            params={
                "sysparm_query": f"user={user_sys_id}^group={group_sys_id}",
                "sysparm_fields": "sys_id",
                "sysparm_limit": 1,
            },
        )
    except ToolExecutionError:
        return None
    return bool(result_of(response))
