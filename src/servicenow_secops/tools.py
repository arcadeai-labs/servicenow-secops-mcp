"""Tools for working ServiceNow Security Incident Response (SIR) incidents."""

import re
from typing import Annotated, Any

from arcade_mcp_server import Context, tool
from arcade_mcp_server.exceptions import RetryableToolError, ToolExecutionError
from arcade_mcp_server.metadata import (
    Behavior,
    Classification,
    Operation,
    ServiceDomain,
    ToolMetadata,
)

from servicenow_secops.auth import SERVICE_ACCOUNT_SECRETS
from servicenow_secops.client import result_of, servicenow_request
from servicenow_secops.constants import (
    ASSIGNED_TO_FIELD,
    ASSIGNMENT_GROUP_FIELD,
    CHOICE_FIELDS,
    SEARCH_FIELDS,
    SECURE_NOTES_FIELD,
    SIR_FIELDS,
    SIR_TABLE,
    UPDATABLE_CHOICE_FIELDS,
)
from servicenow_secops.sir import (
    OBSERVED,
    encode_query_value,
    is_group_member,
    list_choices,
    match_choice,
    resolve_group,
    resolve_sir_sys_id,
    resolve_user,
    tags_on_incident,
)

_CLASSIFICATION = Classification(service_domains=[ServiceDomain.INCIDENT_MANAGEMENT])

_INCIDENT_ARG = Annotated[str, "Security incident number (e.g. 'SIR0010001') or its sys_id"]

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_RESULTS = 100


def _read_metadata() -> ToolMetadata:
    return ToolMetadata(
        classification=_CLASSIFICATION,
        behavior=Behavior(operations=[Operation.READ], read_only=True, open_world=True),
    )


def _field(record: dict[str, Any], name: str) -> dict[str, str] | None:
    """Flatten a sysparm_display_value=all field to {value, label}."""
    raw = record.get(name)
    if raw is None:
        return None
    if isinstance(raw, dict):
        return {"value": raw.get("value", ""), "label": raw.get("display_value", "")}
    return {"value": raw, "label": raw}


@tool(requires_secrets=SERVICE_ACCOUNT_SECRETS, metadata=_read_metadata())
async def get_security_incident(
    context: Context,
    incident: _INCIDENT_ARG,
) -> Annotated[dict, "The security incident's fields, security tags, and secure notes"]:
    """Read a ServiceNow security incident (SIR), including its classification and tags.

    Each field is returned with both its stored value and its display label.
    """
    sys_id = await resolve_sir_sys_id(context, incident)
    response = await servicenow_request(
        context,
        "GET",
        f"/api/now/table/{SIR_TABLE}/{sys_id}",
        params={
            "sysparm_fields": ",".join([*SIR_FIELDS, SECURE_NOTES_FIELD]),
            "sysparm_display_value": "all",
            "sysparm_exclude_reference_link": "true",
        },
    )
    record = result_of(response) or {}

    fields = {name: _field(record, name) for name in SIR_FIELDS}
    secure_notes = _field(record, SECURE_NOTES_FIELD)
    return {
        "sys_id": sys_id,
        "fields": fields,
        # Journal fields come back as the rendered history in the display value.
        "secure_notes": secure_notes["label"] if secure_notes else None,
        "security_tags": await tags_on_incident(context, sys_id),
    }


@tool(requires_secrets=SERVICE_ACCOUNT_SECRETS, metadata=_read_metadata())
async def list_security_incident_field_choices(
    context: Context,
    field: Annotated[
        str,
        "The field to list valid values for: 'state', 'category', 'subcategory', "
        "'business_impact', or 'priority'",
    ],
    category: Annotated[
        str | None,
        "For field='subcategory', only list subcategories of this category value",
    ] = None,
) -> Annotated[dict, "The valid values for the field on this ServiceNow instance"]:
    """List the valid values for a security incident field, as configured on this instance.

    Use this before UpdateSecurityIncident or SearchSecurityIncidents when unsure which
    values exist. Priority can be searched on but not set.
    """
    field = field.strip().lower()
    if field not in CHOICE_FIELDS:
        raise ToolExecutionError(
            message=f"'{field}' is not a supported field. Use one of: {', '.join(CHOICE_FIELDS)}.",
        )

    element = CHOICE_FIELDS[field]
    dependent = category if field == "subcategory" else None
    choices, source = await list_choices(context, element, dependent)
    result: dict[str, Any] = {"field": field, "source": source, "choices": choices}
    if source == OBSERVED:
        result["note"] = (
            "The service account can't read the instance's choice lists, so these are the "
            "values existing incidents use. The instance may define others."
        )
    return result


@tool(requires_secrets=SERVICE_ACCOUNT_SECRETS, metadata=_read_metadata())
async def search_security_incidents(
    context: Context,
    text: Annotated[
        str | None, "Text to look for in the number, short description or description"
    ] = None,
    state: Annotated[str | None, "State, by label or value (e.g. 'Analysis')"] = None,
    category: Annotated[str | None, "Category, by label or value"] = None,
    subcategory: Annotated[str | None, "Subcategory, by label or value"] = None,
    business_impact: Annotated[str | None, "Business impact, by label or value"] = None,
    priority: Annotated[str | None, "Priority, by label or value (e.g. '1 - Critical')"] = None,
    assignment_group: Annotated[str | None, "Assignment group, by name or sys_id"] = None,
    assigned_to: Annotated[str | None, "Assignee, by user name, email, full name or sys_id"] = None,
    unassigned: Annotated[bool, "Only incidents with no assignee"] = False,
    opened_after: Annotated[
        str | None, "Only incidents opened on or after this date (YYYY-MM-DD)"
    ] = None,
    opened_before: Annotated[
        str | None, "Only incidents opened before this date (YYYY-MM-DD)"
    ] = None,
    include_closed: Annotated[bool, "Include closed and cancelled incidents"] = False,
    limit: Annotated[int, f"Maximum incidents to return, up to {_MAX_RESULTS}"] = 25,
    offset: Annotated[int, "Number of matching incidents to skip, for paging"] = 0,
) -> Annotated[dict, "Matching security incidents, most recently updated first"]:
    """Search ServiceNow security incidents (SIR) by text, classification, assignment and date.

    Filters are combined with AND. By default only open incidents are returned.
    Use GetSecurityIncident to read one in full, including secure notes and tags.
    """
    if assigned_to and unassigned:
        raise ToolExecutionError(message="Pass assigned_to or unassigned, not both.")
    conditions = [] if include_closed else ["active=true"]

    if text and text.strip():
        value = encode_query_value(text.strip())
        conditions.append(
            f"numberLIKE{value}^ORshort_descriptionLIKE{value}^ORdescriptionLIKE{value}"
        )

    choice_filters = {
        "state": state,
        "category": category,
        "subcategory": subcategory,
        "business_impact": business_impact,
        "priority": priority,
    }
    matched: dict[str, str] = {}
    for arg, given in choice_filters.items():
        if given is None:
            continue
        element = CHOICE_FIELDS[arg]
        dependent = matched.get("category") if arg == "subcategory" else None
        choices, source = await list_choices(context, element, dependent)
        matched[element] = match_choice(arg, given, choices, source)
        conditions.append(f"{element}={encode_query_value(matched[element])}")

    if assignment_group:
        group = await resolve_group(context, assignment_group)
        conditions.append(f"{ASSIGNMENT_GROUP_FIELD}={group['sys_id']}")
    if assigned_to:
        user = await resolve_user(context, assigned_to)
        conditions.append(f"{ASSIGNED_TO_FIELD}={user['sys_id']}")
    if unassigned:
        conditions.append(f"{ASSIGNED_TO_FIELD}ISEMPTY")

    for arg, given, operator in (
        ("opened_after", opened_after, ">="),
        ("opened_before", opened_before, "<"),
    ):
        if given is None:
            continue
        if not _DATE.match(given.strip()):
            raise RetryableToolError(
                message=f"{arg} must be a date in YYYY-MM-DD format, not '{given}'.",
            )
        conditions.append(f"opened_at{operator}{given.strip()} 00:00:00")

    limit = max(1, min(limit, _MAX_RESULTS))
    offset = max(0, offset)
    response = await servicenow_request(
        context,
        "GET",
        f"/api/now/table/{SIR_TABLE}",
        params={
            "sysparm_query": "^".join([*conditions, "ORDERBYDESCsys_updated_on"]),
            "sysparm_fields": ",".join(SEARCH_FIELDS),
            "sysparm_display_value": "all",
            "sysparm_exclude_reference_link": "true",
            "sysparm_limit": limit,
            "sysparm_offset": offset,
        },
    )
    rows = result_of(response) or []
    header = response.headers.get("X-Total-Count")
    total = int(header) if header and header.isdigit() else None
    incidents = [
        {
            "sys_id": (_field(row, "sys_id") or {}).get("value"),
            "number": (_field(row, "number") or {}).get("value"),
            "fields": {name: _field(row, name) for name in SEARCH_FIELDS[2:]},
        }
        for row in rows
    ]
    more = total is not None and offset + len(rows) < total
    return {
        "incidents": incidents,
        "total_matches": total,
        "next_offset": offset + len(rows) if more else None,
    }


@tool(
    requires_secrets=SERVICE_ACCOUNT_SECRETS,
    metadata=ToolMetadata(
        classification=_CLASSIFICATION,
        behavior=Behavior(
            operations=[Operation.UPDATE],
            read_only=False,
            destructive=False,
            idempotent=False,  # a secure note is appended to the existing notes on every call
            open_world=True,
        ),
    ),
)
async def update_security_incident(
    context: Context,
    incident: _INCIDENT_ARG,
    state: Annotated[str | None, "New state, by label or value (e.g. 'Contain')"] = None,
    category: Annotated[str | None, "Category, by label or value"] = None,
    subcategory: Annotated[
        str | None, "Subcategory, by label or value; must belong to the incident's category"
    ] = None,
    business_impact: Annotated[str | None, "Business impact, by label or value"] = None,
    assignment_group: Annotated[
        str | None, "Assignment group, by name or sys_id. Pass an empty string to clear it"
    ] = None,
    assigned_to: Annotated[
        str | None,
        "Assignee, by user name, email, full name or sys_id; must be a member of the "
        "assignment group. Pass an empty string to clear it",
    ] = None,
    secure_note: Annotated[
        str | None,
        "Text to append to the incident's secure notes, visible only to authorized responders",
    ] = None,
) -> Annotated[dict, "The fields that were changed, with their new values"]:
    """Set a security incident's classification, state and assignment, and optionally add a
    secure note.

    Values are checked against the instance's choice lists, and the assignee against the
    assignment group's members, before anything is written. A secure note is appended
    below any existing secure notes rather than replacing them.
    """
    requested = {
        "state": state,
        "category": category,
        "subcategory": subcategory,
        "business_impact": business_impact,
    }
    assignment = {ASSIGNMENT_GROUP_FIELD: assignment_group, ASSIGNED_TO_FIELD: assigned_to}
    if all(v is None for v in (*requested.values(), *assignment.values())) and secure_note is None:
        raise ToolExecutionError(message="Nothing to update: pass at least one field to set.")

    sys_id = await resolve_sir_sys_id(context, incident)

    # Read what the update depends on: the current category, to validate a
    # subcategory passed on its own; the current group, to check an assignee passed
    # on its own; and the current secure notes, because the field is a single
    # encrypted value and writing it replaces the whole thing.
    current: dict[str, Any] = {}
    needs_category = subcategory is not None and category is None
    needs_group = bool(assigned_to) and assignment_group is None
    if needs_category or needs_group or secure_note:
        response = await servicenow_request(
            context,
            "GET",
            f"/api/now/table/{SIR_TABLE}/{sys_id}",
            params={
                "sysparm_fields": f"category,{ASSIGNMENT_GROUP_FIELD},{SECURE_NOTES_FIELD}",
                "sysparm_exclude_reference_link": "true",
            },
        )
        current = result_of(response) or {}

    payload: dict[str, str] = {}
    for arg, given in requested.items():
        if given is None:
            continue
        element = UPDATABLE_CHOICE_FIELDS[arg]
        # Subcategories depend on the category: the one being set in this call,
        # otherwise the incident's current one.
        dependent = (
            payload.get("category", current.get("category")) if arg == "subcategory" else None
        )
        choices, source = await list_choices(context, element, dependent)
        payload[element] = match_choice(arg, given, choices, source)

    payload.update(await _assignment_payload(context, assignment_group, assigned_to, current))

    if secure_note:
        existing = current.get(SECURE_NOTES_FIELD) or ""
        payload[SECURE_NOTES_FIELD] = f"{existing}\n\n{secure_note}" if existing else secure_note

    # TODO: setting company (a reference to core_company) is not supported yet.
    response = await servicenow_request(
        context,
        "PATCH",
        f"/api/now/table/{SIR_TABLE}/{sys_id}",
        params={"sysparm_display_value": "all", "sysparm_exclude_reference_link": "true"},
        json_body=payload,
    )
    record = result_of(response) or {}
    return {
        "sys_id": sys_id,
        "number": (_field(record, "number") or {}).get("value"),
        "updated": {name: _field(record, name) for name in payload if name != SECURE_NOTES_FIELD},
        "secure_note_added": bool(secure_note),
    }


async def _assignment_payload(
    context: Context,
    assignment_group: str | None,
    assigned_to: str | None,
    current: dict[str, Any],
) -> dict[str, str]:
    """Resolve the assignment arguments to sys_ids, checking the assignee is in the group."""
    payload: dict[str, str] = {}
    group_sys_id = current.get(ASSIGNMENT_GROUP_FIELD) or ""
    group_name = None
    if assignment_group is not None:
        if assignment_group.strip():
            group = await resolve_group(context, assignment_group)
            group_sys_id, group_name = group["sys_id"], group["name"]
        else:
            group_sys_id = ""
        payload[ASSIGNMENT_GROUP_FIELD] = group_sys_id

    if assigned_to is not None:
        if not assigned_to.strip():
            payload[ASSIGNED_TO_FIELD] = ""
            return payload
        user = await resolve_user(context, assigned_to)
        # ServiceNow's form only offers members of the assignment group; the Table API
        # doesn't enforce that, so check it here. Skipped if memberships aren't readable.
        if group_sys_id and await is_group_member(context, user["sys_id"], group_sys_id) is False:
            raise RetryableToolError(
                message=f"{user['name']} is not a member of the assignment group.",
                developer_message=(
                    f"sys_user {user['sys_id']} has no sys_user_grmember row for "
                    f"group {group_sys_id} ({group_name or 'current group'})."
                ),
                additional_prompt_content=(
                    "Assign someone in the group, or set assignment_group to a group "
                    "this user belongs to in the same call."
                ),
            )
        payload[ASSIGNED_TO_FIELD] = user["sys_id"]
    return payload
