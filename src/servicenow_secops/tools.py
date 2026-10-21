"""Tools for working ServiceNow Security Incident Response (SIR) incidents."""

from typing import Annotated, Any

from arcade_mcp_server import Context, tool
from arcade_mcp_server.exceptions import ToolExecutionError
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
    SECURE_NOTES_FIELD,
    SIR_FIELDS,
    SIR_TABLE,
    UPDATABLE_CHOICE_FIELDS,
)
from servicenow_secops.sir import (
    OBSERVED,
    list_choices,
    match_choice,
    resolve_sir_sys_id,
    tags_on_incident,
)

_CLASSIFICATION = Classification(service_domains=[ServiceDomain.INCIDENT_MANAGEMENT])

_INCIDENT_ARG = Annotated[str, "Security incident number (e.g. 'SIR0010001') or its sys_id"]


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
        "or 'business_impact'",
    ],
    category: Annotated[
        str | None,
        "For field='subcategory', only list subcategories of this category value",
    ] = None,
) -> Annotated[dict, "The valid values for the field on this ServiceNow instance"]:
    """List the valid values for a security incident field, as configured on this instance.

    Use this before UpdateSecurityIncident when unsure which values exist.
    """
    field = field.strip().lower()
    if field not in UPDATABLE_CHOICE_FIELDS:
        raise ToolExecutionError(
            message=(
                f"'{field}' is not a supported field. Use one of: "
                f"{', '.join(UPDATABLE_CHOICE_FIELDS)}."
            ),
        )

    element = UPDATABLE_CHOICE_FIELDS[field]
    dependent = category if field == "subcategory" else None
    choices, source = await list_choices(context, element, dependent)
    result: dict[str, Any] = {"field": field, "source": source, "choices": choices}
    if source == OBSERVED:
        result["note"] = (
            "The service account can't read the instance's choice lists, so these are the "
            "values existing incidents use. The instance may define others."
        )
    return result


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
    secure_note: Annotated[
        str | None,
        "Text to append to the incident's secure notes, visible only to authorized responders",
    ] = None,
) -> Annotated[dict, "The fields that were changed, with their new values"]:
    """Set a security incident's classification and state, and optionally add a secure note.

    Values are checked against the instance's choice lists before anything is written.
    A secure note is appended below any existing secure notes rather than replacing them.
    """
    requested = {
        "state": state,
        "category": category,
        "subcategory": subcategory,
        "business_impact": business_impact,
    }
    if all(v is None for v in requested.values()) and secure_note is None:
        raise ToolExecutionError(message="Nothing to update: pass at least one field to set.")

    sys_id = await resolve_sir_sys_id(context, incident)

    # Read what the update depends on: the current category, to validate a
    # subcategory passed on its own, and the current secure notes, because the
    # field is a single encrypted value and writing it replaces the whole thing.
    current: dict[str, Any] = {}
    needs_category = subcategory is not None and category is None
    if needs_category or secure_note:
        response = await servicenow_request(
            context,
            "GET",
            f"/api/now/table/{SIR_TABLE}/{sys_id}",
            params={"sysparm_fields": f"category,{SECURE_NOTES_FIELD}"},
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
