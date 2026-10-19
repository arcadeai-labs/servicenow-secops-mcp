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
    SECURITY_TAG_PSEUDO_FIELD,
    SIR_FIELDS,
    SIR_TABLE,
    SIR_TAG_M2M_RECORD_FIELD,
    SIR_TAG_M2M_TABLE,
    SIR_TAG_M2M_TAG_FIELD,
    UPDATABLE_CHOICE_FIELDS,
)
from servicenow_secops.sir import (
    list_choices,
    list_security_tags,
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
        "'business_impact', or 'security_tag'",
    ],
    category: Annotated[
        str | None,
        "For field='subcategory', only list subcategories of this category value",
    ] = None,
) -> Annotated[dict, "The valid values for the field on this ServiceNow instance"]:
    """List the valid values for a security incident field, as configured on this instance.

    Use this before UpdateSecurityIncident or AddSecurityTag when unsure which values exist.
    """
    field = field.strip().lower()
    if field == SECURITY_TAG_PSEUDO_FIELD:
        tags = await list_security_tags(context)
        return {"field": field, "choices": [{"label": t["name"], "value": t["name"]} for t in tags]}

    if field not in UPDATABLE_CHOICE_FIELDS:
        raise ToolExecutionError(
            message=(
                f"'{field}' is not a supported field. Use one of: "
                f"{', '.join([*UPDATABLE_CHOICE_FIELDS, SECURITY_TAG_PSEUDO_FIELD])}."
            ),
        )

    element = UPDATABLE_CHOICE_FIELDS[field]
    dependent = category if field == "subcategory" else None
    return {"field": field, "choices": await list_choices(context, element, dependent)}


@tool(
    requires_secrets=SERVICE_ACCOUNT_SECRETS,
    metadata=ToolMetadata(
        classification=_CLASSIFICATION,
        behavior=Behavior(
            operations=[Operation.UPDATE],
            read_only=False,
            destructive=False,
            idempotent=False,  # a secure note appends a new journal entry on every call
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
        str | None, "Text to add as a secure note, visible only to authorized responders"
    ] = None,
) -> Annotated[dict, "The fields that were changed, with their new values"]:
    """Set a security incident's classification and state, and optionally add a secure note.

    Values are checked against the instance's choice lists before anything is written.
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

    payload: dict[str, str] = {}
    for arg, given in requested.items():
        if given is None:
            continue
        element = UPDATABLE_CHOICE_FIELDS[arg]
        # Subcategories depend on the category, so validate them against the new
        # category when one is being set in the same call.
        # TODO: when only subcategory is passed, read the incident's current category.
        dependent = payload.get("category") if arg == "subcategory" else None
        payload[element] = match_choice(arg, given, await list_choices(context, element, dependent))

    if secure_note:
        payload[SECURE_NOTES_FIELD] = secure_note

    # TODO: setting organization (a reference field) is not supported yet.
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


@tool(
    requires_secrets=SERVICE_ACCOUNT_SECRETS,
    metadata=ToolMetadata(
        classification=_CLASSIFICATION,
        behavior=Behavior(
            operations=[Operation.CREATE],
            read_only=False,
            destructive=False,
            idempotent=True,
            open_world=True,
        ),
    ),
)
async def add_security_tag(
    context: Context,
    incident: _INCIDENT_ARG,
    tag: Annotated[str, "Name of the security tag to apply (e.g. 'Phishing')"],
) -> Annotated[dict, "The tags on the incident after the change"]:
    """Apply a security tag to a security incident. Does nothing if the tag is already applied."""
    sys_id = await resolve_sir_sys_id(context, incident)

    tags = await list_security_tags(context)
    name = match_choice(
        SECURITY_TAG_PSEUDO_FIELD, tag, [{"label": t["name"], "value": t["name"]} for t in tags]
    )
    wanted = next(t for t in tags if t["name"] == name)

    current = await tags_on_incident(context, sys_id)
    if any(t["tag_sys_id"] == wanted["sys_id"] for t in current):
        return {"sys_id": sys_id, "added": False, "security_tags": current}

    await servicenow_request(
        context,
        "POST",
        f"/api/now/table/{SIR_TAG_M2M_TABLE}",
        json_body={
            SIR_TAG_M2M_RECORD_FIELD: sys_id,
            SIR_TAG_M2M_TAG_FIELD: wanted["sys_id"],
        },
    )
    return {
        "sys_id": sys_id,
        "added": True,
        "security_tags": await tags_on_incident(context, sys_id),
    }
