"""Table and field names for ServiceNow Security Incident Response (SIR).

Verified against Security Incident Response 14.4.4 with demo data on a
Brazil-release instance (2026-10-20). SIR schemas can differ between plugin
versions, so re-check them (sys_db_object / sys_dictionary) on older releases.
"""

SIR_TABLE = "sn_si_incident"

# sn_si_incident extends sm_order, which extends task. SIR defines its own choice
# lists on sn_si_incident; the parents are a fallback for instances that don't.
CHOICE_FALLBACK_TABLES = ("sm_order", "task")

# Fields returned by GetSecurityIncident.
SIR_FIELDS = [
    "sys_id",
    "number",
    "short_description",
    "description",
    "state",
    "substate",
    "priority",
    "category",
    "subcategory",
    "business_criticality",  # labelled "Business impact" on SIR
    "company",  # reference to core_company, inherited from task
    "assignment_group",
    "assigned_to",
    "opened_at",
    "sys_updated_on",
]

# Choice fields UpdateSecurityIncident may set, keyed by the tool's argument name.
# Subcategory choices depend on the category's stored value.
UPDATABLE_CHOICE_FIELDS = {
    "state": "state",
    "category": "category",
    "subcategory": "subcategory",
    "business_impact": "business_criticality",
}

# Choice fields SearchSecurityIncidents and ListSecurityIncidentFieldChoices accept:
# the updatable ones, plus priority (calculated from impact and urgency, so not set here).
CHOICE_FIELDS = {**UPDATABLE_CHOICE_FIELDS, "priority": "priority"}

# Assignment is a pair of references inherited from task. The tools accept a group's
# name or sys_id, and a user's user_name, email, full name or sys_id, and resolve them
# through the Table API (sn_si.analyst can read sys_user, sys_user_group and
# sys_user_grmember in testing).
ASSIGNED_TO_FIELD = "assigned_to"
ASSIGNMENT_GROUP_FIELD = "assignment_group"

# Fields returned for each match by SearchSecurityIncidents.
SEARCH_FIELDS = [
    "sys_id",
    "number",
    "short_description",
    "state",
    "priority",
    "category",
    "subcategory",
    "business_criticality",
    ASSIGNMENT_GROUP_FIELD,
    ASSIGNED_TO_FIELD,
    "opened_at",
    "sys_updated_on",
]

# Secure notes live on sm_order as a single encrypted field (glide_encrypted), not
# a journal: a write replaces the whole value, so updates read it and append. The
# sn_si.analyst role could read and write it in testing; an account that can't read
# it would see it empty and overwrite earlier notes.
SECURE_NOTES_FIELD = "secure_notes"

# Security tags applied to an incident, read by GetSecurityIncident. An applied tag
# points at its record with a document_id pair (record_table + record_id). SIR only
# lets server-side code create these rows, and offers no out-of-the-box API for it,
# so this server reads tags but doesn't apply them. The incident's security_tags
# list field is filled in from these rows, not the other way round.
APPLIED_TAG_TABLE = "sn_sec_cmn_applied_security_tag"
APPLIED_TAG_RECORD_TABLE_FIELD = "record_table"
APPLIED_TAG_RECORD_ID_FIELD = "record_id"
APPLIED_TAG_TAG_FIELD = "security_tag"
