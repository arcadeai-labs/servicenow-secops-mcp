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

# Secure notes live on sm_order as a single encrypted field (glide_encrypted), not
# a journal: a write replaces the whole value. Reading and writing it requires the
# encryption context SIR assigns to its secure-notes role, so the service account
# needs that role or the field reads back empty.
SECURE_NOTES_FIELD = "secure_notes"

# Security tag definitions, and the table that applies a tag to any record. An
# applied tag points at its record with a document_id pair (record_table +
# record_id). sn_si_incident also has a security_tags list field, but the demo
# data populates the applied-tag table, so that is the one read and written here.
SECURITY_TAG_TABLE = "sn_sec_cmn_security_tag"
APPLIED_TAG_TABLE = "sn_sec_cmn_applied_security_tag"
APPLIED_TAG_RECORD_TABLE_FIELD = "record_table"
APPLIED_TAG_RECORD_ID_FIELD = "record_id"
APPLIED_TAG_TAG_FIELD = "security_tag"

SECURITY_TAG_PSEUDO_FIELD = "security_tag"
