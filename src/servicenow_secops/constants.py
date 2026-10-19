"""Table and field names for ServiceNow Security Incident Response (SIR).

Entries marked UNVERIFIED have not been checked against a live SIR instance. Confirm
them in the customer's instance (sys_db_object / sys_dictionary) before relying on
them; SIR schemas differ between plugin versions.
"""

SIR_TABLE = "sn_si_incident"

# SIR choice lists (state in particular) may be defined on the parent task table
# rather than on sn_si_incident itself, so choice lookups fall back to it.
CHOICE_FALLBACK_TABLE = "task"

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
    "business_criticality",  # UNVERIFIED: the field behind "Business impact"
    "company",  # UNVERIFIED: the field behind "Organization"
    "assignment_group",
    "assigned_to",
    "opened_at",
    "sys_updated_on",
]

# Choice fields UpdateSecurityIncident may set, keyed by the tool's argument name.
UPDATABLE_CHOICE_FIELDS = {
    "state": "state",
    "category": "category",
    "subcategory": "subcategory",
    "business_impact": "business_criticality",  # UNVERIFIED
}

# UNVERIFIED: the journal field SIR uses for secure notes, which are visible only
# to users holding the secure-notes role. Confirm the name and that the service
# account holds that role.
SECURE_NOTES_FIELD = "secure_notes"

# UNVERIFIED: security tag definitions and the many-to-many table linking tags to
# security incidents.
SECURITY_TAG_TABLE = "sn_sec_cmn_security_tag"
SIR_TAG_M2M_TABLE = "sn_sec_cmn_m2m_security_tag"
SIR_TAG_M2M_RECORD_FIELD = "record"  # UNVERIFIED: reference to the SIR
SIR_TAG_M2M_TAG_FIELD = "security_tag"  # UNVERIFIED: reference to the tag

SECURITY_TAG_PSEUDO_FIELD = "security_tag"
