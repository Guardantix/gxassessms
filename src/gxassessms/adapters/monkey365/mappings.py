"""Monkey365 declarative mappings -- data, not logic.

Maps Monkey365 OCSF output values to domain enums and dedup keys.
SEVERITY_MAP, CATEGORY_MAP, and DEDUP_KEY_RULES are consumed by the adapter and
NormalizationPolicy. STATUS_MAP is a reference constant for tests.

Monkey365 uses the OCSF Detection Finding schema. Key fields:
- severity: Title case string (e.g., "High", "Informational")
- statusCode: Lowercase string ("pass", "fail", "manual")
- resources.group.name: Functional domain (e.g., "Entra Identity Governance")
- findingInfo.id: Contains idSuffix for check identity

Verified against Monkey365 source and sample OCSF output.
"""

from gxassessms.core.domain.enums import Category, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Severity mapping: (OCSF severity string, canonical status) -> Severity
# Source: psocsf/public/Ocsf/SeverityId.cs in Monkey365 source
# Keys are (native_severity, canonical_status) tuples matching the contract
# in NormalizationPolicy._resolve_severity().  PASS observations are
# short-circuited to INFO before this map is consulted.
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[tuple[str, str], Severity] = {
    ("Critical", FindingStatus.FAIL): Severity.CRITICAL,
    ("Critical", FindingStatus.MANUAL): Severity.CRITICAL,
    ("High", FindingStatus.FAIL): Severity.HIGH,
    ("High", FindingStatus.MANUAL): Severity.HIGH,
    ("Medium", FindingStatus.FAIL): Severity.MEDIUM,
    ("Medium", FindingStatus.MANUAL): Severity.MEDIUM,
    ("Low", FindingStatus.FAIL): Severity.LOW,
    ("Low", FindingStatus.MANUAL): Severity.LOW,
    ("Informational", FindingStatus.FAIL): Severity.INFO,
    ("Informational", FindingStatus.MANUAL): Severity.INFO,
    ("Unknown", FindingStatus.FAIL): Severity.INFO,  # severityId=0; conservative
    ("Unknown", FindingStatus.MANUAL): Severity.INFO,
}

# ---------------------------------------------------------------------------
# Status mapping: OCSF statusCode (lowercase) -> FindingStatus
# Source: Invoke-RuleScan.ps1 sets pass/fail/manual
# Note: OCSF "status" field is lifecycle status ("New"/"Suppressed"),
# NOT the assessment result. Use statusCode for pass/fail/manual.
# ---------------------------------------------------------------------------

STATUS_MAP: dict[str, FindingStatus] = {
    "pass": FindingStatus.PASS,
    "fail": FindingStatus.FAIL,
    "manual": FindingStatus.MANUAL,
}

# ---------------------------------------------------------------------------
# Category mapping: module prefix (from native_check_id) -> Category
# _extract_module_prefix() extracts the first underscore segment (e.g.,
# aad_lack_cloud_only_accounts -> aad) or second segment for m365_ IDs
# (e.g., m365_exo_transport_rules -> exo).
# Only entries that differ from or extend default_category_map are needed;
# aad, exo, teams, defender, azure are already in the default map.
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    "eid": Category.IDENTITY_ACCESS,
    "spo": Category.DATA_PROTECTION,
    "odb": Category.DATA_PROTECTION,
    "purview": Category.COMPLIANCE,
    "fabric": Category.DATA_PROTECTION,
}

# ---------------------------------------------------------------------------
# Dedup key rules: Monkey365 idSuffix -> finding_key
# Maps Monkey365 rule identifiers to CIS M365 / shared namespace keys.
# idSuffix is extracted from findingInfo.id field.
# Format: "cis:m365:{control_number}" for CIS-mapped controls,
#          "monkey365:{idSuffix}" for tool-scoped controls.
#
# Verified against rule definitions at:
# /home/guardantix/ToolInspection/monkey365/rules/findings/
# ---------------------------------------------------------------------------

DEDUP_KEY_RULES: dict[str, str] = {
    # CIS M365 Section 1.1 -- Identity: Admin Account Governance
    "aad_lack_cloud_only_accounts": "cis:m365:1.1.1",
    "eid_lack_emergency_account": "cis:m365:1.1.2",
    "eid_excessive_global_admins": "cis:m365:1.1.3",
    "eid_pim_privileged_users_reduced_application_footprint_license": "cis:m365:1.1.4",
    "eid_privileged_users_reduced_application_footprint_license": "cis:m365:1.1.4",
    # CIS M365 Section 2.1 -- Defender: Email Security
    "m365_exo_safe_links_office_disabled": "cis:m365:2.1.1",
    "m365_exo_attachment_type_filter_disabled": "cis:m365:2.1.2",
    "m365_exo_anti_malware_admin_notification_disabled": "cis:m365:2.1.3",
    "m365_exo_safe_attachment_policy_disabled": "cis:m365:2.1.4",
    "m365_exo_safe_attachment_policy_office_apps_disabled": "cis:m365:2.1.5",
    "m365_lack_spf_domain": "cis:m365:2.1.8",
    "m365_lack_dkim_in_domain": "cis:m365:2.1.9",
    "m365_lack_dmarc_in_domain": "cis:m365:2.1.10",
    # CIS M365 Section 5.2.2 -- Conditional Access
    "aad_cap_force_mfa_high_users": "cis:m365:5.2.2.1",
    "aad_cap_force_mfa_all_users": "cis:m365:5.2.2.2",
    "eid_cap_block_basic_auth": "cis:m365:5.2.2.3",
    "aad_cap_force_phishing_resistant_mfa_high_priv_users": "cis:m365:5.2.2.5",
    # CIS M365 Section 5.2.3 -- Authentication Methods
    "aad_mfa_fatigue_not_configured": "cis:m365:5.2.3.1",
    "eid_weak_auth_methods_enabled": "cis:m365:5.2.3.5",
    # CIS M365 Section 6 -- Exchange Online
    "m365_exo_mail_forwarding_enabled": "cis:m365:6.2.1",
    # CIS Azure MFA controls
    "aad_privileged_users_with_mfa_disabled": "cis:azure:2.1.2",
    "aad_users_with_mfa_disabled": "cis:azure:2.1.3",
}
