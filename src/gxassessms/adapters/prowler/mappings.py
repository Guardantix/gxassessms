"""Prowler declarative mappings -- data, not logic.

Maps Prowler OCSF output values to domain enums and dedup keys.
These dicts are consumed by the parser and by NormalizationPolicy.

Prowler uses the OCSF Detection Finding schema (snake_case keys). Key fields:
- severity: Title case string (e.g., "High", "Informational")
- status_code: UPPERCASE string ("PASS", "FAIL", "MANUAL")
- resources[0].group.name: Service name (e.g., "defender", "storage")
- metadata.event_code: Check ID (e.g., "defender_ensure_defender_for_app_services_is_on")

IMPORTANT: Prowler status_code is UPPERCASE (unlike Monkey365 which is lowercase).

Verified against Prowler source code at /home/guardantix/ToolInspection/prowler/.
"""

from __future__ import annotations

from gxassessms.core.domain.enums import Category, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Severity mapping: (OCSF severity, canonical status) -> Severity
# Source: prowler/lib/outputs/ocsf/ocsf.py
# OCSF severity_id: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 99=Other
#
# Keys are (severity_string, domain_status) tuples to match
# DefaultNormalizationPolicy._resolve_severity() lookup.
# PASS observations short-circuit to INFO before consulting this map,
# so only FAIL and MANUAL entries are needed.
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[tuple[str, str], Severity] = {
    # FAIL entries -- direct assessment results
    ("Critical", FindingStatus.FAIL): Severity.CRITICAL,
    ("High", FindingStatus.FAIL): Severity.HIGH,
    ("Medium", FindingStatus.FAIL): Severity.MEDIUM,
    ("Low", FindingStatus.FAIL): Severity.LOW,
    ("Informational", FindingStatus.FAIL): Severity.LOW,
    ("Unknown", FindingStatus.FAIL): Severity.MEDIUM,
    # MANUAL entries -- requires human verification, preserve reported severity
    ("Critical", FindingStatus.MANUAL): Severity.CRITICAL,
    ("High", FindingStatus.MANUAL): Severity.HIGH,
    ("Medium", FindingStatus.MANUAL): Severity.MEDIUM,
    ("Low", FindingStatus.MANUAL): Severity.LOW,
    ("Informational", FindingStatus.MANUAL): Severity.LOW,
    ("Unknown", FindingStatus.MANUAL): Severity.MEDIUM,
}

# ---------------------------------------------------------------------------
# Status mapping: OCSF status_code (UPPERCASE) -> FindingStatus
# Source: prowler check results use PASS/FAIL/MANUAL
# Note: OCSF "status" field is lifecycle status ("New"/"Suppressed"),
# NOT the assessment result. Use status_code for PASS/FAIL/MANUAL.
# ---------------------------------------------------------------------------

STATUS_MAP: dict[str, FindingStatus] = {
    FindingStatus.PASS: FindingStatus.PASS,
    FindingStatus.FAIL: FindingStatus.FAIL,
    FindingStatus.MANUAL: FindingStatus.MANUAL,
}

# ---------------------------------------------------------------------------
# Category mapping: check ID (metadata.event_code) -> Category
#
# Keyed by full check ID because _extract_module_prefix uses dot-delimited
# parsing which doesn't apply to Prowler's underscore-delimited IDs.
# Service grouping: defender -> INFRASTRUCTURE_SECURITY, iam -> IDENTITY_ACCESS,
# sqlserver/storage -> DATA_PROTECTION.
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    # Defender checks (12)
    "defender_ensure_defender_for_app_services_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_arm_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_azure_sql_databases_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_containers_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_cosmosdb_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_databases_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_dns_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_keyvault_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_os_relational_databases_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_server_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_sql_servers_is_on": Category.INFRASTRUCTURE_SECURITY,
    "defender_ensure_defender_for_storage_is_on": Category.INFRASTRUCTURE_SECURITY,
    # IAM checks (1)
    "iam_subscription_roles_owner_custom_not_created": Category.IDENTITY_ACCESS,
    # SQL Server checks (3)
    "sqlserver_auditing_enabled": Category.DATA_PROTECTION,
    "sqlserver_azuread_administrator_enabled": Category.DATA_PROTECTION,
    "sqlserver_unrestricted_inbound_access": Category.DATA_PROTECTION,
    # Storage checks (7)
    "storage_blob_public_access_level_is_disabled": Category.DATA_PROTECTION,
    "storage_default_network_access_rule_is_denied": Category.DATA_PROTECTION,
    "storage_ensure_azure_services_are_trusted_to_access_is_enabled": Category.DATA_PROTECTION,
    "storage_ensure_encryption_with_customer_managed_keys": Category.DATA_PROTECTION,
    "storage_ensure_minimum_tls_version_12": Category.DATA_PROTECTION,
    "storage_infrastructure_encryption_is_enabled": Category.DATA_PROTECTION,
    "storage_secure_transfer_required_is_enabled": Category.DATA_PROTECTION,
}

# ---------------------------------------------------------------------------
# Dedup key rules: Prowler check ID (metadata.event_code) -> finding_key
# Maps Prowler check identifiers to CIS Azure / shared namespace keys.
# Format: "cis:azure:{control_number}" for CIS-mapped controls,
#          "prowler:{check_id}" for tool-scoped controls.
#
# CIS references are from unmapped.compliance in OCSF output.
# Using CIS-2.1 control numbers as the canonical reference.
#
# Verified against Prowler Azure check definitions at:
# /home/guardantix/ToolInspection/prowler/prowler/providers/azure/services/
# ---------------------------------------------------------------------------

DEDUP_KEY_RULES: dict[str, str] = {
    # Defender checks (CIS Azure 2.1 Section 5.3)
    "defender_ensure_defender_for_app_services_is_on": "cis:azure:5.3.1",
    "defender_ensure_defender_for_arm_is_on": "cis:azure:5.3.2",
    "defender_ensure_defender_for_azure_sql_databases_is_on": "cis:azure:5.3.3",
    "defender_ensure_defender_for_containers_is_on": "cis:azure:5.3.4",
    "defender_ensure_defender_for_cosmosdb_is_on": "cis:azure:5.3.5",
    "defender_ensure_defender_for_databases_is_on": "cis:azure:5.3.6",
    "defender_ensure_defender_for_dns_is_on": "cis:azure:5.3.7",
    "defender_ensure_defender_for_keyvault_is_on": "cis:azure:5.3.8",
    "defender_ensure_defender_for_os_relational_databases_is_on": "cis:azure:5.3.9",
    "defender_ensure_defender_for_server_is_on": "cis:azure:5.3.10",
    "defender_ensure_defender_for_sql_servers_is_on": "cis:azure:5.3.11",
    "defender_ensure_defender_for_storage_is_on": "cis:azure:5.1.7",
    # IAM checks (CIS Azure 2.1 Section 1)
    "iam_subscription_roles_owner_custom_not_created": "cis:azure:1.23",
    # SQL Server checks (CIS Azure 2.1 Section 4.1)
    "sqlserver_auditing_enabled": "cis:azure:4.1.1",
    "sqlserver_azuread_administrator_enabled": "cis:azure:4.1.4",
    "sqlserver_unrestricted_inbound_access": "cis:azure:4.1.2",
    # Storage checks (CIS Azure 2.1 Section 3)
    "storage_blob_public_access_level_is_disabled": "cis:azure:3.7",
    "storage_default_network_access_rule_is_denied": "cis:azure:3.8",
    "storage_ensure_azure_services_are_trusted_to_access_is_enabled": "cis:azure:3.9",
    "storage_ensure_encryption_with_customer_managed_keys": "cis:azure:3.2",
    "storage_ensure_minimum_tls_version_12": "cis:azure:3.15",
    "storage_infrastructure_encryption_is_enabled": "cis:azure:3.3",
    "storage_secure_transfer_required_is_enabled": "cis:azure:3.1",
}

# ---------------------------------------------------------------------------
# Auth method mapping: Engagement config AuthMethod -> Prowler CLI auth flags
#
# Maps client-provided auth methods to Prowler command-line flags:
#   client_credential -> --sp-env-auth (service principal via env vars)
#   device_code       -> --browser-auth (closest Prowler equivalent)
#   interactive       -> --browser-auth
#
# For Prowler-specific methods (az_cli, managed_identity), the operator
# overrides via extra_args: ["--az-cli-auth"] or ["--managed-identity-auth"].
# ---------------------------------------------------------------------------

AUTH_METHOD_MAP: dict[str, list[str]] = {
    "client_credential": ["--sp-env-auth"],
    "device_code": ["--browser-auth"],
    "interactive": ["--browser-auth"],
}

# All Prowler CLI authentication flags. When any of these appear in extra_args,
# the adapter skips the mapped auth flags to avoid conflicting auth modes.
PROWLER_AUTH_FLAGS: frozenset[str] = frozenset(
    ["--sp-env-auth", "--browser-auth", "--az-cli-auth", "--managed-identity-auth"]
)
