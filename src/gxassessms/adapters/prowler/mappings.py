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
# Severity mapping: OCSF severity string (title case) -> Severity
# Source: prowler/lib/outputs/ocsf/ocsf.py
# OCSF severity_id: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 99=Other
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Unknown": Severity.INFO,  # severity_id=0; conservative mapping
}

# ---------------------------------------------------------------------------
# Status mapping: OCSF status_code (UPPERCASE) -> FindingStatus
# Source: prowler check results use PASS/FAIL/MANUAL
# Note: OCSF "status" field is lifecycle status ("New"/"Suppressed"),
# NOT the assessment result. Use status_code for PASS/FAIL/MANUAL.
# ---------------------------------------------------------------------------

STATUS_MAP: dict[str, FindingStatus] = {
    "PASS": FindingStatus.PASS,
    "FAIL": FindingStatus.FAIL,
    "MANUAL": FindingStatus.MANUAL,
}

# ---------------------------------------------------------------------------
# Category mapping: resources[0].group.name -> Category
# Source: Prowler check definitions set the service name as group.name.
# The 23 Azure checks use these service prefixes:
#   defender (12 checks), iam (1), sqlserver (3), storage (7)
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    "defender": Category.INFRASTRUCTURE_SECURITY,
    "iam": Category.IDENTITY_ACCESS,
    "sqlserver": Category.DATA_PROTECTION,
    "storage": Category.DATA_PROTECTION,
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
    "defender_ensure_defender_for_storage_is_on": "cis:azure:5.3.12",
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
