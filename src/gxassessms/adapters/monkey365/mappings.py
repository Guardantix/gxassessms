"""Monkey365 declarative mappings -- data, not logic.

Maps Monkey365 OCSF output values to domain enums and dedup keys.
These dicts are consumed by the parser and by NormalizationPolicy.

Monkey365 uses the OCSF Detection Finding schema. Key fields:
- severity: Title case string (e.g., "High", "Informational")
- statusCode: Lowercase string ("pass", "fail", "manual")
- resources.group.name: Functional domain (e.g., "Entra Identity Governance")
- findingInfo.id: Contains idSuffix for check identity

Verified against source code at /home/guardantix/ToolInspection/monkey365/
and sample output at /home/guardantix/ToolInspection/SampleReports/monkey365-reports/.
"""

from gxassessms.core.domain.enums import Category, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Severity mapping: OCSF severity string (title case) -> Severity
# Source: psocsf/public/Ocsf/SeverityId.cs in Monkey365 source
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Unknown": Severity.INFO,  # severityId=0; conservative mapping
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
# Category mapping: resources.group.name -> Category
# Source: Rule definitions set serviceType which maps to group.name in OCSF.
# Values observed in real output and rule files.
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    "Entra Identity Governance": Category.IDENTITY_ACCESS,
    "Entra ID": Category.IDENTITY_ACCESS,
    "Microsoft Entra ID": Category.IDENTITY_ACCESS,
    "Exchange Online": Category.EMAIL_COLLABORATION,
    "SharePoint Online": Category.DATA_PROTECTION,
    "OneDrive for Business": Category.DATA_PROTECTION,
    "Microsoft Teams": Category.EMAIL_COLLABORATION,
    "Microsoft Purview": Category.COMPLIANCE,
    "Microsoft Fabric": Category.DATA_PROTECTION,
    "Microsoft Defender for Office 365": Category.EMAIL_COLLABORATION,
    "Azure": Category.INFRASTRUCTURE_SECURITY,
    "General": Category.COMPLIANCE,
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
    # CIS M365 Conditional Access controls
    "aad_cap_force_mfa_high_users": "cis:m365:5.2.2.1",
    "aad_cap_force_mfa_all_users": "cis:m365:5.2.2.2",
    "aad_cap_admin_portals_missing": "cis:m365:5.2.2.3",
    # CIS M365 Identity controls
    "aad_lack_cloud_only_accounts": "cis:m365:1.1.1",
    "eid_lack_emergency_account": "cis:m365:1.1.2",
    "eid_excessive_global_admins": "cis:m365:1.1.3",
    # CIS Azure MFA controls
    "aad_privileged_users_with_mfa_disabled": "cis:azure:2.1.2",
    "aad_users_with_mfa_disabled": "cis:azure:2.1.3",
}
