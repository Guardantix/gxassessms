"""M365-Assess declarative mappings -- data, not logic.

Maps M365-Assess output values to domain enums.

M365-Assess outputs CSV files with 7 columns:
  Category, Setting, CurrentValue, RecommendedValue, Status, CheckId, Remediation

Severity comes from a separate risk-severity.json file.
Framework mappings come from registry.json.

CheckId format: {COLLECTOR}-{AREA}-{NNN}.{N}
  - Base CheckId (without .N): key into risk-severity.json and registry.json
  - Collector prefix: first segment before first hyphen -> category

Verified against source code and sample output.
"""

import re

from gxassessms.core.domain.enums import Category, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Status mapping: CSV Status column (title case) -> FindingStatus
# 6 values confirmed from source (SecurityConfigHelper.ps1) and sample output.
# ---------------------------------------------------------------------------

STATUS_MAP: dict[str, FindingStatus] = {
    "Pass": FindingStatus.PASS,
    "Fail": FindingStatus.FAIL,
    "Warning": FindingStatus.WARNING,
    "Review": FindingStatus.MANUAL,  # Requires manual assessment
    "Info": FindingStatus.NOT_APPLICABLE,  # Informational, not actionable
    "Unknown": FindingStatus.ERROR,  # Fallback from SecurityConfigHelper
}

# ---------------------------------------------------------------------------
# Severity mapping: (native_severity_str, canonical_status) -> Severity
#
# Keys use the raw severity string from risk-severity.json paired with the
# canonical status value (after default_status_map normalization).  This
# matches the (native_severity, _mapped) tuple looked up by
# DefaultNormalizationPolicy._resolve_severity().
#
# M365-Assess severity is status-independent: a "High" risk check is HIGH
# regardless of whether it FAILed or produced a WARNING.  PASS and N/A
# observations are short-circuited to INFO by the normalization policy before
# this map is consulted, so those statuses are intentionally absent.
# ---------------------------------------------------------------------------

_SEVERITY_BASE: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Info": Severity.INFO,
}

# Canonical status values produced by default_status_map for non-passing checks
_ACTIONABLE_STATUSES: tuple[str, ...] = (
    FindingStatus.FAIL,
    FindingStatus.WARNING,
    FindingStatus.MANUAL,
    FindingStatus.ERROR,
)

SEVERITY_MAP: dict[tuple[str, str], Severity] = {
    (sev_str, status): sev_enum
    for sev_str, sev_enum in _SEVERITY_BASE.items()
    for status in _ACTIONABLE_STATUSES
}

# Guard: _ACTIONABLE_STATUSES must stay in sync with the non-passing FindingStatus members.
# If FindingStatus gains a new non-passing status, add it here too.
_EXPECTED_ACTIONABLE: frozenset[FindingStatus] = frozenset(
    {FindingStatus.FAIL, FindingStatus.WARNING, FindingStatus.MANUAL, FindingStatus.ERROR}
)
if frozenset(_ACTIONABLE_STATUSES) != _EXPECTED_ACTIONABLE:
    raise ValueError(
        "SEVERITY_MAP: _ACTIONABLE_STATUSES is out of sync with FindingStatus non-passing members. "
        "Update _ACTIONABLE_STATUSES when adding new non-passing FindingStatus values."
    )

# ---------------------------------------------------------------------------
# Category mapping: CheckId collector prefix -> Category
# The collector prefix is the first segment of the CheckId before the
# first hyphen (e.g., "ENTRA" from "ENTRA-ADMIN-001").
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    "entra": Category.IDENTITY_ACCESS,
    "ca": Category.IDENTITY_ACCESS,
    "entapp": Category.IDENTITY_ACCESS,
    "exo": Category.EMAIL_COLLABORATION,
    "dns": Category.EMAIL_COLLABORATION,
    "defender": Category.EMAIL_COLLABORATION,
    "spo": Category.DATA_PROTECTION,
    "teams": Category.EMAIL_COLLABORATION,
    "forms": Category.EMAIL_COLLABORATION,
    "intune": Category.DEVICE_MANAGEMENT,
    "compliance": Category.COMPLIANCE,
    "purview": Category.COMPLIANCE,
    "powerbi": Category.DATA_PROTECTION,
}

# ---------------------------------------------------------------------------
# Dedup key rules: full CheckId (with .N suffix) -> canonical cross-reference ID
# Maps M365-Assess checks to CIS benchmark control IDs where known.
#
# Keys use the full subcheck ID as it appears in CSV output (e.g., "ENTRA-X-001.1"),
# not the base CheckId, because SecurityConfigHelper.ps1 auto-appends .N to every
# row before writing the CSV, and the normalization engine does an exact key lookup.
# Cross-references sourced from src/gxassessms/mappings/cis-m365-crossref.yaml.
# ---------------------------------------------------------------------------

DEDUP_KEY_RULES: dict[str, str] = {
    # --- CIS Section 1 ---
    "ENTRA-CLOUDADMIN-001.1": "cis:m365:1.1.1",
    "ENTRA-SYNCADMIN-001.1": "cis:m365:1.1.1",
    "ENTRA-ADMIN-003.1": "cis:m365:1.1.2",
    "ENTRA-ADMIN-001.1": "cis:m365:1.1.3",
    "ENTRA-CLOUDADMIN-002.1": "cis:m365:1.1.4",
    "ENTRA-BREAKGLASS-001.1": "cis:m365:1.1.4",
    "ENTRA-GROUP-003.1": "cis:m365:1.2.1",
    "EXO-SHAREDMBX-001.1": "cis:m365:1.2.2",
    "ENTRA-PASSWORD-001.1": "cis:m365:1.3.1",
    "ENTRA-PASSWORD-001.2": "cis:m365:1.3.1",
    "SPO-SESSION-001.1": "cis:m365:1.3.2",
    "EXO-SHARING-001.1": "cis:m365:1.3.3",
    "ENTRA-ORGSETTING-001.1": "cis:m365:1.3.4",
    "ENTRA-ORGSETTING-002.1": "cis:m365:1.3.5",
    "EXO-LOCKBOX-001.1": "cis:m365:1.3.6",
    "ENTRA-ORGSETTING-003.1": "cis:m365:1.3.7",
    "ENTRA-ORGSETTING-004.1": "cis:m365:1.3.9",
    # --- CIS Section 2 ---
    "DEFENDER-SAFELINKS-001.1": "cis:m365:2.1.1",
    "DEFENDER-SAFELINKS-001.2": "cis:m365:2.1.1",
    "DEFENDER-SAFELINKS-001.3": "cis:m365:2.1.1",
    "DEFENDER-SAFELINKS-001.4": "cis:m365:2.1.1",
    "DEFENDER-ANTIMALWARE-001.1": "cis:m365:2.1.2",
    "DEFENDER-ANTIMALWARE-001.2": "cis:m365:2.1.2",
    "DEFENDER-ANTIMALWARE-002.1": "cis:m365:2.1.3",
    "DEFENDER-SAFEATTACH-001.1": "cis:m365:2.1.4",
    "DEFENDER-SAFEATTACH-001.2": "cis:m365:2.1.4",
    "DEFENDER-SAFEATTACH-001.3": "cis:m365:2.1.4",
    "DEFENDER-SAFEATTACH-002.1": "cis:m365:2.1.5",
    "DEFENDER-ANTISPAM-001.1": "cis:m365:2.1.6",
    "DEFENDER-ANTISPAM-001.2": "cis:m365:2.1.6",
    "DEFENDER-ANTISPAM-001.3": "cis:m365:2.1.6",
    "DEFENDER-ANTISPAM-001.4": "cis:m365:2.1.6",
    "DEFENDER-ANTISPAM-001.5": "cis:m365:2.1.6",
    "DEFENDER-ANTISPAM-001.6": "cis:m365:2.1.6",
    "DEFENDER-ANTISPAM-001.7": "cis:m365:2.1.6",
    "DEFENDER-ANTISPAM-001.8": "cis:m365:2.1.6",
    "DEFENDER-ANTIPHISH-001.1": "cis:m365:2.1.7",
    "DNS-SPF-001.1": "cis:m365:2.1.8",
    "DNS-DKIM-001.1": "cis:m365:2.1.9",
    "DNS-DMARC-001.1": "cis:m365:2.1.10",
    "DEFENDER-MALWARE-002.1": "cis:m365:2.1.11",
    "EXO-CONNFILTER-001.1": "cis:m365:2.1.12",
    "EXO-CONNFILTER-002.1": "cis:m365:2.1.13",
    "DEFENDER-ANTISPAM-002.1": "cis:m365:2.1.14",
    "DEFENDER-OUTBOUND-001.1": "cis:m365:2.1.15",
    "DEFENDER-OUTBOUND-001.2": "cis:m365:2.1.15",
    "DEFENDER-OUTBOUND-001.3": "cis:m365:2.1.15",
    "DEFENDER-PRIORITY-001.1": "cis:m365:2.4.1",
    "DEFENDER-PRIORITY-002.1": "cis:m365:2.4.2",
    "DEFENDER-ZAP-001.1": "cis:m365:2.4.4",
    # --- CIS Section 3 ---
    "COMPLIANCE-AUDIT-001.1": "cis:m365:3.1.1",
    "COMPLIANCE-DLP-001.1": "cis:m365:3.2.1",
    "COMPLIANCE-DLP-002.1": "cis:m365:3.2.2",
    "COMPLIANCE-LABELS-001.1": "cis:m365:3.3.1",
    "FORMS-CONFIG-001.1": "cis:m365:3.6.1",
    "FORMS-CONFIG-002.1": "cis:m365:3.6.1",
    "FORMS-CONFIG-004.1": "cis:m365:3.6.2",
    # --- CIS Section 4 ---
    "INTUNE-COMPLIANCE-001.1": "cis:m365:4.1",
    "INTUNE-ENROLL-001.1": "cis:m365:4.2",
    # --- CIS Section 5 ---
    "ENTRA-PERUSER-001.1": "cis:m365:5.1.2.1",
    "CA-EXCLUSION-001.1": "cis:m365:5.1.2.1",
    "ENTRA-APPS-001.1": "cis:m365:5.1.2.2",
    "ENTRA-TENANT-001.1": "cis:m365:5.1.2.3",
    "ENTRA-ADMIN-002.1": "cis:m365:5.1.2.4",
    "ENTRA-LINKEDIN-001.1": "cis:m365:5.1.2.6",
    "ENTRA-GROUP-002.1": "cis:m365:5.1.3.1",
    "ENTRA-GROUP-001.1": "cis:m365:5.1.3.2",
    "ENTRA-DEVICE-001.1": "cis:m365:5.1.4.1",
    "ENTRA-DEVICE-002.1": "cis:m365:5.1.4.2",
    "ENTRA-DEVICE-003.1": "cis:m365:5.1.4.3",
    "ENTRA-DEVICE-004.1": "cis:m365:5.1.4.4",
    "ENTRA-DEVICE-005.1": "cis:m365:5.1.4.5",
    "ENTRA-DEVICE-006.1": "cis:m365:5.1.4.6",
    "ENTRA-CONSENT-001.1": "cis:m365:5.1.5.1",
    "ENTRA-CONSENT-002.1": "cis:m365:5.1.5.2",
    "ENTRA-GUEST-004.1": "cis:m365:5.1.6.1",
    "ENTRA-GUEST-001.1": "cis:m365:5.1.6.2",
    "ENTRA-GUEST-002.1": "cis:m365:5.1.6.3",
    "ENTRA-HYBRID-001.1": "cis:m365:5.1.8.1",
    "CA-MFA-ADMIN-001.1": "cis:m365:5.2.2.1",
    "CA-MFA-ALL-001.1": "cis:m365:5.2.2.2",
    "CA-LEGACYAUTH-001.1": "cis:m365:5.2.2.3",
    "ENTRA-CA-001.1": "cis:m365:5.2.2.3",
    "CA-SIGNIN-FREQ-001.1": "cis:m365:5.2.2.4",
    "CA-PHISHRES-001.1": "cis:m365:5.2.2.5",
    "CA-USERRISK-001.1": "cis:m365:5.2.2.6",
    "CA-SIGNINRISK-001.1": "cis:m365:5.2.2.7",
    "CA-SIGNINRISK-002.1": "cis:m365:5.2.2.8",
    "CA-DEVICE-001.1": "cis:m365:5.2.2.9",
    "CA-DEVICE-002.1": "cis:m365:5.2.2.10",
    "CA-INTUNE-001.1": "cis:m365:5.2.2.11",
    "CA-DEVICECODE-001.1": "cis:m365:5.2.2.12",
    "ENTRA-AUTHMETHOD-003.1": "cis:m365:5.2.3.1",
    "ENTRA-PASSWORD-002.1": "cis:m365:5.2.3.2",
    "ENTRA-PASSWORD-005.1": "cis:m365:5.2.3.3",
    "ENTRA-MFA-001.1": "cis:m365:5.2.3.4",
    "ENTRA-AUTHMETHOD-001.1": "cis:m365:5.2.3.5",
    "ENTRA-AUTHMETHOD-001.2": "cis:m365:5.2.3.5",
    "ENTRA-AUTHMETHOD-004.1": "cis:m365:5.2.3.6",
    "ENTRA-AUTHMETHOD-002.1": "cis:m365:5.2.3.7",
    "ENTRA-SSPR-001.1": "cis:m365:5.2.4.1",
    "ENTRA-PIM-001.1": "cis:m365:5.3.1",
    "ENTRA-PIM-002.1": "cis:m365:5.3.2",
    "ENTRA-PIM-003.1": "cis:m365:5.3.3",
    "ENTRA-PIM-004.1": "cis:m365:5.3.4",
    "ENTRA-PIM-005.1": "cis:m365:5.3.5",
    # --- CIS Section 6 ---
    "EXO-AUDIT-001.1": "cis:m365:6.1.1",
    "EXO-AUDIT-003.1": "cis:m365:6.1.2",
    "EXO-AUDIT-002.1": "cis:m365:6.1.3",
    "EXO-FORWARD-001.1": "cis:m365:6.2.1",
    "EXO-TRANSPORT-001.1": "cis:m365:6.2.2",
    "EXO-EXTTAG-001.1": "cis:m365:6.2.3",
    "EXO-ADDINS-001.1": "cis:m365:6.3.1",
    "EXO-AUTH-001.1": "cis:m365:6.5.1",
    "EXO-MAILTIPS-001.1": "cis:m365:6.5.2",
    "EXO-OWA-001.1": "cis:m365:6.5.3",
    "EXO-AUTH-002.1": "cis:m365:6.5.4",
    "EXO-DIRECTSEND-001.1": "cis:m365:6.5.5",
    # --- CIS Section 7 ---
    "SPO-AUTH-001.1": "cis:m365:7.2.1",
    "SPO-B2B-001.1": "cis:m365:7.2.2",
    "SPO-SHARING-001.1": "cis:m365:7.2.3",
    "SPO-OD-001.1": "cis:m365:7.2.4",
    "SPO-SHARING-002.1": "cis:m365:7.2.5",
    "SPO-SHARING-003.1": "cis:m365:7.2.6",
    "SPO-SHARING-004.1": "cis:m365:7.2.7",
    "SPO-SHARING-008.1": "cis:m365:7.2.8",
    "SPO-SHARING-005.1": "cis:m365:7.2.9",
    "SPO-SHARING-006.1": "cis:m365:7.2.10",
    "SPO-SHARING-007.1": "cis:m365:7.2.11",
    "SPO-MALWARE-002.1": "cis:m365:7.3.1",
    "SPO-SYNC-001.1": "cis:m365:7.3.2",
    "SPO-SCRIPT-001.1": "cis:m365:7.3.3",
    "SPO-SCRIPT-002.1": "cis:m365:7.3.4",
    # --- CIS Section 8 ---
    "TEAMS-CLIENT-001.1": "cis:m365:8.1.1",
    "TEAMS-CLIENT-002.1": "cis:m365:8.1.2",
    "TEAMS-EXTACCESS-003.1": "cis:m365:8.2.1",
    "TEAMS-EXTACCESS-001.1": "cis:m365:8.2.2",
    "TEAMS-EXTACCESS-002.1": "cis:m365:8.2.3",
    "TEAMS-EXTACCESS-004.1": "cis:m365:8.2.4",
    "TEAMS-APPS-002.1": "cis:m365:8.4.1",
    "TEAMS-MEETING-001.1": "cis:m365:8.5.1",
    "TEAMS-MEETING-002.1": "cis:m365:8.5.2",
    "TEAMS-MEETING-003.1": "cis:m365:8.5.3",
    "TEAMS-MEETING-004.1": "cis:m365:8.5.4",
    "TEAMS-MEETING-006.1": "cis:m365:8.5.5",
    "TEAMS-MEETING-007.1": "cis:m365:8.5.6",
    "TEAMS-MEETING-005.1": "cis:m365:8.5.7",
    "TEAMS-MEETING-008.1": "cis:m365:8.5.8",
    "TEAMS-MEETING-009.1": "cis:m365:8.5.9",
    "TEAMS-REPORTING-001.1": "cis:m365:8.6.1",
    # --- CIS Section 9 ---
    "POWERBI-GUEST-001.1": "cis:m365:9.1.1",
    "POWERBI-GUEST-002.1": "cis:m365:9.1.2",
    "POWERBI-GUEST-003.1": "cis:m365:9.1.3",
    "POWERBI-SHARING-001.1": "cis:m365:9.1.4",
    "POWERBI-SHARING-002.1": "cis:m365:9.1.5",
    "POWERBI-INFOPROT-001.1": "cis:m365:9.1.6",
    "POWERBI-SHARING-003.1": "cis:m365:9.1.7",
    "POWERBI-SHARING-004.1": "cis:m365:9.1.8",
    "POWERBI-AUTH-001.1": "cis:m365:9.1.9",
    "POWERBI-AUTH-002.1": "cis:m365:9.1.10",
    "POWERBI-AUTH-003.1": "cis:m365:9.1.11",
}

# Regex to strip .N sub-numbering from CheckId
_SUB_NUMBER_PATTERN = re.compile(r"\.\d+$")


def extract_base_check_id(check_id: str) -> str:
    """Strip .N sub-numbering suffix from a CheckId.

    'ENTRA-ADMIN-001.1' -> 'ENTRA-ADMIN-001'
    'ENTRA-ADMIN-001' -> 'ENTRA-ADMIN-001' (unchanged)
    """
    return _SUB_NUMBER_PATTERN.sub("", check_id)


def extract_collector_prefix(check_id: str) -> str:
    """Extract the collector prefix from a CheckId.

    'ENTRA-ADMIN-001.1' -> 'ENTRA'
    'CA-MFA-ADMIN-001.1' -> 'CA'
    """
    return check_id.split("-")[0]
