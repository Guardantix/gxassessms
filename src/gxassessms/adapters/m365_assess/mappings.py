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
# Dedup key rules: base CheckId -> canonical cross-reference ID
# Maps M365-Assess checks to CIS benchmark control IDs where known.
# Populated from registry.json framework mappings at implementation time.
# ---------------------------------------------------------------------------

DEDUP_KEY_RULES: dict[str, str] = {}

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
