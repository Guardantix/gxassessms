"""ScubaGear declarative mappings -- pure data, no logic.

Maps ScubaGear-native values to domain enums and canonical cross-reference IDs.
All three dicts are intended to be imported directly and treated as read-only.
"""

from __future__ import annotations

from gxassessms.core.domain.enums import Category, FindingStatus, Severity

# ---------------------------------------------------------------------------
# SEVERITY_MAP
#
# Maps (Criticality, Result) tuples to Severity enum values.
#
# Criticality values:
#   "Shall"                -- mandatory requirement, ScubaGear can assess
#   "Should"               -- recommended, ScubaGear can assess
#   "Shall/3rd Party"      -- mandatory but implemented via 3rd-party tooling
#   "Should/3rd Party"     -- recommended, 3rd-party tooling
#   "Shall/Not-Implemented"-- mandatory, ScubaGear cannot check (always N/A)
#   "Should/Not-Implemented"-- recommended, ScubaGear cannot check (always N/A)
#
# Result values:
#   "Fail", "Warning", "Pass", "N/A"
#
# Pass (any Criticality) and N/A with 3rd-Party Criticality resolve to INFO
# via DefaultNormalizationPolicy._resolve_severity(), which short-circuits
# PASS and NOT_APPLICABLE statuses to INFO before consulting this map.
# These entries are therefore intentionally absent.
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[tuple[str, str], Severity] = {
    # --- Shall (mandatory, directly assessed) ---
    ("Shall", "Fail"): Severity.CRITICAL,
    ("Shall", "Warning"): Severity.HIGH,
    # --- Should (recommended, directly assessed) ---
    ("Should", "Fail"): Severity.HIGH,
    ("Should", "Warning"): Severity.MEDIUM,
    # --- Shall/3rd Party (mandatory, 3rd-party implementation) ---
    # Lower confidence than direct assessment -- one notch down.
    ("Shall/3rd Party", "Fail"): Severity.HIGH,
    ("Shall/3rd Party", "Warning"): Severity.MEDIUM,
    # --- Should/3rd Party (recommended, 3rd-party implementation) ---
    ("Should/3rd Party", "Fail"): Severity.MEDIUM,
    ("Should/3rd Party", "Warning"): Severity.LOW,
    # --- Not-Implemented (ScubaGear cannot check; always produces N/A) ---
    # Under DefaultNormalizationPolicy these entries are unreachable because
    # _resolve_severity short-circuits N/A -> INFO before consulting this map.
    # Retained for alternative NormalizationPolicy implementations.
    # Represents a SHALL/SHOULD gap requiring manual verification.
    ("Shall/Not-Implemented", FindingStatus.NOT_APPLICABLE): Severity.HIGH,
    ("Should/Not-Implemented", FindingStatus.NOT_APPLICABLE): Severity.MEDIUM,
}

# ---------------------------------------------------------------------------
# CATEGORY_MAP
#
# Maps ScubaGear module abbreviation (lowercased) to Category enum.
# All keys must be lowercase to allow case-insensitive lookup.
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    "aad": Category.IDENTITY_ACCESS,
    "entra": Category.IDENTITY_ACCESS,  # future alias for AAD
    "exo": Category.EMAIL_COLLABORATION,
    "sharepoint": Category.DATA_PROTECTION,
    "teams": Category.EMAIL_COLLABORATION,
    "defender": Category.EMAIL_COLLABORATION,
    "powerplatform": Category.APPLICATION_SECURITY,
}

# ---------------------------------------------------------------------------
# DEDUP_KEY_RULES
#
# Maps ScubaGear PolicyId to a canonical cross-reference ID using the
# namespaced format "<framework>:<benchmark>:<control-id>".
#
# These are used by the consolidation engine to detect duplicate findings
# across tools that cover the same underlying control.
#
# Only controls with known CIS M365 equivalents are listed here.
# Additional mappings will be added as the cross-reference library grows.
# ---------------------------------------------------------------------------

DEDUP_KEY_RULES: dict[str, str] = {
    "MS.AAD.1.1v1": "cis:m365:1.1.4",  # Block legacy authentication
    "MS.AAD.3.4v1": "cis:m365:1.1.1",  # Authentication Methods migration complete
    "MS.EXO.1.1v2": "cis:m365:2.1.4",  # Disable automatic forwarding to external domains
    "MS.EXO.2.2v2": "cis:m365:2.1.2",  # SPF policy published for each domain
    "MS.EXO.3.1v1": "cis:m365:2.1.1",  # DKIM enabled for all domains
}
