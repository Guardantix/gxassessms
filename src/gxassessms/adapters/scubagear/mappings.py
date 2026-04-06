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
# Result values (canonicalized by default_status_map before lookup):
#   "FAIL", "WARNING", "PASS", "N/A"
#
# Pass (any Criticality) and N/A with 3rd-Party Criticality resolve to INFO
# via DefaultNormalizationPolicy._resolve_severity(), which short-circuits
# PASS and NOT_APPLICABLE statuses to INFO before consulting this map.
# These entries are therefore intentionally absent.
#
# Keys use canonicalized (domain) status values because _resolve_severity()
# applies default_status_map ("Fail"->"FAIL", etc.) before looking up here.
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[tuple[str, str], Severity] = {
    # --- Shall (mandatory, directly assessed) ---
    ("Shall", FindingStatus.FAIL): Severity.CRITICAL,
    ("Shall", FindingStatus.WARNING): Severity.HIGH,
    # --- Should (recommended, directly assessed) ---
    ("Should", FindingStatus.FAIL): Severity.HIGH,
    ("Should", FindingStatus.WARNING): Severity.MEDIUM,
    # --- Shall/3rd Party (mandatory, 3rd-party implementation) ---
    # Lower confidence than direct assessment -- one notch down.
    ("Shall/3rd Party", FindingStatus.FAIL): Severity.HIGH,
    ("Shall/3rd Party", FindingStatus.WARNING): Severity.MEDIUM,
    # --- Should/3rd Party (recommended, 3rd-party implementation) ---
    ("Should/3rd Party", FindingStatus.FAIL): Severity.MEDIUM,
    ("Should/3rd Party", FindingStatus.WARNING): Severity.LOW,
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
    # --- Section 1.1: Admin Account Governance ---
    "MS.AAD.7.3v1": "cis:m365:1.1.1",  # Admin accounts must be cloud-only
    # CIS 1.1.3 requires max 4 global admins; CISA allows 2-8 -- different threshold.
    "MS.AAD.7.1v1": "cisa:aad:global_admin_count",  # Global admin count (CISA threshold: 2-8)
    # --- Section 2.1: Email Security (Defender/EXO) ---
    "MS.DEFENDER.3.1v1": "cis:m365:2.1.5",  # Safe Attachments for SPO/ODB/Teams
    "MS.EXO.2.2v2": "cis:m365:2.1.8",  # SPF -- ScubaGear <= 1.7.x
    "MS.EXO.2.2v3": "cis:m365:2.1.8",  # SPF -- ScubaGear >= 1.8.x
    "MS.EXO.3.1v1": "cis:m365:2.1.9",  # DKIM enabled for all domains
    "MS.EXO.4.1v1": "cis:m365:2.1.10",  # DMARC record published for each domain
    "MS.EXO.4.2v1": "cis:m365:2.1.10",  # DMARC p=reject (same CIS control)
    # --- Section 5.2.2: Conditional Access ---
    "MS.AAD.3.6v1": "cis:m365:5.2.2.1",  # MFA for admin roles
    "MS.AAD.3.2v2": "cis:m365:5.2.2.2",  # MFA for all users
    "MS.AAD.1.1v1": "cis:m365:5.2.2.3",  # Block legacy authentication
    # CIS 5.2.2.5 is admins only -- CISA requires all users, different scope
    "MS.AAD.3.1v1": "cisa:aad:phishing_resistant_mfa",
    # --- Section 5.2.3: Authentication Methods ---
    "MS.AAD.3.3v2": "cis:m365:5.2.3.1",  # Authenticator anti-fatigue (context info)
    "MS.AAD.3.5v2": "cis:m365:5.2.3.5",  # Disable weak auth methods
    # --- Section 6: Exchange Online ---
    "MS.EXO.1.1v2": "cis:m365:6.2.1",  # Block all forms of mail forwarding
}
