"""Maester declarative mappings -- data, not logic.

Maps Maester native values to domain enums and dedup keys.
These dicts are consumed by the parser and by NormalizationPolicy.
Adding a new mapping is a one-line data change.

Maester is unique among adapters: it runs tests from multiple benchmark
frameworks simultaneously (CIS M365, CISA SCuBA, EIDSCA, ORCA, and its
own MT community tests). Each framework uses a different ID format.
The dedup key rules must handle all formats.
"""

from gxassessms.core.domain.enums import Category, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Severity mapping: (Maester Severity, canonicalized status) -> domain Severity
#
# Keys use canonicalized (domain) status values because _resolve_severity()
# applies default_status_map ("Failed"->"FAIL", etc.) before looking up here.
#
# Maester Severity values: Critical, High, Medium, Low, Info, "" (empty).
# Maester Result values (after status_map): FAIL, PASS, ERROR, N/A.
#
# PASS and N/A short-circuit to INFO in _resolve_severity() before consulting
# this map, so only FAIL entries are needed. ERROR-status observations
# (test execution failures, not clean assessments) fall to fallback_severity.
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[tuple[str, str], Severity] = {
    ("Critical", FindingStatus.FAIL): Severity.CRITICAL,
    ("High", FindingStatus.FAIL): Severity.HIGH,
    ("Medium", FindingStatus.FAIL): Severity.MEDIUM,
    ("Low", FindingStatus.FAIL): Severity.LOW,
    ("Info", FindingStatus.FAIL): Severity.LOW,
    ("", FindingStatus.FAIL): Severity.MEDIUM,
}

# ---------------------------------------------------------------------------
# Category mapping: check-ID prefix (lowercased) -> domain Category
#
# NormalizationPolicy._resolve_category() looks up by the prefix returned
# from _extract_module_prefix(). For Maester IDs, the generic fallback
# extracts the first dot-separated segment (lowercased):
#   CISA.MS.AAD.3.1 -> "cisa"
#   CIS.M365.1.1.1  -> "cis"
#   EIDSCA.AF01     -> "eidsca"
#   MT.1001         -> "mt"
#   ORCA.118        -> "orca"
#
# MT (Maester community) tests span multiple product areas; the ID prefix
# alone cannot distinguish them. IDENTITY_ACCESS is the default because
# the majority of MT tests cover Entra/Conditional Access.
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    "cis": Category.COMPLIANCE,
    "cisa": Category.COMPLIANCE,
    "eidsca": Category.IDENTITY_ACCESS,
    "orca": Category.EMAIL_COLLABORATION,
    "mt": Category.IDENTITY_ACCESS,
}

# ---------------------------------------------------------------------------
# Dedup key rules: Maester test Id -> shared dedup namespace key
#
# Maester uses multiple ID formats from different frameworks:
#   CISA.MS.AAD.3.1  -> overlaps with ScubaGear's MS.AAD.3.1v1
#   CIS.M365.1.1.1   -> CIS M365 benchmark (different control than CISA)
#   MT.1001           -> Maester community tests (tool-scoped)
#   EIDSCA.AF01       -> Entra ID security config (tool-scoped)
#   ORCA.118          -> Office 365 recommended config (tool-scoped)
#
# CISA tests map to the SAME dedup keys as ScubaGear (same baseline).
# CIS tests map to cis:m365: namespace with a semantic suffix to
# distinguish from CISA-origin mappings that share the same number.
# MT/EIDSCA/ORCA tests without cross-tool overlap get tool-scoped keys
# (maester:{test_id}), assigned by the parser as the default fallback.
# ---------------------------------------------------------------------------

DEDUP_KEY_RULES: dict[str, str] = {
    # CISA SCuBA tests -- same controls as ScubaGear, same dedup keys.
    # Mapped to CIS M365 v5/v6 control IDs where equivalent exists.
    # --- Section 1.1: Admin Account Governance ---
    "CISA.MS.AAD.7.3": "cis:m365:1.1.1",  # Admin accounts cloud-only
    "CISA.MS.AAD.7.1": "cis:m365:1.1.3",  # Global admin count
    # --- Section 2.1: Email Security (Defender/EXO) ---
    "CISA.MS.DEFENDER.3.1": "cis:m365:2.1.5",  # Safe Attachments for SPO/ODB/Teams
    "CISA.MS.EXO.2.2": "cis:m365:2.1.8",  # SPF
    "CISA.MS.EXO.3.1": "cis:m365:2.1.9",  # DKIM
    "CISA.MS.EXO.4.1": "cis:m365:2.1.10",  # DMARC record
    "CISA.MS.EXO.4.2": "cis:m365:2.1.10",  # DMARC p=reject (same CIS control)
    # --- Section 5.2.2: Conditional Access ---
    "CISA.MS.AAD.3.6": "cis:m365:5.2.2.1",  # MFA for admin roles
    "CISA.MS.AAD.3.2": "cis:m365:5.2.2.2",  # MFA for all users
    "CISA.MS.AAD.1.1": "cis:m365:5.2.2.3",  # Block legacy auth
    # CIS 5.2.2.5 is admins only -- CISA requires all users, different scope
    "CISA.MS.AAD.3.1": "cisa:aad:phishing_resistant_mfa",
    # --- Section 5.2.3: Authentication Methods ---
    "CISA.MS.AAD.3.3": "cis:m365:5.2.3.1",  # Authenticator anti-fatigue
    "CISA.MS.AAD.3.5": "cis:m365:5.2.3.5",  # Disable weak auth methods
    # --- Section 6: Exchange Online ---
    "CISA.MS.EXO.1.1": "cis:m365:6.2.1",  # Block mail forwarding
    # --- CISA-only (no CIS equivalent) ---
    "CISA.MS.SHAREPOINT.1.1": "cisa:spo:external_sharing",
    # CIS M365 benchmark tests -- separate framework, own dedup keys
    "CIS.M365.1.1.1": "cis:m365:1.1.1:cloud_only_admins",
    "CIS.M365.1.2.1": "cis:m365:1.2.1:public_groups",
    "CIS.M365.2.1.9": "cis:m365:2.1.9:dkim",
    "CIS.M365.8.6.1": "cis:m365:8.6.1:teams_security_reporting",
}
