"""Maester declarative mappings -- data, not logic.

Maps Maester native values to domain enums and dedup keys.
These dicts are consumed by the parser and by NormalizationPolicy.
Adding a new mapping is a one-line data change.

Maester is unique among adapters: it runs tests from multiple benchmark
frameworks simultaneously (CIS M365, CISA SCuBA, EIDSCA, ORCA, and its
own MT community tests). Each framework uses a different ID format.
The dedup key rules must handle all formats.
"""

from gxassessms.core.domain.enums import Category, Severity

# ---------------------------------------------------------------------------
# Severity mapping: Maester Severity string -> domain Severity
# Maester uses: Critical, High, Medium, Low, Info (NOT "Informational").
# Empty string is possible in real output and defaults to INFO.
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Info": Severity.INFO,
    "": Severity.INFO,
}

# ---------------------------------------------------------------------------
# Block -> Category mapping: Maester's Block field -> domain Category
# Maester does NOT have a "Category" field. Instead, the Block field
# indicates which benchmark framework/product area the test belongs to.
# Block values observed in real output:
#   CIS, CISA, EIDSCA, Maester/Entra, Maester/Intune, Maester/Exchange,
#   Maester/Teams, ORCA, AzureConfig, Exposure Management
# ---------------------------------------------------------------------------

BLOCK_CATEGORY_MAP: dict[str, Category] = {
    # Benchmark framework blocks
    "CIS": Category.COMPLIANCE,
    "CISA": Category.COMPLIANCE,
    "EIDSCA": Category.IDENTITY_ACCESS,
    "ORCA": Category.EMAIL_COLLABORATION,
    # Maester product-area blocks
    "Maester/Entra": Category.IDENTITY_ACCESS,
    "Maester/Intune": Category.DEVICE_MANAGEMENT,
    "Maester/Exchange": Category.EMAIL_COLLABORATION,
    "Maester/Teams": Category.EMAIL_COLLABORATION,
    "Maester/Azure": Category.INFRASTRUCTURE_SECURITY,
    "Maester/Defender": Category.INFRASTRUCTURE_SECURITY,
    # Other blocks seen in real output
    "AzureConfig": Category.INFRASTRUCTURE_SECURITY,
    "Exposure Management": Category.INFRASTRUCTURE_SECURITY,
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
    # CISA SCuBA tests -- same controls as ScubaGear, same dedup keys
    "CISA.MS.AAD.3.1": "cis:m365:1.1.1",
    "CISA.MS.AAD.3.2": "cis:m365:1.1.2",
    "CISA.MS.AAD.3.3": "cis:m365:1.1.3",
    "CISA.MS.AAD.7.1": "cis:m365:1.1.4",
    "CISA.MS.EXO.4.1": "cis:m365:2.1.1",
    "CISA.MS.EXO.4.2": "cis:m365:2.1.2",
    "CISA.MS.EXO.4.3": "cis:m365:2.1.3",
    "CISA.MS.SHAREPOINT.1.1": "cisa:spo:external_sharing",
    # CIS M365 benchmark tests -- separate framework, own dedup keys
    "CIS.M365.1.1.1": "cis:m365:1.1.1:cloud_only_admins",
    "CIS.M365.1.2.1": "cis:m365:1.2.1:public_groups",
    "CIS.M365.2.1.9": "cis:m365:2.1.9:connection_filter_safelist",
    "CIS.M365.8.6.1": "cis:m365:8.6.1:teams_security_reporting",
}
