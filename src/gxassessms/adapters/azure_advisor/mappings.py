"""Azure Advisor declarative mappings -- data, not logic.

Maps Azure Advisor API response values to domain enums and dedup keys.
These dicts are consumed by the parser and by NormalizationPolicy.

Azure Advisor is a REST API that returns recommendations for an Azure
subscription. Key fields:
- impact: Title case string ("High", "Medium", "Low")
- category: PascalCase string ("Security", "HighAvailability", etc.)
- recommendationTypeId: GUID identifying the recommendation TYPE (for dedup)

Verified against Azure Advisor REST API docs and real API sample output.
"""

from gxassessms.core.domain.enums import Category, Severity

# ---------------------------------------------------------------------------
# Impact -> Severity mapping
# Azure Advisor has no native severity field. Impact is the closest analog.
# 3 impact levels: High, Medium, Low (title case, from API response)
# ---------------------------------------------------------------------------

IMPACT_TO_SEVERITY_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}

# ---------------------------------------------------------------------------
# Category mapping: Azure Advisor category -> domain Category
# 5 categories (PascalCase, from API response):
#   Security, HighAvailability, Performance, Cost, OperationalExcellence
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, Category] = {
    "security": Category.INFRASTRUCTURE_SECURITY,
    "highavailability": Category.INFRASTRUCTURE_SECURITY,
    "performance": Category.OPERATIONAL_EXCELLENCE,
    "cost": Category.COST_OPTIMIZATION,
    "operationalexcellence": Category.OPERATIONAL_EXCELLENCE,
}

# ---------------------------------------------------------------------------
# Dedup key rules: recommendationTypeId GUID -> finding_key
# Maps Azure Advisor recommendation type GUIDs to shared namespace keys.
# Azure Advisor is NOT CIS-aligned; keys use "advisor:" namespace.
#
# The recommendationTypeId is stable across instances -- the same recommendation
# type for different resources shares the same type GUID. The per-instance
# GUID (name field) is NOT suitable for dedup.
#
# This dict is intentionally small -- it will grow as we encounter and
# catalog more recommendation types during real assessments. Unknown
# recommendationTypeIds fall back to "advisor:{recommendationTypeId}".
#
# Verified against sample API output and Microsoft docs.
# ---------------------------------------------------------------------------

DEDUP_KEY_RULES: dict[str, str] = {
    # Keys are bare recommendationTypeId GUIDs, matching the stable native_check_id
    # emitted by the parser (no category prefix).
    "242639fd-cd73-4be2-8f55-70478db8d1a5": "advisor:service_health_alert",
}
