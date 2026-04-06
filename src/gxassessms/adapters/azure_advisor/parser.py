"""Azure Advisor recommendation parser.

Transforms Azure Advisor API response JSON into ToolObservation instances.
Azure Advisor returns recommendations via the Azure Management REST API.

Key fields used:
- recommendationTypeId: GUID identifying the recommendation TYPE (stable for dedup)
- impact: "High", "Medium", "Low" -- maps to severity
- category: "Security", "HighAvailability", "Performance", "Cost", "OperationalExcellence"
- shortDescription.problem: Human-readable title
- shortDescription.solution: Remediation guidance
- impactedField: Azure resource type (e.g., "Microsoft.Compute/virtualMachines")
- impactedValue: Specific resource name
- risk: Can be null, "Error", "Warning", "None" -- preserved in raw_data
- resourceMetadata.resourceId: Full ARM resource path

All recommendations are active (action needed) -- there is no pass/fail concept.
Every recommendation maps to FindingStatus.FAIL.

Verified against Azure Advisor REST API docs and sample output.
"""

from __future__ import annotations

import logging
from typing import Any

from gxassessms.adapters.azure_advisor.mappings import (
    IMPACT_TO_SEVERITY_MAP,
)
from gxassessms.core.domain.enums import (
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import ToolObservation

logger = logging.getLogger(__name__)


def parse_advisor_recommendations(
    recommendations: list[dict[str, Any]],
) -> list[ToolObservation]:
    """Parse a list of Azure Advisor recommendation dicts into ToolObservations.

    Args:
        recommendations: List of recommendation objects from the API "value" array.

    Returns:
        List of ToolObservation instances, one per recommendation.
    """
    observations: list[ToolObservation] = []

    for rec in recommendations:
        recommendation_type_id: str = rec.get("recommendationTypeId", "")
        instance_name: str = rec.get("name", "")

        if not recommendation_type_id:
            logger.warning(
                "Recommendation missing recommendationTypeId, name=%s",
                instance_name or "unknown",
            )
            recommendation_type_id = instance_name or "unknown"

        if not instance_name:
            logger.warning(
                "Recommendation missing name, using recommendationTypeId=%s",
                recommendation_type_id,
            )
            instance_name = recommendation_type_id

        category_raw = rec.get("category")
        if not isinstance(category_raw, str) or not category_raw:
            logger.warning(
                "Recommendation %s has null/empty category; "
                "native_check_id will lack category prefix",
                recommendation_type_id,
            )
            category = ""
        else:
            category = category_raw

        impact_raw = rec.get("impact")
        if not isinstance(impact_raw, str) or not impact_raw:
            logger.warning(
                "Recommendation %s has unexpected impact value %r; defaulting to MEDIUM",
                recommendation_type_id,
                impact_raw,
            )
            severity = Severity.MEDIUM
        else:
            severity = IMPACT_TO_SEVERITY_MAP.get(impact_raw, Severity.MEDIUM)
            if impact_raw not in IMPACT_TO_SEVERITY_MAP:
                logger.warning(
                    "Unknown impact value %r for recommendation %s; defaulting to MEDIUM",
                    impact_raw,
                    recommendation_type_id,
                )

        # Prefix native_check_id with Advisor category so normalization's
        # _extract_module_prefix can resolve it via the category_map.
        # e.g. "Security.242639fd-..." -> prefix "security" -> INFRASTRUCTURE_SECURITY
        check_id = f"{category}.{recommendation_type_id}" if category else recommendation_type_id

        short_desc: dict[str, Any] = rec.get("shortDescription", {})
        title: str = short_desc.get("problem", "")
        solution: str = short_desc.get("solution", "")

        description = _build_description(rec, title, solution)

        observation = ToolObservation(
            observation_id=f"azure_advisor:{instance_name}",
            tool=ToolSource.AZURE_ADVISOR,
            native_check_id=check_id,
            title=title,
            native_severity=severity,
            native_status=FindingStatus.FAIL,
            description=description,
            raw_data=rec,
            benchmark_refs=[],
        )
        observations.append(observation)

    return observations


def _build_description(rec: dict[str, Any], title: str, solution: str) -> str:
    """Build a descriptive string from recommendation fields.

    Includes the problem description, impacted resource, and solution.
    """
    parts: list[str] = []

    if title:
        parts.append(title)

    impacted_field: str = rec.get("impactedField", "")
    impacted_value: str = rec.get("impactedValue", "")
    if impacted_field and impacted_value:
        parts.append(f"Affected resource: {impacted_value} ({impacted_field})")
    elif impacted_value:
        parts.append(f"Affected resource: {impacted_value}")

    if solution and solution != title:
        parts.append(f"Recommendation: {solution}")

    risk: str | None = rec.get("risk")
    if risk and risk != "None":
        parts.append(f"Risk level: {risk}")

    return "\n".join(parts)
