"""Payload assembly -- builds ReportPayload from engagement data.

Pulls findings and coverage records from the persistence layer via
repositories. Merges optional QA narratives. Produces a fully populated
ReportPayload ready for a renderer to consume.

This module handles data assembly only -- no rendering logic.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from gxassessms.core.domain.models import ReportPayload

logger = logging.getLogger(__name__)


def _deserialize_json_fields(
    finding: dict[str, Any],
    fields: tuple[str, ...] = ("sources", "confidence", "benchmark_refs"),
) -> dict[str, Any]:
    """Deserialize JSON string fields from a database row.

    The persistence layer stores some fields as JSON strings. This function
    parses them back into Python objects for the report payload.
    """
    result = dict(finding)
    for field in fields:
        value = result.get(field)
        if isinstance(value, str):
            result[field] = json.loads(value)
    return result


def assemble_payload(
    *,
    engagement_id: str,
    tenant_name: str,
    assessment_date: str,
    tool_sources: list[str],
    finding_repo: Any,
    coverage_repo: Any,
    narratives: dict[str, str | None] | None = None,
    config_snapshot: dict[str, Any] | None = None,
) -> ReportPayload:
    """Assemble a ReportPayload from engagement data.

    Args:
        engagement_id: ID of the engagement to build a payload for.
        tenant_name: Display name of the assessed tenant.
        assessment_date: ISO 8601 date string of the assessment run.
        tool_sources: List of enabled tool source names.
        finding_repo: FindingRepo instance (or compatible mock with .get_consolidated()).
        coverage_repo: CoverageRepo instance (or compatible mock with .get_for_engagement()).
        narratives: Optional QA-generated narratives (executive_summary, roadmap, etc.).
            If None, defaults are provided with None values.
        config_snapshot: Optional config snapshot for metadata.

    Returns:
        A fully populated ReportPayload ready for rendering.
    """
    logger.info("Assembling report payload for engagement %s", engagement_id)

    raw_findings = finding_repo.get_consolidated(engagement_id)
    raw_coverage = coverage_repo.get_for_engagement(engagement_id)

    findings = [_deserialize_json_fields(f) for f in raw_findings]
    coverage = [dict(r) for r in raw_coverage]

    merged_narratives: dict[str, str | None] = {
        "executive_summary": None,
        "roadmap": None,
        "findings_narrative": None,
    }
    if narratives:
        merged_narratives.update(narratives)

    metadata: dict[str, Any] = {}
    if config_snapshot is not None:
        metadata["config_snapshot"] = config_snapshot

    payload = ReportPayload(
        schema_version="1.0.0",
        engagement_id=engagement_id,
        tenant_name=tenant_name,
        assessment_date=assessment_date,
        tool_sources=tool_sources,
        findings=findings,
        coverage=coverage,
        narratives=merged_narratives,
        metadata=metadata,
    )

    logger.info(
        "Payload assembled: %d findings, %d coverage records, %d tools",
        len(findings),
        len(coverage),
        len(tool_sources),
    )
    return payload
