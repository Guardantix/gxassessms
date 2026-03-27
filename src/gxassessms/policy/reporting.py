"""ReportingPolicy -- suppression rules, display filtering, audience-specific thresholds.

Determines which findings appear in reports and how they are filtered
for different audiences (executive vs. technical).

This module NEVER performs I/O. Rules are loaded by config/ and injected
as plain dicts.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from gxassessms.core.domain.constants import SEVERITY_ORDER
from gxassessms.core.domain.enums import Severity
from gxassessms.core.domain.models import ConsolidatedFinding

logger = logging.getLogger(__name__)


@runtime_checkable
class ReportingPolicy(Protocol):
    """Protocol for reporting policy extension point.

    Implementations control which findings appear in reports, apply
    suppression and audience-specific filtering, and provide display
    configuration.
    """

    def apply_suppression(
        self, findings: list[ConsolidatedFinding]
    ) -> list[ConsolidatedFinding]: ...

    def filter_for_audience(
        self, findings: list[ConsolidatedFinding], audience: str
    ) -> list[ConsolidatedFinding]: ...

    def get_sections(self, audience: str) -> list[str]: ...

    def get_display_config(self) -> dict[str, Any]: ...


class DefaultReportingPolicy:
    """Default reporting policy shipped with the public package.

    Pure function: findings + rules in, filtered findings out. No I/O.
    """

    def __init__(self, rules: dict[str, Any]) -> None:
        self._rules = rules

    def apply_suppression(self, findings: list[ConsolidatedFinding]) -> list[ConsolidatedFinding]:
        """Remove findings that match suppression rules.

        Suppressed findings are excluded from reports but retained in the
        database for audit purposes.
        """
        suppression_rules = self._rules.get("suppression_rules", [])
        if not suppression_rules:
            return list(findings)

        result: list[ConsolidatedFinding] = []
        for finding in findings:
            if not self._is_suppressed(finding, suppression_rules):
                result.append(finding)

        return result

    def filter_for_audience(
        self, findings: list[ConsolidatedFinding], audience: str
    ) -> list[ConsolidatedFinding]:
        """Filter findings based on audience-specific thresholds."""
        audiences = self._rules.get("audiences", {})
        audience_config = audiences.get(audience)

        if audience_config is None:
            # Unknown audience: return all findings unfiltered
            return list(findings)

        min_severity_str = audience_config.get("minimum_severity", Severity.INFO.value)
        min_confidence = audience_config.get("minimum_confidence", 0.0)
        max_findings = audience_config.get("max_findings")

        min_severity_order = SEVERITY_ORDER.get(min_severity_str, 0)

        filtered: list[ConsolidatedFinding] = []
        for finding in findings:
            finding_severity_order = SEVERITY_ORDER.get(finding.severity.value, 0)
            if finding_severity_order < min_severity_order:
                continue
            if finding.confidence.overall < min_confidence:
                continue
            filtered.append(finding)

        # Sort by severity descending, then by confidence descending
        filtered.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity.value, 0),
                f.confidence.overall,
            ),
            reverse=True,
        )

        # Apply max_findings limit
        if max_findings is not None and len(filtered) > max_findings:
            filtered = filtered[:max_findings]

        return filtered

    def get_sections(self, audience: str) -> list[str]:
        """Get the report sections to include for an audience."""
        audiences = self._rules.get("audiences", {})
        audience_config = audiences.get(audience)
        if audience_config is None:
            return []
        return list(audience_config.get("sections", []))

    def get_display_config(self) -> dict[str, Any]:
        """Get display formatting configuration."""
        return dict(self._rules.get("display", {}))

    @staticmethod
    def _is_suppressed(
        finding: ConsolidatedFinding,
        suppression_rules: list[dict[str, str]],
    ) -> bool:
        """Check if a finding matches any suppression rule."""
        for rule in suppression_rules:
            field = rule.get("field", "")
            value = rule.get("value", "")

            if (
                (field == "status" and finding.status.value == value)
                or (field == "severity" and finding.severity.value == value)
                or (field == "category" and finding.category.value == value)
            ):
                return True

        return False
