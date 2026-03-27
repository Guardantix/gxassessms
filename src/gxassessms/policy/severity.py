"""SeverityPolicy -- override suggestions, escalation thresholds, confidence-based adjustment.

Produces severity adjustment suggestions (never auto-applies). Checks whether
a finding's confidence level supports its current severity.

This module NEVER performs I/O. Rules are loaded by config/ and injected
as plain dicts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from gxassessms.core.domain.enums import Severity
from gxassessms.core.domain.models import ConsolidatedFinding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SeverityAdjustment:
    """A suggested severity adjustment -- never auto-applied."""

    finding_instance_id: str
    finding_key: str
    current_severity: Severity
    suggested_severity: Severity
    reason: str


@runtime_checkable
class SeverityPolicy(Protocol):
    """Protocol for severity policy extension point.

    Implementations produce severity adjustment suggestions based on
    confidence scores, escalation thresholds, and override history.
    """

    def suggest_adjustments(
        self, findings: list[ConsolidatedFinding]
    ) -> list[SeverityAdjustment]: ...

    def check_escalation(self, finding: ConsolidatedFinding) -> bool: ...

    def suggest_rule_changes(
        self, override_history: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]: ...


class DefaultSeverityPolicy:
    """Default severity policy shipped with the public package.

    Pure function: findings + rules in, suggestions out. No I/O.
    Suggestions are never auto-applied -- they surface in the review UI
    or as proposed YAML patches.
    """

    def __init__(self, rules: dict[str, Any]) -> None:
        self._rules = rules

    def suggest_adjustments(self, findings: list[ConsolidatedFinding]) -> list[SeverityAdjustment]:
        """Suggest severity adjustments based on confidence thresholds.

        If a finding's confidence is below the escalation threshold for its
        severity, suggest downgrading by one level.
        """
        adjustments: list[SeverityAdjustment] = []
        thresholds = self._rules.get("escalation_thresholds", {})

        for finding in findings:
            threshold = thresholds.get(finding.severity.value, 0.0)
            if finding.confidence.overall < threshold:
                suggested = self._downgrade(finding.severity)
                if suggested != finding.severity:
                    adjustments.append(
                        SeverityAdjustment(
                            finding_instance_id=finding.finding_instance_id,
                            finding_key=finding.finding_key,
                            current_severity=finding.severity,
                            suggested_severity=suggested,
                            reason=(
                                f"Confidence {finding.confidence.overall:.2f} "
                                f"is below threshold {threshold:.2f} for "
                                f"{finding.severity.value}"
                            ),
                        )
                    )

        return adjustments

    def check_escalation(self, finding: ConsolidatedFinding) -> bool:
        """Check if a finding's confidence is below its escalation threshold.

        Returns True if the finding should be reviewed for potential downgrade.
        """
        thresholds = self._rules.get("escalation_thresholds", {})
        threshold = thresholds.get(finding.severity.value, 0.0)
        return finding.confidence.overall < threshold

    def suggest_rule_changes(
        self, override_history: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Suggest rule changes when findings are consistently overridden.

        If a finding has been overridden more than suggestion_threshold times
        in the same direction, suggest updating the default mapping.
        """
        suggestions: list[dict[str, Any]] = []
        override_config = self._rules.get("override_suggestions", {})
        threshold = override_config.get("suggestion_threshold", 3)

        for finding_key, history in override_history.items():
            count = history.get("count", 0)
            if count >= threshold:
                suggestions.append(
                    {
                        "finding_key": finding_key,
                        "current_default": history.get("from"),
                        "suggested_default": history.get("to"),
                        "override_count": count,
                        "reason": (
                            f"Finding {finding_key} has been overridden "
                            f"{count} times from {history.get('from')} "
                            f"to {history.get('to')}"
                        ),
                    }
                )

        return suggestions

    def _downgrade(self, severity: Severity) -> Severity:
        """Downgrade severity by one level using the downgrade map."""
        downgrade_map = self._rules.get("downgrade_map", {})
        downgraded = downgrade_map.get(severity.value)
        if downgraded is not None:
            return Severity(downgraded)
        return severity
