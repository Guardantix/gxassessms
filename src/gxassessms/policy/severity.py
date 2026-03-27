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

from gxassessms.core.domain.constants import SEVERITY_ORDER
from gxassessms.core.domain.enums import FindingStatus, Severity
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

    def check_escalation(self, finding: ConsolidatedFinding) -> bool:
        """Return True if the finding's confidence is below its effective downgrade threshold.

        The effective threshold is the stricter of two values:
        ``max(escalation_thresholds[severity], confidence_adjustments.downgrade_threshold)``.
        A result of True means the finding should be reviewed for potential downgrade.
        Implementations must apply both the per-severity threshold and the global floor;
        using only ``escalation_thresholds`` will diverge from DefaultSeverityPolicy when
        ``downgrade_threshold`` is set higher than the per-severity value.
        """
        ...

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

        Downgrade: if a finding's confidence is below the escalation threshold
        for its severity, suggest downgrading by one level (floor: minimum_severity).

        Upgrade: if a finding's confidence is at or above the configured
        upgrade_threshold, suggest upgrading by one level (ceiling: maximum_severity).
        """
        adjustments: list[SeverityAdjustment] = []
        ca = self._rules.get("confidence_adjustments", {})
        min_sev_str = ca.get("minimum_severity")
        min_sev = Severity(min_sev_str) if min_sev_str else None
        max_sev_str = ca.get("maximum_severity")
        max_sev = Severity(max_sev_str) if max_sev_str else None
        upgrade_threshold = ca.get("upgrade_threshold")

        for finding in findings:
            # Skip PASS and NOT_APPLICABLE -- they are non-actionable regardless of confidence.
            if finding.status in (FindingStatus.PASS, FindingStatus.NOT_APPLICABLE):
                continue

            # Downgrade path: low confidence -> suggest lower severity.
            threshold = self._effective_downgrade_threshold(finding)
            if finding.confidence.overall < threshold:
                suggested = self._downgrade(finding.severity)
                if suggested != finding.severity and (
                    min_sev is None
                    or SEVERITY_ORDER.get(suggested.value, 0)
                    >= SEVERITY_ORDER.get(min_sev.value, 0)
                ):
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
                continue

            # Upgrade path: high confidence -> suggest higher severity
            if upgrade_threshold is not None and finding.confidence.overall >= upgrade_threshold:
                suggested = self._upgrade(finding.severity)
                if suggested != finding.severity and (
                    max_sev is None
                    or SEVERITY_ORDER.get(suggested.value, 0)
                    <= SEVERITY_ORDER.get(max_sev.value, 0)
                ):
                    adjustments.append(
                        SeverityAdjustment(
                            finding_instance_id=finding.finding_instance_id,
                            finding_key=finding.finding_key,
                            current_severity=finding.severity,
                            suggested_severity=suggested,
                            reason=(
                                f"Confidence {finding.confidence.overall:.2f} "
                                f"is at or above upgrade threshold "
                                f"{upgrade_threshold:.2f} for "
                                f"{finding.severity.value}"
                            ),
                        )
                    )

        return adjustments

    def check_escalation(self, finding: ConsolidatedFinding) -> bool:
        """Return True only when confidence is below threshold AND a downgrade is actionable.

        Effective threshold = max(per-severity escalation_threshold, global downgrade_threshold).
        A downgrade is actionable when the downgrade_map produces a lower severity AND the
        result is at or above confidence_adjustments.minimum_severity. This mirrors the
        suppression logic in suggest_adjustments() so the two methods never contradict each other.
        """
        if finding.confidence.overall >= self._effective_downgrade_threshold(finding):
            return False
        # No-op downgrade (e.g., INFO -> INFO): not actionable.
        suggested = self._downgrade(finding.severity)
        if suggested == finding.severity:
            return False
        # Downgrade target below minimum_severity floor: not actionable.
        ca = self._rules.get("confidence_adjustments", {})
        min_sev_str = ca.get("minimum_severity")
        return min_sev_str is None or SEVERITY_ORDER.get(suggested.value, 0) >= SEVERITY_ORDER.get(
            Severity(min_sev_str).value, 0
        )

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

    def _effective_downgrade_threshold(self, finding: ConsolidatedFinding) -> float:
        """Return the stricter of per-severity escalation threshold and global floor."""
        thresholds = self._rules.get("escalation_thresholds", {})
        ca = self._rules.get("confidence_adjustments", {})
        downgrade_threshold_global: float = ca.get("downgrade_threshold", 0.0)
        return max(thresholds.get(finding.severity.value, 0.0), downgrade_threshold_global)

    def _downgrade(self, severity: Severity) -> Severity:
        """Downgrade severity by one level using the downgrade map."""
        downgrade_map = self._rules.get("downgrade_map", {})
        downgraded = downgrade_map.get(severity.value)
        if downgraded is not None:
            return Severity(downgraded)
        return severity

    def _upgrade(self, severity: Severity) -> Severity:
        """Upgrade severity by one level using the upgrade map."""
        upgrade_map = self._rules.get("upgrade_map", {})
        upgraded = upgrade_map.get(severity.value)
        if upgraded is not None:
            return Severity(upgraded)
        return severity
