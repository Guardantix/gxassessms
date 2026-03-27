"""RoadmapPolicy -- phase assignment, priority scoring, remediation timeline estimation.

Assigns each consolidated finding to a remediation phase based on severity
and computes priority scores for ordering within and across phases.

This module NEVER performs I/O. Rules are loaded by config/ and injected
as plain dicts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from gxassessms.core.domain.models import ConsolidatedFinding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RoadmapAssignment:
    """A finding's assigned roadmap phase and priority."""

    finding_instance_id: str
    finding_key: str
    phase: str
    timeline: str
    priority_score: float


@runtime_checkable
class RoadmapPolicy(Protocol):
    """Protocol for roadmap policy extension point.

    Implementations assign findings to remediation phases and compute
    priority scores for ordering.
    """

    def assign_phases(self, findings: list[ConsolidatedFinding]) -> list[RoadmapAssignment]: ...


class DefaultRoadmapPolicy:
    """Default roadmap policy shipped with the public package.

    Pure function: findings + rules in, phase assignments out. No I/O.
    """

    def __init__(self, rules: dict[str, Any]) -> None:
        self._rules = rules

    def assign_phases(self, findings: list[ConsolidatedFinding]) -> list[RoadmapAssignment]:
        """Assign each finding to a remediation phase with priority score."""
        assignments: list[RoadmapAssignment] = []

        for finding in findings:
            phase = self._determine_phase(finding)
            timeline = self._get_timeline(phase)
            priority_score = self._compute_priority(finding)

            assignments.append(
                RoadmapAssignment(
                    finding_instance_id=finding.finding_instance_id,
                    finding_key=finding.finding_key,
                    phase=phase,
                    timeline=timeline,
                    priority_score=round(priority_score, 2),
                )
            )

        return assignments

    def _determine_phase(self, finding: ConsolidatedFinding) -> str:
        """Determine the remediation phase from severity."""
        severity_to_phase = self._rules.get("severity_to_phase", {})
        phase = severity_to_phase.get(finding.severity.value)
        if phase is not None:
            return phase
        # Fallback: MEDIUM_TERM
        return "MEDIUM_TERM"

    def _get_timeline(self, phase: str) -> str:
        """Get the timeline string for a phase."""
        phases = self._rules.get("phases", {})
        phase_info = phases.get(phase, {})
        return phase_info.get("timeline", "TBD")

    def _compute_priority(self, finding: ConsolidatedFinding) -> float:
        """Compute a priority score (0-100) for ordering findings.

        Higher score = higher priority. Combines severity, confidence,
        category weight, and corroboration.
        """
        weights = self._rules.get("priority_weights", {})
        w_severity = weights.get("severity", 0.40)
        w_confidence = weights.get("confidence", 0.25)
        w_category = weights.get("category_weight", 0.20)
        w_corroboration = weights.get("corroboration", 0.15)

        # Severity component (0-100)
        severity_scores = self._rules.get("severity_scores", {})
        severity_score = severity_scores.get(finding.severity.value, 50)

        # Confidence component (0-100)
        confidence_score = finding.confidence.overall * 100

        # Category weight component (0-100, adjusted by category multiplier)
        category_priority = self._rules.get("category_priority", {})
        # Use the Category enum's name attribute for lookup
        cat_key = finding.category.name
        cat_multiplier = category_priority.get(cat_key, 1.0)
        category_score = 50.0 * cat_multiplier  # Base 50, scaled by multiplier

        # Corroboration component (0-100)
        corroboration_score = min(100, finding.confidence.corroborating_tools * 25)

        total = (
            (severity_score * w_severity)
            + (confidence_score * w_confidence)
            + (category_score * w_category)
            + (corroboration_score * w_corroboration)
        )

        return min(100.0, max(0.0, total))
