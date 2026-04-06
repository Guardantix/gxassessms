"""Secure Score Graph API parser.

Joins two separate Microsoft Graph API responses into ToolObservation
instances. Join key: controlProfiles[].id == controlScores[].controlName
"""

from __future__ import annotations

import logging
from typing import Any

from gxassessms.adapters.secure_score.mappings import (
    CONTROL_STATE_PASS_THROUGH,
    derive_severity,
)
from gxassessms.core.domain.enums import (
    FindingStatus,
    ToolSource,
)
from gxassessms.core.domain.models import ToolObservation

logger = logging.getLogger(__name__)


def get_latest_control_state(
    control_state_updates: list[dict[str, Any]] | None,
) -> str:
    """Return the most recent control state from update history.

    Args:
        control_state_updates: List of state update dicts from the
            controlProfiles API, each with ``state`` and ``updatedDateTime``.

    Returns:
        The ``state`` string from the most recent update, or ``"Default"``
        if no updates are available.
    """
    if not control_state_updates:
        return "Default"
    try:
        sorted_updates = sorted(
            control_state_updates,
            key=lambda u: u.get("updatedDateTime", ""),
            reverse=True,
        )
        return sorted_updates[0].get("state", "Default")
    except TypeError, IndexError, KeyError:
        return "Default"


def _derive_status(
    score: float | None,
    max_score: float,
    latest_state: str,
) -> FindingStatus:
    """Derive finding status from score, max score, and control state.

    Decision order:
        1. No score data at all -> MANUAL (needs human review)
        2. Full score achieved   -> PASS
        3. Third-party/ignored   -> NOT_APPLICABLE
        4. Otherwise             -> FAIL
    """
    if score is None:
        return FindingStatus.MANUAL
    if max_score > 0 and score >= max_score:
        return FindingStatus.PASS
    if latest_state in CONTROL_STATE_PASS_THROUGH:
        return FindingStatus.NOT_APPLICABLE
    return FindingStatus.FAIL


def _build_description(profile: dict[str, Any]) -> str:
    """Build a human-readable description from profile fields."""
    parts: list[str] = []
    remediation = profile.get("remediation", "")
    if remediation:
        parts.append(remediation)
    remediation_impact = profile.get("remediationImpact", "")
    if remediation_impact:
        parts.append(f"Impact: {remediation_impact}")
    threats = profile.get("threats", [])
    if threats:
        parts.append(f"Threats: {', '.join(threats)}")
    service = profile.get("service", "")
    if service:
        parts.append(f"Service: {service}")
    action_url = profile.get("actionUrl", "")
    if action_url:
        parts.append(f"Action URL: {action_url}")
    return "\n".join(parts) if parts else ""


def parse_secure_score(
    profiles_response: dict[str, Any],
    scores_response: dict[str, Any],
) -> list[ToolObservation]:
    """Join control profiles and score snapshot into ToolObservations.

    Args:
        profiles_response: Full JSON from
            ``GET /security/secureScoreControlProfiles``.
        scores_response: Full JSON from
            ``GET /security/secureScores?$top=1``.

    Returns:
        List of :class:`ToolObservation` instances, one per non-deprecated
        control profile. Deprecated profiles are silently skipped.
    """
    profiles = profiles_response.get("value", [])
    if not profiles:
        return []

    score_lookup: dict[str, dict[str, Any]] = {}
    scores_list = scores_response.get("value", [])
    if scores_list:
        latest_snapshot = scores_list[0]
        for cs in latest_snapshot.get("controlScores", []):
            control_name = cs.get("controlName", "")
            if control_name:
                score_lookup[control_name] = cs

    observations: list[ToolObservation] = []

    for profile in profiles:
        if profile.get("deprecated", False):
            logger.debug("Skipping deprecated control: %s", profile.get("id"))
            continue

        control_id = profile.get("id", "")
        if not control_id:
            logger.warning("Control profile missing 'id' field, skipping")
            continue

        score_data = score_lookup.get(control_id)
        current_score: float | None = None
        if score_data is not None:
            current_score = score_data.get("score")

        max_score = profile.get("maxScore", 0.0)
        rank = profile.get("rank", 999)
        tier = profile.get("tier", "")

        severity = derive_severity(rank=rank, tier=tier)
        latest_state = get_latest_control_state(
            profile.get("controlStateUpdates"),
        )
        status = _derive_status(current_score, max_score, latest_state)
        description = _build_description(profile)

        observation = ToolObservation(
            observation_id=f"secure_score:{control_id}",
            tool=ToolSource.SECURE_SCORE,
            native_check_id=control_id,
            title=profile.get("title", ""),
            description=description,
            native_severity=severity,
            native_status=status,
            native_category=profile.get("controlCategory"),
            raw_data={
                "profile": profile,
                "score_data": score_data if score_data is not None else {},
            },
        )
        observations.append(observation)

    logger.info(
        "Parsed %d observations from Secure Score (%d profiles, %d scores)",
        len(observations),
        len(profiles),
        len(score_lookup),
    )
    return observations
