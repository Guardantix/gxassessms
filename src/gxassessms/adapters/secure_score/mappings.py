"""Secure Score declarative mappings -- data, not logic.

Maps Microsoft Secure Score Graph API values to domain enums.
Severity is derived from rank + tier (Microsoft's own prioritization),
NOT from score gap.
"""

from __future__ import annotations

import logging

from gxassessms.core.domain.enums import Category, Severity

logger = logging.getLogger(__name__)

CATEGORY_MAP: dict[str, Category] = {
    "Identity": Category.IDENTITY_ACCESS,
    "Data": Category.DATA_PROTECTION,
    "Device": Category.DEVICE_MANAGEMENT,
    "Apps": Category.COMPLIANCE,
    "Infrastructure": Category.INFRASTRUCTURE_SECURITY,
}

CONTROL_STATE_PASS_THROUGH: frozenset[str] = frozenset(
    {
        "ignored",
        "thirdParty",
    }
)

_TIER_THRESHOLDS: dict[str, list[tuple[int, Severity]]] = {
    "Core": [
        (20, Severity.CRITICAL),
        (50, Severity.HIGH),
    ],
    "Defense in Depth": [
        (30, Severity.HIGH),
        (60, Severity.MEDIUM),
    ],
    "Advanced": [
        (40, Severity.MEDIUM),
    ],
}

_TIER_DEFAULTS: dict[str, Severity] = {
    "Core": Severity.HIGH,
    "Defense in Depth": Severity.MEDIUM,
    "Advanced": Severity.LOW,
}


def derive_severity(rank: int, tier: str) -> Severity:
    """Derive severity from Secure Score rank and tier.

    Args:
        rank: Microsoft's priority ranking (lower = higher priority).
        tier: Control tier: "Core", "Defense in Depth", or "Advanced".

    Returns:
        Derived Severity enum value. Falls back to INFO for unknown tiers.
    """
    thresholds = _TIER_THRESHOLDS.get(tier)
    if thresholds is None:
        logger.warning(
            "Unknown Secure Score tier %r (rank=%d); falling back to INFO severity. "
            "Update _TIER_THRESHOLDS if Microsoft has added a new tier.",
            tier,
            rank,
        )
        return Severity.INFO

    for threshold, severity in thresholds:
        if rank <= threshold:
            return severity

    return _TIER_DEFAULTS.get(tier, Severity.INFO)
