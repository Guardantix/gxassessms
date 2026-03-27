"""NormalizationPolicy -- maps ToolObservation -> Finding.

Applies severity mapping, category mapping, dedup key assignment.
Consumes adapter-specific mappings and centralized cross-reference data.

This module NEVER performs I/O. YAML rules are loaded by config/ and
injected as plain dicts.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
)
from gxassessms.core.domain.models import Finding, ToolObservation

logger = logging.getLogger(__name__)


@runtime_checkable
class NormalizationPolicy(Protocol):
    """Protocol for normalization policy extension point.

    Implementations transform raw ToolObservations into normalized Findings
    using severity mapping, category mapping, and dedup key assignment.
    """

    def normalize(
        self,
        observations: list[ToolObservation],
        adapter_severity_map: dict[tuple[str, str], str],
        adapter_category_map: dict[str, str],
        adapter_dedup_keys: dict[str, str],
    ) -> list[Finding]: ...


class DefaultNormalizationPolicy:
    """Default normalization policy shipped with the public package.

    Pure function: reference data in, normalized Findings out. No I/O.
    """

    def __init__(self, rules: dict[str, Any]) -> None:
        self._rules = rules

    def normalize(
        self,
        observations: list[ToolObservation],
        adapter_severity_map: dict[tuple[str, str], str],
        adapter_category_map: dict[str, str],
        adapter_dedup_keys: dict[str, str],
    ) -> list[Finding]:
        """Transform ToolObservations into normalized Findings."""
        findings: list[Finding] = []
        for obs in observations:
            severity = self._resolve_severity(obs, adapter_severity_map)
            category = self._resolve_category(obs, adapter_category_map)
            status = self._resolve_status(obs)
            finding_key = self._resolve_finding_key(obs, adapter_dedup_keys)
            dedup_keys = [finding_key]

            finding = Finding(
                observation_id=obs.observation_id,
                finding_key=finding_key,
                tool=obs.tool,
                title=obs.title,
                severity=severity,
                status=status,
                category=category,
                description=obs.description,
                dedup_keys=dedup_keys,
                benchmark_refs=list(obs.benchmark_refs),
                raw_data=dict(obs.raw_data),
            )
            findings.append(finding)

        return findings

    def _resolve_severity(
        self,
        obs: ToolObservation,
        adapter_severity_map: dict[tuple[str, str], str],
    ) -> Severity:
        """Resolve severity: adapter-specific map first, then default rules, then fallback."""
        # Try adapter-specific severity map
        key = (obs.native_severity, obs.native_status)
        adapter_result = adapter_severity_map.get(key)
        if adapter_result is not None:
            return Severity(adapter_result)

        # Try default severity map from rules
        default_map = self._rules.get("default_severity_map", [])
        for entry in default_map:
            if entry["requirement"] == obs.native_severity and entry["status"] == obs.native_status:
                return Severity(entry["severity"])

        # Fallback severity
        fallback = self._rules.get("fallback_severity", "MEDIUM")
        return Severity(fallback)

    def _resolve_category(
        self,
        obs: ToolObservation,
        adapter_category_map: dict[str, str],
    ) -> Category:
        """Resolve category from check ID prefix using adapter map, then default rules."""
        prefix = self._extract_module_prefix(obs.native_check_id)

        # Try adapter-specific category map
        if prefix and prefix in adapter_category_map:
            category_key = adapter_category_map[prefix]
            return self._category_key_to_enum(category_key)

        # Try default category map from rules
        default_map = self._rules.get("default_category_map", {})
        if prefix and prefix in default_map:
            return self._category_key_to_enum(default_map[prefix])

        # Fallback category
        fallback = self._rules.get("fallback_category", "COMPLIANCE")
        return self._category_key_to_enum(fallback)

    def _resolve_status(self, obs: ToolObservation) -> FindingStatus:
        """Map tool-native status to domain FindingStatus."""
        status_map = self._rules.get("default_status_map", {})
        mapped = status_map.get(obs.native_status)
        if mapped is not None:
            return FindingStatus(mapped)
        # If no mapping, try direct conversion
        return FindingStatus(obs.native_status)

    def _resolve_finding_key(
        self,
        obs: ToolObservation,
        adapter_dedup_keys: dict[str, str],
    ) -> str:
        """Resolve finding_key from adapter dedup keys or fallback pattern.

        Format when mapped: {namespace}:{control_id} (e.g., cis:m365:1.1.1)
        Format when fallback: {tool}:{native_check_id} (e.g., ScubaGear:MS.AAD.3.1v1)
        """
        # Try adapter-specific dedup key
        mapped_key = adapter_dedup_keys.get(obs.native_check_id)
        if mapped_key is not None:
            return mapped_key

        # Fallback: use the pattern from rules
        pattern = self._rules.get("dedup_key_fallback_pattern", "{tool}:{native_check_id}")
        return pattern.format(
            tool=obs.tool.value,
            native_check_id=obs.native_check_id,
        )

    @staticmethod
    def _extract_module_prefix(native_check_id: str) -> str | None:
        """Extract the module prefix from a tool-native check ID.

        Examples:
            MS.AAD.3.1v1 -> aad
            MS.EXO.4.1v1 -> exo
            MT.1003 -> (no prefix extractable, returns None)
            m365.iam.mfa_admins -> iam
        """
        # ScubaGear pattern: MS.{MODULE}.x.y
        if native_check_id.startswith("MS."):
            parts = native_check_id.split(".")
            if len(parts) >= 3:
                return parts[1].lower()

        # Monkey365 pattern: m365.{module}.check_name
        if native_check_id.startswith("m365."):
            parts = native_check_id.split(".")
            if len(parts) >= 3:
                return parts[1].lower()

        return None

    @staticmethod
    def _category_key_to_enum(key: str) -> Category:
        """Convert a category key (e.g., 'IDENTITY_ACCESS') to a Category enum.

        Handles both enum-name keys (IDENTITY_ACCESS) and display-name values
        (Identity & Access).
        """
        # Try direct enum name lookup
        try:
            return Category[key]
        except KeyError:
            pass

        # Try value lookup (display name)
        for cat in Category:
            if cat.value == key:
                return cat

        # Fallback to COMPLIANCE
        return Category.COMPLIANCE
