"""ConsolidationPolicy -- dedup merge rules, severity reconciliation, confidence scoring.

Groups Findings by finding_key, reconciles severity when tools disagree,
computes ConfidenceScore, produces ConsolidatedFindings.

This module NEVER performs I/O. Rules are loaded by config/ and injected
as plain dicts.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from typing import Any, Protocol, runtime_checkable

from gxassessms.core.contracts.errors import ConsolidationError
from gxassessms.core.domain.constants import SEVERITY_ORDER
from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
)
from gxassessms.core.domain.models import (
    ConfidenceScore,
    ConsolidatedFinding,
    Finding,
    SourceEvidence,
)

logger = logging.getLogger(__name__)


@runtime_checkable
class ConsolidationPolicy(Protocol):
    """Protocol for consolidation policy extension point.

    Implementations reconcile conflicting severity/status, compute
    confidence scores, and produce ConsolidatedFindings.

    Two usage patterns:
    - consolidate(): full pipeline -- receives raw findings and returns consolidated output
    - merge_group(): merges a pre-formed group (e.g., from union-find dedup)

    Contract: ``merge_group()`` requires ``findings`` to be non-empty.
    Implementations must raise ``ConsolidationError`` if called with an
    empty list.
    """

    def consolidate(self, findings: list[Finding]) -> list[ConsolidatedFinding]: ...

    def merge_group(self, finding_key: str, findings: list[Finding]) -> ConsolidatedFinding: ...


class DefaultConsolidationPolicy:
    """Default consolidation policy shipped with the public package.

    Pure function: Findings + rules in, ConsolidatedFindings out. No I/O.
    """

    def __init__(self, rules: dict[str, Any]) -> None:
        self._rules = rules

    def consolidate(self, findings: list[Finding]) -> list[ConsolidatedFinding]:
        """Group findings by finding_key, merge, and compute confidence."""
        if not findings:
            return []

        # Group by finding_key
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            groups[finding.finding_key].append(finding)

        consolidated: list[ConsolidatedFinding] = []
        for finding_key, group in groups.items():
            cf = self.merge_group(finding_key, group)
            consolidated.append(cf)

        return consolidated

    def merge_group(self, finding_key: str, findings: list[Finding]) -> ConsolidatedFinding:
        """Merge a pre-formed group of Findings into a single ConsolidatedFinding."""
        if not findings:
            raise ConsolidationError(
                f"merge_group() requires at least one Finding (finding_key={finding_key!r})"
            )
        severity = self._reconcile_severity(findings)
        status = self._reconcile_status(findings)
        title = self._reconcile_title(findings)
        description = self._reconcile_description(findings)
        sources = self._build_sources(findings)
        benchmark_refs = self._merge_benchmark_refs(findings)
        confidence = self._compute_confidence(findings)
        category = self._reconcile_category(findings)

        # Per spec: finding_instance_id is engagement-specific and never reused across
        # engagements, even for the same finding_key.  The persistence layer handles
        # within-engagement dedup via (engagement_id, finding_key).
        finding_instance_id = str(uuid.uuid4())

        return ConsolidatedFinding(
            finding_instance_id=finding_instance_id,
            finding_key=finding_key,
            title=title,
            severity=severity,
            status=status,
            category=category,
            description=description,
            sources=sources,
            confidence=confidence,
            benchmark_refs=benchmark_refs,
        )

    def _reconcile_severity(self, group: list[Finding]) -> Severity:
        """Take the highest severity across all findings in the group."""
        return max(
            (f.severity for f in group),
            key=lambda s: SEVERITY_ORDER.get(s.value, 0),
        )

    def _reconcile_status(self, group: list[Finding]) -> FindingStatus:
        """Take the highest-priority status (FAIL wins over PASS, etc.).

        Status priority is an ordered list (lower index = higher priority).
        min() selects the element with the lowest index, i.e., the highest-priority status.
        """
        merge_strategy = self._rules.get("merge_strategy", {})
        status_priority = merge_strategy.get(
            "status_priority",
            [
                FindingStatus.FAIL.value,
                FindingStatus.ERROR.value,
                FindingStatus.WARNING.value,
                FindingStatus.MANUAL.value,
                FindingStatus.PASS.value,
                FindingStatus.NOT_APPLICABLE.value,
            ],
        )
        if not status_priority:
            raise ValueError(
                "merge_strategy.status_priority must not be empty; "
                "cannot reconcile finding status without a priority list."
            )

        priority_map = {s: i for i, s in enumerate(status_priority)}

        known = set(status_priority)
        warned: set[str] = set()
        for f in group:
            if f.status.value not in known and f.status.value not in warned:
                warned.add(f.status.value)
                logger.warning(
                    "FindingStatus %r is not in configured status_priority list; "
                    "it will be treated as lowest priority (below %r). "
                    "Update consolidation rules to set explicit priority.",
                    f.status.value,
                    status_priority[-1],
                )

        return min(
            (f.status for f in group),
            key=lambda s: (priority_map.get(s.value, len(status_priority)), s.value),
        )

    def _reconcile_title(self, group: list[Finding]) -> str:
        """Use the title from the highest-severity finding; tool then check ID as tie-breaks."""
        highest = max(
            group,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity.value, 0),
                f.tool.value,
                f.native_check_id,
            ),
        )
        return highest.title

    def _reconcile_category(self, group: list[Finding]) -> Category:
        """Use the category from the highest-severity finding; category name as tie-break."""
        return max(
            group,
            key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 0), f.category.name),
        ).category

    def _reconcile_description(self, group: list[Finding]) -> str:
        """Concatenate unique descriptions from all sources, sorted for stability."""
        seen: set[str] = set()
        descriptions: list[str] = []
        for finding in group:
            if finding.description not in seen:
                seen.add(finding.description)
                descriptions.append(finding.description)
        return " | ".join(sorted(descriptions))

    @staticmethod
    def _build_sources(group: list[Finding]) -> list[SourceEvidence]:
        """Build SourceEvidence list from group members."""
        return [
            SourceEvidence(
                tool=finding.tool,
                check_id=finding.native_check_id,
                raw_data=dict(finding.raw_data),
            )
            for finding in group
        ]

    @staticmethod
    def _merge_benchmark_refs(group: list[Finding]) -> list[str]:
        """Merge benchmark refs from all findings, deduped, order preserved."""
        seen: set[str] = set()
        merged: list[str] = []
        for finding in group:
            for ref in finding.benchmark_refs:
                if ref not in seen:
                    seen.add(ref)
                    merged.append(ref)
        return merged

    def _compute_confidence(self, group: list[Finding]) -> ConfidenceScore:
        """Compute confidence from tool count, evidence weights, and corroboration rules."""
        weights = self._rules.get("confidence_weights", {})
        w_evidence = weights.get("evidence_strength", 0.30)
        w_corroboration = weights.get("corroboration", 0.35)
        w_freshness = weights.get("data_freshness", 0.20)
        w_provenance = weights.get("provenance", 0.15)

        # Count distinct tools
        distinct_tools = len({f.tool for f in group})

        # Evidence strength: direct observations score high
        evidence_strength = min(1.0, 0.6 + (distinct_tools * 0.1))

        # Corroboration score from rules.
        # Use the highest configured tier that does not exceed distinct_tools (floor lookup).
        # An exact-key lookup with fallback would under-score multi-tool findings when the
        # config omits intermediate tiers (e.g. {1: 0.4, 2: 0.7, 4: 0.95} with 3 tools).
        corroboration_scores_raw = self._rules.get("corroboration_scores", {})
        if corroboration_scores_raw:
            # Coerce keys to int so YAML quoted keys ("1") don't cause TypeError.
            try:
                corroboration_scores = {
                    int(k): float(v) for k, v in corroboration_scores_raw.items()
                }
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"corroboration_scores entries must have integer keys and numeric values, "
                    f"got: {dict(corroboration_scores_raw)}"
                ) from exc
            # Floor lookup: highest tier <= distinct_tools. When no tier qualifies
            # (all configured tiers exceed distinct_tools), use the conservative 0.4
            # default rather than min(corroboration_scores), which could assign a
            # multi-tool tier to a single-tool finding and inflate confidence.
            applicable = [k for k in corroboration_scores if k <= distinct_tools]
            if applicable:
                corroboration = corroboration_scores[max(applicable)]
            else:
                corroboration = 0.4
                logger.debug(
                    "No corroboration tier <= %d tools; using conservative default (0.4)",
                    distinct_tools,
                )
        else:
            corroboration = 0.4
            logger.debug("No corroboration_scores configured; using default (0.4)")

        # Data freshness: default to 1.0 (fresh) -- actual staleness
        # is computed by the pipeline stage that has access to timestamps
        data_freshness = 1.0

        # Provenance: system-generated for initial consolidation
        provenance_str = "system-generated"
        provenance_scores = self._rules.get("provenance_scores", {})
        provenance_score = provenance_scores.get(provenance_str, 0.7)

        overall = (
            (evidence_strength * w_evidence)
            + (corroboration * w_corroboration)
            + (data_freshness * w_freshness)
            + (provenance_score * w_provenance)
        )
        overall = min(1.0, max(0.0, overall))

        return ConfidenceScore(
            evidence_strength=round(evidence_strength, 4),
            corroborating_tools=distinct_tools,
            data_freshness=round(data_freshness, 4),
            provenance=provenance_str,
            overall=round(overall, 4),
        )
