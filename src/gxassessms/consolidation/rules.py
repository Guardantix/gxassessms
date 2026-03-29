"""ConsolidationRule implementations.

The DefaultConsolidationRule wires two concerns together:
1. The union-find dedup engine (dedup.py) groups Findings by shared dedup keys
2. The ConsolidationPolicy (policy/consolidation.py) merges each group into
   a ConsolidatedFinding via merge_group() (severity reconciliation,
   confidence scoring, etc.)

This separation means:
- dedup.py and policy/consolidation.py have no knowledge of each other
  -- rules.py is the only bridge
- The dedup algorithm can be tested and optimized independently
- The merge policy can be swapped via entry points without touching grouping

This module NEVER performs I/O.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gxassessms.consolidation.dedup import UnionFindDedup
from gxassessms.core.contracts.errors import ConsolidationError
from gxassessms.core.domain.constants import SEVERITY_ORDER

if TYPE_CHECKING:
    from gxassessms.core.domain.models import ConsolidatedFinding, Finding
    from gxassessms.policy.consolidation import ConsolidationPolicy

logger = logging.getLogger(__name__)


class DefaultConsolidationRule:
    """Default consolidation rule shipped with the public package.

    Implements the ConsolidationRule Protocol defined in
    gxassessms.core.contracts.types.

    Usage:
        policy = DefaultConsolidationPolicy(rules=loaded_yaml)
        rule = DefaultConsolidationRule(policy=policy)
        consolidated = rule.consolidate(findings)
    """

    def __init__(self, policy: ConsolidationPolicy) -> None:
        self._policy = policy
        self._dedup = UnionFindDedup()

    def consolidate(self, findings: list[Finding]) -> list[ConsolidatedFinding]:
        """Group findings by shared dedup keys, then merge each group.

        Steps:
        1. Use union-find dedup engine to group findings with shared keys
        2. For each group, select a canonical finding_key
        3. Delegate to ConsolidationPolicy.merge_group() to produce a
           ConsolidatedFinding per group

        Returns a list of ConsolidatedFinding objects -- one per dedup group.
        """
        if not findings:
            return []

        # Step 1: Group findings by shared dedup keys
        groups = self._dedup.group(findings=findings)

        logger.info(
            "Consolidation: %d findings grouped into %d clusters",
            len(findings),
            len(groups),
        )

        # Step 2-3: Select canonical key and merge each group
        consolidated: list[ConsolidatedFinding] = []
        for i, group in enumerate(groups):
            try:
                canonical_key = self._select_canonical_finding_key(group)
                merged = self._policy.merge_group(finding_key=canonical_key, findings=group)
            except (ConsolidationError, ValueError) as exc:
                raise ConsolidationError(
                    f"Failed to consolidate group {i + 1}/{len(groups)} "
                    f"(group_size={len(group)}): {type(exc).__name__}: {exc}"
                ) from exc
            consolidated.append(merged)

        logger.info(
            "Consolidation complete: %d consolidated findings",
            len(consolidated),
        )

        return consolidated

    @staticmethod
    def _select_canonical_finding_key(group: list[Finding]) -> str:
        """Select the canonical finding_key for a merged group.

        Strategy:
        1. If all findings share the same finding_key, use it (common case)
        2. Otherwise, use the finding_key from the highest-severity finding
        3. Tiebreak: lexicographically highest (max()) for deterministic output
        """
        if not group:
            raise ConsolidationError("Cannot select canonical finding_key from empty group")

        unique_keys = {f.finding_key for f in group}
        if len(unique_keys) == 1:
            return unique_keys.pop()

        # Highest severity, then lexicographically highest (max()) for stability
        canonical = max(
            group,
            key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 0), f.finding_key),
        ).finding_key
        logger.debug(
            "Canonical key tiebreak: selected %r from %d candidates",
            canonical,
            len(unique_keys),
        )
        return canonical
