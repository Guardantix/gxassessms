"""Union-find dedup engine -- policy-agnostic grouping by shared dedup keys.

Groups Findings that share any dedup key into the same cluster using a
union-find (disjoint set) data structure. Handles transitive merges:
if Finding A shares a key with B, and B shares a key with C, all three
end up in the same group.

This module knows NOTHING about ConsolidationPolicy. It only groups.
The ConsolidationRule in rules.py decides what to do with the groups.

This module NEVER performs I/O.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from gxassessms.core.domain.models import Finding

logger = logging.getLogger(__name__)


_CARDINALITY_WARN_THRESHOLD = 50


class _DisjointSet:
    """Union-find data structure with path compression and union by rank.

    Each element is identified by an integer index. Uses iterative path
    compression (not recursive) to avoid stack overflow on deep chains.
    """

    def __init__(self, size: int) -> None:
        self._parent: list[int] = list(range(size))
        self._rank: list[int] = [0] * size

    def find(self, x: int) -> int:
        """Find the root representative of x with iterative path compression."""
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            next_x = self._parent[x]
            self._parent[x] = root
            x = next_x
        return root

    def union(self, x: int, y: int) -> None:
        """Merge the sets containing x and y using union by rank."""
        root_x = self.find(x)
        root_y = self.find(y)
        if root_x == root_y:
            return
        if self._rank[root_x] < self._rank[root_y]:
            self._parent[root_x] = root_y
        elif self._rank[root_x] > self._rank[root_y]:
            self._parent[root_y] = root_x
        else:
            self._parent[root_y] = root_x
            self._rank[root_x] += 1


class UnionFindDedup:
    """Groups Findings by shared dedup keys using union-find.

    Usage:
        engine = UnionFindDedup()
        groups = engine.group(findings)
        # groups is a list of lists; each inner list is a cluster of Findings

    The engine instance is reusable -- each call to group() starts fresh.
    Empty-string and whitespace-only dedup keys are filtered to prevent
    false merges (a warning is logged when a finding has no valid keys
    remaining).
    """

    def group(self, findings: list[Finding]) -> list[list[Finding]]:
        """Group findings that share any dedup key into clusters.

        Returns one list per cluster. Empty input returns empty output.
        Findings with no valid dedup keys after whitespace filtering each
        form an isolated single-element cluster.
        """
        if not findings:
            return []

        n = len(findings)
        ds = _DisjointSet(n)

        key_to_indices: dict[str, list[int]] = defaultdict(list)
        for idx, finding in enumerate(findings):
            had_valid_key = False
            for key in finding.dedup_keys:
                stripped = key.strip()
                if stripped:
                    key_to_indices[stripped].append(idx)
                    had_valid_key = True
                else:
                    logger.debug(
                        "Finding %s: filtered empty/whitespace dedup key %r",
                        finding.finding_key,
                        key,
                    )
            if not had_valid_key:
                logger.warning(
                    "Finding %s has no valid dedup keys after whitespace filtering; "
                    "it will form its own isolated group",
                    finding.finding_key,
                )

        for indices in key_to_indices.values():
            if len(indices) > _CARDINALITY_WARN_THRESHOLD:
                logger.warning(
                    "Dedup key shared by %d findings; possible adapter misconfiguration",
                    len(indices),
                )
            if len(indices) > 1:
                first = indices[0]
                for i in range(1, len(indices)):
                    ds.union(first, indices[i])

        groups_map: dict[int, list[Finding]] = defaultdict(list)
        for idx, finding in enumerate(findings):
            root = ds.find(idx)
            groups_map[root].append(finding)

        groups = list(groups_map.values())
        logger.debug("Dedup grouped %d findings into %d clusters", n, len(groups))
        return groups
