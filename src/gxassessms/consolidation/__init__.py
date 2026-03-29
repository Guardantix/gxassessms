"""Consolidation engine -- dedup grouping and rule execution.

Two modules with distinct responsibilities:
- dedup.py: Policy-agnostic union-find grouping by shared dedup keys
- rules.py: ConsolidationRule Protocol implementation that wires
  dedup groups to ConsolidationPolicy merge_group() logic
"""

from gxassessms.consolidation.dedup import UnionFindDedup
from gxassessms.consolidation.rules import DefaultConsolidationRule

__all__ = [
    "DefaultConsolidationRule",
    "UnionFindDedup",
]
