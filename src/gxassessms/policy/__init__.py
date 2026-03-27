"""Policy engine -- pure functions that consume reference tables and produce decisions.

Policy modules NEVER do I/O. YAML rule files are loaded by config/ and injected
as plain dicts. Each policy module defines a Protocol for its extension point
and ships a default implementation.

Three policy tiers:
1. Reference tables (YAML) -- pure data, no branching logic
2. Deterministic policy functions (Python) -- side-effect-free, consume reference tables
3. Policy recommendations (AI/analytics) -- never auto-applied (separate plans)
"""

__all__ = [
    "ConsolidationPolicy",
    "DefaultConsolidationPolicy",
    "DefaultNormalizationPolicy",
    "DefaultReportingPolicy",
    "DefaultRoadmapPolicy",
    "DefaultSeverityPolicy",
    "NormalizationPolicy",
    "ReportingPolicy",
    "RoadmapPolicy",
    "SeverityPolicy",
]

from gxassessms.policy.consolidation import (
    ConsolidationPolicy as ConsolidationPolicy,
)
from gxassessms.policy.consolidation import (
    DefaultConsolidationPolicy as DefaultConsolidationPolicy,
)
from gxassessms.policy.normalization import (
    DefaultNormalizationPolicy as DefaultNormalizationPolicy,
)
from gxassessms.policy.normalization import (
    NormalizationPolicy as NormalizationPolicy,
)
from gxassessms.policy.reporting import (
    DefaultReportingPolicy as DefaultReportingPolicy,
)
from gxassessms.policy.reporting import (
    ReportingPolicy as ReportingPolicy,
)
from gxassessms.policy.roadmap import (
    DefaultRoadmapPolicy as DefaultRoadmapPolicy,
)
from gxassessms.policy.roadmap import (
    RoadmapPolicy as RoadmapPolicy,
)
from gxassessms.policy.severity import (
    DefaultSeverityPolicy as DefaultSeverityPolicy,
)
from gxassessms.policy.severity import (
    SeverityPolicy as SeverityPolicy,
)
