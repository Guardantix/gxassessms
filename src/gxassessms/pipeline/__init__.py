"""Pipeline layer -- stage execution engine, state machine, and replay.

The pipeline wires together adapters, policy, consolidation, persistence,
and QA into a sequential stage-based execution engine.

Key exports:
- Stage: Enum of pipeline stages
- Orchestrator: Pipeline execution engine (lazy import to avoid circular deps)
- EngagementState: State machine states (from state.py)
- PipelineEvent: Event journal record (from state.py)
- EngagementLock: Advisory file lock (from state.py)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gxassessms.pipeline.stages import Stage
from gxassessms.pipeline.state import EngagementLock, EngagementState, PipelineEvent

if TYPE_CHECKING:
    from gxassessms.pipeline.orchestrator import Orchestrator as Orchestrator

__all__ = [
    "EngagementLock",
    "EngagementState",
    "Orchestrator",
    "PipelineEvent",
    "Stage",
]


def __getattr__(name: str) -> object:
    if name == "Orchestrator":
        from gxassessms.pipeline.orchestrator import Orchestrator

        return Orchestrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
