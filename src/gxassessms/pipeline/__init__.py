"""Pipeline layer -- stage execution engine, state machine, and replay.

The pipeline wires together adapters, policy, consolidation, persistence,
and QA into a sequential stage-based execution engine.

Key exports:
- Stage: Enum of pipeline stages
- Orchestrator: Pipeline execution engine
- EngagementState: State machine states (from state.py)
- PipelineEvent: Event journal record (from state.py)
- EngagementLock: Advisory file lock (from state.py)
"""

from gxassessms.pipeline.orchestrator import Orchestrator
from gxassessms.pipeline.stages import Stage
from gxassessms.pipeline.state import EngagementLock, EngagementState, PipelineEvent

__all__ = [
    "EngagementLock",
    "EngagementState",
    "Orchestrator",
    "PipelineEvent",
    "Stage",
]
