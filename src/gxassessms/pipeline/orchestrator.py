"""Pipeline orchestrator -- DI, state management, overrides, hash invalidation.

The Orchestrator is the integration point that wires together all layers.
It does not contain domain logic; it manages state transitions and delegates
to stage functions via the _runner module.

Stage execution itself lives in _runner.py to keep both files under 400 lines.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.config.datetime_utils import utc_now
from gxassessms.core.contracts.errors import PersistenceError, PipelineError
from gxassessms.core.domain.enums import Severity
from gxassessms.core.domain.models import Finding
from gxassessms.persistence import (
    ArtifactManager,
    CoverageRepo,
    DatabaseManager,
    EngagementRepo,
    EventRepo,
    FindingRepo,
)
from gxassessms.pipeline.stages import STAGE_STATE_MAP, Stage, get_stages_from
from gxassessms.pipeline.state import EngagementLock, EngagementState, PipelineEvent

logger = logging.getLogger(__name__)


def _extract_payload(event: Any) -> dict[str, Any]:
    """Extract the payload dict from an event row or object.

    EventRepo.get_events_by_type() returns list[dict[str, Any]] where
    the 'payload' value is a JSON string. PipelineEvent and similar
    objects use a .payload attribute. We handle both representations.
    """
    if isinstance(event, dict):
        raw: str | dict[str, Any] = event["payload"]  # pyright: ignore[reportUnknownVariableType]
        if isinstance(raw, str):
            try:
                result: dict[str, Any] = json.loads(raw)
            except json.JSONDecodeError as e:
                raise PersistenceError(f"Corrupt event payload: {e}") from e
            return result
        return raw  # type: ignore[no-any-return]
    # Mock objects use attribute access
    return dict(event.payload)  # type: ignore[union-attr]


class Orchestrator:
    """Pipeline execution engine with dependency injection.

    Manages engagement state transitions, delegates stage execution to
    _runner.run_stages(), and provides override/manual-finding operations
    that mutate engagement data under an advisory lock.
    """

    def __init__(
        self,
        engagement_repo: EngagementRepo,
        event_repo: EventRepo,
        finding_repo: FindingRepo,
        coverage_repo: CoverageRepo,
        lock: EngagementLock,
        db: DatabaseManager,
        artifact_manager: ArtifactManager,
    ) -> None:
        if engagement_repo is None:  # type: ignore[comparison-overlap]
            raise TypeError("engagement_repo is required")

        self._engagement_repo = engagement_repo
        self._event_repo = event_repo
        self._finding_repo = finding_repo
        self._coverage_repo = coverage_repo
        self._lock = lock
        self._db = db
        self._artifact_manager = artifact_manager

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def _transition_state(
        self,
        engagement_id: str,
        from_state: EngagementState,
        to_state: EngagementState,
        content_hash: str | None = None,
    ) -> None:
        """Validate and execute a state transition.

        Calls EngagementState.assert_can_transition_to() for validation,
        then persists the new state and appends a journal event.

        Args:
            engagement_id: Engagement to transition.
            from_state: Expected current state.
            to_state: Target state.
            content_hash: Optional content hash for completed states.

        Raises:
            InvalidTransitionError: If the transition is not valid.
        """
        EngagementState.assert_can_transition_to(from_state, to_state)
        self._engagement_repo.update_state(engagement_id, to_state)

        payload: dict[str, Any] = {
            "from": from_state.value,
            "to": to_state.value,
        }
        if content_hash is not None:
            payload["content_hash"] = content_hash

        event = PipelineEvent(
            event_id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            timestamp=utc_now(),
            event_type="state_transition",
            actor="system",
            payload=payload,
        )
        self._event_repo.append(event)

    # ------------------------------------------------------------------
    # Overrides and manual findings
    # ------------------------------------------------------------------

    def override_severity(
        self,
        engagement_id: str,
        finding_id: str,
        new_severity: Severity,
        reason: str,
        actor: str,
    ) -> None:
        """Override the severity of a finding under lock.

        Args:
            engagement_id: Engagement owning the finding.
            finding_id: Finding to override.
            new_severity: New severity value.
            reason: Human-readable justification.
            actor: Who initiated the override (e.g. "human:rick").
        """
        with self._lock.hold(engagement_id):
            self._finding_repo.override_severity(
                finding_id=finding_id,
                new_severity=new_severity,
                reason=reason,
                actor=actor,
                engagement_id=engagement_id,
            )
            event = PipelineEvent(
                event_id=str(uuid.uuid4()),
                engagement_id=engagement_id,
                timestamp=utc_now(),
                event_type="override",
                actor=actor,
                payload={
                    "finding_id": finding_id,
                    "field": "severity",
                    "new_severity": new_severity.value,
                    "reason": reason,
                },
            )
            self._event_repo.append(event)

    def add_manual_finding(
        self,
        engagement_id: str,
        finding: Finding,
        actor: str,
    ) -> None:
        """Add a manually-created finding under lock.

        Args:
            engagement_id: Engagement to add the finding to.
            finding: Finding model to persist.
            actor: Who added the finding (e.g. "human:rick").
        """
        finding_dict = finding.model_dump()
        with self._lock.hold(engagement_id):
            self._finding_repo.add_manual_finding(
                engagement_id=engagement_id,
                finding=finding_dict,
            )
            event = PipelineEvent(
                event_id=str(uuid.uuid4()),
                engagement_id=engagement_id,
                timestamp=utc_now(),
                event_type="manual_finding_added",
                actor=actor,
                payload={
                    "finding_key": finding.finding_key,
                    "severity": finding.severity.value,
                },
            )
            self._event_repo.append(event)

    # ------------------------------------------------------------------
    # QA strategy inspection
    # ------------------------------------------------------------------

    def _should_auto_advance_qa(self, strategy: Any) -> bool:
        """Return True if the QA strategy is a no-op (auto-advance)."""
        return getattr(strategy, "is_noop", False) is True

    # ------------------------------------------------------------------
    # Stage ordering
    # ------------------------------------------------------------------

    def _get_stages_to_run(self, start_stage: Stage) -> list[Stage]:
        """Return the ordered list of stages from start_stage onward."""
        return get_stages_from(start_stage)

    # ------------------------------------------------------------------
    # Content hashing and invalidation
    # ------------------------------------------------------------------

    def _compute_content_hash(self, data: Any) -> str:
        """Compute SHA-256 hash of JSON-serialized data.

        Uses sort_keys and default=str for deterministic serialization.
        """
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _get_last_stage_hash(self, engagement_id: str, stage: Stage) -> str | None:
        """Scan state_transition events for the last content_hash of a stage.

        Looks for events where the 'to' field matches the stage's completed
        state, and returns the content_hash from the most recent one.
        Uses _extract_payload() for event deserialization.
        """
        _, completed_state = STAGE_STATE_MAP[stage]
        events = self._event_repo.get_events_by_type(engagement_id, "state_transition")
        last_hash: str | None = None
        for event in events:
            payload = _extract_payload(event)
            if payload.get("to") == completed_state.value:
                last_hash = payload.get("content_hash")
        return last_hash

    def _is_stage_invalidated(
        self,
        engagement_id: str,
        stage: Stage,
        current_input_hash: str,
    ) -> bool:
        """Check whether a stage needs re-execution due to changed input.

        Returns True if no prior hash exists or if the hashes differ.
        """
        last_hash = self._get_last_stage_hash(engagement_id, stage)
        if last_hash is None:
            return True
        return last_hash != current_input_hash

    # ------------------------------------------------------------------
    # Current state inspection
    # ------------------------------------------------------------------

    def _get_current_state(self, engagement_id: str) -> EngagementState:
        """Get the current EngagementState for an engagement."""
        engagement = self._engagement_repo.get(engagement_id)
        return EngagementState(engagement["state"])

    def _detect_stale_running(
        self,
        engagement_id: str,
        current_state: EngagementState,
    ) -> bool:
        """Check if the engagement is stuck in a RUNNING state.

        Returns True if current_state is one of the "running" states
        in STAGE_STATE_MAP (COLLECTING, PARSING, etc.), which indicates
        a prior process crashed mid-stage.

        QA_REVIEW is excluded: non-noop QA strategies intentionally
        park the engagement at QA_REVIEW for human approval. That is
        a legitimate waiting state, not a crash.
        """
        running_states = {running for running, _completed in STAGE_STATE_MAP.values()}
        running_states.discard(EngagementState.QA_REVIEW)
        return current_state in running_states

    # ------------------------------------------------------------------
    # Rerun reset
    # ------------------------------------------------------------------

    def reset_for_rerun(self, engagement_id: str, target_stage: Stage) -> None:
        """Reset engagement state to allow re-execution from target_stage.

        Used by --rerun and --force-stage CLI options. Bypasses normal
        transition validation (like crash recovery) because the operator
        is intentionally requesting re-execution from a terminal or
        completed state.

        No-ops if the engagement is already at the required entry state.
        """
        from gxassessms.pipeline.stages import get_stage_entry_state

        current_state = self._get_current_state(engagement_id)
        entry_state = get_stage_entry_state(target_stage)

        if current_state == entry_state:
            return  # Already at the right state

        # Guard: RENDER requires QA_APPROVED in the event journal.
        # Without this, replay --from report can bypass the human approval gate.
        if target_stage == Stage.RENDER:
            events = self._event_repo.get_events_by_type(engagement_id, "state_transition")
            completed_states = {_extract_payload(e).get("to") for e in events}
            if "QA_APPROVED" not in completed_states:
                raise PipelineError(
                    message=(
                        "Cannot reset to RENDER: QA has not been approved. "
                        "Complete QA review before replaying from report."
                    ),
                    engagement_id=engagement_id,
                    stage=Stage.RENDER.value,
                )

        self._engagement_repo.force_update_state(engagement_id, entry_state)

        event = PipelineEvent(
            event_id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            timestamp=utc_now(),
            event_type="rerun",
            actor="system",
            payload={
                "from_state": current_state.value,
                "to_state": entry_state.value,
                "target_stage": target_stage.value,
                "reason": "operator_rerun",
            },
        )
        self._event_repo.append(event)
        logger.info(
            "Reset engagement %s from %s to %s for rerun at %s",
            engagement_id,
            current_state.value,
            entry_state.value,
            target_stage.value,
        )

    # ------------------------------------------------------------------
    # Resume stage determination
    # ------------------------------------------------------------------

    def determine_resume_stage(self, engagement_id: str) -> Stage | None:
        """Determine which stage to resume from based on current engagement state.

        Returns the Stage to resume from, or None for terminal/waiting states:
        - COMPLETE: no work to do (no-op)
        - QA_REVIEW: awaiting human approval (cannot auto-resume)

        For FAILED engagements, scans the event journal for the last failed
        stage. Raises PipelineError if the failed stage cannot be determined.
        """
        current_state = self._get_current_state(engagement_id)

        # Terminal / waiting states
        if current_state in (EngagementState.COMPLETE, EngagementState.QA_REVIEW):
            return None

        # Completed states -> next stage
        _COMPLETED_TO_NEXT: dict[EngagementState, Stage] = {
            EngagementState.CREATED: Stage.COLLECT,
            EngagementState.COLLECTED: Stage.PARSE,
            EngagementState.PARSED: Stage.NORMALIZE,
            EngagementState.NORMALIZED: Stage.CONSOLIDATE,
            EngagementState.CONSOLIDATED: Stage.QA_REVIEW,
            EngagementState.QA_APPROVED: Stage.RENDER,
        }
        if current_state in _COMPLETED_TO_NEXT:
            return _COMPLETED_TO_NEXT[current_state]

        # Running (*ING) states -> owning stage (stale recovery handles the rest)
        for stage, (running, _completed) in STAGE_STATE_MAP.items():
            if running == current_state:
                return stage

        # FAILED -> find last failed stage from event journal
        if current_state == EngagementState.FAILED:
            events = self._event_repo.get_events_by_type(engagement_id, "state_transition")
            for event in reversed(events):
                payload = _extract_payload(event)
                if payload.get("to") == "FAILED":
                    from_state_val = payload.get("from", "")
                    for stage, (running, _) in STAGE_STATE_MAP.items():
                        if running.value == from_state_val:
                            return stage
                    break
            raise PipelineError(
                message=(
                    "Engagement is FAILED but the failed stage cannot be determined "
                    "from the event journal. Use --force-stage to specify."
                ),
                engagement_id=engagement_id,
                stage="",
            )

        # Unreachable for valid EngagementState values, but fail-closed
        raise PipelineError(
            message=f"Unexpected engagement state: {current_state.value}",
            engagement_id=engagement_id,
            stage="",
        )

    # ------------------------------------------------------------------
    # Pipeline execution entry points
    # ------------------------------------------------------------------

    def run(
        self,
        engagement_id: str,
        config: EngagementConfig,
        adapters: list[Any],
        normalization_policy: Any,
        consolidation_rule: Any,
        qa_strategy: Any,
        renderers: list[Any],
        output_dir: Path | None = None,
    ) -> None:
        """Run the full pipeline from COLLECT through RENDER.

        Args:
            engagement_id: Engagement to execute.
            config: Engagement configuration.
            adapters: List of ToolAdapter implementations.
            normalization_policy: NormalizationPolicy implementation.
            consolidation_rule: ConsolidationRule implementation.
            qa_strategy: QAStrategy implementation.
            renderers: List of ReportRenderer implementations.
            output_dir: Optional output directory for rendered reports.
        """
        from gxassessms.pipeline._runner import run_stages

        run_stages(
            orchestrator=self,
            engagement_id=engagement_id,
            config=config,
            adapters=adapters,
            normalization_policy=normalization_policy,
            consolidation_rule=consolidation_rule,
            qa_strategy=qa_strategy,
            renderers=renderers,
            start_stage=Stage.COLLECT,
            output_dir=output_dir,
        )

    def run_from(
        self,
        engagement_id: str,
        config: EngagementConfig,
        start_stage: Stage,
        adapters: list[Any],
        normalization_policy: Any,
        consolidation_rule: Any,
        qa_strategy: Any,
        renderers: list[Any],
        output_dir: Path | None = None,
        stop_stage: Stage | None = None,
    ) -> None:
        """Run the pipeline from a specific stage onward.

        Used for resumption after failure or re-running from a checkpoint.
        Pass stop_stage to halt after a specific stage completes (e.g. to
        run only collect without crashing on missing normalization/QA strategies).

        Args:
            engagement_id: Engagement to execute.
            config: Engagement configuration.
            start_stage: Stage to begin execution from.
            adapters: List of ToolAdapter implementations.
            normalization_policy: NormalizationPolicy implementation.
            consolidation_rule: ConsolidationRule implementation.
            qa_strategy: QAStrategy implementation.
            renderers: List of ReportRenderer implementations.
            output_dir: Optional output directory for rendered reports.
            stop_stage: Optional stage to stop after. Defaults to None (run
                to completion).
        """
        from gxassessms.pipeline._runner import run_stages

        run_stages(
            orchestrator=self,
            engagement_id=engagement_id,
            config=config,
            adapters=adapters,
            normalization_policy=normalization_policy,
            consolidation_rule=consolidation_rule,
            qa_strategy=qa_strategy,
            renderers=renderers,
            start_stage=start_stage,
            output_dir=output_dir,
            stop_stage=stop_stage,
        )
