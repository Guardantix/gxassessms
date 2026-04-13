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
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.config.datetime_utils import parse_utc, utc_now
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
from gxassessms.pipeline._runner import run_stages
from gxassessms.pipeline.stages import (
    STAGE_STATE_MAP,
    Stage,
    get_stage_entry_state,
)
from gxassessms.pipeline.state import (
    EngagementLock,
    EngagementState,
    EventType,
    PipelineEvent,
    RawOutputIngestedPayload,
    _extract_payload,
)

if TYPE_CHECKING:
    from gxassessms.core.contracts.types import (
        ConsolidationRule,
        NormalizationPolicy,
        QAStrategy,
        ReportRenderer,
        ToolAdapter,
    )

logger = logging.getLogger(__name__)

# Stages whose rerun invalidates a prior QA approval for RENDER gating.
_QA_UPSTREAM_STAGES: frozenset[str] = frozenset(
    {
        Stage.COLLECT.value,
        Stage.PARSE.value,
        Stage.NORMALIZE.value,
        Stage.CONSOLIDATE.value,
    }
)

# Maps completed/created states to the next stage to run.
_COMPLETED_TO_NEXT: dict[EngagementState, Stage] = {
    EngagementState.CREATED: Stage.COLLECT,
    EngagementState.COLLECTED: Stage.PARSE,
    EngagementState.PARSED: Stage.PARSE,
    EngagementState.NORMALIZED: Stage.CONSOLIDATE,
    EngagementState.CONSOLIDATED: Stage.QA_REVIEW,
    EngagementState.QA_APPROVED: Stage.RENDER,
}


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
    # Event emission
    # ------------------------------------------------------------------

    def _emit_event(
        self,
        engagement_id: str,
        event_type: EventType,
        actor: str,
        payload: dict[str, Any],
    ) -> None:
        """Construct a PipelineEvent and append it to the event journal."""
        self._event_repo.append(
            PipelineEvent(
                event_id=str(uuid.uuid4()),
                engagement_id=engagement_id,
                timestamp=utc_now(),
                event_type=event_type,
                actor=actor,
                payload=payload,
            )
        )

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

        payload: dict[str, Any] = {"from": from_state.value, "to": to_state.value}
        if content_hash is not None:
            payload["content_hash"] = content_hash
        self._emit_event(engagement_id, "state_transition", "system", payload)

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
            self._emit_event(
                engagement_id,
                "override",
                actor,
                {
                    "finding_id": finding_id,
                    "field": "severity",
                    "new_severity": new_severity.value,
                    "reason": reason,
                },
            )

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
            self._emit_event(
                engagement_id,
                "manual_finding_added",
                actor,
                {
                    "finding_key": finding.finding_key,
                    "severity": finding.severity.value,
                },
            )

    def record_raw_output_ingested(
        self,
        *,
        engagement_id: str,
        actor: str,
        tool_slug: str,
        source_path: str,
        file_count: int,
        replaced: bool,
        ingested_at: datetime,
    ) -> None:
        """Record a raw_output_ingested event in the engagement journal."""
        payload: RawOutputIngestedPayload = {
            "tool_slug": tool_slug,
            "source_path": source_path,
            "file_count": file_count,
            "replaced": replaced,
            "ingested_at": ingested_at.isoformat(),
        }
        self._emit_event(
            engagement_id,
            "raw_output_ingested",
            actor,
            dict(payload),
        )

    def has_raw_output_ingested_event(
        self,
        engagement_id: str,
        tool_slug: str,
        *,
        source_path: str | None = None,
        replaced: bool | None = None,
        ingested_at: str | None = None,
    ) -> bool:
        """Return True if a matching raw_output_ingested event exists.

        If source_path is provided, both tool_slug and source_path must match.
        If replaced is provided, the event's replaced flag must also match.
        If ingested_at is provided (ISO string from datetime.isoformat()), the event's
        ingested_at must also match -- use when multiple ingests share
        (tool_slug, source_path, replaced) to discriminate the latest from prior ones.
        If source_path is None, only tool_slug is checked (backward-compatible).

        Backward-compat: events recorded before this fix lack ingested_at in their
        payload. payload.get("ingested_at") returns None for those events, so they
        will NOT satisfy the filter when ingested_at is given. This is intentional:
        a legacy event from a prior replace should not mask a missing newer event.
        """
        events = self._event_repo.get_events_by_type(engagement_id, "raw_output_ingested")
        for event in events:
            try:
                payload = _extract_payload(event)
            except PersistenceError:
                logger.warning(
                    "Skipping event with corrupt payload for engagement %s",
                    engagement_id,
                    exc_info=True,
                )
                continue
            if (
                payload.get("tool_slug") == tool_slug
                and (source_path is None or payload.get("source_path") == source_path)
                and (replaced is None or payload.get("replaced") == replaced)
                and (ingested_at is None or payload.get("ingested_at") == ingested_at)
            ):
                return True
        return False

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
        """Return the content_hash from the most recent completed transition for stage."""
        _, completed_state = STAGE_STATE_MAP[stage]
        events = self._event_repo.get_events_by_type(engagement_id, "state_transition")
        for event in reversed(events):
            payload = _extract_payload(event)
            if payload.get("to") == completed_state.value:
                return payload.get("content_hash")
        return None

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
        running_states = {running for running, _ in STAGE_STATE_MAP.values()}
        running_states.discard(EngagementState.QA_REVIEW)
        return current_state in running_states

    # ------------------------------------------------------------------
    # QA approval verification
    # ------------------------------------------------------------------

    def _verify_qa_for_render(self, engagement_id: str) -> None:
        """Verify QA approval exists and is fresh for RENDER stage.

        Raises PipelineError if QA was never approved, or if an upstream
        stage (COLLECT/PARSE/NORMALIZE/CONSOLIDATE) was re-run after the
        most recent QA_APPROVED transition.
        """
        state_events = self._event_repo.get_events_by_type(engagement_id, "state_transition")

        # Find the most recent QA_APPROVED timestamp.
        # Events are ORDER BY timestamp, rowid -- iterate forward, keep last.
        qa_approved_ts: datetime | None = None
        for event in state_events:
            payload = _extract_payload(event)
            if payload.get("to") == "QA_APPROVED":
                qa_approved_ts = parse_utc(event["timestamp"])

        if qa_approved_ts is None:
            raise PipelineError(
                message=(
                    "Cannot proceed to RENDER: QA has not been approved. "
                    "Complete QA review before rendering."
                ),
                engagement_id=engagement_id,
                stage=Stage.RENDER.value,
            )

        # Check for upstream reruns after QA approval.
        rerun_events = self._event_repo.get_events_by_type(engagement_id, "rerun")
        for event in rerun_events:
            payload = _extract_payload(event)
            target_stage = payload.get("target_stage", "")
            if target_stage in _QA_UPSTREAM_STAGES:
                rerun_ts = parse_utc(event["timestamp"])
                if rerun_ts > qa_approved_ts:
                    raise PipelineError(
                        message=(
                            f"Cannot proceed to RENDER: QA approval is stale. "
                            f"Stage {target_stage} was re-run after the last "
                            f"QA approval. Complete QA review before rendering."
                        ),
                        engagement_id=engagement_id,
                        stage=Stage.RENDER.value,
                    )

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
        current_state = self._get_current_state(engagement_id)
        entry_state = get_stage_entry_state(target_stage)

        if current_state == entry_state:
            return  # Already at the right state

        # Guard: RENDER requires fresh QA approval in the event journal.
        if target_stage == Stage.RENDER:
            self._verify_qa_for_render(engagement_id)

        self._engagement_repo.force_update_state(engagement_id, entry_state)
        self._emit_event(
            engagement_id,
            "rerun",
            "system",
            {
                "from_state": current_state.value,
                "to_state": entry_state.value,
                "target_stage": target_stage.value,
                "reason": "operator_rerun",
            },
        )
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
        adapters: list[ToolAdapter],
        normalization_policy: NormalizationPolicy,
        consolidation_rule: ConsolidationRule,
        qa_strategy: QAStrategy,
        renderers: list[ReportRenderer],
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
        adapters: list[ToolAdapter],
        normalization_policy: NormalizationPolicy,
        consolidation_rule: ConsolidationRule,
        qa_strategy: QAStrategy,
        renderers: list[ReportRenderer],
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
