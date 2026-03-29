"""Tests for pipeline state machine transition logic.

Verifies that the state machine correctly maps stages to state pairs,
validates transitions, and rejects invalid transitions.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from gxassessms.core.contracts.errors import InvalidTransitionError
from gxassessms.pipeline.stages import (
    STAGE_STATE_MAP,
    Stage,
    get_stage_entry_state,
    get_stages_from,
)
from gxassessms.pipeline.state import EngagementState, PipelineEvent


class TestStageStateMap:
    """STAGE_STATE_MAP maps each Stage to (running_state, completed_state)."""

    def test_all_stages_mapped(self) -> None:
        for stage in Stage:
            assert stage in STAGE_STATE_MAP, f"Stage {stage} not in STAGE_STATE_MAP"

    def test_collect_maps_to_collecting_collected(self) -> None:
        running, completed = STAGE_STATE_MAP[Stage.COLLECT]
        assert running == EngagementState.COLLECTING
        assert completed == EngagementState.COLLECTED

    def test_parse_maps_to_parsing_parsed(self) -> None:
        running, completed = STAGE_STATE_MAP[Stage.PARSE]
        assert running == EngagementState.PARSING
        assert completed == EngagementState.PARSED

    def test_normalize_maps_to_normalizing_normalized(self) -> None:
        running, completed = STAGE_STATE_MAP[Stage.NORMALIZE]
        assert running == EngagementState.NORMALIZING
        assert completed == EngagementState.NORMALIZED

    def test_consolidate_maps_to_consolidating_consolidated(self) -> None:
        running, completed = STAGE_STATE_MAP[Stage.CONSOLIDATE]
        assert running == EngagementState.CONSOLIDATING
        assert completed == EngagementState.CONSOLIDATED

    def test_qa_review_maps_correctly(self) -> None:
        running, completed = STAGE_STATE_MAP[Stage.QA_REVIEW]
        assert running == EngagementState.QA_REVIEW
        assert completed == EngagementState.QA_APPROVED

    def test_render_maps_to_rendering_complete(self) -> None:
        running, completed = STAGE_STATE_MAP[Stage.RENDER]
        assert running == EngagementState.RENDERING
        assert completed == EngagementState.COMPLETE


class TestStageStateMapConsistency:
    """Verify STAGE_STATE_MAP transitions are valid per the enum-level state machine (RN-3)."""

    def test_all_running_states_reachable(self) -> None:
        """Each stage's running state must be reachable from its entry state."""
        for stage in Stage:
            entry = get_stage_entry_state(stage)
            running, _completed = STAGE_STATE_MAP[stage]
            assert EngagementState.can_transition_to(entry, running), (
                f"Entry state {entry} cannot transition to running state {running} for {stage}"
            )

    def test_all_completed_states_reachable(self) -> None:
        """Each stage's completed state must be reachable from its running state."""
        for stage in Stage:
            running, completed = STAGE_STATE_MAP[stage]
            assert EngagementState.can_transition_to(running, completed), (
                f"Running state {running} cannot transition to "
                f"completed state {completed} for {stage}"
            )


class TestValidTransitionsViaEnum:
    """Test state transitions using the existing EngagementState methods (RN-3)."""

    def test_valid_transition_succeeds(self) -> None:
        assert EngagementState.can_transition_to(
            EngagementState.CREATED, EngagementState.COLLECTING
        )

    def test_invalid_transition_raises(self) -> None:
        with pytest.raises(InvalidTransitionError) as exc_info:
            EngagementState.assert_can_transition_to(
                EngagementState.CREATED, EngagementState.PARSED
            )
        assert exc_info.value.from_state == "CREATED"
        assert exc_info.value.to_state == "PARSED"

    def test_transition_from_failed_raises(self) -> None:
        with pytest.raises(InvalidTransitionError):
            EngagementState.assert_can_transition_to(
                EngagementState.FAILED, EngagementState.COLLECTING
            )

    def test_failed_is_terminal(self) -> None:
        assert EngagementState.FAILED.is_terminal

    def test_complete_is_terminal(self) -> None:
        assert EngagementState.COMPLETE.is_terminal

    def test_any_non_terminal_state_can_fail(self) -> None:
        non_terminal = [s for s in EngagementState if not s.is_terminal]
        for state in non_terminal:
            assert EngagementState.can_transition_to(state, EngagementState.FAILED), (
                f"{state} should be able to transition to FAILED"
            )


class TestGetStageEntryState:
    """get_stage_entry_state returns the state an engagement must be in
    before a given stage can start."""

    def test_collect_requires_created(self) -> None:
        assert get_stage_entry_state(Stage.COLLECT) == EngagementState.CREATED

    def test_parse_requires_collected(self) -> None:
        assert get_stage_entry_state(Stage.PARSE) == EngagementState.COLLECTED

    def test_normalize_requires_parsed(self) -> None:
        assert get_stage_entry_state(Stage.NORMALIZE) == EngagementState.PARSED

    def test_consolidate_requires_normalized(self) -> None:
        assert get_stage_entry_state(Stage.CONSOLIDATE) == EngagementState.NORMALIZED

    def test_qa_review_requires_consolidated(self) -> None:
        assert get_stage_entry_state(Stage.QA_REVIEW) == EngagementState.CONSOLIDATED

    def test_render_requires_qa_approved(self) -> None:
        assert get_stage_entry_state(Stage.RENDER) == EngagementState.QA_APPROVED


class TestGetStagesFrom:
    def test_from_collect_returns_all(self) -> None:
        stages = get_stages_from(Stage.COLLECT)
        assert stages == list(Stage)

    def test_from_parse_skips_collect(self) -> None:
        stages = get_stages_from(Stage.PARSE)
        assert Stage.COLLECT not in stages
        assert stages[0] == Stage.PARSE

    def test_from_render_returns_only_render(self) -> None:
        stages = get_stages_from(Stage.RENDER)
        assert stages == [Stage.RENDER]

    def test_from_qa_review(self) -> None:
        stages = get_stages_from(Stage.QA_REVIEW)
        assert stages == [Stage.QA_REVIEW, Stage.RENDER]


class TestPipelineEventValidation:
    def test_invalid_event_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid event_type"):
            PipelineEvent(
                event_id="1",
                engagement_id="eng-001",
                timestamp=datetime(2026, 3, 25, tzinfo=UTC),
                event_type="bogus",  # type: ignore[arg-type]
                actor="system",
                payload={},
            )

    def test_valid_event_types_accepted(self) -> None:
        for etype in ("state_transition", "override", "stale_recovery"):
            PipelineEvent(
                event_id="1",
                engagement_id="eng-001",
                timestamp=datetime(2026, 3, 25, tzinfo=UTC),
                event_type=etype,  # type: ignore[arg-type]
                actor="system",
                payload={},
            )
