"""Tests for PipelineEvent, EngagementState, and EngagementLock."""

from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

import pytest

from gxassessms.core.contracts.errors import LockTimeoutError
from gxassessms.pipeline.state import (
    EngagementLock,
    EngagementState,
    PipelineEvent,
)


class TestEngagementState:
    def test_is_terminal_for_terminal_states(self) -> None:
        assert EngagementState.COMPLETE.is_terminal
        assert EngagementState.FAILED.is_terminal

    def test_is_terminal_for_non_terminal_state(self) -> None:
        assert not EngagementState.CREATED.is_terminal
        assert not EngagementState.RENDERING.is_terminal

    def test_all_states_exist(self) -> None:
        expected = {
            "CREATED",
            "COLLECTING",
            "COLLECTED",
            "PARSING",
            "PARSED",
            "NORMALIZING",
            "NORMALIZED",
            "CONSOLIDATING",
            "CONSOLIDATED",
            "QA_REVIEW",
            "QA_APPROVED",
            "RENDERING",
            "COMPLETE",
            "FAILED",
        }
        assert {s.value for s in EngagementState} == expected

    def test_is_str_enum(self) -> None:
        assert isinstance(EngagementState.CREATED, str)
        assert EngagementState.CREATED == "CREATED"

    def test_failed_is_terminal(self) -> None:
        assert EngagementState.FAILED.value == "FAILED"


class TestPipelineEvent:
    def test_create_state_transition_event(self) -> None:
        event = PipelineEvent(
            event_id="evt-001",
            engagement_id="eng-001",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            event_type="state_transition",
            actor="system",
            payload={"from": "CREATED", "to": "COLLECTING"},
        )
        assert event.event_id == "evt-001"
        assert event.engagement_id == "eng-001"
        assert event.event_type == "state_transition"
        assert event.actor == "system"
        assert event.payload["from"] == "CREATED"

    def test_create_override_event(self) -> None:
        event = PipelineEvent(
            event_id="evt-002",
            engagement_id="eng-001",
            timestamp=datetime(2026, 3, 25, 11, 0, 0, tzinfo=UTC),
            event_type="override",
            actor="human:rick",
            payload={
                "finding_id": "uuid-001",
                "old_severity": "MEDIUM",
                "new_severity": "HIGH",
                "reason": "Client-specific risk factor",
            },
        )
        assert event.actor == "human:rick"
        assert event.payload["finding_id"] == "uuid-001"

    def test_create_ai_modification_event(self) -> None:
        event = PipelineEvent(
            event_id="evt-003",
            engagement_id="eng-001",
            timestamp=datetime(2026, 3, 25, 12, 0, 0, tzinfo=UTC),
            event_type="ai_modification",
            actor="ai:severity_review",
            payload={"finding_id": "uuid-002", "adjustment": "severity_downgrade"},
        )
        assert event.event_type == "ai_modification"

    def test_timestamp_must_be_datetime(self) -> None:
        event = PipelineEvent(
            event_id="evt-004",
            engagement_id="eng-001",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            event_type="rerun",
            actor="system",
            payload={},
        )
        assert isinstance(event.timestamp, datetime)

    def test_frozen_immutability(self) -> None:
        event = PipelineEvent(
            event_id="evt-frozen",
            engagement_id="eng-001",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            event_type="state_transition",
            actor="system",
            payload={"test": True},
        )
        with pytest.raises(AttributeError):
            event.event_id = "changed"  # type: ignore[misc]

    def test_payload_is_immutable(self) -> None:
        event = PipelineEvent(
            event_id="evt-imm",
            engagement_id="eng-001",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            event_type="state_transition",
            actor="system",
            payload={"key": "value"},
        )
        with pytest.raises(TypeError):
            event.payload["key"] = "mutated"  # type: ignore[index]


class TestEngagementLock:
    def test_acquire_and_release(self, tmp_path: Path) -> None:
        lock = EngagementLock(engagements_root=tmp_path)
        lock.acquire("eng-001", timeout=5.0)
        assert (tmp_path / ".locks" / "eng-001.lock").exists()
        lock.release("eng-001")

    def test_context_manager(self, tmp_path: Path) -> None:
        lock = EngagementLock(engagements_root=tmp_path)
        with lock.hold("eng-002", timeout=5.0):
            assert (tmp_path / ".locks" / "eng-002.lock").exists()

    def test_lock_timeout_raises(self, tmp_path: Path) -> None:
        from filelock import FileLock

        locks_dir = tmp_path / ".locks"
        locks_dir.mkdir()
        # Acquire the lock externally to simulate contention
        external_lock = FileLock(str(locks_dir / "eng-003.lock"))
        external_lock.acquire()
        try:
            lock = EngagementLock(engagements_root=tmp_path)
            with pytest.raises(LockTimeoutError) as exc_info:
                lock.acquire("eng-003", timeout=0.1)
            assert exc_info.value.engagement_id == "eng-003"
            assert exc_info.value.timeout_seconds == 0.1
        finally:
            external_lock.release()

    def test_double_release_is_safe(self, tmp_path: Path) -> None:
        lock = EngagementLock(engagements_root=tmp_path)
        lock.acquire("eng-004", timeout=5.0)
        lock.release("eng-004")
        # Second release should not raise
        lock.release("eng-004")

    def test_acquire_creates_locks_dir_if_missing(self, tmp_path: Path) -> None:
        lock = EngagementLock(engagements_root=tmp_path)
        # .locks/ directory does not exist yet
        lock.acquire("eng-005", timeout=5.0)
        assert (tmp_path / ".locks" / "eng-005.lock").exists()
        lock.release("eng-005")

    def test_hold_releases_lock_on_exception(self, tmp_path: Path) -> None:
        lock = EngagementLock(engagements_root=tmp_path)
        with pytest.raises(RuntimeError), lock.hold("eng-exc", timeout=5.0):
            raise RuntimeError("simulated failure")
        # Lock should have been released -- re-acquire should work
        lock.acquire("eng-exc", timeout=5.0)
        lock.release("eng-exc")

    def test_double_acquire_raises(self, tmp_path: Path) -> None:
        from gxassessms.core.contracts.errors import PersistenceError

        lock = EngagementLock(engagements_root=tmp_path)
        lock.acquire("eng-double", timeout=5.0)
        try:
            with pytest.raises(PersistenceError, match="already held"):
                lock.acquire("eng-double", timeout=5.0)
        finally:
            lock.release("eng-double")

    def test_invalid_engagement_id_raises(self, tmp_path: Path) -> None:
        from gxassessms.core.contracts.errors import PersistenceError

        lock = EngagementLock(engagements_root=tmp_path)
        with pytest.raises(PersistenceError, match="Invalid engagement ID"):
            lock.acquire("../../../etc/passwd", timeout=5.0)


class TestEngagementStateTransitions:
    def test_valid_transitions_happy_path(self) -> None:
        """Walk the happy path: CREATED -> COLLECTING -> ... -> COMPLETE."""
        happy_path = [
            EngagementState.CREATED,
            EngagementState.COLLECTING,
            EngagementState.COLLECTED,
            EngagementState.PARSING,
            EngagementState.PARSED,
            EngagementState.NORMALIZING,
            EngagementState.NORMALIZED,
            EngagementState.CONSOLIDATING,
            EngagementState.CONSOLIDATED,
            EngagementState.QA_REVIEW,
            EngagementState.QA_APPROVED,
            EngagementState.RENDERING,
            EngagementState.COMPLETE,
        ]
        for from_state, to_state in pairwise(happy_path):
            assert EngagementState.can_transition_to(from_state, to_state), (
                f"{from_state} -> {to_state} should be valid"
            )

    def test_failed_reachable_from_non_terminal(self) -> None:
        """Every non-terminal state can transition to FAILED."""
        for state in EngagementState:
            if state in (EngagementState.COMPLETE, EngagementState.FAILED):
                continue
            assert EngagementState.can_transition_to(state, EngagementState.FAILED), (
                f"{state} -> FAILED should be valid"
            )

    def test_terminal_states_have_no_outgoing_transitions(self) -> None:
        """COMPLETE and FAILED are terminal -- no valid outgoing transitions."""
        for terminal in (EngagementState.COMPLETE, EngagementState.FAILED):
            for target in EngagementState:
                assert not EngagementState.can_transition_to(terminal, target), (
                    f"{terminal} -> {target} should be invalid"
                )

    def test_invalid_transition_rejected(self) -> None:
        """Skipping states should be rejected."""
        assert not EngagementState.can_transition_to(
            EngagementState.CREATED, EngagementState.PARSED
        )

    def test_assert_can_transition_to_valid_does_not_raise(self) -> None:
        # Should not raise for valid transition
        EngagementState.assert_can_transition_to(
            EngagementState.CREATED, EngagementState.COLLECTING
        )

    def test_assert_can_transition_to_invalid_raises_with_context(self) -> None:
        from gxassessms.core.contracts.errors import InvalidTransitionError

        with pytest.raises(InvalidTransitionError) as exc_info:
            EngagementState.assert_can_transition_to(
                EngagementState.CREATED, EngagementState.PARSED
            )
        assert exc_info.value.from_state == "CREATED"
        assert exc_info.value.to_state == "PARSED"
