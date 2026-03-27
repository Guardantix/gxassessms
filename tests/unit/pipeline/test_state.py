"""Tests for PipelineEvent, EngagementState, and EngagementLock."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.core.contracts.errors import LockTimeoutError
from gxassessms.pipeline.state import (
    EngagementLock,
    EngagementState,
    PipelineEvent,
)


class TestEngagementState:
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


class TestEngagementLock:
    def test_acquire_and_release(self, tmp_path: Path) -> None:

        eng_dir = tmp_path / "eng-001"
        eng_dir.mkdir()
        lock = EngagementLock(engagements_root=tmp_path)
        lock.acquire("eng-001", timeout=5.0)
        # Lock file should exist
        assert (eng_dir / ".lock").exists()
        lock.release("eng-001")

    def test_context_manager(self, tmp_path: Path) -> None:

        eng_dir = tmp_path / "eng-002"
        eng_dir.mkdir()
        lock = EngagementLock(engagements_root=tmp_path)
        with lock.hold("eng-002", timeout=5.0):
            assert (eng_dir / ".lock").exists()

    def test_lock_timeout_raises(self, tmp_path: Path) -> None:
        from filelock import FileLock

        eng_dir = tmp_path / "eng-003"
        eng_dir.mkdir()
        # Acquire the lock externally to simulate contention
        external_lock = FileLock(str(eng_dir / ".lock"))
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

        eng_dir = tmp_path / "eng-004"
        eng_dir.mkdir()
        lock = EngagementLock(engagements_root=tmp_path)
        lock.acquire("eng-004", timeout=5.0)
        lock.release("eng-004")
        # Second release should not raise
        lock.release("eng-004")

    def test_acquire_creates_engagement_dir_if_missing(self, tmp_path: Path) -> None:

        lock = EngagementLock(engagements_root=tmp_path)
        # eng-005 directory does not exist yet
        lock.acquire("eng-005", timeout=5.0)
        assert (tmp_path / "eng-005" / ".lock").exists()
        lock.release("eng-005")
