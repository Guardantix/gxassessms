"""Tests for persistence repositories."""

import json
import uuid
from pathlib import Path

import pytest

from gxassessms.core.config.datetime_utils import utc_now
from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.persistence.database import DatabaseManager
from gxassessms.persistence.repositories import (
    CoverageRepo,
    EngagementRepo,
    EventRepo,
    FindingRepo,
)
from gxassessms.pipeline.state import EngagementState, PipelineEvent


@pytest.fixture
def db_manager(tmp_path: Path) -> DatabaseManager:
    """Create a test DatabaseManager with real migrations."""
    db_path = tmp_path / "test.db"
    migrations_dir = (
        Path(__file__).parent.parent.parent.parent / "src/gxassessms/persistence/migrations"
    )
    mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
    mgr.initialize()
    return mgr


@pytest.fixture
def engagement_repo(db_manager: DatabaseManager) -> EngagementRepo:
    return EngagementRepo(db_manager)


@pytest.fixture
def event_repo(db_manager: DatabaseManager) -> EventRepo:
    return EventRepo(db_manager)


@pytest.fixture
def finding_repo(db_manager: DatabaseManager) -> FindingRepo:
    return FindingRepo(db_manager)


@pytest.fixture
def coverage_repo(db_manager: DatabaseManager) -> CoverageRepo:
    return CoverageRepo(db_manager)


# ── EngagementRepo ─────────────────────────────────────────────────────


class TestEngagementRepoCreate:
    def test_create_returns_engagement_id(self, engagement_repo: EngagementRepo) -> None:
        eng_id = engagement_repo.create(
            client_name="Acme Healthcare",
            tenant_id="tenant-001",
            config_snapshot={"tools": {"scubagear": {"enabled": True}}},
        )
        assert isinstance(eng_id, str)
        assert len(eng_id) > 0

    def test_create_sets_state_to_created(self, engagement_repo: EngagementRepo) -> None:
        eng_id = engagement_repo.create(
            client_name="Acme Healthcare",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        eng = engagement_repo.get(eng_id)
        assert eng["state"] == "CREATED"

    def test_create_stores_config_snapshot_as_json(self, engagement_repo: EngagementRepo) -> None:
        config = {"tools": {"scubagear": {"enabled": True}}}
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="tenant-001",
            config_snapshot=config,
        )
        eng = engagement_repo.get(eng_id)
        parsed = json.loads(eng["config_snapshot"])
        assert parsed == config


class TestEngagementRepoGet:
    def test_get_returns_engagement(self, engagement_repo: EngagementRepo) -> None:
        eng_id = engagement_repo.create(
            client_name="Acme",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        eng = engagement_repo.get(eng_id)
        assert eng["engagement_id"] == eng_id
        assert eng["client_name"] == "Acme"

    def test_get_nonexistent_raises(self, engagement_repo: EngagementRepo) -> None:
        with pytest.raises(PersistenceError):
            engagement_repo.get("nonexistent-id")


class TestEngagementRepoUpdateState:
    def test_update_state(self, engagement_repo: EngagementRepo) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        engagement_repo.update_state(eng_id, EngagementState.COLLECTING)
        eng = engagement_repo.get(eng_id)
        assert eng["state"] == "COLLECTING"

    def test_update_state_sets_updated_at(self, engagement_repo: EngagementRepo) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        engagement_repo.update_state(eng_id, EngagementState.COLLECTING)
        eng = engagement_repo.get(eng_id)
        assert eng["updated_at"] is not None


class TestEngagementRepoListByClient:
    def test_list_by_client(self, engagement_repo: EngagementRepo) -> None:
        engagement_repo.create(
            client_name="Acme",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        engagement_repo.create(
            client_name="Acme",
            tenant_id="tenant-002",
            config_snapshot={},
        )
        engagement_repo.create(
            client_name="Other",
            tenant_id="tenant-003",
            config_snapshot={},
        )
        results = engagement_repo.list_by_client("Acme")
        assert len(results) == 2

    def test_list_by_client_no_results(self, engagement_repo: EngagementRepo) -> None:
        results = engagement_repo.list_by_client("Nonexistent")
        assert results == []


# ── EventRepo ──────────────────────────────────────────────────────────


class TestEventRepoAppend:
    def test_append_event(self, engagement_repo: EngagementRepo, event_repo: EventRepo) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        event = PipelineEvent(
            event_id=str(uuid.uuid4()),
            engagement_id=eng_id,
            timestamp=utc_now(),
            event_type="state_transition",
            actor="system",
            payload={"from": "CREATED", "to": "COLLECTING"},
        )
        event_repo.append(event)
        events = event_repo.get_events(eng_id)
        assert len(events) == 1
        assert events[0]["event_type"] == "state_transition"

    def test_append_multiple_events_preserves_order(
        self, engagement_repo: EngagementRepo, event_repo: EventRepo
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        now = utc_now()
        for i in range(5):
            event = PipelineEvent(
                event_id=f"evt-{i:03d}",
                engagement_id=eng_id,
                timestamp=now,
                event_type=f"event_{i}",
                actor="system",
                payload={"index": i},
            )
            event_repo.append(event)
        events = event_repo.get_events(eng_id)
        assert len(events) == 5


class TestEventRepoGetByType:
    def test_get_events_by_type(
        self, engagement_repo: EngagementRepo, event_repo: EventRepo
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        now = utc_now()
        event_repo.append(
            PipelineEvent(
                event_id="evt-001",
                engagement_id=eng_id,
                timestamp=now,
                event_type="state_transition",
                actor="system",
                payload={"from": "CREATED", "to": "COLLECTING"},
            )
        )
        event_repo.append(
            PipelineEvent(
                event_id="evt-002",
                engagement_id=eng_id,
                timestamp=now,
                event_type="override",
                actor="human:rick",
                payload={"finding_id": "f-001"},
            )
        )
        event_repo.append(
            PipelineEvent(
                event_id="evt-003",
                engagement_id=eng_id,
                timestamp=now,
                event_type="state_transition",
                actor="system",
                payload={"from": "COLLECTING", "to": "COLLECTED"},
            )
        )
        transitions = event_repo.get_events_by_type(eng_id, "state_transition")
        assert len(transitions) == 2
        overrides = event_repo.get_events_by_type(eng_id, "override")
        assert len(overrides) == 1
