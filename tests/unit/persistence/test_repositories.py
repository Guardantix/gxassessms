"""Tests for persistence repositories."""

import json
import uuid
from pathlib import Path

import pytest

from gxassessms.core.config.datetime_utils import utc_now
from gxassessms.core.contracts.errors import InvalidTransitionError, PersistenceError
from gxassessms.core.domain.enums import Severity
from gxassessms.persistence.coverage_repo import CoverageRepo
from gxassessms.persistence.database import DatabaseManager
from gxassessms.persistence.engagement_repo import EngagementRepo
from gxassessms.persistence.event_repo import EventRepo
from gxassessms.persistence.finding_repo import FindingRepo
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

    def test_update_state_nonexistent_raises(self, engagement_repo: EngagementRepo) -> None:
        with pytest.raises(PersistenceError):
            engagement_repo.update_state("nonexistent-id", EngagementState.COLLECTING)

    def test_update_state_invalid_transition_raises(self, engagement_repo: EngagementRepo) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="tenant-001",
            config_snapshot={},
        )
        # CREATED -> PARSED is not a valid transition (must go through COLLECTING first)
        with pytest.raises(InvalidTransitionError) as exc_info:
            engagement_repo.update_state(eng_id, EngagementState.PARSED)
        assert exc_info.value.from_state == "CREATED"
        assert exc_info.value.to_state == "PARSED"


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


class TestEngagementRepoListAll:
    def test_list_all_returns_all_engagements(self, engagement_repo: EngagementRepo) -> None:
        engagement_repo.create(client_name="A", tenant_id="t-1", config_snapshot={})
        engagement_repo.create(client_name="B", tenant_id="t-2", config_snapshot={})
        engagement_repo.create(client_name="C", tenant_id="t-3", config_snapshot={})
        results = engagement_repo.list_all()
        assert len(results) == 3

    def test_list_all_empty(self, engagement_repo: EngagementRepo) -> None:
        results = engagement_repo.list_all()
        assert results == []


class TestEngagementRepoDelete:
    def test_delete_nonexistent_engagement_raises(self, engagement_repo: EngagementRepo) -> None:
        with pytest.raises(PersistenceError, match="not found"):
            engagement_repo.delete("nonexistent-id")

    def test_delete_removes_engagement_and_related_records(
        self,
        engagement_repo: EngagementRepo,
        event_repo: EventRepo,
        finding_repo: FindingRepo,
        coverage_repo: CoverageRepo,
        db_manager: DatabaseManager,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="DeleteTest",
            tenant_id="t-del",
            config_snapshot={},
        )
        # Add related records
        event_repo.append(
            PipelineEvent(
                event_id="evt-del-001",
                engagement_id=eng_id,
                timestamp=utc_now(),
                event_type="state_transition",
                actor="system",
                payload={"from": "CREATED", "to": "COLLECTING"},
            )
        )
        finding_repo.save_parsed(
            eng_id,
            [
                {
                    "finding_id": "f-del-001",
                    "observation_id": "obs-001",
                    "finding_key": "key-001",
                    "tool_source": "ScubaGear",
                    "title": "Test",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "category": "Identity & Access",
                    "description": "Test",
                    "dedup_keys": ["key-001"],
                },
            ],
        )
        coverage_repo.save(
            eng_id,
            [{"control_id": "c-1", "tool_source": "ScubaGear", "status": "assessed"}],
        )

        # Delete
        engagement_repo.delete(eng_id)

        # Verify all gone
        with pytest.raises(PersistenceError):
            engagement_repo.get(eng_id)
        assert event_repo.get_events(eng_id) == []
        assert finding_repo.get_parsed(eng_id) == []
        assert coverage_repo.get_for_engagement(eng_id) == []


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
                event_type="state_transition",
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


# ── FindingRepo ────────────────────────────────────────────────────────


class TestFindingRepoSaveParsed:
    def test_save_and_retrieve_parsed_findings(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        findings = [
            {
                "finding_id": "f-001",
                "observation_id": "scubagear:MS.AAD.3.1v1",
                "finding_key": "cis:m365:1.1.1",
                "tool_source": "ScubaGear",
                "title": "MFA for privileged roles",
                "severity": "CRITICAL",
                "status": "FAIL",
                "category": "Identity & Access",
                "description": "MFA not enabled.",
                "dedup_keys": ["cis:m365:1.1.1"],
                "benchmark_refs": ["CIS M365 1.1.1"],
            },
            {
                "finding_id": "f-002",
                "observation_id": "maester:MT.1001",
                "finding_key": "cis:m365:2.1.1",
                "tool_source": "Maester",
                "title": "Conditional access baseline",
                "severity": "HIGH",
                "status": "FAIL",
                "category": "Identity & Access",
                "description": "No baseline policy.",
                "dedup_keys": ["cis:m365:2.1.1"],
            },
        ]
        finding_repo.save_parsed(eng_id, findings)
        result = finding_repo.get_parsed(eng_id)
        assert len(result) == 2

    def test_save_parsed_stores_json_fields(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        findings = [
            {
                "finding_id": "f-001",
                "observation_id": "scubagear:MS.AAD.3.1v1",
                "finding_key": "cis:m365:1.1.1",
                "tool_source": "ScubaGear",
                "title": "Test",
                "severity": "CRITICAL",
                "status": "FAIL",
                "category": "Identity & Access",
                "description": "Test",
                "dedup_keys": ["key1", "key2"],
                "benchmark_refs": ["CIS 1.1"],
                "raw_data": {"extra": "data"},
            },
        ]
        finding_repo.save_parsed(eng_id, findings)
        result = finding_repo.get_parsed(eng_id)
        assert json.loads(result[0]["dedup_keys"]) == ["key1", "key2"]
        assert json.loads(result[0]["benchmark_refs"]) == ["CIS 1.1"]
        assert json.loads(result[0]["raw_data"]) == {"extra": "data"}


class TestFindingRepoSaveConsolidated:
    def test_save_and_retrieve_consolidated(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        consolidated = [
            {
                "finding_instance_id": "cf-001",
                "finding_key": "cis:m365:1.1.1",
                "title": "MFA for privileged roles",
                "severity": "CRITICAL",
                "status": "FAIL",
                "category": "Identity & Access",
                "description": "MFA not enabled.",
                "sources": [
                    {"tool": "ScubaGear", "check_id": "MS.AAD.3.1v1", "raw_data": {}},
                ],
                "confidence": {
                    "evidence_strength": 0.9,
                    "corroborating_tools": 2,
                    "data_freshness": 0.95,
                    "provenance": "system-generated",
                    "overall": 0.88,
                },
                "benchmark_refs": ["CIS M365 1.1.1"],
                "root_cause": "No MFA policy configured",
                "remediation": "Enable MFA for all privileged roles",
            },
        ]
        finding_repo.save_consolidated(eng_id, consolidated)
        result = finding_repo.get_consolidated(eng_id)
        assert len(result) == 1
        assert result[0]["finding_instance_id"] == "cf-001"
        sources = json.loads(result[0]["sources"])
        assert len(sources) == 1
        assert sources[0]["tool"] == "ScubaGear"


class TestFindingRepoOverrideSeverity:
    def test_override_severity_updates_finding(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        finding_repo.save_consolidated(
            eng_id,
            [
                {
                    "finding_instance_id": "cf-001",
                    "finding_key": "cis:m365:1.1.1",
                    "title": "Test",
                    "severity": "MEDIUM",
                    "status": "FAIL",
                    "category": "Identity & Access",
                    "description": "Test",
                    "sources": [],
                    "confidence": {
                        "evidence_strength": 0.5,
                        "corroborating_tools": 1,
                        "data_freshness": 0.9,
                        "provenance": "system-generated",
                        "overall": 0.7,
                    },
                },
            ],
        )
        finding_repo.override_severity(
            finding_id="cf-001",
            new_severity=Severity.HIGH,
            reason="Client-specific risk",
            actor="human:rick",
            engagement_id=eng_id,
        )
        result = finding_repo.get_consolidated(eng_id)
        assert result[0]["severity"] == "HIGH"

    def test_override_severity_records_override(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
        db_manager: DatabaseManager,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        finding_repo.save_consolidated(
            eng_id,
            [
                {
                    "finding_instance_id": "cf-001",
                    "finding_key": "cis:m365:1.1.1",
                    "title": "Test",
                    "severity": "LOW",
                    "status": "FAIL",
                    "category": "Identity & Access",
                    "description": "Test",
                    "sources": [],
                    "confidence": {
                        "evidence_strength": 0.5,
                        "corroborating_tools": 1,
                        "data_freshness": 0.9,
                        "provenance": "system-generated",
                        "overall": 0.7,
                    },
                },
            ],
        )
        finding_repo.override_severity(
            finding_id="cf-001",
            new_severity=Severity.CRITICAL,
            reason="Regulatory requirement",
            actor="human:rick",
            engagement_id=eng_id,
        )
        with db_manager.connect() as conn:
            overrides = conn.execute(
                "SELECT * FROM overrides WHERE finding_id = ?", ("cf-001",)
            ).fetchall()
        assert len(overrides) == 1
        ovr = dict(overrides[0])
        assert ovr["old_value"] == "LOW"
        assert ovr["new_value"] == "CRITICAL"
        assert ovr["reason"] == "Regulatory requirement"
        assert ovr["actor"] == "human:rick"

    def test_override_nonexistent_finding_raises(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        with pytest.raises(PersistenceError):
            finding_repo.override_severity(
                finding_id="nonexistent",
                new_severity=Severity.HIGH,
                reason="test",
                actor="system",
                engagement_id=eng_id,
            )

    def test_override_severity_cross_engagement_isolation(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        """Finding from eng_a cannot be mutated via eng_b's engagement_id."""
        eng_a = engagement_repo.create(client_name="EngA", tenant_id="t-a", config_snapshot={})
        eng_b = engagement_repo.create(client_name="EngB", tenant_id="t-b", config_snapshot={})
        finding_repo.save_consolidated(
            eng_a,
            [
                {
                    "finding_instance_id": "cf-cross-001",
                    "finding_key": "test-key",
                    "title": "Test Finding",
                    "severity": "MEDIUM",
                    "status": "FAIL",
                    "category": "Identity",
                    "description": "Test description",
                    "sources": [],
                    "confidence": {},
                }
            ],
        )
        with pytest.raises(PersistenceError):
            finding_repo.override_severity(
                finding_id="cf-cross-001",
                new_severity=Severity.HIGH,
                reason="cross-engagement attack",
                actor="attacker",
                engagement_id=eng_b,  # wrong engagement
            )


class TestFindingRepoManualFinding:
    def test_add_manual_finding(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        finding_id = finding_repo.add_manual_finding(
            eng_id,
            {
                "title": "Custom finding",
                "severity": "HIGH",
                "category": "Identity & Access",
                "description": "Manually identified issue",
            },
        )
        assert isinstance(finding_id, str)
        results = finding_repo.get_parsed(eng_id)
        assert len(results) == 1
        assert results[0]["tool_source"] == "Manual"

    def test_delete_for_engagement(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        finding_repo.save_parsed(
            eng_id,
            [
                {
                    "finding_id": "f-001",
                    "observation_id": "obs-001",
                    "finding_key": "key-001",
                    "tool_source": "ScubaGear",
                    "title": "Test",
                    "severity": "LOW",
                    "status": "PASS",
                    "category": "Identity & Access",
                    "description": "Test",
                    "dedup_keys": ["key-001"],
                },
            ],
        )
        count = finding_repo.delete_for_engagement(eng_id)
        assert count == 1
        assert finding_repo.get_parsed(eng_id) == []


# ── CoverageRepo ──────────────────────────────────────────────────────


class TestCoverageRepoSave:
    def test_save_and_retrieve_coverage(
        self,
        engagement_repo: EngagementRepo,
        coverage_repo: CoverageRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        records = [
            {
                "control_id": "CIS M365 1.1.1",
                "tool_source": "ScubaGear",
                "status": "assessed",
            },
            {
                "control_id": "CIS M365 1.2.1",
                "tool_source": "ScubaGear",
                "status": "not_assessed",
                "reason": "Not applicable to license tier",
            },
        ]
        coverage_repo.save(eng_id, records)
        result = coverage_repo.get_for_engagement(eng_id)
        assert len(result) == 2

    def test_save_empty_list_is_no_op(
        self,
        engagement_repo: EngagementRepo,
        coverage_repo: CoverageRepo,
    ) -> None:
        eng_id = engagement_repo.create(client_name="Test", tenant_id="t-001", config_snapshot={})
        coverage_repo.save(eng_id, [])  # executemany with empty list must not raise
        assert coverage_repo.get_for_engagement(eng_id) == []

    def test_coverage_invalid_status_raises(
        self,
        engagement_repo: EngagementRepo,
        coverage_repo: CoverageRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            coverage_repo.save(
                eng_id,
                [
                    {
                        "control_id": "CIS M365 1.1.1",
                        "tool_source": "ScubaGear",
                        "status": "invalid_status",
                    },
                ],
            )

    def test_delete_for_engagement(
        self,
        engagement_repo: EngagementRepo,
        coverage_repo: CoverageRepo,
    ) -> None:
        eng_id = engagement_repo.create(
            client_name="Test",
            tenant_id="t-001",
            config_snapshot={},
        )
        coverage_repo.save(
            eng_id,
            [
                {"control_id": "c-1", "tool_source": "ScubaGear", "status": "assessed"},
            ],
        )
        count = coverage_repo.delete_for_engagement(eng_id)
        assert count == 1
        assert coverage_repo.get_for_engagement(eng_id) == []
