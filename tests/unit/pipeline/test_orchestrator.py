"""Tests for the pipeline orchestrator.

All external dependencies are mocked. Tests verify orchestrator behavior:
state transitions, event journal entries, error handling, overrides,
stale state detection, and hash invalidation.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from gxassessms.core.config.config import (
    AuthConfig,
    EngagementConfig,
    ToolConfig,
)
from gxassessms.core.contracts.errors import (
    InvalidTransitionError,
    PersistenceError,
)
from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    ConfidenceScore,
    ConsolidatedFinding,
    Finding,
    SourceEvidence,
)
from gxassessms.pipeline.orchestrator import Orchestrator, _extract_payload
from gxassessms.pipeline.stages import Stage
from gxassessms.pipeline.state import EngagementState
from gxassessms.qa.noop import NoOpQAStrategy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_config() -> EngagementConfig:
    return EngagementConfig(
        client_name="Test Client",
        tenant_id="00000000-0000-0000-0000-000000000001",
        auth=AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_SECRET",  # pragma: allowlist secret
        ),
        tools={"scubagear": ToolConfig(enabled=True)},
    )


def _make_finding(
    key: str = "cis:m365:1.1.1",
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    return Finding(
        observation_id=f"scubagear:{uuid.uuid4().hex[:8]}",
        native_check_id="MS.AAD.3.1v1",
        finding_key=key,
        tool=ToolSource.SCUBAGEAR,
        title=f"Finding {key}",
        severity=severity,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description="Test finding",
        dedup_keys=[key],
    )


def _make_consolidated(
    key: str = "cis:m365:1.1.1",
) -> ConsolidatedFinding:
    return ConsolidatedFinding(
        finding_instance_id=str(uuid.uuid4()),
        finding_key=key,
        title=f"Consolidated {key}",
        severity=Severity.CRITICAL,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description="Consolidated finding",
        sources=[
            SourceEvidence(
                tool=ToolSource.SCUBAGEAR,
                check_id="MS.AAD.3.1v1",
                raw_data={"result": "Fail"},
            )
        ],
        confidence=ConfidenceScore(
            evidence_strength=0.9,
            corroborating_tools=1,
            data_freshness=1.0,
            provenance="system-generated",
            overall=0.9,
        ),
    )


@pytest.fixture
def mock_engagement_repo() -> MagicMock:
    repo = MagicMock()
    repo.get.return_value = {
        "engagement_id": "eng-001",
        "client_name": "Test",
        "state": EngagementState.CREATED.value,
        "config_snapshot": "{}",
    }
    return repo


@pytest.fixture
def mock_event_repo() -> MagicMock:
    repo = MagicMock()
    repo.get_events.return_value = []
    repo.get_events_by_type.return_value = []
    return repo


@pytest.fixture
def mock_finding_repo() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mock_coverage_repo() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mock_lock() -> MagicMock:
    lock = MagicMock()
    lock.hold.return_value.__enter__ = MagicMock(return_value=None)
    lock.hold.return_value.__exit__ = MagicMock(return_value=False)
    return lock


@pytest.fixture
def mock_db() -> MagicMock:
    return MagicMock()


@pytest.fixture
def orchestrator(
    mock_engagement_repo: MagicMock,
    mock_event_repo: MagicMock,
    mock_finding_repo: MagicMock,
    mock_coverage_repo: MagicMock,
    mock_lock: MagicMock,
    mock_db: MagicMock,
) -> Orchestrator:
    return Orchestrator(
        engagement_repo=mock_engagement_repo,
        event_repo=mock_event_repo,
        finding_repo=mock_finding_repo,
        coverage_repo=mock_coverage_repo,
        lock=mock_lock,
        db=mock_db,
    )


# ---------------------------------------------------------------------------
# Orchestrator construction tests
# ---------------------------------------------------------------------------


class TestOrchestratorConstruction:
    def test_creates_with_all_dependencies(self, orchestrator: Orchestrator) -> None:
        assert orchestrator is not None

    def test_requires_engagement_repo(self) -> None:
        with pytest.raises(TypeError):
            Orchestrator(
                engagement_repo=None,
                event_repo=MagicMock(),
                finding_repo=MagicMock(),
                coverage_repo=MagicMock(),
                lock=MagicMock(),
                db=MagicMock(),
            )


# ---------------------------------------------------------------------------
# State transition tests
# ---------------------------------------------------------------------------


class TestOrchestratorStateTransitions:
    def test_records_state_transition_event(
        self,
        orchestrator: Orchestrator,
        mock_engagement_repo: MagicMock,
        mock_event_repo: MagicMock,
    ) -> None:
        orchestrator._transition_state(
            "eng-001",
            EngagementState.CREATED,
            EngagementState.COLLECTING,
        )
        mock_engagement_repo.update_state.assert_called_once_with(
            "eng-001", EngagementState.COLLECTING
        )
        mock_event_repo.append.assert_called_once()
        event = mock_event_repo.append.call_args[0][0]
        assert event.event_type == "state_transition"
        assert event.payload["from"] == "CREATED"
        assert event.payload["to"] == "COLLECTING"

    def test_invalid_transition_raises(self, orchestrator: Orchestrator) -> None:
        with pytest.raises(InvalidTransitionError):
            orchestrator._transition_state(
                "eng-001",
                EngagementState.CREATED,
                EngagementState.PARSED,
            )

    def test_transition_to_failed(
        self,
        orchestrator: Orchestrator,
        mock_engagement_repo: MagicMock,
    ) -> None:
        orchestrator._transition_state(
            "eng-001",
            EngagementState.COLLECTING,
            EngagementState.FAILED,
        )
        mock_engagement_repo.update_state.assert_called_once_with("eng-001", EngagementState.FAILED)


# ---------------------------------------------------------------------------
# Override tests
# ---------------------------------------------------------------------------


class TestOrchestratorOverrides:
    def test_override_severity_records_event(
        self,
        orchestrator: Orchestrator,
        mock_event_repo: MagicMock,
        mock_finding_repo: MagicMock,
        mock_lock: MagicMock,
    ) -> None:
        """NOTE (RN-5): FindingRepo.override_severity() has full signature."""
        orchestrator.override_severity(
            engagement_id="eng-001",
            finding_id="f-001",
            new_severity=Severity.HIGH,
            reason="Client risk factor",
            actor="human:rick",
        )
        mock_finding_repo.override_severity.assert_called_once_with(
            finding_id="f-001",
            new_severity=Severity.HIGH,
            reason="Client risk factor",
            actor="human:rick",
            engagement_id="eng-001",
        )
        mock_event_repo.append.assert_called()
        event = mock_event_repo.append.call_args[0][0]
        assert event.event_type == "override"
        assert event.payload["new_severity"] == "HIGH"

    def test_add_manual_finding_records_event(
        self,
        orchestrator: Orchestrator,
        mock_event_repo: MagicMock,
        mock_finding_repo: MagicMock,
        mock_lock: MagicMock,
    ) -> None:
        """NOTE (RN-5): FindingRepo.add_manual_finding() takes dict."""
        finding = _make_finding()
        orchestrator.add_manual_finding(
            engagement_id="eng-001",
            finding=finding,
            actor="human:rick",
        )
        mock_finding_repo.add_manual_finding.assert_called_once()
        mock_event_repo.append.assert_called()
        event = mock_event_repo.append.call_args[0][0]
        assert event.event_type == "manual_finding_added"


# ---------------------------------------------------------------------------
# Stale state detection and recovery tests
# ---------------------------------------------------------------------------


class TestStaleStateDetection:
    def test_detect_stale_running_returns_true_for_running_states(
        self, orchestrator: Orchestrator
    ) -> None:
        assert orchestrator._detect_stale_running("eng-001", EngagementState.COLLECTING) is True
        assert orchestrator._detect_stale_running("eng-001", EngagementState.PARSING) is True
        assert orchestrator._detect_stale_running("eng-001", EngagementState.NORMALIZING) is True

    def test_detect_stale_running_returns_false_for_completed_states(
        self, orchestrator: Orchestrator
    ) -> None:
        assert orchestrator._detect_stale_running("eng-001", EngagementState.CREATED) is False
        assert orchestrator._detect_stale_running("eng-001", EngagementState.COLLECTED) is False
        assert orchestrator._detect_stale_running("eng-001", EngagementState.COMPLETE) is False

    def test_qa_review_is_not_stale(self, orchestrator: Orchestrator) -> None:
        """QA_REVIEW is a legitimate waiting state for human approval, not a crash."""
        assert orchestrator._detect_stale_running("eng-001", EngagementState.QA_REVIEW) is False


class TestStaleStateRecovery:
    def test_recovery_calls_force_update_state(
        self,
        orchestrator: Orchestrator,
        mock_engagement_repo: MagicMock,
        mock_event_repo: MagicMock,
    ) -> None:
        """Recovery must use force_update_state, not update_state, to bypass validation."""
        from gxassessms.pipeline._runner import _recover_stale_state

        _recover_stale_state(orchestrator, "eng-001", EngagementState.COLLECTING)

        mock_engagement_repo.force_update_state.assert_called_once_with(
            "eng-001", EngagementState.CREATED
        )
        # Normal update_state should NOT be called during recovery
        mock_engagement_repo.update_state.assert_not_called()

    def test_recovery_records_stale_recovery_event(
        self,
        orchestrator: Orchestrator,
        mock_engagement_repo: MagicMock,
        mock_event_repo: MagicMock,
    ) -> None:
        from gxassessms.pipeline._runner import _recover_stale_state

        _recover_stale_state(orchestrator, "eng-001", EngagementState.PARSING)

        mock_event_repo.append.assert_called_once()
        event = mock_event_repo.append.call_args[0][0]
        assert event.event_type == "stale_recovery"
        assert event.payload["from"] == "PARSING"
        assert event.payload["to"] == "COLLECTED"


# ---------------------------------------------------------------------------
# NoOp QA auto-advance tests
# ---------------------------------------------------------------------------


class TestNoOpQAAutoAdvance:
    def test_noop_qa_auto_advances(self, orchestrator: Orchestrator) -> None:
        strategy = NoOpQAStrategy()
        assert orchestrator._should_auto_advance_qa(strategy) is True

    def test_real_qa_does_not_auto_advance(self, orchestrator: Orchestrator) -> None:
        strategy = MagicMock()
        strategy.is_noop = False
        assert orchestrator._should_auto_advance_qa(strategy) is False

    def test_missing_is_noop_does_not_auto_advance(self, orchestrator: Orchestrator) -> None:
        strategy = MagicMock(spec=[])
        # No is_noop attribute
        del strategy.is_noop
        assert orchestrator._should_auto_advance_qa(strategy) is False


# ---------------------------------------------------------------------------
# _get_stages_to_run tests
# ---------------------------------------------------------------------------


class TestGetStagesToRun:
    def test_run_from_returns_stages_to_execute(self, orchestrator: Orchestrator) -> None:
        stages = orchestrator._get_stages_to_run(Stage.PARSE)
        assert stages[0] == Stage.PARSE
        assert Stage.COLLECT not in stages

    def test_run_from_collect_includes_all_stages(self, orchestrator: Orchestrator) -> None:
        stages = orchestrator._get_stages_to_run(Stage.COLLECT)
        assert stages == list(Stage)


# ---------------------------------------------------------------------------
# Content hash tests
# ---------------------------------------------------------------------------


class TestContentHashing:
    def test_compute_hash_deterministic(self, orchestrator: Orchestrator) -> None:
        data = [{"key": "value", "num": 42}]
        h1 = orchestrator._compute_content_hash(data)
        h2 = orchestrator._compute_content_hash(data)
        assert h1 == h2
        assert isinstance(h1, str)
        assert len(h1) > 0

    def test_different_data_different_hash(self, orchestrator: Orchestrator) -> None:
        h1 = orchestrator._compute_content_hash([{"a": 1}])
        h2 = orchestrator._compute_content_hash([{"a": 2}])
        assert h1 != h2

    def test_empty_data_has_hash(self, orchestrator: Orchestrator) -> None:
        h = orchestrator._compute_content_hash([])
        assert isinstance(h, str)
        assert len(h) > 0


# ---------------------------------------------------------------------------
# Hash invalidation detection tests
# ---------------------------------------------------------------------------


class TestHashInvalidation:
    def test_no_prior_hash_returns_invalidated(
        self, orchestrator: Orchestrator, mock_event_repo: MagicMock
    ) -> None:
        mock_event_repo.get_events_by_type.return_value = []
        assert orchestrator._is_stage_invalidated("eng-001", Stage.PARSE, "abc123") is True

    def test_same_hash_not_invalidated(
        self, orchestrator: Orchestrator, mock_event_repo: MagicMock
    ) -> None:
        event = MagicMock()
        event.payload = {
            "from": "PARSING",
            "to": "PARSED",
            "content_hash": "abc123",
        }
        mock_event_repo.get_events_by_type.return_value = [event]
        assert orchestrator._is_stage_invalidated("eng-001", Stage.PARSE, "abc123") is False

    def test_different_hash_invalidated(
        self, orchestrator: Orchestrator, mock_event_repo: MagicMock
    ) -> None:
        event = MagicMock()
        event.payload = {
            "from": "PARSING",
            "to": "PARSED",
            "content_hash": "old_hash",
        }
        mock_event_repo.get_events_by_type.return_value = [event]
        assert orchestrator._is_stage_invalidated("eng-001", Stage.PARSE, "new_hash") is True

    def test_get_last_stage_hash_returns_most_recent(
        self, orchestrator: Orchestrator, mock_event_repo: MagicMock
    ) -> None:
        old_event = MagicMock()
        old_event.payload = {"to": "PARSED", "content_hash": "old"}
        new_event = MagicMock()
        new_event.payload = {"to": "PARSED", "content_hash": "new"}
        mock_event_repo.get_events_by_type.return_value = [old_event, new_event]
        assert orchestrator._get_last_stage_hash("eng-001", Stage.PARSE) == "new"


# ---------------------------------------------------------------------------
# run() and run_from() integration tests
# ---------------------------------------------------------------------------


class TestOrchestratorRun:
    """Integration tests for the full pipeline run."""

    def test_run_calls_run_stages_from_collect(
        self,
        orchestrator: Orchestrator,
    ) -> None:
        """run() delegates to run_stages with start_stage=COLLECT."""
        config = _make_config()
        with patch("gxassessms.pipeline._runner.run_stages") as mock_run:
            orchestrator.run(
                engagement_id="eng-001",
                config=config,
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=NoOpQAStrategy(),
                renderers=[],
            )
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args
            assert call_kwargs[1]["start_stage"] == Stage.COLLECT
            assert call_kwargs[1]["engagement_id"] == "eng-001"


class TestOrchestratorRunFrom:
    """Integration tests for pipeline resumption."""

    def test_run_from_calls_run_stages_with_start_stage(
        self,
        orchestrator: Orchestrator,
    ) -> None:
        """run_from() delegates to run_stages with the given start_stage."""
        config = _make_config()
        with patch("gxassessms.pipeline._runner.run_stages") as mock_run:
            orchestrator.run_from(
                engagement_id="eng-001",
                config=config,
                start_stage=Stage.NORMALIZE,
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=NoOpQAStrategy(),
                renderers=[],
            )
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args
            assert call_kwargs[1]["start_stage"] == Stage.NORMALIZE

    def test_run_from_parse_skips_collect(
        self,
        orchestrator: Orchestrator,
    ) -> None:
        """run_from(PARSE) should not include COLLECT in stages."""
        config = _make_config()
        with patch("gxassessms.pipeline._runner.run_stages") as mock_run:
            orchestrator.run_from(
                engagement_id="eng-001",
                config=config,
                start_stage=Stage.PARSE,
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=NoOpQAStrategy(),
                renderers=[],
            )
            mock_run.assert_called_once()
            assert mock_run.call_args[1]["start_stage"] == Stage.PARSE


# ---------------------------------------------------------------------------
# _extract_payload tests
# ---------------------------------------------------------------------------


class TestExtractPayload:
    def test_dict_with_json_string_payload(self) -> None:
        event = {"payload": '{"to": "PARSED", "content_hash": "abc123"}'}
        result = _extract_payload(event)
        assert result == {"to": "PARSED", "content_hash": "abc123"}

    def test_dict_with_dict_payload(self) -> None:
        event = {"payload": {"to": "PARSED"}}
        result = _extract_payload(event)
        assert result == {"to": "PARSED"}

    def test_corrupt_json_raises_persistence_error(self) -> None:
        event = {"payload": "{not valid json"}
        with pytest.raises(PersistenceError, match="Corrupt"):
            _extract_payload(event)
