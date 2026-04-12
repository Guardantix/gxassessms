"""Tests for the ``mseco ingest`` CLI command.

Covers:
  - Argument validation (missing --from, mutual exclusion with --repair-event)
  - Happy path fresh ingest (all deps mocked, exit 0, save called)
  - Repair-event happy path (mock manifest, verify event emission)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from gxassessms.cli.main import cli
from gxassessms.core.contracts.errors import PersistenceError

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_ENGAGEMENT_ID = "eng-ingest-001"
_TOOL_SLUG = "scubagear"
_ACTOR = "human:testuser"


def _make_engagement_row(engagement_id: str = _ENGAGEMENT_ID) -> dict[str, Any]:
    """Return a minimal engagement row with a scubagear-enabled config snapshot.

    The snapshot must include 'auth' because EngagementConfig.model_validate()
    requires it (stored as the model_dump() result in the DB).
    """
    snapshot = {
        "client_name": "Test Corp",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "subscription_id": "",
        "auth": {
            "method": "client_credential",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "client_id": "00000000-0000-0000-0000-000000000002",
            "client_secret_env": "GX_TEST_SECRET",  # pragma: allowlist secret
            "certificate_path": None,
        },
        "tools": {
            "scubagear": {
                "enabled": True,
                "output_dir": "",
                "controls_dir": "",
                "script_dir": "",
                "modules": [],
                "timeout": None,
                "extra_args": [],
                "module_policy_override": None,
            },
        },
        "max_parallel": 4,
        "report_formats": ["docx"],
        "report_theme": "basic",
        "report_logo_path": None,
        "qa_model": "claude-sonnet-4-6",
        "qa_token_budget": 100000,
    }
    return {
        "engagement_id": engagement_id,
        "client_name": "Test Corp",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "state": "CREATED",
        "created_at": "2026-01-01T00:00:00Z",
        "config_snapshot": json.dumps(snapshot),
    }


def _make_mock_adapter() -> MagicMock:
    """Return a mock adapter that passes require_ingest_capable checks."""
    adapter = MagicMock()
    adapter.tool_name = _TOOL_SLUG
    adapter.storage_slug = _TOOL_SLUG
    adapter.capabilities = frozenset({"ingest"})
    adapter.default_schema_version = "1.0.0"
    return adapter


def _make_collection_output(artifact_count: int = 3) -> MagicMock:
    """Return a mock CollectionOutput with the given number of artifacts."""
    co = MagicMock()
    co.tool_slug = _TOOL_SLUG
    co.artifacts = [MagicMock() for _ in range(artifact_count)]
    return co


def _make_loaded_manifest(replaced: bool = False) -> MagicMock:
    """Return a mock LoadedManifest with the given replaced state."""
    prov = MagicMock()
    prov.replaced = replaced
    raw_output = MagicMock()
    raw_output.ingest_provenance = prov
    loaded = MagicMock()
    loaded.raw_output = raw_output
    return loaded


# ---------------------------------------------------------------------------
# 1. Missing --from without --repair-event exits nonzero
# ---------------------------------------------------------------------------


class TestMissingFromFlag:
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_missing_from_exits_nonzero(self, mock_repo: MagicMock) -> None:
        """--from is required unless --repair-event is given."""
        mock_repo.return_value.get.return_value = _make_engagement_row()
        runner = CliRunner()
        result = runner.invoke(cli, ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_missing_from_prints_helpful_message(self, mock_repo: MagicMock) -> None:
        """Error message tells the user --from is required."""
        mock_repo.return_value.get.return_value = _make_engagement_row()
        runner = CliRunner()
        result = runner.invoke(cli, ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG])
        # Output goes to stderr via Rich console; CliRunner mixes them
        assert result.exit_code != 0
        assert "--from" in (result.output or "")


# ---------------------------------------------------------------------------
# 2. --repair-event + --from is rejected
# ---------------------------------------------------------------------------


class TestRepairEventMutualExclusion:
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_plus_from_exits_nonzero(
        self, mock_repo: MagicMock, tmp_path: Path
    ) -> None:
        """--repair-event and --from together must be rejected."""
        mock_repo.return_value.get.return_value = _make_engagement_row()
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--from",
                str(source_dir),
                "--repair-event",
            ],
        )
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_plus_from_prints_error(
        self, mock_repo: MagicMock, tmp_path: Path
    ) -> None:
        """Error message mentions mutual exclusion."""
        mock_repo.return_value.get.return_value = _make_engagement_row()
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--from",
                str(source_dir),
                "--repair-event",
            ],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output.lower()


# ---------------------------------------------------------------------------
# 3. --repair-event + --replace is rejected
# ---------------------------------------------------------------------------


class TestRepairEventRejectReplace:
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_plus_replace_exits_nonzero(self, mock_repo: MagicMock) -> None:
        """--repair-event and --replace together must be rejected."""
        mock_repo.return_value.get.return_value = _make_engagement_row()
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--replace",
                "--repair-event",
            ],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 4. Happy path fresh ingest
# ---------------------------------------------------------------------------


class TestIngestNormalHappyPath:
    """Happy path: mock all deps, verify exit 0 and save called."""

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_fresh_ingest_exits_zero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A fresh ingest with all mocked deps exits 0."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()

        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        collection_output = _make_collection_output(artifact_count=3)
        adapter.ingest_from_directory.return_value = collection_output
        loaded = _make_loaded_manifest(replaced=False)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )

        assert result.exit_code == 0, result.output

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_fresh_ingest_calls_save(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """save_ingested_raw_output() is called exactly once on success."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()

        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        collection_output = _make_collection_output()
        adapter.ingest_from_directory.return_value = collection_output
        loaded = _make_loaded_manifest(replaced=False)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )

        mock_get_artifacts.return_value.save_ingested_raw_output.assert_called_once()

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_fresh_ingest_calls_record_event(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """record_raw_output_ingested() is called with the correct tool_slug."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()

        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        collection_output = _make_collection_output(artifact_count=2)
        adapter.ingest_from_directory.return_value = collection_output
        loaded = _make_loaded_manifest(replaced=False)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )

        orchestrator = mock_build_orch.return_value
        orchestrator.record_raw_output_ingested.assert_called_once()
        call_kwargs = orchestrator.record_raw_output_ingested.call_args.kwargs
        assert call_kwargs["tool_slug"] == _TOOL_SLUG
        assert call_kwargs["engagement_id"] == _ENGAGEMENT_ID

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_fresh_ingest_shows_replaced_warning(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """When replaced=True, 'Replaced' appears in console output."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()

        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        collection_output = _make_collection_output()
        adapter.ingest_from_directory.return_value = collection_output
        loaded = _make_loaded_manifest(replaced=True)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--from",
                str(source_dir),
                "--replace",
            ],
        )

        assert result.exit_code == 0
        assert "Replaced" in result.output or "replaced" in result.output.lower()


# ---------------------------------------------------------------------------
# 5. Repair-event happy path
# ---------------------------------------------------------------------------


class TestRepairEventHappyPath:
    """Repair-event: mock manifest load, verify event emission."""

    def _make_manifest_json(self, tool_slug: str = _TOOL_SLUG, replaced: bool = False) -> str:
        """Build a minimal RawToolOutput JSON for repair-event tests.

        tool must be a ToolSource StrEnum value (e.g. "ScubaGear", not a dict).
        """
        # ToolSource enum value for scubagear is "ScubaGear"
        tool_source_value = "ScubaGear" if tool_slug == "scubagear" else tool_slug
        return json.dumps(
            {
                "tool": tool_source_value,
                "tool_slug": tool_slug,
                "schema_version": "1.0.0",
                "manifest_version": "1.1.0",
                "timestamp": "2026-01-01T00:00:00Z",
                "file_manifest": {
                    f"{tool_slug}/results.json": {
                        "encoding": "utf-8",
                        "sha256": "a" * 64,
                    }
                },
                "execution_metadata": {},
                "source_mode": "ingested",
                "ingest_provenance": {
                    "source_path": "/home/testuser/scubagear-output",
                    "ingested_at": "2026-01-01T00:00:00Z",
                    "ingested_by": "human:testuser",
                    "replaced": replaced,
                },
            }
        )

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_emits_event(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """repair-event reads manifest and calls record_raw_output_ingested."""
        # Set up engagement row
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter

        # Create a real manifest file in the expected location
        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        manifest_path.write_text(self._make_manifest_json(), encoding="utf-8")

        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir

        # No existing events
        orchestrator = mock_build_orch.return_value
        orchestrator.has_raw_output_ingested_event.return_value = False
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--repair-event",
            ],
        )

        assert result.exit_code == 0, result.output
        orchestrator.has_raw_output_ingested_event.assert_called_once_with(
            _ENGAGEMENT_ID,
            _TOOL_SLUG,
            source_path="/home/testuser/scubagear-output",  # from _make_manifest_json
        )
        orchestrator.record_raw_output_ingested.assert_called_once()
        call_kwargs = orchestrator.record_raw_output_ingested.call_args.kwargs
        assert call_kwargs["tool_slug"] == _TOOL_SLUG
        assert call_kwargs["engagement_id"] == _ENGAGEMENT_ID
        assert call_kwargs["actor"] == "human:testuser"  # prov.ingested_by from manifest fixture

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_uses_manifest_ingested_by_not_current_operator(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--operator override must NOT override the committed manifest actor."""
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter

        # Create a real manifest file in the expected location
        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        # Manifest records ingested_by as "human:testuser"
        manifest_path.write_text(self._make_manifest_json(), encoding="utf-8")

        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir

        # No existing events
        orchestrator = mock_build_orch.return_value
        orchestrator.has_raw_output_ingested_event.return_value = False
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--repair-event",
                "--operator",
                "differentuser",
            ],
        )

        assert result.exit_code == 0, result.output
        orchestrator.record_raw_output_ingested.assert_called_once()
        call_kwargs = orchestrator.record_raw_output_ingested.call_args.kwargs
        # The manifest's ingested_by wins; the current --operator must not override it
        assert call_kwargs["actor"] == "human:testuser"

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_idempotent_when_event_exists(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """If the event already exists, repair-event skips emission and exits 0."""
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter

        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        manifest_path.write_text(self._make_manifest_json(), encoding="utf-8")
        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir

        # Existing matching event
        orchestrator = mock_build_orch.return_value
        orchestrator.has_raw_output_ingested_event.return_value = True
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--repair-event",
            ],
        )

        assert result.exit_code == 0
        # Should NOT emit a new event
        orchestrator.record_raw_output_ingested.assert_not_called()

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_missing_manifest_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """repair-event with no manifest on disk exits nonzero."""
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter

        eng_dir = tmp_path / _ENGAGEMENT_ID
        eng_dir.mkdir()
        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--repair-event",
            ],
        )

        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_repair_event_collected_manifest_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """repair-event on a 'collected' manifest (not 'ingested') exits nonzero."""
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter

        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)

        # source_mode is "collected" (no ingest_provenance)
        # tool must be a ToolSource StrEnum string value, not a dict
        collected_manifest = json.dumps(
            {
                "tool": "ScubaGear",
                "tool_slug": _TOOL_SLUG,
                "schema_version": "1.0.0",
                "manifest_version": "1.0.0",
                "timestamp": "2026-01-01T00:00:00Z",
                "file_manifest": {
                    f"{_TOOL_SLUG}/results.json": {
                        "encoding": "utf-8",
                        "sha256": "a" * 64,
                    }
                },
                "execution_metadata": {},
                "source_mode": "collected",
            }
        )
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        manifest_path.write_text(collected_manifest, encoding="utf-8")
        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--repair-event",
            ],
        )

        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Shared helper for repair-event error-path tests
# ---------------------------------------------------------------------------


def _make_repair_manifest_json(tool_slug: str = _TOOL_SLUG, replaced: bool = False) -> str:
    """Build a minimal ingested RawToolOutput JSON for repair-event tests."""
    tool_source_value = "ScubaGear" if tool_slug == "scubagear" else tool_slug
    return json.dumps(
        {
            "tool": tool_source_value,
            "tool_slug": tool_slug,
            "schema_version": "1.0.0",
            "manifest_version": "1.1.0",
            "timestamp": "2026-01-01T00:00:00Z",
            "file_manifest": {
                f"{tool_slug}/results.json": {
                    "encoding": "utf-8",
                    "sha256": "a" * 64,
                }
            },
            "execution_metadata": {},
            "source_mode": "ingested",
            "ingest_provenance": {
                "source_path": "/home/testuser/scubagear-output",
                "ingested_at": "2026-01-01T00:00:00Z",
                "ingested_by": "human:testuser",
                "replaced": replaced,
            },
        }
    )


# ---------------------------------------------------------------------------
# 6. Error path tests
# ---------------------------------------------------------------------------


class TestIngestErrorPaths:
    """Error paths for both normal and repair ingest flows."""

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_engagement_not_found_exits_nonzero(self, mock_get_repo: MagicMock) -> None:
        """Normal path: engagement lookup failure exits nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_get_repo.return_value.get.side_effect = GxAssessError("not found")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", "/tmp"],  # noqa: S108
        )
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_persistence_error_from_save_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """save_ingested_raw_output raising PersistenceError -> exit nonzero."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        adapter.ingest_from_directory.return_value = _make_collection_output()
        mock_get_artifacts.return_value.save_ingested_raw_output.side_effect = PersistenceError(
            "disk full"
        )
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_invalid_run_at_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Invalid --run-at value exits nonzero with descriptive message."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--from",
                str(source_dir),
                "--run-at",
                "not-a-date",
            ],
        )
        assert result.exit_code != 0
        assert "run-at" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_event_recording_failure_exits_zero_with_warning(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Event recording failure is non-fatal: exit 0 with --repair-event hint."""
        from gxassessms.core.contracts.errors import GxAssessError

        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        adapter.ingest_from_directory.return_value = _make_collection_output()
        loaded = _make_loaded_manifest(replaced=False)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_build_orch.return_value.record_raw_output_ingested.side_effect = GxAssessError(
            "db locked"
        )
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )
        assert result.exit_code == 0
        assert "--repair-event" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_repair_event_proceeds_when_idempotency_check_fails(
        self,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Repair path: idempotency check failure is non-fatal; event still emitted."""
        from gxassessms.core.contracts.errors import GxAssessError

        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        manifest_path.write_text(_make_repair_manifest_json(), encoding="utf-8")
        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir

        orchestrator = mock_build_orch.return_value
        orchestrator.has_raw_output_ingested_event.side_effect = GxAssessError("db error")
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--repair-event"],
        )
        assert result.exit_code == 0
        orchestrator.record_raw_output_ingested.assert_called_once()
        assert "Warning" in result.output

    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_adapter_not_enabled_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
    ) -> None:
        """Normal path: adapter not enabled in config -> exit nonzero."""
        import click

        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        mock_resolve.side_effect = click.UsageError("not enabled")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", "unknown-tool", "--from", "/tmp"],  # noqa: S108
        )
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_repair_event_corrupt_manifest_exits_nonzero(
        self,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Repair path: binary garbage manifest -> exit nonzero with 'Repair failed'."""
        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        manifest_path.write_bytes(b"\x00\x01\x02\xff\xfe")
        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--repair-event"],
        )
        assert result.exit_code != 0
        assert "Repair failed" in result.output

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_adapter_ingest_error_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """CollectionError from adapter -> exit nonzero with 'Ingest failed'."""
        from gxassessms.core.contracts.errors import CollectionError

        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        adapter.ingest_from_directory.side_effect = CollectionError(
            "parse failed", adapter_name="scubagear"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )
        assert result.exit_code != 0
        assert "Ingest failed" in result.output

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_valueerror_from_adapter_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """ValueError from adapter (e.g., bad relpath) -> exit nonzero."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        adapter.ingest_from_directory.side_effect = ValueError("bad relpath")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )
        assert result.exit_code != 0
        assert "Ingest failed" in result.output

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_oserror_from_adapter_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """OSError from adapter -> exit nonzero."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        adapter.ingest_from_directory.side_effect = OSError("permission denied")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )
        assert result.exit_code != 0
        assert "Ingest failed" in result.output

    def test_repair_event_invalid_slug_exits_nonzero(self) -> None:
        """--repair-event with path traversal slug exits nonzero."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                "../../etc/passwd",
                "--repair-event",
            ],
        )
        assert result.exit_code != 0
        assert "Invalid tool slug" in result.output

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_invalid_schema_version_format_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--schema-version with non-matching format -> exit nonzero."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--from",
                str(source_dir),
                "--schema-version",
                "garbage",
            ],
        )
        assert result.exit_code != 0
        assert (
            "schema-version" in result.output.lower() or "version string" in result.output.lower()
        )


# ---------------------------------------------------------------------------
# 7. Happy path additional tests (operator, schema-version wiring)
# ---------------------------------------------------------------------------


class TestIngestWiringHappyPath:
    """Tests that CLI flags are correctly forwarded to lower layers."""

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_operator_override_flows_to_provenance(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--operator alice results in ingested_by='human:alice' in provenance."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()

        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        adapter.ingest_from_directory.return_value = _make_collection_output()
        loaded = _make_loaded_manifest(replaced=False)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--from",
                str(source_dir),
                "--operator",
                "alice",
            ],
        )
        assert result.exit_code == 0, result.output
        call_kwargs = mock_get_artifacts.return_value.save_ingested_raw_output.call_args.kwargs
        prov = call_kwargs["ingest_provenance"]
        assert prov.ingested_by == "human:alice"

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_schema_version_override_forwarded(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--schema-version 2.0.0 is forwarded to adapter.ingest_from_directory."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()

        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        adapter.ingest_from_directory.return_value = _make_collection_output()
        loaded = _make_loaded_manifest(replaced=False)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ingest",
                _ENGAGEMENT_ID,
                "--tool",
                _TOOL_SLUG,
                "--from",
                str(source_dir),
                "--schema-version",
                "2.0.0",
            ],
        )
        assert result.exit_code == 0, result.output
        call_kwargs = adapter.ingest_from_directory.call_args.kwargs
        assert call_kwargs["schema_version"] == "2.0.0"


# ---------------------------------------------------------------------------
# 8. Lock acquisition tests
# ---------------------------------------------------------------------------


class TestIngestLockAcquisition:
    """Tests that verify EngagementLock is acquired for mutation operations."""

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_ingest_normal_acquires_engagement_lock(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Normal ingest acquires per-engagement lock before writing artifacts."""
        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        collection_output = _make_collection_output()
        adapter.ingest_from_directory.return_value = collection_output
        loaded = _make_loaded_manifest(replaced=False)
        mock_get_artifacts.return_value.save_ingested_raw_output.return_value = loaded
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        runner.invoke(
            cli, ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)]
        )

        mock_get_lock.return_value.hold.assert_called_once_with(_ENGAGEMENT_ID)

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_repair_event_acquires_engagement_lock(
        self,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--repair-event acquires per-engagement lock before idempotency check."""
        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        manifest_path.write_text(_make_repair_manifest_json(), encoding="utf-8")
        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir
        orchestrator = mock_build_orch.return_value
        orchestrator.has_raw_output_ingested_event.return_value = False
        mock_lock = mock_get_lock.return_value
        mock_lock.hold.return_value.__enter__ = MagicMock(return_value=None)
        mock_lock.hold.return_value.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        runner.invoke(cli, ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--repair-event"])

        mock_get_lock.return_value.hold.assert_called_once_with(_ENGAGEMENT_ID)

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.require_ingest_capable", autospec=True)
    @patch("gxassessms.cli._helpers.resolve_enabled_adapter", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_ingest_normal_lock_timeout_exits_nonzero(
        self,
        mock_get_repo: MagicMock,
        mock_resolve: MagicMock,
        mock_require: MagicMock,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """LockTimeoutError during ingest shows clean error and exits 1."""
        from gxassessms.core.contracts.errors import LockTimeoutError

        source_dir = tmp_path / "output"
        source_dir.mkdir()
        mock_get_repo.return_value.get.return_value = _make_engagement_row()
        adapter = _make_mock_adapter()
        mock_resolve.return_value = adapter
        mock_require.return_value = adapter
        collection_output = _make_collection_output()
        adapter.ingest_from_directory.return_value = collection_output
        mock_get_lock.return_value.hold.side_effect = LockTimeoutError(
            message="Engagement locked by another process",
            engagement_id=_ENGAGEMENT_ID,
            timeout_seconds=30.0,
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)]
        )
        assert result.exit_code == 1
        assert "locked" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_lock", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_repair_event_lock_timeout_exits_nonzero(
        self,
        mock_get_artifacts: MagicMock,
        mock_build_orch: MagicMock,
        mock_get_lock: MagicMock,
        tmp_path: Path,
    ) -> None:
        """LockTimeoutError during --repair-event shows clean error and exits 1."""
        from gxassessms.core.contracts.errors import LockTimeoutError

        eng_dir = tmp_path / _ENGAGEMENT_ID
        manifest_dir = eng_dir / "raw-output" / "manifests"
        manifest_dir.mkdir(parents=True)
        manifest_path = manifest_dir / f"{_TOOL_SLUG}.json"
        manifest_path.write_text(_make_repair_manifest_json(), encoding="utf-8")
        mock_get_artifacts.return_value.get_engagement_dir.return_value = eng_dir
        mock_get_lock.return_value.hold.side_effect = LockTimeoutError(
            message="Engagement locked by another process",
            engagement_id=_ENGAGEMENT_ID,
            timeout_seconds=30.0,
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--repair-event"]
        )
        assert result.exit_code == 1
        assert "locked" in result.output.lower()
