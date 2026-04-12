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

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )

        assert result.exit_code == 0, result.output

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

        runner = CliRunner()
        runner.invoke(
            cli,
            ["ingest", _ENGAGEMENT_ID, "--tool", _TOOL_SLUG, "--from", str(source_dir)],
        )

        mock_get_artifacts.return_value.save_ingested_raw_output.assert_called_once()

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
                "manifest_version": "1.0.0",
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
        orchestrator.record_raw_output_ingested.assert_called_once()
        call_kwargs = orchestrator.record_raw_output_ingested.call_args.kwargs
        assert call_kwargs["tool_slug"] == _TOOL_SLUG
        assert call_kwargs["engagement_id"] == _ENGAGEMENT_ID

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
