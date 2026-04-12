"""End-to-end ingest integration tests (spec Section 6.7).

Drives the real ``mseco engagement create`` + ``mseco ingest`` CLI commands
via Click's CliRunner against a real database and real filesystem in an
isolated tmp_path directory.

``discover_adapters()`` is monkeypatched to return the real ScubaGearAdapter
class (the same technique used by unit tests in test_helpers.py) because the
package entry points are not registered in the test environment.  All other
layers -- EngagementRepo, ArtifactManager, EventRepo -- run against real
SQLite and real filesystem I/O.

This is the integration smoke test for the ``ingest`` subsystem.  It catches
CLI-to-persistence wiring breakage that the unit tests for each layer miss.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from gxassessms.cli.main import cli

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_engagement_id(output: str) -> str:
    """Extract engagement ID from ``engagement create`` output.

    The create command prints::

        Engagement created: <uuid>
        Client: ...
        Tenant: ...
    """
    for line in output.splitlines():
        if "Engagement created:" in line:
            return line.split(":", 1)[-1].strip()
    raise ValueError(f"Could not find engagement ID in output:\n{output}")


def _make_scubagear_registry() -> Any:
    """Return an AdapterRegistry containing the real ScubaGearAdapter class.

    Used to patch ``gxassessms.adapters.discover_adapters`` so that
    ``_helpers.resolve_enabled_adapter`` can find 'scubagear' without
    requiring the package to be installed with entry points.
    """
    from gxassessms.adapters import AdapterRegistry
    from gxassessms.adapters.scubagear import ScubaGearAdapter

    return AdapterRegistry(
        adapters={"scubagear": ScubaGearAdapter},
        validation_errors=[],
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point GxAssessMS at a tmp_path data directory for this test only.

    Mirrors the fixture in test_pipeline_end_to_end.py.
    """
    data_dir = tmp_path / "gxassessms-data"
    data_dir.mkdir()
    monkeypatch.setenv("GXASSESSMS_DATA_DIR", str(data_dir))
    return data_dir


@pytest.fixture
def scubagear_fixtures_dir() -> Path:
    """Return the ScubaGear bundled fixtures directory."""
    fixtures_dir = (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "scubagear"
        / "fixtures"
    )
    assert fixtures_dir.exists(), f"ScubaGear fixtures directory missing: {fixtures_dir}"
    return fixtures_dir


# ---------------------------------------------------------------------------
# Spec Section 6.7 test 1 -- create -> ingest -> verify manifest
# ---------------------------------------------------------------------------


class TestSingleToolIngestAndReplay:
    """Spec Section 6.7 test 1: create -> ingest scubagear -> verify manifest."""

    def _write_config_yaml(self, path: Path) -> None:
        """Write a minimal engagement YAML config to *path*."""
        path.write_text(
            "client:\n"
            "  name: Integration Test\n"
            "  tenant_id: 00000000-0000-0000-0000-000000000001\n"
            "auth:\n"
            "  method: client_credential\n"
            "  client_id: 00000000-0000-0000-0000-000000000002\n"
            "  tenant_id: 00000000-0000-0000-0000-000000000001\n"
            "  client_secret_env: TEST_SECRET\n"
            "tools:\n"
            "  scubagear:\n"
            "    enabled: true\n",
            encoding="utf-8",
        )

    def test_ingest_scubagear_writes_manifest(
        self,
        isolated_data_dir: Path,
        scubagear_fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Full ingest flow: create engagement, ingest ScubaGear output, verify manifest on disk.

        Verifies:
        - ``engagement create`` succeeds and prints engagement ID
        - ``ingest`` succeeds (exit 0)
        - Manifest file lands at ``raw-output/manifests/scubagear.json``
        - Manifest has ``source_mode == "ingested"``, correct ``manifest_version``,
          and ``ingest_provenance`` populated
        """
        runner = CliRunner()

        # 1. Write config YAML
        config_file = tmp_path / "config.yaml"
        self._write_config_yaml(config_file)

        # 2. Create engagement
        result = runner.invoke(cli, ["engagement", "create", str(config_file)])
        assert result.exit_code == 0, (
            f"engagement create failed (exit {result.exit_code}):\n{result.output}"
        )
        engagement_id = _extract_engagement_id(result.output)
        assert engagement_id, "engagement create did not print an engagement ID"

        # 3. Prepare source directory with the bundled ScubaGear fixture
        source_dir = tmp_path / "scuba-export"
        source_dir.mkdir()
        shutil.copy(
            str(scubagear_fixtures_dir / "ScubaResults.json"),
            str(source_dir / "ScubaResults.json"),
        )

        # 4. Ingest -- monkeypatch discover_adapters so the CLI can find
        #    ScubaGearAdapter without requiring package entry points.
        with patch(
            "gxassessms.adapters.discover_adapters",
            return_value=_make_scubagear_registry(),
        ):
            result = runner.invoke(
                cli,
                [
                    "ingest",
                    engagement_id,
                    "--tool",
                    "scubagear",
                    "--from",
                    str(source_dir),
                ],
            )
        assert result.exit_code == 0, f"ingest failed (exit {result.exit_code}):\n{result.output}"

        # 5. Verify manifest exists on disk
        from gxassessms.cli._helpers import get_artifact_manager

        am = get_artifact_manager()
        eng_dir = am.get_engagement_dir(engagement_id)
        manifest = eng_dir / "raw-output" / "manifests" / "scubagear.json"
        assert manifest.exists(), f"Manifest not found at {manifest}"

        # 6. Verify manifest content
        manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
        assert manifest_data["source_mode"] == "ingested", (
            f"Expected source_mode='ingested', got {manifest_data.get('source_mode')!r}"
        )
        assert manifest_data["manifest_version"] == "1.1.0", (
            f"Expected manifest_version='1.1.0', got {manifest_data.get('manifest_version')!r}"
        )
        assert "ingest_provenance" in manifest_data, "Manifest missing 'ingest_provenance' key"

    def test_ingest_creates_artifact_files(
        self,
        isolated_data_dir: Path,
        scubagear_fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Ingest copies artifact files into raw-output/artifacts/scubagear/."""
        runner = CliRunner()

        config_file = tmp_path / "config.yaml"
        self._write_config_yaml(config_file)

        result = runner.invoke(cli, ["engagement", "create", str(config_file)])
        assert result.exit_code == 0, result.output
        engagement_id = _extract_engagement_id(result.output)

        source_dir = tmp_path / "scuba-export"
        source_dir.mkdir()
        shutil.copy(
            str(scubagear_fixtures_dir / "ScubaResults.json"),
            str(source_dir / "ScubaResults.json"),
        )

        with patch(
            "gxassessms.adapters.discover_adapters",
            return_value=_make_scubagear_registry(),
        ):
            result = runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--from", str(source_dir)],
            )
        assert result.exit_code == 0, result.output

        from gxassessms.cli._helpers import get_artifact_manager

        am = get_artifact_manager()
        eng_dir = am.get_engagement_dir(engagement_id)
        artifacts_dir = eng_dir / "raw-output" / "artifacts" / "scubagear"
        assert artifacts_dir.exists(), f"Artifacts directory not found at {artifacts_dir}"
        artifact_files = list(artifacts_dir.iterdir())
        assert len(artifact_files) >= 1, "Expected at least one artifact file"

    def test_ingest_replace_overwrites_existing(
        self,
        isolated_data_dir: Path,
        scubagear_fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Second ingest with --replace succeeds; manifest records replaced=True."""
        runner = CliRunner()

        config_file = tmp_path / "config.yaml"
        self._write_config_yaml(config_file)

        result = runner.invoke(cli, ["engagement", "create", str(config_file)])
        assert result.exit_code == 0, result.output
        engagement_id = _extract_engagement_id(result.output)

        source_dir = tmp_path / "scuba-export"
        source_dir.mkdir()
        shutil.copy(
            str(scubagear_fixtures_dir / "ScubaResults.json"),
            str(source_dir / "ScubaResults.json"),
        )

        registry = _make_scubagear_registry()

        # First ingest
        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            r1 = runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--from", str(source_dir)],
            )
        assert r1.exit_code == 0, r1.output

        # Second ingest without --replace should fail
        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            r2 = runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--from", str(source_dir)],
            )
        assert r2.exit_code != 0, "Expected failure when ingesting duplicate without --replace"

        # Third ingest with --replace should succeed
        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            r3 = runner.invoke(
                cli,
                [
                    "ingest",
                    engagement_id,
                    "--tool",
                    "scubagear",
                    "--from",
                    str(source_dir),
                    "--replace",
                ],
            )
        assert r3.exit_code == 0, f"Replace ingest failed:\n{r3.output}"

        from gxassessms.cli._helpers import get_artifact_manager

        am = get_artifact_manager()
        eng_dir = am.get_engagement_dir(engagement_id)
        manifest_data = json.loads(
            (eng_dir / "raw-output" / "manifests" / "scubagear.json").read_text(encoding="utf-8")
        )
        prov = manifest_data.get("ingest_provenance", {})
        got_replaced = prov.get("replaced")
        assert got_replaced is True, (
            f"Expected ingest_provenance.replaced=true after --replace, got {got_replaced!r}"
        )

    def test_ingest_duplicate_without_replace_fails(
        self,
        isolated_data_dir: Path,
        scubagear_fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Duplicate ingest without --replace exits nonzero with an error message."""
        runner = CliRunner()

        config_file = tmp_path / "config.yaml"
        self._write_config_yaml(config_file)

        result = runner.invoke(cli, ["engagement", "create", str(config_file)])
        assert result.exit_code == 0, result.output
        engagement_id = _extract_engagement_id(result.output)

        source_dir = tmp_path / "scuba-export"
        source_dir.mkdir()
        shutil.copy(
            str(scubagear_fixtures_dir / "ScubaResults.json"),
            str(source_dir / "ScubaResults.json"),
        )

        registry = _make_scubagear_registry()

        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--from", str(source_dir)],
            )

        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            result = runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--from", str(source_dir)],
            )
        assert result.exit_code != 0, "Expected nonzero exit for duplicate ingest"
        assert "already exists" in result.output.lower() or "replace" in result.output.lower(), (
            f"Expected error message about existing data or --replace flag, got:\n{result.output}"
        )

    def test_repair_event_after_ingest(
        self,
        isolated_data_dir: Path,
        scubagear_fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """--repair-event emits a missing ingest event from a committed manifest.

        Simulates audit recovery: ingest the artifact, then call ``ingest
        --repair-event`` to re-emit the event if it was missing from the DB.
        """
        runner = CliRunner()

        config_file = tmp_path / "config.yaml"
        self._write_config_yaml(config_file)

        result = runner.invoke(cli, ["engagement", "create", str(config_file)])
        assert result.exit_code == 0, result.output
        engagement_id = _extract_engagement_id(result.output)

        source_dir = tmp_path / "scuba-export"
        source_dir.mkdir()
        shutil.copy(
            str(scubagear_fixtures_dir / "ScubaResults.json"),
            str(source_dir / "ScubaResults.json"),
        )

        registry = _make_scubagear_registry()

        # Normal ingest first
        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            result = runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--from", str(source_dir)],
            )
        assert result.exit_code == 0, result.output

        # Repair-event: should detect existing event and report idempotency
        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            result = runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--repair-event"],
            )
        assert result.exit_code == 0, (
            f"--repair-event failed (exit {result.exit_code}):\n{result.output}"
        )
        # Either "already exists" (idempotent) or "Repaired" (emitted) are valid
        assert "already exists" in result.output.lower() or "repaired" in result.output.lower(), (
            f"Expected idempotency or repair confirmation, got:\n{result.output}"
        )

    def test_ingest_records_event_in_db(
        self,
        isolated_data_dir: Path,
        scubagear_fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """After CLI ingest, a raw_output_ingested event exists in the DB."""
        runner = CliRunner()

        config_file = tmp_path / "config.yaml"
        self._write_config_yaml(config_file)

        result = runner.invoke(cli, ["engagement", "create", str(config_file)])
        assert result.exit_code == 0, result.output
        engagement_id = _extract_engagement_id(result.output)

        source_dir = tmp_path / "scuba-export"
        source_dir.mkdir()
        shutil.copy(
            str(scubagear_fixtures_dir / "ScubaResults.json"),
            str(source_dir / "ScubaResults.json"),
        )

        registry = _make_scubagear_registry()

        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            result = runner.invoke(
                cli,
                ["ingest", engagement_id, "--tool", "scubagear", "--from", str(source_dir)],
            )
        assert result.exit_code == 0, result.output

        # Query EventRepo directly
        from gxassessms.persistence import DatabaseManager, EventRepo

        db = DatabaseManager()
        db.initialize()
        event_repo = EventRepo(db)
        events = event_repo.get_events_by_type(engagement_id, "raw_output_ingested")
        assert len(events) == 1
        payload = json.loads(events[0]["payload"])
        assert payload["tool_slug"] == "scubagear"
