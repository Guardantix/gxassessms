"""Tests for file artifact storage, archive/restore/purge."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import AdapterResult, RawToolOutput
from gxassessms.persistence.artifacts import (
    ArtifactManager,
    _sanitize_slug,
    _validate_path_within_root,
)


class TestSanitizeSlug:
    def test_alphanumeric_passthrough(self) -> None:
        assert _sanitize_slug("acme-healthcare") == "acme-healthcare"

    def test_spaces_become_hyphens(self) -> None:
        assert _sanitize_slug("Acme Healthcare") == "acme-healthcare"

    def test_special_chars_removed(self) -> None:
        assert _sanitize_slug("Acme's (Test) Corp.") == "acmes-test-corp"

    def test_max_length_truncated(self) -> None:
        long_name = "a" * 100
        result = _sanitize_slug(long_name)
        assert len(result) <= 64

    def test_empty_string_returns_unnamed(self) -> None:
        assert _sanitize_slug("") == "unnamed"

    def test_unicode_handled(self) -> None:
        result = _sanitize_slug("Acme Gesundheit GmbH")
        assert "acme" in result

    def test_all_special_chars_returns_unnamed(self) -> None:
        assert _sanitize_slug("@#$%^&*()") == "unnamed"


class TestValidatePathWithinRoot:
    def test_valid_path(self, tmp_path: Path) -> None:
        root = tmp_path / "engagements"
        root.mkdir()
        target = root / "eng-001"
        target.mkdir()
        # Should not raise
        _validate_path_within_root(target, root)

    def test_traversal_attack_raises(self, tmp_path: Path) -> None:
        root = tmp_path / "engagements"
        root.mkdir()
        evil_path = root / ".." / ".." / "etc" / "passwd"
        with pytest.raises(PersistenceError, match="path traversal"):
            _validate_path_within_root(evil_path, root)

    def test_symlink_outside_root_raises(self, tmp_path: Path) -> None:
        root = tmp_path / "engagements"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        symlink = root / "evil-link"
        symlink.symlink_to(outside)
        with pytest.raises(PersistenceError, match="path traversal"):
            _validate_path_within_root(symlink, root)


class TestArtifactManager:
    @pytest.fixture
    def artifact_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        return ArtifactManager(
            engagements_root=engagements_root,
            audit_dir=audit_dir,
        )

    def test_create_engagement_dir(self, artifact_mgr: ArtifactManager) -> None:
        eng_dir = artifact_mgr.create_engagement_dir(
            engagement_id="eng-001",
            client_name="Acme Healthcare",
        )
        assert eng_dir.exists()
        assert eng_dir.is_dir()
        # Should contain the engagement ID
        assert "eng-001" in eng_dir.name

    def test_create_engagement_dir_has_subdirs(self, artifact_mgr: ArtifactManager) -> None:
        eng_dir = artifact_mgr.create_engagement_dir(
            engagement_id="eng-001",
            client_name="Acme",
        )
        assert (eng_dir / "raw-output").exists()
        assert (eng_dir / "reports").exists()

    def test_get_engagement_dir(self, artifact_mgr: ArtifactManager) -> None:
        created = artifact_mgr.create_engagement_dir(
            engagement_id="eng-001",
            client_name="Acme",
        )
        retrieved = artifact_mgr.get_engagement_dir("eng-001")
        assert retrieved == created

    def test_get_nonexistent_engagement_dir_raises(self, artifact_mgr: ArtifactManager) -> None:
        with pytest.raises(PersistenceError):
            artifact_mgr.get_engagement_dir("nonexistent")


class TestArtifactManagerArchive:
    @pytest.fixture
    def populated_artifact_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mgr = ArtifactManager(
            engagements_root=engagements_root,
            audit_dir=audit_dir,
        )
        # Create an engagement with some files
        eng_dir = mgr.create_engagement_dir("eng-archive", "Acme")
        raw_dir = eng_dir / "raw-output" / "scubagear"
        raw_dir.mkdir(parents=True)
        (raw_dir / "TestResults.json").write_text('{"test": true}')
        (eng_dir / "reports" / "report.docx").write_bytes(b"fake docx")
        return mgr

    def test_archive_creates_tarball(self, populated_artifact_mgr: ArtifactManager) -> None:
        archive_path = populated_artifact_mgr.archive("eng-archive")
        assert archive_path.exists()
        assert archive_path.name == "raw-output.tar.gz"

    def test_archive_removes_raw_output(self, populated_artifact_mgr: ArtifactManager) -> None:
        populated_artifact_mgr.archive("eng-archive")
        eng_dir = populated_artifact_mgr.get_engagement_dir("eng-archive")
        scuba_dir = eng_dir / "raw-output" / "scubagear"
        assert not scuba_dir.exists()

    def test_restore_recreates_files(self, populated_artifact_mgr: ArtifactManager) -> None:
        populated_artifact_mgr.archive("eng-archive")
        populated_artifact_mgr.restore("eng-archive")
        eng_dir = populated_artifact_mgr.get_engagement_dir("eng-archive")
        restored_file = eng_dir / "raw-output" / "scubagear" / "TestResults.json"
        assert restored_file.exists()
        assert json.loads(restored_file.read_text()) == {"test": True}

    def test_archive_on_empty_raw_output_raises(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        mgr = ArtifactManager(engagements_root=engagements_root)
        mgr.create_engagement_dir("eng-empty", "Test")
        with pytest.raises(PersistenceError, match="No raw output"):
            mgr.archive("eng-empty")

    def test_restore_nonexistent_archive_raises(
        self, populated_artifact_mgr: ArtifactManager
    ) -> None:
        # Create engagement dir without archiving so there's no .tar.gz
        populated_artifact_mgr.create_engagement_dir("eng-no-archive", "Test")
        with pytest.raises(PersistenceError, match="archive"):
            populated_artifact_mgr.restore("eng-no-archive")

    def test_archive_raises_if_archive_already_exists(
        self, populated_artifact_mgr: ArtifactManager
    ) -> None:
        # First archive succeeds and leaves .tar.gz on disk.
        populated_artifact_mgr.archive("eng-archive")
        # Second attempt (after re-populating raw-output) must raise.
        eng_dir = populated_artifact_mgr.get_engagement_dir("eng-archive")
        raw_sub = eng_dir / "raw-output" / "scubagear"
        raw_sub.mkdir(parents=True, exist_ok=True)
        (raw_sub / "results.json").write_text("{}")
        with pytest.raises(PersistenceError, match="already exists"):
            populated_artifact_mgr.archive("eng-archive")


class TestArtifactManagerPurge:
    @pytest.fixture
    def purge_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mgr = ArtifactManager(
            engagements_root=engagements_root,
            audit_dir=audit_dir,
        )
        eng_dir = mgr.create_engagement_dir("eng-purge", "PurgeClient")
        (eng_dir / "raw-output" / "scubagear").mkdir(parents=True)
        (eng_dir / "raw-output" / "scubagear" / "results.json").write_text("{}")
        (eng_dir / "reports" / "report.docx").write_bytes(b"fake")
        (eng_dir / "config.yaml").write_text("client: PurgeClient")
        return mgr

    def test_purge_writes_audit_manifest(self, purge_mgr: ArtifactManager) -> None:
        manifest = purge_mgr.purge("eng-purge", operator="rick")
        assert manifest["engagement_id"] == "eng-purge"
        assert manifest["operator"] == "rick"
        assert "purged_at" in manifest
        assert "files_deleted" in manifest
        assert len(manifest["files_deleted"]) > 0

    def test_purge_writes_manifest_to_audit_dir(self, purge_mgr: ArtifactManager) -> None:
        purge_mgr.purge("eng-purge", operator="rick")
        audit_files = list(purge_mgr._audit_dir.glob("purge-eng-purge-*.json"))
        assert len(audit_files) == 1
        manifest_data = json.loads(audit_files[0].read_text())
        assert manifest_data["engagement_id"] == "eng-purge"

    def test_purge_removes_engagement_dir(self, purge_mgr: ArtifactManager) -> None:
        purge_mgr.purge("eng-purge", operator="rick")
        with pytest.raises(PersistenceError):
            purge_mgr.get_engagement_dir("eng-purge")

    def test_purge_nonexistent_raises(self, purge_mgr: ArtifactManager) -> None:
        with pytest.raises(PersistenceError):
            purge_mgr.purge("nonexistent", operator="rick")

    def test_audit_dir_not_affected_by_purge(self, purge_mgr: ArtifactManager) -> None:
        purge_mgr.purge("eng-purge", operator="rick")
        # Audit directory should still exist and contain the manifest
        assert purge_mgr._audit_dir.exists()
        assert len(list(purge_mgr._audit_dir.iterdir())) > 0

    def test_purge_writes_manifest_before_deletion(self, tmp_path: Path) -> None:
        """Audit manifest must exist on disk even if rmtree fails."""
        import shutil as shutil_mod
        from unittest.mock import patch

        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_dir = mgr.create_engagement_dir("eng-fail-purge", "Test")
        (eng_dir / "raw-output" / "data.json").write_text("{}", encoding="utf-8")

        with (
            patch.object(shutil_mod, "rmtree", side_effect=OSError("disk full")),
            pytest.raises(PersistenceError),
        ):
            mgr.purge("eng-fail-purge", operator="rick")

        # Manifest must exist despite rmtree failure
        manifests = list(audit_dir.glob("purge-eng-fail-purge-*.json"))
        assert len(manifests) == 1
        data = json.loads(manifests[0].read_text())
        assert "rmtree_error" in data

    def test_purge_gdpr_order_manifest_written_before_deletion(
        self, purge_mgr: ArtifactManager
    ) -> None:
        """Verify manifest records pre-deletion inventory."""
        manifest = purge_mgr.purge("eng-purge", operator="rick")
        # Engagement dir gone
        with pytest.raises(PersistenceError):
            purge_mgr.get_engagement_dir("eng-purge")
        # Manifest records the pre-deletion inventory
        assert manifest["file_count"] > 0
        assert len(manifest["files_deleted"]) == manifest["file_count"]

    def test_purge_directory_with_only_subdirs_raises(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_dir = mgr.create_engagement_dir("eng-empty-purge", "Test")
        # Remove all files but keep subdirectories
        for f in eng_dir.rglob("*"):
            if f.is_file():
                f.unlink()
        with pytest.raises(PersistenceError, match="empty"):
            mgr.purge("eng-empty-purge")


def _make_raw_output(tool: ToolSource = ToolSource.SCUBAGEAR) -> RawToolOutput:
    return RawToolOutput(
        tool=tool,
        schema_version="1.0.0",
        timestamp=datetime(2026, 3, 30, 12, 0, 0, tzinfo=UTC),
        file_manifest={"TestResults.json": "utf-8"},
        execution_metadata={"duration": 42.0},
    )


def _make_adapter_result(
    tool: ToolSource = ToolSource.SCUBAGEAR,
    *,
    success: bool = True,
) -> AdapterResult:
    return AdapterResult(
        adapter_name=tool.value,
        status=AdapterRunStatus.SUCCESS if success else AdapterRunStatus.FAILED,
        raw_output=_make_raw_output(tool) if success else None,
        error=None if success else "boom",
        duration_seconds=1.0,
    )


class TestSaveRawOutputs:
    @pytest.fixture
    def artifact_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        return ArtifactManager(engagements_root=engagements_root)

    def test_creates_dir_and_writes_manifest(self, artifact_mgr: ArtifactManager) -> None:
        results = [_make_adapter_result(ToolSource.SCUBAGEAR)]
        raw_dir = artifact_mgr.save_raw_outputs("eng-001", "Acme", results)

        assert raw_dir.exists()
        manifest = raw_dir / "scubagear.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        assert data["tool"] == "ScubaGear"
        assert data["schema_version"] == "1.0.0"

    def test_multiple_adapters(self, artifact_mgr: ArtifactManager) -> None:
        results = [
            _make_adapter_result(ToolSource.SCUBAGEAR),
            _make_adapter_result(ToolSource.MAESTER),
        ]
        raw_dir = artifact_mgr.save_raw_outputs("eng-002", "Acme", results)

        assert (raw_dir / "scubagear.json").exists()
        assert (raw_dir / "maester.json").exists()

    def test_skips_failed_adapters(self, artifact_mgr: ArtifactManager) -> None:
        results = [
            _make_adapter_result(ToolSource.SCUBAGEAR, success=True),
            _make_adapter_result(ToolSource.MAESTER, success=False),
        ]
        raw_dir = artifact_mgr.save_raw_outputs("eng-003", "Acme", results)

        assert (raw_dir / "scubagear.json").exists()
        assert not (raw_dir / "maester.json").exists()

    def test_overwrites_existing_on_rerun(self, artifact_mgr: ArtifactManager) -> None:
        results = [_make_adapter_result(ToolSource.SCUBAGEAR)]
        artifact_mgr.save_raw_outputs("eng-004", "Acme", results)

        # Second save with different metadata
        new_raw = _make_raw_output(ToolSource.SCUBAGEAR)
        new_raw.execution_metadata["duration"] = 99.0
        new_result = AdapterResult(
            adapter_name="ScubaGear",
            status=AdapterRunStatus.SUCCESS,
            raw_output=new_raw,
            duration_seconds=2.0,
        )
        raw_dir = artifact_mgr.save_raw_outputs("eng-004", "Acme", [new_result])

        data = json.loads((raw_dir / "scubagear.json").read_text(encoding="utf-8"))
        assert data["execution_metadata"]["duration"] == 99.0

    def test_round_trip_with_load_raw_outputs(self, artifact_mgr: ArtifactManager) -> None:
        """Verify written manifests can be loaded by replay.load_raw_outputs()."""
        from gxassessms.pipeline.replay import load_raw_outputs

        results = [
            _make_adapter_result(ToolSource.SCUBAGEAR),
            _make_adapter_result(ToolSource.MAESTER),
        ]
        artifact_mgr.save_raw_outputs("eng-005", "Acme", results)
        eng_dir = artifact_mgr.get_engagement_dir("eng-005")

        loaded = load_raw_outputs(eng_dir)
        assert len(loaded) == 2
        tool_names = {r.tool for r in loaded}
        assert tool_names == {ToolSource.SCUBAGEAR, ToolSource.MAESTER}

    def test_empty_results_writes_nothing(self, artifact_mgr: ArtifactManager) -> None:
        raw_dir = artifact_mgr.save_raw_outputs("eng-006", "Acme", [])
        assert raw_dir.exists()
        assert list(raw_dir.glob("*.json")) == []

    def test_uses_existing_engagement_dir(self, artifact_mgr: ArtifactManager) -> None:
        artifact_mgr.create_engagement_dir("eng-007", "Acme")
        results = [_make_adapter_result(ToolSource.SCUBAGEAR)]
        raw_dir = artifact_mgr.save_raw_outputs("eng-007", "Acme", results)
        assert (raw_dir / "scubagear.json").exists()

    def test_clears_stale_files_on_rerun(self, artifact_mgr: ArtifactManager) -> None:
        """Rerun should remove old manifests not in the current result set."""
        # Run 1: scubagear succeeds
        result_1 = _make_adapter_result(ToolSource.SCUBAGEAR)
        artifact_mgr.save_raw_outputs("eng-1", "Test Corp", [result_1])

        raw_dir = artifact_mgr.get_engagement_dir("eng-1") / "raw-output"
        assert (raw_dir / "scubagear.json").exists()

        # Run 2: only maester succeeds (scubagear failed, not in results)
        result_2 = _make_adapter_result(ToolSource.MAESTER)
        artifact_mgr.save_raw_outputs("eng-1", "Test Corp", [result_2])

        # Stale scubagear.json should be gone
        assert not (raw_dir / "scubagear.json").exists()
        assert (raw_dir / "maester.json").exists()
