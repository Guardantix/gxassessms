"""Tests for file artifact storage, archive/restore/purge."""

import json
from pathlib import Path

import pytest

from gxassessms.core.contracts.errors import PersistenceError
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
        assert archive_path.suffix == ".gz" or ".tar" in archive_path.name

    def test_archive_removes_raw_output(self, populated_artifact_mgr: ArtifactManager) -> None:
        populated_artifact_mgr.archive("eng-archive")
        eng_dir = populated_artifact_mgr.get_engagement_dir("eng-archive")
        raw_dir = eng_dir / "raw-output"
        # Raw output should be removed after archive
        scuba_dir = raw_dir / "scubagear"
        assert not scuba_dir.exists() or not any(scuba_dir.iterdir())

    def test_restore_recreates_files(self, populated_artifact_mgr: ArtifactManager) -> None:
        populated_artifact_mgr.archive("eng-archive")
        populated_artifact_mgr.restore("eng-archive")
        eng_dir = populated_artifact_mgr.get_engagement_dir("eng-archive")
        restored_file = eng_dir / "raw-output" / "scubagear" / "TestResults.json"
        assert restored_file.exists()
        assert json.loads(restored_file.read_text()) == {"test": True}

    def test_restore_nonexistent_archive_raises(
        self, populated_artifact_mgr: ArtifactManager
    ) -> None:
        with pytest.raises(PersistenceError, match="archive"):
            populated_artifact_mgr.restore("eng-no-archive")


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
