"""Tests for file artifact storage, archive/restore/purge."""

import hashlib as _hashlib
import json
import os as _os
import sys as _sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import (
    CollectedArtifact,
    CollectionOutput,
    CollectionResult,
)
from gxassessms.persistence.artifacts import (
    ArtifactManager,
    _sanitize_slug,
    _validate_path_within_root,
)
from gxassessms.pipeline.confinement import LoadedManifest


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
        eng_dir = mgr.create_engagement_dir("eng-empty", "Test")
        # Remove subdirs so raw-output is truly empty
        import shutil as _shutil

        _shutil.rmtree(eng_dir / "raw-output")
        (eng_dir / "raw-output").mkdir()
        with pytest.raises(PersistenceError, match="No raw output"):
            mgr.archive("eng-empty")

    def test_archive_on_scaffolding_only_raises(self, tmp_path: Path) -> None:
        """Scaffolding subdirs (manifests/, artifacts/) without files should not be archiveable."""
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        mgr = ArtifactManager(engagements_root=engagements_root)
        # create_engagement_dir creates manifests/ and artifacts/ subdirs
        mgr.create_engagement_dir("eng-scaffold", "Test")
        with pytest.raises(PersistenceError, match="No raw output"):
            mgr.archive("eng-scaffold")

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
        (eng_dir / "raw-output" / "scubagear").mkdir(parents=True, exist_ok=True)
        (eng_dir / "raw-output" / "scubagear" / "results.json").write_text("{}", encoding="utf-8")
        (eng_dir / "reports" / "report.docx").write_bytes(b"fake")
        (eng_dir / "config.yaml").write_text("client: PurgeClient", encoding="utf-8")
        return mgr

    def test_purge_writes_audit_manifest(self, purge_mgr: ArtifactManager) -> None:
        manifest = purge_mgr.purge("eng-purge", operator="rick")
        assert manifest["engagement_id"] == "eng-purge"
        assert manifest["operator"] == "rick"
        assert manifest["action"] == "purge"
        assert "timestamp" in manifest
        assert "hostname" in manifest
        assert "os_user" in manifest
        assert "pid" in manifest
        assert "files_deleted" in manifest
        assert len(manifest["files_deleted"]) > 0

    def test_purge_writes_manifest_to_audit_dir(self, purge_mgr: ArtifactManager) -> None:
        purge_mgr.purge("eng-purge", operator="rick")
        audit_files = list(purge_mgr._audit_dir.glob("purge-eng-purge-*.json"))
        assert len(audit_files) == 1
        manifest_data = json.loads(audit_files[0].read_text(encoding="utf-8"))
        assert manifest_data["engagement_id"] == "eng-purge"
        assert manifest_data["action"] == "purge"

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
        data = json.loads(manifests[0].read_text(encoding="utf-8"))
        assert "rmtree_error" in data
        # Enriched fields should survive the rewrite
        assert "hostname" in data
        assert data["action"] == "purge"

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


def _sha256(content: bytes) -> str:
    return _hashlib.sha256(content).hexdigest()


def _make_collection_result(
    tmp_path: Path,
    tool: ToolSource = ToolSource.SCUBAGEAR,
    slug: str = "scubagear",
    filename: str = "ScubaResults.json",
    content: bytes = b'{"Results": {}}',
) -> CollectionResult:
    """Create a CollectionResult with a real source file."""
    source_file = tmp_path / "source" / slug / filename
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_bytes(content)
    sha = _sha256(content)
    co = CollectionOutput(
        tool=tool,
        tool_slug=slug,
        schema_version="1.0.0",
        timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
        artifacts=[
            CollectedArtifact(
                source_path=str(source_file),
                target_relpath=f"{slug}/{filename}",
                encoding="utf-8",
                sha256=sha,
            ),
        ],
        execution_metadata={},
    )
    return CollectionResult(
        adapter_name=slug,
        status=AdapterRunStatus.SUCCESS,
        collection_output=co,
        duration_seconds=1.0,
    )


class TestSaveRawOutputsNew:
    @pytest.fixture
    def artifact_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        return ArtifactManager(engagements_root=engagements_root)

    def test_creates_manifests_and_artifacts_dirs(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        cr = _make_collection_result(tmp_path)
        result = artifact_mgr.save_raw_outputs("eng-001", "Acme", [cr])
        assert len(result) == 1
        eng_dir = artifact_mgr.get_engagement_dir("eng-001")
        assert (eng_dir / "raw-output" / "manifests" / "scubagear.json").exists()
        assert (eng_dir / "raw-output" / "artifacts" / "scubagear" / "ScubaResults.json").exists()

    def test_returns_loaded_manifests(self, artifact_mgr: ArtifactManager, tmp_path: Path) -> None:
        cr = _make_collection_result(tmp_path)
        result = artifact_mgr.save_raw_outputs("eng-002", "Acme", [cr])
        assert len(result) == 1
        assert isinstance(result[0], LoadedManifest)
        assert result[0].raw_output.tool_slug == "scubagear"

    def test_artifact_content_matches_source(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        content = b'{"test": "data"}'
        cr = _make_collection_result(tmp_path, content=content)
        artifact_mgr.save_raw_outputs("eng-003", "Acme", [cr])
        eng_dir = artifact_mgr.get_engagement_dir("eng-003")
        copied = eng_dir / "raw-output" / "artifacts" / "scubagear" / "ScubaResults.json"
        assert copied.read_bytes() == content

    def test_skips_failed_collection_results(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        good = _make_collection_result(tmp_path)
        bad = CollectionResult(
            adapter_name="maester",
            status=AdapterRunStatus.FAILED,
            error="PowerShell timed out",
            duration_seconds=0.0,
        )
        result = artifact_mgr.save_raw_outputs("eng-004", "Acme", [good, bad])
        assert len(result) == 1
        assert result[0].raw_output.tool_slug == "scubagear"

    def test_execution_metadata_allowlist(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Only allowlisted keys survive persistence."""
        source_file = tmp_path / "source" / "scubagear" / "results.json"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        content = b"{}"
        source_file.write_bytes(content)
        sha = _sha256(content)

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path=str(source_file),
                    target_relpath="scubagear/results.json",
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={
                "modules": ["AAD"],
                "output_dir": "C:\\temp",  # not allowlisted
                "exit_code": 0,  # not allowlisted
            },
        )
        cr = CollectionResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.SUCCESS,
            collection_output=co,
            duration_seconds=1.0,
        )
        result = artifact_mgr.save_raw_outputs("eng-005", "Acme", [cr])
        meta = result[0].raw_output.execution_metadata
        assert "modules" in meta
        assert "output_dir" not in meta
        assert "exit_code" not in meta

    def test_rejects_source_modified_after_collection(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Source file changed between collect and save -> rejected."""
        cr = _make_collection_result(tmp_path)
        # Tamper with source file after CollectionResult was created
        source_path = cr.collection_output.artifacts[0].source_path
        Path(source_path).write_bytes(b"tampered content")
        with pytest.raises(PersistenceError, match="hash"):
            artifact_mgr.save_raw_outputs("eng-006", "Acme", [cr])

    def test_rejects_duplicate_storage_slug(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        cr1 = _make_collection_result(tmp_path, slug="scubagear", filename="a.json")
        cr2 = _make_collection_result(tmp_path, slug="scubagear", filename="b.json")
        with pytest.raises(PersistenceError, match=r"[Dd]uplicate"):
            artifact_mgr.save_raw_outputs("eng-007", "Acme", [cr1, cr2])

    def test_rejects_symlink_source(self, artifact_mgr: ArtifactManager, tmp_path: Path) -> None:
        """Source file that is a symlink -> rejected."""
        real = tmp_path / "source" / "real.json"
        real.parent.mkdir(parents=True, exist_ok=True)
        real.write_bytes(b"{}")
        link = tmp_path / "source" / "link.json"
        link.symlink_to(real)
        sha = _sha256(b"{}")

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path=str(link),
                    target_relpath="scubagear/link.json",
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={},
        )
        cr = CollectionResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.SUCCESS,
            collection_output=co,
            duration_seconds=1.0,
        )
        with pytest.raises(PersistenceError, match="symlink"):
            artifact_mgr.save_raw_outputs("eng-009", "Acme", [cr])

    def test_create_engagement_dir_has_subdirs(self, artifact_mgr: ArtifactManager) -> None:
        eng_dir = artifact_mgr.create_engagement_dir("eng-010", "Acme")
        assert (eng_dir / "raw-output" / "manifests").exists()
        assert (eng_dir / "raw-output" / "artifacts").exists()
        assert (eng_dir / "reports").exists()

    def test_source_mode_is_collected(self, artifact_mgr: ArtifactManager, tmp_path: Path) -> None:
        """save_raw_outputs produces manifests with source_mode='collected'."""
        cr = _make_collection_result(tmp_path)
        result = artifact_mgr.save_raw_outputs("eng-smode", "Acme", [cr])
        assert result[0].raw_output.source_mode == "collected"


# ---------------------------------------------------------------------------
# Security hardening tests (issues #40 and #36)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_sys.platform == "win32", reason="POSIX permissions only")
class TestPermissionHardening:
    @pytest.fixture
    def artifact_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        return ArtifactManager(engagements_root=engagements_root)

    def test_create_engagement_dir_restrictive_permissions(
        self, artifact_mgr: ArtifactManager
    ) -> None:
        eng_dir = artifact_mgr.create_engagement_dir("eng-perm", "Acme")
        assert eng_dir.stat().st_mode & 0o777 == 0o700
        assert (eng_dir / "raw-output").stat().st_mode & 0o777 == 0o700
        assert (eng_dir / "reports").stat().st_mode & 0o777 == 0o700

    def test_audit_dir_restrictive_permissions(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        # Do NOT pre-create audit_dir -- purge should create it via secure_mkdir
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_dir = mgr.create_engagement_dir("eng-audit-perm", "Test")
        (eng_dir / "raw-output" / "data.json").write_text("{}", encoding="utf-8")
        mgr.purge("eng-audit-perm", operator="test")
        assert audit_dir.stat().st_mode & 0o777 == 0o700


class TestLifecycleAudit:
    @pytest.fixture
    def populated_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_dir = mgr.create_engagement_dir("eng-lifecycle", "Acme")
        raw_dir = eng_dir / "raw-output" / "scubagear"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "TestResults.json").write_text('{"test": true}', encoding="utf-8")
        return mgr

    def test_archive_writes_audit_manifest(self, populated_mgr: ArtifactManager) -> None:
        populated_mgr.archive("eng-lifecycle", operator="rick")
        audit_files = list(populated_mgr._audit_dir.glob("archive-eng-lifecycle-*.json"))
        assert len(audit_files) == 1
        data = json.loads(audit_files[0].read_text(encoding="utf-8"))
        assert data["action"] == "archive"

    def test_archive_audit_contains_context(self, populated_mgr: ArtifactManager) -> None:
        populated_mgr.archive("eng-lifecycle", operator="rick")
        audit_files = list(populated_mgr._audit_dir.glob("archive-*.json"))
        data = json.loads(audit_files[0].read_text(encoding="utf-8"))
        assert data["operator"] == "rick"
        assert "hostname" in data
        assert "os_user" in data
        assert "pid" in data
        assert "engagement_dir" in data
        assert "archive_path" in data

    def test_archive_audit_failure_does_not_fail_archive(
        self, populated_mgr: ArtifactManager
    ) -> None:
        from unittest.mock import patch

        with patch.object(
            ArtifactManager, "_write_lifecycle_audit", side_effect=OSError("disk full")
        ):
            result = populated_mgr.archive("eng-lifecycle")
        # Archive should still succeed
        assert result.exists()
        assert result.name == "raw-output.tar.gz"

    def test_archive_audit_dir_created_if_missing(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "fresh-audit"
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_dir = mgr.create_engagement_dir("eng-fresh", "Test")
        raw_dir = eng_dir / "raw-output" / "tool"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "data.json").write_text("{}", encoding="utf-8")
        mgr.archive("eng-fresh", operator="test")
        assert audit_dir.exists()
        assert len(list(audit_dir.glob("archive-*.json"))) == 1

    def test_restore_writes_audit_manifest(self, populated_mgr: ArtifactManager) -> None:
        populated_mgr.archive("eng-lifecycle", operator="rick")
        populated_mgr.restore("eng-lifecycle", operator="rick")
        audit_files = list(populated_mgr._audit_dir.glob("restore-eng-lifecycle-*.json"))
        assert len(audit_files) == 1
        data = json.loads(audit_files[0].read_text(encoding="utf-8"))
        assert data["action"] == "restore"
        assert "hostname" in data
        assert "engagement_dir" in data

    def test_purge_audit_contains_enriched_context(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_dir = mgr.create_engagement_dir("eng-ctx", "Test")
        (eng_dir / "raw-output" / "data.json").write_text("{}", encoding="utf-8")
        manifest = mgr.purge("eng-ctx", operator="admin")
        assert manifest["action"] == "purge"
        assert manifest["operator"] == "admin"
        assert "hostname" in manifest
        assert "os_user" in manifest
        assert "pid" in manifest
        assert "platform" in manifest


# ---------------------------------------------------------------------------
# Task 9: save_ingested_raw_output
# ---------------------------------------------------------------------------


def _make_collection_output(
    tmp_path: Path,
    slug: str = "scubagear",
    filename: str = "ScubaResults.json",
    content: bytes = b'{"Results": {}}',
    tool: ToolSource = ToolSource.SCUBAGEAR,
) -> CollectionOutput:
    """Create a CollectionOutput backed by a real temp file."""
    from gxassessms.core.domain.models import CollectedArtifact, CollectionOutput

    source_file = tmp_path / "ingest-src" / slug / filename
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_bytes(content)
    sha = _sha256(content)
    return CollectionOutput(
        tool=tool,
        tool_slug=slug,
        schema_version="1.0.0",
        timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
        artifacts=[
            CollectedArtifact(
                source_path=str(source_file),
                target_relpath=f"{slug}/{filename}",
                encoding="utf-8",
                sha256=sha,
            ),
        ],
        execution_metadata={},
    )


def _make_ingest_provenance(tmp_path: Path, slug: str = "scubagear") -> Any:
    """Build an IngestProvenance pointing at tmp_path as source."""
    from gxassessms.core.domain.models import IngestProvenance

    return IngestProvenance(
        source_path=str(tmp_path / "ingest-src" / slug),
        ingested_at=datetime(2026, 4, 12, 9, 0, 0, tzinfo=UTC),
        ingested_by="human:rick",
        replaced=False,
    )


class TestSaveIngestedRawOutput:
    """Spec Section 4.1-4.4: save_ingested_raw_output."""

    @pytest.fixture
    def artifact_mgr(self, tmp_path: Path) -> ArtifactManager:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        return ArtifactManager(engagements_root=engagements_root)

    def test_happy_path_fresh_ingest(self, artifact_mgr: ArtifactManager, tmp_path: Path) -> None:
        """Fresh ingest writes manifest and artifacts atomically."""
        artifact_mgr.create_engagement_dir("eng-ingest-01", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        result = artifact_mgr.save_ingested_raw_output("eng-ingest-01", co, ingest_provenance=prov)

        assert isinstance(result, LoadedManifest)
        assert result.raw_output.source_mode == "ingested"
        assert result.raw_output.manifest_version == "1.1.0"
        assert result.raw_output.tool_slug == "scubagear"

        # Files on disk
        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-01")
        raw_dir = eng_dir / "raw-output"
        assert (raw_dir / "manifests" / "scubagear.json").exists()
        assert (raw_dir / "artifacts" / "scubagear" / "ScubaResults.json").exists()

        # source_path on the returned LoadedManifest
        assert result.source_path == raw_dir / "manifests" / "scubagear.json"

    def test_manifest_content_correct(self, artifact_mgr: ArtifactManager, tmp_path: Path) -> None:
        """Written manifest round-trips correctly."""
        artifact_mgr.create_engagement_dir("eng-ingest-02", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        artifact_mgr.save_ingested_raw_output("eng-ingest-02", co, ingest_provenance=prov)

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-02")
        manifest_json = (eng_dir / "raw-output" / "manifests" / "scubagear.json").read_text(
            encoding="utf-8"
        )
        data = json.loads(manifest_json)
        assert data["source_mode"] == "ingested"
        assert data["manifest_version"] == "1.1.0"
        assert data["ingest_provenance"]["ingested_by"] == "human:rick"
        assert "scubagear/ScubaResults.json" in data["file_manifest"]

    def test_artifact_content_matches_source(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Artifact bytes are identical after copy."""
        content = b'{"answer": 42}'
        artifact_mgr.create_engagement_dir("eng-ingest-03", "Acme")
        co = _make_collection_output(tmp_path, content=content)
        prov = _make_ingest_provenance(tmp_path)

        artifact_mgr.save_ingested_raw_output("eng-ingest-03", co, ingest_provenance=prov)

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-03")
        copied = eng_dir / "raw-output" / "artifacts" / "scubagear" / "ScubaResults.json"
        assert copied.read_bytes() == content

    def test_replaced_false_on_fresh_ingest(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """ingest_provenance.replaced is False when no prior data exists."""
        artifact_mgr.create_engagement_dir("eng-ingest-04", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        result = artifact_mgr.save_ingested_raw_output("eng-ingest-04", co, ingest_provenance=prov)

        assert result.raw_output.ingest_provenance.replaced is False

    def test_conflict_without_replace_raises(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Ingest when data already exists without replace=True -> PersistenceError."""
        artifact_mgr.create_engagement_dir("eng-ingest-05", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        # First ingest succeeds
        artifact_mgr.save_ingested_raw_output("eng-ingest-05", co, ingest_provenance=prov)

        # Second ingest without replace raises
        co2 = _make_collection_output(tmp_path, content=b'{"v": 2}')
        prov2 = _make_ingest_provenance(tmp_path)
        with pytest.raises(PersistenceError, match="already exists"):
            artifact_mgr.save_ingested_raw_output("eng-ingest-05", co2, ingest_provenance=prov2)

    def test_replace_path_overwrites_data(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """replace=True overwrites existing data and sets replaced=True in provenance."""
        artifact_mgr.create_engagement_dir("eng-ingest-06", "Acme")
        co = _make_collection_output(tmp_path, filename="v1.json", content=b'{"v": 1}')
        prov = _make_ingest_provenance(tmp_path)
        artifact_mgr.save_ingested_raw_output("eng-ingest-06", co, ingest_provenance=prov)

        # Second ingest with replace=True, different content
        new_content = b'{"v": 2}'
        co2 = _make_collection_output(tmp_path, filename="v1.json", content=new_content)
        prov2 = _make_ingest_provenance(tmp_path)
        result = artifact_mgr.save_ingested_raw_output(
            "eng-ingest-06", co2, ingest_provenance=prov2, replace=True
        )

        assert result.raw_output.ingest_provenance.replaced is True

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-06")
        artifact_path = eng_dir / "raw-output" / "artifacts" / "scubagear" / "v1.json"
        assert artifact_path.read_bytes() == new_content

    def test_replace_cleans_up_old_manifest_file(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """After a successful replace, the old manifest file must not remain.

        The .old-manifest-* aside is a JSON file, not a directory.  A prior
        bug used shutil.rmtree() for the cleanup which silently skipped it
        (ignore_errors=True), leaving stale manifests to accumulate.
        """
        artifact_mgr.create_engagement_dir("eng-ingest-replace-clean", "Acme")
        co = _make_collection_output(tmp_path, filename="v1.json", content=b'{"v": 1}')
        prov = _make_ingest_provenance(tmp_path)
        artifact_mgr.save_ingested_raw_output(
            "eng-ingest-replace-clean", co, ingest_provenance=prov
        )

        co2 = _make_collection_output(tmp_path, filename="v1.json", content=b'{"v": 2}')
        prov2 = _make_ingest_provenance(tmp_path)
        artifact_mgr.save_ingested_raw_output(
            "eng-ingest-replace-clean", co2, ingest_provenance=prov2, replace=True
        )

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-replace-clean")
        raw_dir = eng_dir / "raw-output"
        leftovers = [p for p in raw_dir.iterdir() if p.name.startswith(".old-manifest-")]
        assert leftovers == [], f"Old manifest files not cleaned up: {leftovers}"

    def test_nonexistent_engagement_raises(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Engagement must exist before ingest."""
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)
        with pytest.raises(PersistenceError):
            artifact_mgr.save_ingested_raw_output("eng-does-not-exist", co, ingest_provenance=prov)

    def test_no_staging_dirs_left_on_success(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Staging directory is cleaned up after successful commit."""
        artifact_mgr.create_engagement_dir("eng-ingest-07", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        artifact_mgr.save_ingested_raw_output("eng-ingest-07", co, ingest_provenance=prov)

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-07")
        raw_dir = eng_dir / "raw-output"
        staging = [d for d in raw_dir.iterdir() if d.name.startswith(".ingest-staging-")]
        assert staging == []

    def test_rejects_symlink_source(self, artifact_mgr: ArtifactManager, tmp_path: Path) -> None:
        """Symlinked source file must be rejected."""
        artifact_mgr.create_engagement_dir("eng-ingest-08", "Acme")

        # Create a real file and a symlink pointing to it
        real_file = tmp_path / "real-data" / "results.json"
        real_file.parent.mkdir(parents=True, exist_ok=True)
        content = b'{"results": []}'
        real_file.write_bytes(content)
        sha = _sha256(content)

        symlink_dir = tmp_path / "ingest-src" / "scubagear"
        symlink_dir.mkdir(parents=True, exist_ok=True)
        symlink_file = symlink_dir / "ScubaResults.json"
        symlink_file.symlink_to(real_file)

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path=str(symlink_file),
                    target_relpath="scubagear/ScubaResults.json",
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={},
        )
        prov = _make_ingest_provenance(tmp_path)

        with pytest.raises(PersistenceError, match="symlink"):
            artifact_mgr.save_ingested_raw_output("eng-ingest-08", co, ingest_provenance=prov)

    def test_copy_corruption_raises_and_cleans_staging(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Mismatching copy hash -> PersistenceError; no staging dirs remain."""
        from unittest.mock import patch as mock_patch

        artifact_mgr.create_engagement_dir("eng-ingest-corrupt", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        with (
            mock_patch("gxassessms.core.hashing.sha256_file", return_value="0" * 64),
            pytest.raises(PersistenceError, match="corruption"),
        ):
            artifact_mgr.save_ingested_raw_output("eng-ingest-corrupt", co, ingest_provenance=prov)

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-corrupt")
        raw_dir = eng_dir / "raw-output"
        staging = [d for d in raw_dir.iterdir() if d.name.startswith(".ingest-staging-")]
        assert staging == []

    def test_rejects_relative_source_path(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """CollectionOutput with relative source_path -> PersistenceError."""
        from gxassessms.core.domain.models import CollectedArtifact

        artifact_mgr.create_engagement_dir("eng-ingest-relpath", "Acme")
        content = b'{"data": 1}'
        sha = _sha256(content)
        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path="relative/path/results.json",
                    target_relpath="scubagear/results.json",
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={},
        )
        prov = _make_ingest_provenance(tmp_path)
        with pytest.raises(PersistenceError, match="not absolute"):
            artifact_mgr.save_ingested_raw_output("eng-ingest-relpath", co, ingest_provenance=prov)

    def test_rejects_traversal_in_target_relpath(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Ingest with path traversal in target_relpath raises PersistenceError before any copy."""
        from gxassessms.core.domain.models import CollectedArtifact

        artifact_mgr.create_engagement_dir("eng-ingest-trav", "Acme")
        content = b'{"data": 1}'
        sha = _sha256(content)
        source_file = tmp_path / "src" / "results.json"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_bytes(content)

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path=str(source_file),
                    target_relpath="scubagear/../../etc/passwd",
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={},
        )
        prov = _make_ingest_provenance(tmp_path)
        with pytest.raises(PersistenceError, match="Invalid target_relpath"):
            artifact_mgr.save_ingested_raw_output("eng-ingest-trav", co, ingest_provenance=prov)

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-trav")
        assert not (eng_dir / "raw-output" / "artifacts" / "scubagear").exists()

    def test_rejects_target_relpath_with_wrong_slug_prefix(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """target_relpath starting with a different slug raises PersistenceError."""
        from gxassessms.core.domain.models import CollectedArtifact

        artifact_mgr.create_engagement_dir("eng-ingest-wrongslug", "Acme")
        content = b'{"data": 1}'
        sha = _sha256(content)
        source_file = tmp_path / "src2" / "results.json"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_bytes(content)

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path=str(source_file),
                    target_relpath="maester/results.json",  # wrong slug prefix
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={},
        )
        prov = _make_ingest_provenance(tmp_path)
        with pytest.raises(PersistenceError, match="does not start with scubagear/"):
            artifact_mgr.save_ingested_raw_output(
                "eng-ingest-wrongslug", co, ingest_provenance=prov
            )

    def test_phase3_failure_cleans_staging_and_raises(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Phase 3 rename failure -> PersistenceError; staging dir cleaned up."""
        from unittest.mock import patch as mock_patch

        artifact_mgr.create_engagement_dir("eng-ingest-p3fail", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        original_rename = Path.rename

        def fail_on_commit_rename(self_path: Path, target: Path) -> Path:
            # Fail when Phase 3 renames staged artifacts to final location.
            # Phase 3 renames: staging/.../artifacts/slug -> raw-output/artifacts/slug
            target = Path(target)
            if (
                ".ingest-staging-" in str(self_path)
                and target.name == "scubagear"
                and target.parent.name == "artifacts"
            ):
                raise OSError("simulated commit failure")
            return original_rename(self_path, target)

        with (
            mock_patch.object(Path, "rename", fail_on_commit_rename),
            pytest.raises(PersistenceError, match="Failed to commit"),
        ):
            artifact_mgr.save_ingested_raw_output("eng-ingest-p3fail", co, ingest_provenance=prov)

        eng_dir = artifact_mgr.get_engagement_dir("eng-ingest-p3fail")
        raw_dir = eng_dir / "raw-output"
        staging = [d for d in raw_dir.iterdir() if d.name.startswith(".ingest-staging-")]
        assert staging == []

    def test_fresh_ingest_rollback_removes_committed_artifacts_on_manifest_rename_failure(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Fresh ingest Phase 3 manifest rename failure: rollback removes committed artifacts."""
        from unittest.mock import patch as mock_patch

        artifact_mgr.create_engagement_dir("eng-p3fail-mfail", "Acme")
        co = _make_collection_output(tmp_path)
        prov = _make_ingest_provenance(tmp_path)

        original_rename = Path.rename

        def fail_on_manifest_commit(self_path: Path, target: Path) -> Path:
            # Fail only when the staging manifest is renamed to its final location
            target = Path(target)
            if (
                ".ingest-staging-" in str(self_path)
                and target.name == "scubagear.json"
                and target.parent.name == "manifests"
            ):
                raise OSError("simulated manifest rename failure")
            return original_rename(self_path, target)

        with (
            mock_patch.object(Path, "rename", fail_on_manifest_commit),
            pytest.raises(PersistenceError, match="Failed to commit"),
        ):
            artifact_mgr.save_ingested_raw_output("eng-p3fail-mfail", co, ingest_provenance=prov)

        eng_dir = artifact_mgr.get_engagement_dir("eng-p3fail-mfail")
        raw_dir = eng_dir / "raw-output"
        # Rollback must have removed newly-committed artifacts
        assert not (raw_dir / "artifacts" / "scubagear").exists()
        # No staging debris
        staging = [d for d in raw_dir.iterdir() if d.name.startswith(".ingest-staging-")]
        assert staging == []

    def test_replace_ingest_rollback_restores_old_data_on_manifest_rename_failure(
        self, artifact_mgr: ArtifactManager, tmp_path: Path
    ) -> None:
        """Replace ingest: Phase 3 manifest rename failure restores prior artifacts and manifest."""
        from unittest.mock import patch as mock_patch

        artifact_mgr.create_engagement_dir("eng-p3fail-replace", "Acme")

        # First ingest (fresh, succeeds)
        co1 = _make_collection_output(tmp_path, content=b'{"version": 1}')
        prov1 = _make_ingest_provenance(tmp_path)
        artifact_mgr.save_ingested_raw_output("eng-p3fail-replace", co1, ingest_provenance=prov1)

        eng_dir = artifact_mgr.get_engagement_dir("eng-p3fail-replace")
        raw_dir = eng_dir / "raw-output"
        old_artifact = raw_dir / "artifacts" / "scubagear" / "ScubaResults.json"
        assert old_artifact.read_bytes() == b'{"version": 1}'

        # Second ingest (replace), fails on manifest rename
        co2 = _make_collection_output(tmp_path, content=b'{"version": 2}')
        prov2 = _make_ingest_provenance(tmp_path)
        original_rename = Path.rename

        def fail_on_manifest_commit(self_path: Path, target: Path) -> Path:
            target = Path(target)
            if (
                ".ingest-staging-" in str(self_path)
                and target.name == "scubagear.json"
                and target.parent.name == "manifests"
            ):
                raise OSError("simulated manifest rename failure")
            return original_rename(self_path, target)

        with (
            mock_patch.object(Path, "rename", fail_on_manifest_commit),
            pytest.raises(PersistenceError, match="Failed to commit"),
        ):
            artifact_mgr.save_ingested_raw_output(
                "eng-p3fail-replace", co2, ingest_provenance=prov2, replace=True
            )

        # Old artifacts restored -- v1 content
        assert old_artifact.read_bytes() == b'{"version": 1}'
        # Old manifest restored
        assert (raw_dir / "manifests" / "scubagear.json").exists()
        # No staging or aside debris
        for entry in raw_dir.iterdir():
            assert not entry.name.startswith(".ingest-staging-")
            assert not entry.name.startswith(".old-")

    def test_purge_audit_path_in_returned_manifest(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_dir = mgr.create_engagement_dir("eng-path", "Test")
        (eng_dir / "raw-output" / "data.json").write_text("{}", encoding="utf-8")
        manifest = mgr.purge("eng-path", operator="test")
        assert "audit_path" in manifest
        assert Path(manifest["audit_path"]).exists()

    @pytest.mark.skipif(_sys.platform == "win32", reason="POSIX permissions only")
    def test_write_lifecycle_audit_manifest_has_restrictive_permissions(
        self, tmp_path: Path
    ) -> None:
        """Audit manifest files should be written with 0o600 permissions."""
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        _, manifest_path = mgr._write_lifecycle_audit(
            "archive", "eng-perm-test", "test-operator", {}
        )
        mode = manifest_path.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_write_lifecycle_audit_rejects_crafted_engagement_id(self, tmp_path: Path) -> None:
        """Crafted engagement_id with path separators should be blocked."""
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        # Create parent dirs so resolve doesn't fail before validation
        escape_dir = audit_dir / "purge-x"
        escape_dir.mkdir()
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        # This ID contains path separators that create subdirs and then
        # traverse above audit_dir via ..
        with pytest.raises(PersistenceError, match="path traversal"):
            mgr._write_lifecycle_audit("purge", "x/../../../escape", "test", {})


class TestConfigSnapshot:
    def test_write_and_read_roundtrip(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-123"
        (tmp_path / f"client-{eng_id}").mkdir()
        snapshot = {"client_name": "Acme", "tenant_id": "t-1"}
        mgr.write_config_snapshot(eng_id, snapshot)
        assert mgr.read_config_snapshot(eng_id) == snapshot

    def test_write_overwrites_existing(self, tmp_path: Path) -> None:
        """Last-writer-wins semantics, required when re-collecting against
        an existing engagement whose YAML has been edited since creation."""
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-456"
        (tmp_path / f"client-{eng_id}").mkdir()
        mgr.write_config_snapshot(eng_id, {"v": 1})
        mgr.write_config_snapshot(eng_id, {"v": 2})
        assert mgr.read_config_snapshot(eng_id) == {"v": 2}

    def test_write_is_atomic_no_temp_leftover(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-atom"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()
        mgr.write_config_snapshot(eng_id, {"k": "v"})
        leftovers = list(eng_dir.glob(".config_snapshot.json.tmp-*"))
        assert leftovers == []

    def test_failed_replace_cleans_up_tmp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # If Path.replace() raises, the finally block must still unlink tmp.
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-failreplace"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()

        def bad_replace(self: Path, target: Path) -> Path:
            raise OSError("simulated replace failure")

        monkeypatch.setattr(Path, "replace", bad_replace)

        with pytest.raises(OSError, match="simulated"):
            mgr.write_config_snapshot(eng_id, {"k": "v"})
        leftovers = list(eng_dir.glob(".config_snapshot.json.tmp-*"))
        assert leftovers == []  # finally cleaned up even on failure

    def test_write_produces_indented_json(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-pretty"
        (tmp_path / f"client-{eng_id}").mkdir()
        path = mgr.write_config_snapshot(eng_id, {"client_name": "Acme"})
        body = path.read_text(encoding="utf-8")
        assert "\n  " in body  # 2-space indent visible on wrapped lines

    def test_read_rejects_oversized_file(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-huge"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()
        target = eng_dir / "config_snapshot.json"
        huge = {"padding": "x" * (1_500_000)}
        target.write_text(json.dumps(huge), encoding="utf-8")
        with pytest.raises(PersistenceError, match="suspiciously large"):
            mgr.read_config_snapshot(eng_id)

    def test_write_refuses_preexisting_tmp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # O_EXCL should fail if the tmp path is somehow pre-created
        # (defense against attacker planting a stale tmp file).
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-planted"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()
        # Force a deterministic uuid so we can pre-plant the tmp path.
        fixed_hex = "0123456789abcdef0123456789abcdef"  # pragma: allowlist secret

        class _FixedUUID:
            hex = fixed_hex

        monkeypatch.setattr(
            "gxassessms.persistence.artifacts.uuid.uuid4",
            lambda: _FixedUUID(),
        )
        (eng_dir / f".config_snapshot.json.tmp-{fixed_hex}").write_text("stale")
        with pytest.raises(FileExistsError):
            mgr.write_config_snapshot(eng_id, {"k": "v"})

    def test_read_missing_raises(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-789"
        (tmp_path / f"client-{eng_id}").mkdir()
        with pytest.raises(PersistenceError, match=r"No config_snapshot\.json"):
            mgr.read_config_snapshot(eng_id)

    def test_read_empty_file_raises(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-empty"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()
        (eng_dir / "config_snapshot.json").write_text("", encoding="utf-8")
        with pytest.raises(PersistenceError, match="corrupt"):
            mgr.read_config_snapshot(eng_id)

    def test_read_corrupt_json_raises(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-bad"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()
        (eng_dir / "config_snapshot.json").write_text("not-json", encoding="utf-8")
        with pytest.raises(PersistenceError, match="corrupt"):
            mgr.read_config_snapshot(eng_id)

    @pytest.mark.parametrize(
        ("payload", "description"),
        [
            ("null", "null"),
            ("[]", "list"),
            ("42", "int"),
            ("true", "bool"),
            ('"hello"', "string"),
        ],
    )
    def test_read_non_object_json_raises(
        self, tmp_path: Path, payload: str, description: str
    ) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = f"abc-{description}"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()
        (eng_dir / "config_snapshot.json").write_text(payload, encoding="utf-8")
        with pytest.raises(PersistenceError, match="not a JSON object"):
            mgr.read_config_snapshot(eng_id)

    def test_read_when_engagement_dir_missing_raises(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        with pytest.raises(PersistenceError, match="Engagement directory not found"):
            mgr.read_config_snapshot("nonexistent-id")

    @pytest.mark.skipif(_sys.platform == "win32", reason="POSIX only")
    def test_write_sets_0o600(self, tmp_path: Path) -> None:
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-perm"
        (tmp_path / f"client-{eng_id}").mkdir()
        path = mgr.write_config_snapshot(eng_id, {})
        assert oct(path.stat().st_mode & 0o777) == oct(0o600)

    @pytest.mark.skipif(_sys.platform == "win32", reason="chmod 0 blocks reads only on POSIX")
    def test_read_unreadable_file_raises_persistence_error(self, tmp_path: Path) -> None:
        if hasattr(_os, "geteuid") and _os.geteuid() == 0:
            pytest.skip("chmod 0 does not block reads when running as root")
        mgr = ArtifactManager(engagements_root=tmp_path)
        eng_id = "abc-unreadable"
        eng_dir = tmp_path / f"client-{eng_id}"
        eng_dir.mkdir()
        target = eng_dir / "config_snapshot.json"
        target.write_text('{"k": "v"}', encoding="utf-8")
        target.chmod(0o000)
        try:
            with pytest.raises(PersistenceError, match="Cannot read"):
                mgr.read_config_snapshot(eng_id)
        finally:
            target.chmod(0o600)

    def test_write_survives_archive_boundary(self, tmp_path: Path) -> None:
        # Snapshot lives outside raw-output/, so archive() (which only
        # archives raw-output/) must not touch it.
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mgr = ArtifactManager(engagements_root=engagements_root, audit_dir=audit_dir)
        eng_id = "abc-arch"
        eng_dir = engagements_root / f"client-{eng_id}"
        (eng_dir / "raw-output" / "manifests").mkdir(parents=True)
        (eng_dir / "raw-output" / "artifacts").mkdir(parents=True)
        # Archive requires at least one real file under raw-output/.
        (eng_dir / "raw-output" / "artifacts" / "results.json").write_text("{}", encoding="utf-8")
        mgr.write_config_snapshot(eng_id, {"sentinel": True})
        mgr.archive(eng_id, operator="test")
        assert (eng_dir / "config_snapshot.json").exists()
        assert mgr.read_config_snapshot(eng_id) == {"sentinel": True}
