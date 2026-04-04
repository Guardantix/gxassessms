"""Tests for file artifact storage, archive/restore/purge."""

import hashlib as _hashlib
import json
import sys as _sys
from datetime import UTC, datetime
from pathlib import Path

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
