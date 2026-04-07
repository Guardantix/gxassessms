"""Tests for confine_and_resolve() -- the replay trust boundary (spec Section 2)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from gxassessms.core.contracts.errors import ManifestConfinementError
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ArtifactRecord, RawToolOutput, ResolvedManifest
from gxassessms.pipeline.confinement import (
    LoadedManifest,
    _check_artifact_path,
    _check_artifacts_root,
    _check_manifest_identity,
    _check_tool_subtree,
    _confinement_error,
    confine_and_resolve,
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _make_adapter(
    slug: str = "scubagear",
    tool_source: ToolSource = ToolSource.SCUBAGEAR,
) -> Any:
    adapter = MagicMock()
    adapter.storage_slug = slug
    adapter.tool_source = tool_source
    return adapter


def _make_raw_output(
    tool: ToolSource = ToolSource.SCUBAGEAR,
    slug: str = "scubagear",
    manifest_version: str = "1.0.0",
    file_manifest: dict[str, ArtifactRecord] | None = None,
) -> RawToolOutput:
    if file_manifest is None:
        file_manifest = {
            f"{slug}/results.json": ArtifactRecord(
                encoding="utf-8",
                sha256="a" * 64,
            ),
        }
    return RawToolOutput(
        tool=tool,
        tool_slug=slug,
        schema_version="1.0.0",
        manifest_version=manifest_version,
        timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
        file_manifest=file_manifest,
        execution_metadata={},
    )


def _setup_artifact(
    artifacts_dir: Path, slug: str, filename: str, content: bytes = b'{"test": true}'
) -> str:
    """Create an artifact file and return its SHA-256 hash."""
    artifact_path = artifacts_dir / slug / filename
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(content)
    return _sha256(content)


class TestConfineAndResolveHappyPath:
    def test_valid_manifest_returns_resolved(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        content = b'{"Results": {}}'
        sha = _setup_artifact(artifacts_dir, "scubagear", "results.json", content)

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        adapters = [_make_adapter()]

        result = confine_and_resolve(loaded, eng_dir, adapters)
        assert len(result) == 1
        assert isinstance(result[0], ResolvedManifest)
        assert result[0].tool_slug == "scubagear"
        # Resolved paths should be absolute
        for path in result[0].file_manifest:
            assert Path(path).is_absolute()


class TestConfineAndResolveRejections:
    def test_rejects_unknown_manifest_version(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        sha = _setup_artifact(artifacts_dir, "scubagear", "results.json")

        raw = _make_raw_output(
            manifest_version="99.0.0",
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="manifest_version"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_slug_not_matching_adapter(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        sha = _setup_artifact(artifacts_dir, "scubagear", "results.json")

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="slug"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter(slug="other")])

    def test_rejects_filename_stem_slug_mismatch(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        sha = _setup_artifact(artifacts_dir, "scubagear", "results.json")

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "wrongname.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="filename"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_tool_source_mismatch(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        sha = _setup_artifact(artifacts_dir, "scubagear", "results.json")

        raw = _make_raw_output(
            tool=ToolSource.SCUBAGEAR,
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="tool"):
            confine_and_resolve(
                loaded,
                eng_dir,
                [
                    _make_adapter(slug="scubagear", tool_source=ToolSource.MAESTER),
                ],
            )

    def test_rejects_path_not_starting_with_slug(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        sha = _setup_artifact(artifacts_dir, "maester", "results.json")

        raw = _make_raw_output(
            file_manifest={
                "maester/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="does not start with"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_missing_artifact_file(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        (eng_dir / "raw-output" / "artifacts" / "scubagear").mkdir(parents=True)

        raw = _make_raw_output()  # references scubagear/results.json
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="not found"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_sha256_mismatch(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        _setup_artifact(artifacts_dir, "scubagear", "results.json", b"real content")

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(
                    encoding="utf-8",
                    sha256="b" * 64,  # wrong hash
                ),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="SHA-256"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_symlink_escape(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        scuba_dir = artifacts_dir / "scubagear"
        scuba_dir.mkdir(parents=True)

        outside = tmp_path / "outside" / "secret.json"
        outside.parent.mkdir(parents=True)
        outside.write_bytes(b"secret")
        sha = _sha256(b"secret")

        (scuba_dir / "results.json").symlink_to(outside)

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="subtree"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_symlink_to_other_tool_subtree(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        scuba_dir = artifacts_dir / "scubagear"
        scuba_dir.mkdir(parents=True)
        maester_dir = artifacts_dir / "maester"
        maester_dir.mkdir(parents=True)

        maester_file = maester_dir / "results.json"
        maester_file.write_bytes(b"maester data")
        sha = _sha256(b"maester data")

        (scuba_dir / "results.json").symlink_to(maester_file)

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="subtree"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_symlinked_tool_subtree(self, tmp_path: Path) -> None:
        """Per-slug subtree symlink pointing outside engagement must be rejected.

        Even though artifacts_root itself is real and passes its confinement
        check, a symlink at artifacts/<slug>/ redirects both tool_subtree and
        resolved paths outside the engagement together, making the
        is_relative_to check pass. The canonical-path check catches this.
        """
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        artifacts_dir.mkdir(parents=True)

        # Create real artifacts outside the engagement
        outside = tmp_path / "outside" / "scubagear"
        outside.mkdir(parents=True)
        content = b'{"Results": {}}'
        (outside / "results.json").write_bytes(content)
        sha = _sha256(content)

        # Symlink only the slug subdirectory, not artifacts_root
        (artifacts_dir / "scubagear").symlink_to(outside)

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match=r"non-canonical"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_symlinked_artifacts_root(self, tmp_path: Path) -> None:
        """Artifacts root that is a symlink pointing outside engagement must be rejected."""
        eng_dir = tmp_path / "eng"
        raw_output_dir = eng_dir / "raw-output"
        raw_output_dir.mkdir(parents=True)

        # Create real artifacts outside the engagement
        outside = tmp_path / "outside" / "artifacts"
        scuba_dir = outside / "scubagear"
        scuba_dir.mkdir(parents=True)
        content = b'{"Results": {}}'
        (scuba_dir / "results.json").write_bytes(content)
        sha = _sha256(content)

        # Symlink artifacts root to outside location
        (raw_output_dir / "artifacts").symlink_to(outside)

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="outside engagement"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_artifacts_root_symlinked_within_engagement(self, tmp_path: Path) -> None:
        """Artifacts root symlinked to another location inside the engagement.

        Even though the resolved path is within the engagement, it's not the
        canonical raw-output/artifacts path. This could let manifests reference
        files from an unintended engagement subtree.
        """
        eng_dir = tmp_path / "eng"
        raw_output_dir = eng_dir / "raw-output"
        raw_output_dir.mkdir(parents=True)

        # Create real artifacts in a non-canonical engagement subtree
        alt_dir = eng_dir / "reports" / "artifacts"
        scuba_dir = alt_dir / "scubagear"
        scuba_dir.mkdir(parents=True)
        content = b'{"Results": {}}'
        (scuba_dir / "results.json").write_bytes(content)
        sha = _sha256(content)

        # Symlink artifacts root to the non-canonical in-engagement location
        (raw_output_dir / "artifacts").symlink_to(alt_dir)

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="non-canonical"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_tool_subtree_symlinked_to_sibling(self, tmp_path: Path) -> None:
        """Per-slug subtree symlinked to a sibling tool directory.

        artifacts/scubagear/ -> artifacts/maester/ stays within the engagement
        and within artifacts_root, but it's not the canonical location for
        scubagear. This would let scubagear manifests process maester files.
        """
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"

        # Create real maester artifacts
        maester_dir = artifacts_dir / "maester"
        maester_dir.mkdir(parents=True)
        content = b'{"MaesterResults": {}}'
        (maester_dir / "results.json").write_bytes(content)
        sha = _sha256(content)

        # Symlink scubagear -> maester (sibling redirect)
        (artifacts_dir / "scubagear").symlink_to(maester_dir)

        raw = _make_raw_output(
            file_manifest={
                "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256=sha),
            },
        )
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="non-canonical"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])

    def test_rejects_directory_as_artifact(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        (artifacts_dir / "scubagear" / "results.json").mkdir(parents=True)

        raw = _make_raw_output()
        loaded = [
            LoadedManifest(
                source_path=eng_dir / "raw-output" / "manifests" / "scubagear.json",
                raw_output=raw,
            )
        ]
        with pytest.raises(ManifestConfinementError, match="file"):
            confine_and_resolve(loaded, eng_dir, [_make_adapter()])


# ---------------------------------------------------------------------------
# Direct unit tests for extracted validators
# ---------------------------------------------------------------------------


class TestConfinementErrorFactory:
    def test_returns_error_with_stage_confine(self) -> None:
        err = _confinement_error(
            message="boom",
            engagement_id="eng-1",
            tool_slug="scubagear",
            check_name="test_check",
            detail="some detail",
        )
        assert isinstance(err, ManifestConfinementError)
        assert err.stage == "confine"
        assert err.tool_slug == "scubagear"
        assert err.check_name == "test_check"
        assert err.detail == "some detail"

    def test_returned_error_is_raisable(self) -> None:
        err = _confinement_error(
            message="boom",
            engagement_id="eng-1",
            tool_slug="scubagear",
            check_name="test_check",
            detail="detail",
        )
        with pytest.raises(ManifestConfinementError, match="boom"):
            raise err


class TestCheckArtifactsRoot:
    def test_returns_resolved_root(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        artifacts_dir.mkdir(parents=True)

        result = _check_artifacts_root(artifacts_dir, eng_dir)
        assert result == artifacts_dir.resolve()
        assert result.is_absolute()

    def test_rejects_symlinked_root(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        raw_output_dir = eng_dir / "raw-output"
        raw_output_dir.mkdir(parents=True)

        outside = tmp_path / "outside" / "artifacts"
        outside.mkdir(parents=True)
        (raw_output_dir / "artifacts").symlink_to(outside)

        with pytest.raises(ManifestConfinementError) as exc_info:
            _check_artifacts_root(raw_output_dir / "artifacts", eng_dir)
        assert exc_info.value.check_name == "artifacts_root_confinement"


class TestCheckManifestIdentity:
    def _build(
        self,
        *,
        slug: str = "scubagear",
        tool: ToolSource = ToolSource.SCUBAGEAR,
        manifest_version: str = "1.0.0",
        filename_stem: str = "scubagear",
    ) -> tuple[LoadedManifest, dict[str, Any]]:
        raw = _make_raw_output(tool=tool, slug=slug, manifest_version=manifest_version)
        lm = LoadedManifest(
            source_path=Path(f"/fake/manifests/{filename_stem}.json"),
            raw_output=raw,
        )
        adapter_by_slug = {slug: _make_adapter(slug=slug, tool_source=tool)}
        return lm, adapter_by_slug

    def test_passes_valid_manifest(self) -> None:
        lm, adapter_by_slug = self._build()
        assert _check_manifest_identity(lm, adapter_by_slug, "eng-1") is None

    def test_rejects_version(self) -> None:
        lm, adapter_by_slug = self._build(manifest_version="99.0.0")
        with pytest.raises(ManifestConfinementError) as exc_info:
            _check_manifest_identity(lm, adapter_by_slug, "eng-1")
        assert exc_info.value.check_name == "manifest_version_gate"

    def test_rejects_slug_mismatch(self) -> None:
        lm, adapter_by_slug = self._build(filename_stem="wrongname")
        with pytest.raises(ManifestConfinementError) as exc_info:
            _check_manifest_identity(lm, adapter_by_slug, "eng-1")
        assert exc_info.value.check_name == "filename_stem_slug_match"

    def test_rejects_missing_adapter(self) -> None:
        lm, _ = self._build()
        with pytest.raises(ManifestConfinementError) as exc_info:
            _check_manifest_identity(lm, {}, "eng-1")
        assert exc_info.value.check_name == "slug_adapter_match"

    def test_rejects_tool_source(self) -> None:
        lm, _ = self._build()
        wrong_adapter = {
            "scubagear": _make_adapter(slug="scubagear", tool_source=ToolSource.MAESTER)
        }
        with pytest.raises(ManifestConfinementError) as exc_info:
            _check_manifest_identity(lm, wrong_adapter, "eng-1")
        assert exc_info.value.check_name == "tool_source_match"


class TestCheckToolSubtree:
    def test_returns_resolved_subtree(self, tmp_path: Path) -> None:
        artifacts_root = tmp_path / "artifacts"
        (artifacts_root / "scubagear").mkdir(parents=True)
        resolved_root = artifacts_root.resolve()

        result = _check_tool_subtree(artifacts_root, resolved_root, "scubagear", "eng-1")
        assert result == resolved_root / "scubagear"

    def test_rejects_symlinked_subtree(self, tmp_path: Path) -> None:
        artifacts_root = tmp_path / "artifacts"
        artifacts_root.mkdir(parents=True)
        resolved_root = artifacts_root.resolve()

        outside = tmp_path / "outside" / "scubagear"
        outside.mkdir(parents=True)
        (artifacts_root / "scubagear").symlink_to(outside)

        with pytest.raises(ManifestConfinementError) as exc_info:
            _check_tool_subtree(artifacts_root, resolved_root, "scubagear", "eng-1")
        assert exc_info.value.check_name == "tool_subtree_canonical"


class TestCheckArtifactPath:
    def test_returns_resolved_path(self, tmp_path: Path) -> None:
        artifacts_root = tmp_path / "artifacts"
        scuba = artifacts_root / "scubagear"
        scuba.mkdir(parents=True)
        content = b'{"test": true}'
        (scuba / "results.json").write_bytes(content)
        sha = _sha256(content)

        record = ArtifactRecord(encoding="utf-8", sha256=sha)
        seen: set[str] = set()
        result = _check_artifact_path(
            "scubagear/results.json",
            record,
            artifacts_root,
            scuba.resolve(),
            "scubagear",
            "eng-1",
            seen,
        )
        assert result.is_absolute()
        assert result == (scuba / "results.json").resolve()

    def test_adds_to_seen_resolved(self, tmp_path: Path) -> None:
        artifacts_root = tmp_path / "artifacts"
        scuba = artifacts_root / "scubagear"
        scuba.mkdir(parents=True)
        content = b'{"test": true}'
        (scuba / "results.json").write_bytes(content)
        sha = _sha256(content)

        record = ArtifactRecord(encoding="utf-8", sha256=sha)
        seen: set[str] = set()
        result = _check_artifact_path(
            "scubagear/results.json",
            record,
            artifacts_root,
            scuba.resolve(),
            "scubagear",
            "eng-1",
            seen,
        )
        assert str(result) in seen

    def test_rejects_sha256_mismatch(self, tmp_path: Path) -> None:
        artifacts_root = tmp_path / "artifacts"
        scuba = artifacts_root / "scubagear"
        scuba.mkdir(parents=True)
        (scuba / "results.json").write_bytes(b"real content")

        record = ArtifactRecord(encoding="utf-8", sha256="b" * 64)
        seen: set[str] = set()
        with pytest.raises(ManifestConfinementError) as exc_info:
            _check_artifact_path(
                "scubagear/results.json",
                record,
                artifacts_root,
                scuba.resolve(),
                "scubagear",
                "eng-1",
                seen,
            )
        assert exc_info.value.check_name == "sha256_verify"


class TestAdapterSlugUnique:
    def test_rejects_duplicate_adapter_slugs(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts" / "scubagear"
        artifacts_dir.mkdir(parents=True)

        adapters = [
            _make_adapter(slug="scubagear", tool_source=ToolSource.SCUBAGEAR),
            _make_adapter(slug="scubagear", tool_source=ToolSource.MAESTER),
        ]
        with pytest.raises(ManifestConfinementError) as exc_info:
            confine_and_resolve([], eng_dir, adapters)
        assert exc_info.value.check_name == "adapter_slug_unique"

    def test_accepts_distinct_adapter_slugs(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng"
        artifacts_dir = eng_dir / "raw-output" / "artifacts"
        artifacts_dir.mkdir(parents=True)

        adapters = [
            _make_adapter(slug="scubagear", tool_source=ToolSource.SCUBAGEAR),
            _make_adapter(slug="maester", tool_source=ToolSource.MAESTER),
        ]
        # No manifests -- should return empty list, no error
        result = confine_and_resolve([], eng_dir, adapters)
        assert result == []
