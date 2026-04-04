"""File artifact storage -- engagement directories, archive/restore/purge.

Manages the filesystem half of the hybrid persistence model. Raw tool
output and generated reports live on disk. Archive compresses raw output
to cold storage; restore decompresses. Purge permanently deletes all
engagement files after writing an audit manifest.
"""

from __future__ import annotations

import glob
import json
import logging
import re
import shutil
import tarfile
from pathlib import Path
from typing import Any

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import PersistenceError

logger = logging.getLogger(__name__)

_MAX_SLUG_LENGTH = 64
RAW_OUTPUT_DIR = "raw-output"
_REPORTS_DIR = "reports"
_ARCHIVE_NAME = "raw-output.tar.gz"
_RESTORE_STAGING_DIR = ".restore-staging"


def _sanitize_slug(name: str) -> str:
    """Sanitize a client name into a filesystem-safe slug.

    Alphanumeric + hyphens only, max 64 chars. Empty input returns "unnamed".
    """
    if not name:
        return "unnamed"
    slug = name.lower().replace(" ", "-")
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    slug = slug[:_MAX_SLUG_LENGTH]
    return slug or "unnamed"


def _validate_path_within_root(target: Path, root: Path) -> None:
    """Validate that target path resolves to within root.

    Prevents path traversal via crafted names or symlinks.
    Raises PersistenceError if the path escapes the root.
    """
    resolved_target = target.resolve()
    resolved_root = root.resolve()
    if not resolved_target.is_relative_to(resolved_root):
        raise PersistenceError(
            f"Blocked path traversal: {target} resolves outside engagements root {root}"
        )


class ArtifactManager:
    """Manages engagement directory lifecycle and file artifacts.

    Engagement directory layout:
        <engagements_root>/<slug>-<engagement_id>/
            config.yaml (created by pipeline initialization)
            raw-output/
                manifests/          # one RawToolOutput JSON per tool
                    scubagear.json
                    maester.json
                artifacts/          # actual tool output files
                    scubagear/
                        ScubaResults_<guid>.json
                    maester/
                        TestResults-<timestamp>.json
            reports/
                *.docx, *.pptx
    """

    def __init__(
        self,
        engagements_root: Path,
        audit_dir: Path | None = None,
    ) -> None:
        self._engagements_root = engagements_root
        self._audit_dir = audit_dir or (engagements_root.parent / "audit")

    def create_engagement_dir(self, engagement_id: str, client_name: str) -> Path:
        """Create the engagement directory with standard subdirectories.

        Returns the path to the created directory.
        """
        slug = _sanitize_slug(client_name)
        dir_name = f"{slug}-{engagement_id}"
        eng_dir = self._engagements_root / dir_name

        _validate_path_within_root(eng_dir, self._engagements_root)

        eng_dir.mkdir(parents=True, exist_ok=True)
        (eng_dir / RAW_OUTPUT_DIR / "manifests").mkdir(parents=True, exist_ok=True)
        (eng_dir / RAW_OUTPUT_DIR / "artifacts").mkdir(parents=True, exist_ok=True)
        (eng_dir / _REPORTS_DIR).mkdir(exist_ok=True)

        logger.info("Created engagement directory: %s", eng_dir)
        return eng_dir

    def get_engagement_dir(self, engagement_id: str) -> Path:
        """Find the engagement directory by ID.

        Scans the engagements root for a directory ending with the
        engagement ID. Raises PersistenceError if not found.
        """
        for entry in self._engagements_root.glob(f"*-{glob.escape(engagement_id)}"):
            if entry.is_dir():
                _validate_path_within_root(entry, self._engagements_root)
                return entry
        raise PersistenceError(f"Engagement directory not found for: {engagement_id}")

    def archive(self, engagement_id: str) -> Path:
        """Archive raw output to a compressed tarball.

        Compresses the raw-output directory, then removes the original
        files. Reports and config remain on disk. Returns the archive path.
        """
        eng_dir = self.get_engagement_dir(engagement_id)
        raw_dir = eng_dir / RAW_OUTPUT_DIR

        has_files = raw_dir.exists() and any(f for f in raw_dir.rglob("*") if f.is_file())
        if not has_files:
            raise PersistenceError(f"No raw output to archive for engagement {engagement_id}")

        archive_path = eng_dir / _ARCHIVE_NAME
        if archive_path.exists():
            raise PersistenceError(
                f"Archive already exists for engagement {engagement_id}. "
                "Restore or delete it before re-archiving."
            )

        # Write and verify archive. Keep PersistenceError (empty-archive check) outside
        # the TarError/OSError handler so it doesn't suppress archive_path cleanup.
        try:
            with tarfile.open(str(archive_path), "w:gz") as tar:
                tar.add(str(raw_dir), arcname=RAW_OUTPUT_DIR)
            with tarfile.open(str(archive_path), "r:gz") as verify_tar:
                members = verify_tar.getmembers()
        except (tarfile.TarError, OSError) as e:
            archive_path.unlink(missing_ok=True)
            raise PersistenceError(f"Failed to archive engagement {engagement_id}: {e}") from e

        if not members:
            archive_path.unlink(missing_ok=True)
            raise PersistenceError(
                f"Archive verification failed: empty tarball for {engagement_id}"
            )

        shutil.rmtree(raw_dir)
        raw_dir.mkdir()

        logger.info(
            "Archived raw output for engagement %s to %s",
            engagement_id,
            archive_path,
        )
        return archive_path

    def restore(self, engagement_id: str) -> Path:
        """Restore raw output from a compressed tarball.

        Extracts to a staging directory first; only replaces raw-output/
        after successful extraction and verification.
        Returns the raw-output directory path.
        """
        eng_dir = self.get_engagement_dir(engagement_id)
        archive_path = eng_dir / _ARCHIVE_NAME
        if not archive_path.exists():
            raise PersistenceError(f"No archive found for engagement {engagement_id}")

        raw_dir = eng_dir / RAW_OUTPUT_DIR
        staging_dir = eng_dir / _RESTORE_STAGING_DIR
        try:
            staging_dir.mkdir()
            with tarfile.open(str(archive_path), "r:gz") as tar:
                tar.extractall(path=str(staging_dir), filter="data")
        except (tarfile.TarError, OSError) as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise PersistenceError(f"Failed to restore engagement {engagement_id}: {e}") from e

        extracted_raw = staging_dir / RAW_OUTPUT_DIR
        if not extracted_raw.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise PersistenceError(f"Archive for {engagement_id} contained no raw-output directory")

        # Atomically swap -- staging_dir cleanup in finally so it always runs
        try:
            if raw_dir.exists():
                shutil.rmtree(raw_dir)
            extracted_raw.rename(raw_dir)
        except OSError as e:
            raise PersistenceError(f"Failed to replace raw-output for {engagement_id}: {e}") from e
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

        logger.info("Restored raw output for engagement %s from %s", engagement_id, archive_path)
        return raw_dir

    def purge(self, engagement_id: str, operator: str = "system") -> dict[str, Any]:
        """Permanently delete all engagement files after writing an audit manifest.

        The audit manifest is written to the audit directory BEFORE
        deletion begins, preserving GDPR demonstrability. The audit
        directory is outside the engagement directory and is not
        affected by the purge.

        Returns the manifest dict.
        """
        eng_dir = self.get_engagement_dir(engagement_id)

        files_deleted: list[str] = []
        for item in eng_dir.rglob("*"):
            if item.is_file():
                files_deleted.append(str(item.relative_to(eng_dir)))

        if not files_deleted:
            raise PersistenceError(
                f"Engagement directory is empty, nothing to purge: {engagement_id}"
            )

        now = utc_now()
        manifest: dict[str, Any] = {
            "engagement_id": engagement_id,
            "operator": operator,
            "purged_at": format_utc(now),
            "engagement_dir": str(eng_dir),
            "files_deleted": files_deleted,
            "file_count": len(files_deleted),
        }

        self._audit_dir.mkdir(parents=True, exist_ok=True)
        timestamp_slug = format_utc(now).replace(":", "-").replace(".", "-")
        manifest_path = self._audit_dir / f"purge-{engagement_id}-{timestamp_slug}.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        logger.info("Wrote purge audit manifest to %s", manifest_path)

        try:
            shutil.rmtree(eng_dir)
        except OSError as e:
            manifest["rmtree_error"] = str(e)
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            logger.error("Failed to remove engagement directory %s: %s", eng_dir, e)
            raise PersistenceError(
                f"Purge audit manifest written but directory removal failed: {e}"
            ) from e
        logger.info(
            "Purged engagement %s: %d files deleted",
            engagement_id,
            len(files_deleted),
        )

        return manifest

    def save_raw_outputs(
        self,
        engagement_id: str,
        client_name: str,
        collection_results: list[Any],
    ) -> list[Any]:
        """Persist collection results using generation-staged writes.

        Phase 1: Validate all inputs (before any I/O)
        Phase 2: Stage the full generation
        Phase 3: Commit (artifacts first, manifests last)
        Phase 4: Return LoadedManifest list
        """
        import uuid as uuid_mod

        from gxassessms.core.contracts.types import AdapterRunStatus
        from gxassessms.core.domain.constants import (
            EXECUTION_METADATA_ALLOWLIST,
            MANIFEST_VERSION_CURRENT,
        )
        from gxassessms.core.domain.models import ArtifactRecord, RawToolOutput
        from gxassessms.core.domain.path_validation import validate_canonical_posix_path
        from gxassessms.core.hashing import sha256_file
        from gxassessms.pipeline.confinement import LoadedManifest

        try:
            eng_dir = self.get_engagement_dir(engagement_id)
        except PersistenceError:
            eng_dir = self.create_engagement_dir(engagement_id, client_name)

        raw_output_dir = eng_dir / RAW_OUTPUT_DIR

        # Filter to successful results with collection_output
        successful = [
            r
            for r in collection_results
            if r.status == AdapterRunStatus.SUCCESS and r.collection_output is not None
        ]

        if not successful:
            logger.info(
                "No successful collection results for engagement %s; preserving existing data",
                engagement_id,
            )
            return []

        # Phase 1: Validate all inputs
        seen_slugs: set[str] = set()
        seen_relpaths: set[str] = set()
        seen_relpaths_lower: set[str] = set()

        for cr in successful:
            co = cr.collection_output
            slug = co.tool_slug

            # Duplicate slug check
            if slug in seen_slugs:
                raise PersistenceError(f"Duplicate storage_slug in collection results: {slug!r}")
            seen_slugs.add(slug)

            for artifact in co.artifacts:
                # Source validation
                source = Path(artifact.source_path)
                if not source.is_absolute():
                    raise PersistenceError(f"Source path is not absolute: {artifact.source_path!r}")
                if not source.exists():
                    raise PersistenceError(f"Source file does not exist: {artifact.source_path!r}")
                if not source.is_file():
                    raise PersistenceError(
                        f"Source is not a regular file: {artifact.source_path!r}"
                    )
                if source.is_symlink():
                    raise PersistenceError(
                        f"Source is a symlink (not allowed): {artifact.source_path!r}"
                    )

                # Source hash verification
                actual = sha256_file(source)
                if actual != artifact.sha256:
                    raise PersistenceError(
                        f"Source hash mismatch for {artifact.source_path!r}: "
                        f"expected {artifact.sha256}, got {actual}"
                    )

                # Target relpath validation
                try:
                    validate_canonical_posix_path(artifact.target_relpath)
                except ValueError as e:
                    raise PersistenceError(
                        f"Invalid target_relpath {artifact.target_relpath!r}: {e}"
                    ) from e

                if not artifact.target_relpath.startswith(f"{slug}/"):
                    raise PersistenceError(
                        f"target_relpath {artifact.target_relpath!r} does not start with {slug}/"
                    )

                # Duplicate and collision checks
                if artifact.target_relpath in seen_relpaths:
                    raise PersistenceError(f"Duplicate target_relpath: {artifact.target_relpath!r}")
                lower = artifact.target_relpath.lower()
                if lower in seen_relpaths_lower:
                    raise PersistenceError(
                        f"Case-insensitive collision for target_relpath: "
                        f"{artifact.target_relpath!r}"
                    )
                seen_relpaths.add(artifact.target_relpath)
                seen_relpaths_lower.add(lower)

        # Phase 2: Stage the full generation
        staging_id = str(uuid_mod.uuid4())
        staging_dir = raw_output_dir / f".staging-{staging_id}"
        staging_dir.mkdir(parents=True)

        try:
            staging_artifacts = staging_dir / "artifacts"
            staging_manifests = staging_dir / "manifests"
            staging_artifacts.mkdir()
            staging_manifests.mkdir()

            persisted: dict[str, RawToolOutput] = {}

            for cr in successful:
                co = cr.collection_output
                slug = co.tool_slug
                version = MANIFEST_VERSION_CURRENT
                allowlist = EXECUTION_METADATA_ALLOWLIST.get(version, {}).get(slug, frozenset())

                file_manifest: dict[str, ArtifactRecord] = {}
                for artifact in co.artifacts:
                    source = Path(artifact.source_path)
                    dest = staging_artifacts / artifact.target_relpath
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(source), str(dest))

                    # Verify copy
                    copy_hash = sha256_file(dest)
                    if copy_hash != artifact.sha256:
                        raise PersistenceError(
                            f"Copy corruption for {artifact.target_relpath!r}: "
                            f"expected {artifact.sha256}, got {copy_hash}"
                        )

                    file_manifest[artifact.target_relpath] = ArtifactRecord(
                        encoding=artifact.encoding,
                        sha256=artifact.sha256,
                    )

                filtered_metadata = {
                    k: v for k, v in co.execution_metadata.items() if k in allowlist
                }

                raw_output = RawToolOutput(
                    tool=co.tool,
                    tool_slug=slug,
                    schema_version=co.schema_version,
                    manifest_version=version,
                    timestamp=co.timestamp,
                    file_manifest=file_manifest,
                    execution_metadata=filtered_metadata,
                )

                manifest_path = staging_manifests / f"{slug}.json"
                manifest_path.write_text(
                    raw_output.model_dump_json(indent=2),
                    encoding="utf-8",
                )
                persisted[slug] = raw_output

        except (OSError, PersistenceError, ValueError):  # fmt: skip
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise

        # Phase 3: Commit
        old_artifacts_id = str(uuid_mod.uuid4())
        old_manifests_id = str(uuid_mod.uuid4())
        artifacts_dir = raw_output_dir / "artifacts"
        manifests_dir = raw_output_dir / "manifests"

        try:
            if artifacts_dir.exists():
                artifacts_dir.rename(raw_output_dir / f".old-artifacts-{old_artifacts_id}")
            if manifests_dir.exists():
                manifests_dir.rename(raw_output_dir / f".old-manifests-{old_manifests_id}")
            (staging_dir / "artifacts").rename(artifacts_dir)
            (staging_dir / "manifests").rename(manifests_dir)
        except OSError as e:
            raise PersistenceError(
                f"Failed to commit generation for engagement {engagement_id}: {e}"
            ) from e

        # Best-effort cleanup of old generation and staging
        for name in [
            f".old-artifacts-{old_artifacts_id}",
            f".old-manifests-{old_manifests_id}",
            f".staging-{staging_id}",
        ]:
            target = raw_output_dir / name
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)

        # Clean up orphaned staging dirs from prior failed runs
        for item in raw_output_dir.iterdir():
            if item.name.startswith(".staging-") and item.is_dir():
                shutil.rmtree(item, ignore_errors=True)

        # Best-effort source cleanup
        for cr in successful:
            for artifact in cr.collection_output.artifacts:
                source = Path(artifact.source_path)
                try:
                    source.unlink(missing_ok=True)
                except OSError:
                    logger.debug("Failed to clean source file %s (non-fatal)", source)

        logger.info(
            "Persisted %d raw output manifests for engagement %s",
            len(persisted),
            engagement_id,
        )

        # Phase 4: Return LoadedManifest list
        return [
            LoadedManifest(
                source_path=manifests_dir / f"{slug}.json",
                raw_output=raw_output,
            )
            for slug, raw_output in persisted.items()
        ]
