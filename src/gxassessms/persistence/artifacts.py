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
import os
import re
import shutil
import sys
import tarfile
import uuid
from pathlib import Path
from typing import Any, Literal, cast

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.core.security.permissions import secure_mkdir

logger = logging.getLogger(__name__)

_MAX_SLUG_LENGTH = 64
RAW_OUTPUT_DIR = "raw-output"
_REPORTS_DIR = "reports"
_ARCHIVE_NAME = "raw-output.tar.gz"
_RESTORE_STAGING_DIR = ".restore-staging"
_CONFIG_SNAPSHOT_FILE = "config_snapshot.json"
_CONFIG_SNAPSHOT_MAX_BYTES = 1_048_576  # 1 MB -- DoS ceiling for parse

LifecycleAction = Literal["archive", "restore", "purge"]


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

    def _write_lifecycle_audit(
        self,
        action: LifecycleAction,
        engagement_id: str,
        operator: str,
        details: dict[str, Any],
    ) -> tuple[dict[str, Any], Path]:
        """Write a JSON audit manifest for a lifecycle operation.

        Defense-in-depth: callers validate engagement_id via
        get_engagement_dir(), but a direct call with a crafted ID could
        escape the audit directory.

        Returns (manifest_dict, manifest_path) so callers like purge can
        rewrite the file on post-operation failure.
        """
        from gxassessms.core.security.audit_context import build_audit_context

        now = utc_now()
        manifest: dict[str, Any] = {
            "action": action,
            "engagement_id": engagement_id,
            "operator": operator,
            "timestamp": format_utc(now),
            **build_audit_context(),
            **details,
        }

        secure_mkdir(self._audit_dir, parents=True, exist_ok=True)
        timestamp_slug = format_utc(now).replace(":", "-").replace(".", "-")
        manifest_path = self._audit_dir / f"{action}-{engagement_id}-{timestamp_slug}.json"

        # Path confinement -- prevent traversal via crafted engagement_id
        _validate_path_within_root(manifest_path, self._audit_dir)

        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        if sys.platform != "win32":
            manifest_path.chmod(0o600)
        logger.info("Wrote %s audit manifest to %s", action, manifest_path)
        return manifest, manifest_path

    def _try_write_lifecycle_audit(
        self,
        action: LifecycleAction,
        engagement_id: str,
        operator: str,
        details: dict[str, Any],
    ) -> None:
        """Best-effort audit write -- logs warning on failure, never raises.

        Used by archive/restore where the operation has already completed
        and failing the audit write would leave inconsistent state.
        """
        try:
            self._write_lifecycle_audit(action, engagement_id, operator, details)
        except OSError:
            logger.warning(
                "Failed to write %s audit manifest for %s",
                action,
                engagement_id,
                exc_info=True,
            )

    def create_engagement_dir(self, engagement_id: str, client_name: str) -> Path:
        """Create the engagement directory with standard subdirectories.

        Returns the path to the created directory.
        """
        slug = _sanitize_slug(client_name)
        dir_name = f"{slug}-{engagement_id}"
        eng_dir = self._engagements_root / dir_name

        _validate_path_within_root(eng_dir, self._engagements_root)

        secure_mkdir(eng_dir, parents=True, exist_ok=True)
        secure_mkdir(eng_dir / RAW_OUTPUT_DIR / "manifests", parents=True, exist_ok=True)
        secure_mkdir(eng_dir / RAW_OUTPUT_DIR / "artifacts", parents=True, exist_ok=True)
        secure_mkdir(eng_dir / _REPORTS_DIR, exist_ok=True)

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

    def write_config_snapshot(self, engagement_id: str, snapshot: dict[str, Any]) -> Path:
        """Write config_snapshot.json to the engagement directory atomically.

        Unlike raw-output writes (which copy adapter-produced files), this is
        the one metadata file whose bytes this class owns end-to-end. Callers
        provide a decoded dict; this method owns serialization and atomicity.

        Uses temp-file + atomic rename so concurrent readers never observe a
        partial file. `os.open` with `O_CREAT | O_EXCL | mode=0o600` applies
        to the tmp file: it eliminates the write-then-chmod race window and
        prevents silent overwrite of a pre-created tmp file. The target
        itself is overwritten on every call via `replace()` -- target-level
        semantics are last-writer-wins; no cross-process locking.

        **Sensitive data note:** the snapshot contains client tenant ID,
        subscription ID, client ID, and certificate path. It is protected by
        0o600 (the parent engagement dir is 0o700, secure_mkdir-owned). Do
        NOT add logging statements that dump the full snapshot dict -- the
        logger.debug line below deliberately logs only the engagement_id.
        """
        eng_dir = self.get_engagement_dir(engagement_id)
        target = eng_dir / _CONFIG_SNAPSHOT_FILE
        # Keep tmp inside eng_dir: os.replace is non-atomic cross-filesystem (EXDEV).
        tmp = eng_dir / f".{_CONFIG_SNAPSHOT_FILE}.tmp-{uuid.uuid4().hex}"
        try:
            # O_CREAT|O_EXCL: fail if a stale tmp file already exists (no
            # silent overwrite of attacker-planted files). mode=0o600 at
            # creation time closes the write-then-chmod race window;
            # Windows ignores the mode and inherits NTFS ACLs from the
            # 0o700 parent (matches existing _write_lifecycle_audit convention).
            fd = os.open(
                str(tmp),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
            tmp.replace(target)
        finally:
            # Only reached on write failure before replace(): after a
            # successful replace(), tmp no longer exists.
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    logger.debug("Failed to clean up temp snapshot file %s", tmp)
        logger.debug("Wrote config snapshot for engagement %s", engagement_id)
        return target

    def read_config_snapshot(self, engagement_id: str) -> dict[str, Any]:
        """Read config_snapshot.json from the engagement directory.

        Returns the raw decoded dict. Caller owns Pydantic validation --
        this class deliberately does not import `EngagementConfig` to keep
        `persistence/` independent of pydantic config models.

        Raises PersistenceError if the file is absent, unreadable, or
        not valid JSON.
        """
        eng_dir = self.get_engagement_dir(engagement_id)
        target = eng_dir / _CONFIG_SNAPSHOT_FILE
        _validate_path_within_root(target, self._engagements_root)
        if not target.is_file():
            raise PersistenceError(
                f"No config_snapshot.json for engagement {engagement_id!r} "
                f"(expected at {target}). This engagement was likely created "
                "before filesystem config persistence was added; replay requires "
                "a DB record."
            )
        # DoS ceiling: refuse to parse pathologically large files. A sane
        # config_snapshot is a few KB (client name, IDs, tool dict).
        try:
            size = target.stat().st_size
        except OSError as exc:
            raise PersistenceError(
                f"Cannot stat config_snapshot.json for engagement {engagement_id!r}: {exc}"
            ) from exc
        if size > _CONFIG_SNAPSHOT_MAX_BYTES:
            raise PersistenceError(
                f"config_snapshot.json for engagement {engagement_id!r} is "
                f"suspiciously large ({size} bytes, ceiling is "
                f"{_CONFIG_SNAPSHOT_MAX_BYTES} bytes); refusing to parse"
            )
        try:
            raw = target.read_text(encoding="utf-8")
        except OSError as exc:
            raise PersistenceError(
                f"Cannot read config_snapshot.json for engagement {engagement_id!r}: {exc}"
            ) from exc
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PersistenceError(
                f"config_snapshot.json for engagement {engagement_id!r} is corrupt: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise PersistenceError(
                f"config_snapshot.json for engagement {engagement_id!r} is not a JSON object "
                f"(got {type(parsed).__name__})"
            )
        return cast(dict[str, Any], parsed)

    def archive(self, engagement_id: str, operator: str = "system") -> Path:
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
        secure_mkdir(raw_dir)

        logger.info(
            "Archived raw output for engagement %s to %s",
            engagement_id,
            archive_path,
        )

        self._try_write_lifecycle_audit(
            "archive",
            engagement_id,
            operator,
            {
                "engagement_dir": str(eng_dir),
                "archive_path": str(archive_path),
            },
        )

        return archive_path

    def restore(self, engagement_id: str, operator: str = "system") -> Path:
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
            secure_mkdir(staging_dir)
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

        self._try_write_lifecycle_audit(
            "restore",
            engagement_id,
            operator,
            {
                "engagement_dir": str(eng_dir),
                "archive_path": str(archive_path),
                "raw_output_dir": str(raw_dir),
            },
        )

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

        details = {
            "engagement_dir": str(eng_dir),
            "files_deleted": files_deleted,
            "file_count": len(files_deleted),
        }
        manifest, manifest_path = self._write_lifecycle_audit(
            "purge", engagement_id, operator, details
        )
        manifest["audit_path"] = str(manifest_path)

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
        secure_mkdir(staging_dir, parents=True)

        try:
            staging_artifacts = staging_dir / "artifacts"
            staging_manifests = staging_dir / "manifests"
            secure_mkdir(staging_artifacts)
            secure_mkdir(staging_manifests)

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
                    secure_mkdir(dest.parent, parents=True, exist_ok=True)
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
                    source_mode="collected",
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

    def save_ingested_raw_output(
        self,
        engagement_id: str,
        collection_output: Any,  # CollectionOutput
        *,
        ingest_provenance: Any,  # IngestProvenance
        replace: bool = False,
    ) -> Any:  # LoadedManifest
        """Persist a single-slug ingested raw output atomically.

        Three-phase commit:
        1. Conflict probe + path validation
        2. Hash-verified copy to per-slug staging dir
        3. Rename-aside old data (if replace), commit artifacts then manifest

        Returns LoadedManifest with committed manifest path and RawToolOutput.
        """
        import uuid as uuid_mod

        from gxassessms.core.domain.constants import MANIFEST_VERSION_CURRENT
        from gxassessms.core.domain.models import ArtifactRecord, RawToolOutput
        from gxassessms.core.hashing import sha256_file
        from gxassessms.pipeline.confinement import LoadedManifest

        # Phase 1: Validate and probe for conflicts
        eng_dir = self.get_engagement_dir(engagement_id)
        raw_output_dir = eng_dir / RAW_OUTPUT_DIR
        slug = collection_output.tool_slug

        existing_manifest = raw_output_dir / "manifests" / f"{slug}.json"
        existing_artifacts = raw_output_dir / "artifacts" / slug
        has_existing = existing_manifest.exists() or existing_artifacts.exists()

        if has_existing and not replace:
            raise PersistenceError(
                f"Raw output already exists for {slug!r} in engagement {engagement_id}. "
                f"Use --replace to overwrite."
            )

        # Set replaced based on actual pre-commit state, not the caller's flag
        ingest_provenance = ingest_provenance.model_copy(update={"replaced": has_existing})

        # Phase 2: Stage into a per-slug temp dir
        staging_id = str(uuid_mod.uuid4())
        staging_dir = raw_output_dir / f".ingest-staging-{slug}-{staging_id}"
        secure_mkdir(staging_dir, parents=True)

        try:
            staging_artifacts = staging_dir / "artifacts" / slug
            staging_manifests = staging_dir / "manifests"
            secure_mkdir(staging_artifacts, parents=True)
            secure_mkdir(staging_manifests)

            file_manifest: dict[str, ArtifactRecord] = {}
            for artifact in collection_output.artifacts:
                source = Path(artifact.source_path)
                # Strip the leading slug/ prefix from target_relpath for dest subpath
                rel_under_slug = Path(artifact.target_relpath).relative_to(slug)
                dest = staging_artifacts / rel_under_slug
                secure_mkdir(dest.parent, parents=True, exist_ok=True)
                shutil.copy2(str(source), str(dest))

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

            raw_output = RawToolOutput(
                tool=collection_output.tool,
                tool_slug=slug,
                schema_version=collection_output.schema_version,
                manifest_version=MANIFEST_VERSION_CURRENT,
                timestamp=collection_output.timestamp,
                file_manifest=file_manifest,
                execution_metadata={},
                source_mode="ingested",
                ingest_provenance=ingest_provenance,
            )

            manifest_path = staging_manifests / f"{slug}.json"
            manifest_path.write_text(raw_output.model_dump_json(indent=2), encoding="utf-8")

        except (OSError, PersistenceError, ValueError):  # fmt: skip
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise

        # Phase 3: Rename-aside existing data then commit
        try:
            if existing_artifacts.exists():
                existing_artifacts.rename(raw_output_dir / f".old-artifacts-{slug}-{staging_id}")
            if existing_manifest.exists():
                existing_manifest.rename(raw_output_dir / f".old-manifest-{slug}-{staging_id}")

            # Ensure parent dirs exist before rename (they are created by create_engagement_dir,
            # but guard in case an unusual setup omitted them)
            secure_mkdir(raw_output_dir / "artifacts", exist_ok=True)
            secure_mkdir(raw_output_dir / "manifests", exist_ok=True)

            # Artifacts first, then manifest (manifest is the commit signal)
            (staging_dir / "artifacts" / slug).rename(raw_output_dir / "artifacts" / slug)
            (staging_dir / "manifests" / f"{slug}.json").rename(existing_manifest)
        except OSError as e:
            raise PersistenceError(f"Failed to commit ingest for {slug!r}: {e}") from e

        # Best-effort cleanup: staging dir and renamed-aside old data
        shutil.rmtree(staging_dir, ignore_errors=True)
        for name in (
            f".old-artifacts-{slug}-{staging_id}",
            f".old-manifest-{slug}-{staging_id}",
        ):
            old = raw_output_dir / name
            if old.exists():
                shutil.rmtree(old, ignore_errors=True)

        committed_manifest_path = raw_output_dir / "manifests" / f"{slug}.json"
        logger.info("Persisted ingested raw output for %s/%s", engagement_id, slug)

        return LoadedManifest(
            source_path=committed_manifest_path,
            raw_output=raw_output,
        )
