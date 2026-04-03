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
                scubagear/
                maester/
                ...
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
        (eng_dir / RAW_OUTPUT_DIR).mkdir(exist_ok=True)
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

        if not raw_dir.exists() or not any(raw_dir.iterdir()):
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
        adapter_results: list[Any],
    ) -> Path:
        """Persist raw tool outputs from COLLECT to the engagement directory.

        Creates the engagement directory if it does not already exist.
        Writes each successful adapter's RawToolOutput as a JSON manifest
        in ``raw-output/<tool_name>.json``, matching the format that
        ``replay.load_raw_outputs()`` reads.

        Args:
            engagement_id: Engagement to persist outputs for.
            client_name: Client name (used for directory slug).
            adapter_results: List of AdapterResult objects from COLLECT.

        Returns:
            Path to the raw-output directory.

        Raises:
            PersistenceError: If directory creation or file write fails.
        """
        try:
            eng_dir = self.get_engagement_dir(engagement_id)
        except PersistenceError:
            eng_dir = self.create_engagement_dir(engagement_id, client_name)

        raw_dir = eng_dir / RAW_OUTPUT_DIR
        raw_dir.mkdir(exist_ok=True)

        # Stale data from earlier runs must not reach replay/reparse (DELETE+INSERT pattern).
        for old_file in raw_dir.glob("*.json"):
            try:
                old_file.unlink()
            except OSError as e:
                raise PersistenceError(
                    f"Failed to clear stale raw output {old_file.name}: {e}"
                ) from e

        saved = 0
        for result in adapter_results:
            raw_output = getattr(result, "raw_output", None)
            if raw_output is None:
                continue
            tool_name = getattr(raw_output, "tool", None)
            if tool_name is None:
                continue
            filename = f"{tool_name.value.lower()}.json"
            target = raw_dir / filename
            _validate_path_within_root(target, self._engagements_root)
            try:
                target.write_text(raw_output.model_dump_json(indent=2), encoding="utf-8")
            except OSError as e:
                raise PersistenceError(
                    f"Failed to write raw output for {tool_name.value}: {e}"
                ) from e
            saved += 1

        logger.info(
            "Persisted %d raw output manifests for engagement %s",
            saved,
            engagement_id,
        )
        return raw_dir
