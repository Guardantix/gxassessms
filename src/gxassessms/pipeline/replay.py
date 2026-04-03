"""Replay mode -- re-enter pipeline from persisted raw output.

Replay loads raw tool output from the engagement directory and re-enters
the pipeline at PARSE or later stage. After loading, all manifests pass
through confine_and_resolve() before any adapter method runs.
"""

from __future__ import annotations

import logging
from pathlib import Path

from gxassessms.core.contracts.errors import (
    InvalidRawOutputError,
    MissingRawOutputError,
)
from gxassessms.core.domain.models import RawToolOutput
from gxassessms.pipeline.confinement import LoadedManifest
from gxassessms.pipeline.stages import Stage

logger = logging.getLogger(__name__)


def load_raw_outputs(engagement_dir: Path) -> list[LoadedManifest]:
    """Load persisted raw tool outputs from the engagement directory.

    Reads JSON manifests from <engagement_dir>/raw-output/manifests/.
    Validates directory shape (lowercase filenames, no subdirectories,
    no non-JSON files) before deserializing.

    Returns:
        List of LoadedManifest preserving the source path.

    Raises:
        MissingRawOutputError: If the manifests directory is missing or empty.
        InvalidRawOutputError: If the directory shape is invalid or JSON is malformed.
    """
    manifests_dir = engagement_dir / "raw-output" / "manifests"
    if not manifests_dir.exists():
        raise MissingRawOutputError(
            message=(
                f"Manifests directory not found: {manifests_dir}. "
                f"Cannot replay without raw tool output."
            ),
            engagement_id=engagement_dir.name,
        )

    # Validate directory shape before reading any files.
    entries = sorted(manifests_dir.iterdir())
    if not entries:
        raise MissingRawOutputError(
            message=f"No manifests found in {manifests_dir}.",
            engagement_id=engagement_dir.name,
        )

    for entry in entries:
        if entry.is_dir():
            raise InvalidRawOutputError(
                message=(
                    f"Unexpected subdirectory in manifests/: {entry.name}. "
                    f"manifests/ must contain only JSON manifest files."
                ),
                engagement_id=engagement_dir.name,
                stage="replay",
            )
        if entry.suffix != ".json":
            raise InvalidRawOutputError(
                message=(
                    f"Non-JSON file in manifests/: {entry.name}. "
                    f"Only .json manifest files are allowed."
                ),
                engagement_id=engagement_dir.name,
                stage="replay",
            )
        if entry.name != entry.name.lower():
            raise InvalidRawOutputError(
                message=(
                    f"Mixed-case manifest filename: {entry.name}. "
                    f"Manifest filenames must be lowercase."
                ),
                engagement_id=engagement_dir.name,
                stage="replay",
            )

    # Deserialize validated manifest files.
    loaded: list[LoadedManifest] = []
    for entry in entries:
        raw_json = entry.read_text(encoding="utf-8")
        try:
            raw_output = RawToolOutput.model_validate_json(raw_json)
        except (ValueError, TypeError) as e:
            raise InvalidRawOutputError(
                message=(
                    f"Malformed raw output manifest {entry.name}: {e}. "
                    f"File may be truncated or schema-invalid."
                ),
                engagement_id=engagement_dir.name,
                stage="replay",
            ) from e
        loaded.append(LoadedManifest(source_path=entry, raw_output=raw_output))
        logger.info("Loaded manifest for %s from %s", raw_output.tool.value, entry.name)

    return loaded


class ReplayEngine:
    """Manages replay mode entry into the pipeline."""

    default_start_stage: Stage = Stage.PARSE

    def validate_start_stage(self, stage: Stage) -> None:
        """Validate that the start stage is valid for replay."""
        if stage == Stage.COLLECT:
            raise ValueError(
                "Cannot replay from COLLECT stage. "
                "Replay re-processes existing raw output -- use PARSE or later."
            )
