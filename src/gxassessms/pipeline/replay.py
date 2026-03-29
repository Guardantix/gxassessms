"""Replay mode -- re-enter pipeline from persisted raw output.

Replay loads raw tool output from the engagement directory and re-enters
the pipeline at PARSE or later stage. This supports:
- Debugging consolidation logic against real client data without re-running tools
- Re-running normalization after updating severity/category mappings
- Iterating on severity mappings and re-generating reports
- Testing prompt changes against real findings

Raw output re-validation: validate_raw() is called on loaded raw output
before re-parsing, using the same adapter's validator.

Source priority: filesystem raw output files are authoritative. If raw
output files are missing, replay raises MissingRawOutputError.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from gxassessms.core.contracts.errors import (
    GxAssessError,
    InvalidRawOutputError,
    MissingRawOutputError,
)
from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.models import AdapterResult, RawToolOutput
from gxassessms.pipeline.stages import Stage

logger = logging.getLogger(__name__)


def load_raw_outputs(engagement_dir: Path) -> list[RawToolOutput]:
    """Load persisted raw tool outputs from the engagement directory.

    Looks for JSON manifest files in <engagement_dir>/raw/. Each file
    is a serialized RawToolOutput.

    Args:
        engagement_dir: Path to the engagement directory.

    Returns:
        List of RawToolOutput objects.

    Raises:
        MissingRawOutputError: If the raw directory is missing or empty.
    """
    raw_dir = engagement_dir / "raw-output"
    if not raw_dir.exists():
        raise MissingRawOutputError(
            message=(
                f"Raw output directory not found: {raw_dir}. Cannot replay without raw tool output."
            ),
            engagement_id=engagement_dir.name,
        )

    manifest_files = sorted(raw_dir.rglob("*.json"))
    if not manifest_files:
        raise MissingRawOutputError(
            message=(
                f"No raw output manifests found in {raw_dir}. "
                f"Cannot replay without raw tool output."
            ),
            engagement_id=engagement_dir.name,
        )

    outputs: list[RawToolOutput] = []
    for manifest_file in manifest_files:
        raw_json = manifest_file.read_text(encoding="utf-8")
        try:
            raw_output = RawToolOutput.model_validate_json(raw_json)
        except (ValueError, TypeError) as e:
            raise InvalidRawOutputError(
                message=(
                    f"Malformed raw output manifest {manifest_file.name}: {e}. "
                    f"File may be truncated or schema-invalid."
                ),
                engagement_id=engagement_dir.name,
                stage="replay",
            ) from e
        outputs.append(raw_output)
        logger.info(
            "Loaded raw output for %s from %s",
            raw_output.tool.value,
            manifest_file.name,
        )

    return outputs


def validate_raw_outputs(
    raw_outputs: list[RawToolOutput],
    adapters: list[Any],
    engagement_id: str = "unknown",
) -> None:
    """Re-validate persisted raw outputs using adapter validators.

    Each raw output is validated by the adapter that produced it.
    This catches corrupted or modified artifacts at the replay boundary.

    Args:
        raw_outputs: Loaded RawToolOutput objects.
        adapters: ToolAdapter implementations (matched by tool name).
        engagement_id: Engagement ID for error context.

    Raises:
        InvalidRawOutputError: If any raw output fails re-validation.
    """
    adapter_map = {a.tool_name: a for a in adapters}

    for raw in raw_outputs:
        adapter = adapter_map.get(raw.tool.value)
        if adapter is None:
            logger.warning(
                "No adapter registered for %s, skipping re-validation",
                raw.tool.value,
            )
            continue

        try:
            adapter.validate_raw(raw)
        except (
            ValueError,
            TypeError,
            RuntimeError,
            OSError,
            AttributeError,
            GxAssessError,
        ) as e:
            raise InvalidRawOutputError(
                message=(
                    f"Raw output for {raw.tool.value} failed re-validation "
                    f"in engagement {engagement_id}: {e}. "
                    f"Persisted data may be corrupt or modified."
                ),
                engagement_id=engagement_id,
                stage="replay",
            ) from e

    logger.info("All raw outputs passed re-validation")


class ReplayEngine:
    """Manages replay mode entry into the pipeline.

    Replay builds synthetic AdapterResults from persisted raw output
    so the pipeline can re-enter at PARSE or later without the collect
    stage. The orchestrator runs stages normally from that point.
    """

    default_start_stage: Stage = Stage.PARSE

    def validate_start_stage(self, stage: Stage) -> None:
        """Validate that the start stage is valid for replay.

        Replay cannot start from COLLECT -- the point of replay is
        to skip tool execution and re-process existing raw output.

        Args:
            stage: Requested start stage.

        Raises:
            ValueError: If stage is COLLECT.
        """
        if stage == Stage.COLLECT:
            raise ValueError(
                "Cannot replay from COLLECT stage. "
                "Replay re-processes existing raw output -- "
                "use PARSE or later."
            )

    def build_adapter_results(self, raw_outputs: list[RawToolOutput]) -> list[AdapterResult]:
        """Build synthetic AdapterResults from raw outputs.

        Creates AdapterResult wrappers with SUCCESS status for each
        raw output, simulating a successful collect stage. This allows
        the parse stage to process them normally.

        Args:
            raw_outputs: Loaded and validated RawToolOutput objects.

        Returns:
            List of AdapterResult objects ready for the parse stage.
        """
        results: list[AdapterResult] = []
        for raw in raw_outputs:
            result = AdapterResult(
                adapter_name=raw.tool.value,
                status=AdapterRunStatus.SUCCESS,
                raw_output=raw,
                error=None,
                duration_seconds=0.0,
            )
            results.append(result)
            logger.info(
                "Built replay AdapterResult for %s",
                raw.tool.value,
            )
        return results
