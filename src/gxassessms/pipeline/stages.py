"""Pipeline stage definitions.

Stage is the enum of pipeline stages. Each stage function is a thin wrapper
that delegates to the appropriate collaborators (adapters, policies, rules,
QA strategies, renderers).

All stage functions except collect() and render() are pure -- no side effects,
no I/O. collect() uses ThreadPoolExecutor for parallel adapter execution.
render() writes report files to disk via renderers.

Stage functions are called by the orchestrator, not directly by CLI or UI.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from concurrent.futures import Future

    from gxassessms.core.contracts.types import (
        ConsolidationRule,
        NormalizationPolicy,
        QAResult,
        QAStrategy,
        ReportRenderer,
        ToolAdapter,
    )

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import GxAssessError
from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.models import (
    AdapterResult,
    CollectionResult,
    ConsolidatedFinding,
    CoverageRecord,
    Finding,
    ReportPayload,
    ToolObservation,
)
from gxassessms.pipeline.state import EngagementState

logger = logging.getLogger(__name__)


class Stage(StrEnum):
    """Pipeline stages in execution order.

    These map to state machine transitions in EngagementState:
    COLLECT  -> COLLECTING/COLLECTED
    PARSE    -> PARSING/PARSED
    NORMALIZE -> NORMALIZING/NORMALIZED
    CONSOLIDATE -> CONSOLIDATING/CONSOLIDATED
    QA_REVIEW -> QA_REVIEW/QA_APPROVED
    RENDER   -> RENDERING/COMPLETE
    """

    COLLECT = "COLLECT"
    PARSE = "PARSE"
    NORMALIZE = "NORMALIZE"
    CONSOLIDATE = "CONSOLIDATE"
    QA_REVIEW = "QA_REVIEW"
    RENDER = "RENDER"


# Stage execution order for iteration
STAGE_ORDER: list[Stage] = list(Stage)


def collect(
    config: EngagementConfig,
    adapters: list[ToolAdapter],
) -> list[CollectionResult]:
    """Run adapters in parallel, return results including failures.

    Each adapter is executed in a ThreadPoolExecutor thread. Failures and
    timeouts are captured as CollectionResult with appropriate status -- they
    do NOT abort the pipeline. Downstream stages operate on whatever
    findings were successfully collected.

    Args:
        config: Engagement configuration (includes max_parallel).
        adapters: List of ToolAdapter implementations.

    Returns:
        List of CollectionResult, one per adapter (order not guaranteed).
    """
    if not adapters:
        return []

    max_workers = config.max_parallel or len(adapters)
    results: list[CollectionResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_adapter, adapter, config): adapter for adapter in adapters}
        for future in as_completed(futures):
            adapter = futures[future]
            result = _resolve_future(future, adapter)
            results.append(result)

    logger.info(
        "Collection complete: %d adapters, %d succeeded, %d failed",
        len(results),
        sum(1 for r in results if r.status == AdapterRunStatus.SUCCESS),
        sum(1 for r in results if r.status != AdapterRunStatus.SUCCESS),
    )
    return results


def _run_adapter(adapter: ToolAdapter, config: EngagementConfig) -> CollectionResult:
    """Execute a single adapter's authenticate + collect sequence with timing."""
    start = time.monotonic()
    auth = adapter.authenticate(config)
    collection_output = adapter.collect(config, auth)
    duration = time.monotonic() - start
    return CollectionResult(
        adapter_name=adapter.storage_slug,
        status=AdapterRunStatus.SUCCESS,
        collection_output=collection_output,
        error=None,
        duration_seconds=round(duration, 2),
    )


def _resolve_future(future: Future[CollectionResult], adapter: ToolAdapter) -> CollectionResult:
    """Resolve a completed future into a CollectionResult."""
    try:
        return future.result()
    except TimeoutError as e:
        logger.warning("Adapter %s timed out: %s", adapter.tool_name, e)
        return CollectionResult(
            adapter_name=adapter.storage_slug,
            status=AdapterRunStatus.TIMEOUT,
            error=str(e),
            duration_seconds=0.0,
        )
    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        ImportError,
        GxAssessError,
    ) as e:
        logger.warning("Adapter %s failed: %s", adapter.tool_name, e)
        return CollectionResult(
            adapter_name=adapter.storage_slug,
            status=AdapterRunStatus.FAILED,
            error=str(e),
            duration_seconds=0.0,
        )


def parse(
    results: list[AdapterResult],
    adapters: list[ToolAdapter],
) -> list[ToolObservation]:
    """Parse raw adapter output into ToolObservations.

    Skips adapters with status FAILED, TIMEOUT, or SKIPPED.
    Validates raw output via adapter.validate_raw() before parsing.

    Args:
        results: AdapterResults from the collect stage.
        adapters: Matching ToolAdapter implementations (by adapter_name).

    Returns:
        Concatenated list of ToolObservations from all successful adapters.
    """
    adapter_map = {a.storage_slug: a for a in adapters}
    observations: list[ToolObservation] = []

    for result in results:
        if result.status != AdapterRunStatus.SUCCESS:
            logger.info(
                "Skipping parse for %s (status=%s)",
                result.adapter_name,
                result.status,
            )
            continue

        adapter = adapter_map.get(result.adapter_name)
        if adapter is None:
            logger.warning(
                "No adapter found for %s, skipping parse",
                result.adapter_name,
            )
            continue

        assert result.raw_output is not None  # noqa: S101 -- SUCCESS guarantees raw_output
        adapter.validate_raw(result.raw_output)
        parsed = adapter.parse(result.raw_output)
        observations.extend(parsed)
        logger.info(
            "Parsed %d observations from %s",
            len(parsed),
            result.adapter_name,
        )

    return observations


def collect_coverage(
    results: list[AdapterResult],
    adapters: list[ToolAdapter],
) -> list[CoverageRecord]:
    """Extract coverage records from adapters that declare coverage_export.

    Called alongside parse() during the PARSE stage. Only invokes
    adapter.coverage() for adapters with 'coverage_export' in capabilities.

    Args:
        results: AdapterResults from the collect stage.
        adapters: Matching ToolAdapter implementations (by adapter_name).

    Returns:
        Concatenated list of CoverageRecords from all capable adapters.
    """
    adapter_map = {a.storage_slug: a for a in adapters}
    records: list[CoverageRecord] = []

    for result in results:
        if result.status != AdapterRunStatus.SUCCESS:
            continue

        adapter = adapter_map.get(result.adapter_name)
        if adapter is None:
            continue

        if "coverage_export" not in adapter.capabilities:
            continue

        assert result.raw_output is not None  # noqa: S101 -- SUCCESS guarantees raw_output
        coverage = adapter.coverage(result.raw_output)
        records.extend(coverage)
        logger.info(
            "Collected %d coverage records from %s",
            len(coverage),
            result.adapter_name,
        )

    return records


def normalize(
    observations: list[ToolObservation],
    policy: NormalizationPolicy,
    adapter_severity_map: dict[tuple[str, str], str] | None = None,
    adapter_category_map: dict[str, str] | None = None,
    adapter_dedup_keys: dict[str, str] | None = None,
) -> list[Finding]:
    """Normalize ToolObservations into domain Findings using policy.

    This is a pure function -- delegates entirely to the NormalizationPolicy.
    Adapter-specific mappings are resolved by the orchestrator and passed
    through the policy.

    Args:
        observations: Parsed ToolObservations from the parse stage.
        policy: NormalizationPolicy implementation.
        adapter_severity_map: Flat severity lookup table
            ((native_severity, status) -> severity).
        adapter_category_map: Flat category lookup table
            (prefix/check_id -> category).
        adapter_dedup_keys: Flat dedup key lookup table
            (native_check_id -> finding_key).

    Returns:
        List of normalized Findings.
    """
    findings = policy.normalize(
        observations=observations,
        adapter_severity_map=adapter_severity_map or {},
        adapter_category_map=adapter_category_map or {},
        adapter_dedup_keys=adapter_dedup_keys or {},
    )
    logger.info(
        "Normalized %d observations into %d findings",
        len(observations),
        len(findings),
    )
    return findings


def consolidate(
    findings: list[Finding],
    rule: ConsolidationRule,
) -> list[ConsolidatedFinding]:
    """Consolidate (dedup + merge) Findings using the consolidation rule.

    Pure function -- delegates entirely to the ConsolidationRule.

    Args:
        findings: Normalized Findings from the normalize stage.
        rule: ConsolidationRule implementation.

    Returns:
        List of ConsolidatedFindings (one per dedup group).
    """
    consolidated = rule.consolidate(findings)
    logger.info(
        "Consolidated %d findings into %d groups",
        len(findings),
        len(consolidated),
    )
    return consolidated


def qa_review(
    consolidated: list[ConsolidatedFinding],
    strategy: QAStrategy,
) -> list[QAResult]:
    """Run QA review on consolidated findings.

    Pure function -- delegates entirely to the QAStrategy.

    Args:
        consolidated: ConsolidatedFindings from the consolidate stage.
        strategy: QAStrategy implementation.

    Returns:
        List of QAResult dicts.
    """
    results = strategy.review_findings(consolidated)
    logger.info("QA review produced %d results", len(results))
    return results


def render(
    payload: ReportPayload,
    renderers: list[ReportRenderer],
    output_dir: Path,
) -> list[Path]:
    """Render report payload using all registered renderers.

    Each renderer produces a report file (docx, pptx, etc.) in output_dir.

    Args:
        payload: ReportPayload contract for renderers.
        renderers: List of ReportRenderer implementations.
        output_dir: Directory to write report files into.

    Returns:
        List of Paths to generated report files.
    """
    paths: list[Path] = []
    for renderer in renderers:
        path = renderer.render(payload, output_dir)
        paths.append(path)
        logger.info("Rendered report: %s", path)
    return paths


# ---------------------------------------------------------------------------
# State machine definitions (pipeline-layer additions)
#
# NOTE (RN-3): Valid state transitions are already defined in
# enums.py (_VALID_TRANSITIONS) with EngagementState.can_transition_to()
# and assert_can_transition_to(). We do NOT duplicate that here.
# This module adds pipeline-specific mappings: Stage -> state pairs,
# entry states, and stage ordering.
# ---------------------------------------------------------------------------

# Maps Stage -> (running_state, completed_state)
STAGE_STATE_MAP: dict[Stage, tuple[EngagementState, EngagementState]] = {
    Stage.COLLECT: (EngagementState.COLLECTING, EngagementState.COLLECTED),
    Stage.PARSE: (EngagementState.PARSING, EngagementState.PARSED),
    Stage.NORMALIZE: (EngagementState.NORMALIZING, EngagementState.NORMALIZED),
    Stage.CONSOLIDATE: (
        EngagementState.CONSOLIDATING,
        EngagementState.CONSOLIDATED,
    ),
    Stage.QA_REVIEW: (EngagementState.QA_REVIEW, EngagementState.QA_APPROVED),
    Stage.RENDER: (EngagementState.RENDERING, EngagementState.COMPLETE),
}

# Maps Stage -> required entry state (state the engagement must be in before
# this stage can start). For run_from() support.
_STAGE_ENTRY_STATE: dict[Stage, EngagementState] = {
    Stage.COLLECT: EngagementState.CREATED,
    Stage.PARSE: EngagementState.COLLECTED,
    Stage.NORMALIZE: EngagementState.PARSED,
    Stage.CONSOLIDATE: EngagementState.NORMALIZED,
    Stage.QA_REVIEW: EngagementState.CONSOLIDATED,
    Stage.RENDER: EngagementState.QA_APPROVED,
}


def get_stage_entry_state(stage: Stage) -> EngagementState:
    """Return the state an engagement must be in before a stage can start."""
    return _STAGE_ENTRY_STATE[stage]


def get_stages_from(start_stage: Stage) -> list[Stage]:
    """Return the list of stages to execute starting from start_stage."""
    start_idx = STAGE_ORDER.index(start_stage)
    return STAGE_ORDER[start_idx:]
