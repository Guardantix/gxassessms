"""Stage execution runner -- stage loop, crash recovery, adapter mapping.

Separated from orchestrator.py to keep both files under 400 lines.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import GxAssessError, PipelineError, ReportError
from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.models import (
    AdapterResult,
    CollectionResult,
    ConsolidatedFinding,
    Finding,
    ReportPayload,
    ToolObservation,
)
from gxassessms.core.security.permissions import secure_mkdir, warn_broad_permissions
from gxassessms.pipeline.stages import (
    STAGE_STATE_MAP,
    Stage,
    collect,
    collect_coverage,
    consolidate,
    get_stage_entry_state,
    get_stages_from,
    normalize,
    parse,
    qa_review,
    render,
)
from gxassessms.pipeline.state import EngagementState, _extract_payload

if TYPE_CHECKING:
    from gxassessms.core.contracts.types import (
        ConsolidationRule,
        NormalizationPolicy,
        QAResult,
        QAStrategy,
        ReportRenderer,
        ToolAdapter,
    )
    from gxassessms.persistence import CoverageRepo
    from gxassessms.pipeline.confinement import LoadedManifest
    from gxassessms.pipeline.orchestrator import Orchestrator

logger = logging.getLogger(__name__)


@dataclass
class StageContext:
    """Mutable carrier for cross-stage pipeline data.

    None = "upstream never ran"; empty list = "upstream ran, zero results".
    """

    collection_results: list[CollectionResult] | None = None
    loaded_manifests: list[LoadedManifest] | None = None
    adapter_results: list[AdapterResult] | None = None
    observations: list[ToolObservation] | None = None
    findings: list[Finding] | None = None
    consolidated_findings: list[ConsolidatedFinding] | None = None
    qa_results: list[QAResult] | None = None


def _run_collect(
    ctx: StageContext,
    config: EngagementConfig,
    adapters: list[ToolAdapter],
    orchestrator: Orchestrator,
    engagement_id: str,
) -> None:
    """Execute COLLECT stage: run adapters and persist raw outputs."""
    ctx.collection_results = collect(config, adapters)
    # Persist raw outputs so replay/consolidate --reparse can
    # load them later via load_raw_outputs().
    ctx.loaded_manifests = orchestrator._artifact_manager.save_raw_outputs(
        engagement_id, config.client_name, ctx.collection_results
    )


def _run_parse(
    ctx: StageContext,
    adapters: list[ToolAdapter],
    orchestrator: Orchestrator,
    engagement_id: str,
) -> None:
    """Execute PARSE stage: confine manifests, parse, collect coverage."""
    _require_in_memory("loaded_manifests", ctx.loaded_manifests, Stage.PARSE)
    assert ctx.loaded_manifests is not None  # noqa: S101 -- narrowing for type checker
    from gxassessms.pipeline.confinement import confine_and_resolve

    eng_dir = orchestrator._artifact_manager.get_engagement_dir(engagement_id)
    resolved = confine_and_resolve(ctx.loaded_manifests, eng_dir, adapters)
    # duration_seconds=0.0 is synthetic: confinement is a
    # batch operation, not timed per-manifest.
    ctx.adapter_results = [
        AdapterResult(
            adapter_name=r.tool_slug,
            status=AdapterRunStatus.SUCCESS,
            raw_output=r,
            duration_seconds=0.0,
        )
        for r in resolved
    ]
    ctx.observations = parse(ctx.adapter_results, adapters)
    # Collect coverage from adapters that declare coverage_export.
    # Delete-then-insert matches the finding repo pattern and
    # prevents duplicates on reparse.
    coverage_records = collect_coverage(ctx.adapter_results, adapters)
    orchestrator._coverage_repo.delete_for_engagement(engagement_id)
    if coverage_records:
        orchestrator._coverage_repo.save(
            engagement_id,
            [
                {
                    "control_id": r.control_id,
                    "tool_source": r.tool.value,
                    "status": r.status.value,
                    "reason": r.reason,
                }
                for r in coverage_records
            ],
        )


def _run_normalize(
    ctx: StageContext,
    adapters: list[ToolAdapter],
    normalization_policy: NormalizationPolicy,
    orchestrator: Orchestrator,
    engagement_id: str,
) -> None:
    """Execute NORMALIZE stage: normalize observations into findings."""
    _require_in_memory("observations", ctx.observations, Stage.NORMALIZE)
    assert ctx.observations is not None  # noqa: S101 -- narrowing for type checker
    dedup_keys = _merge_adapter_map(adapters, "dedup_key_rules", resolve_enum=False)
    # Build per-tool severity and category maps to prevent cross-adapter
    # key collisions.  A flat-merged map silently overwrites shared keys
    # on collision -- e.g. ("Informational", FAIL) maps to INFO for
    # Monkey365 but LOW for Prowler; ("Unknown", FAIL) maps to INFO for
    # Monkey365 but MEDIUM for Prowler.  The same collision risk applies
    # to category keys such as "defender".  Normalizing each tool's
    # observations against only its own adapter's maps eliminates that
    # ambiguity without changing the Policy interface.
    per_tool_sev: dict[str, dict[Any, str]] = {
        a.tool_source.value: _merge_adapter_map([a], "severity_map")
        for a in adapters
        if hasattr(a, "tool_source") and hasattr(a, "severity_map")
    }
    per_tool_cat: dict[str, dict[str, str]] = {
        a.tool_source.value: _merge_adapter_map([a], "category_map")
        for a in adapters
        if hasattr(a, "tool_source") and hasattr(a, "category_map")
    }
    tool_obs_groups: dict[str, list[ToolObservation]] = {}
    for obs in ctx.observations:
        tool_obs_groups.setdefault(obs.tool.value, []).append(obs)
    findings_list: list[Finding] = []
    for tool_val, tool_obs in tool_obs_groups.items():
        findings_list.extend(
            normalize(
                tool_obs,
                normalization_policy,
                adapter_severity_map=per_tool_sev.get(tool_val, {}),
                adapter_category_map=per_tool_cat.get(tool_val, {}),
                adapter_dedup_keys=dedup_keys,
            )
        )
    ctx.findings = findings_list
    orchestrator._finding_repo.save_parsed_findings(engagement_id, ctx.findings)


def _run_consolidate(
    ctx: StageContext,
    consolidation_rule: ConsolidationRule,
    orchestrator: Orchestrator,
    engagement_id: str,
) -> None:
    """Execute CONSOLIDATE stage: consolidate findings."""
    _require_in_memory("findings", ctx.findings, Stage.CONSOLIDATE)
    assert ctx.findings is not None  # noqa: S101 -- narrowing for type checker
    ctx.consolidated_findings = consolidate(ctx.findings, consolidation_rule)
    orchestrator._finding_repo.save_consolidated_findings(engagement_id, ctx.consolidated_findings)


def _run_qa_review(
    ctx: StageContext,
    qa_strategy: QAStrategy,
) -> None:
    """Execute QA_REVIEW stage: run QA strategy on consolidated findings."""
    _require_in_memory("consolidated_findings", ctx.consolidated_findings, Stage.QA_REVIEW)
    assert ctx.consolidated_findings is not None  # noqa: S101 -- narrowing for type checker
    ctx.qa_results = qa_review(ctx.consolidated_findings, qa_strategy)


def _filter_renderers(
    renderers: list[ReportRenderer],
    config: EngagementConfig,
) -> list[ReportRenderer]:
    """Filter renderers to match config report_formats and report_theme.

    A renderer is selected if:
    1. Its format is in config.report_formats
    2. Its theme matches config.report_theme, OR the renderer is
       theme-agnostic (theme="" or no theme attribute)

    Raises ReportError if no renderers survive filtering (fail-closed).
    """
    requested_formats = set(config.report_formats)
    requested_theme = config.report_theme

    selected: list[ReportRenderer] = []
    for renderer in renderers:
        if renderer.format not in requested_formats:
            continue
        # getattr required: Protocol defaults are not inherited at runtime.
        renderer_theme = getattr(renderer, "theme", "")
        if renderer_theme and renderer_theme != requested_theme:
            continue
        selected.append(renderer)

    # Warn for requested formats with no matching renderer
    selected_formats = {r.format for r in selected}
    unmatched = sorted(requested_formats - selected_formats)
    for fmt in unmatched:
        logger.warning(
            "No renderer found for requested format '%s' with theme '%s'",
            fmt,
            requested_theme,
        )

    if not selected:
        raise ReportError(
            f"No renderers match config: report_formats={config.report_formats}, "
            f"report_theme={requested_theme!r}. "
            f"Available: {_describe_renderers(renderers)}"
        )

    logger.info(
        "Renderer selection: %d of %d renderers match (formats=%s, theme=%s)",
        len(selected),
        len(renderers),
        config.report_formats,
        requested_theme,
    )
    return selected


def _describe_renderers(renderers: list[ReportRenderer]) -> str:
    """Format available renderers for diagnostic messages."""
    if not renderers:
        return "(none discovered)"
    parts: list[str] = []
    for r in renderers:
        theme = getattr(r, "theme", "")
        label = f"format={r.format}"
        if theme:
            label += f",theme={theme}"
        parts.append(label)
    return "; ".join(parts)


def _run_render(
    ctx: StageContext,
    renderers: list[ReportRenderer],
    output_dir: Path | None,
    config: EngagementConfig,
    engagement_id: str,
    orchestrator: Orchestrator,
) -> None:
    """Execute RENDER stage: build report payload and render."""
    _require_in_memory("consolidated_findings", ctx.consolidated_findings, Stage.RENDER)
    assert ctx.consolidated_findings is not None  # noqa: S101 -- narrowing for type checker
    selected_renderers = _filter_renderers(renderers, config)
    if output_dir is None:
        eng_dir = orchestrator._artifact_manager.get_engagement_dir(engagement_id)
        report_dir = eng_dir / "reports"
    else:
        report_dir = output_dir
    secure_mkdir(report_dir, parents=True, exist_ok=True)
    warn_broad_permissions(report_dir, "report output directory")
    payload = _build_report_payload(
        engagement_id,
        config,
        ctx.consolidated_findings,
        orchestrator._coverage_repo,
    )
    render(payload, selected_renderers, report_dir)


def _handle_qa_completion(
    orchestrator: Orchestrator,
    engagement_id: str,
    qa_strategy: QAStrategy,
    running_state: EngagementState,
    completed_state: EngagementState,
    stage_hash: str,
) -> tuple[EngagementState, bool]:
    """Handle QA_REVIEW post-execution: auto-advance or human gate.

    Returns (new_current_state, should_break).
    """
    # getattr required: Protocol defaults are not
    # inherited by implementations at runtime.
    if getattr(qa_strategy, "is_noop", False) is True:
        logger.info(
            "No-op QA strategy -- auto-advancing QA_REVIEW -> QA_APPROVED for %s",
            engagement_id,
        )
        orchestrator._transition_state(
            engagement_id,
            running_state,
            completed_state,
            content_hash=stage_hash,
        )
        return completed_state, False

    logger.info(
        "QA review complete for %s. Engagement held at QA_REVIEW for human approval.",
        engagement_id,
    )
    return running_state, True


def run_stages(
    orchestrator: Orchestrator,
    engagement_id: str,
    config: EngagementConfig,
    adapters: list[ToolAdapter],
    normalization_policy: NormalizationPolicy,
    consolidation_rule: ConsolidationRule,
    qa_strategy: QAStrategy,
    renderers: list[ReportRenderer],
    start_stage: Stage,
    output_dir: Path | None = None,
    stop_stage: Stage | None = None,
) -> None:
    """Execute pipeline stages sequentially under lock.

    Acquires the engagement lock, detects stale running states, then
    loops through stages from start_stage executing each with state
    transitions.

    Args:
        orchestrator: The Orchestrator instance (for state transitions, repos).
        engagement_id: Engagement to execute.
        config: Engagement configuration.
        adapters: List of ToolAdapter implementations.
        normalization_policy: NormalizationPolicy implementation.
        consolidation_rule: ConsolidationRule implementation.
        qa_strategy: QAStrategy implementation.
        renderers: List of ReportRenderer implementations.
        start_stage: Stage to begin execution from.
        output_dir: Optional output directory for rendered reports.
        stop_stage: Optional stage to stop after. If provided, the pipeline
            halts after this stage completes (state is left in the completed
            state for stop_stage). Defaults to None (run to completion).

            Note: ``stop_stage=Stage.QA_REVIEW`` is not supported and raises
            ``ValueError``. QA_REVIEW has special state-machine handling
            (human-approval gate) that cannot be expressed as a simple stop
            point. Use ``stop_stage=Stage.CONSOLIDATE`` to halt before QA, or
            omit ``stop_stage`` to run to completion.

    Raises:
        ValueError: If ``stop_stage=Stage.QA_REVIEW`` is passed.
    """
    if stop_stage is Stage.QA_REVIEW:
        raise ValueError(
            "stop_stage=Stage.QA_REVIEW is not supported: QA_REVIEW has special "
            "state-machine handling. Use stop_stage=Stage.CONSOLIDATE to halt "
            "before QA, or omit stop_stage to run to completion."
        )

    stages = get_stages_from(start_stage)

    with orchestrator._lock.hold(engagement_id):
        current_state = orchestrator._get_current_state(engagement_id)

        if orchestrator._detect_stale_running(current_state):
            recovery_stage = _recover_stale_state(orchestrator, engagement_id, current_state)
            current_state = orchestrator._get_current_state(engagement_id)
            stages = get_stages_from(recovery_stage)

        ctx = StageContext()

        _lm, _f, _cf = _rehydrate_upstream_state(start_stage, engagement_id, adapters, orchestrator)
        if _lm is not None:
            ctx.loaded_manifests = _lm
        if _f is not None:
            ctx.findings = _f
        if _cf is not None:
            ctx.consolidated_findings = _cf

        # partial() captures ctx by reference -- mutations by one handler
        # (e.g. _run_collect setting ctx.loaded_manifests) are visible to
        # subsequent handlers in the same loop iteration sequence.
        dispatch = {
            Stage.COLLECT: partial(
                _run_collect, ctx, config, adapters, orchestrator, engagement_id
            ),
            Stage.PARSE: partial(_run_parse, ctx, adapters, orchestrator, engagement_id),
            Stage.NORMALIZE: partial(
                _run_normalize, ctx, adapters, normalization_policy, orchestrator, engagement_id
            ),
            Stage.CONSOLIDATE: partial(
                _run_consolidate, ctx, consolidation_rule, orchestrator, engagement_id
            ),
            Stage.QA_REVIEW: partial(_run_qa_review, ctx, qa_strategy),
            Stage.RENDER: partial(
                _run_render, ctx, renderers, output_dir, config, engagement_id, orchestrator
            ),
        }

        for stage in stages:
            running_state, completed_state = STAGE_STATE_MAP[stage]

            try:
                orchestrator._transition_state(engagement_id, current_state, running_state)

                dispatch[stage]()

                stage_data = _get_stage_output(stage, ctx)
                stage_hash = orchestrator._compute_content_hash(stage_data)

                if stage == Stage.QA_REVIEW:
                    current_state, should_break = _handle_qa_completion(
                        orchestrator,
                        engagement_id,
                        qa_strategy,
                        running_state,
                        completed_state,
                        stage_hash,
                    )
                    if should_break:
                        break
                else:
                    orchestrator._transition_state(
                        engagement_id,
                        running_state,
                        completed_state,
                        content_hash=stage_hash,
                    )
                    current_state = completed_state
                    if stop_stage is not None and stage == stop_stage:
                        break

            except PipelineError:
                # Protect original error -- transition failure is secondary
                try:
                    orchestrator._transition_state(
                        engagement_id, running_state, EngagementState.FAILED
                    )
                except (GxAssessError, RuntimeError, OSError):  # fmt: skip
                    logger.error("Failed to transition %s to FAILED", engagement_id, exc_info=True)
                raise
            except (
                GxAssessError,
                RuntimeError,
                OSError,
                ValueError,
                TypeError,
                AttributeError,
                ImportError,
            ) as e:
                logger.error(
                    "Stage %s failed for engagement %s: %s",
                    stage.value,
                    engagement_id,
                    e,
                )
                try:
                    orchestrator._transition_state(
                        engagement_id, running_state, EngagementState.FAILED
                    )
                except (GxAssessError, RuntimeError, OSError):  # fmt: skip
                    logger.error("Failed to transition %s to FAILED", engagement_id, exc_info=True)
                raise PipelineError(
                    message=f"Stage {stage.value} failed: {e}",
                    engagement_id=engagement_id,
                    stage=stage.value,
                ) from e


def _recover_stale_state(
    orchestrator: Orchestrator,
    engagement_id: str,
    stale_state: EngagementState,
) -> Stage:
    """Recover from a stale RUNNING state by rolling back to the entry state.

    Bypasses _transition_state() because backwards transitions (e.g.
    COLLECTING -> CREATED) are not in the valid transition table. Directly
    calls the engagement repo and records a stale_recovery event.

    Returns the Stage to resume from after recovery.
    """
    recovery_stage: Stage | None = None
    recovery_state: EngagementState | None = None
    for stage, (running, _) in STAGE_STATE_MAP.items():
        if running == stale_state:
            recovery_stage = stage
            recovery_state = get_stage_entry_state(stage)
            break

    if recovery_stage is None or recovery_state is None:
        raise PipelineError(
            message=f"Cannot recover from unrecognized stale state: {stale_state.value}",
            engagement_id=engagement_id,
            stage="",
        )

    logger.warning(
        "Detected stale running state %s for engagement %s, recovering to %s",
        stale_state.value,
        engagement_id,
        recovery_state.value,
    )

    orchestrator._engagement_repo.force_update_state(engagement_id, recovery_state)
    orchestrator._emit_event(
        engagement_id,
        "stale_recovery",
        "system",
        {
            "from": stale_state.value,
            "to": recovery_state.value,
            "reason": "Stale running state detected from prior process crash",
        },
    )

    return recovery_stage


def _rehydrate_upstream_state(
    start_stage: Stage,
    engagement_id: str,
    adapters: list[ToolAdapter],
    orchestrator: Orchestrator,
) -> tuple[
    list[LoadedManifest] | None,
    list[Finding] | None,
    list[ConsolidatedFinding] | None,
]:
    """Load persisted upstream data when resuming the pipeline mid-stage.

    Returns a 3-tuple of (loaded_manifests, findings, consolidated_findings).
    Each element is None if not relevant to start_stage.

    Raises:
        PipelineError: If start_stage is NORMALIZE (observations not persisted)
            or if required upstream data cannot be loaded.
    """
    if start_stage == Stage.COLLECT:
        return None, None, None

    if start_stage == Stage.PARSE:
        from gxassessms.pipeline.replay import load_raw_outputs

        eng_dir = orchestrator._artifact_manager.get_engagement_dir(engagement_id)
        loaded_manifests = load_raw_outputs(eng_dir)
        return loaded_manifests, None, None

    if start_stage == Stage.NORMALIZE:
        raise PipelineError(
            message=(
                "Cannot resume from NORMALIZE: ToolObservation data is not persisted. "
                "Use Stage.CONSOLIDATE to re-consolidate from persisted parsed findings, "
                "or Stage.PARSE to re-run from raw tool output (mseco consolidate --reparse)."
            ),
            engagement_id=engagement_id,
            stage=Stage.NORMALIZE.value,
        )

    if start_stage == Stage.CONSOLIDATE:
        _verify_stage_completed(orchestrator, engagement_id, EngagementState.NORMALIZED)
        findings = orchestrator._finding_repo.get_parsed_as_findings(engagement_id)
        return None, findings, None

    if start_stage == Stage.QA_REVIEW:
        _verify_stage_completed(orchestrator, engagement_id, EngagementState.CONSOLIDATED)
        consolidated = orchestrator._finding_repo.get_consolidated_as_findings(engagement_id)
        return None, None, consolidated

    if start_stage == Stage.RENDER:
        # _verify_qa_for_render already confirms CONSOLIDATED was reached
        # (QA_APPROVED cannot exist without a prior CONSOLIDATED transition).
        orchestrator._verify_qa_for_render(engagement_id)
        consolidated = orchestrator._finding_repo.get_consolidated_as_findings(engagement_id)
        return None, None, consolidated

    raise PipelineError(
        message=f"Unhandled start_stage: {start_stage.value}",
        engagement_id=engagement_id,
        stage=str(start_stage.value),
    )


def _verify_stage_completed(
    orchestrator: Orchestrator, engagement_id: str, expected_state: EngagementState
) -> None:
    """Check event journal confirms the upstream stage completed."""
    events = orchestrator._event_repo.get_events_by_type(engagement_id, "state_transition")
    completed_states = {_extract_payload(e).get("to") for e in events}
    if expected_state.value not in completed_states:
        raise PipelineError(
            message=(
                f"Cannot resume: upstream stage never completed "
                f"(expected {expected_state.value} in event journal). "
                f"Run the full pipeline first."
            ),
            engagement_id=engagement_id,
            stage=expected_state.value,
        )


def _require_in_memory(name: str, data: list[Any] | None, stage: Stage) -> None:
    """Validate that upstream data was produced by a prior stage in this run.

    Checks for None (never set) rather than empty list (set, but upstream
    produced zero results). Empty list is valid -- e.g., all controls passed.
    """
    if data is None:
        raise PipelineError(
            message=(
                f"Stage {stage.value} requires {name} from a prior stage, "
                f"but none are available in memory. "
                f"Run the full pipeline or provide persisted data."
            ),
            engagement_id="",
            stage=stage.value,
        )


def _merge_adapter_map(
    adapters: list[ToolAdapter],
    attr: str,
    *,
    resolve_enum: bool = True,
) -> dict[Any, Any]:
    """Merge per-adapter mappings into a flat lookup table.

    Each adapter may expose an ``attr`` property whose value is a dict.
    We merge all adapters into one flat dict, warning on collisions.
    When *resolve_enum* is True, enum-like values are resolved via ``.value``.
    """
    result: dict[Any, Any] = {}
    for adapter in adapters:
        mapping = getattr(adapter, attr, None)
        if mapping is None:
            continue
        for key, value in mapping.items():
            resolved = (
                (value.value if hasattr(value, "value") else str(value)) if resolve_enum else value
            )
            if key in result and result[key] != resolved:
                logger.warning("%s key %s: %s -> %s", attr, key, result[key], resolved)
            result[key] = resolved
    return result


def _build_report_payload(
    engagement_id: str,
    config: EngagementConfig,
    consolidated: list[ConsolidatedFinding],
    coverage_repo: CoverageRepo,
) -> ReportPayload:
    """Build a ReportPayload from consolidated findings and config.

    Delegates to reporting.payload.assemble_payload for the actual
    assembly. This function bridges the pipeline's in-memory consolidated
    findings with the reporting module's repo-based interface by wrapping
    the in-memory data in lightweight mock repos.
    """
    from gxassessms.reporting.payload import assemble_payload

    # The pipeline has consolidated findings in-memory but assemble_payload
    # reads from repos. Create thin wrappers that return the in-memory data.
    class _InMemoryFindingRepo:
        def get_consolidated(self, eid: str) -> list[dict[str, Any]]:
            return [f.model_dump() for f in consolidated]

    class _InMemoryCoverageRepo:
        def get_for_engagement(self, eid: str) -> list[dict[str, Any]]:
            return coverage_repo.get_for_engagement(eid)

    return assemble_payload(
        engagement_id=engagement_id,
        tenant_name=config.client_name,
        assessment_date=format_utc(utc_now()),
        tool_sources=[t for t in config.tools if config.tools[t].enabled],
        finding_repo=_InMemoryFindingRepo(),
        coverage_repo=_InMemoryCoverageRepo(),
        config_snapshot=config.model_dump(),
    )


def _get_stage_output(stage: Stage, ctx: StageContext) -> list[Any]:
    """Return the serializable output list for a given stage."""
    if stage == Stage.COLLECT:
        return [r.model_dump() for r in (ctx.collection_results or [])]
    if stage == Stage.PARSE:
        return [o.model_dump() for o in (ctx.observations or [])]
    if stage == Stage.NORMALIZE:
        return [f.model_dump() for f in (ctx.findings or [])]
    if stage == Stage.CONSOLIDATE:
        return [f.model_dump() for f in (ctx.consolidated_findings or [])]
    if stage == Stage.QA_REVIEW:
        return ctx.qa_results or []
    if stage == Stage.RENDER:
        return []
    raise ValueError(f"Unhandled stage for hashing: {stage.value}")
