"""Stage execution runner -- stage loop, crash recovery, adapter mapping.

Separated from orchestrator.py to keep both files under 400 lines.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import GxAssessError, PipelineError
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

        # None = "upstream never ran"; [] = "upstream ran, produced zero results".
        collection_results: list[CollectionResult] | None = None
        loaded_manifests: list[LoadedManifest] | None = None
        adapter_results: list[AdapterResult] | None = None
        observations: list[ToolObservation] | None = None
        findings: list[Finding] | None = None
        consolidated_findings: list[ConsolidatedFinding] | None = None
        qa_results: list[QAResult] | None = None

        _lm, _f, _cf = _rehydrate_upstream_state(start_stage, engagement_id, adapters, orchestrator)
        if _lm is not None:
            loaded_manifests = _lm
        if _f is not None:
            findings = _f
        if _cf is not None:
            consolidated_findings = _cf

        for stage in stages:
            running_state, completed_state = STAGE_STATE_MAP[stage]

            try:
                orchestrator._transition_state(engagement_id, current_state, running_state)

                if stage == Stage.COLLECT:
                    collection_results = collect(config, adapters)
                    # Persist raw outputs so replay/consolidate --reparse can
                    # load them later via load_raw_outputs().
                    loaded_manifests = orchestrator._artifact_manager.save_raw_outputs(
                        engagement_id, config.client_name, collection_results
                    )

                elif stage == Stage.PARSE:
                    _require_in_memory("loaded_manifests", loaded_manifests, stage)
                    assert loaded_manifests is not None  # noqa: S101 -- narrowing for type checker
                    from gxassessms.pipeline.confinement import confine_and_resolve

                    eng_dir = orchestrator._artifact_manager.get_engagement_dir(engagement_id)
                    resolved = confine_and_resolve(loaded_manifests, eng_dir, adapters)
                    # duration_seconds=0.0 is synthetic: confinement is a
                    # batch operation, not timed per-manifest.
                    adapter_results = [
                        AdapterResult(
                            adapter_name=r.tool_slug,
                            status=AdapterRunStatus.SUCCESS,
                            raw_output=r,
                            duration_seconds=0.0,
                        )
                        for r in resolved
                    ]
                    observations = parse(adapter_results, adapters)
                    # Collect coverage from adapters that declare coverage_export.
                    # Delete-then-insert matches the finding repo pattern and
                    # prevents duplicates on reparse.
                    coverage_records = collect_coverage(adapter_results, adapters)
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

                elif stage == Stage.NORMALIZE:
                    _require_in_memory("observations", observations, stage)
                    assert observations is not None  # noqa: S101 -- narrowing for type checker
                    severity_map = _merge_adapter_map(adapters, "severity_map")
                    dedup_keys = _merge_adapter_map(adapters, "dedup_key_rules", resolve_enum=False)
                    # Build per-tool category maps to prevent cross-adapter prefix
                    # collisions.  A flat-merged map silently overwrites shared keys --
                    # e.g. "defender" means EMAIL_COLLABORATION for ScubaGear/M365 but
                    # INFRASTRUCTURE_SECURITY for Prowler/Azure.  Normalizing each
                    # tool's observations against only its own adapter's category map
                    # eliminates that ambiguity without changing the Policy interface.
                    per_tool_cat: dict[str, dict[str, str]] = {
                        str(a.tool_source.value): _merge_adapter_map([a], "category_map")
                        for a in adapters
                        if hasattr(a, "tool_source") and hasattr(a, "category_map")
                    }
                    tool_obs_groups: dict[str, list[ToolObservation]] = {}
                    for obs in observations:
                        tool_obs_groups.setdefault(obs.tool.value, []).append(obs)
                    findings_list: list[Finding] = []
                    for tool_val, tool_obs in tool_obs_groups.items():
                        findings_list.extend(
                            normalize(
                                tool_obs,
                                normalization_policy,
                                adapter_severity_map=severity_map,
                                adapter_category_map=per_tool_cat.get(tool_val, {}),
                                adapter_dedup_keys=dedup_keys,
                            )
                        )
                    findings = findings_list
                    # Persist: replaces prior parsed findings in one transaction.
                    orchestrator._finding_repo.save_parsed_findings(engagement_id, findings)

                elif stage == Stage.CONSOLIDATE:
                    _require_in_memory("findings", findings, stage)
                    assert findings is not None  # noqa: S101 -- narrowing for type checker
                    consolidated_findings = consolidate(findings, consolidation_rule)
                    # Persist: replaces prior consolidated findings in one transaction.
                    orchestrator._finding_repo.save_consolidated_findings(
                        engagement_id, consolidated_findings
                    )

                elif stage == Stage.QA_REVIEW:
                    _require_in_memory("consolidated_findings", consolidated_findings, stage)
                    assert consolidated_findings is not None  # noqa: S101 -- narrowing for type checker
                    qa_results = qa_review(consolidated_findings, qa_strategy)

                elif stage == Stage.RENDER:
                    _require_in_memory("consolidated_findings", consolidated_findings, stage)
                    assert consolidated_findings is not None  # noqa: S101 -- narrowing for type checker
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
                        consolidated_findings,
                        orchestrator._coverage_repo,
                    )
                    render(payload, renderers, report_dir)

                stage_data = _get_stage_output(
                    stage,
                    collection_results=collection_results,
                    adapter_results=adapter_results,
                    observations=observations,
                    findings=findings,
                    consolidated_findings=consolidated_findings,
                    qa_results=qa_results,
                )
                stage_hash = orchestrator._compute_content_hash(stage_data)

                # QA_REVIEW: only advance to QA_APPROVED if noop strategy.
                # Real QA strategies leave the engagement at QA_REVIEW
                # for human review; the pipeline stops here.
                if stage == Stage.QA_REVIEW:
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
                        current_state = completed_state
                    else:
                        logger.info(
                            "QA review complete for %s. Engagement held "
                            "at QA_REVIEW for human approval.",
                            engagement_id,
                        )
                        current_state = running_state
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

    # RENDER: _verify_qa_for_render already confirms CONSOLIDATED was reached
    # (QA_APPROVED cannot exist without a prior CONSOLIDATED transition).
    orchestrator._verify_qa_for_render(engagement_id)
    consolidated = orchestrator._finding_repo.get_consolidated_as_findings(engagement_id)
    return None, None, consolidated


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
) -> dict[Any, str]:
    """Merge per-adapter mappings into a flat lookup table.

    Each adapter may expose an ``attr`` property whose value is a dict.
    We merge all adapters into one flat dict, warning on collisions.
    When *resolve_enum* is True, enum-like values are resolved via ``.value``.
    """
    result: dict[Any, str] = {}
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


def _get_stage_output(
    stage: Stage,
    *,
    collection_results: list[CollectionResult] | None,
    adapter_results: list[AdapterResult] | None,
    observations: list[ToolObservation] | None,
    findings: list[Finding] | None,
    consolidated_findings: list[ConsolidatedFinding] | None,
    qa_results: list[QAResult] | None,
) -> list[Any]:
    """Return the serializable output list for a given stage."""
    if stage == Stage.COLLECT:
        return [r.model_dump() for r in (collection_results or [])]
    if stage == Stage.PARSE:
        return [o.model_dump() for o in (observations or [])]
    if stage == Stage.NORMALIZE:
        return [f.model_dump() for f in (findings or [])]
    if stage == Stage.CONSOLIDATE:
        return [f.model_dump() for f in (consolidated_findings or [])]
    if stage == Stage.QA_REVIEW:
        return qa_results or []
    if stage == Stage.RENDER:
        return []
    raise ValueError(f"Unhandled stage for hashing: {stage.value}")
