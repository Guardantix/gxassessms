"""Stage execution runner -- stage loop, crash recovery, adapter mapping.

Separated from orchestrator.py to keep both files under 400 lines.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import GxAssessError, PipelineError
from gxassessms.core.domain.models import (
    AdapterResult,
    ConsolidatedFinding,
    Finding,
    ReportPayload,
    ToolObservation,
)
from gxassessms.pipeline.stages import (
    STAGE_STATE_MAP,
    Stage,
    collect,
    consolidate,
    get_stage_entry_state,
    normalize,
    parse,
    qa_review,
    render,
)
from gxassessms.pipeline.state import EngagementState, PipelineEvent

if TYPE_CHECKING:
    from gxassessms.pipeline.orchestrator import Orchestrator

logger = logging.getLogger(__name__)


def run_stages(
    orchestrator: Orchestrator,
    engagement_id: str,
    config: EngagementConfig,
    adapters: list[Any],
    normalization_policy: Any,
    consolidation_rule: Any,
    qa_strategy: Any,
    renderers: list[Any],
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

    stages = orchestrator._get_stages_to_run(start_stage)

    with orchestrator._lock.hold(engagement_id):
        current_state = orchestrator._get_current_state(engagement_id)

        # Detect and recover from stale running states (crash recovery)
        if orchestrator._detect_stale_running(engagement_id, current_state):
            recovery_stage = _recover_stale_state(orchestrator, engagement_id, current_state)
            current_state = orchestrator._get_current_state(engagement_id)
            stages = orchestrator._get_stages_to_run(recovery_stage)

        # In-memory pipeline data flows between stages.
        # None = "upstream never ran"; [] = "upstream ran, produced zero results".
        adapter_results: list[AdapterResult] | None = None
        observations: list[ToolObservation] | None = None
        findings: list[Finding] | None = None
        consolidated_findings: list[ConsolidatedFinding] | None = None
        qa_results: list[Any] | None = None

        # Seed in-memory state from persistence when resuming mid-pipeline.
        # Spec line 1646: orchestrator.run_from() is responsible for rehydration.
        _ra, _f, _cf = _rehydrate_upstream_state(start_stage, engagement_id, adapters, orchestrator)
        if _ra is not None:
            adapter_results = _ra
        if _f is not None:
            findings = _f
        if _cf is not None:
            consolidated_findings = _cf

        for stage in stages:
            running_state, completed_state = STAGE_STATE_MAP[stage]

            try:
                # Transition to RUNNING state
                orchestrator._transition_state(engagement_id, current_state, running_state)

                # Execute stage logic
                if stage == Stage.COLLECT:
                    adapter_results = collect(config, adapters)
                    # Persist raw outputs so replay/consolidate --reparse can
                    # load them later via load_raw_outputs().
                    orchestrator._artifact_manager.save_raw_outputs(
                        engagement_id, config.client_name, adapter_results
                    )

                elif stage == Stage.PARSE:
                    _require_in_memory("adapter_results", adapter_results, stage)
                    assert adapter_results is not None  # noqa: S101 -- narrowing for type checker
                    observations = parse(adapter_results, adapters)

                elif stage == Stage.NORMALIZE:
                    _require_in_memory("observations", observations, stage)
                    assert observations is not None  # noqa: S101 -- narrowing for type checker
                    severity_map = _build_adapter_severity_map(adapters)
                    category_map = _build_adapter_category_map(adapters)
                    dedup_keys = _build_adapter_dedup_keys(adapters)
                    findings = normalize(
                        observations,
                        normalization_policy,
                        adapter_severity_map=severity_map,
                        adapter_category_map=category_map,
                        adapter_dedup_keys=dedup_keys,
                    )
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
                    report_dir = output_dir or Path("output")
                    payload = _build_report_payload(engagement_id, config, consolidated_findings)
                    _execute_render(payload, renderers, report_dir)

                # Compute content hash for the stage output
                stage_hash = _compute_stage_hash(
                    stage,
                    adapter_results=adapter_results or [],
                    observations=observations or [],
                    findings=findings or [],
                    consolidated_findings=consolidated_findings or [],
                    qa_results=qa_results or [],
                    orchestrator=orchestrator,
                )

                # QA_REVIEW: only advance to QA_APPROVED if noop strategy.
                # Real QA strategies leave the engagement at QA_REVIEW
                # for human review; the pipeline stops here.
                if stage == Stage.QA_REVIEW:
                    if orchestrator._should_auto_advance_qa(qa_strategy):
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
                    # All non-QA stages: transition to completed state
                    orchestrator._transition_state(
                        engagement_id,
                        running_state,
                        completed_state,
                        content_hash=stage_hash,
                    )
                    current_state = completed_state
                    # Stop here if a stop_stage was specified
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
    # Find which stage owns this running state
    recovery_stage: Stage | None = None
    recovery_state: EngagementState | None = None
    for stage, (running, _completed) in STAGE_STATE_MAP.items():
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

    # Bypass normal transition validation (backwards transition)
    orchestrator._engagement_repo.force_update_state(engagement_id, recovery_state)

    event = PipelineEvent(
        event_id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        timestamp=utc_now(),
        event_type="stale_recovery",
        actor="system",
        payload={
            "from": stale_state.value,
            "to": recovery_state.value,
            "reason": "Stale running state detected from prior process crash",
        },
    )
    orchestrator._event_repo.append(event)

    return recovery_stage


def _rehydrate_upstream_state(
    start_stage: Stage,
    engagement_id: str,
    adapters: list[Any],
    orchestrator: Any,
) -> tuple[
    list[AdapterResult] | None,
    list[Finding] | None,
    list[ConsolidatedFinding] | None,
]:
    """Load persisted upstream data when resuming the pipeline mid-stage.

    Returns a 3-tuple of (adapter_results, findings, consolidated_findings).
    Each element is None if not relevant to start_stage.

    Raises:
        PipelineError: If start_stage is NORMALIZE (observations not persisted)
            or if required upstream data cannot be loaded.
    """
    if start_stage == Stage.COLLECT:
        return None, None, None

    if start_stage == Stage.PARSE:
        from gxassessms.pipeline.replay import (
            ReplayEngine,
            load_raw_outputs,
            validate_raw_outputs,
        )

        eng_dir = orchestrator._artifact_manager.get_engagement_dir(engagement_id)
        raw_outputs = load_raw_outputs(eng_dir)
        validate_raw_outputs(raw_outputs, adapters, engagement_id)
        adapter_results = ReplayEngine().build_adapter_results(raw_outputs)
        return adapter_results, None, None

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
        _verify_stage_completed(orchestrator, engagement_id, "NORMALIZED")
        findings = orchestrator._finding_repo.get_parsed_as_findings(engagement_id)
        return None, findings, None

    # QA_REVIEW or RENDER
    _verify_stage_completed(orchestrator, engagement_id, "CONSOLIDATED")
    consolidated = orchestrator._finding_repo.get_consolidated_as_findings(engagement_id)
    return None, None, consolidated


def _verify_stage_completed(
    orchestrator: Orchestrator, engagement_id: str, expected_state: str
) -> None:
    """Check event journal confirms the upstream stage completed.

    State transition events use payload key ``"to"`` with
    ``EngagementState.value`` (e.g., ``"NORMALIZED"``).
    """
    from gxassessms.pipeline.orchestrator import _extract_payload

    events = orchestrator._event_repo.get_events_by_type(engagement_id, "state_transition")
    completed_states = {_extract_payload(e).get("to") for e in events}
    if expected_state not in completed_states:
        raise PipelineError(
            message=(
                f"Cannot resume: upstream stage never completed "
                f"(expected {expected_state} in event journal). "
                f"Run the full pipeline first."
            ),
            engagement_id=engagement_id,
            stage=expected_state,
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


def _build_adapter_severity_map(
    adapters: list[Any],
) -> dict[tuple[str, str], str]:
    """Merge per-adapter severity mappings into a flat lookup table.

    Each adapter may expose a severity_map property: dict mapping
    (native_severity, status) -> Severity value. We merge all adapters
    into one flat dict for the NormalizationPolicy.
    """
    result: dict[tuple[str, str], str] = {}
    for adapter in adapters:
        mapping = getattr(adapter, "severity_map", None)
        if mapping is not None:
            for key, value in mapping.items():
                resolved = value.value if hasattr(value, "value") else str(value)
                if key in result and result[key] != resolved:
                    logger.warning("Severity map key %s: %s -> %s", key, result[key], resolved)
                result[key] = resolved
    return result


def _build_adapter_category_map(
    adapters: list[Any],
) -> dict[str, str]:
    """Merge per-adapter category mappings into a flat lookup table.

    Each adapter may expose a category_map property: dict mapping
    prefix/check_id -> Category value. We merge all adapters into
    one flat dict for the NormalizationPolicy.
    """
    result: dict[str, str] = {}
    for adapter in adapters:
        mapping = getattr(adapter, "category_map", None)
        if mapping is not None:
            for key, value in mapping.items():
                resolved = value.value if hasattr(value, "value") else str(value)
                if key in result and result[key] != resolved:
                    logger.warning("Category map key %s: %s -> %s", key, result[key], resolved)
                result[key] = resolved
    return result


def _build_adapter_dedup_keys(
    adapters: list[Any],
) -> dict[str, str]:
    """Merge per-adapter dedup key rules into a flat lookup table.

    Each adapter may expose a dedup_key_rules property: dict mapping
    native_check_id -> canonical finding_key. We merge all adapters
    into one flat dict for the NormalizationPolicy.
    """
    result: dict[str, str] = {}
    for adapter in adapters:
        rules = getattr(adapter, "dedup_key_rules", None)
        if rules is not None:
            for key, value in rules.items():
                if key in result and result[key] != value:
                    logger.warning("Dedup key %s: %s -> %s", key, result[key], value)
                result[key] = value
    return result


def _execute_render(
    payload: ReportPayload,
    renderers: list[Any],
    output_dir: Path,
) -> list[Path]:
    """Execute the render stage, creating output directory if needed."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return render(payload, renderers, output_dir)


def _build_report_payload(
    engagement_id: str,
    config: EngagementConfig,
    consolidated: list[ConsolidatedFinding],
) -> ReportPayload:
    """Build a ReportPayload from consolidated findings and config."""
    return ReportPayload(
        engagement_id=engagement_id,
        tenant_name=config.client_name,
        assessment_date=format_utc(utc_now()),
        tool_sources=[t for t in config.tools if config.tools[t].enabled],
        findings=[f.model_dump() for f in consolidated],
        coverage=[],
        narratives={
            "executive_summary": None,
            "roadmap": None,
            "findings_narrative": None,
        },
        metadata={
            "config_snapshot": config.model_dump(),
        },
    )


def _compute_stage_hash(
    stage: Stage,
    adapter_results: list[AdapterResult],
    observations: list[ToolObservation],
    findings: list[Finding],
    consolidated_findings: list[ConsolidatedFinding],
    qa_results: list[Any],
    orchestrator: Any,
) -> str:
    """Compute a content hash for the output of a given stage."""
    if stage == Stage.COLLECT:
        data = [r.model_dump() for r in adapter_results]
    elif stage == Stage.PARSE:
        data = [o.model_dump() for o in observations]
    elif stage == Stage.NORMALIZE:
        data = [f.model_dump() for f in findings]
    elif stage == Stage.CONSOLIDATE:
        data = [f.model_dump() for f in consolidated_findings]
    elif stage == Stage.QA_REVIEW:
        data = qa_results
    elif stage == Stage.RENDER:
        data = []  # No meaningful output to hash for render; constant placeholder
    else:
        raise ValueError(f"Unhandled stage for hashing: {stage.value}")

    return orchestrator._compute_content_hash(data)
