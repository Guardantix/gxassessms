"""Stage execution runner -- execute + persist + journal for each stage.

Separated from orchestrator.py to keep both files under 400 lines.
This module handles the actual stage loop, crash recovery, data loading
fallbacks, and adapter metadata extraction.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import PipelineError
from gxassessms.core.domain.models import (
    AdapterResult,
    ConsolidatedFinding,
    Finding,
    ReportPayload,
    ToolObservation,
)
from gxassessms.pipeline.stages import (
    _STAGE_ENTRY_STATE,
    STAGE_STATE_MAP,
    Stage,
    collect,
    consolidate,
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
    """
    stages = orchestrator._get_stages_to_run(start_stage)

    with orchestrator._lock.hold(engagement_id):
        current_state = orchestrator._get_current_state(engagement_id)

        # Detect and recover from stale running states (crash recovery)
        if orchestrator._detect_stale_running(engagement_id, current_state):
            _recover_stale_state(orchestrator, engagement_id, current_state)
            current_state = orchestrator._get_current_state(engagement_id)

        # In-memory pipeline data flows between stages
        adapter_results: list[AdapterResult] = []
        observations: list[ToolObservation] = []
        findings: list[Finding] = []
        consolidated_findings: list[ConsolidatedFinding] = []
        qa_results: list[Any] = []

        for stage in stages:
            running_state, completed_state = STAGE_STATE_MAP[stage]

            try:
                # Transition to RUNNING state
                orchestrator._transition_state(engagement_id, current_state, running_state)

                # Execute stage logic
                if stage == Stage.COLLECT:
                    adapter_results = collect(config, adapters)

                elif stage == Stage.PARSE:
                    _require_in_memory("adapter_results", adapter_results, stage)
                    observations = parse(adapter_results, adapters)

                elif stage == Stage.NORMALIZE:
                    _require_in_memory("observations", observations, stage)
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

                elif stage == Stage.CONSOLIDATE:
                    _require_in_memory("findings", findings, stage)
                    consolidated_findings = consolidate(findings, consolidation_rule)

                elif stage == Stage.QA_REVIEW:
                    _require_in_memory("consolidated_findings", consolidated_findings, stage)
                    qa_results = qa_review(consolidated_findings, qa_strategy)

                elif stage == Stage.RENDER:
                    _require_in_memory("consolidated_findings", consolidated_findings, stage)
                    report_dir = output_dir or Path("output")
                    payload = _build_report_payload(engagement_id, config, consolidated_findings)
                    _execute_render(payload, renderers, report_dir)

                # Compute content hash for the stage output
                stage_hash = _compute_stage_hash(
                    stage,
                    adapter_results=adapter_results,
                    observations=observations,
                    findings=findings,
                    consolidated_findings=consolidated_findings,
                    qa_results=qa_results,
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

            except PipelineError:
                # PipelineError is already structured; re-raise as-is
                orchestrator._transition_state(engagement_id, running_state, EngagementState.FAILED)
                raise
            except (
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
                orchestrator._transition_state(engagement_id, running_state, EngagementState.FAILED)
                raise PipelineError(
                    message=f"Stage {stage.value} failed: {e}",
                    engagement_id=engagement_id,
                    stage=stage.value,
                ) from e


def _recover_stale_state(
    orchestrator: Orchestrator,
    engagement_id: str,
    stale_state: EngagementState,
) -> None:
    """Recover from a stale RUNNING state by rolling back to the entry state.

    Bypasses _transition_state() because backwards transitions (e.g.
    COLLECTING -> CREATED) are not in the valid transition table. Directly
    calls the engagement repo and records a stale_recovery event.
    """
    # Find which stage owns this running state
    recovery_state: EngagementState | None = None
    for stage, (running, _completed) in STAGE_STATE_MAP.items():
        if running == stale_state:
            recovery_state = _STAGE_ENTRY_STATE[stage]
            break

    if recovery_state is None:
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


def _require_in_memory(name: str, data: list[Any], stage: Stage) -> None:
    """Validate that upstream data exists in memory for a stage.

    Raises PipelineError if the data list is empty and the stage requires it.
    """
    if not data:
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
                result[key] = value.value if hasattr(value, "value") else str(value)
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
                result[key] = value.value if hasattr(value, "value") else str(value)
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
            result.update(rules)
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
        data = []  # Render stage hash is based on input, not output files
    else:
        raise ValueError(f"Unhandled stage for hashing: {stage.value}")

    return orchestrator._compute_content_hash(data)
