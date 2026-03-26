"""Protocol definitions and type aliases for all extension points.

Imports from domain only. Uses string annotations for forward references
to models that live in domain/models.py (resolved at runtime by Pydantic
and at type-check time by mypy).
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypedDict, runtime_checkable

from gxassessms.core.domain.enums import Severity

if TYPE_CHECKING:
    from gxassessms.core.config.config import EngagementConfig
    from gxassessms.core.domain.models import (
        AuthContext,
        ConsolidatedFinding,
        CoverageRecord,
        Finding,
        RawToolOutput,
        ReportPayload,
        ToolObservation,
    )


# ---------------------------------------------------------------------------
# Supporting types
# ---------------------------------------------------------------------------


class AdapterRunStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"


class PrerequisiteResult(TypedDict):
    satisfied: bool
    message: str


class QAResult(TypedDict):
    finding_instance_id: str
    adjusted_severity: Severity | None
    confidence_delta: float
    narrative: str | None
    flags: list[str]


class Narratives(TypedDict):
    executive_summary: str
    roadmap: str
    findings_narrative: str | None


# ---------------------------------------------------------------------------
# Extension point Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class ToolAdapter(Protocol):
    tool_name: str = ""
    capabilities: frozenset[str] = frozenset()

    def check_prerequisites(self) -> PrerequisiteResult: ...
    def authenticate(self, config: EngagementConfig) -> AuthContext | None: ...
    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> RawToolOutput: ...
    def validate_raw(self, raw: RawToolOutput) -> None: ...
    def parse(self, raw: RawToolOutput) -> list[ToolObservation]: ...
    def coverage(self, raw: RawToolOutput) -> list[CoverageRecord]: ...


@runtime_checkable
class ReportRenderer(Protocol):
    format: str = ""
    supported_payload_versions: str = ""

    def render(self, payload: ReportPayload, output_path: Path) -> Path: ...


@runtime_checkable
class QAStrategy(Protocol):
    def review_findings(
        self, findings: list[ConsolidatedFinding]
    ) -> list[QAResult]: ...
    def generate_narratives(
        self, findings: list[ConsolidatedFinding], config: EngagementConfig
    ) -> Narratives: ...


@runtime_checkable
class ConsolidationRule(Protocol):
    def consolidate(self, findings: list[Finding]) -> list[ConsolidatedFinding]: ...
