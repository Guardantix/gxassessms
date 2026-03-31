"""Protocol definitions and type aliases for all extension points.

Runtime imports from domain only (config types via TYPE_CHECKING). Uses
string annotations for forward references to models that live in
domain/models.py (resolved at runtime by Pydantic and at type-check time
by mypy).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypedDict, runtime_checkable

from gxassessms.core.domain.enums import AdapterRunStatus, Severity  # noqa: F401 (re-exported)

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

    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify tool is installed and meets version requirements."""
        ...

    def authenticate(self, config: EngagementConfig) -> AuthContext | None:
        """Acquire credentials for the tool. Returns None if no auth needed."""
        ...

    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> RawToolOutput:
        """Execute the tool and capture raw output. Called after authenticate()."""
        ...

    def validate_raw(self, raw: RawToolOutput) -> None:
        """Validate raw output structure. Raises RawOutputValidationError on failure."""
        ...

    def parse(self, raw: RawToolOutput) -> list[ToolObservation]:
        """Parse raw output into tool-native observations. Called after validate_raw()."""
        ...

    def coverage(self, raw: RawToolOutput) -> list[CoverageRecord]:
        """Extract per-control coverage records from raw output."""
        ...


@runtime_checkable
class ReportRenderer(Protocol):
    format: str = ""
    supported_payload_versions: str = ""

    def render(self, payload: ReportPayload, output_path: Path) -> Path: ...


@runtime_checkable
class QAStrategy(Protocol):
    """Extension point for QA strategies.

    Optional class attributes:
        priority (int): Selection priority when multiple strategies are
            registered. Higher values win. Default is 0 (used when the
            attribute is absent). The ``--qa-strategy`` CLI flag overrides
            priority-based selection entirely.
    """

    def review_findings(self, findings: list[ConsolidatedFinding]) -> list[QAResult]: ...
    def generate_narratives(
        self, findings: list[ConsolidatedFinding], config: EngagementConfig
    ) -> Narratives: ...


@runtime_checkable
class ConsolidationRule(Protocol):
    """Extension point for consolidation rules.

    Invariants (architecture spec Section 11):
    1. len(output) <= len(input)
    2. Every input finding traceable in exactly one output
    3. Severity never decreases during merge
    4. No dedup key appears in more than one output group
    """

    def consolidate(self, findings: list[Finding]) -> list[ConsolidatedFinding]: ...
