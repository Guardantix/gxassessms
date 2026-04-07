"""Protocol definitions and type aliases for all extension points.

Runtime imports from domain only (config types via TYPE_CHECKING). Uses
string annotations for forward references to models that live in
domain/models.py (resolved at runtime by Pydantic and at type-check time
by mypy).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypedDict, runtime_checkable

from gxassessms.core.domain.constants import AdapterCapability
from gxassessms.core.domain.enums import (  # noqa: F401 (re-exported)
    AdapterRunStatus,
    Severity,
    ToolSource,
)

if TYPE_CHECKING:
    from gxassessms.core.config.config import EngagementConfig
    from gxassessms.core.domain.models import (
        AuthContext,
        CollectionOutput,
        ConsolidatedFinding,
        CoverageRecord,
        Finding,
        ReportPayload,
        ResolvedManifest,
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
    storage_slug: str = ""  # stable, unique, [a-z0-9][a-z0-9-]*
    tool_source: ToolSource  # identity, not presentation
    capabilities: frozenset[AdapterCapability] = frozenset()

    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify tool is installed and meets version requirements.

        For PowerShell adapters, this validates against the code-owned
        baseline policy (MODULE_POLICY), not config overrides. Use
        ``mseco preflight`` for policy-complete validation including
        config overrides via ModulePolicyOverride.
        """
        ...

    def authenticate(self, config: EngagementConfig) -> AuthContext | None:
        """Acquire credentials for the tool. Returns None if no auth needed."""
        ...

    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput:
        """Execute the tool and capture raw output. Called after authenticate()."""
        ...

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate raw output structure. Raises RawOutputValidationError on failure."""
        ...

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse raw output into tool-native observations. Called after validate_raw()."""
        ...

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
        """Extract per-control coverage records from raw output."""
        ...


@runtime_checkable
class ReportRenderer(Protocol):
    format: str = ""
    theme: str = ""
    supported_payload_versions: str = ""

    def render(self, payload: ReportPayload, output_dir: Path) -> Path: ...


@runtime_checkable
class QAStrategy(Protocol):
    """Extension point for QA strategies.

    Optional class attributes:
        is_noop (bool): When True, the runner auto-advances
            QA_REVIEW -> QA_APPROVED without human interaction.
            Default is False. Checked via ``getattr`` at runtime since
            Protocol defaults are not inherited by implementations.
        priority (int): Selection priority when multiple strategies are
            registered. Higher values win. Default is 0 (used when the
            attribute is absent). The ``--qa-strategy`` CLI flag overrides
            priority-based selection entirely.
    """

    is_noop: bool = False

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


@runtime_checkable
class NormalizationPolicy(Protocol):
    """Extension point for normalization policies.

    Implementations transform raw ToolObservations into normalized Findings
    using severity mapping, category mapping, and dedup key assignment.
    """

    def normalize(
        self,
        observations: list[ToolObservation],
        adapter_severity_map: dict[tuple[str, str], str],
        adapter_category_map: dict[str, str],
        adapter_dedup_keys: dict[str, str],
    ) -> list[Finding]: ...
