"""Domain enums -- str-based for JSON serialization and human readability."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType

from gxassessms.core.contracts.errors import InvalidTransitionError


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(StrEnum):
    FAIL = "FAIL"
    PASS = "PASS"  # noqa: S105
    WARNING = "WARNING"
    ERROR = "ERROR"
    NOT_APPLICABLE = "N/A"
    MANUAL = "MANUAL"


class Category(StrEnum):
    IDENTITY_ACCESS = "Identity & Access"
    DATA_PROTECTION = "Data Protection"
    DEVICE_MANAGEMENT = "Device Management"
    EMAIL_COLLABORATION = "Email & Collaboration"
    INFRASTRUCTURE_SECURITY = "Infrastructure Security"
    NETWORK_SECURITY = "Network Security"
    LOGGING_MONITORING = "Logging & Monitoring"
    COST_OPTIMIZATION = "Cost Optimization"
    OPERATIONAL_EXCELLENCE = "Operational Excellence"
    COMPLIANCE = "Compliance & Governance"
    APPLICATION_SECURITY = "Application Security"


class AdapterRunStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"


class CoverageStatus(StrEnum):
    ASSESSED = "assessed"
    PARTIALLY_ASSESSED = "partially_assessed"
    NOT_ASSESSED = "not_assessed"


class ToolSource(StrEnum):
    SCUBAGEAR = "ScubaGear"
    MAESTER = "Maester"
    MONKEY365 = "Monkey365"
    M365_ASSESS = "M365Assess"
    PROWLER = "Prowler"
    STEAMPIPE = "Steampipe"
    SECURE_SCORE = "SecureScore"
    AZURE_ADVISOR = "AzureAdvisor"
    DEFENDER_CLOUD = "DefenderCloud"
    M365DSC = "M365DSC"
    INTUNE_EXPORT = "IntuneExport"
    AZURE_RESOURCE_GRAPH = "AzureResourceGraph"
    CUSTOM = "Custom"
    MANUAL = "Manual"


class EngagementState(StrEnum):
    """Pipeline lifecycle states."""

    CREATED = "CREATED"
    COLLECTING = "COLLECTING"
    COLLECTED = "COLLECTED"
    PARSING = "PARSING"
    PARSED = "PARSED"
    NORMALIZING = "NORMALIZING"
    NORMALIZED = "NORMALIZED"
    CONSOLIDATING = "CONSOLIDATING"
    CONSOLIDATED = "CONSOLIDATED"
    QA_REVIEW = "QA_REVIEW"
    QA_APPROVED = "QA_APPROVED"
    RENDERING = "RENDERING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"

    @classmethod
    def can_transition_to(cls, from_state: EngagementState, to_state: EngagementState) -> bool:
        """Check whether a state transition is valid."""
        return to_state in _VALID_TRANSITIONS.get(from_state, frozenset())

    @classmethod
    def assert_can_transition_to(
        cls, from_state: EngagementState, to_state: EngagementState
    ) -> None:
        """Assert transition is valid; raises InvalidTransitionError if not."""
        if not cls.can_transition_to(from_state, to_state):
            raise InvalidTransitionError(
                message=f"Cannot transition from {from_state.value} to {to_state.value}",
                from_state=from_state.value,
                to_state=to_state.value,
            )

    @property
    def is_terminal(self) -> bool:
        """True if this state has no valid outgoing transitions."""
        return not bool(_VALID_TRANSITIONS.get(self, frozenset()))


_VALID_TRANSITIONS: MappingProxyType[EngagementState, frozenset[EngagementState]] = (
    MappingProxyType(
        {
            EngagementState.CREATED: frozenset(
                {EngagementState.COLLECTING, EngagementState.FAILED}
            ),
            EngagementState.COLLECTING: frozenset(
                {EngagementState.COLLECTED, EngagementState.FAILED}
            ),
            EngagementState.COLLECTED: frozenset({EngagementState.PARSING, EngagementState.FAILED}),
            EngagementState.PARSING: frozenset({EngagementState.PARSED, EngagementState.FAILED}),
            EngagementState.PARSED: frozenset(
                {EngagementState.NORMALIZING, EngagementState.FAILED}
            ),
            EngagementState.NORMALIZING: frozenset(
                {EngagementState.NORMALIZED, EngagementState.FAILED}
            ),
            EngagementState.NORMALIZED: frozenset(
                {EngagementState.CONSOLIDATING, EngagementState.FAILED}
            ),
            EngagementState.CONSOLIDATING: frozenset(
                {EngagementState.CONSOLIDATED, EngagementState.FAILED}
            ),
            EngagementState.CONSOLIDATED: frozenset(
                {EngagementState.QA_REVIEW, EngagementState.FAILED}
            ),
            EngagementState.QA_REVIEW: frozenset(
                {EngagementState.QA_APPROVED, EngagementState.FAILED}
            ),
            EngagementState.QA_APPROVED: frozenset(
                {EngagementState.RENDERING, EngagementState.FAILED}
            ),
            EngagementState.RENDERING: frozenset(
                {EngagementState.COMPLETE, EngagementState.FAILED}
            ),
            EngagementState.COMPLETE: frozenset(),
            EngagementState.FAILED: frozenset(),
        }
    )
)
