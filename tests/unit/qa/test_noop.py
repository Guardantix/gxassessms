"""Tests for NoOpQAStrategy -- ships with public package.

The no-op strategy returns empty QAResults and empty narratives.
The orchestrator detects it and auto-advances QA_REVIEW -> QA_APPROVED.
"""

from __future__ import annotations

import uuid

from gxassessms.core.config.config import AuthConfig, EngagementConfig
from gxassessms.core.contracts.types import QAStrategy
from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    ConfidenceScore,
    ConsolidatedFinding,
    SourceEvidence,
)
from gxassessms.qa.noop import NoOpQAStrategy


def _make_consolidated_finding() -> ConsolidatedFinding:
    """Create a minimal ConsolidatedFinding for testing."""
    return ConsolidatedFinding(
        finding_instance_id=str(uuid.uuid4()),
        finding_key="cis:m365:1.1.1",
        title="MFA for admins",
        severity=Severity.CRITICAL,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description="MFA not enabled.",
        sources=[
            SourceEvidence(
                tool=ToolSource.SCUBAGEAR,
                check_id="MS.AAD.3.1v1",
                raw_data={"result": "Fail"},
            ),
        ],
        confidence=ConfidenceScore(
            evidence_strength=0.9,
            corroborating_tools=1,
            data_freshness=1.0,
            provenance="system-generated",
            overall=0.9,
        ),
    )


def _make_config() -> EngagementConfig:
    """Create a minimal EngagementConfig for testing."""
    return EngagementConfig(
        client_name="Test",
        tenant_id="00000000-0000-0000-0000-000000000001",
        auth=AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_SECRET",  # pragma: allowlist secret
        ),
        tools={},
    )


class TestNoOpQAStrategySatisfiesProtocol:
    def test_is_qa_strategy(self) -> None:
        strategy = NoOpQAStrategy()
        assert isinstance(strategy, QAStrategy)


class TestNoOpReviewFindings:
    def test_returns_empty_list(self) -> None:
        strategy = NoOpQAStrategy()
        findings = [_make_consolidated_finding(), _make_consolidated_finding()]
        results = strategy.review_findings(findings)
        assert results == []

    def test_empty_input_returns_empty(self) -> None:
        strategy = NoOpQAStrategy()
        results = strategy.review_findings([])
        assert results == []


class TestNoOpGenerateNarratives:
    def test_returns_empty_narratives(self) -> None:
        strategy = NoOpQAStrategy()
        findings = [_make_consolidated_finding()]
        config = _make_config()
        narratives = strategy.generate_narratives(findings, config)
        assert narratives["executive_summary"] == ""
        assert narratives["roadmap"] == ""
        assert narratives["findings_narrative"] is None


class TestNoOpIsNoOp:
    def test_is_noop_flag(self) -> None:
        """The orchestrator checks this attribute to decide auto-advance."""
        strategy = NoOpQAStrategy()
        assert strategy.is_noop is True


class TestNoOpConstructor:
    def test_accepts_engagement_config_kwargs(self) -> None:
        """NoOpQAStrategy accepts model/token_budget/client_name without raising."""
        strategy = NoOpQAStrategy(
            model="claude-opus-4-6",
            token_budget=50000,
            client_name="Acme Corp",
        )
        assert strategy.is_noop is True

    def test_zero_arg_construction_still_works(self) -> None:
        """NoOpQAStrategy() with no args still works after adding __init__."""
        strategy = NoOpQAStrategy()
        assert strategy.is_noop is True
