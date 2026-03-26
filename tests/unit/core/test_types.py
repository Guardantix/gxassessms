"""Tests for Protocol definitions and type aliases."""

from gxassessms.core.contracts.types import (
    AdapterRunStatus,
    ConsolidationRule,
    Narratives,
    PrerequisiteResult,
    QAResult,
    QAStrategy,
    ReportRenderer,
    ToolAdapter,
)


class TestProtocolsExist:
    def test_tool_adapter_is_protocol(self) -> None:
        assert (
            hasattr(ToolAdapter, "__protocol_attrs__")
            or hasattr(ToolAdapter, "__abstractmethods__")
            or ToolAdapter.__class__.__name__ in ("_ProtocolMeta",)
        )
        # Just verify it's importable and has expected attributes
        assert hasattr(ToolAdapter, "tool_name")

    def test_report_renderer_is_protocol(self) -> None:
        assert hasattr(ReportRenderer, "render")

    def test_qa_strategy_is_protocol(self) -> None:
        assert hasattr(QAStrategy, "review_findings")
        assert hasattr(QAStrategy, "generate_narratives")

    def test_consolidation_rule_is_protocol(self) -> None:
        assert hasattr(ConsolidationRule, "consolidate")


class TestTypeAliases:
    def test_qa_result_is_typed_dict(self) -> None:
        annotations = QAResult.__annotations__
        assert "finding_instance_id" in annotations
        assert "adjusted_severity" in annotations
        assert "confidence_delta" in annotations
        assert "narrative" in annotations
        assert "flags" in annotations

    def test_narratives_is_typed_dict(self) -> None:
        annotations = Narratives.__annotations__
        assert "executive_summary" in annotations
        assert "roadmap" in annotations
        assert "findings_narrative" in annotations


class TestPrerequisiteResult:
    def test_prerequisite_result_is_typed_dict(self) -> None:
        annotations = PrerequisiteResult.__annotations__
        assert "satisfied" in annotations
        assert "message" in annotations


class TestAdapterRunStatus:
    def test_all_statuses_exist(self) -> None:
        assert AdapterRunStatus.SUCCESS == "SUCCESS"
        assert AdapterRunStatus.FAILED == "FAILED"
        assert AdapterRunStatus.SKIPPED == "SKIPPED"
        assert AdapterRunStatus.TIMEOUT == "TIMEOUT"
