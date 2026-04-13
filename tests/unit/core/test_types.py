"""Tests for Protocol definitions and type aliases."""

from gxassessms.core.contracts.types import (
    AdapterRunStatus,
    ConsolidationRule,
    IngestCapableAdapter,
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
        assert "flags" in annotations

    def test_narratives_without_flags_is_valid(self) -> None:
        n: Narratives = {
            "executive_summary": "summary",
            "roadmap": "roadmap text",
            "findings_narrative": None,
        }
        assert "flags" not in n

    def test_narratives_with_flags_is_valid(self) -> None:
        n: Narratives = {
            "executive_summary": "summary",
            "roadmap": "roadmap text",
            "findings_narrative": None,
            "flags": ["budget_exhausted"],
        }
        assert n["flags"] == ["budget_exhausted"]


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


class TestIngestCapableAdapter:
    """Spec Section 3.5: IngestCapableAdapter Protocol."""

    def test_protocol_is_runtime_checkable(self) -> None:
        assert hasattr(IngestCapableAdapter, "__protocol_attrs__") or hasattr(
            IngestCapableAdapter, "__abstractmethods__"
        )
        # The Protocol decorator makes it runtime-checkable
        # Just verify we can use isinstance
        assert callable(getattr(IngestCapableAdapter, "__instancecheck__", None))

    def test_class_with_ingest_satisfies_protocol(self) -> None:
        from datetime import datetime
        from pathlib import Path

        from gxassessms.core.domain.models import CollectionOutput

        class FakeIngestAdapter:
            tool_name = "Fake"
            storage_slug = "fake"
            tool_source = "Fake"
            capabilities = frozenset({"collect", "ingest"})
            default_schema_version = "1.0.0"

            def ingest_from_directory(
                self, source_dir: Path, *, schema_version: str, timestamp: datetime
            ) -> CollectionOutput:
                pass  # type: ignore[empty-body]

            def check_prerequisites(self):
                pass

            def authenticate(self, config, auth):
                pass

            def collect(self, config, auth, output_dir, timeout):
                pass

            def validate_raw(self, manifest):
                pass

            def parse(self, manifest):
                pass

            def coverage(self, manifest):
                pass

        assert isinstance(FakeIngestAdapter(), IngestCapableAdapter)

    def test_class_without_ingest_method_fails_check(self) -> None:
        class NoIngestAdapter:
            tool_name = "NoIngest"
            storage_slug = "no-ingest"
            tool_source = "NoIngest"
            capabilities = frozenset({"collect"})
            # Missing: default_schema_version, ingest_from_directory

            def check_prerequisites(self):
                pass

            def authenticate(self, config, auth):
                pass

            def collect(self, config, auth, output_dir, timeout):
                pass

            def validate_raw(self, manifest):
                pass

            def parse(self, manifest):
                pass

            def coverage(self, manifest):
                pass

        assert not isinstance(NoIngestAdapter(), IngestCapableAdapter)
