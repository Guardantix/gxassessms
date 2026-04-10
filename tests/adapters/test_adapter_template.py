"""Adapter test template -- COPY AND RENAME for new adapters.

This file is intentionally inert at collection time. The scaffold classes
use the `Template*` prefix (not `Test*`) so pytest's default collection
pattern never picks them up, AND each class carries an explicit
@pytest.mark.skip as a second safety net. When you copy a class out, you
MUST rename it to `Test<Name>...` for pytest to discover the copy.

How to use for a new adapter named "example":

1. Copy the TemplateConformanceTest class to
   tests/conformance/test_example_conformance.py, rename it to
   TestExampleConformance, remove the pytest.skip, and replace
   EXAMPLE_* markers with your adapter's values.

2. Copy the TemplateParserTests class to
   tests/unit/adapters/test_example_parser.py and rename to
   TestExampleParser. NOTE: tests/unit/adapters/ is one level deeper
   than this template file, so the `Path(__file__).parent.parent.parent`
   walk must gain one extra `.parent` in the copied file.

3. Copy the TemplateMappingTests class to
   tests/unit/adapters/test_example_mappings.py and rename to
   TestExampleMappings. Same extra-.parent note as step 2.

4. Add fixture files to src/gxassessms/adapters/example/fixtures/.

5. Run: python3 -m pytest tests/conformance/test_example_conformance.py -v

Required placeholder replacements (search for "EXAMPLE_"):
  EXAMPLE_ADAPTER_CLASS    -> Your adapter class (e.g. ExampleAdapter)
  EXAMPLE_ADAPTER_MODULE   -> Import path (e.g. gxassessms.adapters.example)
  EXAMPLE_TOOL_SOURCE      -> ToolSource enum value
  EXAMPLE_STORAGE_SLUG     -> adapter.storage_slug ("example")
  EXAMPLE_FIXTURE_STEM     -> Primary fixture filename WITHOUT extension
                              (e.g. "results" -> joined with ".json"
                              in the template body)
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from gxassessms.core.domain.enums import (
    Category,  # noqa: F401  (template surface -- used by copied mapping tests)
    Severity,  # noqa: F401  (template surface -- used by copied mapping tests)
    ToolSource,
)
from gxassessms.core.domain.models import (
    ArtifactRecord,
    CoverageRecord,  # noqa: F401  (template surface -- used by copied coverage tests)
    ResolvedManifest,
    ToolObservation,  # noqa: F401  (template surface -- used by copied parser tests)
)
from tests.conformance.adapter_suite import AdapterConformanceSuite

# -----------------------------------------------------------------------
# Section 1: Conformance test scaffold
# -----------------------------------------------------------------------
#
# Copy this class to tests/conformance/test_<name>_conformance.py,
# rename to Test<Name>Conformance, remove the skip marker, and wire
# the three required fixtures (adapter, resolved_manifest,
# normalization_rules).
#
# Adapter conformance suite source:
#   tests/conformance/adapter_suite.py


@pytest.mark.skip(reason="Template -- copy and rename before use")
class TemplateConformanceTest(AdapterConformanceSuite):
    """Example conformance test. Rename and wire fixtures to use."""

    @pytest.fixture
    def adapter(self) -> Any:
        # from EXAMPLE_ADAPTER_MODULE import EXAMPLE_ADAPTER_CLASS
        # return EXAMPLE_ADAPTER_CLASS()
        raise NotImplementedError("Wire your adapter class here")

    @pytest.fixture
    def fixture_dir(self) -> Path:
        # Adjust "example" to your adapter's directory name
        return (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "adapters"
            / "example"
            / "fixtures"
        )

    @pytest.fixture
    def resolved_manifest(self, adapter: Any, fixture_dir: Path) -> ResolvedManifest:
        # EXAMPLE_FIXTURE_STEM is the primary fixture filename WITHOUT
        # its extension -- the template joins ".json" below.
        fixture_file = fixture_dir / "EXAMPLE_FIXTURE_STEM.json"
        sha = hashlib.sha256(fixture_file.read_bytes()).hexdigest()
        return ResolvedManifest(
            tool=ToolSource.MANUAL,  # Replace with EXAMPLE_TOOL_SOURCE
            tool_slug="example",  # Replace with EXAMPLE_STORAGE_SLUG
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 10, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                str(fixture_file): ArtifactRecord(encoding="utf-8", sha256=sha),
            },
            execution_metadata={},
        )

    @pytest.fixture
    def normalization_rules(self) -> dict[str, Any]:
        # Load the bundled rules from src/gxassessms/policy/rules/normalization.yaml
        import yaml

        rules_path = (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "policy"
            / "rules"
            / "normalization.yaml"
        )
        with rules_path.open(encoding="utf-8") as f:
            return yaml.safe_load(f)  # type: ignore[no-any-return]


# -----------------------------------------------------------------------
# Section 2: Parser unit test scaffold
# -----------------------------------------------------------------------


@pytest.mark.skip(reason="Template -- copy and rename before use")
class TemplateParserTests:
    """Parser unit tests for your adapter."""

    @pytest.fixture
    def raw_data(self) -> dict[str, Any]:
        import json

        fixture_path = (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "adapters"
            / "example"
            / "fixtures"
            / "EXAMPLE_FIXTURE_STEM.json"
        )
        return json.loads(fixture_path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]

    def test_parse_returns_observations(self, raw_data: dict[str, Any]) -> None:
        # Import your adapter and call its parse() with a ResolvedManifest
        # observations = adapter.parse(resolved_manifest)
        # assert len(observations) > 0
        # for obs in observations:
        #     assert isinstance(obs, ToolObservation)
        #     assert obs.native_check_id != ""
        #     assert obs.title != ""
        #     assert obs.tool == EXAMPLE_TOOL_SOURCE
        pytest.skip("Template scaffold -- implement in your copied test")

    def test_all_observations_have_nonempty_native_check_id(
        self,
        raw_data: dict[str, Any],
    ) -> None:
        # for obs in observations:
        #     assert obs.native_check_id != ""
        pytest.skip("Template scaffold -- implement in your copied test")


# -----------------------------------------------------------------------
# Section 3: Mapping coverage test scaffold
# -----------------------------------------------------------------------


@pytest.mark.skip(reason="Template -- copy and rename before use")
class TemplateMappingTests:
    """Mapping coverage tests for your adapter.

    These verify severity_map and category_map produce valid domain
    enum values and cover every raw value observed in the fixture.
    """

    def test_severity_map_values_are_valid_enum(self) -> None:
        # from EXAMPLE_ADAPTER_MODULE import EXAMPLE_ADAPTER_CLASS
        # adapter = EXAMPLE_ADAPTER_CLASS()
        # for k, v in adapter.severity_map.items():
        #     if isinstance(v, Severity):
        #         continue
        #     Severity(v)  # raises on invalid
        pytest.skip("Template scaffold -- implement in your copied test")

    def test_category_map_values_are_valid_enum(self) -> None:
        # for k, v in adapter.category_map.items():
        #     if isinstance(v, Category):
        #         continue
        #     Category(v)
        pytest.skip("Template scaffold -- implement in your copied test")

    def test_fixture_raw_values_are_all_mapped(self) -> None:
        # Parse fixture, collect raw severity/category values used by the
        # adapter, and assert each appears in severity_map or category_map.
        pytest.skip("Template scaffold -- implement in your copied test")
