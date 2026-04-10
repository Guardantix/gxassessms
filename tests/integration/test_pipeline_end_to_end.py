"""End-to-end integration test -- full pipeline via Orchestrator.

Drives the real Orchestrator with the real ScubaGearAdapter (against its
bundled fixtures), NoOpQAStrategy, and a test-only JsonMarkerRenderer.
Uses a tmp_path data directory (no state leaks across tests). Does not
require Node.js -- the JsonMarkerRenderer writes a plain JSON file.

This is the canonical smoke test for the full pipeline. It catches
cross-layer breakage that unit tests and per-stage integration tests miss.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from gxassessms.adapters.scubagear import ScubaGearAdapter
from gxassessms.consolidation.rules import DefaultConsolidationRule
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import AdapterCapability
from gxassessms.core.domain.enums import (
    Category,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    AuthContext,
    CollectedArtifact,
    CollectionOutput,
    ConsolidatedFinding,
    CoverageRecord,
    Finding,
    ReportPayload,
    ResolvedManifest,
    ToolObservation,
)
from gxassessms.persistence import (
    ArtifactManager,
    CoverageRepo,
    DatabaseManager,
    EngagementRepo,
    EventRepo,
    FindingRepo,
)
from gxassessms.pipeline.orchestrator import Orchestrator
from gxassessms.pipeline.state import EngagementLock, EngagementState
from gxassessms.policy.consolidation import DefaultConsolidationPolicy
from gxassessms.policy.normalization import DefaultNormalizationPolicy
from gxassessms.qa.noop import NoOpQAStrategy

# Test-only renderer (no Node.js dependency) ----------------------------


class JsonMarkerRenderer:
    """Minimal ReportRenderer that writes a JSON marker file.

    Used by the end-to-end test to verify the RENDER stage executes
    without pulling in Node.js. Matches the ReportRenderer Protocol.
    """

    format: str = "json_marker"
    theme: str = ""
    # Declared to match the ReportRenderer Protocol; not enforced by this
    # test renderer (no runtime version checking).
    supported_payload_versions: str = ">=1.0.0,<2.0.0"

    def render(self, payload: ReportPayload, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / f"{payload.engagement_id}.json"
        out.write_text(
            json.dumps(
                {
                    "engagement_id": payload.engagement_id,
                    "tenant_name": payload.tenant_name,
                    "assessment_date": payload.assessment_date,
                    "tool_sources": payload.tool_sources,
                    "finding_count": len(payload.findings),
                    "coverage_count": len(payload.coverage),
                    "rendered": True,
                }
            ),
            encoding="utf-8",
        )
        return out


# Failing adapter for partial-failure test -----------------------------


class FailingStubAdapter:
    """Stub adapter that raises during collect().

    Used to exercise the partial-adapter-failure path: the pipeline must
    continue with the successful adapter's output.
    """

    tool_name: str = "FailingStub"
    storage_slug: str = "failing-stub"
    tool_source: ToolSource = ToolSource.MANUAL  # any valid ToolSource
    capabilities: frozenset[AdapterCapability] = frozenset({"collect", "parse", "prerequisites"})

    def check_prerequisites(self) -> PrerequisiteResult:
        return PrerequisiteResult(satisfied=True, message="FailingStub available")

    def authenticate(self, config: EngagementConfig) -> AuthContext | None:
        return None

    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput:
        raise RuntimeError("Simulated tool failure for partial-failure test")

    def validate_raw(self, raw: ResolvedManifest) -> None:  # pragma: no cover
        return

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:  # pragma: no cover
        return []

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:  # pragma: no cover
        return []


# Fixtures --------------------------------------------------------------


@pytest.fixture
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point GxAssessMS at a tmp_path data directory for this test only."""
    data_dir = tmp_path / "gxassessms-data"
    data_dir.mkdir()
    monkeypatch.setenv("GXASSESSMS_DATA_DIR", str(data_dir))
    return data_dir


@pytest.fixture
def normalization_rules() -> dict[str, Any]:
    rules_path = (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "policy"
        / "rules"
        / "normalization.yaml"
    )
    with open(rules_path, encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


@pytest.fixture
def consolidation_rules() -> dict[str, Any]:
    rules_path = (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "policy"
        / "rules"
        / "consolidation.yaml"
    )
    with open(rules_path, encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


@pytest.fixture
def e2e_config() -> EngagementConfig:
    """Minimal engagement config enabling ScubaGear with JSON marker output."""
    return EngagementConfig(
        client_name="E2E Test Client",
        tenant_id="e2e-tenant-00000000-0000-0000-0000-000000000000",
        auth=AuthConfig(
            method="client_credential",
            tenant_id="e2e-tenant-00000000-0000-0000-0000-000000000000",
            client_id="e2e-client-00000000-0000-0000-0000-000000000000",
            client_secret_env="GXASSESSMS_TEST_CLIENT_SECRET",  # pragma: allowlist secret
        ),
        tools={
            "scubagear": ToolConfig(enabled=True),
        },
        report_formats=["json_marker"],
        report_theme="basic",
    )


@pytest.fixture
def scubagear_adapter_with_fixture(
    monkeypatch: pytest.MonkeyPatch,
    isolated_data_dir: Path,
) -> ScubaGearAdapter:
    """ScubaGearAdapter that returns its bundled fixture instead of running PowerShell.

    Patches adapter.collect() to read from the bundled fixtures directory
    and stage it into the tmp data directory. Depends on isolated_data_dir
    explicitly so the closure captures the staging root -- avoids a hidden
    reliance on GXASSESSMS_DATA_DIR being set by another fixture.
    """
    fixtures_dir = (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "scubagear"
        / "fixtures"
    )
    scuba_results = fixtures_dir / "ScubaResults.json"
    assert scuba_results.exists(), f"ScubaGear fixture missing: {scuba_results}"

    adapter = ScubaGearAdapter()

    def fake_collect(config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput:
        # Stage the fixture into the isolated data directory and return a
        # CollectionOutput pointing at it. Mirrors what the real collect
        # does after PowerShell execution.
        data = scuba_results.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        staging_dir = isolated_data_dir / "fixture-stage"
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged = staging_dir / "ScubaResults.json"
        staged.write_bytes(data)

        return CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug=adapter.storage_slug,
            schema_version="1.0.0",
            timestamp=datetime.now(UTC),
            artifacts=[
                CollectedArtifact(
                    source_path=str(staged),
                    target_relpath="scubagear/ScubaResults.json",
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={"exit_code": 0, "duration_seconds": 0.1},
        )

    def fake_authenticate(_config: EngagementConfig) -> AuthContext | None:
        return None

    def fake_check_prerequisites() -> PrerequisiteResult:
        return PrerequisiteResult(satisfied=True, message="Fixture mode")

    monkeypatch.setattr(adapter, "collect", fake_collect)
    # Short-circuit prerequisite check -- fixtures do not need PowerShell.
    monkeypatch.setattr(adapter, "check_prerequisites", fake_check_prerequisites)
    monkeypatch.setattr(adapter, "authenticate", fake_authenticate)
    return adapter


@pytest.fixture
def db(isolated_data_dir: Path) -> DatabaseManager:
    """Real DatabaseManager pointed at the isolated data directory.

    The isolated_data_dir parameter is required so the env var is set
    before DatabaseManager() reads GXASSESSMS_DATA_DIR.
    """
    _ = isolated_data_dir  # force fixture evaluation order
    mgr = DatabaseManager()
    mgr.initialize()
    return mgr


@pytest.fixture
def engagement_repo(db: DatabaseManager) -> EngagementRepo:
    return EngagementRepo(db)


@pytest.fixture
def event_repo(db: DatabaseManager) -> EventRepo:
    return EventRepo(db)


@pytest.fixture
def finding_repo(db: DatabaseManager) -> FindingRepo:
    return FindingRepo(db)


@pytest.fixture
def coverage_repo(db: DatabaseManager) -> CoverageRepo:
    return CoverageRepo(db)


@pytest.fixture
def artifact_manager(isolated_data_dir: Path) -> ArtifactManager:
    engagements_root = isolated_data_dir / "engagements"
    engagements_root.mkdir(parents=True, exist_ok=True)
    return ArtifactManager(engagements_root)


@pytest.fixture
def orchestrator(
    db: DatabaseManager,
    engagement_repo: EngagementRepo,
    event_repo: EventRepo,
    finding_repo: FindingRepo,
    coverage_repo: CoverageRepo,
    artifact_manager: ArtifactManager,
    isolated_data_dir: Path,
) -> Orchestrator:
    """Build a real Orchestrator from the individual repo fixtures."""
    engagements_root = isolated_data_dir / "engagements"
    return Orchestrator(
        engagement_repo=engagement_repo,
        event_repo=event_repo,
        finding_repo=finding_repo,
        coverage_repo=coverage_repo,
        lock=EngagementLock(engagements_root),
        db=db,
        artifact_manager=artifact_manager,
    )


# End-to-end tests ------------------------------------------------------


class TestPipelineEndToEnd:
    """Full pipeline via Orchestrator against real ScubaGear fixtures."""

    def test_full_pipeline_reaches_complete(
        self,
        orchestrator: Orchestrator,
        engagement_repo: EngagementRepo,
        e2e_config: EngagementConfig,
        scubagear_adapter_with_fixture: ScubaGearAdapter,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """Full pipeline: CREATED -> COLLECT -> PARSE -> NORMALIZE -> CONSOLIDATE -> RENDER -> COMPLETE."""  # noqa: E501
        engagement_id = engagement_repo.create(
            client_name=e2e_config.client_name,
            tenant_id=e2e_config.tenant_id,
            config_snapshot=e2e_config.model_dump(),
        )

        norm_policy = DefaultNormalizationPolicy(rules=normalization_rules)
        consol_rule = DefaultConsolidationRule(
            policy=DefaultConsolidationPolicy(rules=consolidation_rules)
        )

        orchestrator.run(
            engagement_id=engagement_id,
            config=e2e_config,
            adapters=[scubagear_adapter_with_fixture],
            normalization_policy=norm_policy,
            consolidation_rule=consol_rule,
            qa_strategy=NoOpQAStrategy(),
            renderers=[JsonMarkerRenderer()],
        )

        engagement = engagement_repo.get(engagement_id)
        assert engagement is not None
        assert engagement["state"] == EngagementState.COMPLETE.value

    def test_pipeline_persists_findings_and_coverage(
        self,
        orchestrator: Orchestrator,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
        coverage_repo: CoverageRepo,
        e2e_config: EngagementConfig,
        scubagear_adapter_with_fixture: ScubaGearAdapter,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """Consolidated findings and coverage records land in the DB."""
        engagement_id = engagement_repo.create(
            client_name=e2e_config.client_name,
            tenant_id=e2e_config.tenant_id,
            config_snapshot=e2e_config.model_dump(),
        )
        orchestrator.run(
            engagement_id=engagement_id,
            config=e2e_config,
            adapters=[scubagear_adapter_with_fixture],
            normalization_policy=DefaultNormalizationPolicy(rules=normalization_rules),
            consolidation_rule=DefaultConsolidationRule(
                policy=DefaultConsolidationPolicy(rules=consolidation_rules)
            ),
            qa_strategy=NoOpQAStrategy(),
            renderers=[JsonMarkerRenderer()],
        )

        consolidated = finding_repo.get_consolidated(engagement_id)
        assert len(consolidated) > 0, "No consolidated findings persisted"

        # Data integrity: every row has required fields populated
        for row in consolidated:
            assert row["finding_instance_id"]
            assert row["finding_key"]
            assert row["severity"] in {s.value for s in Severity}
            # category is stored as the enum .value (display name like
            # "Identity & Access") by FindingRepo.save_consolidated_findings.
            assert row["category"] in {c.value for c in Category}
            # sources is JSON-encoded list; must be non-empty
            raw_sources = row["sources"]
            decoded = json.loads(raw_sources) if isinstance(raw_sources, str) else raw_sources
            assert isinstance(decoded, list)
            sources = cast(list[Any], decoded)
            assert len(sources) >= 1

        coverage = coverage_repo.get_for_engagement(engagement_id)
        # ScubaGear declares coverage_export capability, so coverage records exist.
        assert isinstance(coverage, list)

    def test_pipeline_writes_render_output(
        self,
        orchestrator: Orchestrator,
        engagement_repo: EngagementRepo,
        artifact_manager: ArtifactManager,
        e2e_config: EngagementConfig,
        scubagear_adapter_with_fixture: ScubaGearAdapter,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """JsonMarkerRenderer produces a file in the engagement output directory."""
        engagement_id = engagement_repo.create(
            client_name=e2e_config.client_name,
            tenant_id=e2e_config.tenant_id,
            config_snapshot=e2e_config.model_dump(),
        )
        orchestrator.run(
            engagement_id=engagement_id,
            config=e2e_config,
            adapters=[scubagear_adapter_with_fixture],
            normalization_policy=DefaultNormalizationPolicy(rules=normalization_rules),
            consolidation_rule=DefaultConsolidationRule(
                policy=DefaultConsolidationPolicy(rules=consolidation_rules)
            ),
            qa_strategy=NoOpQAStrategy(),
            renderers=[JsonMarkerRenderer()],
        )

        # JsonMarkerRenderer writes <engagement_id>.json into the reports dir.
        engagement_dir = artifact_manager.get_engagement_dir(engagement_id)
        # Reports are written under the engagement dir; find the marker file.
        matches = list(engagement_dir.rglob(f"{engagement_id}.json"))
        assert matches, f"No render output found under {engagement_dir}"
        data = json.loads(matches[0].read_text(encoding="utf-8"))
        assert data["rendered"] is True
        assert data["engagement_id"] == engagement_id
        assert data["tool_sources"]

    def test_pipeline_with_partial_adapter_failure(
        self,
        orchestrator: Orchestrator,
        engagement_repo: EngagementRepo,
        e2e_config: EngagementConfig,
        scubagear_adapter_with_fixture: ScubaGearAdapter,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """One failing adapter does not abort the pipeline.

        The real ScubaGear adapter's output still flows through to RENDER.
        """
        engagement_id = engagement_repo.create(
            client_name=e2e_config.client_name,
            tenant_id=e2e_config.tenant_id,
            config_snapshot=e2e_config.model_dump(),
        )
        orchestrator.run(
            engagement_id=engagement_id,
            config=e2e_config,
            adapters=[scubagear_adapter_with_fixture, FailingStubAdapter()],
            normalization_policy=DefaultNormalizationPolicy(rules=normalization_rules),
            consolidation_rule=DefaultConsolidationRule(
                policy=DefaultConsolidationPolicy(rules=consolidation_rules)
            ),
            qa_strategy=NoOpQAStrategy(),
            renderers=[JsonMarkerRenderer()],
        )
        engagement = engagement_repo.get(engagement_id)
        assert engagement["state"] == EngagementState.COMPLETE.value

    def test_pipeline_pure_stage_smoke(
        self,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """Pure-function smoke: normalize -> consolidate with empty adapter maps.

        Complements the orchestrator-driven tests by exercising the stage
        functions directly with empty adapter_severity_map / adapter_category_map
        / adapter_dedup_keys. This verifies the YAML-rule fallback branches
        of DefaultNormalizationPolicy that the runner-driven tests (which
        always pass the adapter's own maps) do not exercise.
        """
        from gxassessms.pipeline.stages import consolidate, normalize

        observations = [
            ToolObservation(
                observation_id="scubagear:MS.AAD.3.1v1",
                tool=ToolSource.SCUBAGEAR,
                native_check_id="MS.AAD.3.1v1",
                title="MFA not enforced for admin roles.",
                native_severity="Shall",
                native_status="Fail",
                description="MFA must be enforced for all admin roles.",
                raw_data={"CheckId": "MS.AAD.3.1v1"},
                benchmark_refs=[],
            ),
            ToolObservation(
                observation_id="scubagear:MS.EXO.4.1v1",
                tool=ToolSource.SCUBAGEAR,
                native_check_id="MS.EXO.4.1v1",
                title="DKIM not configured for all domains.",
                native_severity="Should",
                native_status="Warning",
                description="DKIM should be configured.",
                raw_data={"CheckId": "MS.EXO.4.1v1"},
                benchmark_refs=[],
            ),
        ]
        norm_policy = DefaultNormalizationPolicy(rules=normalization_rules)
        findings = normalize(
            observations,
            norm_policy,
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert len(findings) == 2
        for f in findings:
            assert isinstance(f, Finding)
            assert f.severity in Severity
            assert f.category in Category
            assert len(f.dedup_keys) >= 1

        consol_rule = DefaultConsolidationRule(
            policy=DefaultConsolidationPolicy(rules=consolidation_rules)
        )
        consolidated = consolidate(findings, consol_rule)
        assert len(consolidated) <= len(findings)
        for cf in consolidated:
            assert isinstance(cf, ConsolidatedFinding)
            assert cf.finding_instance_id
            assert cf.finding_key
            assert len(cf.sources) >= 1
