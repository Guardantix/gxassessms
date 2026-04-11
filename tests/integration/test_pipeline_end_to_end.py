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

from gxassessms.adapters.scubagear import ScubaGearAdapter
from gxassessms.consolidation.rules import DefaultConsolidationRule
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.contracts.errors import PersistenceError
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
    monkeypatch.setattr(adapter, "check_prerequisites", fake_check_prerequisites)
    monkeypatch.setattr(adapter, "authenticate", fake_authenticate)
    return adapter


@pytest.fixture
def db(isolated_data_dir: Path) -> DatabaseManager:
    """Real DatabaseManager pointed at the isolated data directory.

    The isolated_data_dir parameter is required so the env var is set
    before DatabaseManager() reads GXASSESSMS_DATA_DIR.
    """
    _ = isolated_data_dir  # force fixture evaluation; env var must be set before DatabaseManager()
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

    def _run_pipeline(
        self,
        orchestrator: Orchestrator,
        engagement_repo: EngagementRepo,
        config: EngagementConfig,
        adapters: list[Any],
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> str:
        """Create an engagement and run the full pipeline. Returns engagement_id."""
        engagement_id = engagement_repo.create(
            client_name=config.client_name,
            tenant_id=config.tenant_id,
            config_snapshot=config.model_dump(),
        )
        orchestrator.run(
            engagement_id=engagement_id,
            config=config,
            adapters=adapters,
            normalization_policy=DefaultNormalizationPolicy(rules=normalization_rules),
            consolidation_rule=DefaultConsolidationRule(
                policy=DefaultConsolidationPolicy(rules=consolidation_rules)
            ),
            qa_strategy=NoOpQAStrategy(),
            renderers=[JsonMarkerRenderer()],
        )
        return engagement_id

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
        engagement_id = self._run_pipeline(
            orchestrator,
            engagement_repo,
            e2e_config,
            [scubagear_adapter_with_fixture],
            normalization_rules,
            consolidation_rules,
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
        engagement_id = self._run_pipeline(
            orchestrator,
            engagement_repo,
            e2e_config,
            [scubagear_adapter_with_fixture],
            normalization_rules,
            consolidation_rules,
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
        engagement_id = self._run_pipeline(
            orchestrator,
            engagement_repo,
            e2e_config,
            [scubagear_adapter_with_fixture],
            normalization_rules,
            consolidation_rules,
        )

        engagement_dir = artifact_manager.get_engagement_dir(engagement_id)
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
        engagement_id = self._run_pipeline(
            orchestrator,
            engagement_repo,
            e2e_config,
            [scubagear_adapter_with_fixture, FailingStubAdapter()],
            normalization_rules,
            consolidation_rules,
        )
        engagement = engagement_repo.get(engagement_id)
        assert engagement["state"] == EngagementState.COMPLETE.value

    def test_replay_after_db_wipe_recovers_from_filesystem_snapshot(
        self,
        isolated_data_dir: Path,
        orchestrator: Orchestrator,
        engagement_repo: EngagementRepo,
        e2e_config: EngagementConfig,
        scubagear_adapter_with_fixture: ScubaGearAdapter,
        artifact_manager: ArtifactManager,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """Runbook step 3 contract: after a full pipeline run plus a DB
        wipe, `mseco replay <id> --from parse` recovers end-to-end.

        Exercises:
        1. `_load_config_for_replay` falls back to the filesystem snapshot
           when the DB row is gone.
        2. `_rehydrate_engagement_if_missing` reinserts the row from the
           recovered config snapshot so downstream state transitions find
           a row to update.
        3. A fresh `Orchestrator` built against the wiped DB then runs
           `reset_for_rerun` + `run_from(Stage.PARSE)` to completion,
           loading raw outputs from disk and re-driving NORMALIZE →
           CONSOLIDATE → QA_REVIEW → RENDER against the fresh DB.
        """
        from gxassessms.cli.commands.replay import (
            _load_config_for_replay,
            _rehydrate_engagement_if_missing,
        )
        from gxassessms.pipeline.stages import Stage

        # 1. Run full pipeline to completion.
        engagement_id = self._run_pipeline(
            orchestrator,
            engagement_repo,
            e2e_config,
            [scubagear_adapter_with_fixture],
            normalization_rules,
            consolidation_rules,
        )

        # 2. Verify the mirror was written during COLLECT.
        eng_dir = artifact_manager.get_engagement_dir(engagement_id)
        snapshot_file = eng_dir / "config_snapshot.json"
        assert snapshot_file.exists(), (
            "mirror_config_snapshot_from_db should have written config_snapshot.json during COLLECT"
        )
        stored = json.loads(snapshot_file.read_text(encoding="utf-8"))
        assert stored["client_name"] == e2e_config.client_name, (
            "mirror file should contain the engagement's client_name"
        )

        # 3. Wipe the DB file (simulates the runbook's manual-recovery step 2).
        db_path = isolated_data_dir / "engagements.db"
        if db_path.exists():
            db_path.unlink()
        # Also drop any SQLite WAL/SHM files (they otherwise re-hydrate the DB).
        for suffix in ("-wal", "-shm"):
            sidecar = db_path.with_name(db_path.name + suffix)
            if sidecar.exists():
                sidecar.unlink()

        # 4. Re-initialize a fresh DB + repos + orchestrator against the
        #    same data directory. `replay_cmd` builds these itself via
        #    the _helpers factories; the test mirrors that shape directly.
        fresh_db = DatabaseManager()
        fresh_db.initialize()
        fresh_engagement_repo = EngagementRepo(fresh_db)
        fresh_event_repo = EventRepo(fresh_db)
        fresh_finding_repo = FindingRepo(fresh_db)
        fresh_coverage_repo = CoverageRepo(fresh_db)
        engagements_root = isolated_data_dir / "engagements"
        fresh_lock = EngagementLock(engagements_root)
        fresh_orchestrator = Orchestrator(
            engagement_repo=fresh_engagement_repo,
            event_repo=fresh_event_repo,
            finding_repo=fresh_finding_repo,
            coverage_repo=fresh_coverage_repo,
            lock=fresh_lock,
            db=fresh_db,
            artifact_manager=artifact_manager,
        )

        # Sanity: the engagement really is gone from the fresh DB.
        with pytest.raises(PersistenceError, match="not found"):
            fresh_engagement_repo.get(engagement_id)

        # 5. DR config loading: fall back to the filesystem snapshot.
        config, loaded_from_fallback = _load_config_for_replay(
            engagement_id, fresh_engagement_repo, artifact_manager
        )
        assert loaded_from_fallback is True
        assert config.client_name == e2e_config.client_name
        assert config.tenant_id == e2e_config.tenant_id

        # 6. DR rehydration: reinsert the engagement row from the snapshot.
        rehydrated = _rehydrate_engagement_if_missing(
            engagement_id,
            config,
            fresh_engagement_repo,
            str(eng_dir),
        )
        assert rehydrated is True
        row = fresh_engagement_repo.get(engagement_id)
        assert row["client_name"] == e2e_config.client_name
        assert row["tenant_id"] == e2e_config.tenant_id
        # Row seeded at CREATED; reset_for_rerun will force-update it.
        assert row["state"] == EngagementState.CREATED.value

        # 7. Full replay from PARSE against the fresh DB. This is the path
        #    the runbook tells operators to execute after a DB wipe.
        fresh_orchestrator.reset_for_rerun(engagement_id, Stage.PARSE)
        fresh_orchestrator.run_from(
            engagement_id=engagement_id,
            config=config,
            start_stage=Stage.PARSE,
            adapters=[scubagear_adapter_with_fixture],
            normalization_policy=DefaultNormalizationPolicy(rules=normalization_rules),
            consolidation_rule=DefaultConsolidationRule(
                policy=DefaultConsolidationPolicy(rules=consolidation_rules)
            ),
            qa_strategy=NoOpQAStrategy(),
            renderers=[JsonMarkerRenderer()],
        )

        # 8. Final state is COMPLETE and findings were re-persisted to the
        #    fresh DB (proving the replay actually re-executed every
        #    downstream stage, not just the state transitions).
        final_row = fresh_engagement_repo.get(engagement_id)
        assert final_row["state"] == EngagementState.COMPLETE.value
        assert fresh_finding_repo.get_consolidated(engagement_id), (
            "Replay from PARSE should have re-populated consolidated findings"
        )

    def test_replay_after_db_wipe_rejects_non_parse_start_stage(
        self,
        isolated_data_dir: Path,
        orchestrator: Orchestrator,
        engagement_repo: EngagementRepo,
        e2e_config: EngagementConfig,
        scubagear_adapter_with_fixture: ScubaGearAdapter,
        artifact_manager: ArtifactManager,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """DR replay only supports --from parse.

        CONSOLIDATE/QA/RENDER resume paths verify the event journal, which
        is empty after a DB wipe. replay_cmd rejects those start stages
        with a clear error rather than letting them fail later with a
        confusing `upstream stage never completed` error. This test
        exercises the gate at the CliRunner level so the exit-code and
        user-facing message are both asserted.
        """
        from click.testing import CliRunner

        from gxassessms.cli.commands.replay import replay_cmd

        # 1. Run a full pipeline so the engagement directory + config
        #    snapshot file exist on disk.
        engagement_id = self._run_pipeline(
            orchestrator,
            engagement_repo,
            e2e_config,
            [scubagear_adapter_with_fixture],
            normalization_rules,
            consolidation_rules,
        )

        # 2. Wipe the DB to force the DR fallback path in replay_cmd.
        db_path = isolated_data_dir / "engagements.db"
        if db_path.exists():
            db_path.unlink()
        for suffix in ("-wal", "-shm"):
            sidecar = db_path.with_name(db_path.name + suffix)
            if sidecar.exists():
                sidecar.unlink()

        # 3. Invoke `mseco replay --from consolidate`. replay_cmd detects
        #    the DR fallback, sees start_stage != PARSE, and exits 1 with
        #    the expected error message.
        runner = CliRunner()
        result = runner.invoke(
            replay_cmd,
            [engagement_id, "--from", "consolidate"],
        )
        assert result.exit_code == 1
        # Assert on short, wrap-safe substrings: Rich may soft-wrap the
        # full error message on narrow terminals in CI.
        assert "cannot be replayed" in result.output
        assert "--from parse" in result.output

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
