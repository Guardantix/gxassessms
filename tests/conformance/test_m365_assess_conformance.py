"""M365-Assess adapter conformance tests.

Subclasses AdapterConformanceSuite with M365-Assess-specific fixtures.
All conformance assertions are inherited from the base class.
"""

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from gxassessms.adapters.m365_assess import M365AssessAdapter
from gxassessms.adapters.m365_assess.adapter import _CSV_SUFFIX
from gxassessms.core.contracts.errors import ParseError, RawOutputValidationError
from gxassessms.core.domain.enums import FindingStatus, ToolSource
from gxassessms.core.domain.models import (
    ArtifactRecord,
    ResolvedManifest,
)
from tests.conformance.adapter_suite import AdapterConformanceSuite

FIXTURE_DIR = (
    Path(__file__).parent.parent.parent
    / "src"
    / "gxassessms"
    / "adapters"
    / "m365_assess"
    / "fixtures"
)

_MANIFEST_TIMESTAMP = datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC)


def _make_manifest(
    file_manifest: dict[str, ArtifactRecord],
    execution_metadata: dict[str, str] | None = None,
) -> ResolvedManifest:
    return ResolvedManifest(
        tool=ToolSource.M365_ASSESS,
        tool_slug="m365-assess",
        schema_version="1.0.0",
        manifest_version="1.0.0",
        timestamp=_MANIFEST_TIMESTAMP,
        file_manifest=file_manifest,
        execution_metadata=execution_metadata or {},
    )


class TestM365AssessConformance(AdapterConformanceSuite):
    """M365-Assess-specific conformance tests."""

    @pytest.fixture
    def adapter(self) -> M365AssessAdapter:
        return M365AssessAdapter()

    @pytest.fixture
    def resolved_manifest(self, adapter: M365AssessAdapter, tmp_path: Path) -> ResolvedManifest:
        """Build a ResolvedManifest pointing at M365-Assess fixture files.

        CSV files are copied with names that match the adapter's expected
        ``*-Security-Config.csv`` suffix so that ``validate_raw`` can find them.
        The controls/ directory is placed as a sibling of the CSV files so that
        ``_locate_m365_assess_controls`` resolves via strategy #1 (sibling dir).
        """
        # Copy CSV fixtures to tmp_path with the suffix the adapter expects
        csv_pairs = [
            ("entra_security_config.csv", "Entra-Security-Config.csv"),
            ("exo_security_config.csv", "EXO-Security-Config.csv"),
        ]
        csv_paths: list[Path] = []
        for src_name, dst_name in csv_pairs:
            src = FIXTURE_DIR / src_name
            dst = tmp_path / dst_name
            shutil.copy2(src, dst)
            csv_paths.append(dst)

        # Copy controls/ directory as a sibling of the CSV files so that
        # _locate_m365_assess_controls resolves via strategy #1 (controls/ sibling)
        controls_dir = tmp_path / "controls"
        controls_dir.mkdir()
        shutil.copy2(
            FIXTURE_DIR / "risk_severity_sample.json",
            controls_dir / "risk-severity.json",
        )
        shutil.copy2(
            FIXTURE_DIR / "registry_sample.json",
            controls_dir / "registry.json",
        )

        # Build file_manifest with real SHA-256 hashes
        file_manifest: dict[str, ArtifactRecord] = {}
        for csv_path in csv_paths:
            sha = hashlib.sha256(csv_path.read_bytes()).hexdigest()
            file_manifest[str(csv_path)] = ArtifactRecord(encoding="utf-8", sha256=sha)

        return ResolvedManifest(
            tool=ToolSource.M365_ASSESS,
            tool_slug="m365-assess",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest=file_manifest,
            execution_metadata={
                "output_dir": str(tmp_path),
            },
        )

    @pytest.fixture
    def normalization_rules(self) -> dict[str, Any]:
        """Load normalization rules from the YAML file."""
        rules_path = (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "policy"
            / "rules"
            / "normalization.yaml"
        )
        with open(rules_path) as f:
            return yaml.safe_load(f)

    # M365-Assess-specific tests

    def test_all_six_statuses_parseable(
        self,
        adapter: M365AssessAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """Fixture covers Pass, Fail, Warning, Review, Info statuses."""
        observations = adapter.parse(resolved_manifest)
        statuses = {o.native_status for o in observations}

        assert FindingStatus.PASS in statuses
        assert FindingStatus.FAIL in statuses
        assert FindingStatus.WARNING in statuses
        assert FindingStatus.MANUAL in statuses  # Review -> MANUAL
        assert FindingStatus.NOT_APPLICABLE in statuses  # Info -> N/A

    def test_observation_ids_prefixed(
        self,
        adapter: M365AssessAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        observations = adapter.parse(resolved_manifest)
        for obs in observations:
            assert obs.observation_id.startswith("m365assess:")

    def test_coverage_raises_parse_error_on_io_error(
        self,
        tmp_path: Path,
    ) -> None:
        """coverage() must raise ParseError (not raw OSError) on CSV I/O failure.

        Uses a subclass with no-op validate_raw to isolate coverage() I/O error handling,
        since coverage() normally calls validate_raw() first (which also opens the file).
        """

        class BypassValidation(M365AssessAdapter):
            def validate_raw(self, raw: ResolvedManifest) -> None:
                pass  # Allow coverage() to run directly against missing file

        adapter_under_test = BypassValidation()
        ghost_csv = tmp_path / f"Ghost{_CSV_SUFFIX}"
        # File does not exist: open() inside coverage() will raise FileNotFoundError (OSError)

        raw = _make_manifest({str(ghost_csv): ArtifactRecord(encoding="utf-8", sha256="a" * 64)})
        with pytest.raises(ParseError, match="Failed to read coverage data"):
            adapter_under_test.coverage(raw)

    def test_coverage_deduplicates_sub_checks(
        self,
        adapter: M365AssessAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """Sub-checks .1/.2 must collapse to one CoverageRecord with base CheckId."""
        records = adapter.coverage(resolved_manifest)
        control_ids = [r.control_id for r in records]
        # ENTRA-AUTHMETHOD-001.1 and .2 in fixture must collapse to one record
        authmethod_records = [rid for rid in control_ids if "ENTRA-AUTHMETHOD-001" in rid]
        assert len(authmethod_records) == 1, (
            f"Expected 1 ENTRA-AUTHMETHOD-001 record, got {authmethod_records}"
        )
        # No record should have a .N suffix (sub-check pattern)
        for rid in control_ids:
            parts = rid.split("-")
            assert "." not in parts[-1], f"Sub-check suffix not stripped from control_id: {rid}"

    def test_validate_raw_rejects_empty_manifest(
        self,
        adapter: M365AssessAdapter,
    ) -> None:
        """Empty file_manifest must raise RawOutputValidationError."""
        raw = _make_manifest({})
        with pytest.raises(RawOutputValidationError, match="empty"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_manifest_with_no_csvs(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """Manifest with only JSON files (no CSVs) must raise RawOutputValidationError."""
        json_file = tmp_path / "registry.json"
        json_file.write_text('{"checks": []}')
        sha = hashlib.sha256(json_file.read_bytes()).hexdigest()
        raw = _make_manifest({str(json_file): ArtifactRecord(encoding="utf-8", sha256=sha)})
        with pytest.raises(RawOutputValidationError, match=r"Security-Config\.csv"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_header_only_csv(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """CSV with headers but no data rows must raise RawOutputValidationError."""
        header_csv = tmp_path / f"Entra{_CSV_SUFFIX}"
        header_csv.write_text(
            "Category,Setting,CurrentValue,RecommendedValue,Status,CheckId,Remediation\n"
        )
        sha = hashlib.sha256(header_csv.read_bytes()).hexdigest()
        raw = _make_manifest({str(header_csv): ArtifactRecord(encoding="utf-8", sha256=sha)})
        with pytest.raises(RawOutputValidationError, match="no data rows"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_wrong_columns(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        bad_csv = tmp_path / f"Bad{_CSV_SUFFIX}"
        bad_csv.write_text('"WrongCol1","WrongCol2"\n"a","b"\n')
        sha = hashlib.sha256(bad_csv.read_bytes()).hexdigest()
        raw = _make_manifest({str(bad_csv): ArtifactRecord(encoding="utf-8", sha256=sha)})
        with pytest.raises(RawOutputValidationError, match="missing columns"):
            adapter.validate_raw(raw)

    def test_parse_resolves_controls_via_strategy_2_execution_metadata(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """Controls dir in execution_metadata (not a sibling) must parse correctly."""
        # CSV goes in tmp_path; controls go in a SEPARATE directory (no sibling match)
        csv_dir = tmp_path / "csvs"
        csv_dir.mkdir()
        controls_dir = tmp_path / "controls_elsewhere"
        controls_dir.mkdir()

        csv_dst = csv_dir / f"Entra{_CSV_SUFFIX}"
        shutil.copy2(FIXTURE_DIR / "entra_security_config.csv", csv_dst)
        shutil.copy2(FIXTURE_DIR / "risk_severity_sample.json", controls_dir / "risk-severity.json")
        shutil.copy2(FIXTURE_DIR / "registry_sample.json", controls_dir / "registry.json")

        sha = hashlib.sha256(csv_dst.read_bytes()).hexdigest()
        raw = _make_manifest(
            {str(csv_dst): ArtifactRecord(encoding="utf-8", sha256=sha)},
            execution_metadata={"controls_dir": str(controls_dir)},
        )
        observations = adapter.parse(raw)
        assert len(observations) > 0

    def test_parse_raises_on_invalid_explicit_controls_dir(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """Explicit controls_dir that doesn't exist must raise ParseError immediately."""
        csv_dst = tmp_path / f"Entra{_CSV_SUFFIX}"
        shutil.copy2(FIXTURE_DIR / "entra_security_config.csv", csv_dst)
        sha = hashlib.sha256(csv_dst.read_bytes()).hexdigest()
        raw = _make_manifest(
            {str(csv_dst): ArtifactRecord(encoding="utf-8", sha256=sha)},
            execution_metadata={"controls_dir": str(tmp_path / "does_not_exist")},
        )
        with pytest.raises(ParseError, match="controls_dir does not exist"):
            adapter.parse(raw)

    def test_parse_resolves_controls_via_strategy_3_manifest_scan(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """Controls files in file_manifest (no sibling dir, no execution_metadata) must work."""
        # CSV and controls all in separate dirs, no sibling relationship
        csv_dir = tmp_path / "csvs"
        controls_dir = tmp_path / "controls"
        csv_dir.mkdir()
        controls_dir.mkdir()

        csv_dst = csv_dir / f"Entra{_CSV_SUFFIX}"
        sev_dst = controls_dir / "risk-severity.json"
        reg_dst = controls_dir / "registry.json"

        shutil.copy2(FIXTURE_DIR / "entra_security_config.csv", csv_dst)
        shutil.copy2(FIXTURE_DIR / "risk_severity_sample.json", sev_dst)
        shutil.copy2(FIXTURE_DIR / "registry_sample.json", reg_dst)

        def _sha(p: Path) -> str:
            return hashlib.sha256(p.read_bytes()).hexdigest()

        raw = _make_manifest(
            {
                str(csv_dst): ArtifactRecord(encoding="utf-8", sha256=_sha(csv_dst)),
                str(sev_dst): ArtifactRecord(encoding="utf-8", sha256=_sha(sev_dst)),
                str(reg_dst): ArtifactRecord(encoding="utf-8", sha256=_sha(reg_dst)),
            }
        )
        observations = adapter.parse(raw)
        assert len(observations) > 0

    def test_parse_raises_when_risk_severity_json_missing(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """controls/ dir present but risk-severity.json absent must raise ParseError.

        Previously, parse() silently substituted {} when the file was missing,
        downgrading all severities to Medium without any validation error.
        """
        csv_dst = tmp_path / f"Entra{_CSV_SUFFIX}"
        shutil.copy2(FIXTURE_DIR / "entra_security_config.csv", csv_dst)

        controls_dir = tmp_path / "controls"
        controls_dir.mkdir()
        shutil.copy2(FIXTURE_DIR / "registry_sample.json", controls_dir / "registry.json")
        # risk-severity.json intentionally omitted

        sha = hashlib.sha256(csv_dst.read_bytes()).hexdigest()
        raw = _make_manifest({str(csv_dst): ArtifactRecord(encoding="utf-8", sha256=sha)})
        with pytest.raises(ParseError, match="Failed to load M365-Assess metadata"):
            adapter.parse(raw)

    def test_parse_raises_when_registry_json_missing(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """controls/ dir present but registry.json absent must raise ParseError.

        Previously, parse() silently substituted {} when the file was missing,
        dropping all benchmark references without any validation error.
        """
        csv_dst = tmp_path / f"Entra{_CSV_SUFFIX}"
        shutil.copy2(FIXTURE_DIR / "entra_security_config.csv", csv_dst)

        controls_dir = tmp_path / "controls"
        controls_dir.mkdir()
        shutil.copy2(FIXTURE_DIR / "risk_severity_sample.json", controls_dir / "risk-severity.json")
        # registry.json intentionally omitted

        sha = hashlib.sha256(csv_dst.read_bytes()).hexdigest()
        raw = _make_manifest({str(csv_dst): ArtifactRecord(encoding="utf-8", sha256=sha)})
        with pytest.raises(ParseError, match="Failed to load M365-Assess metadata"):
            adapter.parse(raw)

    def test_parse_raises_when_controls_unreachable(
        self,
        adapter: M365AssessAdapter,
        tmp_path: Path,
    ) -> None:
        """All three strategies failing must raise ParseError with clear message."""
        csv_dst = tmp_path / f"Entra{_CSV_SUFFIX}"
        shutil.copy2(FIXTURE_DIR / "entra_security_config.csv", csv_dst)
        sha = hashlib.sha256(csv_dst.read_bytes()).hexdigest()
        # No controls/ sibling, no execution_metadata hint, no JSON in manifest
        raw = _make_manifest({str(csv_dst): ArtifactRecord(encoding="utf-8", sha256=sha)})
        with pytest.raises(ParseError, match="Cannot locate M365-Assess controls directory"):
            adapter.parse(raw)
