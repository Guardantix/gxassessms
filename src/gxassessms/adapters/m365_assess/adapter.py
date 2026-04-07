"""M365-Assess adapter -- CSV-based multi-framework M365 security assessment.

M365-Assess ships as a standalone PowerShell script (not a PSGallery module).
Collection uses ``run_powershell()`` directly rather than ``run_verified_powershell``
because there is no module provenance hash to verify.  Argument allowlist validation
and ``shell=False`` still apply; the distinction is that the script file itself is
not hash-checked at runtime -- integrity depends on the operator controlling the
``script_dir`` path.
"""

from __future__ import annotations

import csv
import logging
import time
from pathlib import Path

from gxassessms.adapters._base import (
    parse_extra_args,
    run_powershell,
    validate_extra_args,
)
from gxassessms.adapters.m365_assess.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
    extract_base_check_id,
)
from gxassessms.adapters.m365_assess.parser import (
    load_registry,
    load_risk_severity,
    parse_security_config_csv,
)
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    ParseError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.enums import Category, CoverageStatus, Severity, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CollectedArtifact,
    CollectionOutput,
    CoverageRecord,
    ResolvedManifest,
    ToolObservation,
)
from gxassessms.core.security.permissions import secure_mkdir

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = "1.0.0"
_DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes
_CSV_SUFFIX = "-Security-Config.csv"
_EXPECTED_COLUMNS: frozenset[str] = frozenset(
    {"Category", "Setting", "CurrentValue", "RecommendedValue", "Status", "CheckId", "Remediation"}
)
_REQUIRED_PS_MODULES: tuple[str, ...] = (
    "Microsoft.Graph.Authentication",
    "ExchangeOnlineManagement",
)


class M365AssessAdapter:
    """ToolAdapter implementation for M365-Assess (multi-framework M365 security assessment)."""

    tool_name: str = "M365_Assess"
    storage_slug: str = "m365-assess"
    tool_source: ToolSource = ToolSource.M365_ASSESS
    capabilities: frozenset[str] = frozenset(
        {"collect", "parse", "prerequisites", "coverage_export", "benchmark_mapping"}
    )

    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify PowerShell is available and required PS modules are installed."""
        # 1. Check PowerShell is accessible
        try:
            run_powershell(
                script="$PSVersionTable.PSVersion.ToString()",
                arguments=None,
                timeout_seconds=30,
                adapter_name=self.tool_name,
                engagement_id="",
            )
        except CollectionError as exc:
            return PrerequisiteResult(
                satisfied=False,
                message=f"PowerShell not available: {exc.message}",
            )

        # 2. Check required PS modules
        missing: list[str] = []
        for module in _REQUIRED_PS_MODULES:
            try:
                result = run_powershell(
                    script=(
                        f"Get-Module -ListAvailable -Name '{module}' "
                        "| Select-Object -First 1 -ExpandProperty Name"
                    ),
                    arguments=None,
                    timeout_seconds=30,
                    adapter_name=self.tool_name,
                    engagement_id="",
                )
                stdout = result.stdout.decode(errors="replace").strip()
                if not stdout:
                    missing.append(module)
            except CollectionError as exc:
                return PrerequisiteResult(
                    satisfied=False,
                    message=f"Cannot verify PS module '{module}': {exc.message}",
                )

        if missing:
            return PrerequisiteResult(
                satisfied=False,
                message=f"Missing required PowerShell modules: {', '.join(missing)}",
            )

        return PrerequisiteResult(
            satisfied=True,
            message="PowerShell and required modules are available",
        )

    def authenticate(self, config: EngagementConfig) -> AuthContext | None:
        """No-op: M365-Assess handles authentication internally."""
        return None

    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput:
        """Invoke M365-Assess script and collect CSV output.

        Raises CollectionError on PowerShell failure, timeout, or missing output.
        """
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.hashing import sha256_file

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "M365-Assess adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        output_dir = Path(tc.output_dir)
        secure_mkdir(output_dir, parents=True, exist_ok=True)
        timeout = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        # Resolve script path.  When script_dir is configured, build an absolute
        # path so the script is discoverable regardless of the process CWD.
        if tc.script_dir:
            script_path = f"{tc.script_dir}\\Invoke-M365Assessment.ps1"
        else:
            script_path = ".\\Invoke-M365Assessment.ps1"

        # Build script invocation.  Use the call operator (&) with single-quoted
        # path so PowerShell treats it as a literal string rather than splitting
        # on spaces -- necessary for paths that include spaces in directory names.
        script_parts: list[str] = [
            f"& '{script_path}' -TenantId '{config.tenant_id}'",
            f"-OutputPath '{output_dir}'",
        ]

        switches: dict[str, bool] = {}
        if tc.extra_args:
            validated = validate_extra_args(tc.extra_args)
            extra_named, switches = parse_extra_args(validated)
            for name, value in extra_named.items():
                script_parts.append(f"-{name} '{value}'")
            for name in switches:
                script_parts.append(f"-{name}")

        script = " ".join(script_parts)

        # Record wall-clock time before invoking the script so we can detect
        # new or overwritten CSVs by mtime comparison.  M365-Assess uses stable
        # filenames (e.g. Entra-Security-Config.csv), so path-presence alone
        # cannot distinguish a fresh run from a pre-existing stale file.
        pre_run_ts = time.time()

        run_powershell(
            script=script,
            arguments=None,
            timeout_seconds=timeout,
            adapter_name=self.tool_name,
            engagement_id="",
        )

        # Discover CSV output files written or updated during this run.
        # A small clock-skew allowance (1 s) guards against filesystem
        # timestamp granularity on FAT/exFAT volumes.
        csv_files = [
            f
            for f in output_dir.iterdir()
            if f.is_file() and f.name.endswith(_CSV_SUFFIX) and f.stat().st_mtime >= pre_run_ts - 1
        ]

        new_csvs = csv_files
        if not new_csvs:
            raise CollectionError(
                f"M365-Assess did not produce new CSV output in {output_dir}",
                adapter_name=self.tool_name,
            )

        artifacts: list[CollectedArtifact] = []
        for csv_file in sorted(new_csvs, key=lambda f: f.name):
            sha = sha256_file(csv_file)
            artifacts.append(
                CollectedArtifact(
                    source_path=str(csv_file),
                    target_relpath=f"{self.storage_slug}/{csv_file.name}",
                    encoding="utf-8",
                    sha256=sha,
                )
            )

        # Collect controls directory reference files so they are saved in the
        # raw-output manifest and available during replay via manifest scan
        # (strategy #3 in _locate_m365_assess_controls).
        # Resolution order:
        #   1. explicit controls_dir config
        #   2. script_dir/controls (when script_dir is set)
        #   3. CWD/controls (best-effort: script likely ran from here when no script_dir)
        #   4. output_dir/controls (last resort)
        if tc.controls_dir:
            controls_dir = Path(tc.controls_dir)
        elif tc.script_dir:
            controls_dir = Path(tc.script_dir) / "controls"
        else:
            cwd_controls = Path.cwd() / "controls"
            controls_dir = cwd_controls if cwd_controls.is_dir() else output_dir / "controls"
        for filename in ("risk-severity.json", "registry.json"):
            ctrl_file = controls_dir / filename
            if ctrl_file.is_file():
                sha = sha256_file(ctrl_file)
                artifacts.append(
                    CollectedArtifact(
                        source_path=str(ctrl_file),
                        target_relpath=f"{self.storage_slug}/controls/{filename}",
                        encoding="utf-8",
                        sha256=sha,
                    )
                )
        if not any(a.target_relpath.endswith("risk-severity.json") for a in artifacts):
            logger.warning(
                "M365-Assess controls directory not found at %s; "
                "parse will attempt to locate controls at runtime. "
                "Set 'controls_dir' in tool config to specify the path explicitly.",
                controls_dir,
            )

        logger.info(
            "M365-Assess collection complete. Output dir: %s, %d artifacts",
            output_dir,
            len(artifacts),
        )

        execution_metadata: dict[str, str] = {
            "script": "Invoke-M365Assessment.ps1",
            "tenant_id": config.tenant_id,
        }
        if tc.controls_dir:
            execution_metadata["controls_dir"] = str(Path(tc.controls_dir))

        return CollectionOutput(
            tool=ToolSource.M365_ASSESS,
            tool_slug=self.storage_slug,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            artifacts=artifacts,
            execution_metadata=execution_metadata,
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate M365-Assess raw output: manifest non-empty, CSVs present, correct headers."""
        if not raw.file_manifest:
            raise RawOutputValidationError(
                "M365-Assess file manifest is empty -- no output files found",
                adapter_name=self.tool_name,
            )

        csv_paths = [p for p in raw.file_manifest if p.endswith(_CSV_SUFFIX)]
        if not csv_paths:
            raise RawOutputValidationError(
                f"No *{_CSV_SUFFIX} files found in manifest",
                adapter_name=self.tool_name,
            )

        for csv_path in csv_paths:
            self._validate_csv_headers(Path(csv_path))

        logger.debug("M365-Assess raw output validated: %d CSV files", len(csv_paths))

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse M365-Assess CSV output into ToolObservations (validates first)."""
        self.validate_raw(raw)

        controls_dir = self._locate_m365_assess_controls(raw)
        severity_path = controls_dir / "risk-severity.json"
        registry_path = controls_dir / "registry.json"

        try:
            severity_lookup = load_risk_severity(severity_path)
            registry_lookup = load_registry(registry_path)
        except RawOutputValidationError as exc:
            raise ParseError(
                f"Failed to load M365-Assess metadata: {exc}",
                adapter_name=self.tool_name,
            ) from exc

        observations: list[ToolObservation] = []
        csv_paths = [p for p in raw.file_manifest if p.endswith(_CSV_SUFFIX)]

        for csv_path in csv_paths:
            try:
                obs = parse_security_config_csv(Path(csv_path), severity_lookup, registry_lookup)
                observations.extend(obs)
            except (OSError, UnicodeDecodeError, csv.Error) as exc:
                raise ParseError(
                    f"Failed to parse {Path(csv_path).name}: {exc}",
                    adapter_name=self.tool_name,
                ) from exc

        logger.info(
            "M365-Assess parse complete: %d observations from %d CSV files",
            len(observations),
            len(csv_paths),
        )
        return observations

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
        """Extract per-control coverage records, deduplicated by base CheckId.

        All M365-Assess checks with a valid CheckId are marked ASSESSED.
        Sub-checks (.N suffix) are collapsed to their base CheckId.
        """
        self.validate_raw(raw)

        seen_base_ids: set[str] = set()
        records: list[CoverageRecord] = []
        csv_paths = [p for p in raw.file_manifest if p.endswith(_CSV_SUFFIX)]

        for csv_path in csv_paths:
            try:
                with open(csv_path, newline="", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        check_id = (row.get("CheckId") or "").strip()
                        if not check_id:
                            continue
                        base_id = extract_base_check_id(check_id)
                        if base_id in seen_base_ids:
                            continue
                        seen_base_ids.add(base_id)

                        records.append(
                            CoverageRecord(
                                control_id=base_id,
                                tool=ToolSource.M365_ASSESS,
                                status=CoverageStatus.ASSESSED,
                                reason=None,
                            )
                        )
            except (OSError, UnicodeDecodeError, csv.Error) as exc:
                raise ParseError(
                    f"Failed to read coverage data from {Path(csv_path).name}: {exc}",
                    adapter_name=self.tool_name,
                ) from exc

        logger.info("M365-Assess coverage export: %d records", len(records))
        return records

    @property
    def severity_map(self) -> dict[tuple[str, str], Severity]:
        """(native_severity_str, canonical_status) -> Severity for NormalizationPolicy."""
        return SEVERITY_MAP

    @property
    def category_map(self) -> dict[str, Category]:
        """Collector prefix -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """Base CheckId -> canonical cross-reference ID for deduplication."""
        return DEDUP_KEY_RULES

    def _validate_csv_headers(self, csv_path: Path) -> None:
        """Validate a CSV file has correct headers and at least one data row."""
        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                if reader.fieldnames is None:
                    raise RawOutputValidationError(
                        f"CSV file has no header row: {csv_path.name}",
                        adapter_name=self.tool_name,
                    )

                actual = frozenset(reader.fieldnames)
                missing = _EXPECTED_COLUMNS - actual
                if missing:
                    raise RawOutputValidationError(
                        f"CSV {csv_path.name} missing columns: {sorted(missing)}",
                        adapter_name=self.tool_name,
                    )

                # Check for at least one data row
                first_row = next(reader, None)
                if first_row is None:
                    raise RawOutputValidationError(
                        f"CSV {csv_path.name} has headers but no data rows",
                        adapter_name=self.tool_name,
                    )
        except RawOutputValidationError:
            raise
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            raise RawOutputValidationError(
                f"Cannot read CSV file {csv_path.name}: {exc}",
                adapter_name=self.tool_name,
            ) from exc

    def _locate_m365_assess_controls(self, raw: ResolvedManifest) -> Path:
        """Locate controls dir: sibling controls/, execution_metadata, or manifest scan."""
        csv_paths = [p for p in raw.file_manifest if p.endswith(_CSV_SUFFIX)]

        # 1. Sibling of output_dir (parent of first CSV -> controls/)
        if csv_paths:
            output_dir = Path(csv_paths[0]).parent
            controls_dir = output_dir / "controls"
            if controls_dir.is_dir():
                return controls_dir

        # 2. Explicit controls_dir from execution_metadata (stored by collect() when
        #    tc.controls_dir was set; available during replay without a sibling controls/).
        explicit_dir = raw.execution_metadata.get("controls_dir")
        if explicit_dir:
            explicit_path = Path(explicit_dir)
            if not explicit_path.is_dir():
                raise ParseError(
                    f"Explicitly configured controls_dir does not exist or is not a directory: "
                    f"{explicit_path}",
                    adapter_name=self.tool_name,
                )
            return explicit_path

        # 3. Scan file_manifest for metadata files
        for manifest_path in raw.file_manifest:
            p = Path(manifest_path)
            if p.name in ("risk-severity.json", "registry.json"):
                return p.parent

        raise ParseError(
            "Cannot locate M365-Assess controls directory "
            "(tried: sibling controls/, execution_metadata.controls_dir, manifest scan)",
            adapter_name=self.tool_name,
        )
