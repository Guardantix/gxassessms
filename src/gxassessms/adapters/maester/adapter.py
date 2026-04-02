"""Maester adapter -- implements the ToolAdapter protocol.

Handles tool prerequisites, authentication (delegated to Maester/Connect-MgGraph),
collection via PowerShell, raw output validation, parsing, and coverage reporting.
Maester is a Pester-based testing framework for M365/Azure security configuration.

Maester output files are named TestResults-{timestamp}.json (not a fixed name).
The adapter locates the most recent TestResults*.json in the output directory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from gxassessms.adapters._base import (
    get_powershell_executable,
    load_json_file,
    run_powershell,
)
from gxassessms.adapters.maester.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
)
from gxassessms.adapters.maester.parser import parse_maester_tests
from gxassessms.core.contracts.errors import (
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import FileEncoding
from gxassessms.core.domain.enums import CoverageStatus, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CoverageRecord,
    RawToolOutput,
    ToolObservation,
)

logger = logging.getLogger(__name__)


class MaesterAdapter:
    """Maester adapter -- Pester-based M365/Azure security testing framework.

    Capabilities: collect, parse, prerequisites, coverage_export, benchmark_mapping.
    Maester handles its own authentication via Connect-MgGraph, so shared_auth
    is not declared.
    """

    tool_name: str = "Maester"
    capabilities: frozenset[str] = frozenset(
        {"collect", "parse", "prerequisites", "coverage_export", "benchmark_mapping"}
    )

    def check_prerequisites(self) -> PrerequisiteResult:
        """Check that Maester module is installed and PowerShell is available."""
        import subprocess

        ps_exe = get_powershell_executable()

        # Check PowerShell availability
        try:
            result = subprocess.run(  # noqa: S603
                [ps_exe, "-NoProfile", "-Command", "Write-Output 'ok'"],
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
            if result.returncode != 0:
                return PrerequisiteResult(
                    satisfied=False,
                    message=f"PowerShell ({ps_exe}) returned non-zero exit code",
                )
        except FileNotFoundError:
            return PrerequisiteResult(
                satisfied=False,
                message=f"PowerShell not found: {ps_exe}. Install PowerShell Core (pwsh) on Linux.",
            )
        except subprocess.TimeoutExpired:
            return PrerequisiteResult(
                satisfied=False,
                message=f"PowerShell ({ps_exe}) timed out during prerequisite check",
            )

        # Check Maester module availability
        check_script = (
            "if (Get-Module -ListAvailable -Name Maester) { 'installed' } else { 'missing' }"
        )
        try:
            module_result = subprocess.run(  # noqa: S603
                [ps_exe, "-NoProfile", "-NonInteractive", "-Command", check_script],
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )
            if "missing" in module_result.stdout:
                return PrerequisiteResult(
                    satisfied=False,
                    message="Maester PowerShell module is not installed. "
                    "Install via: Install-Module -Name Maester",
                )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return PrerequisiteResult(
                satisfied=False,
                message=f"Failed to check Maester module: {exc}",
            )

        return PrerequisiteResult(
            satisfied=True,
            message="Maester and PowerShell are available",
        )

    def authenticate(
        self,
        config: Any,  # EngagementConfig at runtime
    ) -> AuthContext | None:
        """Maester handles its own auth via Connect-MgGraph. Returns None."""
        return None

    def collect(
        self,
        config: Any,  # EngagementConfig at runtime
        auth: AuthContext | None,
    ) -> RawToolOutput:
        """Execute Maester and return raw output.

        Maester's Invoke-Maester -OutputFolder generates three files:
        - TestResults-{timestamp}.json (primary data)
        - TestResults-{timestamp}.html (visual report)
        - TestResults-{timestamp}.md (markdown summary)

        There is NO -OutputFormat parameter. -OutputFolder generates all three.
        """
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.contracts.errors import CollectionError

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Maester adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        output_dir = Path(tc.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        timeout = tc.timeout if tc.timeout is not None else 600
        extra_args = tc.extra_args

        script_parts = [
            "Import-Module Maester;",
            "Invoke-Maester",
            f"-OutputFolder '{output_dir}'",
        ]

        script = " ".join(script_parts)

        run_powershell(
            script=script,
            arguments=extra_args,
            timeout_seconds=timeout,
            adapter_name=self.tool_name.lower(),
            engagement_id=getattr(config, "engagement_id", ""),
        )

        # Build file manifest from output directory (single pass)
        file_manifest: dict[str, FileEncoding] = {}
        _binary_suffixes = {".html"}

        for path in output_dir.glob("TestResults*"):
            if path.suffix in {".json", ".html", ".md"}:
                encoding: FileEncoding = "binary" if path.suffix in _binary_suffixes else "utf-8"
                file_manifest[str(path)] = encoding

        return RawToolOutput(
            tool=ToolSource.MAESTER,
            schema_version="1.0.0",
            timestamp=utc_now(),
            file_manifest=file_manifest,
            execution_metadata={
                "output_dir": str(output_dir),
            },
        )

    def validate_raw(self, raw: RawToolOutput) -> None:
        """Validate raw Maester output structure before parsing.

        Raises:
            RawOutputValidationError: If output is structurally invalid.
        """
        self._validate_and_load_tests(raw)

    def parse(self, raw: RawToolOutput) -> list[ToolObservation]:
        """Parse validated Maester output into ToolObservations."""
        _, tests = self._validate_and_load_tests(raw)
        return parse_maester_tests(tests)

    def coverage(self, raw: RawToolOutput) -> list[CoverageRecord]:
        """Report per-control coverage from Maester output.

        Skipped, Error, and NotRun tests are reported as not_assessed.
        """
        _, tests = self._validate_and_load_tests(raw)

        not_assessed_statuses = {"Skipped", "Error", "NotRun"}
        records: list[CoverageRecord] = []

        for entry in tests:
            test_id: str = entry["Id"]
            result_status: str = entry["Result"]

            if result_status in not_assessed_statuses:
                cov_status = CoverageStatus.NOT_ASSESSED
                result_detail: dict[str, str] = entry.get("ResultDetail") or {}
                reason: str | None = (
                    result_detail.get("SkippedReason") or f"Test status: {result_status}"
                )
            else:
                cov_status = CoverageStatus.ASSESSED
                reason = None

            records.append(
                CoverageRecord(
                    control_id=test_id,
                    tool=ToolSource.MAESTER,
                    status=cov_status,
                    reason=reason,
                )
            )

        logger.debug("Generated %d coverage records from Maester", len(records))
        return records

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """(Severity, canonicalized status) -> Severity for NormalizationPolicy."""
        return SEVERITY_MAP

    @property
    def category_map(self) -> dict[str, Any]:
        """Check-ID prefix -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """Expose dedup key rules for NormalizationPolicy consumption."""
        return DEDUP_KEY_RULES

    def _validate_and_load_tests(self, raw: RawToolOutput) -> tuple[str, list[dict[str, Any]]]:
        """Validate raw output and return ``(results_file_path, Tests list)``.

        Single entry point for validation + JSON loading so that ``parse()``
        and ``coverage()`` avoid re-reading the file.

        Raises:
            RawOutputValidationError: If any structural check fails.
        """
        adapter = self.tool_name.lower()

        if not raw.file_manifest:
            raise RawOutputValidationError(
                message="Maester output file manifest is empty",
                adapter_name=adapter,
            )

        json_files = [f for f in raw.file_manifest if f.endswith(".json")]
        if not json_files:
            raise RawOutputValidationError(
                message="No JSON files found in Maester output manifest",
                adapter_name=adapter,
            )

        results_path = self._find_results_file(json_files)
        if results_path is None:
            raise RawOutputValidationError(
                message="TestResults*.json not found in Maester output",
                adapter_name=adapter,
            )

        data = load_json_file(Path(results_path), adapter_name=adapter)

        if "Tests" not in data:
            raise RawOutputValidationError(
                message="Maester output missing 'Tests' key",
                adapter_name=adapter,
            )

        if not isinstance(data["Tests"], list):
            raise RawOutputValidationError(
                message="Maester 'Tests' is not a list",
                adapter_name=adapter,
            )

        if len(data["Tests"]) == 0:
            raise RawOutputValidationError(
                message="Maester 'Tests' array is empty -- "
                "this likely indicates a collection failure, not zero findings",
                adapter_name=adapter,
            )

        return results_path, data["Tests"]

    @staticmethod
    def _find_results_file(json_files: list[str]) -> str | None:
        """Find the most recent Maester TestResults JSON file.

        Matches any JSON file whose name starts with 'testresults' or
        'maestertestresults' (case-insensitive). When multiple matches exist,
        returns the last in sorted order (newest timestamp in the filename).
        """
        matches = [
            f
            for f in json_files
            if Path(f).name.lower().startswith(("testresults", "maestertestresults"))
        ]
        if not matches:
            return None
        return sorted(matches, reverse=True)[0]
