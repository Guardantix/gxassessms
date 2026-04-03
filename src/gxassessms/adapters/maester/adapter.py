"""Maester adapter -- implements the ToolAdapter protocol.

Handles tool prerequisites, authentication (delegated to Maester/Connect-MgGraph),
collection via PowerShell, raw output validation, parsing, and coverage reporting.
Maester is a Pester-based testing framework for M365/Azure security configuration.

Each collection run writes to an isolated ``output_dir/run-<uuid>/`` subdirectory
so that prior run artifacts cannot contaminate the current collection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from gxassessms.adapters._base import (
    load_json_file,
)
from gxassessms.adapters.maester.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
)
from gxassessms.adapters.maester.parser import parse_maester_tests
from gxassessms.core.contracts.errors import (
    CollectionError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.enums import CoverageStatus, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CollectedArtifact,
    CollectionOutput,
    CoverageRecord,
    ResolvedManifest,
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
    storage_slug: str = "maester"
    tool_source: ToolSource = ToolSource.MAESTER
    capabilities: frozenset[str] = frozenset(
        {"collect", "parse", "prerequisites", "coverage_export", "benchmark_mapping"}
    )

    def check_prerequisites(self) -> PrerequisiteResult:
        """Check Maester module provenance against baseline policy."""
        from gxassessms.adapters._verification import check_module_prerequisites
        from gxassessms.adapters.maester.policy import MODULE_POLICY

        return check_module_prerequisites(policy=MODULE_POLICY, tool_name=self.tool_name)

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
    ) -> CollectionOutput:
        """Execute Maester with provenance verification.

        Each run is isolated in ``output_dir/run-<uuid>/`` so that prior
        run artifacts cannot contaminate the current collection. Maester's
        Invoke-Maester -OutputFolder generates three files per run:
        - TestResults-{timestamp}.json (primary data -- collected)
        - TestResults-{timestamp}.html (visual report -- excluded)
        - TestResults-{timestamp}.md (markdown summary -- excluded)

        Exactly one TestResults*.json must be present in the run directory.
        """
        import uuid as uuid_mod

        from gxassessms.adapters._base import run_verified_powershell
        from gxassessms.adapters.maester.policy import ALLOWED_COMMANDS, MODULE_POLICY
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.hashing import sha256_file

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Maester adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        output_dir = Path(tc.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        timeout = tc.timeout if tc.timeout is not None else 600

        run_dir = output_dir / f"run-{uuid_mod.uuid4()}"
        run_dir.mkdir()

        named_args: dict[str, Any] = {"OutputFolder": str(run_dir)}

        override = getattr(tc, "module_policy_override", None)

        verification_result = run_verified_powershell(
            policy=MODULE_POLICY,
            allowed_commands=ALLOWED_COMMANDS,
            command_name="Invoke-Maester",
            named_args=named_args,
            override=override,
            timeout_seconds=timeout,
            adapter_name=self.tool_name.lower(),
            engagement_id=getattr(config, "engagement_id", ""),
        )

        # Spec: collect exactly one TestResults*.json -- exclude .html and .md
        json_results = sorted(run_dir.glob("TestResults*.json"))

        if not json_results:
            raise CollectionError(
                f"Maester produced no TestResults*.json files in {run_dir.name}",
                adapter_name=self.tool_name,
            )

        if len(json_results) > 1:
            names = [f.name for f in json_results]
            raise CollectionError(
                f"Maester produced {len(json_results)} TestResults*.json files "
                f"in {run_dir.name} (expected exactly 1): {names}",
                adapter_name=self.tool_name,
            )

        results_path = json_results[0]
        sha = sha256_file(results_path)

        return CollectionOutput(
            tool=ToolSource.MAESTER,
            tool_slug=self.storage_slug,
            schema_version="1.0.0",
            timestamp=utc_now(),
            artifacts=[
                CollectedArtifact(
                    source_path=str(results_path),
                    target_relpath=f"{self.storage_slug}/{results_path.name}",
                    encoding="utf-8",
                    sha256=sha,
                )
            ],
            execution_metadata={
                "module_provenance": verification_result.to_json_dict(),
            },
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate raw Maester output structure before parsing.

        Raises:
            RawOutputValidationError: If output is structurally invalid.
        """
        self._validate_and_load_tests(raw)

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse validated Maester output into ToolObservations."""
        _, tests = self._validate_and_load_tests(raw)
        return parse_maester_tests(tests)

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
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

    def _validate_and_load_tests(self, raw: ResolvedManifest) -> tuple[str, list[dict[str, Any]]]:
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
