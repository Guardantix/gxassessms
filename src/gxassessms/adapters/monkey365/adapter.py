"""Monkey365 adapter -- implements ToolAdapter Protocol.

Monkey365 is a PowerShell-based M365/Azure security assessment tool that
produces OCSF Detection Finding JSON output.

Invocation: Import-Module monkey365; Invoke-Monkey365 -Instance 'Microsoft365'
    -ExportTo 'JSON' -OutDir '{output_dir}'
Output: JSON array of OCSF Detection Finding objects.
Auth: Managed internally by Monkey365 (DeviceCode, SP, certificate, etc.)

Verified against Monkey365 source.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from gxassessms.adapters._base import (
    load_json_file,
    parse_extra_args,
    validate_extra_args,
)
from gxassessms.adapters.monkey365.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
)
from gxassessms.adapters.monkey365.parser import parse_monkey365_findings
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import AdapterCapability
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

_SCHEMA_VERSION = "1.0.0"
_DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes
_OUTPUT_FILE_PREFIX = "monkey365"

# Args the adapter controls -- user cannot override via extra_args.
# Allowing overrides would break collection-path discovery or change
# output format in ways the adapter cannot recover from.
_RESERVED_ARGS: frozenset[str] = frozenset({"Instance", "ExportTo", "OutDir"})


class Monkey365Adapter:
    """ToolAdapter implementation for Monkey365."""

    tool_name: str = "Monkey365"
    storage_slug: str = "monkey365"
    tool_source: ToolSource = ToolSource.MONKEY365
    capabilities: frozenset[AdapterCapability] = frozenset(
        {
            "collect",
            "parse",
            "prerequisites",
            "coverage_export",
            "benchmark_mapping",
        }
    )

    def check_prerequisites(self) -> PrerequisiteResult:
        """Check Monkey365 module provenance against baseline policy."""
        from gxassessms.adapters._verification import check_module_prerequisites
        from gxassessms.adapters.monkey365.policy import MODULE_POLICY

        return check_module_prerequisites(policy=MODULE_POLICY, tool_name=self.tool_name)

    def authenticate(
        self,
        config: EngagementConfig,
    ) -> AuthContext | None:
        """Monkey365 manages its own auth. Return None."""
        return None

    def collect(
        self,
        config: EngagementConfig,
        auth: AuthContext | None,
    ) -> CollectionOutput:
        """Run Monkey365 with provenance verification and capture OCSF JSON output."""
        from gxassessms.adapters._base import run_verified_powershell
        from gxassessms.adapters.monkey365.policy import ALLOWED_COMMANDS, MODULE_POLICY
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.hashing import sha256_file
        from gxassessms.core.security.permissions import secure_mkdir

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Monkey365 adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        output_dir = Path(tc.output_dir)
        secure_mkdir(output_dir, parents=True, exist_ok=True)

        timeout_seconds = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        named_args: dict[str, Any] = {
            "Instance": "Microsoft365",
            "ExportTo": "JSON",
            "OutDir": str(output_dir),
        }
        switches: dict[str, bool] = {}
        if tc.extra_args:
            validated = validate_extra_args(tc.extra_args)
            extra_named, switches = parse_extra_args(validated)
            _reserved_lower = frozenset(r.lower() for r in _RESERVED_ARGS)
            reserved_conflicts = {k for k in extra_named if k.lower() in _reserved_lower}
            reserved_conflicts |= {k for k in switches if k.lower() in _reserved_lower}
            if reserved_conflicts:
                raise CollectionError(
                    f"extra_args contains reserved Monkey365 args that cannot be overridden: "
                    f"{sorted(reserved_conflicts)}",
                    adapter_name=self.tool_name,
                )
            named_args.update(extra_named)

        override = getattr(tc, "module_policy_override", None)

        existing_files = {
            f
            for f in output_dir.iterdir()
            if f.is_file()
            and f.name.lower().startswith(_OUTPUT_FILE_PREFIX)
            and f.suffix == ".json"
        }

        verification_result = run_verified_powershell(
            policy=MODULE_POLICY,
            allowed_commands=ALLOWED_COMMANDS,
            command_name="Invoke-Monkey365",
            named_args=named_args,
            switches=switches or None,
            override=override,
            timeout_seconds=timeout_seconds,
            adapter_name=self.tool_name,
            engagement_id="",
        )

        # Find new output file(s) produced by this run
        new_files = sorted(
            f
            for f in output_dir.iterdir()
            if f.is_file()
            and f.name.lower().startswith(_OUTPUT_FILE_PREFIX)
            and f.suffix == ".json"
            and f not in existing_files
        )

        if not new_files:
            raise CollectionError(
                f"Monkey365 did not produce new output in {output_dir}. "
                f"Expected file matching {_OUTPUT_FILE_PREFIX}*.json",
                adapter_name=self.tool_name,
            )

        artifacts: list[CollectedArtifact] = []
        for results_path in new_files:
            sha = sha256_file(results_path)
            artifacts.append(
                CollectedArtifact(
                    source_path=str(results_path),
                    target_relpath=f"{self.storage_slug}/{results_path.name}",
                    encoding="utf-8",
                    sha256=sha,
                )
            )

        logger.info(
            "Monkey365 collection complete. Output dir: %s, %d artifacts",
            output_dir,
            len(artifacts),
        )

        return CollectionOutput(
            tool=ToolSource.MONKEY365,
            tool_slug=self.storage_slug,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            artifacts=artifacts,
            execution_metadata={
                "module_provenance": verification_result.to_json_dict(),
            },
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate Monkey365 OCSF output structure before parsing."""
        self._validate_and_load_findings(raw)

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse Monkey365 OCSF output into ToolObservations."""
        _, findings = self._validate_and_load_findings(raw)
        observations = parse_monkey365_findings(findings)
        logger.info("Monkey365 parse complete: %d observations", len(observations))
        return observations

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
        """Report coverage based on parsed findings."""
        _, findings = self._validate_and_load_findings(raw)
        observations = parse_monkey365_findings(findings)

        records: list[CoverageRecord] = []
        seen_checks: set[str] = set()

        for obs in observations:
            if obs.native_check_id not in seen_checks:
                seen_checks.add(obs.native_check_id)
                records.append(
                    CoverageRecord(
                        control_id=obs.native_check_id,
                        tool=ToolSource.MONKEY365,
                        status=CoverageStatus.ASSESSED,
                        reason=None,
                    )
                )

        logger.info("Monkey365 coverage export: %d records", len(records))
        return records

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """(OCSF severity, canonical status) -> Severity for NormalizationPolicy."""
        return SEVERITY_MAP

    @property
    def category_map(self) -> dict[str, Any]:
        """Module prefix -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """idSuffix -> canonical cross-reference ID for deduplication."""
        return DEDUP_KEY_RULES

    def _validate_and_load_findings(
        self, raw: ResolvedManifest
    ) -> tuple[str, list[dict[str, Any]]]:
        """Validate raw output and return (results_file_path, findings list)."""
        if not raw.file_manifest:
            raise RawOutputValidationError(
                "Monkey365 file manifest is empty -- no output files found",
                adapter_name=self.tool_name,
            )

        json_files = [f for f in raw.file_manifest if f.lower().endswith(".json")]
        results_file = self._find_monkey365_results_file(json_files)

        if results_file is None:
            raise RawOutputValidationError(
                "Monkey365 JSON file not found in manifest "
                "(expected basename starting with 'monkey365', case-insensitive)",
                adapter_name=self.tool_name,
            )

        raw_data: Any = load_json_file(Path(results_file), adapter_name=self.tool_name)

        if not isinstance(raw_data, list):
            raise RawOutputValidationError(
                f"Expected JSON array, got {type(raw_data).__name__}",
                adapter_name=self.tool_name,
            )

        findings: list[dict[str, Any]] = cast(list[dict[str, Any]], raw_data)

        if len(findings) == 0:
            raise RawOutputValidationError(
                "Empty findings array. Monkey365 should produce at least one finding.",
                adapter_name=self.tool_name,
            )

        for i, finding in enumerate(findings):
            # Runtime validation: cast above asserts type for pyright but
            # malformed JSON can contain non-dict elements (int, null, etc.).
            if not isinstance(finding, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise RawOutputValidationError(
                    f"Finding [{i}] must be an object, got {type(finding).__name__}",
                    adapter_name=self.tool_name,
                )
            if "findingInfo" not in finding:
                raise RawOutputValidationError(
                    f"Finding [{i}] missing 'findingInfo' field",
                    adapter_name=self.tool_name,
                )
            if not isinstance(finding["findingInfo"], dict):
                raise RawOutputValidationError(
                    f"Finding [{i}] 'findingInfo' must be an object, "
                    f"got {type(finding['findingInfo']).__name__}",
                    adapter_name=self.tool_name,
                )
            fi_id = cast(dict[str, Any], finding["findingInfo"]).get("id")
            if not isinstance(fi_id, str) or not fi_id.strip():
                # isinstance check short-circuits before .strip() when fi_id is None
                raise RawOutputValidationError(
                    f"Finding [{i}] findingInfo.id is missing or empty",
                    adapter_name=self.tool_name,
                )
            for text_field in ("title", "description"):
                val = cast(dict[str, Any], finding["findingInfo"]).get(text_field)
                if val is not None and not isinstance(val, str):
                    raise RawOutputValidationError(
                        f"Finding [{i}] findingInfo.{text_field} must be a string or absent, "
                        f"got {type(val).__name__}",
                        adapter_name=self.tool_name,
                    )
            if "severity" not in finding:
                raise RawOutputValidationError(
                    f"Finding [{i}] missing 'severity' field",
                    adapter_name=self.tool_name,
                )
            if not isinstance(finding["severity"], str):
                raise RawOutputValidationError(
                    f"Finding [{i}] 'severity' must be a string",
                    adapter_name=self.tool_name,
                )
            if "statusCode" not in finding:
                raise RawOutputValidationError(
                    f"Finding [{i}] missing 'statusCode' field",
                    adapter_name=self.tool_name,
                )
            if not isinstance(finding["statusCode"], str):
                raise RawOutputValidationError(
                    f"Finding [{i}] 'statusCode' must be a string",
                    adapter_name=self.tool_name,
                )

        logger.debug("Monkey365 raw output validated: %s", results_file)
        return results_file, findings

    @staticmethod
    def _find_monkey365_results_file(json_files: list[str]) -> str | None:
        """Return path of monkey365*.json from json_files, or None."""
        for file_path in json_files:
            name = Path(file_path).name.lower()
            if name.startswith("monkey365") and name.endswith(".json"):
                return file_path
        return None
