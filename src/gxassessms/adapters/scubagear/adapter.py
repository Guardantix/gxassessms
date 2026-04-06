"""ScubaGear adapter -- reference implementation for the ToolAdapter Protocol.

Handles prerequisite checking, collection (PowerShell invocation), raw output
validation, parsing, and coverage export for ScubaGear v1.7.1+ output.
Auth is delegated to ScubaGear itself (Connect-MgGraph); ``authenticate()`` returns None.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from gxassessms.adapters._base import (
    find_latest_output_dir,
    load_json_file,
    parse_extra_args,
    validate_extra_args,
)
from gxassessms.adapters.scubagear.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
)
from gxassessms.adapters.scubagear.parser import parse_scuba_results
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import AdapterCapability
from gxassessms.core.domain.enums import CoverageStatus, FindingStatus, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CollectedArtifact,
    CollectionOutput,
    CoverageRecord,
    ResolvedManifest,
    ToolObservation,
)

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = "1.7.1"
_DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes -- ScubaGear can be slow
_VALID_PRODUCT_NAMES: frozenset[str] = frozenset(
    {"AAD", "Defender", "EXO", "PowerPlatform", "SharePoint", "Teams"}
)
_PRODUCT_NAME_MAP: dict[str, str] = {name.lower(): name for name in _VALID_PRODUCT_NAMES}
_OUTPUT_DIR_PREFIX = "M365BaselineConformance"


class ScubaGearAdapter:
    """ToolAdapter implementation for ScubaGear (CISA SCuBA baseline assessor for M365)."""

    tool_name: str = "ScubaGear"
    storage_slug: str = "scubagear"
    tool_source: ToolSource = ToolSource.SCUBAGEAR
    capabilities: frozenset[AdapterCapability] = frozenset(
        {"collect", "parse", "prerequisites", "coverage_export", "benchmark_mapping"}
    )

    def check_prerequisites(self) -> PrerequisiteResult:
        """Check ScubaGear module provenance against baseline policy."""
        from gxassessms.adapters._verification import check_module_prerequisites
        from gxassessms.adapters.scubagear.policy import MODULE_POLICY

        return check_module_prerequisites(policy=MODULE_POLICY, tool_name=self.tool_name)

    def authenticate(self, config: EngagementConfig) -> AuthContext | None:
        """No-op: ScubaGear handles authentication internally via Connect-MgGraph."""
        return None

    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput:
        """Invoke ScubaGear with provenance verification.

        Reads from ``config.tools["scubagear"]``: ``output_dir`` (required),
        ``modules``, ``timeout`` (default 1800), ``extra_args``.

        Raises:
            CollectionError: On PowerShell failure, timeout, or missing output.
            ModuleVerificationError: On provenance or platform failures.
        """
        from gxassessms.adapters._base import run_verified_powershell
        from gxassessms.adapters.scubagear.policy import ALLOWED_COMMANDS, MODULE_POLICY
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.hashing import sha256_file

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "ScubaGear adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        from gxassessms.core.security.permissions import secure_mkdir

        output_dir = Path(tc.output_dir)
        secure_mkdir(output_dir, parents=True, exist_ok=True)

        modules = tc.modules
        timeout_seconds = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        named_args: dict[str, Any] = {"OutPath": str(output_dir)}
        switches: dict[str, bool] = {}
        if tc.extra_args:
            validated = validate_extra_args(tc.extra_args)
            extra_named, switches = parse_extra_args(validated)
            named_args.update(extra_named)

        if modules:
            canonical_modules: list[str] = []
            invalid: list[str] = []
            for m in modules:
                canonical = _PRODUCT_NAME_MAP.get(m.lower())
                if canonical:
                    canonical_modules.append(canonical)
                else:
                    invalid.append(m)
            if invalid:
                raise CollectionError(
                    f"Invalid ScubaGear module(s): {sorted(invalid)}. "
                    f"Valid modules: {sorted(_VALID_PRODUCT_NAMES)}",
                    adapter_name=self.tool_name,
                )
            named_args["ProductNames"] = canonical_modules

        # Get override from config if present
        override = getattr(tc, "module_policy_override", None)

        existing_dirs = {
            d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith(_OUTPUT_DIR_PREFIX)
        }

        verification_result = run_verified_powershell(
            policy=MODULE_POLICY,
            allowed_commands=ALLOWED_COMMANDS,
            command_name="Invoke-SCuBA",
            named_args=named_args,
            switches=switches or None,
            override=override,
            timeout_seconds=timeout_seconds,
            adapter_name=self.tool_name,
            engagement_id="",
        )

        run_dir = find_latest_output_dir(output_dir, prefix=_OUTPUT_DIR_PREFIX)

        if run_dir in existing_dirs:
            raise CollectionError(
                f"ScubaGear did not produce new output. "
                f"Latest directory {run_dir.name} pre-dates this collection",
                adapter_name=self.tool_name,
            )

        # Spec: collect only the single ScubaResults*.json file
        json_files = [f for f in run_dir.iterdir() if f.suffix == ".json"]
        results_file = self._find_scuba_results_file([str(f) for f in json_files])

        if results_file is None:
            raise CollectionError(
                f"ScubaGear created output directory {run_dir.name} but "
                f"no ScubaResults JSON file was found",
                adapter_name=self.tool_name,
            )

        results_path = Path(results_file)
        sha = sha256_file(results_path)
        artifacts: list[CollectedArtifact] = [
            CollectedArtifact(
                source_path=str(results_path),
                target_relpath=f"{self.storage_slug}/{results_path.name}",
                encoding="utf-8",
                sha256=sha,
            )
        ]

        logger.info(
            "ScubaGear collection complete. Output dir: %s, %d artifacts",
            run_dir,
            len(artifacts),
        )

        return CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug=self.storage_slug,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            artifacts=artifacts,
            execution_metadata={
                "modules": modules,
                "module_provenance": verification_result.to_json_dict(),
            },
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate ScubaGear raw output structure.

        Checks (in order): (1) manifest non-empty, (2) ScubaResults*.json present,
        (3) file parses as JSON dict, (4) 'Results' key exists, (5) Results is a
        non-empty dict, (6) at least one module has controls.

        Raises:
            RawOutputValidationError: If any structural check fails.
        """
        results_file, _ = self._validate_and_load_results(raw)
        logger.debug("ScubaGear raw output validated: %s", results_file)

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse ScubaGear raw output into ToolObservations (validates first)."""
        results_file, results = self._validate_and_load_results(raw)
        observations = parse_scuba_results(results)

        logger.info(
            "ScubaGear parse complete: %d observations from %s",
            len(observations),
            results_file,
        )
        return observations

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
        """Extract per-control coverage records.

        FindingStatus.NOT_APPLICABLE -> NOT_ASSESSED, all others -> ASSESSED.
        """
        _, results = self._validate_and_load_results(raw)

        records: list[CoverageRecord] = []
        for _module_key, groups in results.items():
            for group in groups:
                for control in group.get("Controls", []):
                    control_id: str = control.get("Control ID", "")
                    result_str: str = control.get("Result", "")
                    details: str = control.get("Details", "")

                    if result_str.strip().upper() == FindingStatus.NOT_APPLICABLE:
                        status = CoverageStatus.NOT_ASSESSED
                        reason: str | None = details if details else None
                    else:
                        status = CoverageStatus.ASSESSED
                        reason = None

                    records.append(
                        CoverageRecord(
                            control_id=control_id,
                            tool=ToolSource.SCUBAGEAR,
                            status=status,
                            reason=reason,
                        )
                    )

        logger.info("ScubaGear coverage export: %d records", len(records))
        return records

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """(Criticality, Result) -> Severity for NormalizationPolicy."""
        return SEVERITY_MAP

    @property
    def category_map(self) -> dict[str, Any]:
        """Module abbreviation -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """PolicyId -> canonical cross-reference ID for deduplication."""
        return DEDUP_KEY_RULES

    def _validate_and_load_results(
        self, raw: ResolvedManifest
    ) -> tuple[str, dict[str, list[dict[str, Any]]]]:
        """Validate raw output and return ``(results_file_path, Results dict)``.

        Shared helper used by ``validate_raw()``, ``parse()``, and ``coverage()``
        to consolidate validation logic in one place.

        Raises:
            RawOutputValidationError: If any structural check fails.
        """
        if not raw.file_manifest:
            raise RawOutputValidationError(
                "ScubaGear file manifest is empty -- no output files found",
                adapter_name=self.tool_name,
            )

        json_files = [f for f in raw.file_manifest if f.lower().endswith(".json")]
        results_file = self._find_scuba_results_file(json_files)

        if results_file is None:
            raise RawOutputValidationError(
                "ScubaResults JSON file not found in manifest "
                "(expected basename starting with 'scubaresults', case-insensitive)",
                adapter_name=self.tool_name,
            )

        raw_data: Any = load_json_file(Path(results_file), adapter_name=self.tool_name)

        if not isinstance(raw_data, dict):
            raise RawOutputValidationError(
                f"ScubaResults JSON is not a dict (got {type(raw_data).__name__})",
                adapter_name=self.tool_name,
            )
        data: dict[str, Any] = cast(dict[str, Any], raw_data)

        if "Results" not in data:
            raise RawOutputValidationError(
                "ScubaResults JSON missing required 'Results' key",
                adapter_name=self.tool_name,
            )

        raw_results = data["Results"]
        if not isinstance(raw_results, dict) or not raw_results:
            raise RawOutputValidationError(
                "ScubaResults 'Results' is empty or not a dict",
                adapter_name=self.tool_name,
            )
        results: dict[str, list[dict[str, Any]]] = cast(
            dict[str, list[dict[str, Any]]], raw_results
        )

        has_controls = False
        for module_key, groups in results.items():
            if not isinstance(groups, list):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise RawOutputValidationError(
                    f"ScubaResults module {module_key!r} value is not a list "
                    f"(got {type(groups).__name__})",
                    adapter_name=self.tool_name,
                )
            for group in groups:
                if not isinstance(group, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
                    raise RawOutputValidationError(
                        f"ScubaResults group in module {module_key!r} is not a dict "
                        f"(got {type(group).__name__})",
                        adapter_name=self.tool_name,
                    )
                controls = group.get("Controls")
                if "Controls" in group and not isinstance(controls, list):
                    raise RawOutputValidationError(
                        f"ScubaResults Controls in module {module_key!r} is not a list "
                        f"(got {type(controls).__name__})",
                        adapter_name=self.tool_name,
                    )
                if controls:
                    for control in controls:  # pyright: ignore[reportUnknownVariableType]
                        if not isinstance(control, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
                            raise RawOutputValidationError(
                                f"ScubaResults control entry in module {module_key!r} "
                                f"is not a dict (got {type(control).__name__})",  # pyright: ignore[reportUnknownArgumentType]
                                adapter_name=self.tool_name,
                            )
                    has_controls = True

        if not has_controls:
            raise RawOutputValidationError(
                "ScubaResults contains no controls in any module",
                adapter_name=self.tool_name,
            )

        return results_file, results

    @staticmethod
    def _find_scuba_results_file(json_files: list[str]) -> str | None:
        """Return path of ScubaResults*.json from *json_files*, or None.

        Matches case-insensitively on the basename prefix ``scubaresults``.
        Files like TestResults.json are excluded implicitly (wrong prefix).
        """
        for file_path in json_files:
            name = Path(file_path).name.lower()
            if name.startswith("scubaresults") and name.endswith(".json"):
                return file_path
        return None
