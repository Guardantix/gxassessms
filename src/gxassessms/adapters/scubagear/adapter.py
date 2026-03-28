"""ScubaGear adapter -- reference implementation for the ToolAdapter Protocol.

Handles prerequisite checking, collection (PowerShell invocation), raw output
validation, parsing, and coverage export for ScubaGear v1.7.1+ output.
Auth is delegated to ScubaGear itself (Connect-MgGraph); ``authenticate()`` returns None.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any, cast

from gxassessms.adapters._base import (
    find_latest_output_dir,
    get_powershell_executable,
    load_json_file,
    run_powershell,
)
from gxassessms.adapters.scubagear.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
)
from gxassessms.adapters.scubagear.parser import parse_scuba_results
from gxassessms.core.contracts.errors import (
    CollectionError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import FileEncoding
from gxassessms.core.domain.enums import CoverageStatus, FindingStatus, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CoverageRecord,
    RawToolOutput,
    ToolObservation,
)

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = "1.7.1"
_DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes -- ScubaGear can be slow
_VALID_PRODUCT_NAMES: frozenset[str] = frozenset(
    {"AAD", "Defender", "EXO", "PowerPlatform", "SharePoint", "Teams"}
)
_PRODUCT_NAME_MAP: dict[str, str] = {name.lower(): name for name in _VALID_PRODUCT_NAMES}


class ScubaGearAdapter:
    """ToolAdapter implementation for ScubaGear (CISA SCuBA baseline assessor for M365)."""

    tool_name: str = "ScubaGear"
    capabilities: frozenset[str] = frozenset(
        {"collect", "parse", "prerequisites", "coverage_export", "benchmark_mapping"}
    )

    # ------------------------------------------------------------------
    # ToolAdapter Protocol methods
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> PrerequisiteResult:
        """Check that PowerShell and the ScubaGear module are available."""
        exe = get_powershell_executable()

        # 1. PowerShell itself
        try:
            result = subprocess.run(  # noqa: S603
                [exe, "-NoProfile", "-NonInteractive", "-Command", "Write-Output 'ok'"],
                shell=False,
                capture_output=True,
                timeout=10,
            )
        except OSError:
            return PrerequisiteResult(
                satisfied=False,
                message=f"PowerShell not accessible: {exe!r}",
            )
        except subprocess.TimeoutExpired:
            return PrerequisiteResult(
                satisfied=False,
                message="PowerShell prerequisite check timed out",
            )

        if result.returncode != 0:
            stderr = (result.stderr or b"").decode(errors="replace")[:200]
            return PrerequisiteResult(
                satisfied=False,
                message=f"PowerShell exited with code {result.returncode}: {stderr}",
            )

        # 2. ScubaGear module
        check_script = "Get-Module -ListAvailable -Name ScubaGear"
        try:
            mod_result = subprocess.run(  # noqa: S603
                [exe, "-NoProfile", "-NonInteractive", "-Command", check_script],
                shell=False,
                capture_output=True,
                timeout=30,
            )
        except OSError:
            return PrerequisiteResult(
                satisfied=False,
                message=f"PowerShell not accessible: {exe!r}",
            )
        except subprocess.TimeoutExpired:
            return PrerequisiteResult(
                satisfied=False,
                message="ScubaGear module check timed out",
            )

        stdout = (mod_result.stdout or b"").decode(errors="replace").strip()
        if not stdout:
            return PrerequisiteResult(
                satisfied=False,
                message=(
                    "ScubaGear PowerShell module not found. "
                    "Install with: Install-Module -Name ScubaGear"
                ),
            )

        logger.info("ScubaGear prerequisites satisfied (module found)")
        return PrerequisiteResult(satisfied=True, message="ScubaGear prerequisites satisfied")

    def authenticate(self, config: Any) -> AuthContext | None:
        """No-op: ScubaGear handles authentication internally via Connect-MgGraph."""
        return None

    def collect(self, config: Any, auth: AuthContext | None) -> RawToolOutput:
        """Invoke ScubaGear and capture its output directory.

        Reads from ``config.tools["scubagear"]``: ``output_dir`` (required),
        ``modules``, ``timeout`` (default 1800), ``extra_args``.

        Raises:
            CollectionError: On PowerShell failure, timeout, or missing output.
        """
        from gxassessms.core.config.datetime_utils import utc_now

        tool_cfg: dict[str, Any] = {}
        if hasattr(config, "tools") and config.tools:
            raw_tc = config.tools.get("scubagear", {})
            if hasattr(raw_tc, "model_dump"):
                tool_cfg = cast(dict[str, Any], raw_tc.model_dump())
            elif isinstance(raw_tc, dict):
                tool_cfg = cast(dict[str, Any], raw_tc)

        raw_output_dir = tool_cfg.get("output_dir", "")
        if not raw_output_dir:
            raise CollectionError(
                "ScubaGear adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        output_dir = Path(raw_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        modules: list[str] = tool_cfg.get("modules", [])
        raw_timeout = tool_cfg.get("timeout", _DEFAULT_TIMEOUT_SECONDS)
        try:
            timeout_seconds: int = int(raw_timeout)
        except (TypeError, ValueError) as exc:
            raise CollectionError(
                f"Invalid timeout value: {raw_timeout!r}",
                adapter_name=self.tool_name,
            ) from exc
        if timeout_seconds <= 0:
            raise CollectionError(
                f"timeout must be positive, got {timeout_seconds}",
                adapter_name=self.tool_name,
            )
        extra_args: list[str] = tool_cfg.get("extra_args", [])

        # Build Invoke-SCuBA command
        script_parts = ["Import-Module ScubaGear;", "Invoke-SCuBA"]
        escaped_path = str(output_dir).replace("'", "''")
        script_parts.append(f"-OutPath '{escaped_path}'")
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
            module_list = ",".join(canonical_modules)
            script_parts.append(f"-ProductNames {module_list}")

        script = " ".join(script_parts)

        # Snapshot existing output dirs so we can detect stale results
        existing_dirs = {
            d
            for d in output_dir.iterdir()
            if d.is_dir() and d.name.startswith("M365BaselineConformance")
        }

        engagement_id = getattr(config, "engagement_id", "")
        run_powershell(
            script=script,
            arguments=extra_args if extra_args else None,
            timeout_seconds=timeout_seconds,
            adapter_name=self.tool_name,
            engagement_id=engagement_id,
        )

        # Locate the output subdirectory ScubaGear created
        run_dir = find_latest_output_dir(output_dir, prefix="M365BaselineConformance")

        if run_dir in existing_dirs:
            raise CollectionError(
                f"ScubaGear did not produce new output. "
                f"Latest directory {run_dir.name} pre-dates this collection",
                adapter_name=self.tool_name,
            )

        # Collect JSON and HTML output files
        file_manifest: dict[str, FileEncoding] = {}
        for json_file in run_dir.glob("*.json"):
            file_manifest[str(json_file)] = "utf-8"
        for html_file in run_dir.glob("*.html"):
            file_manifest[str(html_file)] = "utf-8"

        logger.info(
            "ScubaGear collection complete. Output dir: %s, %d files in manifest",
            run_dir,
            len(file_manifest),
        )

        return RawToolOutput(
            tool=ToolSource.SCUBAGEAR,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            file_manifest=file_manifest,
            execution_metadata={
                "output_dir": str(run_dir),
                "modules": modules,
                "extra_args": extra_args,
            },
        )

    def validate_raw(self, raw: RawToolOutput) -> None:
        """Validate ScubaGear raw output structure.

        Checks (in order): (1) manifest non-empty, (2) ScubaResults*.json present,
        (3) file parses as JSON dict, (4) 'Results' key exists, (5) Results is a
        non-empty dict, (6) at least one module has controls.

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

        # Verify structure of ALL modules and that at least one has controls
        has_controls = False
        for _module_key, groups in results.items():
            if not isinstance(groups, list):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise RawOutputValidationError(
                    f"ScubaResults module {_module_key!r} value is not a list "
                    f"(got {type(groups).__name__})",
                    adapter_name=self.tool_name,
                )
            for group in groups:
                if not isinstance(group, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
                    raise RawOutputValidationError(
                        f"ScubaResults group in module {_module_key!r} is not a dict "
                        f"(got {type(group).__name__})",
                        adapter_name=self.tool_name,
                    )
                controls = group.get("Controls")
                if controls is not None and not isinstance(controls, list):
                    raise RawOutputValidationError(
                        f"ScubaResults Controls in module {_module_key!r} is not a list "
                        f"(got {type(controls).__name__})",
                        adapter_name=self.tool_name,
                    )
                if controls:
                    for control in controls:  # pyright: ignore[reportUnknownVariableType]
                        if not isinstance(control, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
                            raise RawOutputValidationError(
                                f"ScubaResults control entry in module {_module_key!r} "
                                f"is not a dict (got {type(control).__name__})",  # pyright: ignore[reportUnknownArgumentType]
                                adapter_name=self.tool_name,
                            )
                    has_controls = True

        if not has_controls:
            raise RawOutputValidationError(
                "ScubaResults contains no controls in any module",
                adapter_name=self.tool_name,
            )

        logger.debug("ScubaGear raw output validated: %s", results_file)

    def parse(self, raw: RawToolOutput) -> list[ToolObservation]:
        """Parse ScubaGear raw output into ToolObservations (calls validate_raw first)."""
        self.validate_raw(raw)

        json_files = [f for f in raw.file_manifest if f.lower().endswith(".json")]
        results_file = self._find_scuba_results_file(json_files)
        if results_file is None:
            # validate_raw guarantees this exists; guard satisfies type checker
            raise RawOutputValidationError(
                "ScubaResults file missing after validation (unexpected)",
                adapter_name=self.tool_name,
            )

        data = load_json_file(Path(results_file), adapter_name=self.tool_name)
        observations = parse_scuba_results(data["Results"])

        logger.info(
            "ScubaGear parse complete: %d observations from %s",
            len(observations),
            results_file,
        )
        return observations

    def coverage(self, raw: RawToolOutput) -> list[CoverageRecord]:
        """Extract per-control coverage records.

        FindingStatus.NOT_APPLICABLE -> NOT_ASSESSED, all others -> ASSESSED.
        """
        self.validate_raw(raw)

        json_files = [f for f in raw.file_manifest if f.lower().endswith(".json")]
        results_file = self._find_scuba_results_file(json_files)
        if results_file is None:
            # validate_raw guarantees this exists; guard satisfies type checker
            raise RawOutputValidationError(
                "ScubaResults file missing after validation (unexpected)",
                adapter_name=self.tool_name,
            )

        data = load_json_file(Path(results_file), adapter_name=self.tool_name)
        results: dict[str, list[dict[str, Any]]] = data["Results"]

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

    # ------------------------------------------------------------------
    # Properties for NormalizationPolicy consumption
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

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
