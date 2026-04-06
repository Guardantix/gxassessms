"""Prowler adapter -- implements ToolAdapter Protocol.

Prowler is a Python-based cloud security scanner that produces OCSF
Detection Finding JSON output. It scans Azure resources against CIS
benchmarks.

Invocation: prowler azure --az-cli-auth -o /output/dir -F ProwlerResults -M json-ocsf
Output: JSON array of OCSF Detection Finding objects (*.ocsf.json)
Auth: Managed by Prowler via CLI auth flags

IMPORTANT:
- Provider (azure) is POSITIONAL (not --provider azure)
- Auth flag is REQUIRED (--az-cli-auth, --sp-env-auth, etc.)
- status_code (UPPERCASE) is the assessment result, NOT status (lifecycle)
- metadata.event_code is the check ID, NOT finding_info.uid
- Prowler requires Python >=3.10, <=3.12 (invoked as subprocess)

Verified against Prowler source at /home/guardantix/ToolInspection/prowler/.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

from gxassessms.adapters._base import load_json_file
from gxassessms.adapters.prowler.mappings import (
    AUTH_METHOD_MAP,
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    PROWLER_AUTH_FLAGS,
    SEVERITY_MAP,
)
from gxassessms.adapters.prowler.parser import parse_prowler_findings
from gxassessms.adapters.prowler.policy import MINIMUM_PROWLER_MAJOR_VERSION
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    ParseError,
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

_SCHEMA_VERSION = "1.4.0"  # OCSF metadata.version from Prowler output
_DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes
_DEFAULT_OUTPUT_FILENAME = "ProwlerResults"
_OCSF_EXTENSION = ".ocsf.json"

# Prowler exit codes:
#   0 = success, no FAIL findings
#   1 = configuration/infrastructure error
#   3 = success WITH FAIL findings (normal for real assessments)
_PROWLER_SUCCESS_CODES: frozenset[int] = frozenset({0, 3})

# Allowlist of permitted Prowler CLI flags for extra_args.
_PROWLER_ALLOWED_FLAGS: frozenset[str] = frozenset(
    {
        "--az-cli-auth",
        "--sp-env-auth",
        "--browser-auth",
        "--managed-identity-auth",
        "--tenant-id",
        "--subscription-ids",
        "--checks",
        "--checks-file",
        "--severity",
        "--services",
        "--scan-list",
        "--ignore-exit-code-3",
        "--only-logs",
        "--quiet",
        "--verbose",
        "--no-banner",
        "--scan-unused-services",
    }
)

# Permitted character set for non-flag values (UUIDs, check IDs, etc.)
_PROWLER_VALUE_RE: re.Pattern[str] = re.compile(r"^[\w\-.,:/@ ]+$")


def _validate_prowler_extra_args(args: list[str], adapter_name: str) -> list[str]:
    """Validate Prowler extra_args against the allowed flag allowlist.

    Raises:
        CollectionError: If any arg contains an unrecognized flag or unsafe value.
    """
    for arg in args:
        if arg.startswith("-"):
            if arg not in _PROWLER_ALLOWED_FLAGS:
                raise CollectionError(
                    f"Unrecognized Prowler flag in extra_args: {arg!r}. "
                    f"Permitted flags: {sorted(_PROWLER_ALLOWED_FLAGS)}",
                    adapter_name=adapter_name,
                )
        elif not _PROWLER_VALUE_RE.match(arg):
            raise CollectionError(
                f"Unsafe value in Prowler extra_args: {arg!r}. "
                f"Values must match: {_PROWLER_VALUE_RE.pattern}",
                adapter_name=adapter_name,
            )
    return args


class ProwlerAdapter:
    """ToolAdapter implementation for Prowler (Azure cloud security scanner)."""

    tool_name: str = "Prowler"
    storage_slug: str = "prowler"
    tool_source: ToolSource = ToolSource.PROWLER
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
        """Verify the prowler CLI is available on PATH."""
        prowler_path = shutil.which("prowler")
        if prowler_path is None:
            return PrerequisiteResult(
                satisfied=False,
                message=(
                    "Prowler CLI not found on PATH. "
                    "Install with: pip install prowler (requires Python 3.10-3.12)"
                ),
            )

        try:
            result = subprocess.run(  # noqa: S603
                [prowler_path, "--version"],
                capture_output=True,
                timeout=30,
                check=True,
            )
            version = (result.stdout or b"").decode(errors="replace").strip()
            version_match = re.search(r"(\d+)\.\d+", version)
            if version_match is None:
                return PrerequisiteResult(
                    satisfied=False,
                    message=f"Prowler version could not be parsed: {version!r}",
                )
            major = int(version_match.group(1))
            if major < MINIMUM_PROWLER_MAJOR_VERSION:
                return PrerequisiteResult(
                    satisfied=False,
                    message=(
                        f"Prowler {version!r} is below the minimum required version "
                        f"{MINIMUM_PROWLER_MAJOR_VERSION}.x "
                        f"(required for -M json-ocsf output)"
                    ),
                )
            logger.info("Prowler prerequisites satisfied (version: %s)", version)
            return PrerequisiteResult(
                satisfied=True,
                message=f"Prowler prerequisites satisfied (version: {version})",
            )
        except (subprocess.TimeoutExpired, OSError, subprocess.CalledProcessError) as exc:
            return PrerequisiteResult(
                satisfied=False,
                message=f"Prowler found but not executable: {exc}",
            )

    def authenticate(
        self,
        _config: EngagementConfig,
    ) -> AuthContext | None:
        """Prowler manages its own Azure auth. Return None."""
        return None

    def collect(
        self,
        config: EngagementConfig,
        _auth: AuthContext | None,
    ) -> CollectionOutput:
        """Run Prowler and capture OCSF JSON output.

        Reads from config.tools["prowler"]:
        - output_dir (required): Where to write output
        - auth_method: One of az_cli, service_principal, browser, managed_identity
        - tenant_id: Required for browser auth
        - modules: Optional list of specific checks to run (passed to --checks)
        - timeout: Seconds (default 1800)
        """
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.hashing import sha256_file

        prowler_path = shutil.which("prowler")
        if prowler_path is None:
            raise CollectionError(
                "Prowler CLI not found on PATH. "
                "Install with: pip install prowler (requires Python 3.10-3.12)",
                adapter_name=self.tool_name,
            )

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Prowler adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        from gxassessms.core.security.permissions import secure_mkdir

        output_dir = Path(tc.output_dir)
        secure_mkdir(output_dir, parents=True, exist_ok=True)

        output_filename = _DEFAULT_OUTPUT_FILENAME
        timeout = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        cmd: list[str] = [
            prowler_path,
            "azure",  # POSITIONAL provider (not --provider)
        ]

        extra_args = _validate_prowler_extra_args(tc.extra_args or [], self.tool_name)

        auth_flags = AUTH_METHOD_MAP.get(config.auth.method)
        extra_has_auth = bool(PROWLER_AUTH_FLAGS & set(extra_args))
        if auth_flags is not None and not extra_has_auth:
            cmd.extend(auth_flags)
        elif not extra_has_auth:
            raise CollectionError(
                f"No Prowler auth mapping for method: {config.auth.method!r}. "
                f"Use extra_args to pass a Prowler-specific auth flag "
                f"(e.g., ['--az-cli-auth'] or ['--managed-identity-auth'])",
                adapter_name=self.tool_name,
            )

        # Browser auth requires --tenant-id; covers both mapped methods and
        # --browser-auth injected directly via extra_args.
        browser_auth_active = (
            config.auth.method
            in (
                "device_code",
                "interactive",
            )
            or "--browser-auth" in extra_args
        )
        if browser_auth_active:
            tenant_id = config.auth.tenant_id
            if not tenant_id:
                raise CollectionError(
                    "Browser auth requires tenant_id in engagement config",
                    adapter_name=self.tool_name,
                )
            cmd.extend(["--tenant-id", tenant_id])

        cmd.extend(["-o", str(output_dir)])
        cmd.extend(["-F", output_filename])
        cmd.extend(["-M", "json-ocsf"])

        # nargs+ = space-separated, NOT comma-joined
        checks = tc.modules if tc.modules else []
        if checks:
            cmd.extend(["--checks", *list(checks)])

        if extra_args:
            cmd.extend(extra_args)

        logger.info(
            "[Prowler] Starting collection: auth_method=%r, extra_args=%d arg(s)",
            config.auth.method,
            len(extra_args),
        )
        logger.debug("[Prowler] Full command: %s", " ".join(cmd))

        try:
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise CollectionError(
                f"Prowler timed out after {timeout}s",
                adapter_name=self.tool_name,
            ) from exc
        except OSError as exc:
            raise CollectionError(
                f"Prowler not accessible: {exc}",
                adapter_name=self.tool_name,
            ) from exc

        if result.returncode not in _PROWLER_SUCCESS_CODES:
            stderr_snippet = (result.stderr or b"").decode(errors="replace")[:500]
            stdout_snippet = (result.stdout or b"").decode(errors="replace")[:500]
            raise CollectionError(
                f"Prowler exited with code {result.returncode}.\n"
                f"  stderr: {stderr_snippet or '(empty)'}\n"
                f"  stdout: {stdout_snippet or '(empty)'}",
                adapter_name=self.tool_name,
            )
        if result.returncode == 3:
            logger.debug(
                "[Prowler] Exit code 3: FAIL findings present (expected for real assessments)"
            )

        ocsf_files = list(output_dir.rglob(f"{output_filename}{_OCSF_EXTENSION}"))
        if not ocsf_files:
            raise CollectionError(
                f"No Prowler OCSF output found in {output_dir}. "
                f"Expected file matching {output_filename}{_OCSF_EXTENSION}",
                adapter_name=self.tool_name,
            )

        artifacts: list[CollectedArtifact] = []
        for f in ocsf_files:
            try:
                sha = sha256_file(f)
            except OSError as exc:
                raise CollectionError(
                    f"Cannot hash Prowler output file {f}: {exc}",
                    adapter_name=self.tool_name,
                ) from exc
            artifacts.append(
                CollectedArtifact(
                    source_path=str(f),
                    target_relpath=f"{self.storage_slug}/{f.relative_to(output_dir).as_posix()}",
                    encoding="utf-8",
                    sha256=sha,
                )
            )
        artifacts.sort(key=lambda a: a.target_relpath)

        logger.info(
            "Prowler collection complete. %d OCSF output file(s) in %s",
            len(ocsf_files),
            output_dir,
        )

        return CollectionOutput(
            tool=ToolSource.PROWLER,
            tool_slug=self.storage_slug,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            artifacts=artifacts,
            execution_metadata={
                "output_dir": str(output_dir),
                "auth_method": config.auth.method,
                "checks": checks,
            },
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate Prowler OCSF output structure before parsing."""
        self._validate_and_load(raw)

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse Prowler OCSF output into ToolObservations (validates first)."""
        all_findings = self._validate_and_load(raw)

        all_observations: list[ToolObservation] = []
        for file_path, findings in all_findings.items():
            try:
                observations = parse_prowler_findings(findings)
                all_observations.extend(observations)
            except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
                raise ParseError(
                    f"Failed to parse Prowler output from {file_path}: {exc}",
                    adapter_name=self.tool_name,
                ) from exc

        logger.info(
            "Parsed %d observations from %d Prowler output file(s)",
            len(all_observations),
            len(all_findings),
        )
        return all_observations

    def _validate_and_load(
        self,
        raw: ResolvedManifest,
    ) -> dict[str, list[dict[str, Any]]]:
        """Validate raw output and return loaded findings per file.

        Shared helper used by ``validate_raw()`` and ``parse()`` to avoid
        reading files twice.

        Returns:
            Dict of file_path -> list of finding dicts.

        Raises:
            RawOutputValidationError: If any structural check fails.
        """
        if not raw.file_manifest:
            raise RawOutputValidationError(
                "Prowler file manifest is empty -- no output files found",
                adapter_name=self.tool_name,
            )

        result: dict[str, list[dict[str, Any]]] = {}

        for file_path in raw.file_manifest:
            path = Path(file_path)
            data: Any = load_json_file(path, adapter_name=self.tool_name)

            if not isinstance(data, list):
                raise RawOutputValidationError(
                    f"Expected JSON array, got {type(data).__name__} in {path}",
                    adapter_name=self.tool_name,
                )

            findings: list[Any] = cast(list[Any], data)

            if len(findings) == 0:
                logger.warning("Empty findings array in %s -- no findings to parse", path)
                result[file_path] = []
                continue

            for i, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    raise RawOutputValidationError(
                        f"Finding [{i}] is {type(finding).__name__}, expected object in {path}",
                        adapter_name=self.tool_name,
                    )
                if "finding_info" not in finding:
                    raise RawOutputValidationError(
                        f"Finding [{i}] missing 'finding_info' field in {path}",
                        adapter_name=self.tool_name,
                    )
                if not isinstance(finding["finding_info"], dict):
                    actual_type = type(cast(Any, finding["finding_info"])).__name__
                    raise RawOutputValidationError(
                        f"Finding [{i}] 'finding_info' is {actual_type}, expected object in {path}",
                        adapter_name=self.tool_name,
                    )
                if "status_code" not in finding:
                    raise RawOutputValidationError(
                        f"Finding [{i}] missing 'status_code' field in {path}",
                        adapter_name=self.tool_name,
                    )
                if (
                    "metadata" not in finding
                    or not isinstance(finding["metadata"], dict)
                    or "event_code" not in finding["metadata"]
                ):
                    raise RawOutputValidationError(
                        f"Finding [{i}] missing 'metadata.event_code' field in {path}",
                        adapter_name=self.tool_name,
                    )

            result[file_path] = findings

        return result

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
        """Report coverage based on parsed findings.

        Prowler coverage is derived from the findings themselves.
        Each unique check ID (metadata.event_code) represents a control that
        was assessed. MANUAL status maps to PARTIALLY_ASSESSED.

        Raises:
            ParseError: If the underlying parse() call fails.
            RawOutputValidationError: If the manifest fails structural validation.
        """
        observations = self.parse(raw)

        # Collect all statuses per check before deciding coverage.
        # Prowler emits one finding per resource -- a check with mixed
        # statuses (e.g., PASS + MANUAL) must be PARTIALLY_ASSESSED.
        check_statuses: dict[str, set[str]] = {}
        for obs in observations:
            check_statuses.setdefault(obs.native_check_id, set()).add(obs.native_status)

        records: list[CoverageRecord] = []
        for check_id, statuses in check_statuses.items():
            if FindingStatus.MANUAL in statuses:
                status = CoverageStatus.PARTIALLY_ASSESSED
                reason: str | None = "Requires manual verification"
            else:
                status = CoverageStatus.ASSESSED
                reason = None

            records.append(
                CoverageRecord(
                    control_id=check_id,
                    tool=ToolSource.PROWLER,
                    status=status,
                    reason=reason,
                )
            )

        return records

    # ------------------------------------------------------------------
    # Properties for NormalizationPolicy consumption
    # ------------------------------------------------------------------

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """(OCSF severity, canonical status) -> Severity for NormalizationPolicy."""
        return SEVERITY_MAP

    @property
    def category_map(self) -> dict[str, Any]:
        """Service group name -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """Check ID -> canonical cross-reference ID for deduplication."""
        return DEDUP_KEY_RULES
