"""Module provenance verification -- script builder, runner, report reader.

Orchestrates the full verification flow:
1. Build JSON input blob from policy + overrides
2. Write input to temp file
3. Invoke static PowerShell template with -File/-InputPath
4. Read verification report JSON from temp file
5. Parse into ModuleVerificationResult
6. Log provenance event
7. Clean up temp directory

The PowerShell template is a static .ps1 file -- no string substitution,
no quoting bugs, no injection surface. All dynamic data flows through the
JSON input blob.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from gxassessms.adapters._base import get_powershell_executable
from gxassessms.core.contracts.errors import (
    CollectionError,
    ModuleAmbiguityError,
    ModuleExecutionUnsupportedError,
    ModuleProvenanceError,
    ModuleVerificationError,
    VerificationInfrastructureError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.contracts.verification import (
    ModulePolicy,
    ModulePolicyOverride,
    ModuleVerificationResult,
    parse_verification_report,
)
from gxassessms.core.domain.constants import VerificationMode

logger = logging.getLogger(__name__)


def get_template_path() -> Path:
    """Return path to the static PowerShell verification template."""
    return Path(__file__).parent / "_verification_scripts" / "verify_module.ps1"


def validate_command_allowlist(command_name: str, allowed_commands: frozenset[str]) -> None:
    """Validate command_name is in the adapter's allowlist.

    Raises ValueError if the command is not allowed.
    """
    if command_name not in allowed_commands:
        raise ValueError(
            f"Command {command_name!r} not in adapter allowlist: {sorted(allowed_commands)}"
        )


def check_module_prerequisites(
    *,
    policy: ModulePolicy,
    tool_name: str,
    timeout_seconds: int = 60,
) -> PrerequisiteResult:
    """Shared preflight check for PowerShell adapters with MODULE_POLICY.

    Calls verify_module(mode="preflight") and returns a PrerequisiteResult.
    """
    try:
        result = verify_module(
            policy=policy,
            mode="preflight",
            adapter_name=tool_name,
            timeout_seconds=timeout_seconds,
        )
        version = result.approved_candidate.version if result.approved_candidate else "?"
        return PrerequisiteResult(
            satisfied=True,
            message=f"{tool_name} {version} verified ({result.evidence_path})",
        )
    except ModuleVerificationError as exc:
        return PrerequisiteResult(satisfied=False, message=str(exc))
    except OSError as exc:
        return PrerequisiteResult(satisfied=False, message=str(exc))


def build_input_blob(
    *,
    policy: ModulePolicy,
    override: ModulePolicyOverride | None,
    mode: VerificationMode,
    post_import_invocation: dict[str, Any] | None,
) -> str:
    """Build the JSON input blob for the PowerShell verification template.

    Returns JSON string. Does not write to disk.
    """
    effective_version_range = policy.version_range
    effective_hashes = sorted(policy.approved_package_hashes)

    if override is not None:
        if override.version_range is not None:
            effective_version_range = override.version_range
        if override.pinned_package_hashes is not None:
            effective_hashes = sorted(override.pinned_package_hashes)

    signers = [
        {"subject": s.subject, "issuer": s.issuer}
        for s in sorted(policy.allowed_signers, key=lambda s: (s.subject, s.issuer))
    ]

    blob: dict[str, Any] = {
        "module_name": policy.module_name,
        "effective_version_range": effective_version_range,
        "effective_approved_hashes": effective_hashes,
        "allowed_signers": signers,
        "allow_package_hash_fallback": policy.allow_package_hash_fallback,
        "mode": mode,
        "post_import_invocation": post_import_invocation,
    }

    return json.dumps(blob, indent=2)


def verify_module(
    *,
    policy: ModulePolicy,
    override: ModulePolicyOverride | None = None,
    mode: VerificationMode = "preflight",
    post_import_invocation: dict[str, Any] | None = None,
    adapter_name: str = "",
    engagement_id: str = "",
    timeout_seconds: int = 120,
) -> ModuleVerificationResult:
    """Run the full module verification pipeline.

    Args:
        policy: Code-owned module policy.
        override: Optional config narrowing.
        mode: "preflight" or "collection".
        post_import_invocation: Structured invocation for collection mode.
        adapter_name: For error context.
        engagement_id: For error context.
        timeout_seconds: PowerShell timeout.

    Returns:
        ModuleVerificationResult.

    Raises:
        ModuleProvenanceError: Provenance rejected.
        ModuleAmbiguityError: Multiple candidates.
        ModuleExecutionUnsupportedError: Provenance OK, platform incompatible.
        VerificationInfrastructureError: Template failed.
        CollectionError: Tool invocation failed after verification passed.
    """
    exe = get_powershell_executable()
    template = get_template_path()

    input_blob = build_input_blob(
        policy=policy,
        override=override,
        mode=mode,
        post_import_invocation=post_import_invocation,
    )

    tmp_dir = Path(tempfile.mkdtemp(prefix="gxassessms_verify_"))
    try:
        input_path = tmp_dir / "input.json"
        report_path = tmp_dir / "report.json"
        input_path.write_text(input_blob, encoding="utf-8")

        cmd = [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(template),
            "-InputPath",
            str(input_path),
            "-ReportPath",
            str(report_path),
            "-StagingDir",
            str(tmp_dir / "candidates"),
        ]

        logger.info(
            "[%s] Running module verification (%s, mode=%s)",
            adapter_name or "adapter",
            exe,
            mode,
        )

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                shell=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise VerificationInfrastructureError(
                f"Verification timed out after {timeout_seconds}s",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                exit_code=None,
                stderr_snippet=None,
                report_path=str(report_path),
            ) from exc
        except OSError as exc:
            raise VerificationInfrastructureError(
                f"PowerShell not accessible: {exe!r} ({exc})",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
            ) from exc

        # Always try to read the report, regardless of exit code
        exit_code = proc.returncode
        stderr = (proc.stderr or b"").decode(errors="replace")[:500]

        try:
            result = parse_verification_report(report_path)
        except VerificationInfrastructureError as exc:
            raise VerificationInfrastructureError(
                f"Verification report missing or unreadable (exit code {exit_code})",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                exit_code=exit_code,
                stderr_snippet=stderr,
                report_path=str(report_path),
            ) from exc

        _log_provenance(result, adapter_name)

        if not result.provenance_approved:
            if "ambiguity" in result.rejection_reasons:
                raise ModuleAmbiguityError(
                    f"Multiple candidates satisfy policy for {policy.module_name}",
                    adapter_name=adapter_name,
                    engagement_id=engagement_id,
                    verification_result=result,
                )
            raise ModuleProvenanceError(
                f"Module {policy.module_name} failed provenance verification: "
                f"{', '.join(result.rejection_reasons)}",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                verification_result=result,
            )

        if not result.execution_supported:
            raise ModuleExecutionUnsupportedError(
                f"Module {policy.module_name} provenance verified but "
                f"cannot execute on this platform",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                verification_result=result,
            )

        if exit_code != 0 and mode == "collection":
            raise CollectionError(
                f"Module verified but tool exited with code {exit_code}: {stderr}",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
            )

        return result

    finally:
        shutil.rmtree(
            tmp_dir,
            onexc=lambda _f, p, e: logger.warning("Failed to clean up temp dir: %s (%s)", p, e),
        )


def _log_provenance(result: ModuleVerificationResult, adapter_name: str) -> None:
    """Emit structured provenance log events."""
    name = adapter_name or result.module_name

    if result.provenance_approved and result.execution_supported:
        ev = result.evidence_path or "unknown"
        ac = result.approved_candidate
        level = logging.INFO
        # Degraded signature -> WARNING
        if (
            ev == "hash_only"
            and ac
            and ac.staged_signature_status
            not in (
                None,
                "platform_unsupported",
            )
        ):
            level = logging.WARNING
            ev = "hash_only, degraded"

        logger.log(
            level,
            "[%s] provenance=APPROVED execution=SUPPORTED (%s): "
            "version=%s, hash=%s, candidates_discovered=%d",
            name,
            ev,
            ac.version if ac else "?",
            ac.package_hash if ac else "?",
            len(result.candidates),
        )
    elif result.provenance_approved and not result.execution_supported:
        ac = result.approved_candidate
        logger.warning(
            "[%s] provenance=APPROVED execution=UNSUPPORTED (%s): "
            "version=%s, candidates_discovered=%d",
            name,
            result.evidence_path or "?",
            ac.version if ac else "?",
            len(result.candidates),
        )
    else:
        logger.error(
            "[%s] provenance=REJECTED: %s, candidates_discovered=%d",
            name,
            ", ".join(result.rejection_reasons),
            len(result.candidates),
        )
