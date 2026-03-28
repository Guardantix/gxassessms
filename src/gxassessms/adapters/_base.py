"""Shared adapter utilities.

Platform-aware PowerShell runner, output directory locator, safe subprocess
invocation, and JSON file loader with BOM-aware encoding support.

ScubaGear and other Windows-native tools produce UTF-8-BOM encoded JSON;
``load_json_file`` defaults to ``utf-8-sig`` to strip the BOM transparently.
"""

from __future__ import annotations

import json
import logging
import platform
import re
import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any

from gxassessms.core.contracts.errors import CollectionError

logger = logging.getLogger(__name__)

# Allowlist for extra PowerShell arguments passed via config.
# Matches: -Flag, -Flag:value, -Flag:value-with-dashes, -Flag:a.b,c
_ARG_PATTERN = re.compile(r"^-[A-Za-z][A-Za-z0-9]*(?::[\w\-.,]+)?$")


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_powershell_executable() -> str:
    """Return the platform-appropriate PowerShell executable name.

    Returns:
        ``"powershell.exe"`` on Windows, ``"pwsh"`` on Linux / macOS.
    """
    return "powershell.exe" if platform.system() == "Windows" else "pwsh"


def validate_extra_args(extra_args: list[str]) -> list[str]:
    """Validate extra PowerShell arguments against an allowlist pattern.

    Prevents command injection via crafted configuration values by
    rejecting anything that doesn't look like a well-formed PowerShell
    named parameter.

    Args:
        extra_args: List of argument strings to validate.

    Returns:
        The original list, unmodified, if every entry is safe.

    Raises:
        CollectionError: If any argument fails the allowlist check.
    """
    for arg in extra_args:
        if not _ARG_PATTERN.match(arg):
            raise CollectionError(
                f"Extra argument rejected by allowlist: {arg!r}",
            )
    return extra_args


def run_powershell(
    script: str,
    arguments: list[str] | None,
    timeout_seconds: int,
    adapter_name: str,
    engagement_id: str,
) -> CompletedProcess[bytes]:
    """Execute a PowerShell command, raising ``CollectionError`` on failure.

    Always runs with ``shell=False``, ``capture_output=True``, and
    ``-NoProfile -NonInteractive -Command``.

    Args:
        script: The PowerShell command string to pass to ``-Command``.
        arguments: Optional extra arguments inserted before ``-Command``.
                   Validated via ``validate_extra_args`` before use.
        timeout_seconds: Hard wall-clock timeout in seconds.
        adapter_name: Adapter name for error context.
        engagement_id: Engagement ID for error context.

    Returns:
        ``subprocess.CompletedProcess`` on success (exit code 0).

    Raises:
        CollectionError: On timeout, non-zero exit code, or missing executable.
    """
    exe = get_powershell_executable()
    validated_args: list[str] = []
    if arguments:
        validated_args = validate_extra_args(arguments)

    cmd: list[str] = [
        exe,
        "-NoProfile",
        "-NonInteractive",
        *validated_args,
        "-Command",
        script,
    ]

    logger.info("[%s] Running PowerShell (%s)", adapter_name or "adapter", exe)
    logger.debug("[%s] Full command: %s", adapter_name or "adapter", " ".join(cmd))

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            shell=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise CollectionError(
            f"PowerShell timed out after {timeout_seconds}s",
            adapter_name=adapter_name,
            engagement_id=engagement_id,
        ) from exc
    except OSError as exc:
        raise CollectionError(
            f"PowerShell not accessible ({type(exc).__name__}): {exe!r}",
            adapter_name=adapter_name,
            engagement_id=engagement_id,
        ) from exc

    if result.returncode != 0:
        stderr_snippet = (result.stderr or b"").decode(errors="replace")[:500]
        raise CollectionError(
            f"PowerShell exited with code {result.returncode}: {stderr_snippet}",
            adapter_name=adapter_name,
            engagement_id=engagement_id,
        )

    return result


def find_latest_output_dir(base_dir: Path, prefix: str = "") -> Path:
    """Return the most recently modified subdirectory under *base_dir*.

    Args:
        base_dir: Parent directory to search.
        prefix: If non-empty, only consider subdirectories whose names start
                with this string.

    Returns:
        Path to the most recently modified matching subdirectory.

    Raises:
        CollectionError: If *base_dir* does not exist or no matching
                         subdirectories are found.
    """
    if not base_dir.exists():
        raise CollectionError(
            f"Output base directory does not exist: {base_dir}",
        )

    try:
        candidates = [
            d
            for d in base_dir.iterdir()
            if d.is_dir() and (not prefix or d.name.startswith(prefix))
        ]
    except OSError as exc:
        raise CollectionError(
            f"Cannot read output directory {base_dir}: {exc}",
        ) from exc

    if not candidates:
        raise CollectionError(
            f"No output directories found under {base_dir}"
            + (f" with prefix {prefix!r}" if prefix else ""),
        )

    try:
        return max(candidates, key=lambda d: d.stat().st_mtime)
    except OSError as exc:
        raise CollectionError(
            f"Cannot stat output subdirectory under {base_dir}: {exc}",
        ) from exc


def load_json_file(
    path: Path,
    adapter_name: str = "",
    encoding: str = "utf-8-sig",
) -> Any:
    """Load and parse a JSON file with BOM-aware encoding support.

    The default encoding ``utf-8-sig`` silently strips the UTF-8 BOM that
    Windows-native tools such as ScubaGear write to their output files.

    Args:
        path: Path to the JSON file.
        adapter_name: Adapter name used in error messages.
        encoding: File encoding (default ``utf-8-sig``).

    Returns:
        Parsed JSON value (dict, list, etc.).

    Raises:
        RawOutputValidationError: If the file is missing, empty, or contains
                                   invalid JSON.
    """
    # Local import to avoid potential circular imports at module load time.
    from gxassessms.core.contracts.errors import RawOutputValidationError

    try:
        text = path.read_text(encoding=encoding)
    except OSError as exc:
        raise RawOutputValidationError(
            f"Cannot read output file {path}: {exc}",
            adapter_name=adapter_name,
        ) from exc

    if not text.strip():
        raise RawOutputValidationError(
            f"Output file is empty: {path}",
            adapter_name=adapter_name,
        )

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RawOutputValidationError(
            f"Invalid JSON in {path}: {exc}",
            adapter_name=adapter_name,
        ) from exc
