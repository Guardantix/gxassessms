"""Shared POSIX path validation for manifest keys and confinement checks.

Single source of truth for path format rules. Used by:
- RawToolOutput field validators (model-level enforcement)
- confine_and_resolve() (defense-in-depth at the trust boundary)

All checks are pure string operations (no filesystem I/O).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

# Windows reserved device names (case-insensitive, with or without extension).
# Matches: CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9
_RESERVED_NAME_RE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..+)?$",
    re.IGNORECASE,
)

# Characters illegal in Windows filenames (beyond what POSIX allows).
_ILLEGAL_CHARS = frozenset('<>"|?*')


def validate_canonical_posix_path(path_str: str) -> None:
    """Validate that *path_str* is a safe, canonical POSIX-relative path.

    Raises ValueError with a descriptive message on any violation.
    """
    if not path_str:
        raise ValueError("Path must not be empty")

    if "\\" in path_str:
        raise ValueError(f"Path contains backslash (use forward slashes): {path_str!r}")

    if path_str.startswith("/"):
        raise ValueError(f"Path must not be absolute (leading '/'): {path_str!r}")

    parts = PurePosixPath(path_str).parts
    for part in parts:
        if part == "..":
            raise ValueError(f"Path contains parent traversal (..): {path_str!r}")

    # Colon in any segment (catches drive letters like C:)
    for part in parts:
        if ":" in part:
            raise ValueError(f"Path segment contains colon: {part!r} in {path_str!r}")

    # Round-trip normalization: the path must be in canonical form.
    # PurePosixPath(".") round-trips cleanly, so check for "." explicitly first.
    normalized = str(PurePosixPath(path_str))
    if normalized == ".":
        raise ValueError(
            f"Path is not in canonical form (resolves to current directory): {path_str!r}"
        )
    if normalized != path_str:
        raise ValueError(
            f"Path is not in canonical form: {path_str!r} normalizes to {normalized!r}"
        )

    # Per-segment checks
    for part in parts:
        # Windows reserved device names
        if _RESERVED_NAME_RE.match(part):
            raise ValueError(
                f"Path segment is a Windows reserved device name: {part!r} in {path_str!r}"
            )

        # Trailing dots or spaces
        if part.endswith(".") or part.endswith(" "):
            raise ValueError(f"Path segment has trailing dot or space: {part!r} in {path_str!r}")

        # Illegal Windows characters
        illegal_found = _ILLEGAL_CHARS & set(part)
        if illegal_found:
            raise ValueError(
                f"Path segment contains illegal character(s) "
                f"{sorted(illegal_found)}: {part!r} in {path_str!r}"
            )
