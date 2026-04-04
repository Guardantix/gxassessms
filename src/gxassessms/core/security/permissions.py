"""Directory permission hardening -- secure creation and broad-access detection.

All directory creation in the codebase should go through ``secure_mkdir``
instead of bare ``Path.mkdir()`` calls.  A convention test in
``tests/conventions/test_mkdir_conventions.py`` enforces this.

Cross-platform behaviour:
  - POSIX: directories are created then ``chmod``'d to the requested mode.
    ``Path.mkdir(mode=...)`` is *not* sufficient because the kernel applies
    the process umask, making explicit permissions unreliable.
  - Windows: ``os.chmod`` only toggles ``FILE_ATTRIBUTE_READONLY``, not
    POSIX permission bits.  We skip ``chmod`` entirely and rely on NTFS
    ACL inheritance from the user profile directory.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

SECURE_DIR_MODE: int = 0o700
"""Canonical restrictive mode for directories holding sensitive data."""

_GROUP_WORLD_MASK: int = 0o077
"""Mask for group + world permission bits."""


class DirectoryPermissionCheck(NamedTuple):
    """Result of checking a directory's permission bits."""

    path: Path
    is_broad_access: bool
    mode_octal: str | None  # e.g. "0o755"; None on Windows or missing path
    warnings: tuple[str, ...]


# ---------------------------------------------------------------------------
# secure_mkdir
# ---------------------------------------------------------------------------


def secure_mkdir(
    path: Path,
    *,
    mode: int = SECURE_DIR_MODE,
    parents: bool = False,
    exist_ok: bool = False,
) -> None:
    """Create a directory and enforce restrictive POSIX permissions.

    On Windows, ``chmod`` is skipped -- NTFS ACLs are managed separately
    and ``os.chmod`` only toggles FILE_ATTRIBUTE_READONLY, which is not
    what we want.

    When *exist_ok* is True and the directory already exists, ``chmod``
    still runs -- this intentionally tightens overly-permissive
    directories to the secure default.

    When *parents* is True, each **newly created** ancestor also gets
    ``chmod``'d.  Pre-existing ancestors are left untouched.
    """
    if sys.platform == "win32":
        path.mkdir(parents=parents, exist_ok=exist_ok)
        return

    # Find the deepest ancestor that already exists *before* creating
    # anything, so we know which directories are newly created.
    existing_ancestor = path
    while not existing_ancestor.exists():
        existing_ancestor = existing_ancestor.parent

    path.mkdir(parents=parents, exist_ok=exist_ok)

    # chmod target (even if it already existed with exist_ok=True)
    path.chmod(mode)

    # chmod newly created parent directories (only if new dirs were actually created)
    if parents and existing_ancestor != path:
        current = path.parent
        while current != existing_ancestor:
            current.chmod(mode)
            current = current.parent


# ---------------------------------------------------------------------------
# check_directory_permissions
# ---------------------------------------------------------------------------


def check_directory_permissions(path: Path) -> DirectoryPermissionCheck:
    """Check whether a directory has group- or world-accessible bits set.

    Never raises -- callers expect a result, not an exception.
    """
    if sys.platform == "win32":
        return DirectoryPermissionCheck(
            path=path,
            is_broad_access=False,
            mode_octal=None,
            warnings=("Windows ACL checking not implemented; verify permissions manually",),
        )

    try:
        stat_result = path.stat()
    except OSError as exc:
        return DirectoryPermissionCheck(
            path=path,
            is_broad_access=False,
            mode_octal=None,
            warnings=(f"Cannot stat {path}: {exc}",),
        )

    mode = stat_result.st_mode & 0o777
    mode_octal = f"0o{mode:03o}"

    if mode & _GROUP_WORLD_MASK:
        return DirectoryPermissionCheck(
            path=path,
            is_broad_access=True,
            mode_octal=mode_octal,
            warnings=(
                f"{path} has broad permissions ({mode_octal}); "
                f"group/world bits are set -- expected {SECURE_DIR_MODE:#o} or stricter",
            ),
        )

    return DirectoryPermissionCheck(
        path=path,
        is_broad_access=False,
        mode_octal=mode_octal,
        warnings=(),
    )


# ---------------------------------------------------------------------------
# warn_broad_permissions
# ---------------------------------------------------------------------------


def warn_broad_permissions(path: Path, context: str) -> bool:
    """Log a warning if *path* has group- or world-accessible bits.

    Returns True if a warning was logged, False otherwise.
    Advisory only -- never raises, never blocks the calling operation.
    """
    try:
        result = check_directory_permissions(path)
    except Exception:
        logger.warning("Permission check failed for %s (%s)", path, context)
        return False

    if result.is_broad_access:
        for warning in result.warnings:
            logger.warning("%s: %s", context, warning)
        return True

    return False
