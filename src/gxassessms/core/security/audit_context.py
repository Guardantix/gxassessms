"""Runtime audit context -- hostname, user, PID, platform.

Used by lifecycle audit manifests (archive, restore, purge) to capture
enough information to attribute actions on shared hosts.

Every value is a string for JSON serialization consistency.  Each
stdlib call is individually wrapped so a failure in one field never
blocks the others -- fail-safe for audit metadata, not fail-fatal.
"""

from __future__ import annotations

import getpass
import logging
import os
import platform as _platform
import socket
import sys

logger = logging.getLogger(__name__)


def build_audit_context() -> dict[str, str]:
    """Return a dict of runtime context for audit manifests.

    Keys: ``hostname``, ``os_user``, ``pid``, ``platform``,
    ``platform_version``.  On failure, individual values fall back to
    ``"unknown"`` rather than raising.
    """
    ctx: dict[str, str] = {}

    try:
        ctx["hostname"] = socket.gethostname()
    except Exception:
        ctx["hostname"] = "unknown"

    try:
        ctx["os_user"] = getpass.getuser()
    except Exception:
        ctx["os_user"] = "unknown"

    try:
        ctx["pid"] = str(os.getpid())
    except Exception:
        ctx["pid"] = "unknown"

    ctx["platform"] = sys.platform

    try:
        ctx["platform_version"] = _platform.version()
    except Exception:
        ctx["platform_version"] = "unknown"

    return ctx
