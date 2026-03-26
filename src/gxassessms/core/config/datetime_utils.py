"""Centralized datetime handling -- UTC everywhere, display-layer conversion only.

All timestamp operations in the codebase go through these functions.
Convention tests ban direct use of datetime.now(), datetime.utcnow(),
and bare fromisoformat() outside this module.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import time as _time


def _detect_local_tz() -> ZoneInfo | timezone:
    """Detect the system's local timezone."""
    import subprocess

    try:
        local_name = _time.tzname[0]
        if local_name and local_name != "UTC":
            result = subprocess.run(
                ["timedatectl", "show", "--property=Timezone", "--value"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0 and result.stdout.strip():
                return ZoneInfo(result.stdout.strip())
    except (OSError, KeyError, subprocess.SubprocessError, ValueError):
        pass
    # Fallback: use the system's UTC offset
    return timezone.utc


# Detect local timezone at import time (no I/O, no side effects)
LOCAL_TZ: ZoneInfo | timezone = _detect_local_tz()


def utc_now() -> datetime:
    """Current time in UTC. Use instead of datetime.now() or datetime.utcnow()."""
    return datetime.now(timezone.utc)


def parse_utc(iso_string: str) -> datetime:
    """Parse an ISO 8601 string and ensure it's UTC.

    Handles: "Z" suffix, "+00:00" offset, and naive datetimes (assumed UTC).
    Raises ValueError on unparseable input.
    """
    # Normalize "Z" to "+00:00" for fromisoformat
    normalized = iso_string.replace("Z", "+00:00") if iso_string.endswith("Z") else iso_string
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    """Format a UTC datetime as ISO 8601 with Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc_dt = dt.astimezone(timezone.utc)
    # Use isoformat and replace +00:00 with Z
    return utc_dt.isoformat().replace("+00:00", "Z")


def utc_to_local(dt: datetime) -> datetime:
    """Convert a UTC datetime to the system's local timezone. Display use only."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(LOCAL_TZ)
