"""Centralized datetime handling -- UTC everywhere, display-layer conversion only.

All timestamp operations in the codebase go through these functions.
Convention tests ban direct use of datetime.now(), datetime.utcnow(),
and bare fromisoformat() outside this module.
"""

from datetime import UTC, datetime, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo


@lru_cache(maxsize=1)
def _detect_local_tz() -> ZoneInfo | timezone:
    """Detect the system's local timezone. Cached after first call.

    Strategy (portable, no subprocess):
    1. Check TZ env var for a named IANA zone (e.g., "America/New_York").
    2. Use datetime.now().astimezone() to get the system's current UTC offset
       and build a fixed-offset timezone. Works on Linux, macOS, and Windows.
    """
    import os

    # 1. Named zone from TZ env var (common in containers and server configs)
    tz_env = os.environ.get("TZ", "").strip()
    if tz_env and tz_env != "UTC":
        try:
            return ZoneInfo(tz_env)
        except KeyError, ValueError:
            pass  # Invalid zone name -- fall through to offset detection

    # 2. Portable offset detection via the C library's localtime
    try:
        local_dt = datetime.now(UTC).astimezone()
        offset = local_dt.utcoffset()
        if offset is not None and offset.total_seconds() != 0:
            return timezone(offset)
    except OSError, ValueError, OverflowError:
        pass

    return UTC


def utc_now() -> datetime:
    """Current time in UTC. Use instead of datetime.now() or datetime.utcnow()."""
    return datetime.now(UTC)


def parse_utc(iso_string: str) -> datetime:
    """Parse an ISO 8601 string and ensure it's UTC.

    Handles: "Z" suffix, "+00:00" offset, and naive datetimes (assumed UTC).
    Raises ValueError on unparseable input.
    """
    # Normalize "Z" to "+00:00" for fromisoformat
    normalized = iso_string.replace("Z", "+00:00") if iso_string.endswith("Z") else iso_string
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def format_utc(dt: datetime) -> str:
    """Format a UTC datetime as ISO 8601 with Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    utc_dt = dt.astimezone(UTC)
    # Use isoformat and replace +00:00 with Z
    return utc_dt.isoformat().replace("+00:00", "Z")


def utc_to_local(dt: datetime) -> datetime:
    """Convert a UTC datetime to the system's local timezone. Display use only."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(_detect_local_tz())
