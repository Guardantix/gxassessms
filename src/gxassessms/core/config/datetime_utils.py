"""Centralized datetime handling -- UTC everywhere, display-layer conversion only.

All timestamp operations in the codebase go through these functions.
Convention tests ban direct use of datetime.now(), datetime.utcnow(),
and bare fromisoformat() outside this module.
"""

from datetime import UTC, datetime


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
    """Convert a UTC datetime to the system's local timezone. Display use only.

    Uses Python's built-in OS timezone support (no argument to astimezone()),
    which correctly handles DST on all platforms including Windows.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone()
