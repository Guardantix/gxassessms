"""Tests for centralized datetime handling."""

from datetime import datetime, timezone

from gxassessms.core.config.datetime_utils import (
    format_utc,
    parse_utc,
    utc_now,
    utc_to_local,
)


class TestUtcNow:
    def test_returns_utc_datetime(self) -> None:
        now = utc_now()
        assert now.tzinfo == timezone.utc

    def test_returns_current_time(self) -> None:
        before = datetime.now(timezone.utc)
        now = utc_now()
        after = datetime.now(timezone.utc)
        assert before <= now <= after


class TestParseUtc:
    def test_parses_iso_format_with_z(self) -> None:
        result = parse_utc("2026-03-25T10:30:00Z")
        assert result.year == 2026
        assert result.month == 3
        assert result.day == 25
        assert result.hour == 10
        assert result.minute == 30
        assert result.tzinfo == timezone.utc

    def test_parses_iso_format_with_offset(self) -> None:
        result = parse_utc("2026-03-25T10:30:00+00:00")
        assert result.tzinfo == timezone.utc

    def test_parses_naive_datetime_as_utc(self) -> None:
        result = parse_utc("2026-03-25T10:30:00")
        assert result.tzinfo == timezone.utc

    def test_raises_on_invalid_format(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            parse_utc("not-a-date")


class TestFormatUtc:
    def test_formats_to_iso_with_z(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0, tzinfo=timezone.utc)
        result = format_utc(dt)
        assert result == "2026-03-25T10:30:00Z"

    def test_formats_microseconds(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0, 123456, tzinfo=timezone.utc)
        result = format_utc(dt)
        assert result == "2026-03-25T10:30:00.123456Z"


class TestUtcToLocal:
    def test_returns_datetime_with_local_tz(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0, tzinfo=timezone.utc)
        local = utc_to_local(dt)
        assert local.tzinfo is not None
        # Converting back to UTC should give the same instant
        back_to_utc = local.astimezone(timezone.utc)
        assert back_to_utc == dt
