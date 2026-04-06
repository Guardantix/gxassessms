"""Tests for centralized datetime handling."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from gxassessms.core.config.datetime_utils import (
    format_utc,
    from_epoch,
    parse_utc,
    utc_now,
    utc_to_local,
)


class TestUtcNow:
    def test_returns_utc_datetime(self) -> None:
        now = utc_now()
        assert now.tzinfo == UTC

    def test_returns_current_time(self) -> None:
        before = datetime.now(UTC)
        now = utc_now()
        after = datetime.now(UTC)
        assert before <= now <= after


class TestParseUtc:
    def test_parses_iso_format_with_z(self) -> None:
        result = parse_utc("2026-03-25T10:30:00Z")
        assert result.year == 2026
        assert result.month == 3
        assert result.day == 25
        assert result.hour == 10
        assert result.minute == 30
        assert result.tzinfo == UTC

    def test_parses_iso_format_with_offset(self) -> None:
        result = parse_utc("2026-03-25T10:30:00+00:00")
        assert result.tzinfo == UTC

    def test_parses_naive_datetime_as_utc(self) -> None:
        result = parse_utc("2026-03-25T10:30:00")
        assert result.tzinfo == UTC

    def test_raises_on_invalid_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid isoformat"):
            parse_utc("not-a-date")

    def test_converts_non_utc_offset_to_utc(self) -> None:
        result = parse_utc("2026-03-25T12:30:00+05:30")
        assert result.tzinfo == UTC
        assert result.hour == 7
        assert result.minute == 0


class TestFormatUtc:
    def test_formats_to_iso_with_z(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0, tzinfo=UTC)
        result = format_utc(dt)
        assert result == "2026-03-25T10:30:00Z"

    def test_formats_microseconds(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0, 123456, tzinfo=UTC)
        result = format_utc(dt)
        assert result == "2026-03-25T10:30:00.123456Z"

    def test_raises_on_naive_datetime(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0)
        with pytest.raises(ValueError, match="timezone-aware"):
            format_utc(dt)

    def test_converts_non_utc_aware_datetime(self) -> None:
        tz_plus5 = timezone(timedelta(hours=5))
        dt = datetime(2026, 3, 25, 15, 30, 0, tzinfo=tz_plus5)
        result = format_utc(dt)
        assert result == "2026-03-25T10:30:00Z"


class TestFromEpoch:
    def test_zero_epoch_is_1970(self) -> None:
        result = from_epoch(0)
        assert result.year == 1970
        assert result.month == 1
        assert result.day == 1
        assert result.hour == 0
        assert result.tzinfo == UTC

    def test_known_value_round_trip(self) -> None:
        # 2026-03-25T10:30:00Z = 1774434600
        result = from_epoch(1774434600)
        assert result.year == 2026
        assert result.month == 3
        assert result.day == 25
        assert result.hour == 10
        assert result.minute == 30

    def test_result_is_utc_aware(self) -> None:
        result = from_epoch(1000000)
        assert result.tzinfo == UTC

    def test_float_accepted(self) -> None:
        result = from_epoch(1000000.5)
        assert result.tzinfo == UTC
        assert result.microsecond == 500000

    def test_negative_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            from_epoch(-1)


class TestUtcToLocal:
    def test_returns_datetime_with_local_tz(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0, tzinfo=UTC)
        local = utc_to_local(dt)
        assert local.tzinfo is not None
        # Converting back to UTC should give the same instant
        back_to_utc = local.astimezone(UTC)
        assert back_to_utc == dt

    def test_naive_datetime_assumed_utc(self) -> None:
        dt = datetime(2026, 3, 25, 10, 30, 0)
        local = utc_to_local(dt)
        assert local.tzinfo is not None
        back_to_utc = local.astimezone(UTC)
        assert back_to_utc.hour == 10


class TestFromEpoch:
    def test_returns_utc_datetime(self) -> None:
        """from_epoch always returns a UTC-aware datetime."""
        result = from_epoch(0.0)
        assert result.tzinfo == UTC

    def test_converts_known_epoch(self) -> None:
        """Unix epoch 0 is 1970-01-01T00:00:00Z."""
        result = from_epoch(0.0)
        assert result.year == 1970
        assert result.month == 1
        assert result.day == 1
        assert result.hour == 0
        assert result.minute == 0

    def test_converts_modern_timestamp(self) -> None:
        """A known timestamp converts correctly."""
        # 2026-03-25T10:00:00Z = 1774432800.0
        result = from_epoch(1774432800.0)
        assert result.year == 2026
        assert result.month == 3
        assert result.tzinfo == UTC
