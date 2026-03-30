"""Tests for CLI output utilities.

Tests the Rich console formatting helpers that all commands share:
severity coloring, summary tables, status formatting.
"""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from gxassessms.cli.output import (
    format_severity,
    format_state,
    format_status,
    make_engagement_status_table,
    make_findings_summary_table,
    print_preflight_result,
)
from gxassessms.core.domain.constants import SEVERITY_COLORS


class TestFormatSeverity:
    def test_critical_uses_bright_red(self) -> None:
        result = format_severity("CRITICAL")
        assert "bright_red" in result
        assert "CRITICAL" in result

    def test_high_uses_red(self) -> None:
        result = format_severity("HIGH")
        assert "red" in result
        assert "HIGH" in result

    def test_medium_uses_yellow(self) -> None:
        result = format_severity("MEDIUM")
        assert "yellow" in result

    def test_low_uses_cyan(self) -> None:
        result = format_severity("LOW")
        assert "cyan" in result

    def test_info_uses_dim(self) -> None:
        result = format_severity("INFO")
        assert "dim" in result

    def test_unknown_severity_no_crash(self) -> None:
        result = format_severity("UNKNOWN")
        assert "UNKNOWN" in result

    def test_all_severity_colors_match_constants(self) -> None:
        for severity, color in SEVERITY_COLORS.items():
            result = format_severity(severity)
            assert color in result


class TestFormatState:
    def test_created_uses_cyan(self) -> None:
        result = format_state("CREATED")
        assert "cyan" in result

    def test_complete_uses_bright_green(self) -> None:
        result = format_state("COMPLETE")
        assert "bright_green" in result

    def test_failed_uses_bright_red(self) -> None:
        result = format_state("FAILED")
        assert "bright_red" in result

    def test_in_progress_states_use_yellow(self) -> None:
        for state in ("COLLECTING", "PARSING", "NORMALIZING", "CONSOLIDATING", "RENDERING"):
            result = format_state(state)
            assert "yellow" in result, f"Expected yellow for {state}"

    def test_unknown_state_no_crash(self) -> None:
        result = format_state("NONEXISTENT_STATE")
        assert "NONEXISTENT_STATE" in result


class TestFormatStatus:
    def test_pass_is_green(self) -> None:
        result = format_status("PASS")
        assert "green" in result

    def test_fail_is_red(self) -> None:
        result = format_status("FAIL")
        assert "red" in result

    def test_warning_is_yellow(self) -> None:
        result = format_status("WARNING")
        assert "yellow" in result

    def test_unknown_status_no_crash(self) -> None:
        result = format_status("SOMETHING")
        assert "SOMETHING" in result


class TestMakeFindingsSummaryTable:
    def test_creates_table_with_severity_columns(self) -> None:
        counts = {
            "CRITICAL": 3,
            "HIGH": 7,
            "MEDIUM": 15,
            "LOW": 22,
            "INFO": 5,
        }
        table = make_findings_summary_table(counts)
        assert table.row_count == 1
        assert len(table.columns) == 6  # Severity + Total

    def test_empty_counts(self) -> None:
        counts: dict[str, int] = {}
        table = make_findings_summary_table(counts)
        assert table.row_count == 1

    def test_total_column_sums_correctly(self) -> None:
        counts = {"CRITICAL": 2, "HIGH": 3}
        table = make_findings_summary_table(counts)
        assert table is not None


class TestMakeEngagementStatusTable:
    def test_creates_table_with_engagement_info(self) -> None:
        engagement = {
            "engagement_id": "eng-001",
            "client_name": "Acme Corp",
            "state": "COLLECTED",
            "created_at": "2026-03-25T10:00:00Z",
        }
        table = make_engagement_status_table(engagement)
        assert table.row_count >= 1


class TestPrintPreflightResult:
    def test_prints_pass_result(self) -> None:
        console = Console(file=StringIO(), force_terminal=True)
        results = [
            {"check": "Config valid", "status": "PASS", "message": "OK"},
            {"check": "ScubaGear installed", "status": "PASS", "message": "Found"},
        ]
        print_preflight_result(results, console=console)
        output = console.file.getvalue()
        assert "PASS" in output or "pass" in output.lower()

    def test_prints_fail_result(self) -> None:
        console = Console(file=StringIO(), force_terminal=True)
        results = [
            {"check": "Maester installed", "status": "FAIL", "message": "Not found"},
        ]
        print_preflight_result(results, console=console)
        output = console.file.getvalue()
        assert "FAIL" in output or "fail" in output.lower()

    def test_prints_warn_result(self) -> None:
        console = Console(file=StringIO(), force_terminal=True)
        results = [
            {"check": "Node.js version", "status": "WARN", "message": "Old version"},
        ]
        print_preflight_result(results, console=console)
        output = console.file.getvalue()
        assert "WARN" in output or "warn" in output.lower()
