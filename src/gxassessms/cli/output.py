"""Rich console formatting for CLI output.

Centralizes all Rich formatting: severity colors, status labels,
summary tables, progress indicators, and preflight result display.
Colors are sourced from core/domain/constants.py (single source of truth).

No business logic -- only display formatting.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from rich.console import Console
from rich.table import Table

from gxassessms.core.domain.constants import (
    SEVERITY_COLORS,
    SEVERITY_ORDER,
)

# Module-level console instance for CLI output
console = Console(stderr=True)

# Status colors (not in constants.py -- these are CLI-display-only)
_STATUS_COLORS: dict[str, str] = {
    "PASS": "green",
    "FAIL": "red",
    "WARNING": "yellow",
    "WARN": "yellow",
    "ERROR": "bright_red",
    "N/A": "dim",
    "SKIP": "dim",
    "SKIPPED": "dim",
}

# Engagement state colors (CLI-display-only)
_STATE_COLORS: dict[str, str] = {
    "CREATED": "cyan",
    "COLLECTING": "yellow",
    "COLLECTED": "green",
    "PARSING": "yellow",
    "PARSED": "green",
    "NORMALIZING": "yellow",
    "NORMALIZED": "green",
    "CONSOLIDATING": "yellow",
    "CONSOLIDATED": "green",
    "QA_REVIEW": "yellow",
    "QA_APPROVED": "green",
    "RENDERING": "yellow",
    "COMPLETE": "bright_green",
    "FAILED": "bright_red",
}


def format_severity(severity: str) -> str:
    """Return a Rich markup string for a severity label.

    Uses SEVERITY_COLORS from constants.py for consistent coloring
    across CLI and reports.

    Args:
        severity: Severity level string (e.g., "CRITICAL", "HIGH").

    Returns:
        Rich markup string, e.g., "[bright_red]CRITICAL[/bright_red]".
    """
    color = SEVERITY_COLORS.get(severity, "white")
    return f"[{color}]{severity}[/{color}]"


def format_status(status: str) -> str:
    """Return a Rich markup string for a status label.

    Args:
        status: Status string (e.g., "PASS", "FAIL", "WARNING").

    Returns:
        Rich markup string with appropriate color.
    """
    color = _STATUS_COLORS.get(status, "white")
    return f"[{color}]{status}[/{color}]"


def format_state(state: str) -> str:
    """Return a Rich markup string for an engagement state.

    Args:
        state: EngagementState value string.

    Returns:
        Rich markup string with appropriate color.
    """
    color = _STATE_COLORS.get(state, "white")
    return f"[{color}]{state}[/{color}]"


def make_findings_summary_table(
    counts: dict[str, int],
) -> Table:
    """Create a Rich Table summarizing finding counts by severity.

    Args:
        counts: Mapping of severity level to count (e.g., {"CRITICAL": 3}).

    Returns:
        Rich Table with one row, columns for each severity + total.
    """
    table = Table(title="Findings Summary", show_header=True)

    # Add severity columns in order (highest first)
    ordered_severities = sorted(
        SEVERITY_ORDER.keys(),
        key=lambda s: SEVERITY_ORDER[s],
        reverse=True,
    )
    for sev in ordered_severities:
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_column(sev, style=color, justify="right")

    table.add_column("Total", style="bold", justify="right")

    # Single data row
    total = 0
    row: list[str] = []
    for sev in ordered_severities:
        count = counts.get(sev, 0)
        total += count
        row.append(str(count))
    row.append(str(total))
    table.add_row(*row)

    return table


def make_engagement_status_table(
    engagement: dict[str, Any],
) -> Table:
    """Create a Rich Table showing engagement status details.

    Args:
        engagement: Engagement data dict with keys like engagement_id,
            client_name, state, created_at.

    Returns:
        Rich Table with key-value rows.
    """
    table = Table(title="Engagement Status", show_header=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    field_order = [
        ("engagement_id", "Engagement ID"),
        ("client_name", "Client"),
        ("state", "State"),
        ("created_at", "Created"),
        ("tenant_id", "Tenant ID"),
    ]

    for key, label in field_order:
        value = engagement.get(key, "")
        if key == "state" and value:
            value = format_state(str(value))
        table.add_row(label, str(value))

    return table


def make_adapter_list_table(
    adapters: list[dict[str, Any]],
) -> Table:
    """Create a Rich Table listing discovered adapters.

    Args:
        adapters: List of adapter info dicts with name, capabilities, etc.

    Returns:
        Rich Table with adapter details.
    """
    table = Table(title="Discovered Adapters", show_header=True)
    table.add_column("Name", style="bold")
    table.add_column("Capabilities")
    table.add_column("Status")

    for adapter in adapters:
        name = adapter.get("name", "")
        caps = ", ".join(sorted(adapter.get("capabilities", [])))
        status = format_status(adapter.get("status", "OK"))
        table.add_row(name, caps, status)

    return table


def print_preflight_result(
    results: list[dict[str, str]],
    console: Console | None = None,
) -> None:
    """Print preflight validation results as a Rich table.

    Args:
        results: List of dicts with keys: check, status, message.
        console: Optional Console instance (for testing).
    """
    con = console or Console(stderr=True)
    table = Table(title="Preflight Validation", show_header=True)
    table.add_column("Check", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Details")

    for result in results:
        status_str = format_status(result.get("status", ""))
        table.add_row(
            result.get("check", ""),
            status_str,
            result.get("message", ""),
        )

    con.print(table)

    # Summary line
    status_counts = Counter(r.get("status") for r in results)
    pass_count = status_counts.get("PASS", 0)
    fail_count = status_counts.get("FAIL", 0)
    warn_count = status_counts.get("WARN", 0)

    if fail_count > 0:
        con.print(
            f"\n[bright_red]FAILED[/bright_red]: "
            f"{fail_count} check(s) failed, {warn_count} warning(s), "
            f"{pass_count} passed"
        )
    elif warn_count > 0:
        con.print(f"\n[yellow]WARNING[/yellow]: {warn_count} warning(s), {pass_count} passed")
    else:
        con.print(f"\n[green]ALL PASSED[/green]: {pass_count} check(s) passed")
