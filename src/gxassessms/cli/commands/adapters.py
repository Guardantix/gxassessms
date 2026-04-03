"""mseco adapters -- adapter discovery, prerequisite checks, and scaffolding.

Subcommands:
    mseco adapters list       -- Show discovered adapters
    mseco adapters check      -- Run prerequisite checks for all adapters
    mseco adapters scaffold <name>  -- Generate new adapter package from template

Adapter discovery uses the gxassessms.adapters entry point group.
Third-party adapters in separate packages are discovered automatically.
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

from gxassessms.cli._helpers import discover_adapter_metadata, discover_cli_adapters
from gxassessms.cli.output import console, make_adapter_list_table, print_preflight_result

logger = logging.getLogger(__name__)


@click.group("adapters")
def adapters_group() -> None:
    """Manage assessment tool adapters (list, check, scaffold)."""
    pass


@adapters_group.command("list")
def list_cmd() -> None:
    """Show all discovered adapters and their capabilities.

    Discovers adapters via the gxassessms.adapters entry point group.
    Third-party adapters in separate packages are included automatically.
    """
    adapters = discover_adapter_metadata()

    if not adapters:
        console.print("[dim]No adapters discovered.[/dim]")
        console.print("\nAdapters are registered via the gxassessms.adapters entry point group.")
        return

    table = make_adapter_list_table(adapters)
    console.print(table)
    console.print(f"\n{len(adapters)} adapter(s) discovered.")


@adapters_group.command("check")
def check_cmd() -> None:
    """Run prerequisite checks for all discovered adapters.

    Calls check_prerequisites() on each adapter that declares the
    'prerequisites' capability. For PowerShell adapters, validates
    baseline policy only (no config overrides). Use ``mseco preflight``
    for policy-complete validation with config overrides.
    """
    adapters = discover_cli_adapters()
    results: list[dict[str, str]] = []

    for adapter in adapters:
        tool_name = getattr(adapter, "tool_name", "unknown")
        caps: frozenset[str] = getattr(adapter, "capabilities", frozenset())

        if "prerequisites" not in caps:
            results.append(
                {
                    "check": f"{tool_name}",
                    "status": "WARN",
                    "message": "No prerequisites capability declared",
                }
            )
            continue

        try:
            prereq = adapter.check_prerequisites()
            if prereq.get("satisfied", False):
                results.append(
                    {
                        "check": tool_name,
                        "status": "PASS",
                        "message": prereq.get("message", "OK"),
                    }
                )
            else:
                results.append(
                    {
                        "check": tool_name,
                        "status": "FAIL",
                        "message": prereq.get("message", "Not satisfied"),
                    }
                )
        except (TypeError, ValueError, RuntimeError, OSError) as e:
            results.append(
                {
                    "check": tool_name,
                    "status": "FAIL",
                    "message": str(e),
                }
            )

    if not results:
        console.print("[dim]No adapters to check.[/dim]")
        return

    print_preflight_result(results)


@adapters_group.command("scaffold")
@click.argument("name")
@click.option(
    "--output-dir",
    type=click.Path(),
    default=".",
    help="Directory to create the adapter package in (default: current directory).",
)
def scaffold_cmd(name: str, output_dir: str) -> None:
    """Generate a new adapter package from the standard template.

    Creates the adapter directory structure with:
    - adapter.py (ToolAdapter protocol implementation)
    - parser.py (tool-specific output parsing)
    - mappings.py (severity/category/dedup-key mappings)
    - fixtures/ (test fixture directory)
    - Conformance test file with TODOs

    The generated code satisfies the ToolAdapter protocol and includes
    inline documentation for each method.
    """
    import re

    # Validate name: must be a safe Python identifier
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", name):
        console.print(
            f"[bright_red]Error:[/bright_red] Invalid adapter name {name!r}. "
            "Name must start with a letter and contain only letters, digits, and underscores."
        )
        raise SystemExit(1)

    output_path = Path(output_dir).resolve() / name
    # Verify the resolved path stays within the intended output directory.
    try:
        output_path.relative_to(Path(output_dir).resolve())
    except ValueError:
        console.print(
            f"[bright_red]Error:[/bright_red] Resolved path {output_path} "
            "escapes the output directory. Aborting."
        )
        raise SystemExit(1) from None

    if output_path.exists():
        console.print(f"[bright_red]Error:[/bright_red] Directory already exists: {output_path}")
        raise SystemExit(1)

    # Create directory structure
    output_path.mkdir(parents=True)
    (output_path / "fixtures").mkdir()
    (output_path / "__init__.py").write_text(
        f'"""Adapter for {name} assessment tool."""\n', encoding="utf-8"
    )

    # adapter.py template
    class_name = name.title().replace("_", "")
    adapter_template = f'''"""{name} adapter -- implements ToolAdapter protocol.

TODO: Implement collect(), parse(), and coverage() methods.
"""

from __future__ import annotations

from typing import Any

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.models import (
    AuthContext,
    CoverageRecord,
    RawToolOutput,
    ToolObservation,
)


class {class_name}Adapter:
    """ToolAdapter implementation for {name}."""

    tool_name: str = "{name}"
    capabilities: frozenset[str] = frozenset({{"collect", "parse", "prerequisites"}})

    def check_prerequisites(self) -> PrerequisiteResult:
        """Check if {name} is installed and available."""
        # TODO: Implement prerequisite check
        return PrerequisiteResult(satisfied=False, message="Not implemented")

    def authenticate(
        self, config: EngagementConfig
    ) -> AuthContext | None:
        """Authenticate to the target tenant. Return None if not needed."""
        # TODO: Implement authentication
        return None

    def collect(
        self, config: EngagementConfig, auth: AuthContext | None
    ) -> RawToolOutput:
        """Execute {name} and return raw output."""
        # TODO: Implement tool execution
        raise NotImplementedError("{name} collect not implemented")

    def validate_raw(self, raw: RawToolOutput) -> None:
        """Validate raw output structure before parsing."""
        # TODO: Implement validation
        pass

    def parse(self, raw: RawToolOutput) -> list[ToolObservation]:
        """Parse raw {name} output into ToolObservations."""
        # TODO: Implement parsing
        return []

    def coverage(self, raw: RawToolOutput) -> list[CoverageRecord]:
        """Report per-control assessment coverage."""
        # TODO: Implement coverage reporting
        return []
'''

    (output_path / "adapter.py").write_text(adapter_template, encoding="utf-8")

    # parser.py template
    parser_template = f'''"""{name} parser -- tool-specific output parsing.

TODO: Implement parsing logic for {name} output format.
"""

from __future__ import annotations

from gxassessms.core.domain.models import ToolObservation


def parse_output(raw_data: dict) -> list[ToolObservation]:
    """Parse {name} raw output into ToolObservations.

    TODO: Implement parsing logic.
    """
    return []
'''

    (output_path / "parser.py").write_text(parser_template, encoding="utf-8")

    # mappings.py template
    mappings_template = f'''"""{name} mappings -- severity, category, and dedup key mappings.

TODO: Define tool-native to domain value mappings.
"""

from __future__ import annotations

# Tool-native severity -> domain Severity mapping
SEVERITY_MAP: dict[str, str] = {{
    # TODO: Map {name}-specific severity levels
    # "Critical": "CRITICAL",
    # "High": "HIGH",
}}

# Tool-native category -> domain Category mapping
CATEGORY_MAP: dict[str, str] = {{
    # TODO: Map {name}-specific categories
}}

# Dedup key rules
DEDUP_KEYS: dict[str, str] = {{
    # TODO: Map check IDs to dedup keys
}}
'''

    (output_path / "mappings.py").write_text(mappings_template, encoding="utf-8")

    # fixtures placeholder
    (output_path / "fixtures" / ".gitkeep").write_text("", encoding="utf-8")

    console.print(f"[bright_green]Adapter scaffolded:[/bright_green] {output_path}")
    console.print("\nCreated:")
    console.print(f"  {output_path}/__init__.py")
    console.print(f"  {output_path}/adapter.py")
    console.print(f"  {output_path}/parser.py")
    console.print(f"  {output_path}/mappings.py")
    console.print(f"  {output_path}/fixtures/")
    console.print(
        f"\nNext steps:"
        f"\n  1. Implement collect(), parse(), and coverage() in adapter.py"
        f"\n  2. Add representative fixtures to fixtures/"
        f"\n  3. Add entry point to pyproject.toml:"
        f'\n     {name} = "<your_package>.{name}:{class_name}Adapter"'
        f"\n  4. Copy test template from tests/adapters/test_adapter_template.py"
    )
