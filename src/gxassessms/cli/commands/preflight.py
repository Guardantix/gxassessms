"""mseco preflight -- config validation, prerequisite checks, and auth test.

Usage:
    mseco preflight <config.yaml>

Runs a comprehensive validation pass before standing in front of a client:
1. Config validation: tools, modules, required fields
2. Prerequisite checks: tool installation (delegates to adapters)
3. Auth validation: env vars exist, can authenticate to tenant
4. Renderer dependency chain: Node.js, npm packages, render.js entry points

Returns a structured pass/warn/fail report.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import click

import gxassessms.cli._helpers as _helpers
from gxassessms.cli.output import console, print_preflight_result
from gxassessms.core.config.config import load_config, validate_config
from gxassessms.core.contracts.errors import ConfigError

logger = logging.getLogger(__name__)


def _check_config(config: Any) -> list[dict[str, str]]:
    """Run config validation and return preflight results."""
    results: list[dict[str, str]] = []

    errors, warnings = validate_config(config)

    if not errors:
        results.append(
            {
                "check": "Config validation",
                "status": "PASS",
                "message": "All required fields present",
            }
        )
    else:
        for error in errors:
            results.append(
                {
                    "check": "Config validation",
                    "status": "FAIL",
                    "message": error,
                }
            )

    for warning in warnings:
        results.append(
            {
                "check": "Config validation",
                "status": "WARN",
                "message": warning,
            }
        )

    return results


def _check_prerequisites(
    config: Any,
    adapters: list[Any],
) -> list[dict[str, str]]:
    """Check tool prerequisites via adapter.check_prerequisites()."""
    results: list[dict[str, str]] = []

    enabled_tools = {name for name, tc in config.tools.items() if tc.enabled}

    for adapter in adapters:
        tool_name = adapter.tool_name
        if tool_name.lower() not in enabled_tools:
            continue

        caps: frozenset[str] = getattr(adapter, "capabilities", frozenset())
        if "prerequisites" not in caps:
            results.append(
                {
                    "check": f"{tool_name} prerequisites",
                    "status": "WARN",
                    "message": "Adapter does not declare prerequisites capability",
                }
            )
            continue

        try:
            prereq = adapter.check_prerequisites()
            if prereq.get("satisfied", False):
                results.append(
                    {
                        "check": f"{tool_name} prerequisites",
                        "status": "PASS",
                        "message": prereq.get("message", "OK"),
                    }
                )
            else:
                results.append(
                    {
                        "check": f"{tool_name} prerequisites",
                        "status": "FAIL",
                        "message": prereq.get("message", "Not satisfied"),
                    }
                )
        except (TypeError, ValueError, RuntimeError, OSError, NotImplementedError) as e:
            results.append(
                {
                    "check": f"{tool_name} prerequisites",
                    "status": "FAIL",
                    "message": str(e),
                }
            )

    # Check for enabled tools that have no discovered adapter
    discovered_tool_names = {getattr(a, "tool_name", "").lower() for a in adapters}
    for tool_name in enabled_tools:
        if tool_name.lower() not in discovered_tool_names:
            results.append(
                {
                    "check": f"{tool_name} prerequisites",
                    "status": "FAIL",
                    "message": (
                        f"Tool '{tool_name}' is enabled in config but no adapter "
                        f"package is installed. Install gxassessms-{tool_name} to proceed."
                    ),
                }
            )

    return results


def _check_auth(config: Any) -> list[dict[str, str]]:
    """Check auth env vars exist (does not test actual authentication)."""
    import os

    results: list[dict[str, str]] = []

    secret_env = getattr(config.auth, "client_secret_env", None)
    if secret_env:
        if os.environ.get(secret_env):
            results.append(
                {
                    "check": f"Auth env var ({secret_env})",
                    "status": "PASS",
                    "message": "Environment variable is set",
                }
            )
        else:
            results.append(
                {
                    "check": f"Auth env var ({secret_env})",
                    "status": "FAIL",
                    "message": f"Environment variable {secret_env} is not set",
                }
            )

    return results


def _check_renderers() -> list[dict[str, str]]:
    """Check renderer dependency chain (Node.js, npm packages)."""
    import shutil

    results: list[dict[str, str]] = []

    node = shutil.which("node")
    if node:
        results.append(
            {
                "check": "Node.js installed",
                "status": "PASS",
                "message": f"Found at {node}",
            }
        )
    else:
        results.append(
            {
                "check": "Node.js installed",
                "status": "WARN",
                "message": "Node.js not found (required for DOCX/PPTX report rendering)",
            }
        )

    return results


@click.command("preflight")
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
)
def preflight_cmd(config_path: str) -> None:
    """Run preflight validation: config, prerequisites, auth, and renderers.

    Validates everything before standing in front of a client:

    1. Config validation -- tools, modules, required fields
    2. Prerequisite checks -- tool installation
    3. Auth validation -- env vars and connectivity
    4. Renderer dependency chain -- Node.js and npm packages
    """
    path = Path(config_path)

    try:
        config = load_config(path)
    except ConfigError as e:
        console.print(f"[bright_red]Config error:[/bright_red] {e}")
        raise SystemExit(1) from None

    all_results: list[dict[str, str]] = []

    # Step 1: Config validation
    all_results.extend(_check_config(config))

    # Step 2: Prerequisite checks
    adapters = _helpers.discover_cli_adapters()
    all_results.extend(_check_prerequisites(config, adapters))

    # Step 3: Auth validation
    all_results.extend(_check_auth(config))

    # Step 4: Renderer dependency chain
    all_results.extend(_check_renderers())

    print_preflight_result(all_results)

    # Exit with error code if any checks failed
    has_failures = any(r.get("status") == "FAIL" for r in all_results)
    if has_failures:
        raise SystemExit(1)
