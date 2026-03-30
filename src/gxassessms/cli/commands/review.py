"""mseco review -- launch the review UI.

Usage:
    mseco review <engagement-id>

Stub command that delegates to the private package (gxassessms-guardantix)
via the gxassessms.review_ui entry point. If the private package is not
installed, prints a helpful message.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

import click

from gxassessms.cli.output import console

logger = logging.getLogger(__name__)


@click.command("review")
@click.argument("engagement_id")
def review_cmd(engagement_id: str) -> None:
    """Launch the review UI for an engagement.

    Opens a browser-based review interface for browsing findings,
    overriding severities, approving AI narratives, and triggering
    re-renders.

    Requires the gxassessms-guardantix private package to be installed.
    """
    eps = entry_points(group="gxassessms.review_ui")
    ep_list = list(eps)

    if not ep_list:
        console.print(
            "[yellow]Review UI requires gxassessms-guardantix.[/yellow]\n"
            "\n"
            "The review UI (finding browser, severity overrides, AI narrative\n"
            "approval, and re-render triggers) is provided by the Guardantix\n"
            "private package.\n"
            "\n"
            "Install gxassessms-guardantix to enable this command."
        )
        raise SystemExit(1)

    try:
        launch_fn = ep_list[0].load()
        launch_fn(engagement_id)
    except Exception as e:
        console.print(f"[bright_red]Review UI failed:[/bright_red] {e}")
        logger.error("Review UI failed: %s", e)
        raise SystemExit(1) from None
