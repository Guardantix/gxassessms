"""mseco compute-module-hash -- hash a PowerShell module directory.

Usage:
    mseco compute-module-hash --manifest-path /path/to/Module/X.Y.Z/Module.psd1

Derives ModuleBase from the manifest path, runs reparse point scan,
confinement check, and tree hash computation. Outputs the hash and
module metadata for inclusion in adapter policy.py files.
"""

from __future__ import annotations

from pathlib import Path

import click

from gxassessms.cli.output import console


@click.command("compute-module-hash")
@click.option(
    "--manifest-path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Exact path to the module .psd1 manifest file.",
)
def compute_hash_cmd(manifest_path: str) -> None:
    """Compute sha256tree:v1 hash for a PowerShell module directory.

    Requires --manifest-path to the exact .psd1 file. Derives ModuleBase
    from the manifest's parent directory. No module-name resolution, no
    version guessing.
    """
    from gxassessms.adapters._tree_hash import compute_tree_hash

    psd1 = Path(manifest_path)
    if psd1.suffix.lower() != ".psd1":
        console.print(f"[bright_red]Error:[/bright_red] Expected a .psd1 file, got: {psd1.name}")
        raise SystemExit(1)

    module_root = psd1.parent

    console.print(f"[bold]Module:[/bold] {psd1.stem}")
    console.print(f"[bold]Path:[/bold] {module_root}")

    try:
        tree_hash = compute_tree_hash(module_root)
    except ValueError as exc:
        console.print(f"[bright_red]Error:[/bright_red] {exc}")
        raise SystemExit(1) from None
    except OSError as exc:
        console.print(f"[bright_red]Error:[/bright_red] Cannot read module: {exc}")
        raise SystemExit(1) from None

    console.print(f"[bold]Hash:[/bold] {tree_hash}")
    console.print(f'\nAdd to adapter policy.py:\n    "{tree_hash}",')
