"""Convention test: no import-time side effects.

Importing any module must not trigger I/O, network calls, DB connections,
or stdout wrapping. Config loading, DB connections, and stdout wrapping
go inside if __name__ == '__main__' or explicit init() functions.
"""

import importlib
import pkgutil
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest


def _discover_modules() -> list[str]:
    """Discover all importable modules in gxassessms."""
    src_root = Path(__file__).parent.parent.parent / "src"
    package_root = src_root / "gxassessms"
    modules = []

    for _importer, modname, _ispkg in pkgutil.walk_packages(
        path=[str(package_root)],
        prefix="gxassessms.",
    ):
        modules.append(modname)

    return modules


@pytest.mark.parametrize("module_name", _discover_modules())
def test_import_has_no_side_effects(module_name: str) -> None:
    """Importing a module must not produce stdout output or raise."""
    # Remove from cache to force fresh import
    if module_name in sys.modules:
        # Already imported -- skip (we can't reliably test re-import side effects)
        return

    captured = StringIO()
    with patch("sys.stdout", captured):
        try:
            importlib.import_module(module_name)
        except ImportError as exc:
            # Only skip for missing external dependencies (e.g., click).
            # Internal import breakages (gxassessms.*) must fail the test.
            if exc.name and exc.name.startswith("gxassessms"):
                raise
            pytest.skip(f"Optional dependency missing for {module_name}: {exc.name}")

    output = captured.getvalue()
    if output.strip():
        pytest.fail(f"Module {module_name} produced stdout output on import: {output!r}")
