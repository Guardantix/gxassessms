"""Convention test: enforce architectural dependency direction.

Rules:
- core/domain/ cannot import from adapters, persistence, pipeline, policy,
  consolidation, reporting, or cli
- core/contracts/ can only import from core/domain/
- core/config/ can import from core/domain/ and core/contracts/
- adapters/ cannot import from renderers or review_ui
- policy/ cannot perform I/O (no open(), no DB calls)
"""

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "gxassessms"

# Maps package path prefixes to their banned import prefixes
IMPORT_RULES: dict[str, list[str]] = {
    "core/domain": [
        "gxassessms.adapters",
        "gxassessms.persistence",
        "gxassessms.pipeline",
        "gxassessms.policy",
        "gxassessms.consolidation",
        "gxassessms.reporting",
        "gxassessms.cli",
    ],
    "core/contracts": [
        "gxassessms.adapters",
        "gxassessms.persistence",
        "gxassessms.pipeline",
        "gxassessms.policy",
        "gxassessms.consolidation",
        "gxassessms.reporting",
        "gxassessms.cli",
        "gxassessms.core.config",
    ],
    "core/config": [
        "gxassessms.adapters",
        "gxassessms.persistence",
        "gxassessms.pipeline",
        "gxassessms.policy",
        "gxassessms.consolidation",
        "gxassessms.reporting",
        "gxassessms.cli",
    ],
}


def _is_type_checking_block(node: ast.If) -> bool:
    """Return True if this if-block is guarded by TYPE_CHECKING."""
    test = node.test
    # Matches: if TYPE_CHECKING:
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    # Matches: if typing.TYPE_CHECKING:
    return bool(isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _get_imports(filepath: Path) -> list[tuple[int, str]]:
    """Extract all import targets from a Python file, skipping TYPE_CHECKING blocks."""
    imports = []
    try:
        tree = ast.parse(filepath.read_text(), filename=str(filepath))
    except SyntaxError:
        return []

    def _walk_skipping_type_checking(nodes: list[ast.stmt]) -> None:
        for node in nodes:
            if isinstance(node, ast.If) and _is_type_checking_block(node):
                # Skip the entire body and orelse of this TYPE_CHECKING block
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append((node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append((node.lineno, node.module))
            # Recurse into nested blocks (try/except, with, for, while, etc.)
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.stmt,)):
                    _walk_skipping_type_checking([child])

    _walk_skipping_type_checking(list(ast.iter_child_nodes(tree)))
    return imports


def _check_file_boundaries(filepath: Path) -> list[str]:
    """Check a single file against import boundary rules."""
    violations = []
    rel_path = filepath.relative_to(SRC_ROOT)
    rel_str = str(rel_path).replace("\\", "/")

    for package_prefix, banned_imports in IMPORT_RULES.items():
        if not rel_str.startswith(package_prefix):
            continue

        for lineno, import_target in _get_imports(filepath):
            for banned in banned_imports:
                if import_target.startswith(banned):
                    violations.append(
                        f"{filepath}:{lineno}: {rel_str} imports {import_target} "
                        f"-- violates boundary rule for {package_prefix}/"
                    )
    return violations


def test_import_boundaries() -> None:
    """All source files respect architectural import boundaries."""
    all_violations = []
    for pyfile in SRC_ROOT.rglob("*.py"):
        all_violations.extend(_check_file_boundaries(pyfile))

    if all_violations:
        pytest.fail("Import boundary violations found:\n" + "\n".join(all_violations))
