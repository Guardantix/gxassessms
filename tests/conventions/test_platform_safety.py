"""Convention test: ban platform-unsafe patterns.

GxBridge retrospective: 48 cross-platform issues (trend #2). These rules catch
the most common categories at lint time on Linux, before they reach Windows CI.

Banned patterns:
  - open() without explicit encoding= (Windows defaults to cp1252, not utf-8)
  - os.path.join / os.path.sep / os.sep (use pathlib.Path instead)
"""

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "gxassessms"


def _collect_python_files() -> list[Path]:
    return list(SRC_ROOT.rglob("*.py"))


# ---------------------------------------------------------------------------
# Rule 1: open() must have explicit encoding= (unless binary mode)
# ---------------------------------------------------------------------------

_BINARY_MODES = frozenset({"rb", "wb", "ab", "r+b", "w+b", "a+b", "rb+", "wb+", "ab+"})


def _is_binary_mode(node: ast.Call) -> bool:
    """Check if an open() call uses a binary mode string."""
    # Check positional mode arg (second argument)
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        return node.args[1].value in _BINARY_MODES
    # Check keyword mode arg
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return kw.value in _BINARY_MODES
    return False


def _has_encoding_kwarg(node: ast.Call) -> bool:
    return any(kw.arg == "encoding" for kw in node.keywords)


def _find_open_without_encoding(filepath: Path) -> list[str]:
    """Find open() calls that lack an explicit encoding= parameter."""
    violations = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Match: open(...) or builtins.open(...)
        is_open = (isinstance(node.func, ast.Name) and node.func.id == "open") or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "open"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "builtins"
        )

        if not is_open:
            continue

        # Binary mode is fine without encoding
        if _is_binary_mode(node):
            continue

        if not _has_encoding_kwarg(node):
            violations.append(
                f"{filepath}:{node.lineno}: open() without encoding= -- "
                "pass encoding='utf-8' explicitly (Windows defaults to cp1252)"
            )

    return violations


# ---------------------------------------------------------------------------
# Rule 2: ban os.path usage in favor of pathlib
# ---------------------------------------------------------------------------

_BANNED_OS_PATH = {
    "os.path.join": "Use pathlib.Path / operator instead",
    "os.path.dirname": "Use Path.parent instead",
    "os.path.basename": "Use Path.name instead",
    "os.path.splitext": "Use Path.suffix / Path.stem instead",
    "os.path.exists": "Use Path.exists() instead",
    "os.path.isfile": "Use Path.is_file() instead",
    "os.path.isdir": "Use Path.is_dir() instead",
    "os.path.abspath": "Use Path.resolve() instead",
    "os.path.expanduser": "Use Path.expanduser() instead",
    "os.sep": "Use pathlib.Path / operator instead",
    "os.path.sep": "Use pathlib.Path / operator instead",
}


def _find_banned_os_path(filepath: Path) -> list[str]:
    """Find os.path.* calls and os.sep references via AST."""
    violations = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            # os.sep
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "sep":
                key = "os.sep"
                violations.append(f"{filepath}:{node.lineno}: {key} -- {_BANNED_OS_PATH[key]}")
            # os.path.join, os.path.exists, etc.
            elif (
                isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "path"
            ):
                key = f"os.path.{node.attr}"
                if key in _BANNED_OS_PATH:
                    violations.append(f"{filepath}:{node.lineno}: {key} -- {_BANNED_OS_PATH[key]}")

    return violations


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_open_without_encoding() -> None:
    """Every open() call must specify encoding= explicitly (or use binary mode)."""
    all_violations = []
    for pyfile in _collect_python_files():
        all_violations.extend(_find_open_without_encoding(pyfile))

    if all_violations:
        pytest.fail("open() without explicit encoding= found:\n" + "\n".join(all_violations))


def test_no_os_path_usage() -> None:
    """No source file may use os.path functions. Use pathlib.Path instead."""
    all_violations = []
    for pyfile in _collect_python_files():
        all_violations.extend(_find_banned_os_path(pyfile))

    if all_violations:
        pytest.fail("os.path usage found (use pathlib.Path):\n" + "\n".join(all_violations))
