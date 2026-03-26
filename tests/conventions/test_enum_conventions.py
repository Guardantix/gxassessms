"""Convention test: ban raw string literals for enum values outside constants.py.

Domain enum values (severity names, category names, status values) must come
from constants.py or enums.py, never as raw strings in application code.
"""

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "gxassessms"

# Files that are allowed to define raw enum-like strings
ALLOWED_FILES = {
    SRC_ROOT / "core" / "domain" / "constants.py",
    SRC_ROOT / "core" / "domain" / "enums.py",
}

# Raw string values that should only appear in constants/enums
SEVERITY_LITERALS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
STATUS_LITERALS = {"FAIL", "PASS", "WARNING", "ERROR", "N/A", "MANUAL"}


def _collect_python_files() -> list[Path]:
    return [p for p in SRC_ROOT.rglob("*.py") if p not in ALLOWED_FILES]


def _find_raw_enum_literals(filepath: Path) -> list[str]:
    """Find string literals that match known enum values."""
    violations = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
    except SyntaxError as e:
        return [f"{filepath}: SyntaxError -- {e}"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value
            if val in SEVERITY_LITERALS or val in STATUS_LITERALS:
                # Allow in test files and type annotations
                filepath.relative_to(SRC_ROOT)
                violations.append(
                    f"{filepath}:{node.lineno}: raw enum literal '{val}' "
                    f"-- use Severity.{val} or FindingStatus.{val} from enums"
                )
    return violations


def test_no_raw_enum_literals_in_source() -> None:
    """No source file may use raw string literals for known enum values."""
    all_violations = []
    for pyfile in _collect_python_files():
        all_violations.extend(_find_raw_enum_literals(pyfile))

    if all_violations:
        # Filter out false positives from docstrings, comments, and type annotations
        real_violations = [v for v in all_violations if "__pycache__" not in v]
        if real_violations:
            pytest.fail("Raw enum literals found in source code:\n" + "\n".join(real_violations))
