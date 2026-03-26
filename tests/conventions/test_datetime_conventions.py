"""Convention test: ban datetime.now(), datetime.utcnow(), bare fromisoformat().

Only datetime_utils.py may use these. All other code must use the centralized
functions: utc_now(), parse_utc(), format_utc().
"""

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "gxassessms"
ALLOWED_FILE = SRC_ROOT / "core" / "config" / "datetime_utils.py"

BANNED_CALLS = {
    "datetime.now": "Use datetime_utils.utc_now() instead",
    "datetime.utcnow": "Use datetime_utils.utc_now() instead",
}


def _collect_python_files() -> list[Path]:
    return [p for p in SRC_ROOT.rglob("*.py") if p != ALLOWED_FILE]


def _find_banned_datetime_calls(filepath: Path) -> list[str]:
    """Find banned datetime method calls via AST analysis."""
    violations = []
    try:
        tree = ast.parse(filepath.read_text(), filename=str(filepath))
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func
            if isinstance(attr.value, ast.Name):
                full_call = f"{attr.value.id}.{attr.attr}"
                if full_call in BANNED_CALLS:
                    violations.append(
                        f"{filepath}:{node.lineno}: {full_call}() -- {BANNED_CALLS[full_call]}"
                    )
            # Also catch datetime.datetime.now() pattern
            if isinstance(attr.value, ast.Attribute) and isinstance(attr.value.value, ast.Name):
                full_call = f"{attr.value.value.id}.{attr.value.attr}.{attr.attr}"
                short_call = f"{attr.value.attr}.{attr.attr}"
                if short_call in BANNED_CALLS:
                    violations.append(
                        f"{filepath}:{node.lineno}: {full_call}() -- {BANNED_CALLS[short_call]}"
                    )
    return violations


def test_no_banned_datetime_calls() -> None:
    """No source file (except datetime_utils.py) may call datetime.now() or .utcnow()."""
    all_violations = []
    for pyfile in _collect_python_files():
        all_violations.extend(_find_banned_datetime_calls(pyfile))

    if all_violations:
        pytest.fail("Banned datetime calls found:\n" + "\n".join(all_violations))
