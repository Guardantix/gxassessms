"""Convention test: ban broad except clauses.

Bare except:, except Exception, and except BaseException are banned.
Every except must name a specific exception type.
"""

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "gxassessms"

BANNED_BROAD_EXCEPTIONS = {
    "Exception",
    "BaseException",
}

# Files allowed to use `except Exception` with documented justification:
# - cli/main.py: _get_version() catches any importlib.metadata failure
# - cli/commands/review.py: delegates to private package via entry points
# - cli/commands/analytics.py: delegates to private package via entry points
# These catch Exception because we cannot predict what external packages raise.
BROAD_EXCEPT_ALLOWED_FILES = {
    SRC_ROOT / "cli" / "main.py",
    SRC_ROOT / "cli" / "commands" / "review.py",
    SRC_ROOT / "cli" / "commands" / "analytics.py",
}


def _collect_python_files() -> list[Path]:
    return [p for p in SRC_ROOT.rglob("*.py") if p not in BROAD_EXCEPT_ALLOWED_FILES]


def _find_broad_except_clauses(filepath: Path) -> list[str]:
    """Find except clauses that catch overly broad exception types."""
    violations = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
    except SyntaxError as e:
        return [f"{filepath}: SyntaxError -- {e}"]

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                # Bare `except:` -- always banned
                violations.append(
                    f"{filepath}:{node.lineno}: bare 'except:' -- must name a specific exception"
                )
            elif isinstance(node.type, ast.Name):
                if node.type.id in BANNED_BROAD_EXCEPTIONS:
                    violations.append(
                        f"{filepath}:{node.lineno}: 'except {node.type.id}' -- too broad, "
                        f"catch a specific exception type"
                    )
            elif isinstance(node.type, ast.Tuple):
                for elt in node.type.elts:
                    if isinstance(elt, ast.Name) and elt.id in BANNED_BROAD_EXCEPTIONS:
                        violations.append(
                            f"{filepath}:{node.lineno}: 'except (..., {elt.id}, ...)' -- "
                            f"too broad, catch a specific exception type"
                        )
    return violations


def test_no_broad_except_clauses() -> None:
    """No source file may use broad except clauses."""
    all_violations = []
    for pyfile in _collect_python_files():
        all_violations.extend(_find_broad_except_clauses(pyfile))

    if all_violations:
        pytest.fail("Broad except clauses found:\n" + "\n".join(all_violations))
