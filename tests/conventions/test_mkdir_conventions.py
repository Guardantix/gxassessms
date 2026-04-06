"""Convention test: ban bare mkdir and os.makedirs in source code.

All directory creation must go through secure_mkdir() from
core/security/permissions.py to enforce restrictive POSIX permissions.
"""

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "gxassessms"

# The implementation itself is allowed to use bare mkdir
_ALLOWED_FILES = {
    SRC_ROOT / "core" / "security" / "permissions.py",
}


def _collect_python_files() -> list[Path]:
    return [p for p in SRC_ROOT.rglob("*.py") if p not in _ALLOWED_FILES]


def _find_bare_mkdir(filepath: Path) -> list[str]:
    """Find .mkdir() and os.makedirs() calls via AST."""
    violations = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
    except SyntaxError as e:
        return [f"{filepath}: SyntaxError -- {e}"]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue

        # Catch any_object.mkdir(...)
        if node.func.attr == "mkdir":
            violations.append(
                f"{filepath}:{node.lineno}: .mkdir() -- use secure_mkdir() "
                "from core.security.permissions instead"
            )

        # Catch os.makedirs(...)
        if (
            node.func.attr == "makedirs"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ):
            violations.append(
                f"{filepath}:{node.lineno}: os.makedirs() -- use secure_mkdir() "
                "from core.security.permissions instead"
            )

    return violations


# ---------------------------------------------------------------------------
# Convention enforcement
# ---------------------------------------------------------------------------


def test_no_bare_mkdir_in_source() -> None:
    """All directory creation must use secure_mkdir."""
    all_violations = []
    for pyfile in _collect_python_files():
        all_violations.extend(_find_bare_mkdir(pyfile))

    if all_violations:
        pytest.fail(
            "Bare mkdir/makedirs usage found (use secure_mkdir):\n" + "\n".join(all_violations)
        )


# ---------------------------------------------------------------------------
# Self-tests for the scanner
# ---------------------------------------------------------------------------


class TestMkdirScanner:
    def test_scanner_catches_bare_mkdir(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("from pathlib import Path\nPath('x').mkdir()\n", encoding="utf-8")
        violations = _find_bare_mkdir(f)
        assert len(violations) == 1
        assert ".mkdir()" in violations[0]

    def test_scanner_catches_os_makedirs(self, tmp_path: Path) -> None:
        f = tmp_path / "bad2.py"
        f.write_text("import os\nos.makedirs('x')\n", encoding="utf-8")
        violations = _find_bare_mkdir(f)
        assert len(violations) == 1
        assert "os.makedirs()" in violations[0]

    def test_scanner_allows_permissions_module(self) -> None:
        from gxassessms.core.security import permissions

        perms_path = Path(permissions.__file__)
        # This file IS allowed bare mkdir -- verify it's not in the scan set
        files = _collect_python_files()
        assert perms_path not in files
