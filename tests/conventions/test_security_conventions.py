"""Convention test: ban innerHTML in JS/HTML template files.

All dynamic content must use textContent (JS) or Jinja2 auto-escaping (HTML).
"""

from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "gxassessms"


def _collect_web_files() -> list[Path]:
    """Collect all .js, .html, and .jinja2 files."""
    patterns = ["*.js", "*.html", "*.jinja2"]
    files = []
    for pattern in patterns:
        files.extend(SRC_ROOT.rglob(pattern))
    return files


def test_no_innerhtml_in_web_files() -> None:
    """No JS or HTML file may use innerHTML."""
    violations = []
    for filepath in _collect_web_files():
        content = filepath.read_text()
        for i, line in enumerate(content.splitlines(), 1):
            if "innerHTML" in line:
                violations.append(f"{filepath}:{i}: innerHTML found -- use textContent instead")

    if violations:
        pytest.fail("innerHTML usage found:\n" + "\n".join(violations))
