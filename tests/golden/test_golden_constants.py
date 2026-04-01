"""Golden file regression test for constants bridge output.

Catches unintentional changes to the constants.json structure generated
for Node.js renderers.

To update the golden file after an intentional change:
    UPDATE_GOLDEN=1 python3 -m pytest tests/golden/test_golden_constants.py -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gxassessms.reporting.constants_bridge import generate_constants_json

GOLDEN_DIR = Path(__file__).parent
GOLDEN_FILE = GOLDEN_DIR / "constants_golden.json"


class TestGoldenConstants:
    def test_constants_match_golden_file(self) -> None:
        actual = generate_constants_json()

        if os.environ.get("UPDATE_GOLDEN") == "1":
            GOLDEN_FILE.write_text(actual, encoding="utf-8")
            pytest.skip("Golden file updated -- re-run without UPDATE_GOLDEN")

        expected = GOLDEN_FILE.read_text(encoding="utf-8")
        assert actual == expected, (
            "Constants output does not match golden file. "
            "If this change is intentional, run: "
            "UPDATE_GOLDEN=1 python3 -m pytest tests/golden/test_golden_constants.py -v"
        )

    def test_golden_file_is_valid_json(self) -> None:
        content = GOLDEN_FILE.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert isinstance(parsed, dict)
