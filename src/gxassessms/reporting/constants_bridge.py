"""Constants bridge -- generates constants.json for Node.js report renderers.

Node.js renderers need access to Python domain constants (severity ordering,
category display names, phase timelines, severity colors). This module
generates a constants.json file at render time so there is a single source
of truth with no drift.

The generated file is written to a temp directory alongside the report
payload before invoking Node.js. It is never committed to the repository.
Schema sync tests call generate_constants_dict() and compare against the
live Python constants to catch unintentional changes.
"""

from __future__ import annotations

import json
from pathlib import Path

from gxassessms.core.domain.constants import (
    CATEGORY_DISPLAY_NAMES,
    REMEDIATION_PHASE_TIMELINES,
    SEVERITY_COLORS,
    SEVERITY_ORDER,
)


def generate_constants_dict() -> dict[str, dict[str, str | int]]:
    """Build the constants dictionary for Node.js consumption.

    Returns a dict with four top-level keys:
    - severity_order: maps severity name to numeric rank
    - severity_colors: maps severity name to display color
    - category_display_names: maps category key to human-readable name
    - remediation_phase_timelines: maps phase name to timeline string
    """
    return {
        "severity_order": dict(SEVERITY_ORDER),
        "severity_colors": dict(SEVERITY_COLORS),
        "category_display_names": dict(CATEGORY_DISPLAY_NAMES),
        "remediation_phase_timelines": dict(REMEDIATION_PHASE_TIMELINES),
    }


def generate_constants_json() -> str:
    """Generate the constants as a pretty-printed JSON string.

    Returns sorted, indented JSON suitable for writing to a file
    or comparing against a golden file.
    """
    data = generate_constants_dict()
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def write_constants_file(path: Path) -> None:
    """Write constants.json to the given path.

    Overwrites any existing file at that path.
    """
    path.write_text(generate_constants_json(), encoding="utf-8")
