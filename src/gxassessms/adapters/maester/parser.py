"""Maester output parser -- transforms Maester Tests JSON into ToolObservations.

Parses Maester's JSON output format. Each entry in the Tests array
becomes one ToolObservation with the tool's native severity, status,
and check ID preserved exactly. Normalization happens later in the
policy engine.

Maester test IDs use multiple formats (CIS.M365.*, CISA.MS.*, EIDSCA.*,
MT.*, ORCA.*) reflecting the different benchmark frameworks Maester
executes simultaneously.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ToolObservation

logger = logging.getLogger(__name__)


def parse_maester_tests(tests: list[dict[str, Any]]) -> list[ToolObservation]:
    """Parse Maester Tests array into ToolObservations.

    Args:
        tests: List of test dicts from Maester's TestResults JSON
               "Tests" array.

    Returns:
        List of ToolObservation, one per test entry.
    """
    observations: list[ToolObservation] = []

    for entry in tests:
        test_id: str = entry["Id"]
        raw_detail: Any = entry.get("ResultDetail")
        result_detail: dict[str, Any] = (
            cast(dict[str, Any], raw_detail) if isinstance(raw_detail, dict) else {}
        )

        # Description from ResultDetail.TestDescription (may be null/absent)
        raw_desc: Any = result_detail.get("TestDescription")
        description: str = str(raw_desc) if raw_desc else ""

        # Build benchmark_refs from Tag array
        benchmark_refs: list[str] = list(entry.get("Tag", []))

        observation = ToolObservation(
            observation_id=f"maester:{test_id}",
            tool=ToolSource.MAESTER,
            native_check_id=test_id,
            title=entry["Title"],
            native_severity=entry.get("Severity", ""),
            native_status=entry["Result"],
            description=description,
            benchmark_refs=benchmark_refs,
            raw_data={
                "Block": entry.get("Block", ""),
                "Name": entry.get("Name", ""),
                "HelpUrl": entry.get("HelpUrl", ""),
                "Duration": entry.get("Duration", ""),
                "ErrorRecord": entry.get("ErrorRecord", []),
                "ResultDetail": result_detail,
            },
        )
        observations.append(observation)

    logger.debug("Parsed %d Maester tests into observations", len(observations))
    return observations
