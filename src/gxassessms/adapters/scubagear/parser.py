"""ScubaGear output parser.

Reads the 'Results' dict from a ScubaResults JSON file (v1.7.1 format)
and produces a flat list of ToolObservation instances -- one per control entry.

Entry point:
    parse_scuba_results(results) -> list[ToolObservation]

The function accepts the value of ``data["Results"]`` from ScubaResults JSON,
keyed by module abbreviation ("AAD", "EXO", "Teams", etc.), each containing
a list of group dicts with a "Controls" list.

No normalization occurs here. Severity, status, and category are preserved
as native ScubaGear strings. Normalization is handled by the policy layer.
"""

from __future__ import annotations

import logging
from typing import Any

from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ToolObservation

logger = logging.getLogger(__name__)


def parse_scuba_results(
    results: dict[str, list[dict[str, Any]]],
) -> list[ToolObservation]:
    """Parse ScubaResults 'Results' dict into ToolObservations.

    Args:
        results: The 'Results' dict from ScubaResults JSON, keyed by module
                 abbreviation (AAD, EXO, etc.), each containing groups with
                 Controls.

    Returns:
        List of ToolObservation, one per control entry. Empty list if results
        is empty or contains no controls.
    """
    observations: list[ToolObservation] = []

    for module_key, groups in results.items():
        for group in groups:
            group_name: str = group.get("GroupName", "")
            group_number: str = group.get("GroupNumber", "")
            for control in group.get("Controls", []):
                obs = _parse_control(module_key, group_name, group_number, control)
                observations.append(obs)
                logger.debug(
                    "Parsed control %s from module %s (status=%s)",
                    obs.native_check_id,
                    module_key,
                    obs.native_status,
                )

    logger.info(
        "Parsed %d ScubaGear observations from %d module(s)",
        len(observations),
        len(results),
    )
    return observations


def _parse_control(
    module_key: str,
    group_name: str,
    group_number: str,
    control: dict[str, Any],
) -> ToolObservation:
    """Build a ToolObservation from a single ScubaGear control dict.

    Args:
        module_key: Module abbreviation from the Results dict key ("AAD", "EXO", etc.)
        group_name: GroupName from the enclosing group dict.
        group_number: GroupNumber from the enclosing group dict.
        control: A single control dict from group["Controls"].

    Returns:
        ToolObservation populated from the control's fields.
    """
    native_check_id: str = control["Control ID"]
    title: str = control["Requirement"]
    native_status: str = control["Result"]
    native_severity: str = control["Criticality"]
    description: str = control["Details"]

    raw_data: dict[str, Any] = {
        "module": module_key,
        "group_name": group_name,
        "group_number": group_number,
        "details": control["Details"],
        "original_result": control.get("OriginalResult", ""),
        "original_details": control.get("OriginalDetails", ""),
    }

    return ToolObservation(
        observation_id=f"scubagear:{native_check_id}",
        tool=ToolSource.SCUBAGEAR,
        native_check_id=native_check_id,
        title=title,
        native_severity=native_severity,
        native_status=native_status,
        description=description,
        raw_data=raw_data,
        benchmark_refs=[],
    )
