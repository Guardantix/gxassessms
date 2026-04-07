"""M365-Assess CSV parser.

Parses *-Security-Config.csv files into ToolObservation instances.
Joins with risk-severity.json (severity) and registry.json (frameworks).

CSV schema (7 columns, identical across all 12 collectors):
  Category, Setting, CurrentValue, RecommendedValue, Status, CheckId, Remediation

Verified against real sample output.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, cast

from gxassessms.adapters._base import load_json_file
from gxassessms.adapters.m365_assess.mappings import (
    CATEGORY_MAP,
    STATUS_MAP,
    extract_base_check_id,
    extract_collector_prefix,
)
from gxassessms.core.contracts.errors import RawOutputValidationError
from gxassessms.core.domain.enums import Category, FindingStatus, ToolSource
from gxassessms.core.domain.models import ToolObservation

logger = logging.getLogger(__name__)


def load_risk_severity(path: Path) -> dict[str, str]:
    """Load risk-severity.json. Returns {base_check_id: severity_string}."""
    data: dict[str, Any] = load_json_file(path, adapter_name="M365Assess")
    raw: Any = data.get("checks", {})
    if not isinstance(raw, dict):
        raise RawOutputValidationError(
            f"risk-severity.json 'checks' must be a mapping, got {type(raw).__name__}",
            adapter_name="M365Assess",
        )
    return cast(dict[str, str], raw)


def load_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Load registry.json.

    Expects ``{"checks": [{"checkId": str, ...}, ...]}``.
    Returns ``{check_id: entry_dict}`` keyed by ``checkId``.
    Raises RawOutputValidationError if any entry is missing the 'checkId' field.
    """
    data: dict[str, Any] = load_json_file(path, adapter_name="M365Assess")
    raw: Any = data.get("checks", [])
    if not isinstance(raw, list):
        raise RawOutputValidationError(
            f"registry.json 'checks' must be a list, got {type(raw).__name__}",
            adapter_name="M365Assess",
        )
    result: dict[str, dict[str, Any]] = {}
    for i, entry in enumerate(cast(list[dict[str, Any]], raw)):
        if not isinstance(entry, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise RawOutputValidationError(
                f"registry.json 'checks' entry at index {i} must be a mapping, "
                f"got {type(entry).__name__}",
                adapter_name="M365Assess",
            )
        check_id = entry.get("checkId")
        if not check_id:
            raise RawOutputValidationError(
                f"registry.json entry at index {i} is missing 'checkId' field: {entry!r}",
                adapter_name="M365Assess",
            )
        if not isinstance(check_id, str):
            raise RawOutputValidationError(
                f"registry.json 'checkId' at index {i} must be a string, "
                f"got {type(check_id).__name__}: {check_id!r}",
                adapter_name="M365Assess",
            )
        result[check_id] = entry
    return result


def parse_security_config_csv(
    csv_path: Path,
    severity_lookup: dict[str, str],
    registry_lookup: dict[str, dict[str, Any]],
) -> list[ToolObservation]:
    """Parse a single *-Security-Config.csv file into ToolObservation instances.

    Args:
        csv_path: Path to the CSV file.
        severity_lookup: {base_check_id: severity_string} from risk-severity.json.
        registry_lookup: {check_id: entry_dict} from registry.json.

    Returns:
        List of ToolObservation instances.
    """
    observations: list[ToolObservation] = []

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, restval="")
        for row in reader:
            check_id = (row.get("CheckId") or "").strip()
            if not check_id:
                continue

            base_id = extract_base_check_id(check_id)
            collector = extract_collector_prefix(check_id)

            # Status
            status_str = row.get("Status", "Unknown").strip()
            status = STATUS_MAP.get(status_str, FindingStatus.ERROR)

            # Severity string from risk-severity.json; stored raw so the
            # normalization layer can resolve it via the adapter severity_map.
            sev_str = severity_lookup.get(base_id)
            if sev_str is None:
                if severity_lookup:
                    # risk-severity.json was loaded but this specific check is absent from it.
                    # This typically means the check was added to M365-Assess after the controls
                    # snapshot was taken. Update risk-severity.json to include it.
                    logger.warning(
                        "No severity entry for check_id=%r in risk-severity.json (source: %s); "
                        "defaulting to Medium",
                        base_id,
                        csv_path.name,
                    )
                sev_str = "Medium"

            # Category hint for normalization layer (stored in raw_data)
            category_hint = CATEGORY_MAP.get(collector.lower(), Category.COMPLIANCE)

            # Title from Setting column
            title = row.get("Setting", "").strip()

            # Description: combine Category context with current/recommended values
            category_label = row.get("Category", "").strip()
            current = row.get("CurrentValue", "").strip()
            recommended = row.get("RecommendedValue", "").strip()
            description = f"[{category_label}] Current: {current}. Recommended: {recommended}."

            # Benchmark refs from registry
            benchmark_refs = _extract_benchmark_refs(base_id, registry_lookup)

            raw_data: dict[str, Any] = {
                "csv_row": dict(row),
                "base_check_id": base_id,
                "collector": collector,
                "category_hint": category_hint,
                "remediation": row.get("Remediation", "").strip(),
                "source_file": csv_path.name,
            }

            observation = ToolObservation(
                observation_id=f"m365assess:{check_id}",
                tool=ToolSource.M365_ASSESS,
                native_check_id=check_id,
                title=title,
                description=description,
                native_severity=sev_str,
                native_status=status,
                raw_data=raw_data,
                benchmark_refs=benchmark_refs,
            )
            observations.append(observation)

    return observations


def _extract_benchmark_refs(
    base_check_id: str,
    registry: dict[str, dict[str, Any]],
) -> list[str]:
    """Extract benchmark references from registry.json for a given CheckId.

    Returns list of strings like 'cis:m365:1.1.1', 'nist:800-53:AC-6(5)'.
    """
    entry = registry.get(base_check_id)
    if not entry:
        return []

    refs: list[str] = []
    frameworks: dict[str, Any] = entry.get("frameworks", {})

    cis: dict[str, Any] = frameworks.get("cis-m365-v6", {})
    cis_id: str | None = cis.get("controlId")
    if cis_id:
        refs.append(f"cis:m365:{cis_id}")

    nist: dict[str, Any] = frameworks.get("nist-800-53", {})
    nist_id: str | None = nist.get("controlId")
    if nist_id:
        for ctrl in nist_id.split(";"):
            refs.append(f"nist:800-53:{ctrl.strip()}")

    soc2: dict[str, Any] = frameworks.get("soc2", {})
    soc2_id: str | None = soc2.get("controlId")
    if soc2_id:
        for ctrl in soc2_id.split(";"):
            refs.append(f"soc2:{ctrl.strip()}")

    return refs
