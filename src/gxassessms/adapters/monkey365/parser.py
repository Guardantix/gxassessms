"""Monkey365 OCSF Detection Finding parser.

Transforms Monkey365 JSON output (OCSF Detection Finding schema) into
ToolObservation instances. Monkey365 output is a JSON array of OCSF
Detection Finding objects.

Key OCSF fields used:
- findingInfo.id: Contains idSuffix (check identifier) embedded in format
  Monkey365-{idSuffix-hyphens}-{tenantGuid32hex}-{randomHash}
- severity: Title case string ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
- statusCode: Lowercase string ("pass", "fail", "manual")
- findingInfo.title: Check title
- findingInfo.description: Check description
- remediation.description + remediation.references: Remediation guidance (stored in raw_data)
- resources.group.name: Functional domain for category mapping (stored in raw_data)
- cloud.provider: "Microsoft365" or "Azure"

Verified against source code and sample output. See QA report for details.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from gxassessms.core.contracts.errors import RawOutputValidationError
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ToolObservation

logger = logging.getLogger(__name__)

# Regex to extract idSuffix from findingInfo.id.
# Format: Monkey365-{idSuffix-hyphens}-{32hex}-{variable}
# The 32-char hex block is the tenant GUID with hyphens removed.
_FINDING_ID_PATTERN = re.compile(
    r"^Monkey365-(.+)-([0-9a-f]{32})-(.+)$",
    re.IGNORECASE,
)


def extract_id_suffix(finding_id: str) -> str | None:
    """Extract the idSuffix from a Monkey365 findingInfo.id.

    The findingInfo.id format is:
        Monkey365-{idSuffix-with-hyphens}-{tenantGuidNoHyphens}-{randomHash}

    The idSuffix originally uses underscores, converted to hyphens in the ID.
    This function reverses that: extracts the segment and converts hyphens
    back to underscores.

    Returns None if the ID doesn't match the expected format.
    """
    if not finding_id:
        return None
    match = _FINDING_ID_PATTERN.match(finding_id)
    if not match:
        return None
    id_suffix_hyphens = match.group(1)
    return id_suffix_hyphens.replace("-", "_")


def parse_monkey365_findings(
    findings: list[dict[str, Any]],
) -> list[ToolObservation]:
    """Parse a list of Monkey365 OCSF Detection Finding dicts into ToolObservations.

    Precondition: findings must be pre-validated by
    ``Monkey365Adapter._validate_and_load_findings``. That method guarantees
    each finding has ``findingInfo`` (dict), ``findingInfo.id`` (non-empty str),
    ``severity``, and ``statusCode`` keys.

    Args:
        findings: List of OCSF Detection Finding objects (from JSON array).

    Returns:
        List of ToolObservation instances, one per finding.
    """
    observations: list[ToolObservation] = []

    for finding in findings:
        finding_info = finding["findingInfo"]
        finding_id = finding_info.get("id", "")
        id_suffix = extract_id_suffix(finding_id)

        if id_suffix is None:
            raise RawOutputValidationError(
                f"findingInfo.id {finding_id!r} does not match expected Monkey365 format "
                "(Monkey365-{idSuffix}-{32hexGuid}-{hash})",
                adapter_name="Monkey365",
            )

        observation = ToolObservation(
            observation_id=f"monkey365:{id_suffix}",
            tool=ToolSource.MONKEY365,
            native_check_id=id_suffix,
            title=finding_info.get("title", ""),
            native_severity=finding["severity"],  # validator guarantees this key
            native_status=finding["statusCode"],  # validator guarantees this key
            description=finding_info.get("description", ""),
            raw_data=finding,
        )
        observations.append(observation)

    return observations
