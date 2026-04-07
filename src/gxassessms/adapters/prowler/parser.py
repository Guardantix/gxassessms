"""Prowler OCSF Detection Finding parser.

Transforms Prowler JSON output (OCSF Detection Finding schema, snake_case keys)
into ToolObservation instances. Prowler output is a JSON array of OCSF
Detection Finding objects.

Key OCSF fields used:
- metadata.event_code: Check ID (e.g., "defender_ensure_defender_for_app_services_is_on")
  This is the CHECK identifier. NOT finding_info.uid which is per-finding unique.
- severity: Title case string ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
- status_code: UPPERCASE string ("PASS", "FAIL", "MANUAL") -- the assessment result
  NOT status which is OCSF lifecycle ("New"/"Suppressed")
- finding_info.title: Check title
- finding_info.desc: Check description (NOT "description")
- finding_info.uid: Per-finding unique ID (used for observation_id dedup, NOT check ID)
- remediation.desc + remediation.references: Remediation guidance
- resources[0].group.name: Service name for category mapping
- unmapped.compliance: Dict of framework -> control_id arrays for benchmark_refs
- cloud.provider: "azure"

Verified against Prowler source code at /home/guardantix/ToolInspection/prowler/.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, cast

from gxassessms.core.domain.enums import FindingStatus, ToolSource
from gxassessms.core.domain.models import ToolObservation

logger = logging.getLogger(__name__)


def parse_prowler_findings(
    findings: list[dict[str, Any]],
    source_tag: str = "",
) -> list[ToolObservation]:
    """Parse a list of Prowler OCSF Detection Finding dicts into ToolObservations.

    Prowler produces one finding per resource per check. Multiple findings may
    share the same check ID (metadata.event_code) but refer to different resources.
    Each finding becomes a separate ToolObservation with a unique observation_id.

    Args:
        findings: List of OCSF Detection Finding objects (from JSON array).
        source_tag: Optional discriminator (e.g. file path) included in the
            fallback observation_id suffix when finding_info.uid is absent.
            Required for correctness when this function is called more than once
            (e.g. once per artifact file) -- without it, idx-based fallbacks
            restart from zero each call and can collide across files.

    Returns:
        List of ToolObservation instances, one per finding.
    """
    observations: list[ToolObservation] = []

    for idx, finding in enumerate(findings):
        raw_metadata: Any = finding.get("metadata")
        metadata: dict[str, Any] = (
            cast(dict[str, Any], raw_metadata) if isinstance(raw_metadata, dict) else {}
        )

        raw_finding_info: Any = finding.get("finding_info")
        finding_info: dict[str, Any] = (
            cast(dict[str, Any], raw_finding_info) if isinstance(raw_finding_info, dict) else {}
        )

        raw_check_id: Any = metadata.get("event_code", "")
        check_id: str = str(raw_check_id) if raw_check_id else ""
        if not check_id:
            fallback_uid: Any = finding_info.get("uid", "unknown")
            check_id = str(fallback_uid) if fallback_uid else "unknown"
            logger.warning(
                "Finding missing metadata.event_code, using finding_info.uid: %s",
                check_id,
            )

        raw_severity: Any = finding.get("severity", "Unknown")
        severity_str: str = str(raw_severity) if raw_severity else "Unknown"

        raw_status: Any = finding.get("status_code", FindingStatus.FAIL)
        status_code: str = str(raw_status) if raw_status else FindingStatus.FAIL

        raw_title: Any = finding_info.get("title", "")
        title: str = str(raw_title) if raw_title else ""

        # "desc", not "description" -- OCSF field name trap
        raw_desc: Any = finding_info.get("desc", "")
        description: str = str(raw_desc) if raw_desc else ""

        benchmark_refs = _extract_benchmark_refs(finding)

        # Hash finding_info.uid to differentiate per-resource observations.
        # Fall back to index when uid is absent. Include a hash of source_tag
        # (typically the artifact file path) so the fallback stays unique across
        # multiple parse_prowler_findings() calls -- idx resets to 0 each call.
        raw_finding_uid: Any = finding_info.get("uid", "")
        finding_uid: str = str(raw_finding_uid) if raw_finding_uid else ""
        if finding_uid:
            uid_hash: str = hashlib.sha256(finding_uid.encode()).hexdigest()[:12]
        elif source_tag:
            file_hash = hashlib.sha256(source_tag.encode()).hexdigest()[:8]
            uid_hash = f"{file_hash}:idx{idx}"
        else:
            uid_hash = f"idx{idx}"
        observation_id = f"prowler:{check_id}:{uid_hash}"

        observation = ToolObservation(
            observation_id=observation_id,
            tool=ToolSource.PROWLER,
            native_check_id=check_id,
            title=title,
            native_severity=severity_str,
            native_status=status_code,
            description=description,
            raw_data=finding,
            benchmark_refs=benchmark_refs,
        )
        observations.append(observation)

    return observations


def _extract_benchmark_refs(finding: dict[str, Any]) -> list[str]:
    """Extract benchmark references from unmapped.compliance.

    Prowler puts compliance data in unmapped.compliance as a dict:
        {"CIS-2.1": ["5.3.1"], "CIS-3.0": ["6.3.1"]}

    Returns a list of formatted strings like ["CIS-2.1:5.3.1", "CIS-3.0:6.3.1"].
    """
    refs: list[str] = []

    raw_unmapped: Any = finding.get("unmapped")
    unmapped: dict[str, Any] = (
        cast(dict[str, Any], raw_unmapped) if isinstance(raw_unmapped, dict) else {}
    )

    raw_compliance: Any = unmapped.get("compliance")
    compliance: dict[str, Any] = (
        cast(dict[str, Any], raw_compliance) if isinstance(raw_compliance, dict) else {}
    )

    for framework, control_ids in compliance.items():
        if isinstance(control_ids, list):
            for control_id in cast(list[Any], control_ids):
                refs.append(f"{framework}:{control_id!s}")

    return sorted(refs)
