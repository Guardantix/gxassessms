"""Secure Score adapter -- Microsoft Graph API security posture assessment.

Unlike PowerShell-based adapters (ScubaGear, Maester), this adapter calls
the Microsoft Graph REST API directly via httpx. It fetches two endpoints
(secureScoreControlProfiles and secureScores), joins them by control ID,
and produces ToolObservations representing the tenant's security posture.

Auth dispatches on ``config.auth.method``: ``client_credential`` uses
ClientSecretCredential or CertificateCredential, ``device_code`` uses
DeviceCodeCredential, and ``interactive`` uses InteractiveBrowserCredential.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from gxassessms.adapters._azure_auth import acquire_azure_token
from gxassessms.adapters._http import (
    check_python_packages,
    fetch_paginated_json,
    validate_auth_context,
)
from gxassessms.adapters.secure_score.mappings import CATEGORY_MAP
from gxassessms.adapters.secure_score.parser import parse_secure_score
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import SEVERITY_IDENTITY_MAP, AdapterCapability
from gxassessms.core.domain.enums import CoverageStatus, FindingStatus, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CollectionOutput,
    CoverageRecord,
    ResolvedManifest,
    ToolObservation,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
_PROFILES_ENDPOINT = "/security/secureScoreControlProfiles"
_SCORES_ENDPOINT = "/security/secureScores"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"

_PROFILES_FILENAME = "secureScoreControlProfiles.json"
_SCORES_FILENAME = "secureScores.json"

_SCHEMA_VERSION = "1.0.0"
_DEFAULT_TIMEOUT_SECONDS = 120


class SecureScoreAdapter:
    """ToolAdapter implementation for Microsoft Secure Score (Graph API).

    Capabilities: collect, parse, prerequisites, shared_auth, coverage_export.
    Unlike PowerShell adapters, this adapter acquires its own Graph API token
    and makes HTTP calls directly via httpx.
    """

    tool_name: str = "SecureScore"
    storage_slug: str = "secure-score"
    tool_source: ToolSource = ToolSource.SECURE_SCORE
    capabilities: frozenset[AdapterCapability] = frozenset(
        {"collect", "parse", "prerequisites", "shared_auth", "coverage_export", "ingest"}
    )
    default_schema_version: str = _SCHEMA_VERSION

    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify httpx and azure.identity are importable."""
        return check_python_packages(
            [("httpx", "httpx"), ("azure.identity", "azure-identity")],
            self.tool_name,
        )

    def authenticate(self, config: EngagementConfig) -> AuthContext | None:
        """Acquire a Microsoft Graph API token."""
        return acquire_azure_token(config, scope=_GRAPH_SCOPE, adapter_name=self.tool_name)

    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput:
        """Fetch Secure Score data from the Microsoft Graph API.

        Reads ``output_dir`` and ``timeout`` from
        ``config.tools["secure_score"]`` (note underscore).

        Raises:
            CollectionError: If the API call fails or output_dir is missing.
        """
        from gxassessms.adapters._base import build_collection_output
        from gxassessms.core.config.datetime_utils import utc_now

        validate_auth_context(auth, self.tool_name)

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Secure Score adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        from gxassessms.core.security.permissions import secure_mkdir

        output_dir = Path(tc.output_dir)
        secure_mkdir(output_dir, parents=True, exist_ok=True)
        timeout = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        assert auth is not None  # noqa: S101 -- guaranteed by validate_auth_context
        bearer_token = auth.token.get_secret_value()  # type: ignore[union-attr]
        headers = {"Authorization": f"Bearer {bearer_token}"}

        profiles_items = fetch_paginated_json(
            url=f"{_GRAPH_BASE_URL}{_PROFILES_ENDPOINT}",
            headers=headers,
            timeout=timeout,
            label="secureScoreControlProfiles",
            adapter_name=self.tool_name,
        )
        scores_items = fetch_paginated_json(
            url=f"{_GRAPH_BASE_URL}{_SCORES_ENDPOINT}",
            headers=headers,
            params={"$top": "1"},
            timeout=timeout,
            max_pages=1,
            label="secureScores",
            adapter_name=self.tool_name,
        )
        profiles_data = {"value": profiles_items}
        scores_data = {"value": scores_items}

        profiles_path = output_dir / _PROFILES_FILENAME
        scores_path = output_dir / _SCORES_FILENAME

        profiles_path.write_text(
            json.dumps(profiles_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        scores_path.write_text(
            json.dumps(scores_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        items = [
            (profiles_path, f"{self.storage_slug}/{_PROFILES_FILENAME}"),
            (scores_path, f"{self.storage_slug}/{_SCORES_FILENAME}"),
        ]

        logger.info(
            "Secure Score collection complete. Output dir: %s, %d artifacts",
            output_dir,
            len(items),
        )

        return build_collection_output(
            tool=ToolSource.SECURE_SCORE,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            execution_metadata={
                "profiles_count": len(profiles_data.get("value", [])),
                "scores_count": len(scores_data.get("value", [])),
            },
        )

    def ingest_from_directory(
        self,
        source_dir: Path,
        *,
        schema_version: str,
        timestamp: datetime,
    ) -> CollectionOutput:
        """Construct a CollectionOutput from operator-provided Secure Score output."""
        from gxassessms.adapters._base import build_collection_output

        profiles_path = source_dir / _PROFILES_FILENAME
        scores_path = source_dir / _SCORES_FILENAME
        items = [
            (profiles_path, f"{self.storage_slug}/{_PROFILES_FILENAME}"),
            (scores_path, f"{self.storage_slug}/{_SCORES_FILENAME}"),
        ]

        return build_collection_output(
            tool=ToolSource.SECURE_SCORE,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=schema_version,
            timestamp=timestamp,
            execution_metadata={},
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate both JSON files exist, parse as dicts, and contain "value" lists.

        Raises:
            RawOutputValidationError: If any structural check fails.
        """
        self._validate_and_load_responses(raw)

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse Secure Score raw output into ToolObservations (validates first)."""
        profiles_data, scores_data = self._validate_and_load_responses(raw)
        observations = parse_secure_score(profiles_data, scores_data)

        logger.info(
            "Secure Score parse complete: %d observations",
            len(observations),
        )
        return observations

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
        """Extract per-control coverage records from Secure Score output.

        NOT_APPLICABLE (thirdParty/ignored) and MANUAL (no score data) controls
        are reported as NOT_ASSESSED. All others are ASSESSED.
        Deduplicates by native_check_id.
        """
        _not_assessed_statuses = {FindingStatus.NOT_APPLICABLE, FindingStatus.MANUAL}
        observations = self.parse(raw)

        seen: set[str] = set()
        records: list[CoverageRecord] = []

        for obs in observations:
            if obs.native_check_id in seen:
                continue
            seen.add(obs.native_check_id)

            if obs.native_status in _not_assessed_statuses:
                cov_status = CoverageStatus.NOT_ASSESSED
                reason: str | None = f"Control status: {obs.native_status}"
            else:
                cov_status = CoverageStatus.ASSESSED
                reason = None

            records.append(
                CoverageRecord(
                    control_id=obs.native_check_id,
                    tool=ToolSource.SECURE_SCORE,
                    status=cov_status,
                    reason=reason,
                )
            )

        logger.info("Secure Score coverage export: %d records", len(records))
        return records

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """Pass through parser-derived severity for failing/manual controls.

        Secure Score derives severity from rank+tier in the parser and stores
        it directly as a domain severity string in native_severity. The
        normalization default_severity_map only covers Shall/Should/May entries
        (ScubaGear/Maester), so without this map, all non-pass findings fall
        through to fallback_severity (MEDIUM), discarding the computed value.
        """
        return SEVERITY_IDENTITY_MAP  # type: ignore[return-value]  # StrEnum is str at runtime

    @property
    def category_map(self) -> dict[str, Any]:
        """Graph API controlCategory value -> Category for NormalizationPolicy.

        Keys are Microsoft's controlCategory strings: "Identity", "Data",
        "Device", "Apps", "Infrastructure".
        """
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """Empty -- Secure Score control IDs are already unique."""
        return {}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_and_load_responses(
        self, raw: ResolvedManifest
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Validate and load both JSON files. Returns (profiles, scores) dicts."""
        from gxassessms.adapters._base import load_json_file

        if not raw.file_manifest:
            raise RawOutputValidationError(
                "Secure Score file manifest is empty -- no output files found",
                adapter_name=self.tool_name,
            )

        profiles_path: str | None = None
        scores_path: str | None = None

        for file_path in raw.file_manifest:
            basename = Path(file_path).name
            if basename == _PROFILES_FILENAME:
                profiles_path = file_path
            elif basename == _SCORES_FILENAME:
                scores_path = file_path

        missing = [
            n
            for n, p in [
                (_PROFILES_FILENAME, profiles_path),
                (_SCORES_FILENAME, scores_path),
            ]
            if p is None
        ]
        if missing:
            raise RawOutputValidationError(
                f"Missing in Secure Score manifest: {', '.join(missing)}",
                adapter_name=self.tool_name,
            )

        # Type narrowing: guaranteed non-None after the missing check above
        assert profiles_path is not None  # noqa: S101
        assert scores_path is not None  # noqa: S101

        profiles_data = load_json_file(Path(profiles_path), adapter_name=self.tool_name)
        scores_data = load_json_file(Path(scores_path), adapter_name=self.tool_name)

        for label, data in [("profiles", profiles_data), ("scores", scores_data)]:
            if not isinstance(data, dict):
                raise RawOutputValidationError(
                    f"Secure Score {label} JSON is not a dict (got {type(data).__name__})",
                    adapter_name=self.tool_name,
                )
            if "value" not in data:
                raise RawOutputValidationError(
                    f"Secure Score {label} JSON missing required 'value' key",
                    adapter_name=self.tool_name,
                )
            if not isinstance(data["value"], list):  # pyright: ignore[reportUnknownArgumentType]
                raise RawOutputValidationError(
                    f"Secure Score {label} 'value' is not a list "
                    f"(got {type(data['value']).__name__})",  # pyright: ignore[reportUnknownArgumentType]
                    adapter_name=self.tool_name,
                )

        return profiles_data, scores_data
