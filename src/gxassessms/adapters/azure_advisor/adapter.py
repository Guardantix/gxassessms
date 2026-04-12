"""Azure Advisor adapter -- implements ToolAdapter Protocol.

Azure Advisor is an Azure Management REST API that returns active
recommendations for a subscription. This adapter uses httpx for HTTP
calls and azure-identity for authentication.

API: GET /subscriptions/{sub}/providers/Microsoft.Advisor/recommendations
Auth: dispatches on config.auth.method (client_credential, device_code, interactive)
Output: JSON with {"value": [...], "nextLink": "..."}

Verified against Azure Advisor REST API docs and real sample output.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from gxassessms.adapters._azure_auth import acquire_azure_token
from gxassessms.adapters._base import load_json_file
from gxassessms.adapters._http import (
    check_python_packages,
    fetch_paginated_json,
    validate_auth_context,
)
from gxassessms.adapters.azure_advisor.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
)
from gxassessms.adapters.azure_advisor.parser import parse_advisor_recommendations
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import SEVERITY_IDENTITY_MAP
from gxassessms.core.domain.enums import CoverageStatus, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CollectionOutput,
    CoverageRecord,
    ResolvedManifest,
    ToolObservation,
)

logger = logging.getLogger(__name__)

_ADVISOR_API_VERSION = "2025-01-01"
_MANAGEMENT_BASE_URL = "https://management.azure.com"
_MANAGEMENT_SCOPE = "https://management.azure.com/.default"
_DEFAULT_TIMEOUT_SECONDS = 120
_OUTPUT_FILENAME = "advisor_recommendations.json"
_MAX_PAGES = 200
_SUBSCRIPTION_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# OData $filter values for Azure Advisor contain spaces, single quotes, and
# comparison operators (eq, ne, lt, gt) -- characters that are rejected by the
# PowerShell-safe _ARG_PATTERN in _base.validate_extra_args().  This pattern
# allows only the characters valid OData Advisor expressions actually need,
# including '.' and '/' for property paths and resource IDs
# (e.g. ResourceMetadata.ResourceType eq 'Microsoft.Compute/virtualMachines')
# and ':' for ISO-8601 timestamp literals.
_ODATA_FILTER_RE = re.compile(r"^[A-Za-z0-9_\s'\-()./:]{1,512}$")


def _parse_advisor_args(extra_args: list[str], adapter_name: str) -> dict[str, str]:
    """Parse Azure Advisor extra_args, validating -Filter with an OData-safe allowlist.

    Only -Filter is supported.  Any unknown argument raises CollectionError
    (fail-closed).  The Filter value is validated to contain only characters
    valid in an Azure Advisor OData $filter expression.

    Args:
        extra_args: Raw extra_args list from ToolConfig.
        adapter_name: Adapter name for error messages.

    Returns:
        Dict of parsed argument name -> value (e.g., {"Filter": "Category eq 'Security'"}).

    Raises:
        CollectionError: If any argument is malformed, uses disallowed characters, or
                         is not a recognised Azure Advisor extra arg.
    """
    result: dict[str, str] = {}
    for arg in extra_args:
        if not arg.startswith("-"):
            raise CollectionError(
                f"Extra argument must start with '-': {arg!r}",
                adapter_name=adapter_name,
            )
        bare = arg[1:]
        name, _, value = bare.partition(":")
        if not name or not name.isidentifier():
            raise CollectionError(
                f"Extra argument has invalid name: {arg!r}",
                adapter_name=adapter_name,
            )
        if name == "Filter":
            if not _ODATA_FILTER_RE.match(value):
                raise CollectionError(
                    f"Filter value contains disallowed characters: {value!r}. "
                    f"OData filter values may contain alphanumeric characters, "
                    f"spaces, single quotes, hyphens, underscores, parentheses, "
                    f"dots, forward slashes, and colons.",
                    adapter_name=adapter_name,
                )
            result[name] = value
        else:
            raise CollectionError(
                f"Unknown extra argument: -{name!r}. Supported: -Filter",
                adapter_name=adapter_name,
            )
    return result


class AzureAdvisorAdapter:
    """ToolAdapter implementation for Azure Advisor REST API."""

    tool_name: str = "AzureAdvisor"
    storage_slug: str = "azure-advisor"
    tool_source: ToolSource = ToolSource.AZURE_ADVISOR
    capabilities: frozenset[str] = frozenset(
        {
            "collect",
            "parse",
            "prerequisites",
            "shared_auth",
            "coverage_export",
            "ingest",
        }
    )
    default_schema_version: str = _ADVISOR_API_VERSION

    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify azure-identity is importable.

        httpx is a declared package dependency and assumed present.
        """
        return check_python_packages(
            [("azure.identity", "azure-identity")],
            adapter_name=self.tool_name,
        )

    def authenticate(
        self,
        config: EngagementConfig,
    ) -> AuthContext | None:
        """Acquire an Azure Management API token."""
        return acquire_azure_token(config, scope=_MANAGEMENT_SCOPE, adapter_name=self.tool_name)

    def collect(
        self,
        config: EngagementConfig,
        auth: AuthContext | None,
    ) -> CollectionOutput:
        """Call the Azure Advisor REST API and save recommendations to disk.

        Handles pagination via nextLink. Saves the full response (all pages
        merged) as a single JSON file.
        """
        from gxassessms.adapters._base import build_collection_output
        from gxassessms.core.config.datetime_utils import utc_now

        validate_auth_context(auth, adapter_name=self.tool_name)

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Azure Advisor adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        from gxassessms.core.security.permissions import secure_mkdir

        output_dir = Path(tc.output_dir)
        secure_mkdir(output_dir, parents=True, exist_ok=True)

        if not config.subscription_id:
            raise CollectionError(
                "Azure Advisor requires subscription_id in engagement config",
                adapter_name=self.tool_name,
            )

        if not _SUBSCRIPTION_ID_RE.match(config.subscription_id):
            raise CollectionError(
                f"Invalid subscription_id format: expected a UUID, got {config.subscription_id!r}",
                adapter_name=self.tool_name,
            )

        subscription_id = config.subscription_id
        timeout = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        url = (
            f"{_MANAGEMENT_BASE_URL}/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Advisor/recommendations"
        )
        params: dict[str, str] = {"api-version": _ADVISOR_API_VERSION}

        if tc.extra_args:
            advisor_args = _parse_advisor_args(tc.extra_args, self.tool_name)
            if "Filter" in advisor_args:
                params["$filter"] = advisor_args["Filter"]

        # validate_auth_context() raised above if auth or token is None
        bearer = auth.token.get_secret_value()  # type: ignore[union-attr]
        headers = {"Authorization": f"Bearer {bearer}"}

        all_recommendations = fetch_paginated_json(
            url=url,
            headers=headers,
            params=params,
            pagination_key="nextLink",
            max_pages=_MAX_PAGES,
            timeout=timeout,
            label="Azure Advisor recommendations",
            adapter_name=self.tool_name,
        )

        output_file = output_dir / _OUTPUT_FILENAME
        output_data: dict[str, Any] = {"value": all_recommendations}
        try:
            output_file.write_text(
                json.dumps(output_data, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            raise CollectionError(
                f"Failed to write Azure Advisor output to {output_file}: {exc}",
                adapter_name=self.tool_name,
            ) from exc

        items = [(output_file, f"{self.storage_slug}/{_OUTPUT_FILENAME}")]

        logger.info(
            "Azure Advisor collection complete: %d recommendations saved to %s",
            len(all_recommendations),
            output_file,
        )

        return build_collection_output(
            tool=ToolSource.AZURE_ADVISOR,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=_ADVISOR_API_VERSION,
            timestamp=utc_now(),
            execution_metadata={
                "recommendation_count": len(all_recommendations),
            },
        )

    def ingest_from_directory(
        self,
        source_dir: Path,
        *,
        schema_version: str,
        timestamp: datetime,
    ) -> CollectionOutput:
        """Construct a CollectionOutput from operator-provided Azure Advisor output."""
        from gxassessms.adapters._base import build_collection_output

        output_file = source_dir / _OUTPUT_FILENAME

        if not output_file.exists():
            raise CollectionError(
                f"Azure Advisor output file not found: {output_file}",
                adapter_name=self.tool_name,
            )

        items = [(output_file, f"{self.storage_slug}/{_OUTPUT_FILENAME}")]

        return build_collection_output(
            tool=ToolSource.AZURE_ADVISOR,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=schema_version,
            timestamp=timestamp,
            execution_metadata={},
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate Azure Advisor output structure before parsing.

        Empty "value" array is VALID -- the subscription may have
        no active recommendations.
        """
        if not raw.file_manifest:
            raise RawOutputValidationError(
                "Azure Advisor file manifest is empty",
                adapter_name=self.tool_name,
            )

        for file_path in raw.file_manifest:
            path = Path(file_path)
            data = load_json_file(path, adapter_name=self.tool_name)

            if not isinstance(data, dict):
                raise RawOutputValidationError(
                    f"Expected JSON object, got {type(data).__name__} in {path}",
                    adapter_name=self.tool_name,
                )

            if "value" not in data:
                raise RawOutputValidationError(
                    f"Missing 'value' key in {path}",
                    adapter_name=self.tool_name,
                )

            value = data["value"]  # pyright: ignore[reportUnknownVariableType]
            if not isinstance(value, list):
                raise RawOutputValidationError(
                    f"'value' is not a list in {path} (got {type(value).__name__})",  # pyright: ignore[reportUnknownArgumentType]
                    adapter_name=self.tool_name,
                )

            for i, rec in enumerate(value):  # pyright: ignore[reportUnknownArgumentType,reportUnknownVariableType]
                if not isinstance(rec, dict):
                    raise RawOutputValidationError(
                        f"Recommendation [{i}] is not a dict in {path}",
                        adapter_name=self.tool_name,
                    )
                for required_field in (
                    "recommendationTypeId",
                    "category",
                    "impact",
                    "shortDescription",
                ):
                    if required_field not in rec:
                        raise RawOutputValidationError(
                            f"Recommendation [{i}] missing '{required_field}' in {path}",
                            adapter_name=self.tool_name,
                        )

                short_desc = rec.get("shortDescription")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
                if not isinstance(short_desc, dict):
                    raise RawOutputValidationError(
                        f"Recommendation [{i}] 'shortDescription' must be a dict, "
                        f"got {type(short_desc).__name__!r} in {path}",  # pyright: ignore[reportUnknownArgumentType]
                        adapter_name=self.tool_name,
                    )

    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]:
        """Parse Azure Advisor output into ToolObservations."""
        self.validate_raw(raw)

        all_observations: list[ToolObservation] = []

        for file_path in raw.file_manifest:
            data = load_json_file(
                Path(file_path),
                adapter_name=self.tool_name,
            )
            recommendations = data["value"]
            observations = parse_advisor_recommendations(recommendations)
            all_observations.extend(observations)

        logger.info(
            "Parsed %d observations from Azure Advisor output",
            len(all_observations),
        )
        return all_observations

    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]:
        """Report coverage based on parsed recommendations.

        Azure Advisor only reports active recommendations (things to fix).
        Each unique recommendationTypeId represents a control that was
        assessed. Since recommendations are only present when action is
        needed, all coverage records are ASSESSED.
        """
        observations = self.parse(raw)
        records: list[CoverageRecord] = []
        seen_checks: set[str] = set()

        for obs in observations:
            if obs.native_check_id not in seen_checks:
                seen_checks.add(obs.native_check_id)
                records.append(
                    CoverageRecord(
                        control_id=obs.native_check_id,
                        tool=ToolSource.AZURE_ADVISOR,
                        status=CoverageStatus.ASSESSED,
                    )
                )

        return records

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """(Severity, FindingStatus) -> Severity passthrough for NormalizationPolicy."""
        return SEVERITY_IDENTITY_MAP  # type: ignore[return-value]  # StrEnum keys satisfy str

    @property
    def category_map(self) -> dict[str, Any]:
        """Advisor category -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """recommendationTypeId GUID -> canonical cross-reference ID.

        Keys are bare GUIDs (e.g. '242639fd-cd73-4be2-8f55-70478db8d1a5'),
        matching the stable native_check_id emitted by the parser.
        """
        return DEDUP_KEY_RULES
