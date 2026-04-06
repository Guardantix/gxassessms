"""Azure Advisor adapter -- implements ToolAdapter Protocol.

Azure Advisor is an Azure Management REST API that returns active
recommendations for a subscription. This adapter uses httpx for HTTP
calls and azure-identity for authentication.

API: GET /subscriptions/{sub}/providers/Microsoft.Advisor/recommendations
Auth: DefaultAzureCredential (azure-identity SDK)
Output: JSON with {"value": [...], "nextLink": "..."}

Verified against Azure Advisor REST API docs and real sample output.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import SecretStr

from gxassessms.adapters._base import load_json_file
from gxassessms.adapters.azure_advisor.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
)
from gxassessms.adapters.azure_advisor.parser import parse_advisor_recommendations
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    PrerequisiteError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.enums import CoverageStatus, ToolSource
from gxassessms.core.domain.models import (
    AuthContext,
    CollectedArtifact,
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
        }
    )

    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify azure-identity and httpx are importable."""
        missing: list[str] = []
        try:
            import azure.identity  # noqa: F401  # pyright: ignore[reportMissingImports]
        except ImportError:
            missing.append("azure-identity")

        try:
            import httpx as _httpx  # noqa: F401
        except ImportError:
            missing.append("httpx")

        if missing:
            return PrerequisiteResult(
                satisfied=False,
                message=(
                    f"Missing required packages: {', '.join(missing)}. "
                    f"Install with: pip install {' '.join(missing)}"
                ),
            )

        return PrerequisiteResult(
            satisfied=True,
            message="Azure Advisor prerequisites satisfied",
        )

    def authenticate(
        self,
        config: EngagementConfig,
    ) -> AuthContext | None:
        """Acquire an Azure Management API token via DefaultAzureCredential.

        DefaultAzureCredential tries (in order): environment variables,
        managed identity, Azure CLI, Azure PowerShell, interactive browser.
        No custom env vars needed.
        """
        from azure.identity import (  # pyright: ignore[reportMissingImports]
            DefaultAzureCredential,  # pyright: ignore[reportUnknownVariableType]
        )

        try:
            credential = DefaultAzureCredential()  # pyright: ignore[reportUnknownVariableType]
            token = credential.get_token(_MANAGEMENT_SCOPE)  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
        except Exception as exc:
            raise PrerequisiteError(
                f"Azure authentication failed: {exc}",
                adapter_name=self.tool_name,
            ) from exc

        return AuthContext(
            token=SecretStr(token.token),  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
            credential_refs={"scope": _MANAGEMENT_SCOPE},
            expires_at=datetime.fromtimestamp(token.expires_on, tz=UTC),  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
        )

    def collect(
        self,
        config: EngagementConfig,
        auth: AuthContext | None,
    ) -> CollectionOutput:
        """Call the Azure Advisor REST API and save recommendations to disk.

        Handles pagination via nextLink. Saves the full response (all pages
        merged) as a single JSON file.
        """
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.hashing import sha256_file

        if auth is None or auth.token is None:
            raise CollectionError(
                "Azure Advisor requires authentication. Call authenticate() first.",
                adapter_name=self.tool_name,
            )

        tc = config.tools.get(self.tool_name.lower())
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Azure Advisor adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        output_dir = Path(tc.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        subscription_id = config.tenant_id
        timeout = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        # Build API URL
        url = (
            f"{_MANAGEMENT_BASE_URL}/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Advisor/recommendations"
        )
        params: dict[str, str] = {"api-version": _ADVISOR_API_VERSION}

        # Optional category filter from tool config extra_args
        for arg in tc.extra_args:
            if arg.startswith("-Filter:"):
                params["$filter"] = arg.split(":", 1)[1]

        headers = {
            "Authorization": f"Bearer {auth.token.get_secret_value()}",
            "Content-Type": "application/json",
        }

        all_recommendations: list[dict[str, Any]] = []

        try:
            with httpx.Client(timeout=timeout) as client:
                next_url: str | None = url
                while next_url is not None:
                    response = client.get(
                        next_url,
                        headers=headers,
                        params=params if next_url == url else None,
                    )
                    response.raise_for_status()
                    data = response.json()

                    recommendations = data.get("value", [])
                    all_recommendations.extend(recommendations)

                    next_url = data.get("nextLink")
        except httpx.HTTPStatusError as exc:
            raise CollectionError(
                f"Azure Advisor API returned HTTP "
                f"{exc.response.status_code}: "
                f"{exc.response.text[:500]}",
                adapter_name=self.tool_name,
            ) from exc
        except httpx.RequestError as exc:
            raise CollectionError(
                f"Azure Advisor API request failed: {exc}",
                adapter_name=self.tool_name,
            ) from exc

        # Save merged response to disk
        output_file = output_dir / _OUTPUT_FILENAME
        output_data: dict[str, Any] = {"value": all_recommendations}
        output_file.write_text(
            json.dumps(output_data, indent=2),
            encoding="utf-8",
        )

        sha = sha256_file(output_file)
        artifacts: list[CollectedArtifact] = [
            CollectedArtifact(
                source_path=str(output_file),
                target_relpath=f"{self.storage_slug}/{_OUTPUT_FILENAME}",
                encoding="utf-8",
                sha256=sha,
            )
        ]

        logger.info(
            "Azure Advisor collection complete: %d recommendations saved to %s",
            len(all_recommendations),
            output_file,
        )

        return CollectionOutput(
            tool=ToolSource.AZURE_ADVISOR,
            tool_slug=self.storage_slug,
            schema_version=_ADVISOR_API_VERSION,
            timestamp=utc_now(),
            artifacts=artifacts,
            execution_metadata={
                "subscription_id": subscription_id,
                "recommendation_count": len(all_recommendations),
                "output_file": str(output_file),
            },
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate Azure Advisor output structure before parsing.

        Checks:
        1. At least one output file in manifest
        2. File contains valid JSON
        3. Top-level structure has "value" key
        4. "value" is a list
        5. Each element has required fields: recommendationTypeId, category,
           impact, shortDescription

        NOTE: Empty "value" array is VALID -- the subscription may have
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

            # Empty value array is valid -- no recommendations
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

    # ------------------------------------------------------------------
    # Properties for NormalizationPolicy consumption
    # ------------------------------------------------------------------

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """Azure Advisor uses impact-based severity, not standard severity map."""
        return {}  # severity derived from impact field in parser

    @property
    def category_map(self) -> dict[str, Any]:
        """Advisor category -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """recommendationTypeId -> canonical cross-reference ID."""
        return DEDUP_KEY_RULES
