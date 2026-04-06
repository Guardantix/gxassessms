"""Secure Score adapter -- Microsoft Graph API security posture assessment.

Unlike PowerShell-based adapters (ScubaGear, Maester), this adapter calls
the Microsoft Graph REST API directly via httpx. It fetches two endpoints
(secureScoreControlProfiles and secureScores), joins them by control ID,
and produces ToolObservations representing the tenant's security posture.

Auth is handled by azure.identity (ClientSecretCredential for service
principal configs, DefaultAzureCredential as fallback).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from gxassessms.adapters.secure_score.mappings import CATEGORY_MAP
from gxassessms.adapters.secure_score.parser import parse_secure_score
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import (
    CollectionError,
    RawOutputValidationError,
)
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.constants import AdapterCapability
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
        {"collect", "parse", "prerequisites", "shared_auth", "coverage_export"}
    )

    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify httpx and azure.identity are importable."""
        missing: list[str] = []

        try:
            import httpx  # noqa: F401
        except ImportError:
            missing.append("httpx")

        try:
            import azure.identity  # noqa: F401  # pyright: ignore[reportMissingImports]
        except ImportError:
            missing.append("azure-identity")

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
            message="httpx and azure.identity available",
        )

    def authenticate(self, config: EngagementConfig) -> AuthContext | None:
        """Acquire a Microsoft Graph API token via azure.identity.

        Uses ClientSecretCredential when SP credentials are configured;
        falls back to DefaultAzureCredential otherwise.

        Raises:
            CollectionError: If token acquisition fails.
        """
        from pydantic import SecretStr

        from gxassessms.core.config.datetime_utils import from_epoch

        try:
            from azure.core.exceptions import (  # pyright: ignore[reportMissingImports]
                AzureError,  # pyright: ignore[reportUnknownVariableType]
            )
            from azure.identity import (  # pyright: ignore[reportMissingImports]
                ClientSecretCredential,  # pyright: ignore[reportUnknownVariableType]
                DefaultAzureCredential,  # pyright: ignore[reportUnknownVariableType]
            )
        except ImportError as exc:
            raise CollectionError(
                "azure-identity package is required for Secure Score authentication. "
                "Install with: pip install azure-identity",
                adapter_name=self.tool_name,
            ) from exc

        client_id = config.auth.client_id
        client_secret_env = config.auth.client_secret_env

        try:
            if client_id and client_secret_env:
                client_secret = os.environ.get(client_secret_env, "")
                if not client_secret:
                    raise CollectionError(
                        f"Environment variable '{client_secret_env}' is not set "
                        f"or empty. Required for service principal authentication.",
                        adapter_name=self.tool_name,
                    )
                logger.info(
                    "Authenticating Secure Score via ClientSecretCredential (SP: %s)",
                    client_id,
                )
                credential = ClientSecretCredential(  # pyright: ignore[reportUnknownVariableType]
                    tenant_id=config.auth.tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            elif client_id and not client_secret_env:
                raise CollectionError(
                    "'client_id' is configured but 'client_secret_env' is absent. "
                    "Provide both for service principal auth, or remove 'client_id' "
                    "to use DefaultAzureCredential.",
                    adapter_name=self.tool_name,
                )
            elif not client_id and client_secret_env:
                raise CollectionError(
                    "'client_secret_env' is configured but 'client_id' is absent. "
                    "Provide both for service principal auth, or remove 'client_secret_env' "
                    "to use DefaultAzureCredential.",
                    adapter_name=self.tool_name,
                )
            else:
                logger.info("Authenticating Secure Score via DefaultAzureCredential")
                credential = DefaultAzureCredential()  # pyright: ignore[reportUnknownVariableType]

            token_result = credential.get_token(_GRAPH_SCOPE)  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
        except CollectionError:
            raise
        except (AzureError, ValueError, OSError) as exc:  # pyright: ignore[reportUnknownVariableType]
            raise CollectionError(
                f"Failed to acquire Graph API token: {exc}",
                adapter_name=self.tool_name,
            ) from exc

        expires_at = from_epoch(token_result.expires_on)  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
        return AuthContext(
            token=SecretStr(token_result.token),  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
            expires_at=expires_at,
            extra={"scope": _GRAPH_SCOPE},
        )

    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput:
        """Fetch Secure Score data from the Microsoft Graph API.

        Reads ``output_dir`` and ``timeout`` from
        ``config.tools["securescore"]``.

        Raises:
            CollectionError: If the API call fails or output_dir is missing.
        """
        from gxassessms.core.config.datetime_utils import utc_now
        from gxassessms.core.hashing import sha256_file

        if auth is None or auth.token is None:
            raise CollectionError(
                "Secure Score adapter requires authentication. Call authenticate() first.",
                adapter_name=self.tool_name,
            )

        tc = config.tools.get("secure_score")
        if tc is None or not tc.output_dir:
            raise CollectionError(
                "Secure Score adapter requires 'output_dir' in tool config",
                adapter_name=self.tool_name,
            )

        from gxassessms.core.security.permissions import secure_mkdir

        output_dir = Path(tc.output_dir)
        secure_mkdir(output_dir, parents=True, exist_ok=True)
        timeout = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

        bearer_token = auth.token.get_secret_value()
        headers = {"Authorization": f"Bearer {bearer_token}"}

        profiles_data = self._fetch_graph_endpoint(
            f"{_GRAPH_BASE_URL}{_PROFILES_ENDPOINT}",
            headers=headers,
            timeout=timeout,
            label="secureScoreControlProfiles",
        )
        scores_data = self._fetch_graph_endpoint(
            f"{_GRAPH_BASE_URL}{_SCORES_ENDPOINT}?$top=1",
            headers=headers,
            timeout=timeout,
            label="secureScores",
        )

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

        profiles_sha = sha256_file(profiles_path)
        scores_sha = sha256_file(scores_path)

        artifacts: list[CollectedArtifact] = [
            CollectedArtifact(
                source_path=str(profiles_path),
                target_relpath=f"{self.storage_slug}/{_PROFILES_FILENAME}",
                encoding="utf-8",
                sha256=profiles_sha,
            ),
            CollectedArtifact(
                source_path=str(scores_path),
                target_relpath=f"{self.storage_slug}/{_SCORES_FILENAME}",
                encoding="utf-8",
                sha256=scores_sha,
            ),
        ]

        logger.info(
            "Secure Score collection complete. Output dir: %s, %d artifacts",
            output_dir,
            len(artifacts),
        )

        return CollectionOutput(
            tool=ToolSource.SECURE_SCORE,
            tool_slug=self.storage_slug,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            artifacts=artifacts,
            execution_metadata={
                "profiles_count": len(profiles_data.get("value", [])),
                "scores_count": len(scores_data.get("value", [])),
            },
        )

    def validate_raw(self, raw: ResolvedManifest) -> None:
        """Validate both JSON files exist, parse, and contain "value" arrays.

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

        All non-deprecated controls that produce an observation are reported
        as ASSESSED. Deduplicates by native_check_id.
        """
        observations = self.parse(raw)

        seen: set[str] = set()
        records: list[CoverageRecord] = []

        for obs in observations:
            if obs.native_check_id in seen:
                continue
            seen.add(obs.native_check_id)

            records.append(
                CoverageRecord(
                    control_id=obs.native_check_id,
                    tool=ToolSource.SECURE_SCORE,
                    status=CoverageStatus.ASSESSED,
                    reason=None,
                )
            )

        logger.info("Secure Score coverage export: %d records", len(records))
        return records

    @property
    def severity_map(self) -> dict[tuple[str, str], Any]:
        """Empty -- Secure Score derives severity from rank/tier, not a map."""
        return {}

    @property
    def category_map(self) -> dict[str, Any]:
        """Microsoft service name -> Category for NormalizationPolicy."""
        return CATEGORY_MAP

    @property
    def dedup_key_rules(self) -> dict[str, str]:
        """Empty -- Secure Score control IDs are already unique."""
        return {}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_graph_endpoint(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout: int,
        label: str,
    ) -> dict[str, Any]:
        """Fetch a single Graph API endpoint. Raises CollectionError on failure."""
        import httpx

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                data: Any = response.json()
        except httpx.TimeoutException as exc:
            raise CollectionError(
                f"Graph API request timed out for {label} (timeout={timeout}s)",
                adapter_name=self.tool_name,
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise CollectionError(
                f"Graph API returned HTTP {exc.response.status_code} "
                f"for {label}: {exc.response.text[:500]}",
                adapter_name=self.tool_name,
            ) from exc
        except httpx.HTTPError as exc:
            raise CollectionError(
                f"Graph API request failed for {label}: {exc}",
                adapter_name=self.tool_name,
            ) from exc
        except ValueError as exc:
            raise CollectionError(
                f"Graph API returned invalid JSON for {label}: {exc}",
                adapter_name=self.tool_name,
            ) from exc

        if not isinstance(data, dict):
            raise CollectionError(
                f"Graph API returned non-object JSON for {label} (got {type(data).__name__})",
                adapter_name=self.tool_name,
            )

        return data  # pyright: ignore[reportUnknownVariableType]

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
