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
from gxassessms.core.domain.enums import CoverageStatus, FindingStatus, Severity, ToolSource
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
_MAX_PAGES = 50  # Guard against runaway Graph API pagination


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
            if client_secret_env:
                client_secret = os.environ.get(client_secret_env, "")
                if not client_secret:
                    raise CollectionError(
                        f"Environment variable '{client_secret_env}' is not set "
                        f"or empty. Required for service principal authentication.",
                        adapter_name=self.tool_name,
                    )
                logger.info(  # nosemgrep  # client_id is a public Azure AD app GUID, not a secret
                    "Authenticating Secure Score via ClientSecretCredential (SP: %s)",
                    client_id,
                )
                credential = ClientSecretCredential(  # pyright: ignore[reportUnknownVariableType]
                    tenant_id=config.auth.tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
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
        ``config.tools["secure_score"]`` (note underscore).

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

        if auth.expires_at is not None and auth.expires_at <= utc_now():
            raise CollectionError(
                f"Graph API token expired at {auth.expires_at.isoformat()}. "
                "Call authenticate() again before collect().",
                adapter_name=self.tool_name,
            )

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
            max_pages=1,
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
        """Pass through parser-derived severity for failing/manual controls.

        Secure Score derives severity from rank+tier in the parser and stores
        it directly as a domain severity string in native_severity. The
        normalization default_severity_map only covers Shall/Should/May entries
        (ScubaGear/Maester), so without this map, all non-pass findings fall
        through to fallback_severity (MEDIUM), discarding the computed value.
        """
        return {
            (Severity.CRITICAL, FindingStatus.FAIL): Severity.CRITICAL,
            (Severity.HIGH, FindingStatus.FAIL): Severity.HIGH,
            (Severity.MEDIUM, FindingStatus.FAIL): Severity.MEDIUM,
            (Severity.LOW, FindingStatus.FAIL): Severity.LOW,
            (Severity.CRITICAL, FindingStatus.MANUAL): Severity.CRITICAL,
            (Severity.HIGH, FindingStatus.MANUAL): Severity.HIGH,
            (Severity.MEDIUM, FindingStatus.MANUAL): Severity.MEDIUM,
            (Severity.LOW, FindingStatus.MANUAL): Severity.LOW,
        }

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

    def _fetch_graph_endpoint(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout: int,
        label: str,
        max_pages: int | None = None,
    ) -> dict[str, Any]:
        """Fetch a Graph API endpoint, following @odata.nextLink for pagination.

        Accumulates all pages into a single ``{"value": [...]}`` response.
        Raises CollectionError on any HTTP or parse failure.

        Args:
            max_pages: Stop after this many pages. Defaults to ``_MAX_PAGES``
                when ``None``. Use ``1`` when only the first page is needed
                (e.g. ``secureScores?$top=1``).
        """
        import httpx

        page_limit = max_pages if max_pages is not None else _MAX_PAGES
        all_items: list[Any] = []
        next_url: str | None = url
        page_count = 0

        with httpx.Client(timeout=timeout) as client:
            while next_url is not None:
                page_count += 1
                if page_count > page_limit:
                    raise CollectionError(
                        f"Graph API pagination exceeded {page_limit} pages for {label}; "
                        "possible runaway pagination or server error",
                        adapter_name=self.tool_name,
                    )
                try:
                    response = client.get(next_url, headers=headers)  # pyright: ignore[reportUnknownArgumentType]
                    response.raise_for_status()
                    data: Any = response.json()
                except httpx.TimeoutException as exc:
                    raise CollectionError(
                        f"Graph API request timed out for {label} "
                        f"(timeout={timeout}s, page={page_count})",
                        adapter_name=self.tool_name,
                    ) from exc
                except httpx.HTTPStatusError as exc:
                    raise CollectionError(
                        f"Graph API returned HTTP {exc.response.status_code} "
                        f"for {label} (page={page_count}): {exc.response.text[:500]}",
                        adapter_name=self.tool_name,
                    ) from exc
                except httpx.HTTPError as exc:
                    raise CollectionError(
                        f"Graph API request failed for {label} (page={page_count}): {exc}",
                        adapter_name=self.tool_name,
                    ) from exc
                except ValueError as exc:
                    raise CollectionError(
                        f"Graph API returned invalid JSON for {label} (page={page_count}): {exc}",
                        adapter_name=self.tool_name,
                    ) from exc

                if not isinstance(data, dict):
                    raise CollectionError(
                        f"Graph API returned non-object JSON for {label} "
                        f"(page={page_count}, got {type(data).__name__})",
                        adapter_name=self.tool_name,
                    )

                all_items.extend(data.get("value", []))  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]

                # Explicit max_pages: stop cleanly after the requested pages.
                # Default _MAX_PAGES cap: let the top-of-loop guard error on
                # the next iteration (runaway pagination is unexpected).
                if max_pages is not None and page_count >= max_pages:
                    next_url = None
                else:
                    raw_next = data.get("@odata.nextLink")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
                    if raw_next is not None and not isinstance(raw_next, str):
                        raise CollectionError(
                            f"Graph API returned non-string @odata.nextLink for {label} "
                            f"(page={page_count}, got {type(raw_next).__name__})",  # pyright: ignore[reportUnknownArgumentType]
                            adapter_name=self.tool_name,
                        )
                    next_url = raw_next

        logger.info(
            "Fetched %s: %d items across %d page(s)",
            label,
            len(all_items),
            page_count,
        )
        return {"value": all_items}

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
