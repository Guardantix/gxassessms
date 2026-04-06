"""Unit tests for AzureAdvisorAdapter -- adapter-level methods.

Tests for collect(), check_prerequisites(), authenticate() that require
mocking httpx or azure-identity. Parser and mapping tests live in their
own files.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr

from gxassessms.adapters.azure_advisor import AzureAdvisorAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.contracts.errors import CollectionError, PrerequisiteError
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import AuthContext

_DEFAULT_SUBSCRIPTION_ID = "12345678-1234-1234-1234-123456789012"


def _make_config(
    output_dir: str = "",
    subscription_id: str = _DEFAULT_SUBSCRIPTION_ID,
) -> EngagementConfig:
    return EngagementConfig(
        client_name="Test Client",
        tenant_id="00000000-0000-0000-0000-000000000001",
        subscription_id=subscription_id,
        auth=AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_TEST_SECRET",  # pragma: allowlist secret
        ),
        tools={
            "azureadvisor": ToolConfig(
                enabled=True,
                output_dir=output_dir,
            )
        },
    )


def _make_auth() -> AuthContext:
    return AuthContext(
        token=SecretStr("fake-token"),  # pragma: allowlist secret
        extra={"scope": "https://management.azure.com/.default"},
        expires_at=datetime(2026, 12, 31, 0, 0, 0, tzinfo=UTC),
    )


def _make_mock_client(responses: list[dict[str, Any]]) -> MagicMock:
    """Return a mock httpx client whose get() returns the given dicts in sequence."""
    mock_client = MagicMock()
    mock_responses = []
    for data in responses:
        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status.return_value = None
        mock_responses.append(resp)
    mock_client.get.side_effect = mock_responses
    return mock_client


# ---------------------------------------------------------------------------
# check_prerequisites
# ---------------------------------------------------------------------------


class TestCheckPrerequisites:
    def test_satisfied_when_azure_identity_is_importable(self) -> None:
        adapter = AzureAdvisorAdapter()
        # Inject mocks for both azure and azure.identity so this test works
        # even when azure-identity is not installed in the dev environment.
        with patch.dict(sys.modules, {"azure": MagicMock(), "azure.identity": MagicMock()}):
            result = adapter.check_prerequisites()
        assert result["satisfied"] is True
        assert "satisfied" in result["message"]

    def test_not_satisfied_when_azure_identity_missing(self) -> None:
        adapter = AzureAdvisorAdapter()
        with patch.dict(sys.modules, {"azure": None, "azure.identity": None}):
            result = adapter.check_prerequisites()
        assert result["satisfied"] is False
        assert "azure-identity" in result["message"]
        assert "pip install" in result["message"]


# ---------------------------------------------------------------------------
# authenticate
# ---------------------------------------------------------------------------


class TestAuthenticate:
    def test_raises_prerequisite_error_on_import_error(self, tmp_path: Path) -> None:
        """ImportError from inside authenticate() must become PrerequisiteError."""
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))
        # Simulate azure.core.exceptions being unavailable
        with (
            patch.dict(sys.modules, {"azure.core.exceptions": None}),
            pytest.raises(PrerequisiteError, match="not importable"),
        ):
            adapter.authenticate(config)


# ---------------------------------------------------------------------------
# collect() -- HTTP error handling and response validation
# ---------------------------------------------------------------------------


class TestCollectHTTPErrors:
    @patch("gxassessms.adapters.azure_advisor.adapter.httpx.Client")
    def test_raises_collection_error_on_http_status_error(
        self, MockClient: MagicMock, tmp_path: Path
    ) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        mock_client = MagicMock()
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        request = httpx.Request("GET", "https://management.azure.com/")
        error_response = httpx.Response(403, text="Forbidden")
        mock_client.get.side_effect = httpx.HTTPStatusError(
            "403", request=request, response=error_response
        )

        with pytest.raises(CollectionError, match="403"):
            adapter.collect(config, _make_auth())

    @patch("gxassessms.adapters.azure_advisor.adapter.httpx.Client")
    def test_raises_collection_error_on_request_error(
        self, MockClient: MagicMock, tmp_path: Path
    ) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        mock_client = MagicMock()
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        request = httpx.Request("GET", "https://management.azure.com/")
        mock_client.get.side_effect = httpx.ConnectError("timeout", request=request)

        with pytest.raises(CollectionError, match="request failed"):
            adapter.collect(config, _make_auth())

    @patch("gxassessms.adapters.azure_advisor.adapter.httpx.Client")
    def test_raises_collection_error_on_non_dict_response(
        self, MockClient: MagicMock, tmp_path: Path
    ) -> None:
        """Non-dict JSON response must raise CollectionError, not AttributeError."""
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        mock_client = _make_mock_client([["not", "a", "dict"]])  # type: ignore[arg-type]
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        with pytest.raises(CollectionError, match="unexpected response type"):
            adapter.collect(config, _make_auth())

    @patch("gxassessms.adapters.azure_advisor.adapter.httpx.Client")
    def test_raises_collection_error_on_null_value_key(
        self, MockClient: MagicMock, tmp_path: Path
    ) -> None:
        """null 'value' must raise CollectionError, not TypeError on extend(None)."""
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        mock_client = _make_mock_client([{"value": None}])
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        with pytest.raises(CollectionError, match="'value' is not a list"):
            adapter.collect(config, _make_auth())


# ---------------------------------------------------------------------------
# collect() -- pagination
# ---------------------------------------------------------------------------


class TestCollectPagination:
    @patch("gxassessms.adapters.azure_advisor.adapter.httpx.Client")
    def test_accumulates_recommendations_across_pages(
        self, MockClient: MagicMock, tmp_path: Path
    ) -> None:
        """Multi-page response accumulates all recommendations into one file."""
        import json as _json

        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        rec1 = {
            "recommendationTypeId": "aaa",
            "name": "instance-1",
            "category": "Security",
            "impact": "High",
            "shortDescription": {"problem": "P1", "solution": "S1"},
        }
        rec2 = {
            "recommendationTypeId": "bbb",
            "name": "instance-2",
            "category": "Cost",
            "impact": "Medium",
            "shortDescription": {"problem": "P2", "solution": "S2"},
        }

        page2_url = "https://management.azure.com/nextpage"

        mock_client = _make_mock_client(
            [
                {"value": [rec1], "nextLink": page2_url},
                {"value": [rec2]},
            ]
        )
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        adapter.collect(config, _make_auth())
        output_file = tmp_path / "advisor_recommendations.json"
        saved = _json.loads(output_file.read_text())
        assert len(saved["value"]) == 2

    @patch("gxassessms.adapters.azure_advisor.adapter.httpx.Client")
    def test_raises_on_pagination_cycle(self, MockClient: MagicMock, tmp_path: Path) -> None:
        """Cyclic nextLink must raise CollectionError instead of looping forever."""
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        cycle_url = (
            f"https://management.azure.com/subscriptions/{_DEFAULT_SUBSCRIPTION_ID}"
            f"/providers/Microsoft.Advisor/recommendations"
        )

        mock_client = _make_mock_client([{"value": [], "nextLink": cycle_url}])
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        with pytest.raises(CollectionError, match="cycle"):
            adapter.collect(config, _make_auth())

    @patch("gxassessms.adapters.azure_advisor.adapter.httpx.Client")
    def test_single_page_returns_correct_collection_output(
        self, MockClient: MagicMock, tmp_path: Path
    ) -> None:
        """Happy path: single-page response writes file and returns CollectionOutput."""
        import json as _json

        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        rec = {
            "recommendationTypeId": "abc",
            "name": "inst-1",
            "category": "Security",
            "impact": "High",
            "shortDescription": {"problem": "P", "solution": "S"},
        }
        mock_client = _make_mock_client([{"value": [rec]}])
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        result = adapter.collect(config, _make_auth())

        assert result.tool == ToolSource.AZURE_ADVISOR
        assert result.tool_slug == "azure-advisor"
        assert result.execution_metadata["recommendation_count"] == 1
        assert len(result.artifacts) == 1
        output_file = tmp_path / "advisor_recommendations.json"
        assert output_file.exists()
        saved = _json.loads(output_file.read_text())
        assert len(saved["value"]) == 1


# ---------------------------------------------------------------------------
# collect() -- guard conditions
# ---------------------------------------------------------------------------


class TestCollectGuards:
    def test_raises_when_auth_is_none(self, tmp_path: Path) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))

        with pytest.raises(CollectionError, match="requires authentication"):
            adapter.collect(config, None)

    def test_raises_when_auth_token_is_none(self, tmp_path: Path) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path))
        auth = AuthContext()  # token=None by default

        with pytest.raises(CollectionError, match="requires authentication"):
            adapter.collect(config, auth)

    def test_raises_when_output_dir_not_configured(self) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir="")  # empty output_dir

        with pytest.raises(CollectionError, match="output_dir"):
            adapter.collect(config, _make_auth())

    def test_raises_when_subscription_id_missing(self, tmp_path: Path) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path), subscription_id="")

        with pytest.raises(CollectionError, match="subscription_id"):
            adapter.collect(config, _make_auth())

    def test_raises_when_subscription_id_is_not_a_uuid(self, tmp_path: Path) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(output_dir=str(tmp_path), subscription_id="not-a-uuid")

        with pytest.raises(CollectionError, match="Invalid subscription_id"):
            adapter.collect(config, _make_auth())
