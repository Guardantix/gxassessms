"""Azure Advisor collect() parity test after build_collection_output refactor."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from pydantic import SecretStr

from gxassessms.adapters.azure_advisor.adapter import AzureAdvisorAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import AuthContext

_DEFAULT_SUBSCRIPTION_ID = "12345678-1234-1234-1234-123456789012"


def _make_config(output_dir: str) -> EngagementConfig:
    return EngagementConfig(
        client_name="Test Client",
        tenant_id="00000000-0000-0000-0000-000000000001",
        subscription_id=_DEFAULT_SUBSCRIPTION_ID,
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
    mock_client = MagicMock()
    mock_responses = []
    for data in responses:
        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status.return_value = None
        mock_responses.append(resp)
    mock_client.get.side_effect = mock_responses
    return mock_client


class TestAzureAdvisorCollectParity:
    """Verify that the refactored collect() produces the expected CollectionOutput."""

    @patch("httpx.Client")
    def test_collect_returns_expected_output(self, MockClient: MagicMock, tmp_path: Path) -> None:
        adapter = AzureAdvisorAdapter()
        config = _make_config(str(tmp_path))

        rec = {
            "recommendationTypeId": "abc-123",
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
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.target_relpath == "azure-advisor/advisor_recommendations.json"
        assert artifact.target_relpath.startswith("azure-advisor/")
        assert len(artifact.sha256) == 64
        assert all(c in "0123456789abcdef" for c in artifact.sha256)
        assert result.execution_metadata["recommendation_count"] == 1

    @patch("httpx.Client")
    def test_collect_zero_recommendations(self, MockClient: MagicMock, tmp_path: Path) -> None:
        """Empty recommendation list still produces a valid artifact."""
        adapter = AzureAdvisorAdapter()
        config = _make_config(str(tmp_path))

        mock_client = _make_mock_client([{"value": []}])
        MockClient.return_value.__enter__.return_value = mock_client
        MockClient.return_value.__exit__.return_value = False

        result = adapter.collect(config, _make_auth())

        assert result.tool == ToolSource.AZURE_ADVISOR
        assert len(result.artifacts) == 1
        assert result.execution_metadata["recommendation_count"] == 0
        assert len(result.artifacts[0].sha256) == 64
