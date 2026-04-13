"""Secure Score collect() parity test after build_collection_output refactor."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from pydantic import SecretStr

from gxassessms.adapters.secure_score.adapter import SecureScoreAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.config.datetime_utils import utc_now
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import AuthContext


def _make_config(output_dir: str) -> EngagementConfig:
    return EngagementConfig(
        client_name="Test Client",
        tenant_id="00000000-0000-0000-0000-000000000001",
        auth=AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_TEST_SECRET",  # pragma: allowlist secret
        ),
        tools={
            "securescore": ToolConfig(
                enabled=True,
                output_dir=output_dir,
            )
        },
    )


def _make_auth() -> AuthContext:
    return AuthContext(
        token=SecretStr("fake-token"),  # pragma: allowlist secret
        extra={"scope": "https://graph.microsoft.com/.default"},
        expires_at=utc_now() + timedelta(hours=1),
    )


def _make_profile_item() -> dict[str, Any]:
    return {
        "id": "MFAEnabled",
        "controlName": "MFA Enabled",
        "controlCategory": "Identity",
        "tier": "Defense in Depth",
        "userImpact": "Low",
        "implementationCost": "Low",
        "threats": [],
        "deprecated": False,
        "remediationImpact": "High",
        "title": "Require MFA for all users",
    }


def _make_score_item() -> dict[str, Any]:
    return {
        "id": "score-1",
        "activeUserCount": 10,
        "averageComparativeScores": [],
        "azureTenantId": "00000000-0000-0000-0000-000000000001",
        "controlScores": [
            {
                "controlName": "MFAEnabled",
                "score": 0.0,
                "total": 20.0,
                "on": False,
                "description": "MFA not configured",
            }
        ],
        "currentScore": 50.0,
        "enabledServices": [],
        "licensedUserCount": 10,
        "maxScore": 100.0,
    }


class TestSecureScoreCollectParity:
    """Verify that the refactored collect() produces the expected CollectionOutput."""

    def test_collect_returns_expected_output(self, tmp_path: Path) -> None:
        adapter = SecureScoreAdapter()
        config = _make_config(str(tmp_path))
        auth = _make_auth()

        profiles_response = [_make_profile_item()]
        scores_response = [_make_score_item()]

        with patch(
            "gxassessms.adapters.secure_score.adapter.fetch_paginated_json",
            side_effect=[profiles_response, scores_response],
        ):
            result = adapter.collect(config, auth)

        assert result.tool == ToolSource.SECURE_SCORE
        assert result.tool_slug == "secure-score"
        assert len(result.artifacts) == 2

        # Both artifacts must start with the slug
        for artifact in result.artifacts:
            assert artifact.target_relpath.startswith("secure-score/")
            assert len(artifact.sha256) == 64
            assert all(c in "0123456789abcdef" for c in artifact.sha256)

        # Verify expected filenames
        relpaths = {a.target_relpath for a in result.artifacts}
        assert "secure-score/secureScoreControlProfiles.json" in relpaths
        assert "secure-score/secureScores.json" in relpaths

        # Verify execution_metadata keys
        assert "profiles_count" in result.execution_metadata
        assert "scores_count" in result.execution_metadata
        assert result.execution_metadata["profiles_count"] == 1
        assert result.execution_metadata["scores_count"] == 1
