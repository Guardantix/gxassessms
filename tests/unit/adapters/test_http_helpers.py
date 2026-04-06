"""Tests for shared HTTP adapter helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr

from gxassessms.adapters._http import (
    check_python_packages,
    fetch_paginated_json,
    validate_auth_context,
)
from gxassessms.core.contracts.errors import CollectionError
from gxassessms.core.domain.models import AuthContext

# ---------------------------------------------------------------------------
# check_python_packages
# ---------------------------------------------------------------------------


class TestCheckPythonPackages:
    def test_all_present(self) -> None:
        result = check_python_packages([("json", "json"), ("os", "os")], "test-adapter")
        assert result["satisfied"] is True

    def test_one_missing(self) -> None:
        result = check_python_packages(
            [("json", "json"), ("nonexistent_pkg_xyz", "nonexistent-pkg-xyz")],
            "test-adapter",
        )
        assert result["satisfied"] is False
        assert "nonexistent-pkg-xyz" in result["message"]

    def test_empty_list(self) -> None:
        result = check_python_packages([], "test-adapter")
        assert result["satisfied"] is True

    def test_pip_name_in_message(self) -> None:
        result = check_python_packages([("azure.identity", "azure-identity")], "test-adapter")
        # azure.identity is not installed in test env
        if not result["satisfied"]:
            assert "azure-identity" in result["message"]
            assert "pip install" in result["message"]


# ---------------------------------------------------------------------------
# validate_auth_context
# ---------------------------------------------------------------------------


class TestValidateAuthContext:
    def test_none_auth_raises(self) -> None:
        with pytest.raises(CollectionError, match="no auth context"):
            validate_auth_context(None, "test-adapter")

    def test_none_token_raises(self) -> None:
        auth = AuthContext(token=None)
        with pytest.raises(CollectionError, match="no token"):
            validate_auth_context(auth, "test-adapter")

    def test_expired_token_raises(self) -> None:
        auth = AuthContext(
            token=SecretStr("tok"),
            expires_at=datetime(2020, 1, 1, tzinfo=UTC),
        )
        with pytest.raises(CollectionError, match="expired"):
            validate_auth_context(auth, "test-adapter")

    def test_valid_auth_passes(self) -> None:
        auth = AuthContext(
            token=SecretStr("tok"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        validate_auth_context(auth, "test-adapter")  # should not raise

    def test_no_expiry_passes(self) -> None:
        auth = AuthContext(token=SecretStr("tok"), expires_at=None)
        validate_auth_context(auth, "test-adapter")  # should not raise


# ---------------------------------------------------------------------------
# fetch_paginated_json
# ---------------------------------------------------------------------------


def _mock_response(
    data: dict[str, Any],
    status_code: int = 200,
) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = data
    resp.text = ""
    resp.raise_for_status.return_value = None
    return resp


def _mock_error_response(status_code: int, body: str = "") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = body
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        message=f"HTTP {status_code}",
        request=MagicMock(),
        response=resp,
    )
    return resp


def _make_client(**kwargs: Any) -> MagicMock:
    """Build a mock httpx.Client context manager."""
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    for attr, value in kwargs.items():
        setattr(client, attr, value)
    return client


_GRAPH_URL = "https://graph.microsoft.com/v1.0/test"


class TestFetchPaginatedJson:
    def test_single_page(self) -> None:
        resp = _mock_response({"value": [{"id": 1}, {"id": 2}]})
        client = _make_client(get=MagicMock(return_value=resp))

        with patch("httpx.Client", return_value=client):
            items = fetch_paginated_json(
                url=_GRAPH_URL,
                headers={"Authorization": "Bearer tok"},
                adapter_name="test",
            )

        assert items == [{"id": 1}, {"id": 2}]

    def test_multi_page(self) -> None:
        page1 = _mock_response(
            {
                "value": [{"id": 1}],
                "@odata.nextLink": f"{_GRAPH_URL}?page=2",
            }
        )
        page2 = _mock_response({"value": [{"id": 2}]})

        client = _make_client(get=MagicMock(side_effect=[page1, page2]))

        with patch("httpx.Client", return_value=client):
            items = fetch_paginated_json(
                url=_GRAPH_URL,
                headers={"Authorization": "Bearer tok"},
                adapter_name="test",
            )

        assert len(items) == 2
        assert items[0]["id"] == 1
        assert items[1]["id"] == 2

    def test_arm_pagination_key(self) -> None:
        arm_url = "https://management.azure.com/sub"
        page1 = _mock_response(
            {
                "value": [{"id": 1}],
                "nextLink": f"{arm_url}?page=2",
            }
        )
        page2 = _mock_response({"value": [{"id": 2}]})

        client = _make_client(get=MagicMock(side_effect=[page1, page2]))

        with patch("httpx.Client", return_value=client):
            items = fetch_paginated_json(
                url=arm_url,
                headers={},
                pagination_key="nextLink",
                adapter_name="test",
            )

        assert len(items) == 2

    def test_max_pages_exceeded(self) -> None:
        def make_page(n: int) -> MagicMock:
            return _mock_response(
                {
                    "value": [{"id": n}],
                    "@odata.nextLink": f"{_GRAPH_URL}?page={n + 1}",
                }
            )

        client = _make_client(get=MagicMock(side_effect=[make_page(i) for i in range(5)]))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match="exceeded 3 pages"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                max_pages=3,
                adapter_name="test",
            )

    def test_cycle_detection(self) -> None:
        page1 = _mock_response(
            {
                "value": [{"id": 1}],
                "@odata.nextLink": _GRAPH_URL,
            }
        )

        client = _make_client(get=MagicMock(return_value=page1))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match="cycle"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

    def test_non_dict_response_raises(self) -> None:
        resp = MagicMock(spec=httpx.Response)
        resp.json.return_value = [1, 2, 3]
        resp.raise_for_status.return_value = None

        client = _make_client(get=MagicMock(return_value=resp))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match="expected JSON object"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

    def test_missing_value_key_raises(self) -> None:
        resp = _mock_response({"items": [{"id": 1}]})
        client = _make_client(get=MagicMock(return_value=resp))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match=r"missing or invalid.*value"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

    def test_http_error_raises(self) -> None:
        resp = _mock_error_response(403, "Forbidden")
        client = _make_client(get=MagicMock(return_value=resp))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match="HTTP 403"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

    def test_timeout_raises(self) -> None:
        client = _make_client(get=MagicMock(side_effect=httpx.ReadTimeout("timed out")))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match="timeout"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

    def test_params_first_request_only(self) -> None:
        page1 = _mock_response(
            {
                "value": [{"id": 1}],
                "@odata.nextLink": f"{_GRAPH_URL}?page=2",
            }
        )
        page2 = _mock_response({"value": [{"id": 2}]})

        client = _make_client(get=MagicMock(side_effect=[page1, page2]))

        with patch("httpx.Client", return_value=client):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={"Authorization": "Bearer tok"},
                params={"$top": "100"},
                adapter_name="test",
            )

        call_args = client.get.call_args_list
        assert call_args[0].kwargs.get("params") == {"$top": "100"}
        assert call_args[1].kwargs.get("params") is None

    def test_cross_origin_next_link_rejected(self) -> None:
        page1 = _mock_response(
            {
                "value": [{"id": 1}],
                "@odata.nextLink": "https://evil.example.com/steal?data=1",
            }
        )

        client = _make_client(get=MagicMock(return_value=page1))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match="cross-origin"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

    def test_non_string_next_link_rejected(self) -> None:
        page1 = _mock_response(
            {
                "value": [{"id": 1}],
                "@odata.nextLink": 12345,
            }
        )

        client = _make_client(get=MagicMock(return_value=page1))

        with (
            patch("httpx.Client", return_value=client),
            pytest.raises(CollectionError, match="not a string"),
        ):
            fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

    def test_empty_value_list_continues_pagination(self) -> None:
        page1 = _mock_response(
            {
                "value": [],
                "@odata.nextLink": f"{_GRAPH_URL}?page=2",
            }
        )
        page2 = _mock_response({"value": [{"id": 1}]})

        client = _make_client(get=MagicMock(side_effect=[page1, page2]))

        with patch("httpx.Client", return_value=client):
            items = fetch_paginated_json(
                url=_GRAPH_URL,
                headers={},
                adapter_name="test",
            )

        assert items == [{"id": 1}]
