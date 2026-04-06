"""Shared HTTP helpers for API-based adapters (Azure Advisor, SecureScore, etc.).

Provides prerequisite checking, auth validation, and paginated JSON fetching
so each HTTP adapter doesn't duplicate ~80 lines of boilerplate.
"""

from __future__ import annotations

import importlib
from typing import Any, cast
from urllib.parse import urlparse

from gxassessms.core.config.datetime_utils import utc_now
from gxassessms.core.contracts.errors import CollectionError
from gxassessms.core.contracts.types import PrerequisiteResult
from gxassessms.core.domain.models import AuthContext


def check_python_packages(
    packages: list[tuple[str, str]],
    adapter_name: str,
) -> PrerequisiteResult:
    """Check that required Python packages are importable.

    Each entry in *packages* is ``(import_path, pip_name)`` -- e.g.,
    ``("httpx", "httpx")`` or ``("azure.identity", "azure-identity")``.
    Import names and pip package names differ for azure packages.
    """
    if not packages:
        return PrerequisiteResult(satisfied=True, message="No packages to check")

    missing: list[str] = []
    for import_path, pip_name in packages:
        try:
            importlib.import_module(import_path)
        except ImportError:
            missing.append(pip_name)

    if missing:
        install_cmd = " ".join(missing)
        return PrerequisiteResult(
            satisfied=False,
            message=f"{adapter_name}: missing packages -- pip install {install_cmd}",
        )

    return PrerequisiteResult(satisfied=True, message=f"{adapter_name}: all packages available")


def validate_auth_context(auth: AuthContext | None, adapter_name: str) -> None:
    """Validate auth context before making API calls.

    Raises CollectionError if auth is missing, token is missing, or token
    has expired.
    """
    if auth is None:
        raise CollectionError(
            f"{adapter_name}: no auth context provided",
            adapter_name=adapter_name,
        )

    if auth.token is None:
        raise CollectionError(
            f"{adapter_name}: auth context has no token",
            adapter_name=adapter_name,
        )

    if auth.expires_at is not None and auth.expires_at <= utc_now():
        raise CollectionError(
            f"{adapter_name}: auth token has expired",
            adapter_name=adapter_name,
        )


def fetch_paginated_json(
    *,
    url: str,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
    pagination_key: str = "@odata.nextLink",
    max_pages: int = 100,
    timeout: int = 120,
    label: str = "",
    adapter_name: str = "",
) -> list[dict[str, Any]]:
    """Fetch paginated JSON from a Microsoft Graph / ARM API endpoint.

    Returns a flat list of all items across all pages.  Raises
    ``CollectionError`` on HTTP errors, timeouts, or malformed responses.
    """
    import httpx  # function-scoped: heavy third-party dep

    initial_origin = urlparse(url)
    # Normalize scheme + netloc to lowercase for case-insensitive comparison
    # (RFC 3986: scheme and host are case-insensitive)
    origin = (initial_origin.scheme.lower(), initial_origin.netloc.lower())

    all_items: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    current_url: str | None = url
    page = 0

    try:
        with httpx.Client(timeout=timeout) as client:
            while current_url is not None and page < max_pages:
                if current_url in seen_urls:
                    raise CollectionError(
                        f"{adapter_name}: pagination cycle detected at {label} page {page}",
                        adapter_name=adapter_name,
                    )
                seen_urls.add(current_url)

                request_params = params if page == 0 else None
                response = client.get(current_url, headers=headers, params=request_params)
                response.raise_for_status()

                data = response.json()

                if not isinstance(data, dict):
                    raise CollectionError(
                        f"{adapter_name}: expected JSON object at {label} page {page}, "
                        f"got {type(data).__name__}",
                        adapter_name=adapter_name,
                    )

                body = cast(dict[str, Any], data)

                if "value" not in body or not isinstance(body["value"], list):
                    raise CollectionError(
                        f"{adapter_name}: missing or invalid 'value' array at {label} page {page}",
                        adapter_name=adapter_name,
                    )

                items = cast(list[Any], body["value"])
                if items and not all(isinstance(item, dict) for item in items):
                    raise CollectionError(
                        f"{adapter_name}: 'value' contains non-object items at {label} page {page}",
                        adapter_name=adapter_name,
                    )

                all_items.extend(cast(list[dict[str, Any]], items))
                page += 1

                next_link: Any = body.get(pagination_key)
                if next_link is None:
                    current_url = None
                elif not isinstance(next_link, str):
                    raise CollectionError(
                        f"{adapter_name}: {pagination_key} is not a string at {label} page {page}",
                        adapter_name=adapter_name,
                    )
                else:
                    parsed = urlparse(next_link)
                    if (parsed.scheme.lower(), parsed.netloc.lower()) != origin:
                        raise CollectionError(
                            f"{adapter_name}: cross-origin pagination link rejected"
                            f" at {label} page {page}",
                            adapter_name=adapter_name,
                        )
                    current_url = next_link

    except httpx.TimeoutException as exc:
        raise CollectionError(
            f"{adapter_name}: request timeout at {label} page {page}",
            adapter_name=adapter_name,
        ) from exc
    except httpx.HTTPStatusError as exc:
        snippet = exc.response.text[:500] if exc.response.text else ""
        raise CollectionError(
            f"{adapter_name}: HTTP {exc.response.status_code} at {label} page {page}: {snippet}",
            adapter_name=adapter_name,
        ) from exc
    except CollectionError:
        raise
    except ValueError as exc:
        raise CollectionError(
            f"{adapter_name}: invalid JSON at {label} page {page}: {exc}",
            adapter_name=adapter_name,
        ) from exc
    except httpx.RequestError as exc:
        raise CollectionError(
            f"{adapter_name}: request failed at {label} page {page}: {exc}",
            adapter_name=adapter_name,
        ) from exc

    if page >= max_pages and current_url is not None:
        raise CollectionError(
            f"{adapter_name}: exceeded {max_pages} pages at {label}",
            adapter_name=adapter_name,
        )

    return all_items
