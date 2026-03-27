"""TypedDicts for persistence layer I/O shapes."""

from __future__ import annotations

from typing import Any, TypedDict


class ExplanationResult(TypedDict):
    """Return shape for FindingExplanationService.explain()."""

    finding_instance_id: str
    sources: list[dict[str, Any]]
    severity_basis: dict[str, Any]
    dedup_history: list[dict[str, Any]]
    override_history: list[dict[str, Any]]
    ai_modifications: list[dict[str, Any]]
    confidence_basis: dict[str, Any]
