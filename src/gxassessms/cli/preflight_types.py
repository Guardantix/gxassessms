"""Preflight display types -- presentation layer DTOs.

Separates structured check results from the dict-based contract
previously used in preflight and adapters check commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from gxassessms.core.contracts.verification import ModuleVerificationResult


@dataclass
class PreflightCheckResult:
    """Single preflight check outcome for display."""

    check: str
    status: Literal["PASS", "WARN", "FAIL"]
    message: str
    provenance: ModuleVerificationResult | None = None
