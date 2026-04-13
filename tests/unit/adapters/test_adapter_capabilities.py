# tests/unit/adapters/test_adapter_capabilities.py
"""Negative tests: Monkey365 and M365-Assess do not support ingest."""

from __future__ import annotations

from gxassessms.adapters.m365_assess.adapter import M365AssessAdapter
from gxassessms.adapters.monkey365.adapter import Monkey365Adapter


def test_monkey365_has_no_ingest_capability() -> None:
    adapter = Monkey365Adapter()
    assert "ingest" not in adapter.capabilities
    assert not hasattr(adapter, "ingest_from_directory")


def test_m365_assess_has_no_ingest_capability() -> None:
    adapter = M365AssessAdapter()
    assert "ingest" not in adapter.capabilities
    assert not hasattr(adapter, "ingest_from_directory")
