"""Tests for mseco adapters check with provenance verification."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from gxassessms.cli.commands.adapters import _try_ps_adapter_baseline_check
from gxassessms.core.contracts.verification import (
    CandidateOutcome,
    ModuleVerificationResult,
)


def _make_mock_result(
    *,
    approved: bool = True,
    execution_supported: bool = True,
    evidence_path: str = "hash_only",
    version: str = "1.5.2",
) -> ModuleVerificationResult:
    candidate = CandidateOutcome(
        version=version,
        live_manifest_path="/path",
        live_module_root="/path",
        staged_manifest_path="/staged",
        staged_module_root="/staged",
        provenance_approved=approved,
        execution_supported=execution_supported,
        package_hash="sha256tree:v1:" + "a" * 64,
        hash_approved=approved,
        evidence_path=evidence_path if approved else None,
    )
    return ModuleVerificationResult(
        module_name="ScubaGear",
        provenance_approved=approved,
        execution_supported=execution_supported,
        evidence_path=evidence_path if approved else None,
        rejection_reasons=() if approved else ("provenance_rejected",),
        approved_candidate=candidate if approved else None,
        candidates=(candidate,),
        required_modules_logged=(),
        powershell_executable="/usr/bin/pwsh",
    )


class TestAdaptersCheckProvenance:
    def test_ps_adapter_calls_verify_module_directly(self) -> None:
        """adapters check calls verify_module with MODULE_POLICY, not check_prerequisites."""
        mock_result = _make_mock_result()
        adapter = MagicMock()
        adapter.tool_name = "scubagear"

        with patch(
            "gxassessms.adapters._verification.verify_module",
            return_value=mock_result,
        ) as mock_verify:
            result = _try_ps_adapter_baseline_check(adapter)

        assert result is not None
        assert result["status"] == "PASS"
        assert "1.5.2" in result["message"]
        assert "hash_only" in result["message"]
        mock_verify.assert_called_once()
        # Verify no config override was passed
        call_kwargs = mock_verify.call_args.kwargs
        assert call_kwargs.get("override") is None or "override" not in call_kwargs

    def test_ps_adapter_rejected_returns_fail(self) -> None:
        """Provenance rejection yields FAIL status."""
        from gxassessms.core.contracts.errors import ModuleProvenanceError

        adapter = MagicMock()
        adapter.tool_name = "scubagear"

        with patch(
            "gxassessms.adapters._verification.verify_module",
            side_effect=ModuleProvenanceError("hash_rejected"),
        ):
            result = _try_ps_adapter_baseline_check(adapter)

        assert result is not None
        assert result["status"] == "FAIL"
        assert "hash_rejected" in result["message"]

    def test_non_ps_adapter_returns_none(self) -> None:
        """Adapter without MODULE_POLICY falls through to check_prerequisites."""
        adapter = MagicMock()
        adapter.tool_name = "custom_tool"

        result = _try_ps_adapter_baseline_check(adapter)
        assert result is None

    def test_no_config_override_applied(self) -> None:
        """adapters check uses baseline policy only -- no ModulePolicyOverride."""
        mock_result = _make_mock_result()
        adapter = MagicMock()
        adapter.tool_name = "scubagear"

        with patch(
            "gxassessms.adapters._verification.verify_module",
            return_value=mock_result,
        ) as mock_verify:
            _try_ps_adapter_baseline_check(adapter)

        call_kwargs = mock_verify.call_args.kwargs
        assert "override" not in call_kwargs or call_kwargs.get("override") is None
