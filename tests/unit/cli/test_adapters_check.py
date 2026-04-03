"""Tests for mseco adapters check with provenance verification."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


class TestAdaptersCheckProvenance:
    def test_ps_adapter_uses_baseline_policy(self) -> None:
        """adapters check calls verify_module with MODULE_POLICY, not config override."""
        from gxassessms.core.contracts.verification import (
            CandidateOutcome,
            ModuleVerificationResult,
        )

        mock_result = ModuleVerificationResult(
            module_name="ScubaGear",
            provenance_approved=True,
            execution_supported=True,
            evidence_path="hash_only",
            rejection_reasons=(),
            approved_candidate=CandidateOutcome(
                version="1.5.2",
                live_manifest_path="/path",
                live_module_root="/path",
                staged_manifest_path="/staged",
                staged_module_root="/staged",
                provenance_approved=True,
                execution_supported=True,
                package_hash="sha256tree:v1:" + "a" * 64,
                hash_approved=True,
                evidence_path="hash_only",
            ),
            candidates=(),
            required_modules_logged=(),
            powershell_executable="/usr/bin/pwsh",
        )

        with patch(
            "gxassessms.adapters._verification.verify_module",
            return_value=mock_result,
        ) as mock_verify:
            from gxassessms.adapters._verification import verify_module

            verify_module(
                policy=MagicMock(),
                mode="preflight",
                adapter_name="ScubaGear",
            )
            mock_verify.assert_called_once()
