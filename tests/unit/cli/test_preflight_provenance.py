"""Tests for preflight provenance rendering."""

from __future__ import annotations

from gxassessms.cli.preflight_types import PreflightCheckResult


class TestPreflightCheckResult:
    def test_pass_without_provenance(self) -> None:
        r = PreflightCheckResult(
            check="Config validation",
            status="PASS",
            message="OK",
        )
        assert r.provenance is None
        assert r.status == "PASS"

    def test_pass_with_provenance(self) -> None:
        from gxassessms.core.contracts.verification import (
            CandidateOutcome,
            ModuleVerificationResult,
        )

        result = ModuleVerificationResult(
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
        r = PreflightCheckResult(
            check="ScubaGear provenance",
            status="PASS",
            message="v1.5.2 verified (hash_only)",
            provenance=result,
        )
        assert r.provenance is not None
        assert r.provenance.can_execute is True
