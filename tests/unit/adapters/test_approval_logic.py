"""Parametric tests for the module provenance approval decision matrix.

Covers spec Section 4.2 + ambiguity rules.
"""

from __future__ import annotations

import pytest

from gxassessms.core.contracts.verification import (
    CandidateOutcome,
    ModulePolicy,
    SignerIdentity,
)


def _policy(fallback: bool = True) -> ModulePolicy:
    return ModulePolicy(
        module_name="TestModule",
        version_range=">=1.0.0,<2.0.0",
        allowed_signers=frozenset({SignerIdentity(subject="CN=Good", issuer="CN=Root")}),
        approved_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64}),
        allow_package_hash_fallback=fallback,
    )


def _candidate(
    *,
    provenance_approved: bool = True,
    execution_supported: bool = True,
    evidence_path: str | None = "hash_only",
    version: str = "1.0.0",
    rejection_reasons: tuple[str, ...] = (),
    hash_approved: bool = True,
    package_hash: str | None = "sha256tree:v1:" + "a" * 64,
) -> CandidateOutcome:
    return CandidateOutcome(
        version=version,
        live_manifest_path="/live/TestModule.psd1",
        live_module_root="/live/TestModule",
        staged_manifest_path="/staged/TestModule.psd1",
        staged_module_root="/staged/TestModule",
        provenance_approved=provenance_approved,
        execution_supported=execution_supported,
        rejection_reasons=rejection_reasons,
        package_hash=package_hash,
        hash_approved=hash_approved,
        evidence_path=evidence_path,
    )


class TestApplyApprovalLogic:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import apply_approval_logic

        self.apply_approval_logic = apply_approval_logic

    def test_single_approved_executable(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate()],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is True
        assert result.execution_supported is True
        assert result.can_execute is True
        assert result.approved_candidate is not None

    def test_single_approved_not_executable(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate(execution_supported=False)],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is True
        assert result.execution_supported is False
        assert result.can_execute is False
        assert result.approved_candidate is not None

    def test_ambiguity_two_executable(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate(version="1.0.0"), _candidate(version="1.1.0")],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert "ambiguity" in result.rejection_reasons

    def test_zero_provenance_approved(self) -> None:
        result = self.apply_approval_logic(
            candidates=[
                _candidate(
                    provenance_approved=False,
                    rejection_reasons=("hash_rejected",),
                    evidence_path=None,
                )
            ],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert result.approved_candidate is None

    def test_no_candidates(self) -> None:
        result = self.apply_approval_logic(
            candidates=[],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert result.can_execute is False

    def test_signature_and_hash_evidence(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate(evidence_path="signature_and_hash")],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.evidence_path == "signature_and_hash"

    def test_multiple_provenance_approved_none_executable(self) -> None:
        """Multiple provenance-approved but none executable -> provenance ambiguity."""
        result = self.apply_approval_logic(
            candidates=[
                _candidate(version="1.0.0", execution_supported=False),
                _candidate(version="1.1.0", execution_supported=False),
            ],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert "ambiguity" in result.rejection_reasons

    def test_one_provenance_approved_not_executable(self) -> None:
        """Single provenance-approved but not executable -> approved, not executable."""
        result = self.apply_approval_logic(
            candidates=[_candidate(execution_supported=False)],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is True
        assert result.execution_supported is False
        assert result.approved_candidate is not None

    def test_required_modules_logged_passed_through(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate()],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=("Microsoft.Graph.Authentication", "Pester"),
        )
        assert result.required_modules_logged == (
            "Microsoft.Graph.Authentication",
            "Pester",
        )
