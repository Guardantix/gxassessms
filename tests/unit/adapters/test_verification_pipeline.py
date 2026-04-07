"""Tests for verify_module, check_module_prerequisites, and _log_provenance."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any, Literal
from unittest.mock import MagicMock, patch

import pytest

from gxassessms.adapters._verification import (
    _log_provenance,
    check_module_prerequisites,
    verify_module,
)
from gxassessms.core.contracts.errors import (
    CollectionError,
    ModuleAmbiguityError,
    ModuleExecutionUnsupportedError,
    ModuleProvenanceError,
    VerificationInfrastructureError,
)
from gxassessms.core.contracts.verification import (
    CandidateOutcome,
    ModuleVerificationResult,
)
from tests.unit.adapters.conftest import make_test_policy


def _candidate(
    *,
    version: str = "1.5.0",
    provenance_approved: bool = True,
    execution_supported: bool = True,
    package_hash: str = "sha256tree:v1:" + "a" * 64,
    staged_signature_status: str | None = "platform_unsupported",
    evidence_path: Literal["signature_and_hash", "hash_only"] | None = "hash_only",
) -> CandidateOutcome:
    return CandidateOutcome(
        version=version,
        live_manifest_path="/live/TestModule.psd1",
        live_module_root="/live/TestModule",
        staged_manifest_path="/staged/TestModule.psd1",
        staged_module_root="/staged/TestModule",
        provenance_approved=provenance_approved,
        execution_supported=execution_supported,
        package_hash=package_hash,
        hash_approved=True,
        staged_signature_status=staged_signature_status,
        evidence_path=evidence_path,
    )


def _result(
    *,
    provenance_approved: bool = True,
    execution_supported: bool = True,
    evidence_path: Literal["signature_and_hash", "hash_only"] | None = "hash_only",
    rejection_reasons: tuple[str, ...] = (),
    approved_candidate: CandidateOutcome | None = None,
    candidates: tuple[CandidateOutcome, ...] = (),
) -> ModuleVerificationResult:
    if approved_candidate is None and provenance_approved:
        approved_candidate = _candidate()
    return ModuleVerificationResult(
        module_name="TestModule",
        provenance_approved=provenance_approved,
        execution_supported=execution_supported,
        evidence_path=evidence_path,
        rejection_reasons=rejection_reasons,
        approved_candidate=approved_candidate,
        candidates=candidates,
        required_modules_logged=(),
        powershell_executable="pwsh",
    )


# -- Patch targets live in the _verification module's namespace --
_MOD = "gxassessms.adapters._verification"


class TestVerifyModule:
    """Tests for verify_module -- the main pipeline function."""

    @pytest.fixture(autouse=True)
    def _patch_infra(self, tmp_path: Path) -> None:
        """Patch subprocess, tempfile, PS executable, and report parser."""
        self.tmp_dir = tmp_path / "gxassessms_verify_test"
        self.tmp_dir.mkdir()

        self.mock_proc = MagicMock(spec=subprocess.CompletedProcess)
        self.mock_proc.returncode = 0
        self.mock_proc.stderr = b""

        self.good_result = _result()

        patchers = [
            patch(f"{_MOD}.get_powershell_executable", return_value="pwsh"),
            patch(f"{_MOD}.tempfile.mkdtemp", return_value=str(self.tmp_dir)),
            patch(f"{_MOD}.subprocess.run", return_value=self.mock_proc),
            patch(f"{_MOD}.parse_verification_report", return_value=self.good_result),
            patch(f"{_MOD}.shutil.rmtree"),
        ]
        self.mocks: dict[str, Any] = {}
        for p in patchers:
            mock = p.start()
            self.mocks[p.attribute] = mock

        yield

        for p in patchers:
            p.stop()

    def test_happy_path_preflight(self) -> None:
        result = verify_module(policy=make_test_policy(), mode="preflight", adapter_name="test")
        assert result.provenance_approved is True
        assert result.execution_supported is True

    def test_happy_path_collection(self) -> None:
        invocation = {"command_name": "Invoke-SCuBA", "named_args": {}, "switches": {}}
        result = verify_module(
            policy=make_test_policy(),
            mode="collection",
            post_import_invocation=invocation,
            adapter_name="test",
        )
        assert result is self.good_result

    def test_subprocess_timeout_raises_infrastructure_error(self) -> None:
        self.mocks["run"].side_effect = subprocess.TimeoutExpired(cmd="pwsh", timeout=120)
        with pytest.raises(VerificationInfrastructureError, match="timed out"):
            verify_module(policy=make_test_policy(), adapter_name="test", timeout_seconds=120)
        assert self.mocks["run"].call_args[1]["timeout"] == 120

    def test_oserror_raises_infrastructure_error(self) -> None:
        self.mocks["run"].side_effect = OSError("No such file")
        with pytest.raises(VerificationInfrastructureError, match="PowerShell not accessible"):
            verify_module(policy=make_test_policy(), adapter_name="test")

    def test_missing_report_raises_infrastructure_error(self) -> None:
        self.mocks["parse_verification_report"].side_effect = VerificationInfrastructureError(
            "Missing report"
        )
        self.mock_proc.returncode = 1
        self.mock_proc.stderr = b"something failed"
        with pytest.raises(VerificationInfrastructureError, match="missing or unreadable"):
            verify_module(policy=make_test_policy(), adapter_name="test")

    def test_provenance_rejected_raises_provenance_error(self) -> None:
        self.mocks["parse_verification_report"].return_value = _result(
            provenance_approved=False,
            execution_supported=True,
            evidence_path=None,
            rejection_reasons=("hash_rejected",),
            approved_candidate=None,
        )
        with pytest.raises(ModuleProvenanceError, match="failed provenance"):
            verify_module(policy=make_test_policy(), adapter_name="test")

    def test_ambiguity_rejection_raises_ambiguity_error(self) -> None:
        self.mocks["parse_verification_report"].return_value = _result(
            provenance_approved=False,
            execution_supported=True,
            evidence_path=None,
            rejection_reasons=("ambiguity",),
            approved_candidate=None,
        )
        with pytest.raises(ModuleAmbiguityError, match="Multiple candidates"):
            verify_module(policy=make_test_policy(), adapter_name="test")

    def test_execution_unsupported_raises(self) -> None:
        self.mocks["parse_verification_report"].return_value = _result(
            provenance_approved=True,
            execution_supported=False,
        )
        with pytest.raises(ModuleExecutionUnsupportedError, match="cannot execute"):
            verify_module(policy=make_test_policy(), adapter_name="test")

    def test_nonzero_exit_in_collection_raises_collection_error(self) -> None:
        self.mock_proc.returncode = 1
        self.mock_proc.stderr = b"tool crash"
        with pytest.raises(CollectionError, match="exited with code 1"):
            verify_module(policy=make_test_policy(), mode="collection", adapter_name="test")

    def test_nonzero_exit_in_preflight_does_not_raise(self) -> None:
        """Preflight only cares about provenance, not tool exit code."""
        self.mock_proc.returncode = 1
        result = verify_module(policy=make_test_policy(), mode="preflight", adapter_name="test")
        assert result.provenance_approved is True

    def test_temp_dir_cleaned_up_on_success(self) -> None:
        verify_module(policy=make_test_policy(), adapter_name="test")
        self.mocks["rmtree"].assert_called_once()
        call_args = self.mocks["rmtree"].call_args
        assert Path(call_args[0][0]) == self.tmp_dir

    def test_temp_dir_cleaned_up_on_error(self) -> None:
        self.mocks["run"].side_effect = subprocess.TimeoutExpired(cmd="pwsh", timeout=60)
        with pytest.raises(VerificationInfrastructureError):
            verify_module(policy=make_test_policy(), adapter_name="test")
        self.mocks["rmtree"].assert_called_once()

    def test_stderr_truncated_to_500_chars(self) -> None:
        """Long stderr is truncated before being attached to errors."""
        long_stderr = b"x" * 1000
        self.mock_proc.stderr = long_stderr
        self.mocks["parse_verification_report"].side_effect = VerificationInfrastructureError(
            "Missing report"
        )
        self.mock_proc.returncode = 1
        with pytest.raises(VerificationInfrastructureError) as exc_info:
            verify_module(policy=make_test_policy(), adapter_name="test")
        assert exc_info.value.stderr_snippet is not None
        assert len(exc_info.value.stderr_snippet) <= 500

    def test_subprocess_command_structure(self) -> None:
        """Verify the subprocess command uses -File, -InputPath, etc."""
        verify_module(policy=make_test_policy(), adapter_name="test")
        call_args = self.mocks["run"].call_args
        cmd = call_args[0][0]
        assert cmd[0] == "pwsh"
        assert "-NoProfile" in cmd
        assert "-NonInteractive" in cmd
        assert "-File" in cmd
        assert "-InputPath" in cmd
        assert "-ReportPath" in cmd
        assert "-StagingDir" in cmd
        assert call_args[1]["shell"] is False
        assert call_args[1]["capture_output"] is True


class TestCheckModulePrerequisites:
    """Tests for check_module_prerequisites -- thin wrapper over verify_module."""

    @patch(f"{_MOD}.verify_module")
    def test_success_returns_satisfied(self, mock_verify: MagicMock) -> None:
        mock_verify.return_value = _result()
        result = check_module_prerequisites(policy=make_test_policy(), tool_name="ScubaGear")
        assert result["satisfied"] is True
        assert "1.5.0" in result["message"]

    @patch(f"{_MOD}.verify_module")
    def test_success_no_candidate_shows_question_mark(self, mock_verify: MagicMock) -> None:
        mock_verify.return_value = ModuleVerificationResult(
            module_name="TestModule",
            provenance_approved=True,
            execution_supported=True,
            evidence_path="hash_only",
            rejection_reasons=(),
            approved_candidate=None,
            candidates=(),
            required_modules_logged=(),
            powershell_executable="pwsh",
        )
        result = check_module_prerequisites(policy=make_test_policy(), tool_name="ScubaGear")
        assert result["satisfied"] is True
        assert "?" in result["message"]

    @patch(f"{_MOD}.verify_module")
    def test_verification_error_returns_unsatisfied(self, mock_verify: MagicMock) -> None:
        mock_verify.side_effect = ModuleProvenanceError("bad hash", adapter_name="test")
        result = check_module_prerequisites(policy=make_test_policy(), tool_name="ScubaGear")
        assert result["satisfied"] is False
        assert "bad hash" in result["message"]

    @patch(f"{_MOD}.verify_module")
    def test_oserror_returns_unsatisfied(self, mock_verify: MagicMock) -> None:
        mock_verify.side_effect = OSError("pwsh not found")
        result = check_module_prerequisites(policy=make_test_policy(), tool_name="ScubaGear")
        assert result["satisfied"] is False
        assert "pwsh not found" in result["message"]

    @patch(f"{_MOD}.verify_module")
    def test_passes_timeout(self, mock_verify: MagicMock) -> None:
        mock_verify.return_value = _result()
        check_module_prerequisites(policy=make_test_policy(), tool_name="test", timeout_seconds=30)
        mock_verify.assert_called_once()
        assert mock_verify.call_args[1]["timeout_seconds"] == 30


class TestLogProvenance:
    """Tests for _log_provenance -- structured logging of verification outcomes."""

    def test_approved_and_supported_logs_info(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.DEBUG):
            _log_provenance(_result(), "test-adapter")
        assert any("APPROVED" in r.message and "SUPPORTED" in r.message for r in caplog.records)
        info_records = [r for r in caplog.records if "APPROVED" in r.message]
        assert info_records[0].levelno == logging.INFO

    def test_hash_only_degraded_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """hash_only with a non-None/non-platform_unsupported sig status is degraded."""
        candidate = _candidate(
            staged_signature_status="invalid_signature",
            evidence_path="hash_only",
        )
        result = _result(evidence_path="hash_only", approved_candidate=candidate)
        with caplog.at_level(logging.DEBUG):
            _log_provenance(result, "test-adapter")
        warn_records = [r for r in caplog.records if "degraded" in r.message]
        assert len(warn_records) == 1
        assert warn_records[0].levelno == logging.WARNING

    @pytest.mark.parametrize("sig_status", ["platform_unsupported", None])
    def test_hash_only_expected_sig_status_not_degraded(
        self, sig_status: str | None, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Expected sig statuses (platform_unsupported, None) stay at INFO."""
        candidate = _candidate(staged_signature_status=sig_status, evidence_path="hash_only")
        result = _result(evidence_path="hash_only", approved_candidate=candidate)
        with caplog.at_level(logging.DEBUG):
            _log_provenance(result, "test-adapter")
        records = [r for r in caplog.records if "APPROVED" in r.message]
        assert records[0].levelno == logging.INFO

    def test_approved_but_unsupported_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        result = _result(provenance_approved=True, execution_supported=False)
        with caplog.at_level(logging.DEBUG):
            _log_provenance(result, "test-adapter")
        records = [r for r in caplog.records if "UNSUPPORTED" in r.message]
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING

    def test_rejected_logs_error(self, caplog: pytest.LogCaptureFixture) -> None:
        result = _result(
            provenance_approved=False,
            execution_supported=True,
            evidence_path=None,
            rejection_reasons=("hash_rejected", "version_mismatch"),
            approved_candidate=None,
        )
        with caplog.at_level(logging.DEBUG):
            _log_provenance(result, "test-adapter")
        records = [r for r in caplog.records if "REJECTED" in r.message]
        assert len(records) == 1
        assert records[0].levelno == logging.ERROR
        assert "hash_rejected" in records[0].message

    def test_uses_module_name_when_no_adapter_name(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.DEBUG):
            _log_provenance(_result(), "")
        records = [r for r in caplog.records if "APPROVED" in r.message]
        assert "TestModule" in records[0].message

    def test_no_candidate_approved_unsupported_shows_question_mark(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When approved_candidate is None, version shows as '?'."""
        result = ModuleVerificationResult(
            module_name="TestModule",
            provenance_approved=True,
            execution_supported=False,
            evidence_path=None,
            rejection_reasons=(),
            approved_candidate=None,
            candidates=(),
            required_modules_logged=(),
            powershell_executable="pwsh",
        )
        with caplog.at_level(logging.DEBUG):
            _log_provenance(result, "test")
        records = [r for r in caplog.records if "UNSUPPORTED" in r.message]
        assert "version=?" in records[0].message
