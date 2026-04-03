"""Tests for verification report JSON parsing."""

from __future__ import annotations

import json

import pytest


class TestParseVerificationReport:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import parse_verification_report

        self.parse_verification_report = parse_verification_report

    def _valid_report(self) -> dict:
        return {
            "module_name": "TestModule",
            "provenance_approved": True,
            "execution_supported": True,
            "evidence_path": "hash_only",
            "rejection_reasons": [],
            "powershell_executable": "/usr/bin/pwsh",
            "required_modules_logged": [],
            "approved_candidate": {
                "version": "1.0.0",
                "live_manifest_path": "/live/TestModule.psd1",
                "live_module_root": "/live/TestModule",
                "staged_manifest_path": "/staged/TestModule.psd1",
                "staged_module_root": "/staged/TestModule",
                "provenance_approved": True,
                "execution_supported": True,
                "rejection_reasons": [],
                "confinement_violation": None,
                "package_hash": "sha256tree:v1:" + "a" * 64,
                "hash_approved": True,
                "live_signature_status": "platform_unsupported",
                "live_signer_subject": None,
                "live_signer_issuer": None,
                "live_signer_thumbprint": None,
                "staged_signature_status": "platform_unsupported",
                "staged_signer_subject": None,
                "staged_signer_issuer": None,
                "staged_signer_thumbprint": None,
                "staged_signer_approved": None,
                "evidence_path": "hash_only",
            },
            "candidates": [],
        }

    def test_valid_report_parses(self, tmp_path) -> None:
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(self._valid_report()))

        result = self.parse_verification_report(report_path)
        assert result.module_name == "TestModule"
        assert result.provenance_approved is True
        assert result.can_execute is True

    def test_missing_report_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report_path = tmp_path / "missing.json"
        with pytest.raises(VerificationInfrastructureError, match="Missing"):
            self.parse_verification_report(report_path)

    def test_empty_report_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report_path = tmp_path / "empty.json"
        report_path.write_text("")
        with pytest.raises(VerificationInfrastructureError, match=r"[Ee]mpty"):
            self.parse_verification_report(report_path)

    def test_malformed_json_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report_path = tmp_path / "bad.json"
        report_path.write_text("{invalid")
        with pytest.raises(VerificationInfrastructureError, match=r"[Mm]alformed|JSON"):
            self.parse_verification_report(report_path)

    def test_missing_required_field_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report = self._valid_report()
        del report["module_name"]
        report_path = tmp_path / "bad.json"
        report_path.write_text(json.dumps(report))
        with pytest.raises(VerificationInfrastructureError):
            self.parse_verification_report(report_path)

    def test_candidate_with_rejection_reasons(self, tmp_path) -> None:
        report = self._valid_report()
        report["provenance_approved"] = False
        report["approved_candidate"] = None
        report["rejection_reasons"] = ["hash_rejected"]
        report["candidates"] = [
            {
                "version": "1.0.0",
                "live_manifest_path": "/live/TestModule.psd1",
                "live_module_root": "/live/TestModule",
                "staged_manifest_path": None,
                "staged_module_root": None,
                "provenance_approved": False,
                "execution_supported": True,
                "rejection_reasons": ["hash_rejected"],
                "confinement_violation": None,
                "package_hash": "sha256tree:v1:" + "b" * 64,
                "hash_approved": False,
                "live_signature_status": None,
                "live_signer_subject": None,
                "live_signer_issuer": None,
                "live_signer_thumbprint": None,
                "staged_signature_status": None,
                "staged_signer_subject": None,
                "staged_signer_issuer": None,
                "staged_signer_thumbprint": None,
                "staged_signer_approved": None,
                "evidence_path": None,
            }
        ]
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        result = self.parse_verification_report(report_path)
        assert result.provenance_approved is False
        assert len(result.candidates) == 1
        assert "hash_rejected" in result.candidates[0].rejection_reasons
