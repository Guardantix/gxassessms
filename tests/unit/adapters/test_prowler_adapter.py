"""Tests for Prowler adapter -- prerequisites, collect, validation, coverage."""

from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from gxassessms.adapters.prowler.adapter import ProwlerAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.contracts.errors import CollectionError, RawOutputValidationError
from gxassessms.core.domain.constants import AuthMethod
from gxassessms.core.domain.enums import CoverageStatus, ToolSource
from gxassessms.core.domain.models import ArtifactRecord, ResolvedManifest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    auth_method: AuthMethod = "client_credential",
    extra_args: list[str] | None = None,
    output_dir: str = "/tmp/prowler-test",  # noqa: S108
) -> EngagementConfig:
    tc = ToolConfig(
        enabled=True,
        output_dir=output_dir,
        extra_args=extra_args or [],
    )
    return EngagementConfig(
        client_name="TestClient",
        tenant_id="00000000-0000-0000-0000-000000000000",
        auth=AuthConfig(
            method=auth_method,
            tenant_id="00000000-0000-0000-0000-000000000000",
            client_id="test-client-id",
        ),
        tools={"prowler": tc},
    )


def _make_manifest(tmp_path: Path, findings_json: str) -> ResolvedManifest:
    f = tmp_path / "prowler_output.ocsf.json"
    f.write_text(findings_json)
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    return ResolvedManifest(
        tool=ToolSource.PROWLER,
        tool_slug="prowler",
        schema_version="1.0.0",
        manifest_version="1.0.0",
        timestamp=datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC),
        file_manifest={str(f): ArtifactRecord(encoding="utf-8", sha256=sha)},
        execution_metadata={},
    )


def _minimal_finding(
    *,
    check_id: str = "test_check",
    status_code: str = "PASS",
    uid: str = "prowler-azure-test_check-sub1-res1",
) -> dict[str, Any]:
    return {
        "finding_info": {"uid": uid, "title": "Test", "desc": "Desc", "types": []},
        "metadata": {"event_code": check_id},
        "severity": "Medium",
        "status_code": status_code,
        "status": "New",
        "resources": [{"group": {"name": "compute"}, "uid": "uid1"}],
        "remediation": {"desc": "", "references": []},
        "unmapped": {"compliance": {}, "provider": "azure"},
        "cloud": {"provider": "azure"},
    }


# ---------------------------------------------------------------------------
# check_prerequisites
# ---------------------------------------------------------------------------


class TestCheckPrerequisites:
    def test_not_found_on_path(self) -> None:
        adapter = ProwlerAdapter()
        with patch("shutil.which", return_value=None):
            result = adapter.check_prerequisites()
        assert not result["satisfied"]
        assert "not found" in result["message"]

    def test_nonzero_exit_code_reports_unsatisfied(self) -> None:
        adapter = ProwlerAdapter()
        with (
            patch("shutil.which", return_value="/usr/bin/prowler"),
            patch(
                "subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "prowler"),
            ),
        ):
            result = adapter.check_prerequisites()
        assert not result["satisfied"]
        assert "not executable" in result["message"]

    def test_timeout_reports_unsatisfied(self) -> None:
        adapter = ProwlerAdapter()
        with (
            patch("shutil.which", return_value="/usr/bin/prowler"),
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired("prowler", 30),
            ),
        ):
            result = adapter.check_prerequisites()
        assert not result["satisfied"]

    def test_success_reports_version(self) -> None:
        adapter = ProwlerAdapter()
        mock_result = MagicMock()
        mock_result.stdout = b"Prowler 4.6.1"
        with (
            patch("shutil.which", return_value="/usr/bin/prowler"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = adapter.check_prerequisites()
        assert result["satisfied"]
        assert "4.6.1" in result["message"]

    def test_version_below_minimum_reports_unsatisfied(self) -> None:
        adapter = ProwlerAdapter()
        mock_result = MagicMock()
        mock_result.stdout = b"Prowler 3.12.0"
        with (
            patch("shutil.which", return_value="/usr/bin/prowler"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = adapter.check_prerequisites()
        assert not result["satisfied"]
        assert "3.12.0" in result["message"]

    def test_unparseable_version_reports_unsatisfied(self) -> None:
        adapter = ProwlerAdapter()
        mock_result = MagicMock()
        mock_result.stdout = b"unexpected output"
        with (
            patch("shutil.which", return_value="/usr/bin/prowler"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = adapter.check_prerequisites()
        assert not result["satisfied"]
        assert "could not be parsed" in result["message"]


# ---------------------------------------------------------------------------
# collect -- extra_args
# ---------------------------------------------------------------------------


class TestCollectExtraArgs:
    @patch("gxassessms.adapters.prowler.adapter.shutil")
    @patch("subprocess.run")
    def test_extra_args_appended_to_command(
        self, mock_run: MagicMock, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """extra_args from tool config should appear in the subprocess command."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")
        config = _make_config(
            extra_args=["--az-cli-auth", "--scan-list", "check1"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()

        # Create a fake output file so collect doesn't error on missing output
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"test": true}]')

        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)

        cmd = mock_run.call_args[0][0]
        assert "--az-cli-auth" in cmd
        assert "--scan-list" in cmd
        assert "check1" in cmd
        # Mapped flag must be suppressed -- no conflicting auth modes
        assert "--sp-env-auth" not in cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    @patch("subprocess.run")
    def test_extra_args_auth_flag_replaces_mapped_auth(
        self, mock_run: MagicMock, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """An auth flag in extra_args replaces, not supplements, the mapped auth flag."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")
        config = _make_config(
            extra_args=["--managed-identity-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()

        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"test": true}]')

        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)

        cmd = mock_run.call_args[0][0]
        assert "--managed-identity-auth" in cmd
        assert "--sp-env-auth" not in cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    @patch("subprocess.run")
    def test_non_auth_extra_args_do_not_suppress_mapped_auth(
        self, mock_run: MagicMock, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Non-auth extra_args do not suppress the mapped auth flag."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")
        config = _make_config(
            extra_args=["--scan-list", "check1"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()

        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"test": true}]')

        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)

        cmd = mock_run.call_args[0][0]
        assert "--sp-env-auth" in cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_no_auth_mapping_and_no_extra_args_raises(self, mock_shutil: MagicMock) -> None:
        """No auth mapping + no extra_args = CollectionError."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(extra_args=[])
        adapter = ProwlerAdapter()

        with (
            patch.dict(
                "gxassessms.adapters.prowler.adapter.AUTH_METHOD_MAP",
                {"client_credential": None},
            ),
            pytest.raises(CollectionError, match="extra_args"),
        ):
            adapter.collect(config, None)


# ---------------------------------------------------------------------------
# _validate_and_load -- foundational validation (manifest, elements, fields)
# ---------------------------------------------------------------------------


class TestValidateAndLoadFoundational:
    def test_validate_raw_rejects_empty_manifest(self) -> None:
        """Empty file_manifest must raise RawOutputValidationError immediately."""
        from gxassessms.core.domain.models import ResolvedManifest

        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC),
            file_manifest={},
            execution_metadata={},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match=r"[Ee]mpty"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_missing_status_code(self, tmp_path: Path) -> None:
        """Findings missing 'status_code' must be rejected."""
        import json

        finding = {
            "finding_info": {"uid": "test-uid", "title": "Test"},
            # status_code intentionally omitted
            "metadata": {"event_code": "some_check"},
        }
        manifest_file = tmp_path / "bad.ocsf.json"
        manifest_file.write_text(json.dumps([finding]))
        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC),
            file_manifest={str(manifest_file): ArtifactRecord(encoding="utf-8", sha256="a" * 64)},
            execution_metadata={},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match="status_code"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_non_dict_element(self, tmp_path: Path) -> None:
        """A non-dict element in the findings array must be rejected."""
        import json

        manifest_file = tmp_path / "bad.ocsf.json"
        manifest_file.write_text(json.dumps([None, {"finding_info": {}}]))
        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC),
            file_manifest={str(manifest_file): ArtifactRecord(encoding="utf-8", sha256="a" * 64)},
            execution_metadata={},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match=r"NoneType|expected object"):
            adapter.validate_raw(raw)


# ---------------------------------------------------------------------------
# _validate_and_load -- event_code
# ---------------------------------------------------------------------------


class TestValidateEventCode:
    def test_rejects_metadata_without_event_code(self, tmp_path: Path) -> None:
        """metadata present but missing event_code fails validation."""
        import json

        finding = {
            "finding_info": {"uid": "x", "title": "T", "desc": "D"},
            "status_code": "PASS",
            "metadata": {"version": "1.4.0"},  # no event_code
        }
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()

        with pytest.raises(RawOutputValidationError, match=r"metadata\.event_code"):
            adapter.validate_raw(raw)

    def test_accepts_metadata_with_event_code(self, tmp_path: Path) -> None:
        import json

        finding = _minimal_finding()
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()
        adapter.validate_raw(raw)  # should not raise


# ---------------------------------------------------------------------------
# _validate_and_load -- finding_info type validation
# ---------------------------------------------------------------------------


class TestValidateFindingInfoType:
    def test_validate_raw_rejects_finding_info_not_dict(self, tmp_path: Path) -> None:
        """finding_info must be a dict, not a string or number."""
        import json

        bad_finding = {
            "finding_info": "not-a-dict",
            "status_code": "FAIL",
            "metadata": {"event_code": "some_check"},
        }
        manifest_file = tmp_path / "bad.ocsf.json"
        manifest_file.write_text(json.dumps([bad_finding]))
        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC),
            file_manifest={str(manifest_file): ArtifactRecord(encoding="utf-8", sha256="a" * 64)},
            execution_metadata={},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match=r"finding_info.*expected object"):
            adapter.validate_raw(raw)

    def test_validate_raw_accepts_finding_info_dict(self, tmp_path: Path) -> None:
        """finding_info as a proper dict should pass validation."""
        import json

        good_finding = _minimal_finding()
        raw = _make_manifest(tmp_path, json.dumps([good_finding]))
        adapter = ProwlerAdapter()
        adapter.validate_raw(raw)  # should not raise


# ---------------------------------------------------------------------------
# coverage -- aggregation across findings
# ---------------------------------------------------------------------------


class TestCoverageAggregation:
    def test_mixed_statuses_produce_partially_assessed(self, tmp_path: Path) -> None:
        """Check with PASS + MANUAL findings should be PARTIALLY_ASSESSED."""
        import json

        findings = [
            _minimal_finding(check_id="mixed_check", status_code="PASS", uid="uid-res1"),
            _minimal_finding(check_id="mixed_check", status_code="MANUAL", uid="uid-res2"),
            _minimal_finding(check_id="mixed_check", status_code="PASS", uid="uid-res3"),
        ]
        raw = _make_manifest(tmp_path, json.dumps(findings))
        adapter = ProwlerAdapter()
        records = adapter.coverage(raw)

        assert len(records) == 1
        assert records[0].control_id == "mixed_check"
        assert records[0].status == CoverageStatus.PARTIALLY_ASSESSED

    def test_all_pass_produces_assessed(self, tmp_path: Path) -> None:
        import json

        findings = [
            _minimal_finding(check_id="clean_check", status_code="PASS", uid="uid-r1"),
            _minimal_finding(check_id="clean_check", status_code="PASS", uid="uid-r2"),
        ]
        raw = _make_manifest(tmp_path, json.dumps(findings))
        adapter = ProwlerAdapter()
        records = adapter.coverage(raw)

        assert len(records) == 1
        assert records[0].status == CoverageStatus.ASSESSED

    def test_all_manual_produces_partially_assessed(self, tmp_path: Path) -> None:
        import json

        findings = [
            _minimal_finding(check_id="manual_check", status_code="MANUAL", uid="uid-r1"),
        ]
        raw = _make_manifest(tmp_path, json.dumps(findings))
        adapter = ProwlerAdapter()
        records = adapter.coverage(raw)

        assert len(records) == 1
        assert records[0].status == CoverageStatus.PARTIALLY_ASSESSED

    def test_multiple_checks_each_get_own_record(self, tmp_path: Path) -> None:
        import json

        findings = [
            _minimal_finding(check_id="check_a", status_code="PASS", uid="uid-1"),
            _minimal_finding(check_id="check_b", status_code="FAIL", uid="uid-2"),
            _minimal_finding(check_id="check_b", status_code="MANUAL", uid="uid-3"),
        ]
        raw = _make_manifest(tmp_path, json.dumps(findings))
        adapter = ProwlerAdapter()
        records = adapter.coverage(raw)

        by_id = {r.control_id: r for r in records}
        assert len(by_id) == 2
        assert by_id["check_a"].status == CoverageStatus.ASSESSED
        assert by_id["check_b"].status == CoverageStatus.PARTIALLY_ASSESSED


# ---------------------------------------------------------------------------
# collect -- path resolution
# ---------------------------------------------------------------------------


class TestCollectPathResolution:
    """Verify collect() resolves the prowler binary path."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_prowler_not_on_path_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """If prowler is not on PATH when collect() runs, CollectionError is raised."""
        mock_shutil.which.return_value = None
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="not found on PATH"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_collect_uses_resolved_path_in_command(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """collect() must use the resolved binary path, not the bare string 'prowler'."""
        mock_shutil.which.return_value = "/opt/prowler-venv/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert captured_cmd[0] == "/opt/prowler-venv/bin/prowler"


# ---------------------------------------------------------------------------
# collect -- exit codes
# ---------------------------------------------------------------------------


class TestCollectExitCodes:
    """Verify Prowler exit code handling."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_exit_code_3_does_not_raise(self, mock_shutil: MagicMock, tmp_path: Path) -> None:
        """Exit code 3 (FAIL findings present) is Prowler's normal success signal."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with patch(
            "subprocess.run",
            return_value=MagicMock(returncode=3, stdout=b"", stderr=b""),
        ):
            result = adapter.collect(config, None)
        assert result is not None
        assert result.tool == ToolSource.PROWLER
        assert len(result.artifacts) == 1

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_exit_code_0_does_not_raise(self, mock_shutil: MagicMock, tmp_path: Path) -> None:
        """Exit code 0 (no FAIL findings) is also success."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with patch(
            "subprocess.run",
            return_value=MagicMock(returncode=0, stdout=b"", stderr=b""),
        ):
            result = adapter.collect(config, None)
        assert result is not None
        assert result.tool == ToolSource.PROWLER

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_exit_code_1_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Exit code 1 (infrastructure/config error) must raise CollectionError."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with (
            patch(
                "subprocess.run",
                return_value=MagicMock(
                    returncode=1, stdout=b"auth failed detail", stderr=b"error detail"
                ),
            ),
            pytest.raises(CollectionError, match="exited with code 1"),
        ):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_exit_code_1_error_includes_stdout(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Failure message must include stdout (Prowler writes diagnostics there)."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with (
            pytest.raises(CollectionError, match="auth failed detail"),
            patch(
                "subprocess.run",
                return_value=MagicMock(returncode=1, stdout=b"auth failed detail", stderr=b""),
            ),
        ):
            adapter.collect(config, None)


# ---------------------------------------------------------------------------
# collect -- error paths (timeout, OSError, missing output)
# ---------------------------------------------------------------------------


class TestCollectErrorPaths:
    """Verify collect() error handling for subprocess exceptions and missing output."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_collect_timeout_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """subprocess.TimeoutExpired during collect() must raise CollectionError."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with (
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("prowler", 1800)),
            pytest.raises(CollectionError, match="timed out"),
        ):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_collect_oserror_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """OSError (binary not accessible) during collect() must raise CollectionError."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with (
            patch("subprocess.run", side_effect=OSError("Permission denied")),
            pytest.raises(CollectionError, match="not accessible"),
        ):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_collect_no_output_file_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Prowler exit 0 but no .ocsf.json file produced must raise CollectionError."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with (
            patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=b"", stderr=b"")),
            pytest.raises(CollectionError, match="No Prowler OCSF output found"),
        ):
            adapter.collect(config, None)


# ---------------------------------------------------------------------------
# collect -- auth method behavior
# ---------------------------------------------------------------------------


class TestCollectAuthMethods:
    """Verify auth method handling in collect()."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_device_code_auth_injects_tenant_id(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """device_code auth must inject --tenant-id into the Prowler command."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = _make_config(auth_method="device_code", output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert "--tenant-id" in captured_cmd
        idx = captured_cmd.index("--tenant-id")
        assert captured_cmd[idx + 1] != ""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_device_code_auth_without_tenant_id_raises(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """device_code auth without tenant_id in config must raise CollectionError."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = EngagementConfig(
            client_name="test-client",
            tenant_id="",
            auth=AuthConfig(method="device_code", tenant_id="", client_id=""),
            tools={"prowler": ToolConfig(output_dir=str(tmp_path))},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="tenant_id"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_browser_auth_via_extra_args_injects_tenant_id(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """--browser-auth supplied via extra_args must still inject --tenant-id."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--browser-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert "--tenant-id" in captured_cmd
        idx = captured_cmd.index("--tenant-id")
        assert captured_cmd[idx + 1] == "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# collect -- modules / --checks injection
# ---------------------------------------------------------------------------


class TestCollectModules:
    """Verify modules list is passed as --checks to Prowler."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_modules_list_injects_checks_flag(self, mock_shutil: MagicMock, tmp_path: Path) -> None:
        """Specifying modules in tool config must pass --checks to Prowler."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = EngagementConfig(
            client_name="test-client",
            tenant_id="test-tenant",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="test-tenant",
                client_id="test-client-id",
            ),
            tools={
                "prowler": ToolConfig(
                    output_dir=str(tmp_path),
                    modules=["defender_ensure_defender_for_app_services_is_on"],
                )
            },
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert "--checks" in captured_cmd
        assert "defender_ensure_defender_for_app_services_is_on" in captured_cmd


# ---------------------------------------------------------------------------
# extra_args validation -- allowlist enforcement
# ---------------------------------------------------------------------------


class TestValidateProwlerExtraArgs:
    """Verify extra_args are validated against the Prowler flag allowlist."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_known_auth_flag_is_accepted(self, mock_shutil: MagicMock, tmp_path: Path) -> None:
        """Known Prowler auth flags must pass validation."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--az-cli-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        with patch(
            "subprocess.run",
            return_value=MagicMock(returncode=0, stdout=b"", stderr=b""),
        ):
            result = adapter.collect(config, None)
        assert result is not None

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_unknown_flag_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Unrecognized flags must be rejected before subprocess invocation."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--unknown-dangerous-flag"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match=r"[Uu]nrecognized.*flag"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_single_dash_flag_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Single-dash flags like -M or -o must be rejected -- they bypass the allowlist."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="client_credential",
            extra_args=["-M", "csv"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match=r"[Uu]nrecognized.*flag"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_unsafe_value_raises_collection_error(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Values containing shell metacharacters must be rejected."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--checks", "check; rm -rf /"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match=r"[Uu]nsafe"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_valid_flag_value_pair_is_accepted(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Known flag + safe value must pass validation and appear in command."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--checks", "defender_ensure_defender_for_app_services_is_on"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert "--checks" in captured_cmd
        assert "defender_ensure_defender_for_app_services_is_on" in captured_cmd
