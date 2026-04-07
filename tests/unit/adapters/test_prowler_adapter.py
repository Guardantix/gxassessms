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

# Name of the test env var used by _make_config for client_credential tests.
_TEST_SECRET_ENV = "AZURE_CLIENT_SECRET_TEST"  # pragma: allowlist secret
_TEST_SECRET_VAL = "test-secret-value"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _inject_sp_env_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure the test secret env var is set for any test that triggers --sp-env-auth."""
    monkeypatch.setenv(_TEST_SECRET_ENV, _TEST_SECRET_VAL)


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
            client_secret_env=_TEST_SECRET_ENV,
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


def _make_collector(
    tmp_path: Path,
    returncode: int = 0,
    content: str = '[{"finding_info": {}}]',
) -> Any:
    """Return a subprocess.run callable that writes the OCSF output file on invocation.

    Simulates Prowler writing its output during subprocess execution so that the
    file mtime is >= the run_start_ts captured just before subprocess.run() is
    called.  Tests that need collect() to succeed must use this instead of
    writing the file before calling collect().
    """

    def run(cmd: list[str], **kwargs: Any) -> MagicMock:
        (tmp_path / "ProwlerResults.ocsf.json").write_text(content)
        return MagicMock(returncode=returncode, stdout=b"", stderr=b"")

    return run


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
        mock_run.side_effect = _make_collector(tmp_path)
        config = _make_config(
            extra_args=["--az-cli-auth", "--services", "storage"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()

        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)

        cmd = mock_run.call_args[0][0]
        assert "--az-cli-auth" in cmd
        assert "--services" in cmd
        assert "storage" in cmd
        # Mapped flag must be suppressed -- no conflicting auth modes
        assert "--sp-env-auth" not in cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    @patch("subprocess.run")
    def test_extra_args_auth_flag_replaces_mapped_auth(
        self, mock_run: MagicMock, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """An auth flag in extra_args replaces, not supplements, the mapped auth flag."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.side_effect = _make_collector(tmp_path)
        config = _make_config(
            extra_args=["--managed-identity-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()

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
        mock_run.side_effect = _make_collector(tmp_path)
        config = _make_config(
            extra_args=["--services", "storage"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()

        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)

        cmd = mock_run.call_args[0][0]
        assert "--sp-env-auth" in cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    @patch("subprocess.run")
    def test_subscription_id_injected_when_set(
        self, mock_run: MagicMock, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """subscription_id in EngagementConfig must be passed as --subscription-ids."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.side_effect = _make_collector(tmp_path)
        tc = ToolConfig(enabled=True, output_dir=str(tmp_path))
        config = EngagementConfig(
            client_name="TestClient",
            tenant_id="00000000-0000-0000-0000-000000000000",
            subscription_id="sub-1234",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="00000000-0000-0000-0000-000000000000",
                client_id="test-client-id",
                client_secret_env=_TEST_SECRET_ENV,
            ),
            tools={"prowler": tc},
        )
        adapter = ProwlerAdapter()
        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)
        cmd = mock_run.call_args[0][0]
        assert "--subscription-ids" in cmd
        assert "sub-1234" in cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    @patch("subprocess.run")
    def test_subscription_id_not_injected_when_empty(
        self, mock_run: MagicMock, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """When subscription_id is empty, --subscription-ids must not appear in cmd."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.side_effect = _make_collector(tmp_path)
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)
        cmd = mock_run.call_args[0][0]
        assert "--subscription-ids" not in cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    @patch("subprocess.run")
    def test_subscription_id_not_duplicated_when_in_extra_args(
        self, mock_run: MagicMock, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """If --subscription-ids is in extra_args, config value must not also be injected."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.side_effect = _make_collector(tmp_path)
        tc = ToolConfig(
            enabled=True,
            output_dir=str(tmp_path),
            extra_args=["--az-cli-auth", "--subscription-ids", "sub-explicit"],
        )
        config = EngagementConfig(
            client_name="TestClient",
            tenant_id="00000000-0000-0000-0000-000000000000",
            subscription_id="sub-from-config",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="00000000-0000-0000-0000-000000000000",
                client_id="test-client-id",
                client_secret_env=_TEST_SECRET_ENV,
            ),
            tools={"prowler": tc},
        )
        adapter = ProwlerAdapter()
        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)
        cmd = mock_run.call_args[0][0]
        assert cmd.count("--subscription-ids") == 1
        assert "sub-explicit" in cmd
        assert "sub-from-config" not in cmd

    @patch("subprocess.run")
    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_subscription_id_singular_in_extra_args_suppresses_injection(
        self, mock_shutil: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """--subscription-id (singular) in extra_args must suppress config injection."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        mock_run.side_effect = _make_collector(tmp_path)
        tc = ToolConfig(
            enabled=True,
            output_dir=str(tmp_path),
            extra_args=["--az-cli-auth", "--subscription-id", "sub-explicit"],
        )
        config = EngagementConfig(
            client_name="TestClient",
            tenant_id="00000000-0000-0000-0000-000000000000",
            subscription_id="sub-from-config",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="00000000-0000-0000-0000-000000000000",
                client_id="test-client-id",
                client_secret_env=_TEST_SECRET_ENV,
            ),
            tools={"prowler": tc},
        )
        adapter = ProwlerAdapter()
        with patch("gxassessms.core.hashing.sha256_file", return_value="a" * 64):
            adapter.collect(config, None)
        cmd = mock_run.call_args[0][0]
        assert "--subscription-ids" not in cmd
        assert "sub-from-config" not in cmd

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
# _validate_and_load -- status_code type and value validation
# ---------------------------------------------------------------------------


class TestValidateStatusCode:
    def test_rejects_null_status_code(self, tmp_path: Path) -> None:
        """status_code: null must be rejected (not coerced to FAIL)."""
        import json

        finding = _minimal_finding()
        finding["status_code"] = None
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match="status_code"):
            adapter.validate_raw(raw)

    def test_rejects_empty_string_status_code(self, tmp_path: Path) -> None:
        """status_code: '' must be rejected (not coerced to FAIL)."""
        import json

        finding = _minimal_finding()
        finding["status_code"] = ""
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match="status_code"):
            adapter.validate_raw(raw)

    def test_rejects_non_string_status_code(self, tmp_path: Path) -> None:
        """status_code must be a string, not an integer."""
        import json

        finding = _minimal_finding()
        finding["status_code"] = 1
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match="status_code"):
            adapter.validate_raw(raw)

    def test_rejects_unrecognized_status_code(self, tmp_path: Path) -> None:
        """status_code values outside PASS/FAIL/MANUAL/MUTED must be rejected."""
        import json

        finding = _minimal_finding()
        finding["status_code"] = "UNKNOWN_VALUE"
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()
        with pytest.raises(RawOutputValidationError, match="status_code"):
            adapter.validate_raw(raw)

    @pytest.mark.parametrize("code", ["PASS", "FAIL", "MANUAL", "MUTED"])
    def test_accepts_valid_status_codes(self, tmp_path: Path, code: str) -> None:
        """PASS, FAIL, MANUAL, and MUTED are all valid status_code values."""
        import json

        finding = _minimal_finding(status_code=code)
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()
        adapter.validate_raw(raw)  # should not raise


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

    def test_rejects_event_code_null(self, tmp_path: Path) -> None:
        """event_code present but null fails validation."""
        import json

        finding = {
            "finding_info": {"uid": "x", "title": "T", "desc": "D"},
            "status_code": "PASS",
            "metadata": {"event_code": None},
        }
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()

        with pytest.raises(RawOutputValidationError, match=r"non-empty string"):
            adapter.validate_raw(raw)

    def test_rejects_event_code_whitespace(self, tmp_path: Path) -> None:
        """event_code that is all whitespace fails validation."""
        import json

        finding = {
            "finding_info": {"uid": "x", "title": "T", "desc": "D"},
            "status_code": "PASS",
            "metadata": {"event_code": "   "},
        }
        raw = _make_manifest(tmp_path, json.dumps([finding]))
        adapter = ProwlerAdapter()

        with pytest.raises(RawOutputValidationError, match=r"non-empty string"):
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
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
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
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with patch("subprocess.run", side_effect=_make_collector(tmp_path, returncode=3)):
            result = adapter.collect(config, None)
        assert result is not None
        assert result.tool == ToolSource.PROWLER
        assert len(result.artifacts) == 1

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_exit_code_0_does_not_raise(self, mock_shutil: MagicMock, tmp_path: Path) -> None:
        """Exit code 0 (no FAIL findings) is also success."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with patch("subprocess.run", side_effect=_make_collector(tmp_path)):
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

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_rerun_with_same_output_dir_succeeds(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """collect() must succeed when the output_dir is reused across runs.

        Prowler writes to a fixed path (-o <output_dir> -F ProwlerResults), so the
        .ocsf.json file already exists when a second run begins.  The adapter must
        collect the overwritten file rather than raising CollectionError.
        """
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()

        # Pre-create the output file as Prowler would have left it after a prior run.
        existing_file = tmp_path / "ProwlerResults.ocsf.json"
        existing_file.write_text('[{"stale": true}]')

        # The subprocess overwrites the same file with fresh results.
        def _fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            existing_file.write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=_fake_run):
            result = adapter.collect(config, None)

        assert len(result.artifacts) == 1
        assert result.artifacts[0].source_path == str(existing_file)


# ---------------------------------------------------------------------------
# collect -- auth method behavior
# ---------------------------------------------------------------------------


class TestCollectAuthMethods:
    """Verify auth method handling in collect()."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_device_code_auth_raises_unsupported(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """device_code auth must raise CollectionError -- Prowler has no device-code flow.

        Prowler's --browser-auth is interactive-browser auth, not the OAuth2 device
        authorization grant.  Silently mapping device_code to --browser-auth would
        cause headless/remote collectors to hang trying to open a browser.
        """
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(auth_method="device_code", output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="No Prowler auth mapping"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_device_code_auth_raises_even_without_tenant_id(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """device_code must raise the unsupported-method error regardless of tenant_id."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = EngagementConfig(
            client_name="test-client",
            tenant_id="",
            auth=AuthConfig(method="device_code", tenant_id="", client_id=""),
            tools={"prowler": ToolConfig(output_dir=str(tmp_path))},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="No Prowler auth mapping"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_browser_auth_via_extra_args_injects_tenant_id(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """--browser-auth supplied via extra_args must still inject --tenant-id."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--browser-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert "--tenant-id" in captured_cmd
        idx = captured_cmd.index("--tenant-id")
        assert captured_cmd[idx + 1] == "00000000-0000-0000-0000-000000000000"

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_browser_auth_with_tenant_id_in_extra_args_no_duplicate(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """--tenant-id already in extra_args must not be injected a second time."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="interactive",
            extra_args=["--tenant-id", "explicit-tenant"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert captured_cmd.count("--tenant-id") == 1
        idx = captured_cmd.index("--tenant-id")
        assert captured_cmd[idx + 1] == "explicit-tenant"


# ---------------------------------------------------------------------------
# collect -- modules / --checks injection
# ---------------------------------------------------------------------------


class TestCollectModules:
    """Verify modules list is passed as --checks to Prowler."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_modules_list_injects_checks_flag(self, mock_shutil: MagicMock, tmp_path: Path) -> None:
        """Specifying modules in tool config must pass --checks to Prowler."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = EngagementConfig(
            client_name="test-client",
            tenant_id="test-tenant",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="test-tenant",
                client_id="test-client-id",
                client_secret_env=_TEST_SECRET_ENV,
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
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
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
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--az-cli-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        with patch("subprocess.run", side_effect=_make_collector(tmp_path)):
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
    def test_azure_region_flag_is_accepted(self, mock_shutil: MagicMock, tmp_path: Path) -> None:
        """--azure-region must be in the allowlist to support sovereign cloud scans."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--azure-region", "AzureUSGovernment"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        with patch("subprocess.run", side_effect=_make_collector(tmp_path)):
            result = adapter.collect(config, None)
        assert result is not None

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_valid_flag_value_pair_is_accepted(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """Known flag + safe value must pass validation and appear in command."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="client_credential",
            extra_args=["--checks", "defender_ensure_defender_for_app_services_is_on"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)
        assert "--checks" in captured_cmd
        assert "defender_ensure_defender_for_app_services_is_on" in captured_cmd


# ---------------------------------------------------------------------------
# P1 -- client_credential env injection
# ---------------------------------------------------------------------------


class TestCollectClientCredentialEnvInjection:
    """Verify AZURE_* env vars are injected into the Prowler subprocess for sp-env-auth."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_client_credential_injects_azure_env_vars(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """collect() must pass AZURE_* credentials in the subprocess env for --sp-env-auth."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        captured_env: dict[str, str] = {}

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_env.update(kwargs.get("env") or {})
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)

        assert captured_env.get("AZURE_CLIENT_ID") == "test-client-id"
        assert captured_env.get("AZURE_TENANT_ID") == "00000000-0000-0000-0000-000000000000"
        assert captured_env.get("AZURE_CLIENT_SECRET") == _TEST_SECRET_VAL

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_client_credential_missing_secret_env_name_raises(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """collect() must raise if client_secret_env is empty when --sp-env-auth is active."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = EngagementConfig(
            client_name="test-client",
            tenant_id="test-tenant",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="test-tenant",
                client_id="test-client-id",
                client_secret_env="",  # explicitly empty
            ),
            tools={"prowler": ToolConfig(output_dir=str(tmp_path))},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="client_secret_env"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_client_credential_certificate_path_raises(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """collect() must raise with a clear message when certificate_path is set
        but client_secret_env is absent -- Prowler --sp-env-auth requires a secret."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = EngagementConfig(
            client_name="test-client",
            tenant_id="test-tenant",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="test-tenant",
                client_id="test-client-id",
                client_secret_env="",
                certificate_path="/path/to/cert.pem",
            ),
            tools={"prowler": ToolConfig(output_dir=str(tmp_path))},
        )
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="certificate"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_client_credential_secret_env_var_not_set_raises(
        self, mock_shutil: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """collect() must raise if the env var named by client_secret_env is absent."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        monkeypatch.delenv(_TEST_SECRET_ENV, raising=False)
        config = _make_config(output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="is not set"):
            adapter.collect(config, None)

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_auth_override_skips_env_injection(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """When extra_args overrides auth to --az-cli-auth, no AZURE_* injection occurs."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(extra_args=["--az-cli-auth"], output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        captured_kwargs: dict[str, Any] = {}

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_kwargs.update(kwargs)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)

        # env kwarg should be None (no injection) when auth is overridden
        assert captured_kwargs.get("env") is None

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_sp_env_auth_via_extra_args_does_not_inject_env_vars(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """--sp-env-auth in extra_args must not overwrite already-exported AZURE_* vars.

        Operators who pass --sp-env-auth explicitly are asserting that AZURE_*
        env vars are already exported.  The adapter must pass subprocess.env=None
        so the parent env is inherited as-is, not overwritten with config values.
        This covers the scenario where client_credential auth is configured for
        other adapters but Prowler should use pre-exported AZURE_* instead.
        """
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        # client_credential method normally injects from config, but when the
        # operator also passes --sp-env-auth in extra_args, extra_has_auth=True
        # prevents AUTH_METHOD_MAP from adding --sp-env-auth to cmd, so
        # sp_env_auth_active (keyed off cmd) is False and injection is skipped.
        config = _make_config(extra_args=["--sp-env-auth"], output_dir=str(tmp_path))
        adapter = ProwlerAdapter()
        captured_kwargs: dict[str, Any] = {}

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_kwargs.update(kwargs)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)

        # env must be None: subprocess inherits the parent environment.
        assert captured_kwargs.get("env") is None


# ---------------------------------------------------------------------------
# P2 -- browser_auth_active keyed off actual cmd, not config.auth.method
# ---------------------------------------------------------------------------


class TestCollectBrowserAuthActive:
    """Verify --tenant-id is only appended when --browser-auth is actually in the command."""

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_device_code_overridden_by_az_cli_auth_skips_tenant_id(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """device_code method + --az-cli-auth extra_arg must NOT inject --tenant-id.

        Prowler rejects --tenant-id unless --browser-auth is active; pairing it
        with --az-cli-auth causes a non-zero exit before scanning begins.
        """
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="device_code",
            extra_args=["--az-cli-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)

        assert "--tenant-id" not in captured_cmd
        assert "--az-cli-auth" in captured_cmd

    @patch("gxassessms.adapters.prowler.adapter.shutil")
    def test_interactive_overridden_by_managed_identity_skips_tenant_id(
        self, mock_shutil: MagicMock, tmp_path: Path
    ) -> None:
        """interactive method + --managed-identity-auth must NOT inject --tenant-id."""
        mock_shutil.which.return_value = "/usr/local/bin/prowler"
        config = _make_config(
            auth_method="interactive",
            extra_args=["--managed-identity-auth"],
            output_dir=str(tmp_path),
        )
        adapter = ProwlerAdapter()
        captured_cmd: list[str] = []

        def capture(cmd: list[str], **kwargs: Any) -> MagicMock:
            captured_cmd.extend(cmd)
            (tmp_path / "ProwlerResults.ocsf.json").write_text('[{"finding_info": {}}]')
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=capture):
            adapter.collect(config, None)

        assert "--tenant-id" not in captured_cmd
        assert "--managed-identity-auth" in captured_cmd


# ---------------------------------------------------------------------------
# P3 -- Windows paths accepted in extra_args values
# ---------------------------------------------------------------------------


class TestValidateProwlerExtraArgsWindowsPaths:
    """Verify Windows-style file paths (backslashes) are accepted as extra_args values."""

    def test_windows_path_for_checks_file_is_accepted(self) -> None:
        """C:\\temp\\checks.txt must pass value validation."""
        from gxassessms.adapters.prowler.adapter import _validate_prowler_extra_args

        result = _validate_prowler_extra_args(["--checks-file", r"C:\temp\checks.txt"], "Prowler")
        assert r"C:\temp\checks.txt" in result

    def test_windows_path_for_mutelist_file_is_accepted(self) -> None:
        """Windows path for --mutelist-file must not be rejected."""
        from gxassessms.adapters.prowler.adapter import _validate_prowler_extra_args

        result = _validate_prowler_extra_args(
            ["--mutelist-file", r"C:\Users\auditor\mutelist.yaml"], "Prowler"
        )
        assert r"C:\Users\auditor\mutelist.yaml" in result

    def test_shell_metachar_still_rejected_on_windows_style_value(self) -> None:
        """Backslash allowance must not open shell injection via semicolons etc."""
        from gxassessms.adapters.prowler.adapter import _validate_prowler_extra_args

        with pytest.raises(CollectionError, match="Unsafe value"):
            _validate_prowler_extra_args(
                ["--checks-file", r"C:\temp\checks.txt; rm -rf /"], "Prowler"
            )

    def test_mutelist_file_windows_path_is_accepted(self) -> None:
        """--mutelist-file with a Windows path must pass validation."""
        from gxassessms.adapters.prowler.adapter import _validate_prowler_extra_args

        result = _validate_prowler_extra_args(
            ["--mutelist-file", r"C:\temp\mutelist.yaml"], "Prowler"
        )
        assert r"C:\temp\mutelist.yaml" in result
