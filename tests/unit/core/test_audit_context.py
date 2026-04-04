"""Tests for runtime audit context generation."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

from gxassessms.core.security.audit_context import build_audit_context


class TestBuildAuditContext:
    def test_contains_required_keys(self) -> None:
        result = build_audit_context()
        assert set(result.keys()) == {"hostname", "os_user", "pid", "platform", "platform_version"}

    def test_all_values_are_strings(self) -> None:
        result = build_audit_context()
        for key, value in result.items():
            assert isinstance(value, str), f"{key} is {type(value)}, expected str"

    def test_pid_matches_current_process(self) -> None:
        result = build_audit_context()
        assert int(result["pid"]) == os.getpid()

    def test_platform_matches_sys_platform(self) -> None:
        result = build_audit_context()
        assert result["platform"] == sys.platform

    def test_graceful_on_hostname_failure(self) -> None:
        with patch(
            "gxassessms.core.security.audit_context.socket.gethostname",
            side_effect=OSError("no host"),
        ):
            result = build_audit_context()
        assert result["hostname"] == "unknown"
        # Other keys should still be populated
        assert result["pid"] != "unknown"

    def test_graceful_on_getuser_keyerror(self) -> None:
        with patch(
            "gxassessms.core.security.audit_context.getpass.getuser",
            side_effect=KeyError("no user"),
        ):
            result = build_audit_context()
        assert result["os_user"] == "unknown"

    def test_graceful_on_getuser_oserror(self) -> None:
        with patch(
            "gxassessms.core.security.audit_context.getpass.getuser", side_effect=OSError("tty")
        ):
            result = build_audit_context()
        assert result["os_user"] == "unknown"
