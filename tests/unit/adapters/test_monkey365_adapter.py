"""Tests for Monkey365Adapter.collect() reserved-arg guard.

Covers: case-insensitive conflict detection for reserved PowerShell parameters.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from gxassessms.core.contracts.errors import CollectionError


def _make_config(output_dir: str, extra_args: list[str]):
    """Build a minimal EngagementConfig with the given extra_args for monkey365."""
    from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig

    tc = ToolConfig(enabled=True, output_dir=output_dir, extra_args=extra_args)
    auth = AuthConfig(method="device_code", tenant_id="t-1", client_id="c-1")
    return EngagementConfig(
        client_name="Test",
        tenant_id="t-1",
        auth=auth,
        tools={"monkey365": tc},
    )


class TestReservedArgGuard:
    """Monkey365Adapter.collect() must block reserved-arg overrides (case-insensitive).

    Values in test extra_args must satisfy _ARG_PATTERN (no slashes; only word chars, hyphens, dots,
    commas).
    The guard must fire before run_verified_powershell is ever called.
    """

    @pytest.fixture(autouse=True)
    def _adapter(self) -> None:
        from gxassessms.adapters.monkey365.adapter import Monkey365Adapter

        self.adapter = Monkey365Adapter()

    def _collect_blocked(self, extra_args: list[str]) -> None:
        """Call collect() and expect a 'reserved' CollectionError."""
        config = _make_config("/nonexistent/fake-output", extra_args)
        with patch("gxassessms.core.security.permissions.secure_mkdir"):
            self.adapter.collect(config, auth=None)

    # -- canonical casing is rejected --

    def test_outdir_canonical_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutDir:evil"])

    def test_exportto_canonical_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-ExportTo:CSV"])

    def test_instance_canonical_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-Instance:Azure"])

    # -- case variants must also be blocked (regression for bypass via case mismatch) --

    def test_outdir_lowercase_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-outdir:evil"])

    def test_outdir_uppercase_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OUTDIR:evil"])

    def test_exportto_mixed_case_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-exportto:CSV"])

    def test_instance_mixed_case_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-INSTANCE:Azure"])

    # -- reserved args as bare switches must also be blocked --

    def test_outdir_as_switch_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutDir"])

    def test_exportto_as_switch_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-ExportTo"])

    def test_instance_as_switch_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-Instance"])

    def test_outdir_switch_lowercase_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-outdir"])

    # -- non-reserved args must pass through without triggering the guard --

    def test_non_reserved_arg_passes_guard(self, tmp_path: Path) -> None:
        """A legitimate extra_arg must not be blocked by the reserved-arg guard.

        run_verified_powershell is mocked so the test never calls PowerShell;
        we only verify that the reserved-arg check does not raise.
        """
        config = _make_config(str(tmp_path), ["-M365Environment:Commercial"])
        with (
            patch("gxassessms.core.security.permissions.secure_mkdir"),
            patch(
                "gxassessms.adapters._base.run_verified_powershell",
                side_effect=CollectionError("mocked -- not testing collection"),
            ),
            pytest.raises(CollectionError, match="mocked"),
        ):
            self.adapter.collect(config, auth=None)
