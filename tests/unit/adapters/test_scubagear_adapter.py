"""Tests for ScubaGearAdapter.collect() reserved-arg guard.

Covers: case-insensitive conflict detection for reserved PowerShell parameters,
including PowerShell prefix-binding bypasses.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from gxassessms.core.contracts.errors import CollectionError


def _make_config(output_dir: str, extra_args: list[str]):
    """Build a minimal EngagementConfig with the given extra_args for scubagear."""
    from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig

    tc = ToolConfig(enabled=True, output_dir=output_dir, extra_args=extra_args)
    auth = AuthConfig(method="device_code", tenant_id="t-1", client_id="c-1")
    return EngagementConfig(
        client_name="Test",
        tenant_id="t-1",
        auth=auth,
        tools={"scubagear": tc},
    )


class TestReservedArgGuard:
    """ScubaGearAdapter.collect() must block reserved-arg overrides (case-insensitive).

    Values in test extra_args must satisfy _ARG_PATTERN (no slashes; only word chars, hyphens, dots,
    commas).
    The guard must fire before run_verified_powershell is ever called.
    """

    @pytest.fixture(autouse=True)
    def _adapter(self) -> None:
        from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter

        self.adapter = ScubaGearAdapter()

    def _collect_blocked(self, extra_args: list[str]) -> None:
        """Call collect() and expect a 'reserved' CollectionError."""
        config = _make_config("/nonexistent/fake-output", extra_args)
        with patch("gxassessms.core.security.permissions.secure_mkdir"):
            self.adapter.collect(config, auth=None)

    # -- canonical casing is rejected --

    def test_outpath_canonical_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutPath:evil"])

    # -- case variants must also be blocked --

    def test_outpath_lowercase_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-outpath:evil"])

    def test_outpath_uppercase_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OUTPATH:evil"])

    # -- reserved args as bare switches must also be blocked --

    def test_outpath_as_switch_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutPath"])

    def test_outpath_switch_lowercase_blocked(self) -> None:
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-outpath"])

    # -- PowerShell prefix-binding bypasses must be blocked --

    def test_outpath_prefix_named_outpat_blocked(self) -> None:
        """'-OutPat:foo' is a prefix of 'OutPath' and must be blocked."""
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutPat:foo"])

    def test_outpath_prefix_named_outp_blocked(self) -> None:
        """'-OutP:foo' is a shorter prefix of 'OutPath' and must be blocked."""
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutP:foo"])

    def test_outpath_prefix_named_out_blocked(self) -> None:
        """'-Out:foo' is a prefix of 'OutPath' and must be blocked."""
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-Out:foo"])

    def test_outpath_prefix_switch_outpat_blocked(self) -> None:
        """'-OutPat' as bare switch is a prefix of 'OutPath' and must be blocked."""
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutPat"])

    def test_outpath_prefix_switch_outp_blocked(self) -> None:
        """'-OutP' as bare switch is a prefix of 'OutPath' and must be blocked."""
        with pytest.raises(CollectionError, match="reserved"):
            self._collect_blocked(["-OutP"])

    # -- non-reserved args must pass through --

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

    # -- longer-than-reserved arg must NOT be blocked --

    def test_longer_than_reserved_arg_passes(self, tmp_path: Path) -> None:
        """'-OutPathExtra:val' is longer than 'OutPath' and must NOT be blocked.

        Tests that the startswith direction is correct: 'outpath'.startswith('outpathextra')
        is False, so this arg passes the guard.
        """
        config = _make_config(str(tmp_path), ["-OutPathExtra:val"])
        with (
            patch("gxassessms.core.security.permissions.secure_mkdir"),
            patch(
                "gxassessms.adapters._base.run_verified_powershell",
                side_effect=CollectionError("mocked -- not testing collection"),
            ),
            pytest.raises(CollectionError, match="mocked"),
        ):
            self.adapter.collect(config, auth=None)
