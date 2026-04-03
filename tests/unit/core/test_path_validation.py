"""Tests for POSIX path validation helper (spec Section 1)."""

from __future__ import annotations

import pytest

from gxassessms.core.domain.path_validation import validate_canonical_posix_path


class TestValidateCanonicalPosixPath:
    """Tests for validate_canonical_posix_path()."""

    # -- Valid paths --

    def test_accepts_simple_relative_path(self) -> None:
        validate_canonical_posix_path("scubagear/ScubaResults.json")

    def test_accepts_nested_relative_path(self) -> None:
        validate_canonical_posix_path("scubagear/subdir/results.json")

    def test_accepts_single_segment(self) -> None:
        validate_canonical_posix_path("results.json")

    def test_accepts_hyphenated_segments(self) -> None:
        validate_canonical_posix_path("scubagear/ScubaResults_abc-123.json")

    # -- Backslash rejection --

    def test_rejects_backslash(self) -> None:
        with pytest.raises(ValueError, match="backslash"):
            validate_canonical_posix_path("scubagear\\results.json")

    # -- Absolute path rejection --

    def test_rejects_leading_slash(self) -> None:
        with pytest.raises(ValueError, match="absolute"):
            validate_canonical_posix_path("/scubagear/results.json")

    # -- Parent traversal rejection --

    def test_rejects_dotdot_traversal(self) -> None:
        with pytest.raises(ValueError, match="traversal"):
            validate_canonical_posix_path("scubagear/../etc/passwd")

    def test_rejects_dotdot_at_start(self) -> None:
        with pytest.raises(ValueError, match="traversal"):
            validate_canonical_posix_path("../scubagear/results.json")

    def test_rejects_bare_dotdot(self) -> None:
        with pytest.raises(ValueError, match="traversal"):
            validate_canonical_posix_path("..")

    # -- Colon rejection --

    def test_rejects_colon_in_segment(self) -> None:
        with pytest.raises(ValueError, match="colon"):
            validate_canonical_posix_path("C:/scubagear/results.json")

    def test_rejects_colon_in_filename(self) -> None:
        with pytest.raises(ValueError, match="colon"):
            validate_canonical_posix_path("scubagear/file:alt.json")

    # -- Round-trip normalization --

    def test_rejects_double_slash(self) -> None:
        with pytest.raises(ValueError, match="canonical"):
            validate_canonical_posix_path("scubagear//results.json")

    def test_rejects_trailing_slash(self) -> None:
        with pytest.raises(ValueError, match="canonical"):
            validate_canonical_posix_path("scubagear/results.json/")

    def test_rejects_dot_segment(self) -> None:
        with pytest.raises(ValueError, match="canonical"):
            validate_canonical_posix_path("scubagear/./results.json")

    # -- Empty / trivial --

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            validate_canonical_posix_path("")

    def test_rejects_single_dot(self) -> None:
        with pytest.raises(ValueError, match="canonical"):
            validate_canonical_posix_path(".")

    # -- Windows reserved device names --

    def test_rejects_con_filename(self) -> None:
        with pytest.raises(ValueError, match="reserved"):
            validate_canonical_posix_path("scubagear/CON")

    def test_rejects_con_with_extension(self) -> None:
        with pytest.raises(ValueError, match="reserved"):
            validate_canonical_posix_path("scubagear/CON.json")

    def test_rejects_nul_case_insensitive(self) -> None:
        with pytest.raises(ValueError, match="reserved"):
            validate_canonical_posix_path("scubagear/nul")

    def test_rejects_com1(self) -> None:
        with pytest.raises(ValueError, match="reserved"):
            validate_canonical_posix_path("com1/results.json")

    def test_rejects_lpt9(self) -> None:
        with pytest.raises(ValueError, match="reserved"):
            validate_canonical_posix_path("scubagear/LPT9.txt")

    def test_rejects_prn(self) -> None:
        with pytest.raises(ValueError, match="reserved"):
            validate_canonical_posix_path("PRN")

    def test_rejects_aux_with_extension(self) -> None:
        with pytest.raises(ValueError, match="reserved"):
            validate_canonical_posix_path("AUX.json")

    def test_allows_conventional_prefix(self) -> None:
        """'conclusion.json' is NOT a reserved name even though it starts with 'con'."""
        validate_canonical_posix_path("scubagear/conclusion.json")

    # -- Trailing dots / spaces --

    def test_rejects_trailing_dot_in_segment(self) -> None:
        with pytest.raises(ValueError, match="trailing"):
            validate_canonical_posix_path("scubagear/results.")

    def test_rejects_trailing_space_in_segment(self) -> None:
        with pytest.raises(ValueError, match="trailing"):
            validate_canonical_posix_path("scubagear/results ")

    # -- Illegal Windows characters --

    def test_rejects_angle_brackets(self) -> None:
        with pytest.raises(ValueError, match="illegal"):
            validate_canonical_posix_path("scubagear/<results>.json")

    def test_rejects_pipe(self) -> None:
        with pytest.raises(ValueError, match="illegal"):
            validate_canonical_posix_path("scubagear/results|alt.json")

    def test_rejects_question_mark(self) -> None:
        with pytest.raises(ValueError, match="illegal"):
            validate_canonical_posix_path("scubagear/results?.json")

    def test_rejects_asterisk(self) -> None:
        with pytest.raises(ValueError, match="illegal"):
            validate_canonical_posix_path("scubagear/results*.json")

    def test_rejects_double_quote(self) -> None:
        with pytest.raises(ValueError, match="illegal"):
            validate_canonical_posix_path('scubagear/"results".json')
