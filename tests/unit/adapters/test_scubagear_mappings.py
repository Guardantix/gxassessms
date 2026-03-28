"""Tests for ScubaGear declarative mappings (SEVERITY_MAP, CATEGORY_MAP, DEDUP_KEY_RULES).

These are pure-data tests -- no logic, just structure and correctness checks.
The fixture-driven tests verify that every non-trivial (Criticality, Result) pair
and every module name present in the real ScubaGear output is covered.

Imports of domain enums are deferred into fixtures to avoid the circular import
between gxassessms.core.domain and gxassessms.core.contracts at collection time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants (no domain-enum imports at module level)
# ---------------------------------------------------------------------------

FIXTURE_PATH: Path = (
    Path(__file__).parents[3]
    / "src"
    / "gxassessms"
    / "adapters"
    / "scubagear"
    / "fixtures"
    / "ScubaResults.json"
)

# Pairs intentionally absent from SEVERITY_MAP because
# DefaultNormalizationPolicy._resolve_severity() short-circuits PASS and
# NOT_APPLICABLE statuses to INFO before consulting the adapter severity map.
_PASS_RESULT = "Pass"
_STANDARD_NA_CRITICALITIES = frozenset({"Shall/3rd Party", "Should/3rd Party"})


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _load_fixture_pairs() -> set[tuple[str, str]]:
    """Return all (Criticality, Result) pairs found in the fixture."""
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    pairs: set[tuple[str, str]] = set()
    for module_groups in data["Results"].values():
        for group in module_groups:
            for control in group["Controls"]:
                pairs.add((control["Criticality"], control["Result"]))
    return pairs


def _load_fixture_modules() -> set[str]:
    """Return all module keys (as-is) found in the fixture Results."""
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return set(data["Results"].keys())


# ---------------------------------------------------------------------------
# Import tests (trigger ImportError if module doesn't exist yet)
# ---------------------------------------------------------------------------


class TestImport:
    def test_mappings_module_importable(self) -> None:
        from gxassessms.adapters.scubagear import mappings  # noqa: F401

    def test_severity_map_exported(self) -> None:
        from gxassessms.adapters.scubagear.mappings import SEVERITY_MAP

        assert SEVERITY_MAP is not None

    def test_category_map_exported(self) -> None:
        from gxassessms.adapters.scubagear.mappings import CATEGORY_MAP

        assert CATEGORY_MAP is not None

    def test_dedup_key_rules_exported(self) -> None:
        from gxassessms.adapters.scubagear.mappings import DEDUP_KEY_RULES

        assert DEDUP_KEY_RULES is not None


# ---------------------------------------------------------------------------
# SEVERITY_MAP
# ---------------------------------------------------------------------------


class TestSeverityMap:
    @pytest.fixture(autouse=True)
    def _import_maps(self) -> None:
        from gxassessms.adapters.scubagear.mappings import SEVERITY_MAP
        from gxassessms.core.domain.enums import Severity

        self.map = SEVERITY_MAP
        self.Severity = Severity

    def test_is_dict(self) -> None:
        assert isinstance(self.map, dict)

    def test_keys_are_str_tuples(self) -> None:
        for key in self.map:
            assert isinstance(key, tuple), f"Key {key!r} is not a tuple"
            assert len(key) == 2, f"Key {key!r} does not have length 2"
            assert isinstance(key[0], str), f"Key[0] {key[0]!r} is not str"
            assert isinstance(key[1], str), f"Key[1] {key[1]!r} is not str"

    def test_values_are_severity(self) -> None:
        for key, val in self.map.items():
            assert isinstance(val, self.Severity), f"Value for {key!r} is not Severity: {val!r}"

    # --- known mappings ---

    def test_shall_fail_is_critical(self) -> None:
        assert self.map[("Shall", "Fail")] == self.Severity.CRITICAL

    def test_shall_warning_is_high(self) -> None:
        assert self.map[("Shall", "Warning")] == self.Severity.HIGH

    def test_should_fail_is_high(self) -> None:
        assert self.map[("Should", "Fail")] == self.Severity.HIGH

    def test_should_warning_is_medium(self) -> None:
        assert self.map[("Should", "Warning")] == self.Severity.MEDIUM

    def test_shall_3rd_party_fail_is_high(self) -> None:
        assert self.map[("Shall/3rd Party", "Fail")] == self.Severity.HIGH

    def test_should_3rd_party_fail_is_medium(self) -> None:
        assert self.map[("Should/3rd Party", "Fail")] == self.Severity.MEDIUM

    def test_shall_3rd_party_warning_is_medium(self) -> None:
        assert self.map[("Shall/3rd Party", "Warning")] == self.Severity.MEDIUM

    def test_should_3rd_party_warning_is_low(self) -> None:
        assert self.map[("Should/3rd Party", "Warning")] == self.Severity.LOW

    def test_shall_not_implemented_na_is_high(self) -> None:
        assert self.map[("Shall/Not-Implemented", "N/A")] == self.Severity.HIGH

    def test_should_not_implemented_na_is_medium(self) -> None:
        assert self.map[("Should/Not-Implemented", "N/A")] == self.Severity.MEDIUM

    # --- fixture coverage ---

    def test_all_fixture_pairs_that_need_mapping_are_present(self) -> None:
        """Every (Criticality, Result) pair from the fixture that should have a
        non-INFO severity must appear as a key in SEVERITY_MAP."""
        all_pairs = _load_fixture_pairs()
        must_be_mapped = {
            (crit, result)
            for crit, result in all_pairs
            if result != _PASS_RESULT
            and not (result == "N/A" and crit in _STANDARD_NA_CRITICALITIES)
        }
        missing = must_be_mapped - set(self.map.keys())
        assert not missing, f"Fixture pairs not covered by SEVERITY_MAP: {missing!r}"


# ---------------------------------------------------------------------------
# CATEGORY_MAP
# ---------------------------------------------------------------------------


class TestCategoryMap:
    @pytest.fixture(autouse=True)
    def _import_maps(self) -> None:
        from gxassessms.adapters.scubagear.mappings import CATEGORY_MAP
        from gxassessms.core.domain.enums import Category

        self.map = CATEGORY_MAP
        self.Category = Category

    def test_is_dict(self) -> None:
        assert isinstance(self.map, dict)

    def test_keys_are_lowercase_strings(self) -> None:
        for key in self.map:
            assert isinstance(key, str), f"Key {key!r} is not str"
            assert key == key.lower(), f"Key {key!r} is not lowercase"

    def test_values_are_category(self) -> None:
        for key, val in self.map.items():
            assert isinstance(val, self.Category), f"Value for {key!r} is not Category: {val!r}"

    # --- known mappings ---

    def test_aad_maps_to_identity_access(self) -> None:
        assert self.map["aad"] == self.Category.IDENTITY_ACCESS

    def test_entra_alias_maps_to_identity_access(self) -> None:
        assert self.map["entra"] == self.Category.IDENTITY_ACCESS

    def test_exo_maps_to_email_collaboration(self) -> None:
        assert self.map["exo"] == self.Category.EMAIL_COLLABORATION

    def test_sharepoint_maps_to_data_protection(self) -> None:
        assert self.map["sharepoint"] == self.Category.DATA_PROTECTION

    def test_teams_maps_to_email_collaboration(self) -> None:
        assert self.map["teams"] == self.Category.EMAIL_COLLABORATION

    def test_defender_maps_to_email_collaboration(self) -> None:
        assert self.map["defender"] == self.Category.EMAIL_COLLABORATION

    def test_powerplatform_maps_to_application_security(self) -> None:
        assert self.map["powerplatform"] == self.Category.APPLICATION_SECURITY

    # --- fixture coverage ---

    def test_all_fixture_modules_have_category_entry(self) -> None:
        """Every module key in the fixture must appear (lowercased) in CATEGORY_MAP."""
        fixture_modules = _load_fixture_modules()
        missing = {m for m in fixture_modules if m.lower() not in self.map}
        assert not missing, f"Fixture modules not covered by CATEGORY_MAP: {missing!r}"


# ---------------------------------------------------------------------------
# DEDUP_KEY_RULES
# ---------------------------------------------------------------------------


class TestDedupKeyRules:
    @pytest.fixture(autouse=True)
    def _import_maps(self) -> None:
        from gxassessms.adapters.scubagear.mappings import DEDUP_KEY_RULES

        self.rules = DEDUP_KEY_RULES

    def test_is_dict(self) -> None:
        assert isinstance(self.rules, dict)

    def test_keys_start_with_ms_dot(self) -> None:
        for key in self.rules:
            assert key.startswith("MS."), f"Key {key!r} does not start with 'MS.'"

    def test_values_are_namespaced(self) -> None:
        for key, val in self.rules.items():
            assert ":" in val, f"Value for {key!r} is not namespaced (no ':'): {val!r}"

    def test_values_use_cis_m365_namespace(self) -> None:
        for key, val in self.rules.items():
            assert val.startswith("cis:m365:"), (
                f"Value for {key!r} does not use 'cis:m365:' namespace: {val!r}"
            )

    # --- known mappings ---

    def test_ms_aad_1_1v1_block_legacy_auth(self) -> None:
        assert self.rules["MS.AAD.1.1v1"] == "cis:m365:1.1.4"

    def test_ms_aad_3_4v1(self) -> None:
        assert self.rules["MS.AAD.3.4v1"] == "cis:m365:1.1.1"

    def test_ms_exo_1_1v2_auto_forwarding(self) -> None:
        assert self.rules["MS.EXO.1.1v2"] == "cis:m365:2.1.4"

    def test_ms_exo_2_2v2_spf(self) -> None:
        assert self.rules["MS.EXO.2.2v2"] == "cis:m365:2.1.2"

    def test_ms_exo_3_1v1_dkim(self) -> None:
        assert self.rules["MS.EXO.3.1v1"] == "cis:m365:2.1.1"

    def test_has_at_least_five_entries(self) -> None:
        assert len(self.rules) >= 5
