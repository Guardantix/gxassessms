"""Property tests for decode_config_snapshot invariants."""

import json
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.persistence.engagement_repo import decode_config_snapshot

# Restrict text to JSON-encodable Unicode (exclude lone surrogates, which
# json.dumps refuses with UnicodeEncodeError and would escape the try/except
# as an unexpected exception type).
_json_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)))

_json_value = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        _json_text,
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(_json_text, children, max_size=5),
    ),
    max_leaves=10,
)


@given(
    st.one_of(
        st.none(),
        st.text(),
        st.integers(),
        st.booleans(),
        st.lists(st.integers()),
        st.dictionaries(st.text(), st.text()),
    )
)
def test_decode_always_dict_or_persistence_error(value: Any) -> None:
    """For any input value, decode returns dict[str, Any] OR raises PersistenceError."""
    row = {"config_snapshot": value}
    try:
        result = decode_config_snapshot(row)
    except PersistenceError:
        return  # expected failure mode
    assert isinstance(result, dict)


@given(_json_value)
def test_decode_of_json_serialized_values_is_stable(value: Any) -> None:
    """Decoding any JSON-serializable value (as its JSON string form)
    either round-trips through a dict or raises PersistenceError."""
    row = {"config_snapshot": json.dumps(value)}
    try:
        result = decode_config_snapshot(row)
    except PersistenceError:
        return
    # Only dicts survive decode; everything else should have raised
    assert isinstance(value, dict)
    assert result == value
