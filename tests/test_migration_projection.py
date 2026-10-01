"""Projection comparison preserves JSON semantics without normalizing evidence bytes."""

from traust_engine.corpus.migration_projection import _row_key


def test_object_order_and_equivalent_json_numbers_compare_equal() -> None:
    assert _row_key({"a": 1, "b": [2.0]}) == _row_key({"b": [2], "a": 1.0})


def test_null_absence_boolean_and_array_order_remain_distinct() -> None:
    assert _row_key({"a": None}) != _row_key({})
    assert _row_key({"a": True}) != _row_key({"a": 1})
    assert _row_key({"a": "1"}) != _row_key({"a": 1})
    assert _row_key([1, 2]) != _row_key([2, 1])
    assert _row_key([1, 1]) != _row_key([1])


def test_large_integer_comparison_does_not_round() -> None:
    assert _row_key(10**80 + 1) != _row_key(10**80)
