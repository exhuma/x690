"""
Access to the items of a decoded sequence.
"""

import pytest

import x690.types
from x690.types import Integer, OctetString, Sequence, decode


@pytest.fixture
def items() -> list[x690.types.X690Type[object]]:
    return [Integer(1), OctetString(b"two"), Integer(3), Sequence([Integer(4)])]


@pytest.fixture
def decoded(items: list[x690.types.X690Type[object]]) -> Sequence:
    value, _ = decode(bytes(Sequence(items)), enforce_type=Sequence)
    return value


def test_index(decoded: Sequence, items: list[object]) -> None:
    """
    Ensure each index of a decoded sequence returns the encoded item.
    """
    assert [decoded[index] for index in range(len(items))] == items


def test_negative_index(decoded: Sequence, items: list[object]) -> None:
    """
    Ensure negative indexes count from the end.
    """
    assert decoded[-1] == items[-1]


def test_slice(decoded: Sequence, items: list[object]) -> None:
    """
    Ensure a slice returns a list of the selected items.
    """
    assert decoded[1:3] == items[1:3]


def test_index_out_of_range(decoded: Sequence) -> None:
    """
    Ensure an index past the end raises IndexError.
    """
    with pytest.raises(IndexError):
        decoded[4]


def test_len_and_iteration(decoded: Sequence, items: list[object]) -> None:
    """
    Ensure len() and iteration agree with the encoded items.
    """
    assert len(decoded) == len(items)
    assert list(decoded) == items


def test_value(decoded: Sequence, items: list[object]) -> None:
    """
    Ensure value is the list of items.
    """
    assert decoded.value == items


def test_empty() -> None:
    """
    Ensure an empty decoded sequence has no items.
    """
    value, _ = decode(b"\x30\x00", enforce_type=Sequence)
    assert len(value) == 0
    assert list(value) == []


def test_offset_into_buffer() -> None:
    """
    Ensure items are found when the sequence starts inside a larger buffer.
    """
    data = b"junk" + bytes(Sequence([Integer(1), Integer(2)])) + b"junk"
    value, _ = decode(data, 4, enforce_type=Sequence)
    assert value[1] == Integer(2)


def test_indexing_is_linear(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure reading every item by index reads each header a bounded number
    of times, instead of rescanning the sequence for every index.
    """
    size = 200
    data = bytes(Sequence([Integer(index) for index in range(size)]))
    value, _ = decode(data, enforce_type=Sequence)
    calls = 0
    original = x690.types.get_value_slice

    def counting(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(x690.types, "get_value_slice", counting)
    total = sum(value[index].value for index in range(len(value)))
    assert total == sum(range(size))
    assert calls <= 3 * size
