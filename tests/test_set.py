"""
Tests for the SET type, which holds a list of x690 values like Sequence.
"""

import gc
from collections.abc import Callable
from typing import Any

import pytest

import x690.types
from x690 import decode
from x690.exc import UnexpectedType
from x690.types import (
    Boolean,
    Explicit,
    Integer,
    OctetString,
    Sequence,
    Set,
)
from x690.util import TypeClass, TypeNature

REFERENCE = b"\x31\x06\x02\x01\x01\x01\x01\xff"


def test_construction_encodes_in_given_order() -> None:
    """
    Ensure a Set encodes its items in the given order, without sorting.
    """
    value = Set([Integer(1), Boolean(True)])
    assert bytes(value) == b"\x31\x06\x02\x01\x01\x01\x01\x01"
    assert bytes(Set([Boolean(True), Integer(1)]))[2] == 0x01


def test_decode() -> None:
    """
    Ensure a Set decodes to a Set of its items, in their encoded order.
    """
    value, _ = decode(REFERENCE)
    assert type(value) is Set
    assert value.value == [Integer(1), Boolean(True)]
    assert value.pythonize() == [1, True]
    assert bytes(value) == REFERENCE


def test_empty() -> None:
    """
    Ensure an empty Set encodes and decodes.
    """
    assert bytes(Set()) == b"\x31\x00"
    value, _ = decode(b"\x31\x00")
    assert len(value) == 0
    assert value.value == []


def count_header_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[], int]:
    """
    Count the calls of ``get_value_slice`` made from now on.

    :return: A function returning the number of calls so far.
    """
    calls = 0
    original = x690.types.get_value_slice

    def counting(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(x690.types, "get_value_slice", counting)
    return lambda: calls


def test_lazy_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure a decoded Set finds its item offsets only on access, and
    supports len, indexing, slicing and iteration.
    """
    calls = count_header_reads(monkeypatch)
    value, _ = decode(REFERENCE)
    after_decode = calls()
    assert len(value) == 2
    after_len = calls()
    assert after_len == after_decode + 2
    assert len(value) == 2
    assert calls() == after_len
    assert value[0] == Integer(1)
    assert value[-1] == Boolean(True)
    assert value[0:1] == [Integer(1)]
    assert list(value) == [Integer(1), Boolean(True)]
    with pytest.raises(IndexError):
        value[2]


def test_child_types() -> None:
    """
    Ensure a Set subclass resolves context-specific items with
    CHILD_TYPES.
    """

    class Label(OctetString):
        TYPECLASS = TypeClass.CONTEXT
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 0

    class Labels(Set):
        CHILD_TYPES = [Label]

    data = b"\x31\x05\x80\x03abc"
    plain, _ = decode(data)
    assert type(plain[0]).__name__ == "UnknownType"
    value, _ = decode(data, types=[Labels])
    assert type(value) is Labels
    assert value[0] == Label(b"abc")
    assert type(value[0]) is Label
    assert repr(value) == "Labels([Label(b'abc')])"


def test_explicit_set() -> None:
    """
    Ensure an explicitly tagged Set decodes to the wrapper and its Set.
    """

    class Wrapped(Explicit[Set]):
        TAG = 1

    data = b"\xa1\x05" + b"\x31\x03\x02\x01\x07"
    value, _ = decode(data, types=[Wrapped])
    assert value.value == Set([Integer(7)])
    assert bytes(Wrapped(Set([Integer(7)]))) == data


def test_detach() -> None:
    """
    Ensure a detached Set keeps working on its own copy of the bytes.
    """
    data = b"junk" + REFERENCE + bytes(100)
    value, _ = decode(data, 4)
    assert len(value) == 2
    assert any(ref is data for ref in gc.get_referents(value))
    assert value.detach() is value
    assert not any(ref is data for ref in gc.get_referents(value))
    assert value.raw_bytes == REFERENCE[2:]
    assert list(value) == [Integer(1), Boolean(True)]


def test_repr_and_pretty() -> None:
    """
    Ensure repr and pretty name the Set class.
    """
    assert repr(Set([Integer(1)])) == "Set([Integer(1)])"
    assert Set([Integer(1)]).pretty().startswith("Set with 1 items:")


def test_equality() -> None:
    """
    Ensure Sets compare by their encoding and never equal a Sequence with
    the same items.
    """
    assert Set([Integer(1)]) == decode(b"\x31\x03\x02\x01\x01")[0]
    assert Set([Integer(1)]) != Set([Integer(2)])
    assert Set([Integer(1)]) != Sequence([Integer(1)])
    assert Sequence([Integer(1)]) != Set([Integer(1)])
    assert Set() != object()


def test_not_a_sequence() -> None:
    """
    Ensure Set and Sequence are separate types for isinstance and
    enforce_type.
    """
    value, _ = decode(REFERENCE, enforce_type=Set)
    assert not isinstance(value, Sequence)
    assert not isinstance(Sequence(), Set)
    with pytest.raises(UnexpectedType):
        decode(REFERENCE, enforce_type=Sequence)
    with pytest.raises(UnexpectedType):
        decode(b"\x30\x00", enforce_type=Set)
