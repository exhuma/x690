"""
Tests for the own-bytes semantics of ``raw_bytes`` and for ``detach()``.
"""

import gc

from x690 import decode
from x690.types import Integer, OctetString, Sequence


def test_raw_bytes_is_own_content_only() -> None:
    """
    Ensure raw_bytes of a value decoded from the middle of a larger buffer
    contains only the value's own content bytes.
    """
    data = b"header\x04\x03abctrailer"
    value, _ = decode(data, 6)
    assert value.raw_bytes == b"abc"
    assert value.length == 3


def test_raw_bytes_setter_sets_own_bytes() -> None:
    """
    Ensure assigning raw_bytes makes the given bytes the value's content.
    """
    value = Integer()
    value.raw_bytes = b"\x05"
    assert value.raw_bytes == b"\x05"
    assert value.value == 5
    assert value.length == 1


def test_non_minimal_integer_keeps_encoding() -> None:
    """
    Ensure a decoded non-minimal INTEGER keeps its original bytes, also
    after detach().
    """
    value, _ = decode(b"\x02\x02\x00\x05")
    assert bytes(value) == b"\x02\x02\x00\x05"
    value.detach()
    assert bytes(value) == b"\x02\x02\x00\x05"
    assert value.value == 5


def test_detach_returns_instance_and_drops_buffer() -> None:
    """
    Ensure detach() returns the instance, keeps its observable state and
    drops the reference to the input buffer.
    """
    data = b"header\x04\x03abctrailer"
    value, _ = decode(data, 6)
    expected, _ = decode(data, 6)
    assert any(ref is data for ref in gc.get_referents(value)) is True
    result = value.detach()
    assert result is value
    assert value.value == b"abc"
    assert value.raw_bytes == b"abc"
    assert bytes(value) == b"\x04\x03abc"
    assert value == expected
    assert not any(ref is data for ref in gc.get_referents(value))


def test_detached_sequence_keeps_working() -> None:
    """
    Ensure a detached decoded Sequence still indexes, iterates and has the
    right length.
    """
    data = b"xx\x30\x0b\x02\x01\x01\x04\x03foo\x02\x01\x03yy"
    sequence, _ = decode(data, 2)
    assert isinstance(sequence, Sequence)
    assert len(sequence) == 3
    assert sequence[1] == OctetString(b"foo")
    sequence.detach()
    assert not any(ref is data for ref in gc.get_referents(sequence))
    assert len(sequence) == 3
    assert sequence[0] == Integer(1)
    assert sequence[-1] == Integer(3)
    assert list(sequence) == [Integer(1), OctetString(b"foo"), Integer(3)]
    assert bytes(sequence) == data[2:-2]


def test_detach_of_constructed_value_is_noop() -> None:
    """
    Ensure detach() on a value built from a Python object does nothing and
    returns the instance.
    """
    value = Integer(5)
    assert value.detach() is value
    assert value.value == 5
    assert bytes(value) == b"\x02\x01\x05"
    sequence = Sequence([Integer(1)])
    assert sequence.detach() is sequence
    assert len(sequence) == 1
