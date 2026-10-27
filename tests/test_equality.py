"""
Equality of values: the same class and the same value.
"""

from datetime import datetime

import pytest

from x690 import decode
from x690.types import (
    Bits,
    BitString,
    Boolean,
    Enumerated,
    GeneralizedTime,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    PrintableString,
    Real,
    RelativeOid,
    Sequence,
    Set,
    T61String,
    UnknownType,
    Utf8String,
    X690Type,
)
from x690.util import TypeClass


class Request(Sequence):
    TYPECLASS = TypeClass.CONTEXT
    TAG = 0


class Label(PrintableString):
    pass


class Number(Integer):
    pass


def test_subclass_differs_from_base() -> None:
    """
    Ensure a subclass never equals its base class with the same value.
    """
    assert Label("a") != PrintableString("a")
    assert PrintableString("a") != Label("a")
    assert Number(1) != Integer(1)
    assert Integer(1) != Number(1)
    assert Label("a") == Label("a")


def test_context_sequence_differs_from_plain_sequence() -> None:
    """
    Ensure a context-class Sequence subclass differs from a plain Sequence.
    """
    assert Request([Integer(1)]) != Sequence([Integer(1)])
    assert Sequence([Integer(1)]) != Request([Integer(1)])
    assert Request([Integer(1)]) == Request([Integer(1)])


def test_set_differs_from_sequence() -> None:
    """
    Ensure a Set never equals a Sequence with the same items.
    """
    assert Set([Integer(1)]) != Sequence([Integer(1)])
    assert Sequence([Integer(1)]) != Set([Integer(1)])


@pytest.mark.parametrize(
    "value",
    [
        Boolean(True),
        Null(),
        OctetString(b"abc"),
        Integer(300),
        Enumerated(2),
        Real(1.5),
        ObjectIdentifier("1.3.6.1"),
        RelativeOid("8571.3"),
        BitString(Bits.from_bin("101")),
        Utf8String("café"),
        T61String("abc"),
        GeneralizedTime(datetime(2024, 1, 2, 3, 4, 5)),
        Sequence([Integer(1), Boolean(True)]),
        Set([Integer(1), Boolean(True)]),
    ],
    ids=lambda value: type(value).__name__,
)
def test_decoded_equals_constructed(value: X690Type) -> None:
    """
    Ensure a decoded value equals the constructed one of the same class.
    """
    decoded, _ = decode(bytes(value))
    assert decoded == value
    assert value == decoded
    assert decoded != object()


def test_integer_and_enumerated_differ() -> None:
    """
    Ensure values of different classes with equal content differ.
    """
    assert Integer(2) != Enumerated(2)
    assert RelativeOid("1") != ObjectIdentifier("1")


def test_unknown_types_compare_tag_and_value() -> None:
    """
    Ensure unknown values are equal only with the same tag and value.
    """
    assert UnknownType(b"a", 0x99) == UnknownType(b"a", 0x99)
    assert UnknownType(b"a", 0x99) != UnknownType(b"a", 0x9A)
    assert UnknownType(b"a", 0x99) != UnknownType(b"b", 0x99)
    assert UnknownType(b"a", 0x99) != OctetString(b"a")


def test_converted_types_are_unhashable() -> None:
    """
    Ensure values compared by value cannot be hashed.
    """
    for value in (Utf8String("a"), Sequence(), Real(1.0), Enumerated(1)):
        with pytest.raises(TypeError):
            hash(value)


def test_object_identifier_hash_matches_equality() -> None:
    """
    Ensure equal object identifiers have equal hashes.
    """
    assert hash(ObjectIdentifier("1.2.3")) == hash(ObjectIdentifier("1.2.3"))
