"""
Tests for the BIT STRING type and its value type Bits.
"""

import random

import pytest

from x690 import decode
from x690.types import Bits, BitString


def test_empty() -> None:
    """
    Ensure an empty bit string encodes with only the unused-bits octet and
    decodes to an empty value.
    """
    assert bytes(BitString(Bits())) == b"\x03\x01\x00"
    assert bytes(BitString()) == b"\x03\x01\x00"
    value, _ = decode(b"\x03\x01\x00")
    assert value.value == Bits()
    assert len(value.value) == 0
    assert str(value.value) == ""
    assert bytes(value.value) == b""
    assert list(value.value) == []


def test_empty_contents_decode_leniently() -> None:
    """
    Ensure contents without the unused-bits octet decode to an empty value.
    """
    value, _ = decode(b"\x03\x00")
    assert value.value == Bits()
    assert BitString().value == Bits()


def test_whole_bytes() -> None:
    """
    Ensure bytes such as key material encode with no unused bits and
    decode back to the same bytes.
    """
    reference = b"\x03\x03\x00\x01\x02"
    assert bytes(BitString(b"\x01\x02")) == reference
    assert bytes(BitString(Bits(b"\x01\x02"))) == reference
    value, _ = decode(reference)
    assert bytes(value.value) == b"\x01\x02"
    assert value.value.unused == 0
    assert len(value.value) == 16


def test_unused_bits() -> None:
    """
    Ensure a bit string with unused bits decodes to only its used bits.
    """
    value, _ = decode(b"\x03\x02\x04\xb0")
    bits = value.value
    assert bits == Bits.from_bin("1011")
    assert len(bits) == 4
    assert list(bits) == [True, False, True, True]
    assert str(bits) == "1011"
    assert bytes(value) == b"\x03\x02\x04\xb0"


def test_key_usage_flags() -> None:
    """
    Ensure KeyUsage-style flags read in ASN.1 bit order, with bits past the
    end of a DER-trimmed value reading as unset.
    """
    # digitalSignature (0) and keyEncipherment (2)
    value, _ = decode(b"\x03\x02\x05\xa0")
    bits = value.value
    assert bits[0] and not bits[1] and bits[2]
    assert bits.is_set(0)
    assert bits.is_set(2)
    assert not bits.is_set(1)
    assert not bits.is_set(5)
    assert not bits.is_set(8)


def test_key_usage_nine_bits() -> None:
    """
    Ensure a flag in the second octet (decipherOnly, bit 8) encodes
    with seven unused bits.
    """
    bits = Bits.from_bin("000000001")
    assert bytes(BitString(bits)) == b"\x03\x03\x07\x00\x80"
    assert bits.is_set(8)
    assert bits[-1]


def test_padding_bits_kept_but_ignored() -> None:
    """
    Ensure non-zero unused bits are accepted, kept for encoding and
    ignored by indexing, equality and hashing.
    """
    value, _ = decode(b"\x03\x02\x04\xbf")
    bits = value.value
    assert bits == Bits.from_bin("1011")
    assert hash(bits) == hash(Bits.from_bin("1011"))
    assert str(bits) == "1011"
    assert bits.data == b"\xbf"
    assert bytes(value) == b"\x03\x02\x04\xbf"


@pytest.mark.parametrize(
    "data",
    [b"\x03\x02\x08\x00", b"\x03\x02\xff\x00", b"\x03\x01\x03"],
)
def test_invalid_unused_count(data: bytes) -> None:
    """
    Ensure an unused-bits count above 7, or not 0 for an empty string,
    raises ValueError on decoding.
    """
    value, _ = decode(data)
    with pytest.raises(ValueError, match="Invalid BitString"):
        _ = value.value


@pytest.mark.parametrize("data,unused", [(b"", 1), (b"\x00", 8), (b"\x00", -1)])
def test_bits_validation(data: bytes, unused: int) -> None:
    """
    Ensure Bits rejects an unused count out of range or on empty data.
    """
    with pytest.raises(ValueError):
        Bits(data, unused)


def test_bits_from_bytearray() -> None:
    """
    Ensure Bits stores a bytearray as bytes.
    """
    bits = Bits(bytearray(b"\x01"))
    assert type(bits.data) is bytes


def test_from_bin_rejects_other_characters() -> None:
    """
    Ensure from_bin accepts only "0" and "1".
    """
    with pytest.raises(ValueError):
        Bits.from_bin("102")


def test_indexing() -> None:
    """
    Ensure indexing supports negative indices and raises IndexError out of
    range, and is_set rejects negative positions.
    """
    bits = Bits.from_bin("110")
    assert bits[-1] is False
    assert bits[-3] is True
    with pytest.raises(IndexError):
        bits[3]
    with pytest.raises(IndexError):
        bits[-4]
    with pytest.raises(ValueError):
        bits.is_set(-1)


def test_repr() -> None:
    """
    Ensure the repr shows the octets and the unused count.
    """
    assert repr(Bits(b"\x81")) == "Bits(b'\\x81')"
    assert repr(Bits.from_bin("101")) == "Bits(b'\\xa0', unused=5)"
    expected = "BitString(Bits(b'\\xa0', unused=5))"
    assert repr(BitString(Bits.from_bin("101"))) == expected


def test_equality() -> None:
    """
    Ensure values compare by their bits, and differ from other types.
    """
    assert Bits.from_bin("1") != Bits.from_bin("10")
    assert Bits(b"\x00") != Bits()
    assert Bits() != b""
    assert BitString(b"\x01") == BitString(Bits(b"\x01"))
    assert BitString(b"\x01") != BitString(b"\x02")
    assert BitString(b"\x01") != Bits(b"\x01")


def test_round_trip_random() -> None:
    """
    Ensure random bit strings survive an encode and decode unchanged.
    """
    generator = random.Random(0)
    for _ in range(500):
        size = generator.randrange(0, 41)
        text = "".join(generator.choice("01") for _ in range(size))
        bits = Bits.from_bin(text)
        assert len(bits) == size
        decoded, _ = decode(bytes(BitString(bits)))
        assert decoded.value == bits
        assert str(decoded.value) == text
        assert "".join("1" if bit else "0" for bit in decoded.value) == text
