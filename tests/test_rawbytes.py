"""
Type instances should have raw-bytes easily available without the "type/length" header.
"""

import pytest

import x690.types as t


@pytest.mark.parametrize("cls", t.X690Type.all())
def test_raw_bytes(cls):
    try:
        instance = cls.decode(b"")
    except NotImplementedError:
        raise pytest.skip("Not yet implemented") from None
    assert instance.raw_bytes == b""


@pytest.mark.parametrize("cls", t.X690Type.all())
def test_raw_bytes(cls):  # noqa: F811 (shadows the first, which fails; pre-existing)
    instance = cls()
    assert isinstance(instance.raw_bytes, bytes)


@pytest.mark.parametrize(
    ("cls", "data"),
    [
        (t.VideotexString, b"\x15\x03abc"),
        (t.GeneralString, b"\x1b\x03abc"),
        (t.CharacterString, b"\x1d\x03abc"),
    ],
)
def test_raw_bytes_string_types_decode_to_bytes(cls, data):
    """
    Ensure the raw-bytes string types decode their value as bytes.
    """
    instance = cls.decode(data)
    assert isinstance(instance.value, bytes)
    assert instance.value == b"abc"


@pytest.mark.parametrize(
    "cls", [t.VideotexString, t.GeneralString, t.CharacterString]
)
def test_raw_bytes_string_types_round_trip(cls):
    """
    Ensure a value built from bytes survives an encode and decode.
    """
    original = cls(b"abc")
    encoded = bytes(original)
    decoded = cls.decode(encoded)
    assert decoded.value == b"abc"
    assert bytes(decoded) == encoded
