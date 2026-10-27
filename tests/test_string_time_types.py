"""
Tests for the text, time and enumerated types that hold Python values.
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest

import x690.types as t
from x690 import decode


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag, len(content)]) + content


TEXT_CASES = [
    (t.Utf8String, 0x0C, "hé 日", "hé 日".encode()),
    (t.NumericString, 0x12, "12 34", b"12 34"),
    (t.PrintableString, 0x13, "Ab 1'()+,-./:=?", b"Ab 1'()+,-./:=?"),
    (t.IA5String, 0x16, "a@b.c~", b"a@b.c~"),
    (t.VisibleString, 0x1A, "hello", b"hello"),
    (t.ObjectDescriptor, 0x07, "desc", b"desc"),
    (t.BmpString, 0x1E, "aé日", b"\x00a\x00\xe9\x65\xe5"),
    (
        t.UniversalString,
        0x1C,
        "a\U0001f600",
        b"\x00\x00\x00a\x00\x01\xf6\x00",
    ),
]


@pytest.mark.parametrize("cls,tag,value,content", TEXT_CASES)
def test_text_round_trip(cls, tag, value, content):
    """
    Ensure text types encode to the reference bytes and decode back to
    the same str.
    """
    reference = _tlv(tag, content)
    assert bytes(cls(value)) == reference
    decoded, _ = decode(reference)
    assert type(decoded) is cls
    assert decoded.value == value
    assert decoded == cls(value)
    assert bytes(decoded) == reference


@pytest.mark.parametrize("cls,tag,value,content", TEXT_CASES)
def test_text_empty_and_noarg(cls, tag, value, content):
    """
    Ensure an empty string encodes to empty content and the no-argument
    constructor encodes to nothing as well.
    """
    assert bytes(cls("")) == bytes([tag, 0])
    assert cls().encode_raw() == b""
    assert cls("").value == ""


def test_text_equality_is_per_type():
    """
    Ensure text values of different types never compare equal.
    """
    assert t.IA5String("a") != t.VisibleString("a")
    assert t.IA5String("a") != "a"


@pytest.mark.parametrize(
    "cls,content",
    [
        (t.Utf8String, b"\xff\xfe"),
        (t.IA5String, b"caf\xc3\xa9"),
        (t.VisibleString, b"\x80"),
        (t.NumericString, b"\xe9"),
        (t.PrintableString, b"\xe9"),
        (t.ObjectDescriptor, b"\xe9"),
        (t.BmpString, b"\x00a\x00"),
        (t.UniversalString, b"\x00\x00\x00"),
    ],
)
def test_text_invalid_bytes(cls, content):
    """
    Ensure invalid bytes raise UnicodeDecodeError instead of returning
    bytes.
    """
    with pytest.raises(UnicodeDecodeError):
        _ = cls.from_bytes(content).value


@pytest.mark.parametrize(
    "cls", [t.IA5String, t.VisibleString, t.ObjectDescriptor]
)
def test_ascii_types_reject_non_ascii_on_encode(cls):
    """
    Ensure ASCII types refuse characters outside of ASCII.
    """
    with pytest.raises(UnicodeEncodeError):
        bytes(cls("café"))


def test_bmp_rejects_astral_characters_free_surrogates():
    """
    Ensure a lone surrogate cannot be encoded as BMPString.
    """
    with pytest.raises(UnicodeEncodeError):
        bytes(t.BmpString("\ud800"))


def test_numeric_string_lenient_decode_strict_encode():
    """
    Ensure NumericString decodes any ASCII but encodes only digits and
    spaces.
    """
    assert t.NumericString.from_bytes(b"12a").value == "12a"
    for bad in ["12a", "1-2", "٣"]:
        with pytest.raises(ValueError, match="NumericString"):
            bytes(t.NumericString(bad))


def test_printable_string_lenient_decode_strict_encode():
    """
    Ensure PrintableString decodes any ASCII but encodes only its
    alphabet.
    """
    assert t.PrintableString.from_bytes(b"a@b_c").value == "a@b_c"
    for bad in ["a@b", "a_b", "a*b", "é", "a\nb"]:
        with pytest.raises(ValueError, match="PrintableString"):
            bytes(t.PrintableString(bad))


# UtcTime


@pytest.mark.parametrize(
    "content,expected",
    [
        (b"251026120000Z", datetime(2025, 10, 26, 12, 0, tzinfo=UTC)),
        (b"2510261200Z", datetime(2025, 10, 26, 12, 0, tzinfo=UTC)),
        (b"491231235959Z", datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC)),
        (b"500101000000Z", datetime(1950, 1, 1, tzinfo=UTC)),
        (b"990101000000Z", datetime(1999, 1, 1, tzinfo=UTC)),
        (b"000101000000Z", datetime(2000, 1, 1, tzinfo=UTC)),
        (
            b"251026120000+0130",
            datetime(
                2025,
                10,
                26,
                12,
                tzinfo=timezone(timedelta(hours=1, minutes=30)),
            ),
        ),
        (
            b"2510261200-0500",
            datetime(2025, 10, 26, 12, tzinfo=timezone(-timedelta(hours=5))),
        ),
    ],
)
def test_utc_time_decode(content, expected):
    """
    Ensure UtcTime decodes real-world shapes, the two-digit-year rule and
    offsets into aware datetimes.
    """
    value = decode(_tlv(0x17, content))[0].value
    assert value == expected
    assert value.utcoffset() == expected.utcoffset()


def test_utc_time_reference():
    """
    Ensure the documented example decodes as expected.
    """
    value, _ = decode(b"\x17\x0d251026120000Z")
    assert value.value == datetime(2025, 10, 26, 12, 0, tzinfo=UTC)


def test_utc_time_encode():
    """
    Ensure UtcTime encodes aware datetimes as UTC with seconds and Z.
    """
    moment = datetime(2025, 10, 26, 12, 0, tzinfo=UTC)
    assert bytes(t.UtcTime(moment)) == b"\x17\x0d251026120000Z"
    plus_two = timezone(timedelta(hours=2))
    local = datetime(2025, 10, 26, 14, 0, 5, tzinfo=plus_two)
    assert bytes(t.UtcTime(local)) == b"\x17\x0d251026120005Z"
    assert bytes(t.UtcTime(datetime(1950, 1, 1, tzinfo=UTC))) == (
        b"\x17\x0d500101000000Z"
    )
    assert bytes(t.UtcTime(datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC))) == (
        b"\x17\x0d491231235959Z"
    )


def test_utc_time_encode_drops_fractions():
    """
    Ensure sub-second precision is dropped, since UTCTime has none.
    """
    moment = datetime(2025, 10, 26, 12, 0, 1, 999999, tzinfo=UTC)
    assert bytes(t.UtcTime(moment)) == b"\x17\x0d251026120001Z"


@pytest.mark.parametrize(
    "moment",
    [
        datetime(2025, 10, 26, 12, 0),
        datetime(1949, 12, 31, 23, 59, 59, tzinfo=UTC),
        datetime(2050, 1, 1, tzinfo=UTC),
    ],
)
def test_utc_time_encode_errors(moment):
    """
    Ensure naive datetimes and years outside 1950-2049 raise ValueError.
    """
    with pytest.raises(ValueError):
        bytes(t.UtcTime(moment))


def test_utc_time_year_range_uses_utc():
    """
    Ensure the year range is checked after conversion to UTC.
    """
    zone = timezone(timedelta(hours=-5))
    ok = datetime(2049, 12, 31, 20, 0, tzinfo=zone)  # 2050 in UTC
    with pytest.raises(ValueError):
        bytes(t.UtcTime(ok))


@pytest.mark.parametrize(
    "content",
    [
        b"251026120000",  # no zone
        b"25102612Z",
        b"251326120000Z",  # month 13
        b"251026126100Z",  # minute 61
        b"251026120000+2500",
        b"251026120000+0099",
        b"2510261200000Z",
        b"2510261200.5Z",
        b"",
        b"garbage",
    ],
)
def test_utc_time_invalid(content):
    """
    Ensure malformed UtcTime content raises ValueError.
    """
    with pytest.raises(ValueError, match="UtcTime|offset"):
        _ = t.UtcTime.from_bytes(content).value


def test_utc_time_non_ascii():
    """
    Ensure non-ASCII bytes raise UnicodeDecodeError.
    """
    with pytest.raises(UnicodeDecodeError):
        _ = t.UtcTime.from_bytes(b"\xff").value


def test_utc_time_noarg_and_equality():
    """
    Ensure the no-argument constructor works and equality compares values.
    """
    assert t.UtcTime().encode_raw() == b""
    moment = datetime(2025, 10, 26, 12, 0, tzinfo=UTC)
    assert t.UtcTime(moment) == t.UtcTime(moment)
    assert t.UtcTime(moment) != t.GeneralizedTime(moment)


# GeneralizedTime


@pytest.mark.parametrize(
    "content,expected",
    [
        (b"20251026120000Z", datetime(2025, 10, 26, 12, tzinfo=UTC)),
        (b"20251026120000", datetime(2025, 10, 26, 12)),
        (b"202510261200", datetime(2025, 10, 26, 12)),
        (b"2025102612", datetime(2025, 10, 26, 12)),
        (b"2025102612Z", datetime(2025, 10, 26, 12, tzinfo=UTC)),
        (
            b"20251026120000.123Z",
            datetime(2025, 10, 26, 12, 0, 0, 123000, tzinfo=UTC),
        ),
        (
            b"20251026120000,5",
            datetime(2025, 10, 26, 12, 0, 0, 500000),
        ),
        (
            b"20251026120000.1234567Z",
            datetime(2025, 10, 26, 12, 0, 0, 123456, tzinfo=UTC),
        ),
        (b"202510261200.5", datetime(2025, 10, 26, 12, 0, 30)),
        (b"2025102612.5", datetime(2025, 10, 26, 12, 30)),
        (
            b"20251026120000+0100",
            datetime(2025, 10, 26, 12, tzinfo=timezone(timedelta(hours=1))),
        ),
        (
            b"20251026120000-0530",
            datetime(
                2025,
                10,
                26,
                12,
                tzinfo=timezone(-timedelta(hours=5, minutes=30)),
            ),
        ),
        (
            b"2025102612+02",
            datetime(2025, 10, 26, 12, tzinfo=timezone(timedelta(hours=2))),
        ),
        (b"19991231235959Z", datetime(1999, 12, 31, 23, 59, 59, tzinfo=UTC)),
    ],
)
def test_generalized_time_decode(content, expected):
    """
    Ensure GeneralizedTime decodes optional parts, fractions and zones,
    with naive datetimes where no zone is given.
    """
    value = decode(_tlv(0x18, content))[0].value
    assert value == expected
    assert (value.tzinfo is None) == (expected.tzinfo is None)
    assert value.utcoffset() == expected.utcoffset()


@pytest.mark.parametrize(
    "moment,content",
    [
        (datetime(2025, 10, 26, 12, tzinfo=UTC), b"20251026120000Z"),
        (datetime(2025, 10, 26, 12), b"20251026120000"),
        (
            datetime(2025, 10, 26, 12, 0, 0, 500000, tzinfo=UTC),
            b"20251026120000.5Z",
        ),
        (
            datetime(2025, 10, 26, 12, 0, 0, 123456),
            b"20251026120000.123456",
        ),
        (
            datetime(2025, 10, 26, 12, 0, 0, 1000, tzinfo=UTC),
            b"20251026120000.001Z",
        ),
        (
            datetime(2025, 10, 26, 14, tzinfo=timezone(timedelta(hours=2))),
            b"20251026120000Z",
        ),
        (datetime(5, 1, 2), b"00050102000000"),
    ],
)
def test_generalized_time_encode(moment, content):
    """
    Ensure GeneralizedTime encodes aware values as UTC, naive values
    without a zone, and fractions without trailing zeros.
    """
    assert bytes(t.GeneralizedTime(moment)) == _tlv(0x18, content)


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"2025",
        b"20251026",
        b"202510261",
        b"20251326120000Z",
        b"20251026250000Z",
        b"20251026120060Z",
        b"20251026120000.Z",
        b"20251026120000+25",
        b"20251026120000+0160",
        b"20251026120000 Z",
        b"20251026120000ZZ",
    ],
)
def test_generalized_time_invalid(content):
    """
    Ensure malformed GeneralizedTime content raises ValueError.
    """
    with pytest.raises(ValueError, match="GeneralizedTime|offset"):
        _ = t.GeneralizedTime.from_bytes(content).value


def test_generalized_time_non_ascii():
    """
    Ensure non-ASCII bytes raise UnicodeDecodeError.
    """
    with pytest.raises(UnicodeDecodeError):
        _ = t.GeneralizedTime.from_bytes(b"\xff").value


def test_generalized_time_noarg_and_equality():
    """
    Ensure the no-argument constructor works and equality compares values.
    """
    assert t.GeneralizedTime().encode_raw() == b""
    moment = datetime(2025, 10, 26, 12)
    assert t.GeneralizedTime(moment) == t.GeneralizedTime(moment)
    assert t.GeneralizedTime(moment) != t.UtcTime(moment)


# Enumerated


@pytest.mark.parametrize(
    "value,content",
    [
        (0, b"\x00"),
        (5, b"\x05"),
        (127, b"\x7f"),
        (128, b"\x00\x80"),
        (-1, b"\xff"),
        (-128, b"\x80"),
        (-129, b"\xff\x7f"),
        (2**64, b"\x01" + bytes(8)),
        (-(2**64), b"\xff" + bytes(8)),
    ],
)
def test_enumerated_round_trip(value, content):
    """
    Ensure Enumerated uses the two's-complement encoding of Integer for
    small, negative and large values.
    """
    reference = _tlv(0x0A, content)
    assert bytes(t.Enumerated(value)) == reference
    assert bytes(t.Integer(value))[1:] == reference[1:]
    decoded, _ = decode(reference)
    assert type(decoded) is t.Enumerated
    assert decoded.value == value


def test_enumerated_misc():
    """
    Ensure Enumerated supports the no-argument constructor and equality
    only with other Enumerated values.
    """
    assert t.Enumerated().encode_raw() == b""
    assert t.Enumerated(3) == t.Enumerated(3)
    assert t.Enumerated(3) != t.Enumerated(4)
    assert t.Enumerated(3) != t.Integer(3)


# RelativeOid


@pytest.mark.parametrize(
    "value,content",
    [
        ("8571.3.2", b"\xc2\x7b\x03\x02"),
        ("0", b"\x00"),
        ("1.2", b"\x01\x02"),
        ("127.128", b"\x7f\x81\x00"),
        ("16384", b"\x81\x80\x00"),
        ("2097152.1", b"\x81\x80\x80\x00\x01"),
        ("", b""),
    ],
)
def test_relative_oid_round_trip(value, content):
    """
    Ensure RelativeOid encodes arcs in base 128 without folding the first
    two arcs.
    """
    reference = _tlv(0x0D, content)
    assert bytes(t.RelativeOid(value)) == reference
    decoded, _ = decode(reference)
    assert type(decoded) is t.RelativeOid
    assert decoded.value == value


def test_relative_oid_misc():
    """
    Ensure RelativeOid supports the no-argument constructor and equality.
    """
    assert t.RelativeOid().encode_raw() == b""
    assert t.RelativeOid("1.2") == t.RelativeOid("1.2")
    assert t.RelativeOid("1.2") != t.RelativeOid("1.3")
    assert t.RelativeOid("1.2") != t.ObjectIdentifier("1.2")


def test_relative_oid_truncated():
    """
    Ensure an incomplete last arc raises ValueError.
    """
    with pytest.raises(ValueError, match="Truncated"):
        _ = t.RelativeOid.from_bytes(b"\x01\x81").value


@pytest.mark.parametrize("value", ["1.-2", "a.b", "1..2", "-1"])
def test_relative_oid_invalid_value(value):
    """
    Ensure invalid arcs raise ValueError on encode.
    """
    with pytest.raises(ValueError):
        bytes(t.RelativeOid(value))


@pytest.mark.parametrize("cls", [t.UtcTime, t.GeneralizedTime])
def test_time_repr(cls):
    """
    Ensure repr() works for empty, valid and invalid time values.
    """
    assert repr(cls()) == cls.__name__ + "()"
    assert repr(cls(datetime(2025, 1, 1))) == (
        cls.__name__ + "(datetime.datetime(2025, 1, 1, 0, 0))"
    )
    assert repr(cls.from_bytes(b"bad")) == cls.__name__ + "(raw=b'bad')"
    good = cls.from_bytes(
        b"251026120000Z" if cls is t.UtcTime else b"2025102612"
    )
    assert cls.__name__ in repr(good)


def test_repr_of_invalid_text_shows_raw_bytes():
    """
    Ensure the repr of a decoded string with invalid content shows the raw
    bytes instead of raising.
    """
    value, _ = decode(b"\x0c\x02\xff\xfe")
    assert repr(value) == "Utf8String(raw=b'\\xff\\xfe')"


def test_object_identifier_truncated():
    """
    Ensure an incomplete last arc raises ValueError.
    """
    with pytest.raises(ValueError, match="Truncated"):
        _ = t.ObjectIdentifier.from_bytes(b"\x2b\x81").value
