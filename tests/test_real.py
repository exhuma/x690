"""
Tests for the REAL type, which holds a float.
"""

import math
import random
import struct
import sys

import pytest

from x690 import decode
from x690.types import Real


def _bits(value: float) -> bytes:
    return struct.pack(">d", value)


DECODE_CASES = [
    # zero and the special values
    (b"", 0.0),
    (b"\x40", math.inf),
    (b"\x41", -math.inf),
    (b"\x43", -0.0),
    # binary, base 2
    (b"\x80\x00\x01", 1.0),
    (b"\xc0\x00\x05", -5.0),
    (b"\x80\x00\x01\x02", 258.0),
    (b"\x80\x00\x04", 4.0),
    (b"\x80\xff\x01", 0.5),
    (b"\xc0\x00\x00", -0.0),
    # binary, base 8 and 16
    (b"\x90\x01\x01", 8.0),
    (b"\x90\xfe\x01", 1 / 64),
    (b"\xa0\xff\x01", 0.0625),
    (b"\xa0\x02\x03", 768.0),
    # scaling factors
    (b"\x8c\x00\x01", 8.0),
    (b"\xa4\x01\x03", 96.0),
    (b"\xd8\x00\x01", -4.0),
    # two and three octet exponents
    (b"\x81\x01\x00\x01", 2.0**256),
    (b"\x82\xff\xfc\x00\x01", math.ldexp(1.0, -1024)),
    # long exponent form
    (b"\x83\x01\x05\x03", 96.0),
    (b"\x83\x04\x00\x00\x00\x03\x01", 8.0),
    # out of the float range
    (b"\x81\x7f\xff\x01", math.inf),
    (b"\xc1\x7f\xff\x01", -math.inf),
    (b"\x81\x80\x00\x01", 0.0),
    (b"\x81\x03\xff\xff", math.inf),
    (b"\x81\x04\x00\x01", math.inf),
    (b"\x81\x03\xca\x3f\xff\xff\xff\xff\xff\xff", math.inf),
    # decimal NR1
    (b"\x0142", 42.0),
    (b"\x01  -42", -42.0),
    (b"\x01+7", 7.0),
    # decimal NR2
    (b"\x023.25", 3.25),
    (b"\x02 -0,5", -0.5),
    (b"\x02.5", 0.5),
    (b"\x025.", 5.0),
    # decimal NR3
    (b"\x031.5E3", 1500.0),
    (b"\x03+1,25e-2", 0.0125),
    (b"\x03 -0.E+0", -0.0),
    (b"\x0312E1", 120.0),
]


@pytest.mark.parametrize("content,expected", DECODE_CASES)
def test_decode_reference(content: bytes, expected: float) -> None:
    """
    Ensure the reference contents of every REAL form decode to the
    expected float, sign of zero included.
    """
    value, _ = decode(bytes([0x09, len(content)]) + content)
    assert isinstance(value, Real)
    assert _bits(value.value) == _bits(expected)


def test_decode_nan() -> None:
    """
    Ensure the special value 0x42 decodes to NaN.
    """
    value, _ = decode(b"\x09\x01\x42")
    assert math.isnan(value.value)


def test_decode_rounds_long_mantissa() -> None:
    """
    Ensure a mantissa wider than a float rounds to the nearest float.
    """
    mantissa = (2**53 + 1).to_bytes(7, "big")
    assert Real.decode_raw(b"\x80\x00" + mantissa) == 2.0**53
    mantissa = (2**54 + 3).to_bytes(7, "big")
    assert Real.decode_raw(b"\x80\xfe" + mantissa) == (2**54 + 4) / 4


def test_decode_rounds_subnormal() -> None:
    """
    Ensure a binary value below the smallest normal float rounds
    correctly to a subnormal float.
    """
    content = b"\x81\xfb\xcd\x03"  # 3 * 2 ** -1075
    assert Real.decode_raw(content) == 2 * 5e-324


@pytest.mark.parametrize(
    "content,message",
    [
        (b"\x80", "too short"),
        (b"\x80\x01", "too short"),
        (b"\x81\x01", "too short"),
        (b"\xb0\x00\x01", "reserved"),
        (b"\x83", "exponent length"),
        (b"\x83\x00\x01", "exponent length"),
        (b"\x83\x02\x01\x01", "too short"),
        (b"\x44", "special value"),
        (b"\x40\x00", "special value"),
        (b"\x00", "decimal form 0"),
        (b"\x04 1", "decimal form 4"),
        (b"\x01", "NR1"),
        (b"\x011.5", "NR1"),
        (b"\x011 ", "NR1"),
        (b"\x021", "NR2"),
        (b"\x02.", "NR2"),
        (b"\x031.5", "NR3"),
        (b"\x031.5E", "NR3"),
        (b"\x01\xff", "NR1"),
    ],
)
def test_decode_malformed(content: bytes, message: str) -> None:
    """
    Ensure malformed REAL contents raise ValueError naming the problem.
    """
    with pytest.raises(ValueError, match=message):
        Real.decode_raw(content)


ENCODE_CASES = [
    (0.0, b""),
    (-0.0, b"\x43"),
    (math.inf, b"\x40"),
    (-math.inf, b"\x41"),
    (math.nan, b"\x42"),
    (1.0, b"\x80\x00\x01"),
    (-5.0, b"\xc0\x00\x05"),
    (0.5, b"\x80\xff\x01"),
    (6.0, b"\x80\x01\x03"),
    (2.0**300, b"\x81\x01\x2c\x01"),
    (5e-324, b"\x81\xfb\xce\x01"),
    (0.1, b"\x80\xc9\x0c\xcc\xcc\xcc\xcc\xcc\xcd"),
]


@pytest.mark.parametrize("value,content", ENCODE_CASES)
def test_encode_reference(value: float, content: bytes) -> None:
    """
    Ensure floats encode in base 2 with an odd mantissa and the shortest
    exponent, and zero and the special values as X.690 defines them.
    """
    assert bytes(Real(value)) == bytes([0x09, len(content)]) + content


def test_encode_int() -> None:
    """
    Ensure an int is converted to a float.
    """
    value = Real(-5)
    assert isinstance(value.value, float)
    assert bytes(value) == b"\x09\x03\xc0\x00\x05"


def test_no_arg() -> None:
    """
    Ensure a REAL without a value is zero.
    """
    assert Real().value == 0.0
    assert bytes(Real()) == b"\x09\x00"


SPECIAL_FLOATS = [
    5e-324,
    -5e-324,
    sys.float_info.min,
    sys.float_info.min / 3,
    sys.float_info.max,
    -sys.float_info.max,
    sys.float_info.epsilon,
    1 / 3,
    -2.5,
    1e300,
    -1e-300,
    2.0**-1074 * 12345,
    float(2**53 - 1),
    0.0,
    -0.0,
    math.inf,
    -math.inf,
]


def _random_floats(count: int) -> list[float]:
    generator = random.Random(0)
    output = []
    while len(output) < count:
        pattern = generator.getrandbits(64).to_bytes(8, "big")
        (value,) = struct.unpack(">d", pattern)
        if not math.isnan(value):
            output.append(value)
    return output


@pytest.mark.parametrize("value", SPECIAL_FLOATS)
def test_round_trip_special(value: float) -> None:
    """
    Ensure edge-case floats survive an encode and decode bit for bit.
    """
    decoded, _ = decode(bytes(Real(value)))
    assert _bits(decoded.value) == _bits(value)


def test_round_trip_random() -> None:
    """
    Ensure random float bit patterns, including subnormal, very large and
    negative values, survive an encode and decode bit for bit.
    """
    for value in _random_floats(5000):
        decoded, _ = decode(bytes(Real(value)))
        assert _bits(decoded.value) == _bits(value), value


def test_round_trip_nan() -> None:
    """
    Ensure NaN survives an encode and decode.
    """
    decoded, _ = decode(bytes(Real(math.nan)))
    assert math.isnan(decoded.value)


def test_equality() -> None:
    """
    Ensure REAL values compare by value, with NaN equal to NaN and the
    two zeros different, as their encodings are.
    """
    assert Real(1) == Real(1.0)
    assert decode(b"\x09\x03\x90\x01\x01")[0] == Real(8.0)
    assert Real(math.nan) == Real(math.nan)
    assert Real(math.nan) != Real(1.0)
    assert Real(1.0) != Real(math.nan)
    assert Real(0.0) != Real(-0.0)
    assert Real(1.0) != Real(2.0)
    assert Real(1.0) != 1.0


def test_repr() -> None:
    """
    Ensure the repr shows the float.
    """
    assert repr(Real(1.5)) == "Real(1.5)"
