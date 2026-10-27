"""
x690 emits DEBUG records only, and never configures logging.

The records themselves are not asserted: they are decision chatter, and
the documentation page "Observability" describes them.
"""

import logging
from datetime import UTC, datetime

import pytest

from x690 import decode
from x690.types import (
    GeneralizedTime,
    OctetString,
    Sequence,
    UtcTime,
)
from x690.util import TypeClass, TypeNature

UNKNOWN_TAG = b"\x85\x01\x00"

# One document per decision that is logged
DECISIONS = [
    pytest.param(UNKNOWN_TAG, id="unknown-type"),
    pytest.param(b"0\x03" + UNKNOWN_TAG, id="unknown-type-in-sequence"),
    pytest.param(b"\x13\x03a@b", id="printable-alphabet"),
    pytest.param(b"\x12\x02a1", id="numeric-alphabet"),
    pytest.param(b"\x03\x02\x05\xa1", id="bit-string-padding"),
    pytest.param(b"\x03\x00", id="bit-string-empty"),
    pytest.param(b"\x09\x04\x81\x7f\xff\x01", id="real-inf"),
    pytest.param(b"\x09\x04\xc1\x7f\xff\x01", id="real-negative-inf"),
    pytest.param(b"\x09\x04\x81\x80\x00\x01", id="real-zero"),
    pytest.param(b"\x09\x08\x03" + b"1.0E999", id="real-decimal-inf"),
    pytest.param(b"\x18\x16" + b"20200101000000.1234567", id="fraction"),
]


def _logging_state() -> tuple[object, ...]:
    root = logging.getLogger()
    return (
        list(root.handlers),
        root.level,
        {
            name: (
                list(logging.getLogger(name).handlers),
                logging.getLogger(name).level,
                logging.getLogger(name).propagate,
            )
            for name in ("x690", "x690.types", "x690.util", "x690.exc")
        },
    )


def _use_x690() -> None:
    value, _ = decode(b"0\x03" + UNKNOWN_TAG)
    assert isinstance(value, Sequence)
    assert len(value.value) == 1
    stamp = datetime(2020, 1, 1, 1, 2, 3, 4, tzinfo=UTC)
    assert decode(bytes(UtcTime(stamp)))[0].value.microsecond == 0
    assert bytes(OctetString(b"x")) == b"\x04\x01x"
    assert decode(bytes(GeneralizedTime(stamp)))[0].value == stamp


def test_using_x690_does_not_configure_logging() -> None:
    """
    Ensure decoding and encoding leave handlers and levels untouched.
    """
    before = _logging_state()
    _use_x690()
    assert _logging_state() == before


def test_using_x690_at_debug_does_not_configure_logging(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Ensure the library adds no handler, even when records are emitted.
    """
    caplog.set_level(logging.DEBUG, logger="x690")
    before = [list(logging.getLogger("x690").handlers)]
    _use_x690()
    assert [list(logging.getLogger("x690").handlers)] == before
    assert logging.getLogger("x690.types").handlers == []


def test_unknown_type_prints_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Ensure a default setup writes nothing for an unknown tag.
    """
    value, _ = decode(UNKNOWN_TAG)
    assert value.value == b"\x00"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_unknown_type_prints_nothing_at_file_descriptor_level(
    capfd: pytest.CaptureFixture[str],
) -> None:
    """
    Ensure no output reaches the file descriptors either.
    """
    assert decode(UNKNOWN_TAG)[0].value == b"\x00"
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", "")


@pytest.mark.parametrize("data", DECISIONS)
def test_decisions_decode_with_debug_enabled(
    data: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Ensure logging a decision does not change the decoded value.
    """
    plain, _ = decode(data)
    expected = plain.value
    caplog.set_level(logging.DEBUG, logger="x690")
    logged, _ = decode(data)
    assert repr(logged.value) == repr(expected)


def test_override_decodes_with_debug_enabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Ensure a child type that replaces a registered type still decodes.
    """

    class Counter(OctetString):
        TYPECLASS = TypeClass.APPLICATION
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 29

    class Label(OctetString, register=False):
        TYPECLASS = TypeClass.APPLICATION
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 29

    class Labelled(Sequence):
        CHILD_TYPES = [Label]

    caplog.set_level(logging.DEBUG, logger="x690")
    value, _ = decode(b"0\x03\x5d\x01x", types=[Labelled])
    assert type(value.value[0]) is Label
    assert type(decode(b"\x5d\x01x")[0]) is Counter


def test_microseconds_are_dropped_with_debug_enabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Ensure encoding a UtcTime with microseconds still drops them.
    """
    caplog.set_level(logging.DEBUG, logger="x690")
    stamp = datetime(2020, 1, 1, 0, 0, 0, 5, tzinfo=UTC)
    assert decode(bytes(UtcTime(stamp)))[0].value.microsecond == 0


def test_registered_child_type_decodes_with_debug_enabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Ensure a child type that is also the registered type decodes.
    """

    class Counter(OctetString):
        TYPECLASS = TypeClass.APPLICATION
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 29

    class Counted(Sequence):
        CHILD_TYPES = [Counter]

    caplog.set_level(logging.DEBUG, logger="x690")
    value, _ = decode(b"0\x03\x5d\x01x", types=[Counted])
    assert type(value.value[0]) is Counter
