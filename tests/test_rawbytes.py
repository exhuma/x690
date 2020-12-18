"""
Type instances should have raw-bytes easily available without the "type/length" header.
"""
import pytest

import x690.types as t


@pytest.mark.parametrize(
    "cls",
    [
        (t.BitString),
        (t.BmpString),
        (t.Boolean),
        (t.CharacterString),
        (t.EOC),
        (t.EmbeddedPdv),
        (t.Enumerated),
        (t.External),
        (t.GeneralString),
        (t.GeneralizedTime),
        (t.GraphicString),
        (t.IA5String),
        (t.Integer),
        (t.Null),
        (t.NumericString),
        (t.ObjectDescriptor),
        (t.ObjectIdentifier),
        (t.OctetString),
        (t.PrintableString),
        (t.Real),
        (t.RelativeOid),
        (t.Sequence),
        (t.Set),
        (t.T61String),
        (t.UniversalString),
        (t.UnknownType),
        (t.UtcTime),
        (t.Utf8String),
        (t.VideotexString),
        (t.VisibleString),
    ],
)
def test_raw_bytes(cls):
    try:
        instance = cls.decode(b"")
    except NotImplementedError:
        raise pytest.skip("Not yet implemented")
    assert instance.raw_bytes == b""
