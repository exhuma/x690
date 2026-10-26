"""
Resolution of context-specific and other tags relative to the enclosing type.
"""

from types import MappingProxyType

import pytest

from x690 import decode
from x690.types import (
    Explicit,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    UnknownType,
    X690Type,
)
from x690.util import TypeClass, TypeNature

# SNMP message with a GetRequest PDU (context class, constructed, tag 0)
SNMP_DATA = (
    b"0'\x02\x01\x01\x04\x06public"
    b"\xa0\x1a\x02\x02\x04\xd2\x02\x01\x00"
    b"\x02\x01\x000\x0e0\x0c\x06\x08+\x06"
    b"\x01\x02\x01\x01\x01\x00\x05\x00"
)


class GetRequest(Sequence):
    TYPECLASS = TypeClass.CONTEXT
    TAG = 0


class Message(Sequence):
    CHILD_TYPES = [GetRequest]


class Version(Explicit[Integer]):
    TAG = 0


class TBSCertificate(Sequence):
    CHILD_TYPES = [Version]


class KeyIdentifier(OctetString):
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 0


class AuthorityKeyId(Sequence):
    TYPECLASS = TypeClass.CONTEXT
    TAG = 1
    CHILD_TYPES = [KeyIdentifier]


class Certificate(Sequence):
    TYPECLASS = TypeClass.CONTEXT
    TAG = 2
    CHILD_TYPES = [Version, AuthorityKeyId]


class Document(Sequence):
    CHILD_TYPES = [AuthorityKeyId, Certificate]


def make_document() -> Document:
    """
    Build a document with [0] used for two different types in two
    structures.
    """
    return Document(
        [
            AuthorityKeyId([KeyIdentifier(b"\xca\xfe")]),
            Certificate(
                [
                    Version(Integer(2)),
                    AuthorityKeyId([KeyIdentifier(b"\xbe\xef")]),
                ]
            ),
        ]
    )


def test_context_tag_differs_per_structure() -> None:
    """
    Ensure the same context tag decodes to a different type in each of two
    enclosing structures of one message.
    """
    data = bytes(make_document())
    document, _ = decode(data, types=[Document], enforce_type=Document)
    key_id = document[0][0]
    version = document[1][0]
    assert isinstance(key_id, KeyIdentifier)
    assert key_id.value == b"\xca\xfe"
    assert isinstance(version, Version)
    assert version.value == Integer(2)


def test_nested_resolution_uses_child_declarations() -> None:
    """
    Ensure the items of a child structure are resolved with the child's
    declarations, not the parent's.
    """
    data = bytes(make_document())
    document, _ = decode(data, types=[Document])
    # Certificate declares [0] as Version, but inside its AuthorityKeyId
    # child [0] is a KeyIdentifier.
    nested = document[1][1]
    assert isinstance(nested, AuthorityKeyId)
    assert isinstance(nested[0], KeyIdentifier)
    assert nested[0].value == b"\xbe\xef"


def test_parent_declarations_do_not_reach_grandchildren() -> None:
    """
    Ensure a universal sequence without declarations inside a declaring
    structure does not inherit the structure's declarations.
    """
    data = bytes(TBSCertificate([Sequence([Version(Integer(1))])]))
    tbs, _ = decode(data, types=[TBSCertificate])
    inner = tbs[0]
    assert type(inner) is Sequence
    assert isinstance(inner[0], UnknownType)


def test_undeclared_context_tag_is_unknown() -> None:
    """
    Ensure a context tag that the enclosing type does not declare decodes to
    UnknownType.
    """
    message, _ = decode(SNMP_DATA)
    assert isinstance(message[2], UnknownType)
    tbs, _ = decode(b"0\x03\x81\x01\x05", types=[TBSCertificate])
    assert isinstance(tbs[0], UnknownType)
    assert tbs[0].tag == 0x81


def test_context_types_are_not_registered() -> None:
    """
    Ensure defining a context-class type does not enter the global registry,
    so it cannot leak into unrelated decoding.
    """

    class Leaky(Integer):
        TYPECLASS = TypeClass.CONTEXT
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 5

    assert Leaky not in X690Type.all()
    assert GetRequest not in X690Type.all()
    with pytest.raises(KeyError):
        X690Type.get(TypeClass.CONTEXT, 5, TypeNature.PRIMITIVE)
    assert isinstance(decode(b"\x85\x01\x01")[0], UnknownType)


def test_snmp_message() -> None:
    """
    Ensure an SNMP GetRequest declared on the message decodes, and encodes
    to the same bytes.
    """
    message, _ = decode(SNMP_DATA, types=[Message], enforce_type=Message)
    pdu = message[2]
    assert isinstance(pdu, GetRequest)
    assert pdu[0] == Integer(1234)
    assert pdu[3].pythonize()[0][0] == "1.3.6.1.2.1.1.1.0"
    assert bytes(message) == SNMP_DATA


def test_structure_class_does_not_replace_sequence() -> None:
    """
    Ensure a sequence subclass that only declares child types leaves the
    global Sequence registration in place.
    """
    assert X690Type.get(TypeClass.UNIVERSAL, 0x10) is Sequence
    value, _ = decode(SNMP_DATA)
    assert type(value) is Sequence


def test_top_level_types() -> None:
    """
    Ensure decode() resolves a context-tagged value at the top level with
    the given types.
    """
    pdu, next_index = decode(SNMP_DATA, 13, types=[GetRequest])
    assert isinstance(pdu, GetRequest)
    assert next_index == len(SNMP_DATA)
    assert len(pdu) == 4
    assert isinstance(decode(SNMP_DATA, 13)[0], UnknownType)


def test_application_override_per_structure() -> None:
    """
    Ensure an application type declared on an enclosing type takes
    precedence over the global one inside that structure only.
    """

    class Counter(Integer):
        TYPECLASS = TypeClass.APPLICATION
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 29

    class Label(OctetString, register=False):
        TYPECLASS = TypeClass.APPLICATION
        NATURE = [TypeNature.PRIMITIVE]
        TAG = 29

    class Labelled(Sequence):
        CHILD_TYPES = [Label]

    assert X690Type.get(TypeClass.APPLICATION, 29, TypeNature.PRIMITIVE) is (
        Counter
    )
    assert Label not in X690Type.all()

    data = b"0\x06\x5d\x01A\x02\x01\x07"
    plain, _ = decode(data)
    assert isinstance(plain[0], Counter)
    labelled, _ = decode(data, types=[Labelled])
    assert isinstance(labelled[0], Label)
    assert labelled[0].value == b"A"
    assert labelled[1] == Integer(7)
    assert isinstance(decode(b"\x5d\x01\x41")[0], Counter)


def test_round_trip_context_structures() -> None:
    """
    Ensure encoding decoded context-tagged structures yields the original
    bytes.
    """
    data = bytes(make_document())
    document, _ = decode(data, types=[Document])
    assert bytes(document) == data
    assert bytes(document[1]) == bytes(make_document()[1])
    assert bytes(document[1][0]) == b"\xa0\x03\x02\x01\x02"


def test_repr_pretty_pythonize_detach() -> None:
    """
    Ensure repr(), pretty(), pythonize() and detach() work on context-tagged
    values.
    """
    data = bytes(make_document())
    document, _ = decode(data, types=[Document])
    assert repr(document[0]) == "AuthorityKeyId([KeyIdentifier(b'\\xca\\xfe')])"
    assert "Certificate with 2 items:" in document.pretty()
    assert "Version (explicit tag 0):" in document.pretty()
    assert document.pythonize() == [[b"\xca\xfe"], [2, [b"\xbe\xef"]]]
    certificate = document[1].detach()
    assert isinstance(certificate, Certificate)
    assert isinstance(certificate[0], Version)
    assert certificate[0].value == Integer(2)


def test_sequence_decode_raw_uses_child_types() -> None:
    """
    Ensure decode_raw of a declaring sequence resolves its items with its
    child types.
    """
    data = b"\xa0\x03\x02\x01\x02"
    assert TBSCertificate.decode_raw(data) == [Version(Integer(2))]
    assert isinstance(Sequence.decode_raw(data)[0], UnknownType)


def test_child_types_assigned_later() -> None:
    """
    Ensure CHILD_TYPES assigned after the class statement is used, which
    allows a structure to contain itself.
    """

    class Node(Sequence):
        TYPECLASS = TypeClass.CONTEXT
        TAG = 3

    data = bytes(Node([Node([Integer(1)])]))
    assert isinstance(decode(data, types=[Node])[0][0], UnknownType)
    Node.CHILD_TYPES = [Node]
    outer, _ = decode(data, types=[Node])
    assert isinstance(outer[0], Node)
    assert outer[0][0] == Integer(1)


def test_duplicate_child_types() -> None:
    """
    Ensure declaring two types for the same tag raises ValueError.
    """
    with pytest.raises(ValueError, match="share the context"):

        class Broken(Sequence):
            CHILD_TYPES = [Version, GetRequest]

    with pytest.raises(ValueError):
        decode(b"\x05\x00", types=[Version, GetRequest])


def test_same_class_listed_twice() -> None:
    """
    Ensure listing the same class twice is accepted.
    """
    assert decode(b"\x80\x01A", types=[KeyIdentifier, KeyIdentifier])[0] == (
        KeyIdentifier(b"A")
    )


def test_explicit_decodes_inner_value() -> None:
    """
    Ensure an explicit tag decodes to a wrapper whose value is the inner
    value, and encodes back to the same bytes.
    """
    data = b"\xa0\x03\x02\x01\x02"
    version, next_index = decode(data, types=[Version])
    assert isinstance(version, Version)
    assert next_index == 5
    assert version.value == Integer(2)
    assert version.pythonize() == 2
    assert repr(version) == "Version(Integer(2))"
    assert bytes(version) == data
    assert bytes(Version(Integer(2))) == data
    assert version == Version(Integer(2))
    assert version != Version(Integer(3))
    assert version != Integer(2)


def test_explicit_inner_context_type() -> None:
    """
    Ensure the inner value of an explicit tag is resolved with the CHILD_TYPES
    of the Explicit subclass.
    """

    class Extensions(Explicit[GetRequest]):
        TAG = 3
        CHILD_TYPES = [GetRequest]

    value = Extensions(GetRequest([Null()]))
    data = bytes(value)
    assert data == b"\xa3\x04\xa0\x02\x05\x00"
    decoded, _ = decode(data, types=[Extensions])
    assert isinstance(decoded.value, GetRequest)
    assert decoded.value[0] == Null()
    assert decoded.pretty() == (
        "Extensions (explicit tag 3):\n⁃ GetRequest with 1 items:\n  ⁃ Null()"
    )


def test_explicit_without_value() -> None:
    """
    Ensure an explicit tag without an inner value raises a helpful error,
    and encodes to an empty wrapper.
    """
    empty, _ = decode(b"\xa0\x00", types=[Version])
    with pytest.raises(ValueError, match="holds no value"):
        empty.value  # noqa: B018
    assert Version().encode_raw() == b""


def test_object_identifier_still_global() -> None:
    """
    Ensure universal types still decode without declarations inside a
    declaring structure.
    """
    data = bytes(Message([ObjectIdentifier("1.3.6")]))
    message, _ = decode(data, types=[Message])
    assert message[0] == ObjectIdentifier("1.3.6")


def test_child_lookup_is_read_only() -> None:
    """
    Ensure the lookups of child types are read-only, also the shared empty
    one.
    """
    assert isinstance(Sequence.child_lookup(), MappingProxyType)
    assert isinstance(Message.child_lookup(), MappingProxyType)
