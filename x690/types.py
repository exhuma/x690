# Type-Hinting is done in a stub file
"""
Overview
========

This module contains the encoding/decoding logic for data types as defined in
:term:`X.690`.

Each type is made available via a registry dictionary on :py:class:`~.Type` and
can be retrieved via :py:meth:`~.Type.get`.

Additionally, given a :py:class:`bytes` object, the :py:func:`~.pop_tlv`
function can be used to parse the bytes object and return a typed instance
from it. See :py:func:`~.pop_tlv` for details about it's behaviour!

.. note::
    The individual type classes in this module do not contain any additional
    documentation. The bulk of this module is documented in :py:class:`~.Type`.

    For the rest, the type classes simply define the type identifier tag.

Supporting Additional Classes
=============================

Just by subclassing :py:class:`~.Type` and setting correct ``TAG`` and
``TYPECLASS`` values, most of the basic functionality will be covered by the
superclass. Type detection, and addition to the registry is automatic.
Subclassing is enough.

By default, a new type which does not override any methods will have it's value
reported as bytes objects. You may want to override at least
:py:meth:`~.Type.pythonize` to expose the value to users of the library as pure
Python objects.

Depending on type, you may also want to override certain methods. See
:py:class:`~.Sequence` and :py:class:`~.Integer` for more complex examples.
"""
# pylint: disable=abstract-method, missing-docstring


from dataclasses import astuple
from datetime import datetime, timezone
from itertools import zip_longest
from textwrap import indent
from typing import Any, Dict, Generic, Iterator, List, Optional, Tuple
from typing import Type as TypeType
from typing import TypeVar, Union

import t61codec  # type: ignore

from .exc import IncompleteDecoding, InvalidValueLength, UnexpectedType
from .util import (
    INDENT_STRING,
    TypeClass,
    TypeInfo,
    TypeNature,
    decode_length,
    encode_length,
    visible_octets,
    wrap,
)

TWrappedPyType = TypeVar("TWrappedPyType")
TPopType = TypeVar("TPopType", bound=Any)


def pop_tlv(
    data: bytes,
    enforce_type: Optional[TypeType[TPopType]] = None,
    strict: bool = False,
) -> Tuple["TPopType", bytes]:
    """
    Given a :py:class:`bytes` object, inspects and parses the first octets (as
    many as required) to determine variable type (and corresponding Python
    class), and length. The class is then used to parse the *first* object in
    ``data``.  *data* itself will not be modified. Instead, a new modified copy
    of *data* is returned alongside the parsed object. This new object is the
    remainder after popping off the first object.

    Example::

        >>> data = b'\\x02\\x01\\x05\\x11'
        >>> pop_tlv(data)
        (Integer(5), b'\\x11')

    Note that in the example above, ``\\x11`` is the remainder of the bytes
    object after popping of the integer object.
    """
    # TODO: This function should be moved to another module (util maybe?).
    if not data:
        return Null(), b""  # type: ignore

    type_ = TypeInfo.from_bytes(data[0])
    length, remainder = astuple(decode_length(data[1:]))

    # determine how many octets are used to encode the length!
    offset = len(data) - len(remainder)
    chunk = data[: length + offset]
    try:
        cls = Type.get(type_.cls, type_.tag)
        value = cls.from_bytes(chunk)
    except KeyError:
        # Add context information
        value = UnknownType.from_bytes(chunk)

    if enforce_type and not isinstance(value, enforce_type):
        raise UnexpectedType(
            f"Unexpected decode result. Expected instance of type "
            f"{enforce_type} but got {type(value)} instead"
        )
    remainder = remainder[length:]

    if strict and remainder:
        raise IncompleteDecoding(
            f"Strict decoding still had {len(remainder)} remaining bytes!",
            remainder=remainder,
        )

    return value, remainder  # type: ignore


class Type(Generic[TWrappedPyType]):
    """
    The superclass for all supported types.
    """

    __registry: Dict[Tuple[str, int], TypeType["Type[Any]"]] = {}
    TYPECLASS: TypeClass = TypeClass.UNIVERSAL
    TAG: int = 0
    value: TWrappedPyType

    def __init_subclass__(cls: TypeType["Type[Any]"]) -> None:
        Type.__registry[(cls.TYPECLASS, cls.TAG)] = cls

    @staticmethod
    def get(typeclass: str, typeid: int) -> TypeType["Type[Any]"]:
        return Type.__registry[(typeclass, typeid)]

    @staticmethod
    def all() -> List[TypeType["Type[Any]"]]:
        """
        Returns all registered classes
        """
        return list(Type.__registry.values())

    @classmethod
    def validate(cls, data: bytes) -> None:
        """
        Given a bytes object, checks if the given class *cls* supports decoding
        this object. If not, raises a ValueError.
        """
        # TODO: Making this function return a boolean instead of raising an exception would make the code potentially more readable.
        tinfo = TypeInfo.from_bytes(data[0])
        if tinfo.cls != cls.TYPECLASS or tinfo.tag != cls.TAG:
            raise ValueError(
                "Invalid type header! "
                "Expected a %s class with tag "
                "ID 0x%02x, but got a %s class with "
                "tag ID 0x%02x" % (cls.TYPECLASS, cls.TAG, tinfo.cls, data[0])
            )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Type[TWrappedPyType]":
        """
        Given a bytes object, this method reads the type information and length
        and uses it to convert the bytes representation into a python object.

        :raises puresnmp.x690.exc.InvalidValueLength: If the packet-length does
            not match the expected length reported in the package header.
        """

        if not data:
            return Null()  # type: ignore
        cls.validate(data)
        expected_length, data = astuple(decode_length(data[1:]))
        if len(data) != expected_length:
            raise InvalidValueLength(
                "Corrupt packet: Unexpected length for {0} Expected {1} "
                "(0x{1:02x}) but got {2} (0x{2:02x}). Consider increasing "
                "puresnmp.transport.BUFFER_SIZE.".format(
                    cls, expected_length, len(data)
                )
            )
        return cls.decode(data)

    @classmethod
    def decode(cls, data: bytes) -> "Type[TWrappedPyType]":  # pragma: no cover
        """
        This method takes a bytes object which contains the raw content octets
        of the object. That means, the octets *without* the type information
        and length.

        This function must be overridden by the concrete subclasses.
        """
        raise NotImplementedError("Decoding is not yet implemented on %s" % cls)

    def __bytes__(self) -> bytes:  # pragma: no cover
        """
        Convert this instance into a bytes object. This must be implemented by
        subclasses.
        """
        raise NotImplementedError("Not yet implemented")

    def __repr__(self) -> str:
        # pylint: disable=no-member
        return "%s(%r)" % (self.__class__.__name__, self.value)

    def pythonize(self) -> TWrappedPyType:
        """
        Convert this instance to an appropriate pure Python object.
        """
        # pylint: disable=no-member
        return self.value

    def pretty(self, depth: int = 0) -> str:  # pragma: no cover
        """
        Returns a readable representation (possibly multiline) of the value.

        By default this simply returns the string representation. But more
        complex values may override this.
        """
        return indent(str(self), INDENT_STRING * depth)


class UnknownType(Type[bytes]):
    """
    A fallback type for anything not in X.690.

    Instances of this class contain the raw information as parsed from the
    bytes as the following attributes:

    * ``value``: The value without leading metadata (as bytes value)
    * ``tag``: The *unparsed* "tag". This is the type ID as defined in the
      reference document. See :py:class:`~puresnmp.x690.util.TypeInfo` for
      details.
    * ``typeinfo``: unused (derived from *tag* and only here for consistency
      with ``__repr__`` of this class).
    """

    value = b""

    def __init__(
        self, tag: int, value: bytes, typeinfo: Optional[TypeInfo] = None
    ) -> None:
        self.value = value
        self.tag = tag
        self.length = len(value)
        self.typeinfo = TypeInfo.from_bytes(tag)

    def __bytes__(self) -> bytes:
        return bytes([self.tag]) + encode_length(self.length) + self.value

    def __repr__(self) -> str:
        tinfo = (
            f"{self.typeinfo.cls}/{self.typeinfo.nature}/{self.typeinfo.tag}"
        )
        return f"<{self.__class__.__name__} {self.tag} {self.value!r} {tinfo}>"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, UnknownType)
            and self.value == other.value
            and self.tag == other.tag
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "UnknownType":
        """
        Overrides typical conversion by removing type validation. As, by
        definition this class is used for unknown types, we cannot validate
        them.
        """
        if not data:
            return Null()  # type: ignore
        tag = data[0]
        expected_length, data = astuple(decode_length(data[1:]))
        if len(data) != expected_length:
            raise ValueError(
                "Corrupt packet: Unexpected length for {0} "
                "Expected {1} (0x{1:02x}) "
                "but got {2} (0x{2:02x})".format(
                    UnknownType, expected_length, len(data)
                )
            )
        return UnknownType(tag, data)

    def pretty(self, depth: int = 0) -> str:
        return indent(
            f"Unknown Type\n"
            f"  │ Tag:       {self.tag}\n"
            f"  │ Type Info: {self.typeinfo}\n"
            f"  │ Hex-Value: {self.value.hex()}",
            INDENT_STRING * depth,
        )


class Boolean(Type[bool]):
    TAG = 0x01
    value = False

    @staticmethod
    def decode(data: bytes) -> "Boolean":
        return Boolean(data != b"\x00")

    @classmethod
    def validate(cls, data: bytes) -> None:
        super().validate(data)
        if data[1] != 1:
            raise ValueError(
                "Unexpected Boolean value. Length should be 1,"
                " it was %d" % data[1]
            )

    def __init__(self, value: bool = False) -> None:
        self.value = value

    def __bytes__(self) -> bytes:
        return bytes([1, 1, int(self.value)])

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Boolean) and self.value == other.value


class Null(Type[None]):
    TAG = 0x05

    def __init__(self) -> None:
        self.value = None

    @classmethod
    def validate(cls, data: bytes) -> None:
        super().validate(data)
        if data[1] != 0:
            raise ValueError(
                "Unexpected NULL value. Length should be 0, it "
                "was %d" % data[1]
            )

    @classmethod
    def decode(cls, data: bytes) -> "Null":
        return Null()

    def __bytes__(self) -> bytes:
        return b"\x05\x00"

    def __eq__(self, other: object) -> bool:
        return type(self) == type(other)

    def __repr__(self) -> str:
        return "Null()"

    def __bool__(self) -> bool:
        return False

    def __nonzero__(self) -> bool:  # pragma: no cover
        return False


class OctetString(Type[bytes]):
    TAG = 0x04
    value = b""

    @classmethod
    def decode(cls, data: bytes) -> "OctetString":
        return cls(data)

    def __init__(self, value: Union[str, bytes] = b"") -> None:
        if isinstance(value, str):
            self.value = value.encode("ascii")
        else:
            self.value = value
        self.length = encode_length(len(self.value))

    def __bytes__(self) -> bytes:
        tinfo = TypeInfo(self.TYPECLASS, TypeNature.PRIMITIVE, self.TAG)
        return bytes(tinfo) + self.length + self.value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, OctetString) and self.value == other.value

    def pythonize(self) -> bytes:
        """
        Convert this object in an appropriate python object
        """
        return self.value

    def pretty(self, depth: int = 0) -> str:
        if self.value == b"":
            return repr(self)
        try:
            # We try to decode embedded X.690 items. If we can't, we display
            # the value raw
            embedded = pop_tlv(self.value)[0]  # type: ignore
            return wrap(embedded.pretty(0), f"Embedded in {type(self)}", depth)
        except:  # pylint: disable=bare-except
            wrapped = wrap(visible_octets(self.value), str(type(self)), depth)
            return wrapped


class Sequence(Type[List[Type[Any]]]):
    """
    Represents an X.690 sequence type. Instances of this class are iterable and
    indexable.
    """

    TAG = 0x10
    value: List[Type[Any]] = []

    @classmethod
    def decode(cls, data: bytes) -> "Sequence":
        value: Any
        output = []
        while data:
            value, data = pop_tlv(data)
            output.append(value)
        return Sequence(*output)

    def __init__(self, *items: Type[Any]) -> None:
        self.items = items

    def __bytes__(self) -> bytes:
        items = [bytes(item) for item in self]
        output = b"".join(items)
        length = encode_length(len(output))
        tinfo = TypeInfo(
            TypeClass.UNIVERSAL, TypeNature.CONSTRUCTED, Sequence.TAG
        )
        return bytes(tinfo) + length + output

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Sequence) and self.items == other.items

    def __repr__(self) -> str:
        item_repr = [repr(item) for item in self]
        return "Sequence(%s)" % ", ".join(item_repr)

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[Type[Any]]:
        return iter(self.items)

    def __getitem__(self, idx: int) -> Type[Any]:
        return self.items[idx]

    def pythonize(self) -> List[Type[Any]]:
        return [obj.pythonize() for obj in self]

    def pretty(self, depth: int = 0) -> str:  # pragma: no cover
        """
        Overrides :py:meth:`.Type.pretty`
        """
        lines = [f"{self.__class__.__name__} with {len(self.items)} items:"]
        for item in self.items:
            prettified_item = item.pretty(depth)
            bullet = INDENT_STRING * depth + "⁃ "
            for line in prettified_item.splitlines():
                lines.append(bullet + line)
                bullet = "  "
        return "\n".join(lines)


class Integer(Type[int]):
    SIGNED = True
    TAG = 0x02
    value = 0

    @classmethod
    def decode(cls, data: bytes) -> "Integer":
        return cls(int.from_bytes(data, "big", signed=cls.SIGNED))

    def __init__(self, value: int = 0) -> None:
        self.value = value

    def __bytes__(self) -> bytes:
        octets = [self.value & 0b11111111]

        # Append remaining octets for long integers.
        remainder = self.value
        while remainder not in (0, -1):
            remainder = remainder >> 8
            octets.append(remainder & 0b11111111)

        if remainder == 0 and octets[-1] == 0b10000000:
            octets.append(0)
        octets.reverse()

        # remove leading octet if there is a string of 9 zeros or ones
        while len(octets) > 1 and (
            (octets[0] == 0 and octets[1] & 0b10000000 == 0)
            or (octets[0] == 0b11111111 and octets[1] & 0b10000000 != 0)
        ):
            del octets[0]

        tinfo = TypeInfo(self.TYPECLASS, TypeNature.PRIMITIVE, self.TAG)
        return bytes(tinfo) + bytes([len(octets)]) + bytes(octets)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Integer) and self.value == other.value


class ObjectIdentifier(Type[str]):
    """
    Represents an OID.

    Instances of this class support containment checks to determine if one OID
    is a sub-item of another::

        >>> ObjectIdentifier(1, 2, 3, 4, 5) in ObjectIdentifier(1, 2, 3)
        True

        >>> ObjectIdentifier(1, 2, 4, 5, 6) in ObjectIdentifier(1, 2, 3)
        False
    """

    TAG = 0x06
    value = ""
    identifiers: Tuple[int, ...]

    @staticmethod
    def decode_large_value(current_char: int, stream: Iterator[int]) -> int:

        """
        If we encounter a value larger than 127, we have to consume from the
        stram until we encounter a value below 127 and recombine them.

        See: https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
        """
        buffer = []
        while current_char > 127:
            buffer.append(current_char ^ 0b10000000)
            current_char = next(stream)
        total = current_char
        for i, digit in enumerate(reversed(buffer)):
            total += digit * 128 ** (i + 1)
        return total

    @staticmethod
    def encode_large_value(value: int) -> List[int]:
        """
        Inverse function of :py:meth:`~.ObjectIdentifier.decode_large_value`
        """
        if value <= 127:
            return [value]
        output = [value & 0b1111111]
        value = value >> 7
        while value:
            output.append(value & 0b1111111 | 0b10000000)
            value = value >> 7
        output.reverse()
        return output

    @classmethod
    def decode(cls, data: bytes) -> "ObjectIdentifier":
        # Special case for "empty" object identifiers which should be returned
        # as "0"
        if not data:
            return ObjectIdentifier(0)

        # unpack the first byte into first and second sub-identifiers.
        data0 = data[0]
        first, second = data0 // 40, data0 % 40
        output = [first, second]

        remaining = iter(data[1:])

        for char in remaining:
            # Each node can only contain values from 0-127. Other values need
            # to be combined.
            if char > 127:
                collapsed_value = ObjectIdentifier.decode_large_value(
                    char, remaining
                )
                output.append(collapsed_value)
                continue
            output.append(char)

        return ObjectIdentifier(*output)

    @staticmethod
    def from_string(value: str) -> "ObjectIdentifier":
        """
        Create an OID from a string
        """

        if value == ".":
            return ObjectIdentifier(1)

        if value.startswith("."):
            value = value[1:]

        identifiers = [int(ident, 10) for ident in value.split(".")]
        return ObjectIdentifier(*identifiers)

    def __init__(self, *identifiers: int) -> None:
        # pylint: disable=line-too-long

        # If the user hands in an iterable, instead of positional arguments,
        # make sure we unpack it
        if len(identifiers) == 1 and not isinstance(identifiers[0], int):
            identifiers = [int(ident) for ident in identifiers[0]]

        if len(identifiers) > 1:
            # The first two bytes are collapsed according to X.690
            # See https://en.wikipedia.org/wiki/X.690#BER_encoding
            first, second, rest = (
                identifiers[0],
                identifiers[1],
                identifiers[2:],
            )
            first_output = (40 * first) + second
        elif len(identifiers) == 0:
            self.identifiers = tuple()
            return
        else:
            first_output = identifiers[0]
            rest = tuple()

        # Values above 127 need a special encoding. They get split up into
        # multiple positions.
        exploded_high_values = []
        for char in rest:
            if char > 127:
                exploded_high_values.extend(
                    ObjectIdentifier.encode_large_value(char)
                )
            else:
                exploded_high_values.append(char)

        self.identifiers = tuple(identifiers)
        collapsed_identifiers = [first_output]
        for subidentifier in rest:
            collapsed_identifiers.extend(
                ObjectIdentifier.encode_large_value(subidentifier)
            )
        self.__collapsed_identifiers = tuple(collapsed_identifiers)
        self.length = encode_length(len(self.__collapsed_identifiers))

    def __int__(self) -> int:
        if len(self.identifiers) != 1:
            raise ValueError(
                "Only ObjectIdentifier with one node can be "
                "converted to int. %r is not convertable" % self
            )
        return self.identifiers[0]

    def __str__(self) -> str:
        return ".".join([str(_) for _ in self.identifiers])

    def __bytes__(self) -> bytes:
        output = bytes([self.TAG])
        if self.__collapsed_identifiers == (0,):
            output += b"\x00"
        else:
            output += self.length + bytes(self.__collapsed_identifiers)
        return output

    def __repr__(self) -> str:
        return "ObjectIdentifier(%r)" % (self.identifiers,)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ObjectIdentifier)
            and self.__collapsed_identifiers == other.__collapsed_identifiers
        )

    def __len__(self) -> int:
        return len(self.identifiers)

    def __contains__(self, other: "ObjectIdentifier") -> bool:
        """
        Check if one OID is a child of another.

        TODO: This has been written in the middle of the night! It's messy...
        """
        # pylint: disable=invalid-name

        a, b = other.identifiers, self.identifiers

        # if both have the same amount of identifiers, check for equality
        if len(a) == len(b):
            return a == b

        # if "self" is longer than "other", self cannot be "in" other
        if len(b) > len(a):
            return False

        # For all other cases:
        #   1. zero-fill
        #   2. drop identical items from the front (leaving us with "tail")
        #   3. compare both tails
        zipped = zip_longest(a, b, fillvalue=None)
        tail: List[Tuple[int, int]] = []
        for tmp_a, tmp_b in zipped:
            if tmp_a == tmp_b and not tail:
                continue
            tail.append((tmp_a, tmp_b))

        # if we only have Nones in "b", we know that "a" was longer and that it
        # is a direct subtree of "b" (no diverging nodes). Otherwise we would
        # have te divergence in "b", and we can say that "b is contained in a"
        _, unzipped_b = zip(*tail)
        if all([x is None for x in unzipped_b]):
            return True

        # In all other cases we end up with an unmatching tail and know that "b
        # is not contained in a".
        return False

    def __lt__(self, other: "ObjectIdentifier") -> bool:
        return self.identifiers < other.identifiers

    def __hash__(self) -> int:
        return hash(self.identifiers)

    def __add__(self, other: "ObjectIdentifier") -> "ObjectIdentifier":
        nodes = self.identifiers + other.identifiers
        return ObjectIdentifier(*nodes)

    def __getitem__(self, index: int) -> "ObjectIdentifier":
        return ObjectIdentifier(self.identifiers[index])

    def pythonize(self) -> str:
        return ".".join([str(_) for _ in self.identifiers])

    def parentof(self, other: "ObjectIdentifier") -> bool:
        """
        Convenience method to check whether this OID is a parent of another OID
        """
        return other in self

    def childof(self, other: "ObjectIdentifier") -> bool:
        """
        Convenience method to check whether this OID is a child of another OID
        """
        return self in other


class ObjectDescriptor(Type[str]):
    TAG = 0x07
    value = ""


class External(Type[bytes]):
    TAG = 0x08
    value = b""


class Real(Type[float]):
    TAG = 0x09
    value = 0.0


class Enumerated(Type[List[Any]]):
    TAG = 0x0A
    value: List[Any] = []


class EmbeddedPdv(Type[bytes]):
    TAG = 0x0B
    value = b""


class Utf8String(Type[str]):
    TAG = 0x0C
    value = ""


class RelativeOid(Type[str]):
    TAG = 0x0D
    value = ""


class Set(Type[bytes]):
    TAG = 0x11
    value = b""


class NumericString(Type[str]):
    TAG = 0x12
    value = ""


class PrintableString(Type[str]):
    TAG = 0x13
    value = ""


class T61String(Type[str]):
    TAG = 0x14
    value = ""
    __INITIALISED = False

    def __init__(self, value: Union[str, bytes] = "") -> None:
        if not T61String.__INITIALISED:
            t61codec.register()
            self.__INITIALISED = True
        if isinstance(value, str):
            self.value = value
        else:
            self.value = value.decode("t61")
        self.length = encode_length(len(self.value))

    def __bytes__(self) -> bytes:
        tinfo = TypeInfo(self.TYPECLASS, TypeNature.PRIMITIVE, self.TAG)
        return bytes(tinfo) + self.length + self.value.encode("t61")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, T61String) and self.value == other.value

    @classmethod
    def decode(cls, data: bytes) -> "T61String":
        return cls(data)

    def pythonize(self) -> str:
        """
        Convert this object in an appropriate python object
        """
        return self.value


class VideotexString(Type[str]):
    TAG = 0x15
    value = ""


class IA5String(Type[str]):
    TAG = 0x16
    value = ""


class UtcTime(Type[datetime]):
    TAG = 0x17
    value = datetime(1979, 1, 1, tzinfo=timezone.utc)


class GeneralizedTime(Type[datetime]):
    TAG = 0x18
    value = datetime(1979, 1, 1)


class GraphicString(Type[str]):
    TAG = 0x19
    value = ""


class VisibleString(Type[str]):
    TAG = 0x1A
    value = ""


class GeneralString(Type[str]):
    TAG = 0x1B
    value = ""


class UniversalString(Type[str]):
    TAG = 0x1C
    value = ""


class CharacterString(Type[str]):
    TAG = 0x1D
    value = ""


class BmpString(Type[str]):
    TAG = 0x1E
    value = ""


class EOC(Type[bytes]):
    TAG = 0x00
    value = b""


class BitString(Type[str]):
    TAG = 0x03
    value = ""
