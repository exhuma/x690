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
# pylint: disable=abstract-method, missing-class-docstring, too-few-public-methods


from dataclasses import astuple
from datetime import datetime, timezone
from itertools import zip_longest
from sys import byteorder
from textwrap import indent
from typing import (
    Any,
    Dict,
    Generator,
    Generic,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
)
from typing import Type as TypeType
from typing import TypeVar, Union

import t61codec

from .exc import IncompleteDecoding, UnexpectedType, X690Error
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


def find_slice(data: bytes, start_index: int = 0) -> Tuple[slice, int]:
    if not bytes:
        return slice(0, -1)

    length, offset = astuple(decode_length(data, start_index + 1))
    if length == -1:
        data_start = start_index + 2
        data_end = data.find(b"\x00\x00", data_start)
        next_tlv = data_end + 2
    else:
        data_start = start_index + 1 + offset
        data_end = data_start + length
        next_tlv = data_end
    return slice(data_start, data_end), next_tlv


def decode(data: bytes, start_index: int) -> Tuple["Type[Any]", int]:
    if not data[start_index:]:
        return Null(), 0

    type_ = TypeInfo.from_bytes(data[start_index])
    data_slice, next_tlv = find_slice(data, start_index)
    try:
        cls = Type.get(type_.cls, type_.tag, type_.nature)
    except KeyError:
        cls = UnknownType

    value = cls.decode_raw(data[data_slice])
    output = cls(value)
    if isinstance(output, UnknownType):
        output.tag = data[start_index]

    return output, next_tlv


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
    value, next_tlv = decode(data, 0)

    if enforce_type and not isinstance(value, enforce_type):
        raise UnexpectedType(
            f"Unexpected decode result. Expected instance of type "
            f"{enforce_type} but got {type(value)} instead"
        )

    remainder = data[next_tlv:]
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

    __slots__ = ["_value"]
    __registry: Dict[Tuple[str, int, TypeNature], TypeType["Type[Any]"]] = {}
    TYPECLASS: TypeClass = TypeClass.UNIVERSAL
    NATURE = [TypeNature.CONSTRUCTED]
    TAG: int = -1
    DEFAULT_VALUE: TWrappedPyType
    _value: TWrappedPyType
    raw_bytes: bytes

    def __init_subclass__(cls: TypeType["Type[Any]"]) -> None:
        if cls.__name__ == "Type" and cls.TAG == -1:
            return
        for nature in cls.NATURE:
            Type.__registry[(cls.TYPECLASS, cls.TAG, nature)] = cls

    @property
    def value(self) -> TWrappedPyType:
        return self._value

    @staticmethod
    def decode_raw(data: bytes) -> TWrappedPyType:
        return data  # type: ignore

    @staticmethod
    def get(
        typeclass: str, typeid: int, nature: TypeNature = TypeNature.CONSTRUCTED
    ) -> TypeType["Type[Any]"]:
        cls = Type.__registry[(typeclass, typeid, nature)]
        return cls

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
    def decode(cls, data: bytes) -> "Type[TWrappedPyType]":  # pragma: no cover
        """
        This method takes a bytes object which contains the raw content octets
        of the object. That means, the octets *without* the type information
        and length.

        This function must be overridden by the concrete subclasses.
        """
        slc, _ = find_slice(data)
        output = cls.decode_raw(data[slc])
        return cls(output)

    def __init__(self, value: Optional[TWrappedPyType] = None) -> None:
        if value is None:
            self._value = self.DEFAULT_VALUE
            self.raw_bytes = b""
        else:
            self._value = value
            self.raw_bytes = self.encode_raw(value)

    def __bytes__(self) -> bytes:  # pragma: no cover
        """
        Convert this instance into a bytes object. This must be implemented by
        subclasses.
        """
        value = self.encode_raw(self._value)
        tinfo = TypeInfo(self.TYPECLASS, self.NATURE[0], self.TAG)
        return bytes(tinfo) + encode_length(len(value)) + value

    def __repr__(self) -> str:
        # pylint: disable=no-member
        return "%s(%r)" % (self.__class__.__name__, self._value)

    def encode_raw(self, value: TWrappedPyType) -> bytes:
        return b""

    def pythonize(self) -> TWrappedPyType:
        """
        Convert this instance to an appropriate pure Python object.
        """
        # pylint: disable=no-member
        return self._value

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

    DEFAULT_VALUE = b""
    TAG = 0x99

    def __init__(self, value: bytes = b"", tag: int = -1) -> None:
        super().__init__(value)
        self._value = value
        self.tag = tag
        self.length = len(value)

    def __repr__(self) -> str:
        typeinfo = TypeInfo.from_bytes(self.tag)
        tinfo = f"{typeinfo.cls}/{typeinfo.nature}/{typeinfo.tag}"
        return f"<{self.__class__.__name__} {self.tag} {self._value!r} {tinfo}>"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, UnknownType)
            and self._value == other._value
            and self.tag == other.tag
        )

    def encode_raw(self, value: bytes) -> bytes:
        return value

    def pretty(self, depth: int = 0) -> str:
        wrapped = wrap(
            visible_octets(self._value), str(type(self)), depth
        ).splitlines()
        if len(wrapped) > 15:
            line_width = len(wrapped[0])
            sniptext = ("<%d more lines>" % (len(wrapped) - 10 - 5)).center(
                line_width - 2
            )
            wrapped = wrapped[:10] + ["┊%s┊" % sniptext] + wrapped[-5:]
        typeinfo = TypeInfo.from_bytes(self.tag)
        lines = [
            "Unknown Type",
            f"  │ Tag:       {self.tag}",
            "  │ Type Info:",
            f"  │  │ Class: {typeinfo.cls}",
            f"  │  │ Nature: {typeinfo.nature}",
            f"  │  │ Tag: {typeinfo.tag}",
        ] + wrapped
        return indent(
            "\n".join(lines),
            INDENT_STRING * depth,
        )


class Boolean(Type[bool]):
    TAG = 0x01
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE = False

    @staticmethod
    def decode_raw(data: bytes) -> "Boolean":
        return data != b"\x00"

    @classmethod
    def validate(cls, data: bytes) -> None:
        super().validate(data)
        if data[1] != 1:
            raise ValueError(
                "Unexpected Boolean value. Length should be 1,"
                " it was %d" % data[1]
            )

    def encode_raw(self, value: bool) -> bytes:
        return b"\x01" if value else b"\x00"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Boolean) and self._value == other._value


class Null(Type[None]):
    TAG = 0x05
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE = None

    @classmethod
    def validate(cls, data: bytes) -> None:
        super().validate(data)
        if data[1] != 0:
            raise ValueError(
                "Unexpected NULL value. Length should be 0, it "
                "was %d" % data[1]
            )

    @staticmethod
    def decode_raw(data: bytes) -> "Null":
        return None

    def encode_raw(self, value: None) -> bytes:
        return b"\x00"

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
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = b""

    def __init__(self, value: Union[str, bytes] = b"") -> None:
        if isinstance(value, str):
            value = value.encode("ascii")
        super().__init__(value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, OctetString) and self._value == other._value

    def encode_raw(self, value: bytes) -> bytes:
        return value

    def pretty(self, depth: int = 0) -> str:
        if self._value == b"":
            return repr(self)
        try:
            # We try to decode embedded X.690 items. If we can't, we display
            # the value raw
            embedded = pop_tlv(self._value)[0]  # type: ignore
            if isinstance(embedded, UnknownType):
                raise TypeError("UnknownType should not be prettified here")
            return wrap(embedded.pretty(0), f"Embedded in {type(self)}", depth)
        except:  # pylint: disable=bare-except
            wrapped = wrap(visible_octets(self._value), str(type(self)), depth)
            return wrapped


class Sequence(Type[List[Type[Any]]]):
    """
    Represents an X.690 sequence type. Instances of this class are iterable and
    indexable.
    """

    TAG = 0x10
    value: List[Type[Any]] = []

    @classmethod
    def decode_raw(cls, data: bytes) -> "Sequence":
        item, next_pos = decode(data, 0)
        items = [item]
        while next_pos < len(data):
            item, next_pos = decode(data, next_pos)
            items.append(item)
        return cls(items)

    def __init__(self, items: Optional[List[Type[Any]]] = None) -> None:
        super().__init__(items if items else [])
        self.iter_position = 0

    def encode_raw(self, value: List[Type[Any]]) -> bytes:
        items = [bytes(item) for item in value]
        output = b"".join(items)
        return output

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sequence):
            return False
        return self.raw_bytes == other.raw_bytes

    def __repr__(self) -> str:
        item_repr = [item for item in self]
        return "Sequence(%r)" % item_repr

    def __len__(self) -> int:
        return len(self._value)

    def __iter__(self) -> Iterator[Type[Any]]:
        if self._value:
            yield from self._value
        else:
            return

    def __getitem__(self, idx: int) -> Type[Any]:
        return self._value[idx]

    def pythonize(self) -> List[Type[Any]]:
        return [obj.pythonize() for obj in self]

    def pretty(self, depth: int = 0) -> str:  # pragma: no cover
        """
        Overrides :py:meth:`.Type.pretty`
        """
        lines = [f"{self.__class__.__name__} with {len(self._value)} items:"]
        for item in self._value:
            prettified_item = item.pretty(depth)
            bullet = INDENT_STRING * depth + "⁃ "
            for line in prettified_item.splitlines():
                lines.append(bullet + line)
                bullet = "  "
        return "\n".join(lines)


class Integer(Type[int]):
    SIGNED = True
    TAG = 0x02
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE = 0

    @staticmethod
    def decode_raw(data: bytes) -> int:
        return int.from_bytes(data, "big", signed=Integer.SIGNED)

    def encode_raw(self, value: int) -> bytes:
        octets = [value & 0b11111111]

        # Append remaining octets for long integers.
        remainder = value
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
        return bytes(octets)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Integer) and self._value == other._value


class ObjectIdentifier(Type[Tuple[int, ...]]):
    """
    Represents an OID.

    Instances of this class support containment checks to determine if one OID
    is a sub-item of another::

        >>> ObjectIdentifier((1, 2, 3, 4, 5)) in ObjectIdentifier((1, 2, 3))
        True

        >>> ObjectIdentifier((1, 2, 4, 5, 6)) in ObjectIdentifier((1, 2, 3))
        False
    """

    TAG = 0x06
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE = (0,)

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
    def decode_raw(cls, data: bytes) -> Tuple[int, ...]:
        # Special case for "empty" object identifiers which should be returned
        # as "0"
        if not data:
            return (0,)

        # unpack the first byte into first and second sub-identifiers.
        data0 = data[0]
        first, second = data0 // 40, data0 % 40
        output = [first, second]

        remaining = iter(data[1:])

        for node in remaining:
            # Each node can only contain values from 0-127. Other values need
            # to be combined.
            if node > 127:
                collapsed_value = ObjectIdentifier.decode_large_value(
                    node, remaining
                )
                output.append(collapsed_value)
                continue
            output.append(node)

        instance = tuple(output)
        return instance

    @staticmethod
    def from_string(value: str) -> "ObjectIdentifier":
        """
        Create an OID from a string
        """

        if value == ".":
            return ObjectIdentifier((1,))

        if value.startswith("."):
            value = value[1:]

        identifiers = tuple(int(ident, 10) for ident in value.split("."))
        return ObjectIdentifier(identifiers)

    def collapse_identifiers(
        self, identifiers: Tuple[int, ...]
    ) -> Tuple[int, ...]:
        if len(identifiers) == 0:
            return tuple()
        elif len(identifiers) > 1:
            # The first two bytes are collapsed according to X.690
            # See https://en.wikipedia.org/wiki/X.690#BER_encoding
            first, second, rest = (
                identifiers[0],
                identifiers[1],
                identifiers[2:],
            )
            first_output = (40 * first) + second
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

        collapsed_identifiers = [first_output]
        for subidentifier in rest:
            collapsed_identifiers.extend(
                ObjectIdentifier.encode_large_value(subidentifier)
            )
        return tuple(collapsed_identifiers)

    def encode_raw(self, value: Tuple[int, ...]) -> bytes:
        collapsed_identifiers = self.collapse_identifiers(value)
        if collapsed_identifiers == (0,):
            return b""
        return bytes(collapsed_identifiers)

    def __int__(self) -> int:
        if len(self._value) != 1:
            raise ValueError(
                "Only ObjectIdentifier with one node can be "
                "converted to int. %r is not convertable" % self
            )
        return self._value[0]

    def __str__(self) -> str:
        return ".".join([str(_) for _ in self._value])

    def __repr__(self) -> str:
        return "ObjectIdentifier(%r)" % (self._value,)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ObjectIdentifier) and self._value == other._value
        )

    def __len__(self) -> int:
        return len(self._value)

    def __contains__(self, other: "ObjectIdentifier") -> bool:
        """
        Check if one OID is a child of another.

        TODO: This has been written in the middle of the night! It's messy...
        """
        # pylint: disable=invalid-name

        a, b = other._value, self._value

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
        return self._value < other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __add__(self, other: "ObjectIdentifier") -> "ObjectIdentifier":
        nodes = self._value + other._value
        return ObjectIdentifier(nodes)

    def __getitem__(self, index: int) -> "ObjectIdentifier":
        return ObjectIdentifier((self._value[index],))

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
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class External(Type[bytes]):
    TAG = 0x08
    DEFAULT_VALUE = b""


class Real(Type[float]):
    TAG = 0x09
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE = 0.0


class Enumerated(Type[List[Any]]):
    TAG = 0x0A
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE: List[Type[Any]] = []


class EmbeddedPdv(Type[bytes]):
    TAG = 0x0B
    DEFAULT_VALUE = b""


class Utf8String(Type[str]):
    TAG = 0x0C
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class RelativeOid(Type[str]):
    TAG = 0x0D
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE = ""


class Set(Type[bytes]):
    TAG = 0x11
    DEFAULT_VALUE = b""


class NumericString(Type[str]):
    TAG = 0x12
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class PrintableString(Type[str]):
    TAG = 0x13
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class T61String(Type[str]):
    TAG = 0x14
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""
    __INITIALISED = False

    def __init__(self, value: Union[str, bytes] = "") -> None:
        if isinstance(value, str):
            super().__init__(value)
        else:
            super().__init__(T61String.decode_raw(value))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, T61String) and self._value == other._value

    @staticmethod
    def decode_raw(data: bytes) -> str:
        if not T61String.__INITIALISED:
            t61codec.register()
            T61String.__INITIALISED = True
        return data.decode("t61")

    def encode_raw(self, value: str) -> bytes:
        if not T61String.__INITIALISED:
            t61codec.register()
            T61String.__INITIALISED = True
        return value.encode("t61")


class VideotexString(Type[str]):
    TAG = 0x15
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class IA5String(Type[str]):
    TAG = 0x16
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class UtcTime(Type[datetime]):
    TAG = 0x17
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = datetime(1979, 1, 1, tzinfo=timezone.utc)


class GeneralizedTime(Type[datetime]):
    TAG = 0x18
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = datetime(1979, 1, 1)


class GraphicString(Type[str]):
    # NOTE: As per x.690, this should inherit from OctetString. However, this
    #       library serves as an abstraction layer between X.690 and Python.
    #       For this reason, it defines this as a "str" type. To keep the
    #       correct behaviours, we can still "borrow" the implementation from
    #       OctetString if needed
    TAG = 0x19
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""

    @staticmethod
    def decode_raw(data: bytes) -> str:
        return data.decode("ascii")


class VisibleString(Type[str]):
    TAG = 0x1A
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class GeneralString(Type[str]):
    TAG = 0x1B
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class UniversalString(Type[str]):
    TAG = 0x1C
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class CharacterString(Type[str]):
    TAG = 0x1D
    DEFAULT_VALUE = ""


class BmpString(Type[str]):
    TAG = 0x1E
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""


class EOC(Type[bytes]):
    TAG = 0x00
    NATURE = [TypeNature.PRIMITIVE]
    DEFAULT_VALUE = b""


class BitString(Type[str]):
    TAG = 0x03
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    DEFAULT_VALUE = ""
