"""
The type classes of X.690 and the :func:`decode` function.

Every class wraps a Python value and encodes it with :class:`bytes`.
:class:`X690Type` is the base class: subclassing it registers a new
universal, application or private type with :func:`decode`.
Context-specific types are declared on their enclosing type with
:attr:`X690Type.CHILD_TYPES`. The documentation pages "Supported types" and
"Custom types" describe the classes and how to add new ones.
"""
# pylint: disable=abstract-method, missing-class-docstring, too-few-public-methods

import logging
import math
import re
import string
from array import array
from collections.abc import Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from fractions import Fraction
from itertools import zip_longest
from textwrap import indent
from types import MappingProxyType
from typing import (
    Any,
    ClassVar,
    Generic,
    Self,
    TypeVar,
    Union,
    overload,
)

import t61codec

from .exc import IncompleteDecoding, UnexpectedType, X690Error
from .util import (
    INDENT_STRING,
    TypeClass,
    TypeInfo,
    TypeNature,
    encode_length,
    get_value_slice,
    visible_octets,
    wrap,
)

#: The Python type wrapped by an :class:`X690Type`
TWrappedPyType = TypeVar("TWrappedPyType", bound=Any)
TPopType = TypeVar("TPopType", bound=Any)
TConcreteType = TypeVar("TConcreteType", bound="X690Type[Any]")
TInnerType = TypeVar("TInnerType", bound="X690Type[Any]")


class Uninitialised:
    """
    The type of :data:`UNINITIALISED`, the only instance.

    It marks a value that has not been decoded yet.
    """

    def __repr__(self) -> str:
        return "UNINITIALISED"


#: sentinel value for uninitialised objects (used for lazy decoding)
UNINITIALISED = Uninitialised()

_T61_CODEC = t61codec.Codec()


#: Identifies a type within a lookup: its class, tag and nature
LOG = logging.getLogger(__name__)

TypeKey = tuple[TypeClass, int, TypeNature]

#: The types that decode everywhere: universal, application and private
#: types, by key. Context-specific types are never in here.
_REGISTRY: dict[TypeKey, type["X690Type[Any]"]] = {}

#: The class attributes that make a subclass a type of its own
_IDENTITY = frozenset({"TYPECLASS", "TAG", "NATURE"})

#: The lookup used where no enclosing type declares any types
_NO_TYPES: Mapping[TypeKey, type["X690Type[Any]"]] = MappingProxyType({})


def _type_map(
    types: Iterable[type["X690Type[Any]"]],
) -> Mapping[TypeKey, type["X690Type[Any]"]]:
    """
    Build a lookup from type key to class for *types*.

    Every class is entered once for each of its natures.

    :param types: The classes to enter.
    :return: A new dictionary keyed by ``(TYPECLASS, TAG, nature)``.
    :raises ValueError: If two classes share the same key.
    """
    output: dict[TypeKey, type[X690Type[Any]]] = {}
    for cls in types:
        for nature in cls.NATURE:
            key = (cls.TYPECLASS, cls.TAG, nature)
            existing = output.get(key)
            if existing is not None and existing is not cls:
                raise ValueError(
                    f"{existing.__name__} and {cls.__name__} share the "
                    f"{cls.TYPECLASS.value} {nature.value} tag {cls.TAG}"
                )
            output[key] = cls
    return MappingProxyType(output)


def decode(
    data: bytes,
    start_index: int = 0,
    enforce_type: type[TPopType] | None = None,
    strict: bool = False,
    types: Iterable[type["X690Type[Any]"]] = (),
) -> tuple[TPopType, int]:
    """
    Convert a X.690 bytes object into a Python instance, and the location of
    the next object.

    Given a :py:class:`bytes` object and any start-index, inspects and parses
    the octets starting at the given index (as many as required) to determine
    variable type (and corresponding Python class), and length. That class is
    then used to parse the object located in ``data`` at the given index. The
    location of the start of the next (subsequent) object is also determined.

    The return value is a tuple with the decoded object and the start-index
    of the next object.

    Example::

        >>> data = b'\\x02\\x01\\x05\\x11'
        >>> decode(data)
        (Integer(5), 3)
        >>> data = b'some-skippable-bytes\\x02\\x01\\x05\\x11'
        >>> decode(data, 20)
        (Integer(5), 23)

    :param data: The buffer to read from. It is never copied.
    :param start_index: The position of the value in *data*.
    :param enforce_type: Raise :exc:`~x690.exc.UnexpectedType` unless the
        value is an instance of this class.
    :param strict: Raise :exc:`~x690.exc.IncompleteDecoding` if data is left
        after the value.
    :param types: Classes to try before the global registry for this value,
        as :attr:`~x690.types.X690Type.CHILD_TYPES` does for the items of
        a constructed type. Use it to decode a context-specific value on
        its own.
    :return: The value and the index of the next value.
    """
    lookup = _type_map(types) if types else _NO_TYPES
    output, next_tlv = _decode_value(data, start_index, lookup)

    if enforce_type and not isinstance(output, enforce_type):
        raise UnexpectedType(
            f"Unexpected decode result. Expected instance of type "
            f"{enforce_type} but got {type(output)} instead"
        )

    if strict and next_tlv < len(data):
        remainder = data[next_tlv:]
        raise IncompleteDecoding(
            f"Strict decoding still had {len(remainder)} remaining bytes!",
            remainder=remainder,
        )

    return output, next_tlv  # type: ignore


def _log_unknown_type(
    type_: TypeInfo, offset: int, parent: type["X690Type[Any]"] | None
) -> None:
    """
    Log that no class is known for the identifier of a value.
    """
    if not LOG.isEnabledFor(logging.DEBUG):
        return
    extra: dict[str, str | int] = {
        "x690.type.class": type_.cls.value,
        "x690.type.nature": type_.nature.value,
        "x690.type.tag": type_.tag,
        "x690.offset": offset,
    }
    if parent is not None:
        extra["x690.enclosing_type"] = parent.__name__
    LOG.debug("Unknown type decoded", extra=extra)


def _log_overridden_type(
    key: TypeKey,
    cls: type["X690Type[Any]"],
    parent: type["X690Type[Any]"] | None,
) -> None:
    """
    Log that a child type replaces the class registered for the same key.
    """
    registered = _REGISTRY.get(key)
    if registered is None or registered is cls:
        return
    extra: dict[str, str | int] = {
        "x690.type.tag": key[1],
        "x690.type.name": cls.__name__,
    }
    if parent is not None:
        extra["x690.enclosing_type"] = parent.__name__
    LOG.debug("Registered type overridden by child type", extra=extra)


def _decode_value(
    data: bytes,
    start_index: int,
    lookup: Mapping[TypeKey, type["X690Type[Any]"]],
    parent: type["X690Type[Any]"] | None = None,
) -> tuple["X690Type[Any]", int]:
    """
    Decode the value at *start_index*, trying *lookup* before the global
    registry.

    *parent* is the enclosing type, used only to describe log records.
    """
    if start_index >= len(data):
        raise IndexError(
            f"Attempting to read from position {start_index} "
            f"on data with length {len(data)}"
        )

    type_ = TypeInfo.from_bytes(data[start_index])
    key = (type_.cls, type_.tag, type_.nature)
    cls = lookup.get(key)
    if cls is None:
        cls = _REGISTRY.get(key)
        if cls is None:
            cls = UnknownType
            _log_unknown_type(type_, start_index, parent)
    elif LOG.isEnabledFor(logging.DEBUG):
        _log_overridden_type(key, cls, parent)

    data_slice, next_tlv = get_value_slice(data, start_index)
    output = cls.from_bytes(data, data_slice)
    if cls is UnknownType:
        output.tag = data[start_index]  # type: ignore
    return output, next_tlv


class X690Type(Generic[TWrappedPyType]):
    """
    The superclass for all supported types.

    An instance wraps one Python value of type *TWrappedPyType*. It is
    created either from that value, to be encoded, or by :func:`decode`,
    which keeps the encoded bytes and converts them to a Python value only
    when :attr:`value` is first read. Subclassing registers a new type; see
    :doc:`/custom-types`.

    :param value: The Python value to wrap. The default,
        :data:`UNINITIALISED`, creates an empty instance that
        :meth:`from_bytes` fills with encoded bytes.
    """

    __slots__ = ["pyvalue", "_raw_bytes", "_buffer", "_bounds"]

    #: The x690 type-class (universal, application, context or private)
    TYPECLASS: TypeClass = TypeClass.UNIVERSAL

    #: The x690 "private/constructed" information
    NATURE = [TypeNature.CONSTRUCTED]

    #: The x690 identifier for the type
    TAG: int = -1

    #: The types of the values inside this one. Their tags are looked up
    #: here before the global registry, and context-specific tags only
    #: here. Assign a new collection to change it after the class statement.
    CHILD_TYPES: ClassVar[Collection[type["X690Type[Any]"]]] = ()

    #: CHILD_TYPES as a lookup, with the collection it was built from
    _child_lookup: ClassVar[
        tuple[
            Collection[type["X690Type[Any]"]],
            Mapping[TypeKey, type["X690Type[Any]"]],
        ]
    ] = ((), _NO_TYPES)

    #: The decoded (or to-be encoded) Python value
    pyvalue: TWrappedPyType | Uninitialised

    #: Cache for the byte representation of "pyvalue" without
    #: metadata-header (only used for values built from Python objects)
    _raw_bytes: bytes

    #: The shared input buffer of a decoded value (``None`` if the value was
    #: not created from a buffer). Never copied during decoding.
    _buffer: bytes | None

    #: The location of the value's own content bytes within "_buffer"
    _bounds: slice

    def __init_subclass__(
        cls: type["X690Type[Any]"], register: bool = True, **kwargs: object
    ) -> None:
        """
        Register a new universal, application or private type.

        :param register: Pass ``register=False`` in the class statement to
            keep the type out of the global registry, so that it decodes
            only where an enclosing type lists it in :attr:`CHILD_TYPES`.
            Context-specific types are never registered.
        """
        super().__init_subclass__(**kwargs)
        cls.child_lookup()
        if not register or cls.TYPECLASS == TypeClass.CONTEXT:
            return
        if not _IDENTITY.intersection(vars(cls)):
            # Same type as the parent, for example a sequence that only
            # declares CHILD_TYPES: the parent stays registered.
            return
        for nature in cls.NATURE:
            _REGISTRY[(cls.TYPECLASS, cls.TAG, nature)] = cls

    @classmethod
    def child_lookup(cls) -> Mapping[TypeKey, type["X690Type[Any]"]]:
        """
        Return :attr:`CHILD_TYPES` as a read-only lookup keyed by
        ``(TYPECLASS, TAG, nature)``.

        The lookup is built once, and again only after a new collection is
        assigned to :attr:`CHILD_TYPES`.

        :raises ValueError: If two child types share the same key.
        """
        source, lookup = cls._child_lookup
        if source is not cls.CHILD_TYPES:
            source = cls.CHILD_TYPES
            lookup = _type_map(source) if source else _NO_TYPES
            cls._child_lookup = (source, lookup)
        return lookup

    @property
    def value(self) -> TWrappedPyType:
        """
        Returns the value as a pure Python type
        """
        if not isinstance(self.pyvalue, Uninitialised):
            return self.pyvalue
        buffer, bounds = self._source()
        return self.decode_raw(buffer, bounds)

    def _source(self) -> tuple[bytes, slice]:
        """
        Return the buffer and bounds holding this value's content bytes
        without copying them.
        """
        if self._buffer is None:
            return self.raw_bytes, slice(None)
        return self._buffer, self._bounds

    def detach(self) -> Self:
        """
        Copy the value's own content bytes and drop the reference to the
        buffer it was decoded from.

        Use this to keep a few values from a large document without keeping
        the whole document alive. Values that were not created from a buffer
        are left unchanged.

        >>> data = b"\\x02\\x01\\x05" + bytes(1000)
        >>> value, _ = decode(data)
        >>> value.detach() is value
        True
        >>> value.raw_bytes
        b'\\x05'

        :return: This instance.
        """
        if self._buffer is not None:
            self._buffer = bytes(self._buffer[self._bounds])
            self._bounds = slice(None)
        return self

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> TWrappedPyType:
        """
        Converts the raw byte-value (without type & length header) into a
        pure Python type

        >>> Integer.decode_raw(b"\\x05")
        5

        :param data: A data-block containing the byte-information
        :param slc: A slice of the data-block that contains the exact
            raw-bytes.
        :return: The value that should be wrapped by the current x690 type.
        """
        return data[slc]  # type: ignore

    @staticmethod
    def get(
        typeclass: str,
        typeid: int,
        nature: TypeNature = TypeNature.CONSTRUCTED,
    ) -> type["X690Type[Any]"]:
        """
        Retrieve a globally registered class by x690 type information.

        Subclassing :py:class:`x690.types.X690Type` registers universal,
        application and private types. Context-specific types are never
        registered: they are declared in :attr:`CHILD_TYPES` of the
        enclosing type.

        >>> X690Type.get("universal", 2, TypeNature.PRIMITIVE)
        <class 'x690.types.Integer'>

        :param typeclass: The value of a :class:`~x690.util.TypeClass`:
            ``"universal"``, ``"application"`` or ``"private"``.
        :param typeid: The tag number of the type.
        :param nature: Whether the type is primitive or constructed.
        :returns: The registered class.
        :raises KeyError: If no class is registered for the type.
        :raises ValueError: If *typeclass* is not a valid type class.
        """
        return _REGISTRY[(TypeClass(typeclass), typeid, nature)]

    @staticmethod
    def all() -> list[type["X690Type[Any]"]]:
        """
        Returns all globally registered classes
        """
        return list(_REGISTRY.values())

    @classmethod
    def validate(cls, data: bytes) -> None:
        """
        Given a bytes object, checks if the given class *cls* supports decoding
        this object. If not, raises a ValueError.

        Only the type class and the tag are compared, not the nature.

        >>> Integer.validate(b"\\x02\\x01\\x05")
        >>> Integer.validate(b"\\x04\\x01\\x05")
        Traceback (most recent call last):
        ...
        ValueError: Invalid type header! Expected a ...

        :param data: A complete encoded value, starting with the type octet.
        :raises ValueError: If the type octet is not that of this class.
        :raises IndexError: If *data* is empty.
        """
        tinfo = TypeInfo.from_bytes(data[0])
        if tinfo.cls != cls.TYPECLASS or tinfo.tag != cls.TAG:
            raise ValueError(
                "Invalid type header! "
                "Expected a %s class with tag "
                "ID 0x%02x, but got a %s class with "
                "tag ID 0x%02x" % (cls.TYPECLASS, cls.TAG, tinfo.cls, data[0])
            )

    @classmethod
    def decode(
        cls: type[TConcreteType], data: bytes
    ) -> TConcreteType:  # pragma: no cover
        """
        Decode a complete encoded value, starting at its type octet, into a
        new instance of this class.

        The type octet is not checked; call :meth:`validate` first for that.

        >>> Integer.decode(b"\\x02\\x01\\x05")
        Integer(5)

        :param data: The encoded value including type and length octets.
        :returns: A new instance holding the decoded value.
        :raises X690Error: If the length exceeds the available data.
        """
        slc = get_value_slice(data).bounds
        output = cls.decode_raw(data, slc)
        return cls(output)

    @classmethod
    def from_bytes(
        cls: type[TConcreteType], data: bytes, slc: slice = slice(None)
    ) -> TConcreteType:
        """
        Creates a new :py:class:`x690.types.X690Type` instance from raw-bytes
        (without type nor length bytes)

        >>> Integer.from_bytes(b"\\x01")
        Integer(1)
        >>> OctetString.from_bytes(b"hello-world")
        OctetString(b'hello-world')
        >>> Boolean.from_bytes(b"\\x00")
        Boolean(False)

        :param data: A buffer containing the content octets. It is shared,
            not copied.
        :param slc: The location of the content octets within *data*.
        :returns: A new instance that decodes its value on first access.
        :raises X690Error: If the class cannot be created without
            arguments.
        """
        try:
            instance = cls()
        except TypeError as exc:
            raise X690Error(
                "Custom types must have a no-arg constructor allowing "
                "x690.types.UNINITIALISED as value. Custom type %r does not "
                "support this!" % cls
            ) from exc
        instance._buffer = data
        instance._bounds = slc
        return instance

    def __init__(
        self,
        value: TWrappedPyType | Uninitialised = UNINITIALISED,
    ) -> None:
        self.pyvalue = value
        self._raw_bytes = b""
        self._buffer = None
        self._bounds = slice(None)

    @property
    def raw_bytes(self) -> bytes:
        """
        The value's own content bytes, without the type and length header.

        For decoded values this is a copy of the bytes at the value's
        location in the input buffer.
        """
        if self._buffer is not None:
            return self._buffer[self._bounds]
        if self._raw_bytes != b"":
            return self._raw_bytes
        if self.pyvalue is UNINITIALISED:
            return b""
        self._raw_bytes = self.encode_raw()
        return self._raw_bytes

    @raw_bytes.setter
    def raw_bytes(self, value: bytes) -> None:
        self._buffer = value
        self._bounds = slice(None)

    def __bytes__(self) -> bytes:  # pragma: no cover
        """
        Convert this instance into a bytes object. This must be implemented by
        subclasses.
        """
        value = self.raw_bytes or self.encode_raw()
        tinfo = TypeInfo(self.TYPECLASS, self.NATURE[0], self.TAG)
        return bytes(tinfo) + encode_length(len(value)) + value

    def __eq__(self, other: object) -> bool:
        """
        Two values are equal if they are of exactly the same class and hold
        the same value.

        Subclasses compare equal to nothing but their own class, so a
        context-specific subclass of :class:`Sequence` does not equal a
        plain one. Values are not hashable.
        """
        if not isinstance(other, X690Type) or type(other) is not type(self):
            return False
        return bool(self.value == other.value)

    def __repr__(self) -> str:
        name = self.__class__.__name__
        if isinstance(self.pyvalue, Uninitialised):
            if not self.raw_bytes:
                return "%s()" % name
            try:
                return "%s(%r)" % (name, self.value)
            except (ValueError, UnicodeDecodeError):
                # malformed content must not break the repr
                return "%s(raw=%r)" % (name, self.raw_bytes)
        return "%s(%r)" % (name, self.pyvalue)

    @property
    def length(self) -> int:
        """
        Return the x690 byte-length of this instance
        """
        buffer, bounds = self._source()
        start, stop, _ = bounds.indices(len(buffer))
        return max(stop - start, 0)

    def encode_raw(self) -> bytes:
        """
        Convert this instance into raw x690 bytes (excluding the type and
        length header)

        >>> import x690.types as t
        >>> Integer(5).encode_raw()
        b'\\x05'
        >>> Boolean(True).encode_raw()
        b'\\x01'
        >>> X690Type(t.UNINITIALISED).encode_raw()
        b''
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        return self.pyvalue

    def pythonize(self) -> TWrappedPyType:
        """
        Convert this instance to an appropriate pure Python object.
        """
        return self.value

    def pretty(self, depth: int = 0) -> str:  # pragma: no cover
        """
        Returns a readable representation (possibly multiline) of the value.

        The value is indented by *depth* levels of indentation

        By default this simply returns the string representation. But more
        complex values may override this.

        :param depth: The number of indentation levels to prepend.
        :returns: The text to display.
        """
        return indent(str(self), INDENT_STRING * depth)


class UnknownType(X690Type[bytes]):
    """
    A fallback type for anything not in X.690.

    Instances of this class contain the raw information as parsed from the
    bytes as the following attributes:

    * ``value``: The value without leading metadata (as bytes value)
    * ``tag``: The *unparsed* "tag". This is the type ID as defined in the
      reference document. See :py:class:`~x690.util.TypeInfo` for
      details.
    * ``typeinfo``: unused (derived from *tag* and only here for consistency
      with ``__repr__`` of this class).

    :param value: The content octets.
    :param tag: The unparsed identifier octet of the value.
    """

    __slots__ = ("tag",)
    TAG = 0x99

    def __init__(self, value: bytes = b"", tag: int = -1) -> None:
        super().__init__(value or UNINITIALISED)
        self.tag = tag

    def __repr__(self) -> str:
        typeinfo = TypeInfo.from_bytes(self.tag)
        tinfo = f"{typeinfo.cls.value}/{typeinfo.nature.value}/{typeinfo.tag}"
        return f"<{self.__class__.__name__} {self.tag} {self.value!r} {tinfo}>"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, UnknownType)
            and type(other) is type(self)
            and self.value == other.value
            and self.tag == other.tag
        )

    def pretty(self, depth: int = 0) -> str:
        """
        Returns a prettified string with *depth* levels of indentation

        The content is shown as a hexdump, shortened if it is long. See
        :py:meth:`~.X690Type.pretty`.

        :param depth: The number of indentation levels to prepend.
        :returns: The text to display.
        """
        wrapped = wrap(
            visible_octets(self.value), str(type(self)), depth
        ).splitlines()
        if len(wrapped) > 15:
            line_width = len(wrapped[0])
            sniptext = ("<%d more lines>" % (len(wrapped) - 10 - 5)).center(
                line_width - 2
            )
            wrapped = wrapped[:10] + ["┊%s┊" % sniptext] + wrapped[-5:]
        typeinfo = TypeInfo.from_bytes(self.tag)
        lines = [
            "Unknown X690Type",
            f"  │ Tag:       {self.tag}",
            "  │ X690Type Info:",
            f"  │  │ Class: {typeinfo.cls}",
            f"  │  │ Nature: {typeinfo.nature}",
            f"  │  │ Tag: {typeinfo.tag}",
        ] + wrapped
        return indent(
            "\n".join(lines),
            INDENT_STRING * depth,
        )


class Boolean(X690Type[bool]):
    """
    The ``BOOLEAN`` type, tag ``0x01``, holding a :class:`bool`.

    Encoding writes one content octet: ``0x01`` for true, ``0x00`` for
    false.
    """

    __slots__ = ()
    TAG = 0x01
    NATURE = [TypeNature.PRIMITIVE]

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> bool:
        """
        Decode the content octets as a :class:`bool`.

        Any content other than a single zero octet is true.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded value.
        """
        return data[slc] != b"\x00"

    @classmethod
    def validate(cls, data: bytes) -> None:
        """
        Overrides :py:meth:`.X690Type.validate`

        :param data: A complete encoded value, starting with the type octet.
        :raises ValueError: If the type octet is not that of a
            ``BOOLEAN`` or the length is not 1.
        """
        super().validate(data)
        if data[1] != 1:
            raise ValueError(
                "Unexpected Boolean value. Length should be 1,"
                " it was %d" % data[1]
            )

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        return b"\x01" if self.pyvalue else b"\x00"


class Null(X690Type[None]):
    """
    The ``NULL`` type, tag ``0x05``. Its value is always ``None``.

    The content is empty. An instance is false in a boolean context.
    """

    __slots__ = ()
    TAG = 0x05
    NATURE = [TypeNature.PRIMITIVE]

    @classmethod
    def validate(cls, data: bytes) -> None:
        """
        Overrides :py:meth:`.X690Type.validate`

        :param data: A complete encoded value, starting with the type octet.
        :raises ValueError: If the type octet is not that of a ``NULL`` or
            the length is not 0.
        """
        super().validate(data)
        if data[1] != 0:
            raise ValueError(
                "Unexpected NULL value. Length should be 0, it was %d" % data[1]
            )

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> None:
        """
        Return ``None``, whatever the content octets are.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: ``None``.
        """
        # pylint: disable=unused-argument
        return None

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`

        >>> Null().encode_raw()
        b'\\x00'
        """
        # pylint: disable=no-self-use
        return b"\x00"

    def __bytes__(self) -> bytes:
        return b"\x05\x00"

    def __repr__(self) -> str:
        return "Null()"

    def __bool__(self) -> bool:
        return False

    def __nonzero__(self) -> bool:  # pragma: no cover
        return False


class OctetString(X690Type[bytes]):
    """
    The ``OCTET STRING`` type, tag ``0x04``, holding :class:`bytes`.

    The content is arbitrary binary data without a character encoding, so
    it is kept as raw bytes.

    :param value: The octets. A :class:`str` is encoded as ASCII.
    :raises UnicodeEncodeError: If *value* is a :class:`str` with
        non-ASCII characters.
    """

    __slots__ = ()
    TAG = 0x04
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]

    def __init__(self, value: str | bytes | Uninitialised = b"") -> None:
        if isinstance(value, str):
            value = value.encode("ascii")

        # The custom init allows us to pass in str instances instead of only
        # bytes. We still need to pass down "None" if need to detect
        # "not-yet-decoded" values
        if not value:
            value = UNINITIALISED

        super().__init__(value)

    def pretty(self, depth: int = 0) -> str:
        """
        Returns a prettified string with *depth* levels of indentation

        If the content is itself an encoded value, it is shown decoded in a
        box, otherwise as a hexdump. See :py:meth:`~.X690Type.pretty`.

        :param depth: The number of indentation levels to prepend.
        :returns: The text to display.
        """
        if self.value == b"":
            return repr(self)
        try:
            # We try to decode embedded X.690 items. If we can't, we display
            # the value raw
            embedded: X690Type[Any] = decode(self.value)[0]
            return wrap(embedded.pretty(0), f"Embedded in {type(self)}", depth)
        except Exception:
            wrapped = wrap(visible_octets(self.value), str(type(self)), depth)
            return wrapped


class _Structure(X690Type[list[X690Type[Any]]]):
    """
    Base for the constructed types that hold a list of x690 values:
    :class:`Sequence` and :class:`Set`.

    It is not registered as a type (it has no tag). A decoded value reads
    its items lazily: only the item headers are read to find their
    offsets, and an item is decoded when it is accessed. Items keep their
    order; a :class:`Set` is not sorted.
    """

    __slots__ = ("_item_offsets",)

    #: Start index of each item, once a decoded value has been read.
    _item_offsets: "array[int] | None"

    def __init__(
        self,
        value: list[X690Type[Any]] | Uninitialised = UNINITIALISED,
    ) -> None:
        super().__init__(value)
        self._item_offsets = None

    @property
    def value(self) -> list[X690Type[Any]]:
        """
        The items of this value.

        Overrides :py:attr:`~.X690Type.value`
        """
        if self._is_decoded():
            return list(self)
        return self.pyvalue  # type: ignore

    @staticmethod
    def item_offsets(data: bytes, slc: slice = slice(None)) -> "array[int]":
        """
        Return the start index of every item in the value at *slc*.

        Only the type and length headers are read; no item is decoded.

        :param data: The buffer holding the encoded items.
        :param slc: The location of the items within *data*.
        :returns: The start index of each item within *data*.
        :raises X690Error: If an item announces more data than available.
        """
        start, end, _ = slc.indices(len(data))
        offsets = array("Q")
        position = start
        while position < end:
            offsets.append(position)
            position = get_value_slice(data, position).next_value_index
        return offsets

    @classmethod
    def decode_raw(
        cls, data: bytes, slc: slice = slice(None)
    ) -> list[X690Type[Any]]:
        """
        Decode every item of the value, resolving the tags with
        :meth:`~.X690Type.child_lookup`.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded items, in order.
        """
        lookup = cls.child_lookup()
        return [
            _decode_value(data, offset, lookup, cls)[0]
            for offset in cls.item_offsets(data, slc)
        ]

    def _offsets(self) -> "array[int]":
        """
        Return the item offsets of a decoded value, computed once.
        """
        if self._item_offsets is None:
            self._item_offsets = self.item_offsets(*self._source())
        return self._item_offsets

    def detach(self) -> Self:
        """
        Overrides :py:meth:`.X690Type.detach`

        Also resets the cached item offsets, which refer to the old buffer.
        """
        super().detach()
        self._item_offsets = None
        return self

    def _is_decoded(self) -> bool:
        return isinstance(self.pyvalue, Uninitialised)

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        items = [bytes(item) for item in self.pyvalue]
        output = b"".join(items)
        return output

    def __eq__(self, other: object) -> bool:
        """
        Two structures are equal if they are of exactly the same class and
        their content bytes are equal.
        """
        if not isinstance(other, X690Type) or type(other) is not type(self):
            return False
        return self.raw_bytes == other.raw_bytes

    def __repr__(self) -> str:
        item_repr = list(self)
        return "%s(%r)" % (self.__class__.__name__, item_repr)

    def __len__(self) -> int:
        if self._is_decoded():
            return len(self._offsets())
        return len(self.value)

    def __iter__(self) -> Iterator[X690Type[Any]]:
        if not self._is_decoded():
            yield from self.value
            return
        data = self._source()[0]
        lookup = self.child_lookup()
        for offset in self._offsets():
            yield _decode_value(data, offset, lookup, type(self))[0]

    def __getitem__(self, idx: int) -> X690Type[Any]:
        if not self._is_decoded():
            return self.value[idx]
        data = self._source()[0]
        lookup = self.child_lookup()
        if isinstance(idx, slice):
            return [
                _decode_value(data, offset, lookup, type(self))[0]
                for offset in self._offsets()[idx]
            ]
        return _decode_value(data, self._offsets()[idx], lookup, type(self))[0]

    def pythonize(self) -> list[X690Type[Any]]:
        """
        Overrides :py:meth:`~.X690Type.pythonize`
        """
        return [obj.pythonize() for obj in self]

    def pretty(self, depth: int = 0) -> str:  # pragma: no cover
        """
        Returns a prettified string with *depth* levels of indentation

        Each item is shown as a bullet. See :py:meth:`~.X690Type.pretty`.

        :param depth: The number of indentation levels to prepend.
        :returns: The text to display.
        """
        lines = [f"{self.__class__.__name__} with {len(self.value)} items:"]
        for item in self.value:
            prettified_item = item.pretty(depth)
            bullet = INDENT_STRING * depth + "⁃ "
            for line in prettified_item.splitlines():
                lines.append(bullet + line)
                bullet = "  "
        return "\n".join(lines)


class Sequence(_Structure):
    """
    Represents an X.690 sequence type. Instances of this class are iterable and
    indexable.
    """

    __slots__ = ()
    TAG = 0x10


class Set(_Structure):
    """
    The ``SET`` type, tag ``0x11``, holding a :class:`list` of x690 values.

    It behaves like :class:`Sequence`: it is iterable and indexable, and a
    decoded value reads its items lazily. The items keep the order in which
    they were given or decoded; they are not sorted as DER requires.

    >>> value = Set([Integer(1), Boolean(True)])
    >>> bytes(value)
    b'1\\x06\\x02\\x01\\x01\\x01\\x01\\x01'
    >>> decode(bytes(value))[0]
    Set([Integer(1), Boolean(True)])
    """

    __slots__ = ()
    TAG = 0x11


class Explicit(X690Type[TInnerType]):
    """
    An explicitly tagged value: a constructed context-specific value that
    wraps exactly one inner value, as in ``version [0] EXPLICIT Version``.

    Subclass it with the ``TAG`` of the wrapper, and declare the inner type
    in :attr:`~.X690Type.CHILD_TYPES` if it is not a globally registered
    type. The value is the inner value:

    >>> class Version(Explicit[Integer]):
    ...     TAG = 0
    >>> bytes(Version(Integer(2)))
    b'\\xa0\\x03\\x02\\x01\\x02'
    >>> decode(b"\\xa0\\x03\\x02\\x01\\x02", types=[Version])[0]
    Version(Integer(2))
    """

    __slots__ = ()
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.CONSTRUCTED]

    @classmethod
    def decode_raw(cls, data: bytes, slc: slice = slice(None)) -> TInnerType:
        """
        Decode the inner value, resolving its tag with
        :attr:`~.X690Type.CHILD_TYPES`.

        Overrides :py:meth:`~.X690Type.decode_raw`

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The inner value.
        :raises ValueError: If the wrapper holds no value.
        """
        start, end, _ = slc.indices(len(data))
        if start >= end:
            raise ValueError(
                f"{cls.__name__} is explicitly tagged but holds no value"
            )
        inner, _ = _decode_value(data, start, cls.child_lookup(), cls)
        return inner  # type: ignore[return-value]

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        return bytes(self.pyvalue)

    def __eq__(self, other: object) -> bool:
        """
        Two explicit values are equal if they are of exactly the same class
        and their content bytes are equal.
        """
        if not isinstance(other, X690Type) or type(other) is not type(self):
            return False
        return self.raw_bytes == other.raw_bytes

    # Any: the Python value of the inner type is not known statically
    def pythonize(self) -> Any:
        """
        Return the Python value of the inner value.

        Overrides :py:meth:`~.X690Type.pythonize`
        """
        return self.value.pythonize()

    def pretty(self, depth: int = 0) -> str:
        """
        Returns a prettified string with *depth* levels of indentation

        The inner value is shown below the tag of the wrapper. See
        :py:meth:`~.X690Type.pretty`.

        :param depth: The number of indentation levels to prepend.
        :returns: The text to display.
        """
        lines = [f"{self.__class__.__name__} (explicit tag {self.TAG}):"]
        bullet = INDENT_STRING * depth + "⁃ "
        for line in self.value.pretty(depth).splitlines():
            lines.append(bullet + line)
            bullet = "  "
        return "\n".join(lines)


def _encode_twos_complement(value: int) -> bytes:
    """
    Encode *value* as the shortest big-endian two's-complement octets.
    """
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


class _IntegerContent(X690Type[int]):
    """
    Base for the types whose content is a two's-complement integer:
    :class:`Integer` and :class:`Enumerated`.

    It is not registered as a type (it has no tag). The subclasses stay
    distinct types, so they never compare equal to each other.
    """

    __slots__ = ()

    #: Whether the content octets are read as signed numbers
    SIGNED = True

    @classmethod
    def decode_raw(cls, data: bytes, slc: slice = slice(None)) -> int:
        """
        Decode the content octets as a big-endian :class:`int`.

        The number is read as two's complement if ``SIGNED`` is true.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded number.
        """
        data = data[slc]
        return int.from_bytes(data, "big", signed=cls.SIGNED)

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        return _encode_twos_complement(self.pyvalue)


class Integer(_IntegerContent):
    """
    The ``INTEGER`` type, tag ``0x02``, holding an :class:`int`.

    The value is encoded as the shortest big-endian two's-complement
    octets, so negative numbers are valid and its size is not limited.
    """

    __slots__ = ()
    TAG = 0x02
    NATURE = [TypeNature.PRIMITIVE]


class ObjectIdentifier(X690Type[str]):
    """
    Represents an OID.

    Instances of this class support containment checks to determine if one OID
    is a sub-item of another::

        >>> ObjectIdentifier("1.2.3.4.5") in ObjectIdentifier("1.2.3")
        True

        >>> ObjectIdentifier("1.2.4.5.6") in ObjectIdentifier("1.2.3")
        False

    :param value: The dotted notation of the identifier, such as
        ``"1.3.6.1"``. A leading dot is dropped.
    """

    __slots__ = ()
    TAG = 0x06
    NATURE = [TypeNature.PRIMITIVE]

    def __init__(self, value: str | Uninitialised = UNINITIALISED) -> None:
        if (
            not isinstance(value, Uninitialised)
            and value
            and value.startswith(".")
        ):
            value = value[1:]
        super().__init__(value)

    @property
    def nodes(self) -> tuple[int, ...]:
        """
        Returns the numerical nodes for this instance as tuple

        >>> ObjectIdentifier("1.2.3").nodes
        (1, 2, 3)
        >>> ObjectIdentifier().nodes
        ()
        """
        if not self.value:
            return tuple()
        return tuple(int(n) for n in self.value.split("."))

    @staticmethod
    def decode_large_value(current_char: int, stream: Iterator[int]) -> int:
        """
        If we encounter a value larger than 127, we have to consume from the
        stream until we encounter a value below 127 and recombine them.

        See: https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx

        >>> ObjectIdentifier.decode_large_value(0x81, iter([0x48]))
        200

        :param current_char: The first octet of the arc. It must be above
            127, otherwise it is the whole arc.
        :param stream: The following octets. Octets are consumed up to and
            including the last one of the arc.
        :returns: The recombined number.
        :raises StopIteration: If *stream* ends before the arc is complete.
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
    def encode_large_value(value: int) -> list[int]:
        """
        Inverse function of :py:meth:`~.ObjectIdentifier.decode_large_value`

        >>> ObjectIdentifier.encode_large_value(200)
        [129, 72]

        :param value: The number to encode as one arc.
        :returns: The octets of the arc, each but the last with the high
            bit set.
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

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> str:
        """
        Decode the content octets into the dotted notation.

        The first octet holds the first two arcs. Empty content gives an
        empty string.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The dotted identifier.
        :raises ValueError: If the last arc is incomplete.
        """
        # Special case for "empty" object identifiers which should be returned
        # as "0"
        data = data[slc]
        if not data:
            return ""

        # unpack the first byte into first and second sub-identifiers.
        data0 = data[0]
        first, second = data0 // 40, data0 % 40
        output = [first, second]

        remaining = iter(data[1:])

        for node in remaining:
            # Each node can only contain values from 0-127. Other values need
            # to be combined.
            if node > 127:
                try:
                    collapsed_value = ObjectIdentifier.decode_large_value(
                        node, remaining
                    )
                except StopIteration as exc:
                    raise ValueError(
                        "Truncated ObjectIdentifier: the last arc is incomplete"
                    ) from exc
                output.append(collapsed_value)
                continue
            output.append(node)

        instance = ".".join([str(n) for n in output])
        return instance

    def collapse_identifiers(self) -> tuple[int, ...]:
        """
        Meld the first two octets into one octet as defined by x.690

        In x.690 ObjectIdentifiers are a sequence of numbers. In the
        byte-representation the first two of those numbers are stored in the
        first byte.

        This function takes a "human-readable" OID tuple and returns a new
        tuple with the first two elements merged (collapsed) together.

        >>> ObjectIdentifier("1.3.6.1.4.1").collapse_identifiers()
        (43, 6, 1, 4, 1)
        >>> ObjectIdentifier().collapse_identifiers()
        ()
        """
        # pylint: disable=no-self-use
        identifiers = self.nodes
        if len(identifiers) == 0:
            return tuple()

        if len(identifiers) > 1:
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

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        collapsed_identifiers = self.collapse_identifiers()
        if collapsed_identifiers == ():
            return b""
        try:
            output = bytes(collapsed_identifiers)
        except ValueError as exc:
            raise ValueError(
                "Unable to collapse %r. First two octets are too large!"
                % (self.nodes,)
            ) from exc
        return output

    def __int__(self) -> int:
        nodes = self.nodes
        if len(nodes) != 1:
            raise ValueError(
                "Only ObjectIdentifier with one node can be "
                "converted to int. %r is not convertible. It has %d nodes."
                % (self, len(self))
            )
        return nodes[0]

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return "ObjectIdentifier(%r)" % (self.value,)

    def __len__(self) -> int:
        return len(self.nodes)

    def __contains__(self, other: "ObjectIdentifier") -> bool:
        """
        Check if one OID is a child of another.

        TODO: This has been written in the middle of the night! It's messy...
        """
        # pylint: disable=invalid-name

        a, b = other.nodes, self.nodes

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
        tail: list[tuple[int | None, int | None]] = []
        for tmp_a, tmp_b in zipped:
            if tmp_a == tmp_b and not tail:
                continue
            tail.append((tmp_a, tmp_b))

        # if we only have Nones in "b", we know that "a" was longer and that it
        # is a direct subtree of "b" (no diverging nodes). Otherwise we would
        # have te divergence in "b", and we can say that "b is contained in a"
        _, unzipped_b = zip(*tail)
        # In all other cases we end up with a non-matching tail and know that "b
        # is not contained in a".
        return all(x is None for x in unzipped_b)

    def __lt__(self, other: "ObjectIdentifier") -> bool:
        return self.nodes < other.nodes

    def __hash__(self) -> int:
        return hash(self.value)

    def __add__(self, other: "ObjectIdentifier") -> "ObjectIdentifier":
        nodes = ".".join([self.value, other.value])
        return ObjectIdentifier(nodes)

    @overload
    def __getitem__(self, index: int) -> int:  # pragma: no cover
        ...

    @overload
    def __getitem__(
        self, index: slice
    ) -> "ObjectIdentifier":  # pragma: no cover
        ...

    def __getitem__(self, index: int | slice) -> Union["ObjectIdentifier", int]:
        if isinstance(index, int):
            return self.nodes[index]
        output = self.nodes[index]
        return ObjectIdentifier(".".join([str(n) for n in output]))

    def parentof(self, other: "ObjectIdentifier") -> bool:
        """
        Convenience method to check whether this OID is a parent of another OID

        An identifier is a parent of itself.

        >>> ObjectIdentifier("1.2.3").parentof(ObjectIdentifier("1.2.3.4"))
        True

        :param other: The identifier to test.
        :returns: ``True`` if *other* is this identifier or below it.
        """
        return other in self

    def childof(self, other: "ObjectIdentifier") -> bool:
        """
        Convenience method to check whether this OID is a child of another OID

        An identifier is a child of itself.

        >>> ObjectIdentifier("1.2.3.4").childof(ObjectIdentifier("1.2.3"))
        True

        :param other: The identifier to test.
        :returns: ``True`` if this identifier is *other* or below it.
        """
        return self in other


class _TextString(X690Type[str]):
    """
    Base for the character string types that hold a :class:`str`.

    It is not registered as a type (it has no tag). Subclasses set the
    codec in ``_ENCODING``, and optionally the characters that are allowed
    on encoding in ``_ALPHABET``. Decoding never checks the alphabet.

    Only the primitive encoding is supported.
    """

    __slots__ = ()

    #: Name of the codec used for decoding and encoding
    _ENCODING: ClassVar[str] = "ascii"

    #: The characters allowed on encoding (``None`` allows all)
    _ALPHABET: ClassVar[frozenset[str] | None] = None

    @classmethod
    def decode_raw(cls, data: bytes, slc: slice = slice(None)) -> str:
        """
        Decode the content octets with the character set of the type.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded text.
        :raises UnicodeDecodeError: if the data is invalid for the
            character set of the type.
        """
        text = data[slc].decode(cls._ENCODING)
        alphabet = cls._ALPHABET
        if alphabet is not None and LOG.isEnabledFor(logging.DEBUG):
            outside = sum(1 for char in text if char not in alphabet)
            if outside:
                LOG.debug(
                    "Text outside permitted alphabet decoded",
                    extra={
                        "x690.type.name": cls.__name__,
                        "x690.char_count": outside,
                    },
                )
        return text

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`

        :raises UnicodeEncodeError: if the value contains characters that
            the character set of the type cannot represent.
        :raises ValueError: if the value contains characters outside of the
            alphabet of the type.
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        alphabet = self._ALPHABET
        if alphabet is not None:
            for char in self.pyvalue:
                if char not in alphabet:
                    raise ValueError(
                        "%s cannot contain the character %r"
                        % (self.__class__.__name__, char)
                    )
        return self.pyvalue.encode(self._ENCODING)


class ObjectDescriptor(_TextString):
    """
    The ``ObjectDescriptor`` type, tag ``0x07``, holding an ASCII
    :class:`str`.
    """

    __slots__ = ()
    TAG = 0x07
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class External(X690Type[bytes]):
    """
    The ``EXTERNAL`` type, tag ``0x08``, holding :class:`bytes`.

    The structured content (identification, data value) is not
    interpreted, so the value is the raw content octets.
    """

    __slots__ = ()
    TAG = 0x08


#: The special values of REAL (X.690, 8.5.9), by their contents octet
_REAL_SPECIAL = {
    0x40: math.inf,
    0x41: -math.inf,
    0x42: math.nan,
    0x43: -0.0,
}

#: Bits per digit of the bases of a binary REAL (X.690, 8.5.7.2)
_REAL_BASE_BITS = {0b00: 1, 0b01: 3, 0b10: 4}

#: The decimal REAL forms of ISO 6093 (X.690, 8.5.8), by number
_REAL_DECIMAL_FORMS = {
    1: re.compile(r" *[+-]?[0-9]+"),
    2: re.compile(r" *[+-]?(?:[0-9]+[.,][0-9]*|[.,][0-9]+)"),
    3: re.compile(
        r" *[+-]?(?:[0-9]+(?:[.,][0-9]*)?|[.,][0-9]+)[eE][+-]?[0-9]+"
    ),
}


def _scale_to_float(mantissa: int, exponent: int) -> float:
    """
    Return ``mantissa * 2 ** exponent`` as the nearest float.

    Values too large for a float become infinite, and values too small
    become zero.
    """
    if mantissa == 0:
        return 0.0
    magnitude = mantissa.bit_length() + exponent
    if magnitude > 1025:
        return math.inf
    if magnitude < -1076:
        return 0.0
    if exponent >= 0:
        try:
            return float(mantissa << exponent)
        except OverflowError:
            return math.inf
    # int / int is correctly rounded, also for subnormal results
    return mantissa / (1 << -exponent)


def _log_saturated_real(value: float) -> None:
    """
    Log that a REAL was out of the float range.
    """
    if not LOG.isEnabledFor(logging.DEBUG):
        return
    result = "0" if value == 0.0 else "inf" if value > 0 else "-inf"
    LOG.debug("Real value saturated", extra={"x690.real.result": result})


def _decode_binary_real(content: bytes) -> float:
    """
    Decode the contents of a binary REAL (X.690, 8.5.7).

    :raises ValueError: if the contents are malformed.
    """
    first = content[0]
    base_bits = _REAL_BASE_BITS.get((first >> 4) & 0b11)
    if base_bits is None:
        raise ValueError("Invalid Real: the base bits 0b11 are reserved")
    scale = (first >> 2) & 0b11
    position = 1
    exponent_length = (first & 0b11) + 1
    if exponent_length == 4:
        if len(content) < 2 or content[1] == 0:
            raise ValueError("Invalid Real: missing exponent length")
        exponent_length = content[1]
        position = 2
    exponent_end = position + exponent_length
    if len(content) <= exponent_end:
        raise ValueError(
            "Invalid Real: %d octets are too short for the exponent and "
            "the mantissa" % len(content)
        )
    exponent = int.from_bytes(
        content[position:exponent_end], "big", signed=True
    )
    mantissa = int.from_bytes(content[exponent_end:], "big")
    value = _scale_to_float(mantissa, scale + exponent * base_bits)
    if first & 0x40:
        value = -value
    if mantissa and (value == 0.0 or math.isinf(value)):
        _log_saturated_real(value)
    return value


def _decode_decimal_real(content: bytes) -> float:
    """
    Decode the contents of a decimal REAL in ISO 6093 form (X.690, 8.5.8).

    :raises ValueError: if the contents are malformed.
    """
    form = content[0] & 0b111111
    pattern = _REAL_DECIMAL_FORMS.get(form)
    if pattern is None:
        raise ValueError("Invalid Real: unknown decimal form %d" % form)
    text = content[1:].decode("ascii", errors="replace")
    if not pattern.fullmatch(text):
        raise ValueError(
            "Invalid Real: %r is not in the NR%d form" % (text, form)
        )
    value = float(text.replace(",", ".").lstrip(" "))
    if math.isinf(value):
        _log_saturated_real(value)
    return value


def _encode_real(value: float) -> bytes:
    """
    Encode *value* as the contents of a REAL in base 2, as DER requires.

    The mantissa is odd, the scaling factor 0 and the exponent as short as
    possible. Zero has no contents.
    """
    if math.isnan(value):
        return b"\x42"
    if math.isinf(value):
        return b"\x40" if value > 0 else b"\x41"
    if value == 0:
        return b"" if math.copysign(1.0, value) > 0 else b"\x43"
    mantissa, denominator = abs(value).as_integer_ratio()
    exponent = 1 - denominator.bit_length()
    trailing_zeros = (mantissa & -mantissa).bit_length() - 1
    mantissa >>= trailing_zeros
    exponent += trailing_zeros
    exponent_octets = _encode_twos_complement(exponent)
    first = 0x80 | (0x40 if value < 0 else 0) | (len(exponent_octets) - 1)
    mantissa_octets = mantissa.to_bytes((mantissa.bit_length() + 7) // 8, "big")
    return bytes([first]) + exponent_octets + mantissa_octets


class Real(X690Type[float]):
    """
    The ``REAL`` type, tag ``0x09``, holding a :class:`float`.

    Decoding reads every form of X.690 section 8.5: zero, the special
    values (infinities, NaN and minus zero), binary in base 2, 8 or 16 with
    a scaling factor, and decimal in the ISO 6093 forms NR1, NR2 and NR3.
    Malformed contents raise :py:exc:`ValueError`. A binary value outside
    the range of a float decodes to an infinity or to zero.

    Encoding writes base 2 with an odd mantissa, as DER requires. Every
    finite float survives a round trip unchanged. An :class:`int` is
    converted to a float.

    >>> bytes(Real(0.5))
    b'\\t\\x03\\x80\\xff\\x01'
    >>> decode(b"\\t\\x04\\x01-25")[0]
    Real(-25.0)

    :param value: The number. An :class:`int` is converted to a float.
    """

    __slots__ = ()
    TAG = 0x09
    NATURE = [TypeNature.PRIMITIVE]

    def __init__(self, value: float | Uninitialised = UNINITIALISED) -> None:
        if not isinstance(value, Uninitialised):
            value = float(value)
        super().__init__(value)

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> float:
        """
        Decode the content octets into a :class:`float`.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded number. Empty content is ``0.0``.
        :raises ValueError: if the contents are not a valid REAL.
        """
        content = data[slc]
        if not content:
            return 0.0
        first = content[0]
        if first & 0x80:
            return _decode_binary_real(content)
        if first & 0x40:
            special = _REAL_SPECIAL.get(first)
            if special is None or len(content) != 1:
                raise ValueError(
                    "Invalid Real: unknown special value %r" % content
                )
            return special
        return _decode_decimal_real(content)

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        return _encode_real(self.pyvalue)

    def __eq__(self, other: object) -> bool:
        """
        Compare the values, where NaN equals NaN and ``-0.0`` differs from
        ``0.0``, as their encodings do.
        """
        if not isinstance(other, Real) or type(other) is not type(self):
            return False
        mine, theirs = self.value, other.value
        if math.isnan(mine) or math.isnan(theirs):
            return math.isnan(mine) and math.isnan(theirs)
        return mine == theirs and math.copysign(1.0, mine) == math.copysign(
            1.0, theirs
        )


class Enumerated(_IntegerContent):
    """
    The ``Enumerated`` type, tag ``0x0A``, holding an :class:`int`.

    The value is encoded like an :class:`Integer`: as two's-complement
    octets, so negative numbers are valid.
    """

    __slots__ = ()
    TAG = 0x0A
    NATURE = [TypeNature.PRIMITIVE]


class EmbeddedPdv(X690Type[bytes]):
    """
    The ``EMBEDDED PDV`` type, tag ``0x0B``, holding :class:`bytes`.

    The structured content (identification, data value) is not
    interpreted, so the value is the raw content octets.
    """

    __slots__ = ()
    TAG = 0x0B


class Utf8String(_TextString):
    """
    The ``UTF8String`` type, tag ``0x0C``, holding a :class:`str`.
    """

    __slots__ = ()
    TAG = 0x0C
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    _ENCODING = "utf-8"


class RelativeOid(X690Type[str]):
    """
    The ``RELATIVE-OID`` type, tag ``0x0D``, holding a dotted
    :class:`str` such as ``"8571.3.2"``.

    The arcs are encoded like those of an :class:`ObjectIdentifier`, but
    the first two are not merged into one octet.
    """

    __slots__ = ()
    TAG = 0x0D
    NATURE = [TypeNature.PRIMITIVE]

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> str:
        """
        Decode the content octets into the dotted notation.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The dotted arcs. Empty content gives an empty string.
        :raises ValueError: if the last arc is not complete.
        """
        remaining = iter(data[slc])
        arcs: list[int] = []
        for octet in remaining:
            try:
                arcs.append(
                    ObjectIdentifier.decode_large_value(octet, remaining)
                )
            except StopIteration as exc:
                raise ValueError(
                    "Truncated RelativeOid: the last arc is incomplete"
                ) from exc
        return ".".join(str(arc) for arc in arcs)

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`

        :raises ValueError: if an arc is not a non-negative integer.
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        if not self.pyvalue:
            return b""
        octets: list[int] = []
        for text in self.pyvalue.split("."):
            arc = int(text)
            if arc < 0:
                raise ValueError(
                    "RelativeOid arcs must not be negative: %r" % self.pyvalue
                )
            octets.extend(ObjectIdentifier.encode_large_value(arc))
        return bytes(octets)


class NumericString(_TextString):
    """
    The ``NumericString`` type, tag ``0x12``, holding a :class:`str`.

    Decoding accepts any ASCII. Encoding accepts only digits and the space
    and raises :py:exc:`ValueError` for anything else.
    """

    __slots__ = ()
    TAG = 0x12
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    _ALPHABET = frozenset("0123456789 ")


class PrintableString(_TextString):
    """
    The ``PrintableString`` type, tag ``0x13``, holding a :class:`str`.

    Decoding accepts any ASCII, because real data often breaks the
    alphabet. Encoding accepts only ``A-Z``, ``a-z``, ``0-9``, the space and
    ``'()+,-./:=?``, and raises :py:exc:`ValueError` for anything else.
    """

    __slots__ = ()
    TAG = 0x13
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    _ALPHABET = frozenset(string.ascii_letters + string.digits + " '()+,-./:=?")


class T61String(X690Type[str]):
    """
    The ``T61String`` (``TeletexString``) type, tag ``0x14``.

    Decoding and encoding are strict ITU-T T.61 (1988), via ``t61codec``
    3. Accented letters decode to precomposed characters
    (``b"Caf\\xc2e"`` becomes ``"Café"``) and ``0xE0`` is ``Ω`` (U+03A9,
    GREEK CAPITAL LETTER OMEGA). Invalid T.61 raises
    :py:exc:`UnicodeDecodeError`, and characters without a T.61
    representation raise :py:exc:`UnicodeEncodeError`.

    Data written by OpenSSL is often Latin-1 rather than T.61. For such
    values, decode the raw bytes with ``bytes.decode("latin-1")``.

    The T.61 codec is never registered globally.

    :param value: The text. :class:`bytes` are decoded as T.61.
    :raises UnicodeDecodeError: If *value* is :class:`bytes` that are not
        valid T.61.
    """

    __slots__ = ()
    TAG = 0x14
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]

    def __init__(self, value: str | bytes = "") -> None:
        if isinstance(value, str):
            super().__init__(value or UNINITIALISED)
        else:
            super().__init__(T61String.decode_raw(value))

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None, None)) -> str:
        """
        Decode the content octets as T.61 text.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded text.
        :raises UnicodeDecodeError: if the data is not valid T.61.
        """
        return _T61_CODEC.decode(data[slc])[0]

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`

        :raises UnicodeEncodeError: if the value cannot be represented
            in T.61.
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        return _T61_CODEC.encode(self.pyvalue)[0]


class VideotexString(X690Type[bytes]):
    """
    The ``VideotexString`` type, tag ``0x15``.

    The character set is not interpreted: a decoded value holds the raw
    content octets as :class:`bytes`, because the encoding depends on
    escape sequences that this library does not process.
    """

    __slots__ = ()
    TAG = 0x15
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class IA5String(_TextString):
    """
    The ``IA5String`` type, tag ``0x16``, holding an ASCII :class:`str`.
    """

    __slots__ = ()
    TAG = 0x16
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


_UTC_TIME_PATTERN = re.compile(
    r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})?"
    r"(Z|[+-][0-9]{4})"
)

_GENERALIZED_TIME_PATTERN = re.compile(
    r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})"
    r"(?:([0-9]{2})(?:([0-9]{2}))?)?"
    r"(?:[.,]([0-9]+))?"
    r"(Z|[+-][0-9]{2}(?:[0-9]{2})?)?"
)


def _parse_zone(zone: str) -> timezone:
    """
    Convert ``Z``, ``+hh``, ``+hhmm``, ``-hh`` or ``-hhmm`` to a timezone.

    :raises ValueError: if the offset is out of range.
    """
    if zone == "Z":
        return UTC
    hours, minutes = int(zone[1:3]), int(zone[3:5] or 0)
    if hours > 23 or minutes > 59:
        raise ValueError("Invalid time zone offset: %r" % zone)
    offset = timedelta(hours=hours, minutes=minutes)
    return timezone(-offset if zone[0] == "-" else offset)


def _fraction_suffix(microsecond: int) -> str:
    """
    Return ``.ffffff`` without trailing zeros, or ``""`` for zero.
    """
    if not microsecond:
        return ""
    return ("." + "%06d" % microsecond).rstrip("0")


def _timestamp(moment: datetime) -> str:
    """
    Format *moment* as ``YYYYMMDDhhmmss`` without any zone.
    """
    return "%04d%02d%02d%02d%02d%02d" % (
        moment.year,
        moment.month,
        moment.day,
        moment.hour,
        moment.minute,
        moment.second,
    )


class _TimeType(X690Type[datetime]):
    """
    Base for the time types that hold a :class:`~datetime.datetime`.

    It is not registered as a type (it has no tag).
    """

    __slots__ = ()


class UtcTime(_TimeType):
    """
    The ``UTCTime`` type, tag ``0x17``, holding a timezone-aware
    :class:`~datetime.datetime`.

    Decoding reads ``YYMMDDhhmm[ss]`` followed by ``Z`` or ``+hhmm`` /
    ``-hhmm``. Years 50 to 99 are 1950 to 1999, years 00 to 49 are 2000
    to 2049 (the rule of X.509).

    Encoding converts to UTC and writes ``YYMMDDhhmmssZ``. Fractions of a
    second are dropped. A naive datetime or a year outside 1950 to 2049
    raises :py:exc:`ValueError`.
    """

    __slots__ = ()
    TAG = 0x17
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> datetime:
        """
        Decode the content octets into an aware :class:`~datetime.datetime`.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded moment.
        :raises UnicodeDecodeError: if the data is not ASCII.
        :raises ValueError: if the text is not a valid UTCTime.
        """
        text = data[slc].decode("ascii")
        match = _UTC_TIME_PATTERN.fullmatch(text)
        if match is None:
            raise ValueError("Invalid UtcTime: %r" % text)
        year, month, day, hour, minute, second, zone = match.groups()
        full_year = int(year) + (1900 if int(year) >= 50 else 2000)
        try:
            return datetime(
                full_year,
                int(month),
                int(day),
                int(hour),
                int(minute),
                int(second or 0),
                tzinfo=_parse_zone(zone),
            )
        except ValueError as exc:
            raise ValueError("Invalid UtcTime: %r (%s)" % (text, exc)) from exc

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`

        :raises ValueError: if the value is naive or the year is outside
            of 1950 to 2049.
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        if self.pyvalue.microsecond:
            LOG.debug(
                "Microseconds dropped",
                extra={"x690.type.name": type(self).__name__},
            )
        if self.pyvalue.tzinfo is None or self.pyvalue.utcoffset() is None:
            raise ValueError("UtcTime requires a timezone-aware datetime")
        moment = self.pyvalue.astimezone(UTC)
        if not 1950 <= moment.year <= 2049:
            raise ValueError(
                "UtcTime supports the years 1950 to 2049, not %d" % moment.year
            )
        return (_timestamp(moment)[2:] + "Z").encode("ascii")


class GeneralizedTime(_TimeType):
    """
    The ``GeneralizedTime`` type, tag ``0x18``, holding a
    :class:`~datetime.datetime`.

    Decoding reads ``YYYYMMDDHH[MM[SS[.fff]]]``, optionally followed by
    ``Z`` or ``+hhmm`` / ``-hhmm`` (also ``+hh``). A comma may replace the
    decimal point. With a zone the result is timezone-aware, without one
    it is naive (local time, as X.680 defines it).

    Encoding writes aware datetimes in UTC with a ``Z``, and naive ones
    without a zone. Microseconds are written only if they are not zero.
    """

    __slots__ = ()
    TAG = 0x18
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> datetime:
        """
        Decode the content octets into a :class:`~datetime.datetime`.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded moment, naive if the text has no zone.
        :raises UnicodeDecodeError: if the data is not ASCII.
        :raises ValueError: if the text is not a valid GeneralizedTime.
        """
        text = data[slc].decode("ascii")
        match = _GENERALIZED_TIME_PATTERN.fullmatch(text)
        if match is None:
            raise ValueError("Invalid GeneralizedTime: %r" % text)
        year, month, day, hour, minute, second, fraction, zone = match.groups()
        # a fraction applies to the last component that is present
        unit = 1 if second else 60 if minute else 3600
        extra = timedelta()
        if fraction:
            digits = Fraction(int(fraction), 10 ** len(fraction))
            micros = digits * unit * 1_000_000
            if micros.denominator != 1:
                LOG.debug(
                    "Fraction truncated",
                    extra={"x690.type.name": "GeneralizedTime"},
                )
            extra = timedelta(microseconds=int(micros))
        try:
            return (
                datetime(
                    int(year),
                    int(month),
                    int(day),
                    int(hour),
                    int(minute or 0),
                    int(second or 0),
                    tzinfo=_parse_zone(zone) if zone else None,
                )
                + extra
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid GeneralizedTime: %r (%s)" % (text, exc)
            ) from exc

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        if isinstance(self.pyvalue, Uninitialised):
            return b""
        moment = self.pyvalue
        zone = ""
        if moment.tzinfo is not None and moment.utcoffset() is not None:
            moment = moment.astimezone(UTC)
            zone = "Z"
        text = _timestamp(moment) + _fraction_suffix(moment.microsecond)
        return (text + zone).encode("ascii")


class GraphicString(_TextString):
    """
    The ``GraphicString`` type, tag ``0x19``, holding an ASCII
    :class:`str`.
    """

    __slots__ = ()
    TAG = 0x19
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class VisibleString(_TextString):
    """
    The ``VisibleString`` type, tag ``0x1A``, holding an ASCII
    :class:`str`.
    """

    __slots__ = ()
    TAG = 0x1A
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class GeneralString(X690Type[bytes]):
    """
    The ``GeneralString`` type, tag ``0x1B``.

    The character set is not interpreted: a decoded value holds the raw
    content octets as :class:`bytes`, because the encoding depends on
    escape sequences that this library does not process.
    """

    __slots__ = ()
    TAG = 0x1B
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]


class UniversalString(_TextString):
    """
    The ``UniversalString`` type, tag ``0x1C``, holding a :class:`str`
    encoded as UTF-32-BE.
    """

    __slots__ = ()
    TAG = 0x1C
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    _ENCODING = "utf-32-be"


class CharacterString(X690Type[bytes]):
    """
    The ``CHARACTER STRING`` type, tag ``0x1D``.

    The structured content (identification, string value) is not
    interpreted: a decoded value holds the raw content octets as
    :class:`bytes`.
    """

    __slots__ = ()
    TAG = 0x1D


class BmpString(_TextString):
    """
    The ``BMPString`` type, tag ``0x1E``, holding a :class:`str` encoded
    as UTF-16-BE.
    """

    __slots__ = ()
    TAG = 0x1E
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]
    _ENCODING = "utf-16-be"


class EOC(X690Type[bytes]):
    """
    The end-of-contents marker, tag ``0x00``, two zero octets in total.

    It terminates a constructed value of indefinite length and has no
    content. Its value is an empty :class:`bytes`.
    """

    __slots__ = ()
    TAG = 0x00
    NATURE = [TypeNature.PRIMITIVE]


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class Bits:
    """
    The value of a :class:`BitString`: a string of bits.

    It holds the octets and the number of unused bits at the end of the
    last octet, so a decoded value encodes back without loss. Bit 0 is the
    most significant bit of the first octet, as in ASN.1 named bit lists
    such as the X.509 ``KeyUsage``.

    >>> flags = Bits.from_bin("101")
    >>> flags
    Bits(b'\\xa0', unused=5)
    >>> len(flags), flags[0], flags[1]
    (3, True, False)
    >>> str(flags)
    '101'

    Equality and hashing look at the bits only: the unused bits of the last
    octet are ignored, as they are on indexing and iteration.

    :param data: The octets.
    :param unused: The number of unused bits at the end of the last octet,
        from 0 to 7. It must be 0 if *data* is empty.
    :raises ValueError: if *unused* is out of range.
    """

    data: bytes = b""
    unused: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", bytes(self.data))
        if not 0 <= self.unused <= 7:
            raise ValueError(
                "The number of unused bits must be 0 to 7, not %d" % self.unused
            )
        if self.unused and not self.data:
            raise ValueError(
                "An empty bit string cannot have %d unused bits" % self.unused
            )

    @classmethod
    def from_bin(cls, text: str) -> "Bits":
        """
        Create a value from a string of ``"0"`` and ``"1"``.

        >>> Bits.from_bin("10000001")
        Bits(b'\\x81')

        :param text: The bits, bit 0 first.
        :return: A new value, with the last octet padded with zeros.
        :raises ValueError: if *text* holds other characters.
        """
        if not set(text) <= {"0", "1"}:
            raise ValueError("Bits must be '0' or '1', not %r" % text)
        unused = -len(text) % 8
        padded = text + "0" * unused
        data = int(padded, 2).to_bytes(len(padded) // 8, "big") if text else b""
        return cls(data, unused)

    def is_set(self, index: int) -> bool:
        """
        Return whether bit *index* is 1, where bits past the end are 0.

        Use it for named bit lists: DER drops their trailing zero bits, so
        a set of flags is often shorter than the list of names.

        >>> Bits.from_bin("1").is_set(5)
        False

        :param index: The position of the bit, 0 being the first.
        :returns: Whether the bit is set.
        :raises ValueError: if *index* is negative.
        """
        if index < 0:
            raise ValueError("Bit positions are not negative: %d" % index)
        return index < len(self) and self[index]

    def _bits_only(self) -> bytes:
        """
        Return the octets with the unused bits set to 0.
        """
        if not self.unused:
            return self.data
        last = self.data[-1] & (0xFF << self.unused) & 0xFF
        return self.data[:-1] + bytes([last])

    def __len__(self) -> int:
        return len(self.data) * 8 - self.unused

    def __getitem__(self, index: int) -> bool:
        size = len(self)
        position = index + size if index < 0 else index
        if not 0 <= position < size:
            raise IndexError("Bit index %d out of range" % index)
        return bool(self.data[position >> 3] >> (7 - (position & 7)) & 1)

    def __iter__(self) -> Iterator[bool]:
        for position in range(len(self)):
            yield self[position]

    def __bytes__(self) -> bytes:
        return self.data

    def __str__(self) -> str:
        if not self.data:
            return ""
        number = int.from_bytes(self.data, "big")
        return format(number, "0%db" % (len(self.data) * 8))[: len(self)]

    def __repr__(self) -> str:
        if self.unused:
            return "Bits(%r, unused=%d)" % (self.data, self.unused)
        return "Bits(%r)" % (self.data,)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Bits):
            return NotImplemented
        return len(self) == len(other) and self._bits_only() == (
            other._bits_only()
        )

    def __hash__(self) -> int:
        return hash((len(self), self._bits_only()))


class BitString(X690Type[Bits]):
    """
    The ``BIT STRING`` type, tag ``0x03``, holding a :class:`Bits`.

    Construct it from a :class:`Bits` value, or from :class:`bytes` for a
    string of whole octets such as a key or a signature. The contents start
    with the number of unused bits. Decoding raises :py:exc:`ValueError` if
    that number is above 7, or not 0 for an empty string. Unused bits that
    are not zero are kept, but ignored.

    Only the primitive encoding is supported.

    >>> bytes(BitString(b"\\x01\\x02"))
    b'\\x03\\x03\\x00\\x01\\x02'
    >>> decode(b"\\x03\\x02\\x05\\xa0")[0].value
    Bits(b'\\xa0', unused=5)

    :param value: The bits, or whole octets as :class:`bytes`.
    """

    __slots__ = ()
    TAG = 0x03
    NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]

    def __init__(
        self, value: Bits | bytes | Uninitialised = UNINITIALISED
    ) -> None:
        if isinstance(value, bytes):
            value = Bits(value)
        super().__init__(value)

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> Bits:
        """
        Decode the content octets into a :class:`Bits`.

        Empty contents decode to an empty value.

        :param data: A data-block containing the content octets.
        :param slc: The location of the content octets within *data*.
        :returns: The decoded bits.

        :raises ValueError: if the number of unused bits is invalid.
        """
        content = data[slc]
        if not content:
            LOG.debug("Empty bit string without unused-bits octet")
            return Bits()
        try:
            bits = Bits(content[1:], content[0])
        except ValueError as exc:
            raise ValueError("Invalid BitString: %s" % exc) from exc
        if bits.unused and bits.data[-1] & ((1 << bits.unused) - 1):
            LOG.debug(
                "Bit string padding not zero",
                extra={"x690.bits.unused": bits.unused},
            )
        return bits

    def encode_raw(self) -> bytes:
        """
        Overrides :py:meth:`.X690Type.encode_raw`
        """
        # An empty bit string still carries the unused-bits octet.
        bits = self.value
        return bytes([bits.unused]) + bits.data
