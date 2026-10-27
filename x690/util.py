"""
Utility functions for working with the X.690 and related standards.
"""

from binascii import hexlify, unhexlify
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from .exc import X690Error

#: String to be used for indenting nested items during "pretty()" calls
INDENT_STRING = "  "


class Length(str, Enum):
    """
    A simple "namespace" to avoid magic values for indefinite lengths.
    """

    INDEFINITE = "indefinite"


class TypeClass(str, Enum):
    """
    The class of an X.690 type, taken from the two top bits of the
    identifier octet.

    The members are strings, so they compare equal to their lower-case
    names. See :class:`TypeInfo`.
    """

    UNIVERSAL = "universal"
    APPLICATION = "application"
    CONTEXT = "context"
    PRIVATE = "private"


class TypeNature(str, Enum):
    """
    Whether an X.690 value is primitive or constructed, taken from bit 6
    of the identifier octet.

    A constructed value contains further encoded values, a primitive value
    does not. See :class:`TypeInfo`.
    """

    PRIMITIVE = "primitive"
    CONSTRUCTED = "constructed"


class LengthInfo(NamedTuple):
    """
    The result of :func:`decode_length`.
    """

    #: The length of the value in octets, or ``-1`` if it is indefinite
    length: int
    #: The number of octets used by the length information itself
    offset: int


class ValueMetaData(NamedTuple):
    """
    The result of :func:`get_value_slice`.
    """

    #: The location of the value's content octets in the data stream
    bounds: slice
    #: The index at which the next value in the data stream starts
    next_value_index: int


@dataclass
class TypeInfo:
    """
    Decoded structure for an X.690 "type" octet. Example::

        >>> TypeInfo.from_bytes(b'\\x30')
        TypeInfo(cls=<TypeClass.UNIVERSAL: 'universal'>, nature=<TypeNature.CONSTRUCTED: 'constructed'>, tag=16)

    The structure contains 3 fields:

    cls
        The typeclass (a value taken from :py:class:`~.TypeClass`)

    nature
        A value taken from :py:class:`~.TypeNature`

    tag
        The actual type identifier.

    The instance also keeps the raw value as it was seen in the ``_raw_value``
    attribute.
    """

    cls: TypeClass
    nature: TypeNature
    tag: int

    _raw_value = None

    @staticmethod
    def from_bytes(data: int | bytes) -> "TypeInfo":
        """
        Given one octet, extract the separate fields and return a TypeInfo
        instance::

            >>> TypeInfo.from_bytes(b'\\x30')
            TypeInfo(cls=<TypeClass.UNIVERSAL: 'universal'>, nature=<TypeNature.CONSTRUCTED: 'constructed'>, tag=16)

        :param data: The identifier octet, either as a single byte or as
            the equivalent integer.
        :returns: The decoded class, nature and tag.
        :raises NotImplementedError: If the octet is ``0xff`` (long
            identifier types are not supported).
        """
        # pylint: disable=attribute-defined-outside-init
        # pylint: disable=protected-access

        if isinstance(data, (bytes, bytearray)):
            data = int.from_bytes(data, "big")
        if data == 0b11111111:
            raise NotImplementedError(
                "Long identifier types are not yet implemented"
            )
        cls_hint = (data & 0b11000000) >> 6
        pc_hint = (data & 0b00100000) >> 5
        value = data & 0b00011111

        if cls_hint == 0b00:
            cls = TypeClass.UNIVERSAL
        elif cls_hint == 0b01:
            cls = TypeClass.APPLICATION
        elif cls_hint == 0b10:
            cls = TypeClass.CONTEXT
        elif cls_hint == 0b11:
            cls = TypeClass.PRIVATE
        else:
            pass  # Impossible case (2 bits can only have 4 combinations).

        nature = TypeNature.CONSTRUCTED if pc_hint else TypeNature.PRIMITIVE

        instance = TypeInfo(cls, nature, value)
        instance._raw_value = data  # type: ignore[assignment]
        return instance

    def __bytes__(self) -> bytes:
        # pylint: disable=invalid-name
        if self.cls == TypeClass.UNIVERSAL:
            cls = 0b00
        elif self.cls == TypeClass.APPLICATION:
            cls = 0b01
        elif self.cls == TypeClass.CONTEXT:
            cls = 0b10
        elif self.cls == TypeClass.PRIVATE:
            cls = 0b11
        else:
            raise ValueError("Unexpected class for type info")

        if self.nature == TypeNature.CONSTRUCTED:
            nature = 0b01
        elif self.nature == TypeNature.PRIMITIVE:
            nature = 0b00
        else:
            raise ValueError("Unexpected primitive/constructed for type info")

        output = cls << 6 | nature << 5 | self.tag
        return bytes([output])


def encode_length(value: int) -> bytes:
    """
    This function encodes the length of a variable into bytes conforming to the
    rules defined in :term:`X.690`: The "length" field must be specially
    encoded for values above 127.  Additionally, from :term:`X.690`:

        8.1.3.2 A sender shall:

            a) use the definite form (see 8.1.3.3) if the encoding is
               primitive;
            b) use either the definite form (see 8.1.3.3) or the indefinite
               form (see 8.1.3.6), a sender's option, if the encoding is
               constructed and all immediately available;
            c) use the indefinite form (see 8.1.3.6) if the encoding is
               constructed and is not all immediately available.

    See also: https://en.wikipedia.org/wiki/X.690#Length_octets

    Example::

        >>> encode_length(16)    # no need for special encoding.
        b'\\x10'
        >>> encode_length(200)   # > 127, needs to be specially encoded.
        b'\\x81\\xc8'

    :param value: The length to encode, or ``Length.INDEFINITE`` to
        produce the indefinite form.
    :returns: The encoded length octets.
    """
    if value == Length.INDEFINITE:  # type: ignore
        return bytes([0b10000000])

    if value < 127:
        return bytes([value])

    output: list[int] = []
    while value > 0:
        value, remainder = value // 256, value % 256
        output.insert(0, remainder)

    # prefix length information
    output = [0b10000000 | len(output)] + output
    return bytes(output)


def get_value_slice(data: bytes, index: int = 0) -> ValueMetaData:
    """
    Helper method to extract lightweight information about value locations in
    a data-stream.

    The function returns both a slice at which a value can be found, and the
    index at which the next value can be found.

    :param data: The data stream containing one or more TLV values.
    :param index: Position of the first octet (the type octet) of the value
        to locate.
    :returns: The slice covering the value's content octets and the index
        at which the next value starts. For indefinite lengths, the slice
        starts after the length octet and ends at the first end-of-contents
        marker (two zero octets).
    :raises X690Error: If the announced length exceeds the available data.
    """
    length, offset = decode_length(data, index + 1)
    if length == -1:
        start = index + 2
        end = data.find(b"\x00\x00", index)
        nex_index = end + 2
    else:
        start = index + 1 + offset
        end = index + 1 + offset + length
        nex_index = end
    value_slice = slice(start, end)
    if end > len(data):
        raise X690Error(
            "Invalid Slice %r (data length=%r)" % (value_slice, len(data))
        )
    return ValueMetaData(value_slice, nex_index)


def decode_length(data: bytes, index: int = 0) -> LengthInfo:
    """
    Given a bytes object, which starts with the length information of a TLV
    value, returns a namedtuple with the length and the number of bytes which
    contained the length information. So, given a TLV value, this function
    takes the "LV" part as input, parses the length information and returns
    the length plus the number of bytes which need to be skipped to arrive at
    the beginning of the value.

    For values which are longer than 127 bytes, the length must be encoded into
    an unknown amount of "length" bytes. This function reads as many bytes as
    needed for the length. Consuming bytes for the value must therefore start
    after the bytes containing the length info. The second value returned
    from this function includes this information.

    The second argument (*index*) tells the function at which position to
    look for the length information.

    :param data: Data containing the length information.
    :param index: Position of the first length octet.
    :returns: The decoded length and the number of octets used to encode
        it. For the indefinite form the length is ``-1`` and the offset is
        ``-1``.
    :raises NotImplementedError: If the first length octet is ``0xff``,
        which X.690 reserves.

    Examples::

        >>> # length > 127, consume multiple length bytes
        >>> decode_length(b'\\x81\\xc8...')
        LengthInfo(length=200, offset=2)

        >>> # length <= 127, consume one length byte
        >>> decode_length(b'\\x10...')
        LengthInfo(length=16, offset=1)

    TODO: Upon rereading this, I wonder if it would not make more sense to take
          the complete TLV content as input.
    """
    data0 = data[index]
    if data0 == 0b11111111:
        # reserved
        raise NotImplementedError("This is a reserved case in X690")

    if data0 & 0b10000000 == 0:
        # definite short form
        output = int.from_bytes([data0], "big")
        offset = 1
    elif data0 ^ 0b10000000 == 0:
        # indefinite form
        output = -1
        offset = -1
    else:
        # definite long form
        num_octets = int.from_bytes([data0 ^ 0b10000000], "big")
        value_octets = data[index + 1 : index + num_octets + 1]
        output = int.from_bytes(value_octets, "big")
        offset = num_octets + 1
    return LengthInfo(output, offset)


def visible_octets(data: bytes) -> str:
    """
    Returns a geek-friendly (hexdump)  output of a bytes object.

    :param data: The octets to display.
    :returns: A multi-line string with 16 octets per line, followed by
        their printable ASCII representation.

    Developer note:
        This is not super performant. But it's not something that's supposed to
        be run during normal operations (mostly for testing and debugging).  So
        performance should not be an issue, and this is less obfuscated than
        existing solutions.

    Example::

        >>> from os import urandom
        >>> print(visible_octets(urandom(40)))  # doctest: +SKIP
        99 1f 56 a9 25 50 f7 9b  95 7e ff 80 16 14 88 c5   ..V.%P...~......
        f3 b4 83 d4 89 b2 34 b4  71 4e 5a 69 aa 9f 1d f8   ......4.qNZi....
        1d 33 f9 8e f1 b9 12 e9                            .3......

    """
    hexed = hexlify(data).decode("ascii")
    tuples = ["".join((a, b)) for a, b in zip(hexed[::2], hexed[1::2])]
    line = []
    output = []
    ascii_column = []
    for idx, octet in enumerate(tuples):
        line.append(octet)
        # only use printable characters in ascii output
        ascii_column.append(octet if 32 <= int(octet, 16) < 127 else "2e")
        if (idx + 1) % 8 == 0:
            line.append("")
        if (idx + 1) % 8 == 0 and (idx + 1) % 16 == 0:
            raw_ascii = unhexlify("".join(ascii_column))
            raw_ascii = raw_ascii.replace(b"\\n z", b".")
            ascii_column = []
            output.append(
                "%-50s %s" % (" ".join(line), raw_ascii.decode("ascii"))
            )
            line = []
    raw_ascii = unhexlify("".join(ascii_column))
    raw_ascii = raw_ascii.replace(b"\\n z", b".")
    output.append("%-50s %s" % (" ".join(line), raw_ascii.decode("ascii")))
    line = []
    return "\n".join(output)


def wrap(text: str, header: str, depth: int) -> str:
    """
    Wraps *text* in a border with a *header*, indented by *depth* levels.

    :param text: The (possibly multi-line) text to put into the box.
    :param header: Title shown in the first row of the box.
    :param depth: Nesting level; each level indents by
        :data:`INDENT_STRING`.
    :returns: The boxed text.
    """
    prefix = INDENT_STRING * depth
    box_width = max(len(header), max(len(x) for x in text.splitlines()))
    border1 = prefix + "┌─" + ("─" * box_width) + "─┐"
    border2 = prefix + "├─" + ("─" * box_width) + "─┤"
    border3 = prefix + "└─" + ("─" * box_width) + "─┘"
    fmt = "%s│ %%-%ds │" % (prefix, box_width)
    wrapped = [(fmt % line) for line in text.splitlines()]
    output = "\n".join([border1, fmt % header, border2] + wrapped + [border3])
    return output
