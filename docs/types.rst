Supported types
===============

:mod:`x690.types` has a class for every universal type of X.690. Each class
decodes its tag, and each instance encodes back to bytes. They differ in the
Python value they hold.

Types with a Python value
-------------------------

These types convert between bytes and a Python value in both directions:

.. list-table::
   :header-rows: 1

   * - Class
     - Tag
     - Python value
   * - :class:`~x690.types.Boolean`
     - ``0x01``
     - :class:`bool`
   * - :class:`~x690.types.Integer`
     - ``0x02``
     - :class:`int`
   * - :class:`~x690.types.BitString`
     - ``0x03``
     - :class:`~x690.types.Bits`
   * - :class:`~x690.types.OctetString`
     - ``0x04``
     - :class:`bytes`
   * - :class:`~x690.types.Null`
     - ``0x05``
     - ``None``
   * - :class:`~x690.types.ObjectIdentifier`
     - ``0x06``
     - :class:`str`, such as ``"1.3.6.1"``
   * - :class:`~x690.types.ObjectDescriptor`
     - ``0x07``
     - :class:`str` (ASCII)
   * - :class:`~x690.types.Real`
     - ``0x09``
     - :class:`float`
   * - :class:`~x690.types.Enumerated`
     - ``0x0A``
     - :class:`int`
   * - :class:`~x690.types.Utf8String`
     - ``0x0C``
     - :class:`str`
   * - :class:`~x690.types.RelativeOid`
     - ``0x0D``
     - :class:`str`, such as ``"8571.3.2"``
   * - :class:`~x690.types.Sequence`
     - ``0x10``
     - :class:`list` of x690 values
   * - :class:`~x690.types.Set`
     - ``0x11``
     - :class:`list` of x690 values, in their encoded order
   * - :class:`~x690.types.NumericString`
     - ``0x12``
     - :class:`str` (ASCII)
   * - :class:`~x690.types.PrintableString`
     - ``0x13``
     - :class:`str` (ASCII)
   * - :class:`~x690.types.T61String`
     - ``0x14``
     - :class:`str`
   * - :class:`~x690.types.IA5String`
     - ``0x16``
     - :class:`str` (ASCII)
   * - :class:`~x690.types.UtcTime`
     - ``0x17``
     - timezone-aware :class:`~datetime.datetime`
   * - :class:`~x690.types.GeneralizedTime`
     - ``0x18``
     - :class:`~datetime.datetime`
   * - :class:`~x690.types.GraphicString`
     - ``0x19``
     - :class:`str`
   * - :class:`~x690.types.VisibleString`
     - ``0x1A``
     - :class:`str` (ASCII)
   * - :class:`~x690.types.UniversalString`
     - ``0x1C``
     - :class:`str`
   * - :class:`~x690.types.BmpString`
     - ``0x1E``
     - :class:`str`

Object identifiers
------------------

:class:`~x690.types.ObjectIdentifier` also works as a value in code: it
compares, sorts, hashes, concatenates and slices like the dotted string it
represents.

>>> from x690.types import ObjectIdentifier
>>> oid = ObjectIdentifier("1.3.6.1.2.1.1.1.0")
>>> oid.nodes
(1, 3, 6, 1, 2, 1, 1, 1, 0)
>>> oid.childof(ObjectIdentifier("1.3.6.1.2.1"))
True
>>> oid[:6] + ObjectIdentifier("2")
ObjectIdentifier('1.3.6.1.2.1.2')

Bit strings
-----------

:class:`~x690.types.BitString` holds a :class:`~x690.types.Bits` value.
It keeps the octets and the number of unused bits, so a decoded value
encodes back unchanged. Bit 0 is the most significant bit of the first
octet, as in ASN.1 named bit lists.

Read flags such as the X.509 ``KeyUsage`` by position. DER drops trailing
zero bits, so use :meth:`~x690.types.Bits.is_set`, which reads bits past
the end as 0:

>>> from x690 import decode
>>> usage = decode(b"\x03\x02\x05\xa0")[0].value
>>> str(usage)
'101'
>>> usage.is_set(0), usage.is_set(1)
(True, False)
>>> usage.is_set(8)
False

Pass bytes for keys and signatures, and write flags with
:meth:`~x690.types.Bits.from_bin`:

>>> from x690.types import BitString, Bits
>>> bytes(BitString(b"\x01\x02"))
b'\x03\x03\x00\x01\x02'
>>> bytes(Bits.from_bin("1011"))
b'\xb0'

T61String
---------

:class:`~x690.types.T61String` decodes and encodes strictly according to
ITU-T T.61 (1988) through `t61codec <https://exhuma.github.io/t61codec/>`_.
Invalid T.61 raises :exc:`UnicodeDecodeError`, and characters T.61 cannot
represent raise :exc:`UnicodeEncodeError`.

.. note::

   Data written by OpenSSL is often Latin-1 rather than T.61. Decode such
   values from their raw bytes with ``bytes.decode("latin-1")``.

Time values
-----------

:class:`~x690.types.UtcTime` always holds a timezone-aware
:class:`~datetime.datetime`. It decodes a ``Z`` or an offset such as
``+0130``. The two-digit year follows the X.509 rule: 50 to 99 mean 1950 to
1999, and 00 to 49 mean 2000 to 2049.

>>> from x690 import decode
>>> value, _ = decode(b"\x17\x0d251026120000Z")
>>> value.value
datetime.datetime(2025, 10, 26, 12, 0, tzinfo=datetime.timezone.utc)
>>> decode(b"\x17\x0b4910261200Z")[0].value.year
2049
>>> decode(b"\x17\x0b5010261200Z")[0].value.year
1950

Encoding converts to UTC and writes ``Z``. A naive datetime, or a year
outside 1950 to 2049, raises :exc:`ValueError`.

:class:`~x690.types.GeneralizedTime` has a four-digit year and optional
minutes, seconds and fractions. Without a zone it holds a naive datetime,
which stands for local time. With ``Z`` or an offset it holds an aware one.
Encoding keeps that difference. Microseconds are written only when they are
not zero.

>>> from datetime import datetime
>>> from x690.types import GeneralizedTime
>>> moment = datetime(2025, 10, 26, 12)
>>> bytes(GeneralizedTime(moment))
b'\x18\x0e20251026120000'
>>> data = b"\x18\x1120251026120000.5Z"
>>> decode(data)[0].value.microsecond
500000

Types with raw bytes
--------------------

Six universal types hold the bytes of their value, without the type and
length header. They decode and encode without loss, and the bytes are left
for the application to interpret:

>>> text, _ = decode(b"\x15\x03abc")
>>> text
VideotexString(b'abc')
>>> text.value.decode("ascii")
'abc'

These types are:

- ``EOC``, the end-of-contents marker. It is part of the structure of an
  encoding, not a value.
- ``External``, ``EmbeddedPdv`` and ``CharacterString``, constructed types
  that are rarely used.
- ``VideotexString`` and ``GeneralString``, which switch character sets
  inside the value, as T.100 and ISO 2022 define.

To give one of them a Python value, subclass it, set its ``TAG`` again, and
override :meth:`~x690.types.X690Type.decode_raw` and
:meth:`~x690.types.X690Type.encode_raw` as shown in
:doc:`custom-types`.
