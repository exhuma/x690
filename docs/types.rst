Supported types
===============

:mod:`x690.types` has a class for every universal type of X.690. Each class
decodes its tag, and each instance encodes back to bytes. They differ in the
Python value they hold.

Types with a Python value
-------------------------

These types convert between bytes and a Python value in both directions,
except where noted:

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
   * - :class:`~x690.types.OctetString`
     - ``0x04``
     - :class:`bytes`
   * - :class:`~x690.types.Null`
     - ``0x05``
     - ``None``
   * - :class:`~x690.types.ObjectIdentifier`
     - ``0x06``
     - :class:`str`, such as ``"1.3.6.1"``
   * - :class:`~x690.types.Sequence`
     - ``0x10``
     - :class:`list` of x690 values
   * - :class:`~x690.types.T61String`
     - ``0x14``
     - :class:`str`
   * - :class:`~x690.types.GraphicString`
     - ``0x19``
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

T61String
---------

:class:`~x690.types.T61String` decodes and encodes strictly according to
ITU-T T.61 (1988) through `t61codec <https://exhuma.github.io/t61codec/>`_.
Invalid T.61 raises :exc:`UnicodeDecodeError`, and characters T.61 cannot
represent raise :exc:`UnicodeEncodeError`.

.. note::

   Data written by OpenSSL is often Latin-1 rather than T.61. Decode such
   values from their raw bytes with ``bytes.decode("latin-1")``.

Types with raw bytes
--------------------

All other universal types hold the bytes of their value, without the type and
length header. They decode and encode without loss, and the bytes are left
for the application to interpret:

>>> from x690 import decode
>>> text, _ = decode(b"\x0c\x03h\xc3\xa9")
>>> text
Utf8String(b'h\xc3\xa9')
>>> text.value.decode("utf8")
'hé'

This applies to ``EOC``, ``BitString``, ``ObjectDescriptor``, ``External``,
``Real``, ``Enumerated``, ``EmbeddedPdv``, ``Utf8String``, ``RelativeOid``,
``Set``, ``NumericString``, ``PrintableString``, ``VideotexString``,
``IA5String``, ``UtcTime``, ``GeneralizedTime``, ``VisibleString``,
``GeneralString``, ``UniversalString``, ``CharacterString`` and
``BmpString``. To give one of them a Python value, subclass it, set its
``TAG`` again, and override :meth:`~x690.types.X690Type.decode_raw` and
:meth:`~x690.types.X690Type.encode_raw` as shown in :doc:`custom-types`.
