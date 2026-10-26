Usage
=====

Encode values
-------------

Every type in :mod:`x690.types` wraps a Python value. Call :class:`bytes` on
an instance to get its encoding, type and length header included:

>>> from x690.types import Boolean, Integer, Null, ObjectIdentifier
>>> bytes(Integer(12))
b'\x02\x01\x0c'
>>> bytes(Boolean(True))
b'\x01\x01\x01'
>>> bytes(ObjectIdentifier("1.3.6.1.2.1.1.1.0"))
b'\x06\x08+\x06\x01\x02\x01\x01\x01\x00'
>>> bytes(Null())
b'\x05\x00'

A :class:`~x690.types.Sequence` takes a list of values and encodes them in
order. Sequences nest:

>>> from x690.types import OctetString, Sequence
>>> bytes(Sequence([Integer(1), Sequence([OctetString(b"a")])]))
b'0\x08\x02\x01\x010\x03\x04\x01a'

Decode a value
--------------

:func:`x690.decode` reads one value and returns it with the index of the
next value in the data:

>>> from x690 import decode
>>> value, next_index = decode(b"\x02\x01\x0c")
>>> value
Integer(12)
>>> next_index
3

``value.value`` holds the Python value of a single item.
:meth:`~x690.types.X690Type.pythonize` converts nested sequences as well:

>>> value.value
12
>>> decode(b"0\x08\x02\x01\x010\x03\x04\x01a")[0].pythonize()
[1, [b'a']]

Decode a stream
---------------

Pass the index of the next value back to :func:`~x690.decode` to walk through
data that holds several values:

>>> data = b"\x02\x01\x01\x02\x01\x02\x02\x01\x03"
>>> index = 0
>>> while index < len(data):
...     value, index = decode(data, index)
...     print(value)
Integer(1)
Integer(2)
Integer(3)

The same start index reads a value from the middle of a larger buffer. x690
does not copy the buffer: values keep a reference to it and convert their
bytes when first read.

>>> decode(b"header\x02\x01\x05trailer", 6)
(Integer(5), 9)

Check the type
--------------

When the type of the value is known in advance, pass it as ``enforce_type``.
The result is then typed for type checkers, and a mismatch raises
:exc:`~x690.exc.UnexpectedType`:

>>> decode(b"\x02\x01\x0c", enforce_type=Integer)
(Integer(12), 3)
>>> decode(b"\x02\x01\x0c", enforce_type=OctetString)
Traceback (most recent call last):
  ...
x690.exc.UnexpectedType: Unexpected decode result. Expected instance of type <class 'x690.types.OctetString'> but got <class 'x690.types.Integer'> instead

Reject trailing data
--------------------

With ``strict=True``, data left after the value raises
:exc:`~x690.exc.IncompleteDecoding`. Its ``remainder`` attribute holds the
extra bytes:

>>> from x690.exc import IncompleteDecoding
>>> try:
...     decode(b"\x02\x01\x0cjunk", strict=True)
... except IncompleteDecoding as exc:
...     print(exc.remainder)
b'junk'

Inspect unknown data
--------------------

:meth:`~x690.types.X690Type.pretty` prints a value and everything inside it.
Values x690 has no type for decode to :class:`~x690.types.UnknownType`, which
shows their class, nature and tag. This SNMP request contains such a value:

>>> data = (
...     b"0'\x02\x01\x01\x04\x06public\xa0\x1a\x02\x02\x04\xd2\x02\x01\x00"
...     b"\x02\x01\x000\x0e0\x0c\x06\x08+\x06\x01\x02\x01\x01\x01\x00\x05\x00"
... )
>>> print(decode(data)[0].pretty())
Sequence with 3 items:
⁃ Integer(1)
⁃ ┌───────────────────────────────────────────────────────────┐
  │ <class 'x690.types.OctetString'>                          │
  ├───────────────────────────────────────────────────────────┤
  │ 70 75 62 6c 69 63                                  public │
  └───────────────────────────────────────────────────────────┘
⁃ Unknown X690Type
    │ Tag:       160
    │ X690Type Info:
    │  │ Class: TypeClass.CONTEXT
    │  │ Nature: TypeNature.CONSTRUCTED
    │  │ Tag: 0
  ┌─────────────────────────────────────────────────────────────────────┐
  │ <class 'x690.types.UnknownType'>                                    │
  ├─────────────────────────────────────────────────────────────────────┤
  │ 02 02 04 d2 02 01 00 02  01 00 30 0e 30 0c 06 08   ..........0.0... │
  │ 2b 06 01 02 01 01 01 00  05 00                     +.........       │
  └─────────────────────────────────────────────────────────────────────┘

The third item is a constructed value of the context class with tag 0: the
SNMP ``GetRequest`` PDU. :doc:`custom-types` shows how to teach x690 that
type, so the dump shows its contents.
