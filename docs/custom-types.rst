Custom types
============

Protocols built on ASN.1 define their own types in the application, context
and private classes. x690 decodes them as :class:`~x690.types.UnknownType`
until it knows them. Subclass :class:`~x690.types.X690Type`, or one of its
subclasses, to add a type: subclassing registers it with
:func:`~x690.decode`.

Describe the type
-----------------

Three class attributes identify a type:

``TYPECLASS``
   A :class:`~x690.util.TypeClass`: ``APPLICATION``, ``CONTEXT`` or
   ``PRIVATE`` for protocol types. ``UNIVERSAL`` belongs to the standard.

``NATURE``
   A list of :class:`~x690.util.TypeNature` values: ``PRIMITIVE`` for single
   values, ``CONSTRUCTED`` for values that contain other values.

``TAG``
   The tag number, unique within the class.

:meth:`~x690.types.X690Type.pretty` prints these three values for every
unknown type it finds, so they can be copied from a dump of real data.

Reuse an existing type
----------------------

When the new type is encoded like an existing one, subclass that type and
change only the attributes. The SNMP ``GetRequest`` PDU from
:doc:`usage` is a sequence in the context class with tag 0:

>>> from x690 import decode
>>> from x690.types import Integer, Null, ObjectIdentifier, OctetString
>>> from x690.types import Sequence
>>> from x690.util import TypeClass
>>> class GetRequest(Sequence):
...     TYPECLASS = TypeClass.CONTEXT
...     TAG = 0

Once the class exists, the same bytes decode to a full structure:

>>> data = (
...     b"0'\x02\x01\x01\x04\x06public\xa0\x1a\x02\x02\x04\xd2\x02\x01\x00"
...     b"\x02\x01\x000\x0e0\x0c\x06\x08+\x06\x01\x02\x01\x01\x01\x00\x05\x00"
... )
>>> message, _ = decode(data)
>>> print(message[2].pretty())
GetRequest with 4 items:
⁃ Integer(1234)
⁃ Integer(0)
⁃ Integer(0)
⁃ Sequence with 1 items:
  ⁃ Sequence with 2 items:
    ⁃ 1.3.6.1.2.1.1.1.0
    ⁃ Null()

The class also encodes. This builds the same message from scratch:

>>> request = GetRequest([
...     Integer(1234),
...     Integer(0),
...     Integer(0),
...     Sequence([Sequence([ObjectIdentifier("1.3.6.1.2.1.1.1.0"), Null()])]),
... ])
>>> bytes(Sequence([Integer(1), OctetString(b"public"), request])) == data
True

Convert your own values
-----------------------

For a new encoding, override two methods:

:meth:`~x690.types.X690Type.decode_raw`
   A static method. It receives the data and the slice that holds the value,
   without the type and length header, and returns the Python value.

:meth:`~x690.types.X690Type.encode_raw`
   Returns the bytes of ``self.pyvalue``, without the header.

This type stores a person as UTF-8 encoded JSON in the application class:

>>> import json
>>> from typing import NamedTuple
>>> from x690.types import X690Type
>>> from x690.util import TypeNature
>>> class Person(NamedTuple):
...     name: str
...     age: int
>>> class PersonType(X690Type[Person]):
...     TYPECLASS = TypeClass.APPLICATION
...     NATURE = [TypeNature.PRIMITIVE]
...     TAG = 1
...
...     @staticmethod
...     def decode_raw(data: bytes, slc: slice = slice(None)) -> Person:
...         return Person(**json.loads(data[slc]))
...
...     def encode_raw(self) -> bytes:
...         return json.dumps(self.pyvalue._asdict()).encode("utf8")
>>> data = bytes(PersonType(Person("Ada", 36)))
>>> data
b'A\x1a{"name": "Ada", "age": 36}'
>>> decode(data, enforce_type=PersonType)[0].value
Person(name='Ada', age=36)

Rules for custom types
----------------------

- The class needs a constructor that works without arguments: x690 creates
  the instance first and attaches the data after.
- Import the module that defines the class before decoding. Types are
  registered when the class is created.
- A custom type with a universal class and tag replaces the class x690
  ships for that tag. Do this only on purpose, for example to give one of the
  :doc:`raw-bytes types <types>` a Python value.
