Custom types
============

Protocols built on ASN.1 define their own types in the application, context
and private classes. x690 decodes them as :class:`~x690.types.UnknownType`
until it knows them. Subclass :class:`~x690.types.X690Type`, or one of its
subclasses, to describe a type. How x690 finds the class depends on its
type class:

Universal, application and private types
   Subclassing registers the type with :func:`~x690.decode`. It decodes
   wherever it appears.

Context-specific types
   A context tag such as ``[0]`` has a meaning only inside its enclosing
   type. These types are never registered. Declare them on the enclosing
   type instead, as shown in `Declare the types of a structure`_.

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
   The tag number. It is unique within the class, and for context-specific
   types within the enclosing type.

:meth:`~x690.types.X690Type.pretty` prints these three values for every
unknown type it finds, so they can be copied from a dump of real data.

Reuse an existing type
----------------------

When the new type is encoded like an existing one, subclass that type and
change only the attributes. The SNMP ``GetRequest`` PDU from :doc:`usage`
is a sequence in the context class with tag 0. In ASN.1 it reads
``GetRequest ::= [0] IMPLICIT PDU``: the context tag replaces the tag of the
sequence.

>>> from x690 import decode
>>> from x690.types import Integer, Null
>>> from x690.types import ObjectIdentifier
>>> from x690.types import OctetString, Sequence
>>> from x690.util import TypeClass, TypeNature
>>> class GetRequest(Sequence):
...     TYPECLASS = TypeClass.CONTEXT
...     TAG = 0

Declare the types of a structure
--------------------------------

``GetRequest`` has its meaning only inside an SNMP message. List it in
:attr:`~x690.types.X690Type.CHILD_TYPES` of a class for the message:

>>> class Message(Sequence):
...     CHILD_TYPES = [GetRequest]

``Message`` sets no ``TAG`` of its own. It is a plain sequence that adds
declarations, so it does not replace :class:`~x690.types.Sequence` for
other data. Pass it to :func:`~x690.decode` with ``types`` to read a
message, and the same bytes decode to a full structure:

>>> data = (
...     b"0'\x02\x01\x01\x04\x06public"
...     b"\xa0\x1a\x02\x02\x04\xd2\x02\x01\x00"
...     b"\x02\x01\x000\x0e0\x0c\x06\x08+\x06"
...     b"\x01\x02\x01\x01\x01\x00\x05\x00"
... )
>>> message, _ = decode(data, types=[Message])
>>> print(message[2].pretty())
GetRequest with 4 items:
⁃ Integer(1234)
⁃ Integer(0)
⁃ Integer(0)
⁃ Sequence with 1 items:
  ⁃ Sequence with 2 items:
    ⁃ 1.3.6.1.2.1.1.1.0
    ⁃ Null()

The classes also encode. This builds the same message from scratch:

>>> varbind = Sequence([
...     ObjectIdentifier("1.3.6.1.2.1.1.1.0"),
...     Null(),
... ])
>>> request = GetRequest([
...     Integer(1234),
...     Integer(0),
...     Integer(0),
...     Sequence([varbind]),
... ])
>>> message = Message([
...     Integer(1),
...     OctetString(b"public"),
...     request,
... ])
>>> bytes(message) == data
True

How tags are resolved
---------------------

x690 reads the tag of each item of a constructed value and looks for its
class in this order:

1. ``CHILD_TYPES`` of the class of the enclosing value.
2. The global registry of universal, application and private types.

Context-specific tags are only looked up in ``CHILD_TYPES``. A tag that is
not declared there decodes to :class:`~x690.types.UnknownType`.

Each value uses the declarations of its own class. The items of
``GetRequest`` are resolved with ``GetRequest.CHILD_TYPES``, not with those
of ``Message``. The same tag can therefore mean a different type in every
structure.

A value at the top level has no enclosing type. The ``types`` argument of
:func:`~x690.decode` takes that role. This decodes the PDU on its own, from
its offset in the message:

>>> pdu, _ = decode(data, 13, types=[GetRequest])
>>> type(pdu).__name__, pdu[0]
('GetRequest', Integer(1234))

A declaration also takes precedence over a registered application or
private type, for the items of that structure only.

To list the class itself or a class defined later, assign ``CHILD_TYPES``
after the ``class`` statement.

Explicit tags
-------------

With an explicit tag, the context tag wraps the value instead of replacing
its tag. X.509 certificates tag their version this way:
``version [0] EXPLICIT Version``. Subclass
:class:`~x690.types.Explicit` with the tag. The value of the wrapper is the
inner value:

>>> from x690.types import Explicit
>>> class Version(Explicit[Integer]):
...     TAG = 0
>>> class TBSCertificate(Sequence):
...     CHILD_TYPES = [Version]
>>> data = (
...     b"0\x08\xa0\x03\x02\x01\x02"
...     b"\x02\x01\x07"
... )
>>> tbs, _ = decode(data, types=[TBSCertificate])
>>> tbs
TBSCertificate([Version(Integer(2)), Integer(7)])
>>> tbs[0].value
Integer(2)
>>> bytes(tbs) == data
True

Elsewhere in X.509, ``[0]`` is an implicitly tagged octet string:
``keyIdentifier [0] IMPLICIT OCTET STRING``. The other structure declares
its own type for the same tag:

>>> class KeyIdentifier(OctetString):
...     TYPECLASS = TypeClass.CONTEXT
...     NATURE = [TypeNature.PRIMITIVE]
...     TAG = 0
>>> class AuthorityKeyId(Sequence):
...     CHILD_TYPES = [KeyIdentifier]
>>> data = b"0\x04\x80\x02\xca\xfe"
>>> decode(data, types=[AuthorityKeyId])[0]
AuthorityKeyId([KeyIdentifier(b'\xca\xfe')])

When the inner type of an explicit tag is itself context-specific, list it
in ``CHILD_TYPES`` of the ``Explicit`` subclass.

Convert your own values
-----------------------

For a new encoding, override two methods:

:meth:`~x690.types.X690Type.decode_raw`
   A static or class method (use a class method to read class attributes).
   It receives the data and the slice that holds the value, without the
   type and length header, and returns the Python value.

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
...     def decode_raw(data, slc=slice(None)):
...         return Person(**json.loads(data[slc]))
...
...     def encode_raw(self):
...         value = self.pyvalue._asdict()
...         return json.dumps(value).encode()
>>> data = bytes(PersonType(Person("Ada", 36)))
>>> data
b'A\x1a{"name": "Ada", "age": 36}'
>>> person, _ = decode(
...     data, enforce_type=PersonType
... )
>>> person.value
Person(name='Ada', age=36)

Rules for custom types
----------------------

- The class needs a constructor that works without arguments: x690 creates
  the instance first and attaches the data after.
- Import the module that defines the class before decoding. Types are
  registered when the class is created.
- A subclass is registered only when its class body sets ``TYPECLASS``,
  ``TAG`` or ``NATURE``. A subclass that sets none of them, such as
  ``Message`` above, is the same type as its parent.
- A custom type that sets the universal class and tag of a type x690 ships
  replaces that type. Do this only on purpose, for example to give one of
  the :doc:`raw-bytes types <types>` a Python value.
- Declarations go by tag, not by position. Two items with the same tag in
  one structure, such as two sequences, decode to the same class.
