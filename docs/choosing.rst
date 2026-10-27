Choosing x690
=============

Python has several libraries for :term:`ASN.1` data. They differ in where the
structure of a message is defined, what decoding returns, and what a type
checker can see. This page decodes the same message with five of them, then
explains why x690 works the way it does and where it falls short today.

The task
--------

Each example decodes an SNMP ``GetRequest``, reads its request ID and the
first object identifier, and encodes the message back to the same bytes.
This is the message in ASN.1:

.. code-block:: asn1

   Demo DEFINITIONS IMPLICIT TAGS ::= BEGIN
     Message ::= SEQUENCE {
       version INTEGER,
       community OCTET STRING,
       data GetRequest
     }
     GetRequest ::= [0] PDU
     PDU ::= SEQUENCE {
       request-id INTEGER,
       error-status INTEGER,
       error-index INTEGER,
       variable-bindings SEQUENCE OF VarBind
     }
     VarBind ::= SEQUENCE {
       name OBJECT IDENTIFIER,
       value NULL
     }
   END

All examples read the same bytes from ``DATA``:

.. code-block:: python

   DATA = (
       b"0'\x02\x01\x01\x04\x06public"
       b"\xa0\x1a\x02\x02\x04\xd2\x02\x01\x00"
       b"\x02\x01\x000\x0e0\x0c\x06\x08+\x06"
       b"\x01\x02\x01\x01\x01\x00\x05\x00"
   )

The examples were run with pyasn1 0.6.4, asn1tools 0.169.0, asn1crypto 1.5.1
and pycrate 0.8.1.

pyasn1
------

`pyasn1 <https://github.com/pyasn1/pyasn1>`_ describes the structure with
Python classes built from ``NamedTypes`` and tag objects:

.. code-block:: python

   from pyasn1.codec.ber import decoder, encoder
   from pyasn1.type import namedtype, tag, univ

   class VarBind(univ.Sequence):
       componentType = namedtype.NamedTypes(
           namedtype.NamedType(
               "name", univ.ObjectIdentifier()
           ),
           namedtype.NamedType("value", univ.Null()),
       )

   class PDU(univ.Sequence):
       tagSet = univ.Sequence.tagSet.tagImplicitly(
           tag.Tag(
               tag.tagClassContext,
               tag.tagFormatConstructed,
               0,
           )
       )
       componentType = namedtype.NamedTypes(
           namedtype.NamedType(
               "request-id", univ.Integer()
           ),
           namedtype.NamedType(
               "error-status", univ.Integer()
           ),
           namedtype.NamedType(
               "error-index", univ.Integer()
           ),
           namedtype.NamedType(
               "variable-bindings",
               univ.SequenceOf(
                   componentType=VarBind()
               ),
           ),
       )

   class Message(univ.Sequence):
       componentType = namedtype.NamedTypes(
           namedtype.NamedType(
               "version", univ.Integer()
           ),
           namedtype.NamedType(
               "community", univ.OctetString()
           ),
           namedtype.NamedType("data", PDU()),
       )

   message, _ = decoder.decode(
       DATA, asn1Spec=Message()
   )
   pdu = message["data"]
   int(pdu["request-id"])
   # 1234
   str(pdu["variable-bindings"][0]["name"])
   # '1.3.6.1.2.1.1.1.0'
   encoder.encode(message) == DATA
   # True

The schema mirrors ASN.1 closely and covers the whole standard, including
:term:`BER`, CER and DER. The classes are configured through class
attributes rather than written as ordinary Python, and values are pyasn1
objects that convert with ``int()`` or ``str()``. pyasn1 ships no type
hints; separate stubs exist in typeshed (``types-pyasn1``).

asn1tools
---------

`asn1tools <https://github.com/eerimoq/asn1tools>`_ compiles the ASN.1 text
at runtime and works with plain dictionaries:

.. code-block:: python

   import asn1tools

   spec = asn1tools.compile_string(SPEC, "ber")
   message = spec.decode("Message", DATA)
   pdu = message["data"]
   pdu["request-id"]
   # 1234
   pdu["variable-bindings"][0]["name"]
   # '1.3.6.1.2.1.1.1.0'
   spec.encode("Message", message) == DATA
   # True

``SPEC`` holds the ASN.1 module above. This is the shortest code, and
asn1tools supports many encodings besides BER: DER, PER, UPER, OER, XER and
JER among them. Types are named by strings, and the result is a ``dict``, so
neither the names nor the values are known to a type checker or an editor.
asn1tools ships no type hints.

asn1crypto
----------

`asn1crypto <https://github.com/wbond/asn1crypto>`_ describes the structure
with Python classes and field lists:

.. code-block:: python

   from asn1crypto import core

   class VarBind(core.Sequence):
       _fields = [
           ("name", core.ObjectIdentifier),
           ("value", core.Null),
       ]

   class VarBinds(core.SequenceOf):
       _child_spec = VarBind

   class PDU(core.Sequence):
       _fields = [
           ("request-id", core.Integer),
           ("error-status", core.Integer),
           ("error-index", core.Integer),
           ("variable-bindings", VarBinds),
       ]

   class Message(core.Sequence):
       _fields = [
           ("version", core.Integer),
           ("community", core.OctetString),
           ("data", PDU, {"implicit": 0}),
       ]

   message = Message.load(DATA)
   pdu = message["data"]
   pdu["request-id"].native
   # 1234
   pdu["variable-bindings"][0]["name"].native
   # '1.3.6.1.2.1.1.1.0'
   message.dump() == DATA
   # True

The classes are compact, and nested values are parsed only when they are
read, as in x690. asn1crypto focuses on cryptography: it ships the
structures of X.509, PKCS and related standards, decodes BER and encodes
DER. It ships no type hints.

pycrate
-------

`pycrate <https://github.com/pycrate-org/pycrate>`_ compiles the ASN.1 module
into a generated Python module:

.. code-block:: python

   from pycrate_asn1c.asnproc import (
       PycrateGenerator,
       compile_text,
       generate_modules,
   )

   compile_text(SPEC)
   generate_modules(PycrateGenerator, "demo_gen.py")

   import demo_gen

   Message = demo_gen.Demo.Message
   Message.from_ber(DATA)
   pdu = Message.get_val()["data"]
   pdu["request-id"]
   # 1234
   pdu["variable-bindings"][0]["name"]
   # (1, 3, 6, 1, 2, 1, 1, 1, 0)
   Message.to_ber() == DATA
   # True

pycrate handles large real-world specifications and many encodings,
including the PER variants used in mobile networks. Decoding fills the
generated object in place, values come back as dictionaries and tuples, and
the generated code ships no type hints.

x690
----

x690 needs no schema for the types it knows. Only the context-specific
``GetRequest`` needs a class, declared on the message that encloses it:

.. code-block:: python

   from x690 import decode
   from x690.types import Sequence
   from x690.util import TypeClass

   class GetRequest(Sequence):
       TYPECLASS = TypeClass.CONTEXT
       TAG = 0

   class Message(Sequence):
       CHILD_TYPES = [GetRequest]

   message, _ = decode(
       DATA, types=[Message], enforce_type=Message
   )
   pdu = message[2]
   assert isinstance(pdu, GetRequest)
   pdu[0].value
   # 1234
   pdu[3].pythonize()[0][0]
   # '1.3.6.1.2.1.1.1.0'
   bytes(message) == DATA
   # True

Values are ordinary Python classes, and the package ships type hints: a type
checker knows that ``message`` is a ``Message``. The items inside a sequence
are typed as ``X690Type[Any]``, so indexing into one needs an ``isinstance``
check first, as for ``pdu`` above. Access is by position. x690 encodes BER
only.

Summary
-------

.. list-table::
   :header-rows: 1

   * - Library
     - Structure from
     - Decoded values
     - Type hints
   * - pyasn1
     - Python classes
     - pyasn1 objects
     - typeshed stubs
   * - asn1tools
     - ASN.1 text
     - ``dict``
     - none
   * - asn1crypto
     - Python classes
     - asn1crypto objects
     - none
   * - pycrate
     - generated module
     - ``dict``
     - none
   * - x690
     - Python classes
     - x690 objects
     - first level

.. _performance:

Performance
-----------

A benchmark decodes the same synthetic data with all five libraries:
records shaped like telecom charging data records, about 80 bytes each, in
four workloads. ``stream`` reads records one after another, ``full`` reads
a document of all records by iteration, ``partial`` reads only its last
record, and ``indexed`` reads every record by index. Times cover decoding
only; memory is the peak on top of the input.

These are the results for 1,000,000 records (80 MB) on a desktop with an
AMD Ryzen 5 5600X (6 cores), 31 GB of memory and CPython 3.12.

.. note::

   Absolute times depend on the machine. Run the benchmark on your own
   hardware before relying on them.

Reading records one at a time keeps every library under 1 MB of extra
memory. asn1crypto is fastest there with 6.3 s, followed by x690 with 9.3 s,
asn1tools with 9.5 s, pycrate with 39 s and pyasn1 with 104 s.

For a whole document, x690 is the fastest and needs a few megabytes where the
others need between 351 MB and 9.6 GB: it keeps only the start of each item
and decodes items as they are read.

.. list-table:: Decode time for a whole document
   :header-rows: 1

   * - Library
     - full
     - partial
     - indexed
   * - x690
     - 10 s
     - 0.7 s
     - 11 s
   * - asn1crypto
     - 13 s
     - 1.2 s
     - 13 s
   * - asn1tools
     - 13 s
     - 13 s
     - 13 s
   * - pycrate
     - 70 s
     - 70 s
     - 71 s
   * - pyasn1
     - 146 s
     - 144 s
     - 145 s

.. list-table:: Peak memory on top of the input
   :header-rows: 1

   * - Library
     - full
     - partial
     - indexed
   * - x690
     - 8 MB
     - 8 MB
     - 8 MB
   * - asn1crypto
     - 1,957 MB
     - 351 MB
     - 1,957 MB
   * - asn1tools
     - 1,436 MB
     - 1,437 MB
     - 1,437 MB
   * - pycrate
     - 5,494 MB
     - 5,494 MB
     - 5,494 MB
   * - pyasn1
     - 9,569 MB
     - 9,569 MB
     - 9,569 MB

The same benchmark on a small machine, with 2 cores and 3.7 GB of memory and
each case limited to 2 GB, ran about half as fast and kept the same order.
pycrate and pyasn1 could not decode the whole document there: they ran out of
memory.

The data uses universal tags only, so that all libraries decode the same
structure. The `benchmark
<https://github.com/exhuma/x690/tree/main/benchmarks>`_ runs with one
command and writes a JSON report with the machine details. The reports
behind these numbers are in ``benchmarks/results``.

Why x690 works this way
-----------------------

x690 started as the encoding layer of puresnmp. The libraries above either
asked for a schema written in their own configuration style, or returned
untyped dictionaries. x690 set out to be plain Python, typed, and free of
build steps.

Python classes, schema optional
   A type is a class with three attributes. Universal types decode without
   any declaration, and a protocol type needs only its
   :term:`class <type class>`, :term:`nature` and :term:`tag`.
   A context-specific type is declared on the type that encloses it.
   There is no ASN.1 compiler yet; generating x690 classes from ASN.1 modules
   is a possible addition, as long as x690 keeps working without it.

Typed values, first level
   :func:`~x690.decode` returns the type passed as ``enforce_type`` and checks
   it at runtime. Typing nested values as well would push a schema onto every
   user, so x690 stops at the first level for now: nested values are narrowed
   with ``isinstance`` where the code needs their type.

No copies, parse on read
   Before version 0.5, every nested value copied its part of the data. On
   large documents this cost memory and time. x690 now keeps one reference to
   the input and parses a value only when it is read. A sequence records
   where its items start and creates each item when it is accessed. Beyond
   the input itself, memory grows by about 8 bytes per item of the sequence
   being read, plus the values the application keeps. Applications that need
   a few values from a large document do no work for the rest. Errors in a
   value surface when that value is read.

Decode anything
   Tags x690 does not know decode to :class:`~x690.types.UnknownType`
   instead of failing, and :meth:`~x690.types.X690Type.pretty` shows their
   class, nature and tag. This makes x690 a tool for reverse engineering
   undocumented data. It also means x690 does not validate a structure.

Pure Python
   x690 has no compiled parts and one small dependency. There are no wheels
   to build, it runs wherever Python runs, and the code is short enough to
   audit. Raw throughput is not its goal: on a stream of small records,
   asn1crypto decodes faster. For whole documents, x690 is the fastest of the
   libraries compared, because it does less work.

BER
   x690 implements the Basic Encoding Rules, which SNMP uses. Its output has
   not been checked against the additional rules of DER.

Current limitations
-------------------

- Types are declared by tag, not by position. Two items of one structure
  with the same tag, such as the two sequences that open an X.509
  certificate, decode to the same class.
- Six rarely used universal types hold raw bytes instead of a Python value;
  see :doc:`types`.
- Sequences are accessed by position, not by name (`#9
  <https://github.com/exhuma/x690/issues/9>`_).
- There is no validating decode that rejects unknown types (`#8
  <https://github.com/exhuma/x690/issues/8>`_).
- There is no code generator for ASN.1 modules (`#10
  <https://github.com/exhuma/x690/issues/10>`_).
- DER is not a mode of its own (`#11
  <https://github.com/exhuma/x690/issues/11>`_).

When to choose x690
-------------------

x690 fits when the data is BER, the protocol uses universal types and
protocol types whose tags are unique within each structure (SNMP is the
reference case), and the application decodes large documents with limited
memory, reads only parts of them, wants typed Python objects, or inspects
data without a specification. For X.509 and other cryptographic structures,
x690 needs a class for every structure that uses context tags, while
asn1crypto ships the definitions ready to use. For complete ASN.1 modules or
encodings other than BER, asn1tools and pycrate compile the specification
directly.
