x690
====

Encode and decode ASN.1 data in BER (ITU-T X.690) with pure Python. x690
turns every encoded value into a typed Python object, decodes large buffers
without copying them, and takes new types with a few lines of code. It is the
encoding layer of `puresnmp <https://github.com/exhuma/puresnmp>`_.

Install
-------

.. code-block:: console

   $ pip install x690

x690 needs Python 3.11 or newer.

Example
-------

Build a value from the classes in :mod:`x690.types`, turn it into bytes with
:class:`bytes`, and read it back with :func:`x690.decode`:

>>> from x690 import decode
>>> from x690.types import Integer, OctetString
>>> from x690.types import Sequence
>>> data = bytes(Sequence([
...     Integer(42),
...     OctetString(b"hello"),
... ]))
>>> data
b'0\n\x02\x01*\x04\x05hello'
>>> value, next_index = decode(data)
>>> value
Sequence([Integer(42), OctetString(b'hello')])
>>> value.pythonize()
[42, b'hello']

Features
--------

Typed decoding
   Pass the expected type to :func:`~x690.decode`. x690 checks the result and
   type checkers know what comes back. The package ships type hints and is
   checked with ``mypy --strict``.

No copies
   :func:`~x690.decode` reads from any offset of a buffer and returns the
   offset of the next value. Values keep a reference to the buffer and are
   converted when first read. Definite and indefinite lengths are supported.

Custom types
   Subclass :class:`~x690.types.X690Type` to add application, context or
   private types. Subclassing registers the type with the decoder.

Readable dumps
   :meth:`~x690.types.X690Type.pretty` prints nested values with hex dumps,
   and shows the class, nature and tag of every value x690 does not know.

One dependency
   x690 is pure Python. It depends only on
   `t61codec <https://github.com/exhuma/t61codec>`_ for ``T61String``.

Scope
-----

x690 implements the Basic Encoding Rules. It does not compile ASN.1 modules:
message structures are built from the type classes in code. Some universal
types decode to their raw bytes only; :doc:`types` lists what converts to
which Python value.

The standard is fixed and the library is feature-complete. The project is in
maintenance mode: it accepts bug fixes, support for new Python versions and
security fixes. Versions follow `Semantic Versioning
<https://semver.org/spec/v2.0.0.html>`_.

Contents
--------

:doc:`usage`
   Encode values, decode single values and streams, check types and inspect
   unknown data.

:doc:`custom-types`
   Add application or context types, from a tag-only subclass to a type with
   its own conversion.

:doc:`types`
   The universal types and the Python value each one decodes to.

:doc:`api/index`
   Every public module, class and function.

:doc:`glossary` and :doc:`changelog`
   Terms used in these pages, and changes in every release.

.. toctree::
   :hidden:

   usage
   custom-types
   types
   api/index
   glossary
   changelog
