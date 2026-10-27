x690
====

Encode and decode :term:`ASN.1` data in :term:`BER` (ITU-T :term:`X.690`)
with pure Python. x690 turns every encoded value into a typed Python
object, decodes documents of a million values in a few megabytes of
memory, and takes new types with a few lines of code. It is the
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

Large documents
   A document of 1,000,000 records decodes with 8 MB of memory on top of its
   input, where the other Python libraries in the :ref:`benchmark
   <performance>` need 0.35 to 9.6 GB. :func:`~x690.decode` reads from any
   offset of a buffer without copying it, a sequence records where its items
   start, and values are converted when first read. Definite and indefinite
   lengths are supported.

Custom types
   Subclass :class:`~x690.types.X690Type` to add application, context or
   private types. Application and private types are registered with the
   decoder. Context-specific types are declared on their enclosing type, so
   the same :term:`tag` can mean a different type in every structure.

Readable dumps
   :meth:`~x690.types.X690Type.pretty` prints nested values with hex dumps,
   and shows the class, :term:`nature` and tag of every value x690 does
   not know.

One dependency
   x690 is pure Python. It depends only on
   `t61codec <https://github.com/exhuma/t61codec>`_ for ``T61String``.

Project status
--------------

The API is stable. Context-specific tags resolve per
enclosing type, so structures that reuse a tag such as ``[0]``, as X.509 and
LDAP do, can be described. Work continues: types are declared by tag, not
by position, and some universal types hold raw bytes only.
:doc:`choosing` compares x690 with other ASN.1 libraries and lists its
current limitations. See `Compatibility`_ for the
versioning and deprecation policy.

Compatibility
-------------

x690 follows `Semantic Versioning
<https://semver.org/spec/v2.0.0.html>`_. It supports Python 3.11 to
3.15, the versions in ``requires-python`` and the package classifiers.
Raising the minimum Python version is a breaking change.

A change is breaking when it can make working user code fail or behave
differently. This includes:

- removing or renaming a public name, parameter or attribute,
- changing a return type or the Python type a value converts to,
- raising an exception where the code did not raise before,
- changing equality, hashing or ``repr()`` of a public type,
- raising the minimum Python version.

Breaking changes are released only in a major version. Before x690
removes anything, a minor release deprecates it: the old name emits a
:class:`DeprecationWarning`, and the :doc:`changelog` has a
``deprecated`` entry that names the replacement. The removal comes no
earlier than the next major release.

Contents
--------

:doc:`choosing`
   x690 next to pyasn1, asn1tools, asn1crypto and pycrate, the reasons behind
   its design, and its current limitations.

:doc:`usage`
   Encode values, decode single values and streams, check types and
   inspect unknown data.

:doc:`custom-types`
   Add application or context types, declare the types of a structure,
   and write a type with its own conversion.

:doc:`types`
   The universal types and the Python value each one decodes to.

:doc:`observability`
   The DEBUG records x690 emits and how to switch them on.

:doc:`api/index`
   Every public module, class and function.

:doc:`glossary` and :doc:`changelog`
   Terms used in these pages, and changes in every release.

.. toctree::
   :hidden:

   choosing
   usage
   custom-types
   observability
   types
   api/index
   glossary
   changelog
