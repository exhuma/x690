Changelog
=========

Release 2.0.0
-------------

2.0.0 includes the changes prepared as 1.1.0, which was never published.
Upgrading from 1.0 needs code changes where the breaking changes below
apply.

**Breaking changes**

* Context-specific types are no longer registered globally. A constructed
  type lists the types of its children in ``CHILD_TYPES``, and tags are
  resolved per enclosing type, so the same tag can mean a different type in
  every structure. ``decode()`` takes the types of the top-level value as
  ``types=``. ``Explicit`` describes explicitly tagged values. A subclass
  is registered only if it sets its own ``TYPECLASS``, ``TAG`` or
  ``NATURE``; ``register=False`` keeps an application or private type out of
  the global registry
  (`#6 <https://github.com/exhuma/x690/issues/6>`_).
* More universal types hold Python values instead of bytes:
  ``Utf8String``, ``NumericString``, ``PrintableString``, ``IA5String``,
  ``VisibleString``, ``ObjectDescriptor``, ``BmpString`` and
  ``UniversalString`` hold a ``str``; ``UtcTime`` and ``GeneralizedTime`` a
  ``datetime``; ``Enumerated`` an ``int``; ``RelativeOid`` a ``str``;
  ``Real`` a ``float``; ``BitString`` a ``Bits`` value; ``Set`` a list of
  values like ``Sequence``
  (`#7 <https://github.com/exhuma/x690/issues/7>`_).
* ``raw_bytes`` of a decoded value is its own content bytes instead of the
  whole input buffer, and the ``bounds`` attribute is gone. The new
  ``detach()`` copies a value's own bytes and drops the reference to the
  input, so a value kept from a large document no longer keeps the document
  alive (`#14 <https://github.com/exhuma/x690/issues/14>`_).
* ``repr()`` of a ``Sequence`` subclass starts with the subclass name
  (`#19 <https://github.com/exhuma/x690/issues/19>`_).
* ``T61String`` uses ``t61codec`` 3, which follows ITU-T T.61 (1988) to
  the letter. Accented letters decode to precomposed characters
  (``b"Caf\xc2e"`` gives ``"Café"``), and ``0xE0`` decodes to Ω U+03A9
  (it was U+2126). Invalid T.61 raises ``UnicodeDecodeError``, and
  characters which T.61 cannot represent raise an error when encoding.
  Data written by OpenSSL is often Latin-1 rather than T.61; decode such
  raw values with ``latin-1`` yourself
  (`#3 <https://github.com/exhuma/x690/issues/3>`_).
* x690 no longer registers the ``t61`` codec in Python's global codec
  registry.
* Values compare equal only when they are of the same class and hold the
  same value. A subclass differs from its base class, and a context-class
  ``Sequence`` subclass from a plain ``Sequence`` with the same items.
  The types converted to Python values now compare by value and, like
  ``Integer`` and ``OctetString``, cannot be hashed.
* Requires Python 3.11 or newer.

**Performance**

* Indexing a decoded ``Sequence`` no longer re-decodes all its items: a
  sequence records where its items start and decodes each item when it is
  accessed. Reading every item by index was quadratic and is now linear
  (`#16 <https://github.com/exhuma/x690/issues/16>`_).
* Every type declares ``__slots__``, so decoded values no longer carry a
  ``__dict__``. A decoded ``Integer`` takes about a quarter of the memory it
  took before (`#17 <https://github.com/exhuma/x690/issues/17>`_).
* A benchmark in ``benchmarks/`` compares decode time and memory with
  pyasn1, asn1tools, asn1crypto and pycrate.

**Fixes**

* ``decode(..., strict=True)`` raises on a single trailing byte
  (`#12 <https://github.com/exhuma/x690/issues/12>`_).
* ``GraphicString`` encodes values built from a ``str``
  (`#13 <https://github.com/exhuma/x690/issues/13>`_).
* ``repr()`` of ``UnknownType`` is stable on Python 3.12 and later.

**Packaging and project**

* Depends on ``t61codec>=3.0,<4``.
* Built with hatchling from a PEP 621 ``pyproject.toml``, with PEP 639
  license metadata, and classified as
  ``Development Status :: 5 - Production/Stable``.
* The wheel contains only the ``x690`` package; the test suite is no longer
  installed as a top-level ``tests`` package (see
  `#2 <https://github.com/exhuma/x690/pull/2>`_).
* CI tests all supported CPython versions automatically, plus a monthly
  scheduled run. Releases are published through PyPI Trusted Publishing.
* The documentation has a new theme and structure, including a comparison
  with other ASN.1 libraries, and is deployed to GitHub Pages:
  https://exhuma.github.io/x690/. Every x690 example in it runs as a
  doctest.

Release 1.0.0post1 - Maintenance release
----------------------------------------

* This fixes the incorrectly provided extra ``rest`` in the dependency
  metadata. This extra has become obsolete and removing it fixed
  versioning errors when installing ``x690``.

1.0.0
-----

* Renamed ``x690.types.Type`` to ``x690.types.X690Type``
* Flagged as "stable"
* Dropped support for Python 3.6


0.5.0
-----

* Flagged as "production" release
* All changes from 0.5.0-alpha.0 - 0.5.0-alpha.6


0.5.0-alpha.6
-------------

* Relaxed dev-dependencies a bit which caused issues in some installations

0.5.0-alpha.5
-------------

* Allow ObjectIdentifier instances to be created for "relative" sub-trees by
  delaying the byte-conversion.

  When converting ObjectIdentifiers to bytes, the first two objects are
  "folded" together. This is not possible for some values. Delaying this
  folding until the "is-needed" moment allows the use for such OIDs to be used
  for subtree modifications/concatenation.  They will still raise errors if
  they are converted to bytes unmodified.

* Internal typing improvment


0.5.0-alpha.4
-------------

* Raise an exception when trying to decode data that is out-of-bounds of the
  processed blob.
* Accessing a scalar index (not a slice) from an OID returns the integer value.

0.5.0-alpha.3
-------------

* Housekeeping & typing improvments

0.5.0-alpha.2
-------------

* Don't conider "None/NULL" values as "uninitialised". This prevents
  unnecessary/repetitive byte-conversions.

0.5.0-alpha.1
-------------

* ObjectIdentifiers now "feel" more like strings. The constructor changed to
  reflect this: ``ObjectIdentifier("1.2.3")``
* Improve error message when creating custom typess without no-arg constructor
* Fix "unsigned int" values
* Fix handling of empty ``Sequence`` instances

0.5.0-alpha.0
-------------

This release focussed on performance (both memory and CPU) in order to decode
large x690 documents.

As it goes with performance, a fair amount of refactoring was needed and the
external API could not be guaranteed easily. And as we're still on the 0.x
branch, the backwards-compatibility was dropped in favor of cleaner code.

It is flagged as "alpha" until I feel confident that the new changes have not
introduced breaking bugs.


* **Replaced** ``x690.pop_tlv`` has been replaced by ``x690.decode``.
  This no longer copies data in-memory and therefore no longer returns the
  "remaining" data-bytes. Instead it returns the position of the next
  data-block. ``decode`` also takes an additional argument to define where to
  start decoding data from.
* **changed** ``ObjectIdentifier`` has been aligned to the existing types and
  no longer use ``*args`` to initialise instances. Instead of
  ``ObjectIdentifier(1, 2, 3)`` you must now write ``Sequence((1, 2, 3))``
* **changed** ``Sequence`` has been aligned to the existing types and no longer
  use ``*args`` to initialise instances. Instead of ``Sequence(a, b, c)`` you
  must now write ``Sequence([a, b, c])``
* **changed** ``UnknownType`` has been aligned to the existing types. It now
  takes the value as *first* argument instead of second. Instead of
  ``UnknownType(99, b"abc")`` you must now write ``UnknownType(b"abc", 99)``.
* **changed** Subclasses of ``x690.Type`` must now override the
  ``Type.decode_raw`` method if the data is needed in another type that
  ``bytes``.
* **changed** Subclasses of ``x690.Type`` must now override the
  ``Type.encode_raw`` method if the python-value is a non-bytes object.
* dataclasses in have been replaced with named-tuples for increased performance.
* An instance can now be creted from raw-bytes (excluding the type and length
  header bytes) by calling ``Type.from_bytes(...)`` (by using the class of the
  appropriate type!).
* New function ``x690.util.get_value_slice`` can be used to find the location
  of the raw-bytes of a value at any given location. The location must however
  be the *start* of an x690 "TLV" block. This will return the slice of the
  value location (The "V" part excluding the "TL" part) and the location of the
  next value-block.

0.4.0
-----


* **Removed** Decoding no longer raises a "ValueError" if a value contains
  junk-bytes after decoding. Use either "strict" mode or inspect the
  "remainder" after decoding yourself. This was a necessity to remove a
  duplication with length-decoding and was too impactful to re-introduce.
* **Removed** Types no longer have a ``from_bytes`` implementation. This was
  the core of the code-duplication and is now gone in favor of the ``decode``
  function.
* Support for "indefinite length" values
* Allow registering types with "non-constructed" nature
* Improved prettyfication of unknown types
* Support types which can be encoded as either "primitive" or "constructed"
* Implement decoding of the GraphicString type
* Removed duplication of length-decoding


0.3.0
-----

The most visible changes in this release are the additional arguments on
``pop_tlv``. Using ``enforce_type`` adds valuable typing information for IDEs.
As long as they are known in advance of course. By default, the type will be
``Any``. Using ``strict=True`` can be helpful for fail-fast programming.

Finally, some internals have been modified for more maintainable code. They
should only have an impact if you extended ``x690`` with new types.


* **Dropped Support for Python <3.6**
* **Removed** ``x690.types.NonASN1Type``
* **Removed** custom ``to_bytes`` implementation (use the builtin ``bytes()``
  instead). For example: ``bytes(x690.types.Integer(10))``
* Added ``enforce_type`` to ``pop_tlv`` for improved type-safety and -checking
* Added ``strict`` to ``pop_tlv`` for quick & easy sanity checks
* Improved prettyfication of byte-values and unknown types
* Improved prettyfication of nested sequences
* Improved type-hints
* Added default values to all types
* Changed ``x690.util.LengthValue`` and ``x690.util.TypeInfo`` to dataclasses
* Use enums for internal "typeclass" and "primitive/constructed" values.
* Stricter CI pipeline (including mypy and vulture)
* Switch to ``poetry`` for packaging
