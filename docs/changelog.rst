Changelog
=========

Release 2.0.0
-------------

2.0.0 is the first release since 1.0.0post1. It includes the changes
prepared as 1.1.0, which was never published.

**Changes that need updates to your code**

* Context-specific types such as SNMP PDUs are now declared on the type
  that contains them, in ``CHILD_TYPES``, instead of being registered
  globally when the class is defined. The same tag can now mean a different
  type in every structure, as in X.509 and LDAP. See :doc:`custom-types`
  (`#6 <https://github.com/exhuma/x690/issues/6>`_).
* A subclass that only changes how a type converts its value must set its
  ``TAG`` again to replace the built-in type.
* Most string types now give a ``str``, ``UtcTime`` and
  ``GeneralizedTime`` a ``datetime``, ``Enumerated`` an ``int``, ``Real`` a
  ``float``, ``BitString`` a ``Bits`` value and ``Set`` a list of values,
  instead of bytes. See :doc:`types`
  (`#7 <https://github.com/exhuma/x690/issues/7>`_).
* ``raw_bytes`` of a decoded value is now only that value's bytes, and the
  ``bounds`` attribute is gone
  (`#14 <https://github.com/exhuma/x690/issues/14>`_).
* Values are equal only when they have the same class and value, so a
  subclass no longer equals its base class.
* ``repr()`` of a ``Sequence`` subclass shows the subclass name
  (`#19 <https://github.com/exhuma/x690/issues/19>`_).
* ``T61String`` follows ITU-T T.61 strictly: accented letters decode to
  single characters (``b"Caf\xc2e"`` gives ``"Café"``), ``0xE0`` is Ω
  U+03A9, and invalid data raises an error. Data written by OpenSSL is often
  Latin-1; decode such values with ``latin-1`` yourself
  (`#3 <https://github.com/exhuma/x690/issues/3>`_).
* Importing x690 no longer makes the ``t61`` codec available to Python's
  ``codecs`` module.
* Requires Python 3.11 or newer.

**New**

* ``Explicit`` describes explicitly tagged values.
* ``detach()`` lets you keep a value from a large document without keeping
  the whole document in memory.
* ``decode()`` takes the types of a context-tagged value as ``types=``.
* Decoding decisions (unknown types, overrides, lenient decoding and
  saturated values) are logged at DEBUG on the ``x690.types`` logger. See
  :doc:`observability`.

**Faster and smaller**

* Large documents decode with a fraction of the memory, and reading items by
  index no longer slows down as documents grow
  (`#16 <https://github.com/exhuma/x690/issues/16>`_,
  `#17 <https://github.com/exhuma/x690/issues/17>`_).
  :doc:`choosing` compares the results with other ASN.1 libraries.

**Fixes**

* ``decode(..., strict=True)`` raises on a single trailing byte
  (`#12 <https://github.com/exhuma/x690/issues/12>`_).
* ``GraphicString`` values can be encoded
  (`#13 <https://github.com/exhuma/x690/issues/13>`_).
* ``repr()`` of an unknown type no longer changes between Python versions.
* A truncated ``ObjectIdentifier`` raises ``ValueError`` instead of
  ``StopIteration``.
* The type hints of ``VideotexString``, ``GeneralString`` and
  ``CharacterString`` say ``bytes``, which is what they hold.

**Documentation**

* New documentation at https://exhuma.github.io/x690/, with guides, a list
  of supported types and a comparison with other ASN.1 libraries.
* The start page states the compatibility and deprecation policy, and the
  API reference documents every public class and function.

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

* Internal typing improvement


0.5.0-alpha.4
-------------

* Raise an exception when trying to decode data that is out-of-bounds of the
  processed blob.
* Accessing a scalar index (not a slice) from an OID returns the integer value.

0.5.0-alpha.3
-------------

* Housekeeping & typing improvements

0.5.0-alpha.2
-------------

* Don't consider "None/NULL" values as "uninitialised". This prevents
  unnecessary/repetitive byte-conversions.

0.5.0-alpha.1
-------------

* ObjectIdentifiers now "feel" more like strings. The constructor changed to
  reflect this: ``ObjectIdentifier("1.2.3")``
* Improve error message when creating custom types without no-arg constructor
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
* An instance can now be created from raw-bytes (excluding the type and length
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
* Improved prettification of unknown types
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
* Improved prettification of byte-values and unknown types
* Improved prettification of nested sequences
* Improved type-hints
* Added default values to all types
* Changed ``x690.util.LengthValue`` and ``x690.util.TypeInfo`` to dataclasses
* Use enums for internal "typeclass" and "primitive/constructed" values.
* Stricter CI pipeline (including mypy and vulture)
* Switch to ``poetry`` for packaging
