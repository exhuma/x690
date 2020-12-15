Changelog
=========

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
