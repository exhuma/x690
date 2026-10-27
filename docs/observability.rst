Observability
=============

x690 writes log records through the standard :mod:`logging` module. It
emits nothing by default: it never adds a handler, never sets a level and
never touches the root logger. The application decides whether the
records go anywhere, and how verbose they are.

Logger
------

All records come from one logger, ``x690.types``. Set the level of
``x690`` to tune the whole package, or of ``x690.types`` for this logger
alone.

Every record has the level ``DEBUG``. x690 raises an exception when it
cannot decode or encode a value, and does not log the failure as well.
The records show decisions that are otherwise invisible: x690 carried
on, although the input was unusual.

x690 never logs decoded content, because it can hold personal data. The
attributes are tags, class names, offsets and counts.

Values are converted when they are first read, so the records about the
content of a value appear when ``value`` is read, not during
:func:`~x690.decode`. The record about an unknown type appears during
decoding.

Enable the records
------------------

Set the level of the ``x690`` logger to ``DEBUG`` and attach a handler
of the application to it, or to a logger above it. The example collects the records
in a list. It restores the logging state at the end.

>>> import logging
>>> from x690 import decode
>>> log = logging.getLogger("x690")
>>> level = log.level
>>> records = []
>>> handler = logging.Handler()
>>> handler.emit = records.append
>>> log.addHandler(handler)
>>> log.setLevel(logging.DEBUG)
>>> value, _ = decode(b"\x85\x01\x00")
>>> log.removeHandler(handler)
>>> log.setLevel(level)
>>> records[0].getMessage()
'Unknown type decoded'
>>> records[0].__dict__["x690.type.tag"]
5

Every attribute is a plain ``str`` or ``int``, stored on the record under
a key that starts with ``x690.``. A handler or formatter reads it with
``record.__dict__["x690.type.tag"]``, and JSON and OpenTelemetry log
handlers export it as a log attribute.

Records
-------

``Unknown type decoded``
   No class is registered for the identifier of a value, and the enclosing
   type does not list one either. This includes a context-specific tag that
   is missing from the ``CHILD_TYPES`` of its enclosing type. x690 decodes
   an :class:`~x690.types.UnknownType`.

   ``x690.type.class``, ``x690.type.nature``, ``x690.type.tag``,
   ``x690.offset``, and ``x690.enclosing_type`` (a class name) inside a
   structure.

``Registered type overridden by child type``
   A type in ``CHILD_TYPES`` decodes a value, although another class is
   registered for the same identifier.

   ``x690.type.tag``, ``x690.type.name``, ``x690.enclosing_type``.

``Bit string padding not zero``
   The unused bits of a bit string are not zero. x690 keeps them, and
   ignores them in comparisons.

   ``x690.bits.unused``.

``Empty bit string without unused-bits octet``
   A bit string has no contents at all, not even the octet that counts
   the unused bits. x690 decodes an empty value.

``Text outside permitted alphabet decoded``
   A ``PrintableString`` or ``NumericString`` holds characters that its
   alphabet does not allow. Decoding is lenient and keeps them.

   ``x690.type.name``, and ``x690.char_count``, the number of offending
   characters. The characters themselves are never logged.

``Real value saturated``
   A ``REAL`` is outside the range of a float and decodes to an infinity
   or to zero.

   ``x690.real.result``, one of ``"inf"``, ``"-inf"`` and ``"0"``.

``Microseconds dropped``
   Encoding a ``UtcTime`` discards the microseconds of the value, because
   the format has no room for them.

   ``x690.type.name``.

``Fraction truncated``
   Decoding a ``GeneralizedTime`` discards fraction digits that do not fit
   into microseconds.

   ``x690.type.name``.

Spans
-----

x690 creates no spans. Decoding and encoding are pure computation, and
the caller sees how long they take. To trace a call, wrap it in a span
in the application.

Compatibility
-------------

The logger name, the messages and the attribute keys are part of the
public interface. Renaming or removing one is a breaking change, and
adding one is listed as a new feature in the :doc:`changelog`. See
the "Compatibility" section of :doc:`index` for the policy.
