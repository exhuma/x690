Pure Python `X.690`_ implementation
===================================

.. image:: https://github.com/exhuma/x690/workflows/Build%20&%20Publish%20Docs/badge.svg?branch=main
    :alt: Build & Publish Docs

.. _X.690: https://www.itu.int/rec/recommendation.asp?lang=en&parent=T-REC-X.690-201508-I


This module contains a pure Python implementation of the "x690" standard for
BER encoding/decoding. Other encodings are currently unsupported but
pull-requests are welcome.


Type Extensions
---------------

It allows defining and detecting new data-types by simply subclassing the base
class ``x690.types.Type``. An example for this can be seen in `puresnmp`_

.. _puresnmp: https://github.com/exhuma/puresnmp/blob/4240aa644a1bca01f54683215833dc6711a22745/puresnmp/types.py#L28


Examples
========

Encoding to bytes
-----------------

Encoding to bytes can be done by simply calling the Python builting ``bytes()``
on instances from ``x690.types``:

Encoding of a single value
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    import x690.types as t

    >>> myvalue = t.Integer(12)
    >>> asbytes = bytes(myvalue)
    >>> repr(asbytes)
    b'\x02\x01\x0c'

Encoding of a composite value using Sequence
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    import x690.types as t

    >>> myvalue = t.Sequence(
    ...     t.Integer(12),
    ...     t.Integer(12),
    ...     t.Integer(12),
    ... )
    >>> asbytes = bytes(myvalue)
    >>> repr(asbytes)
    b'0\t\x02\x01\x0c\x02\x01\x0c\x02\x01\x0c'


Decoding from bytes
~~~~~~~~~~~~~~~~~~~

Decode bytes by calling ``x690.types.pop_tlv`` on your byte data. This will
return a tuple where the first value contains the decoded object, and the
second one will contain any remaining bytes which were not decoded.

.. code:: python

    import x690.types as t
    >>> data = b'0\t\x02\x01\x0c\x02\x01\x0c\x02\x01\x0c'
    >>> decoded, remaining_bytes = t.pop_tlv(data)
    >>> decoded
    Sequence(Integer(12), Integer(12), Integer(12))
    >>> remaining_bytes
    b''


Type-Hinting & Enforcing
~~~~~~~~~~~~~~~~~~~~~~~~

**New in 0.3.0**

When decoding bytes, it is possible to specify an expcted type which does two
things: Firstly, it tells tools like ``mypy`` what the return type will be and
secondly, it runs an internal type-check which *ensures* that the returned
value is of the expected type. ``x690.exc.UnexpectedType`` is raised otherwise.

This does of course only work if you know the type in advance.

.. code:: python

    import x690.types as t
    >>> data = b'0\t\x02\x01\x0c\x02\x01\x0c\x02\x01\x0c'
    >>> decoded, remaining_bytes = t.pop_tlv(data, enforce_type=t.Sequence)
    >>> decoded
    Sequence(Integer(12), Integer(12), Integer(12))
    >>> remaining_bytes
    b''


Strict Decoding
~~~~~~~~~~~~~~~

**New in 0.3.0**

When decoding using ``pop_tlv`` and you don't expect any remaining bytes, use
``strict=True`` which will raise ``x690.exc.IncompleteDecoding`` if there's any
remaining data.

.. code:: python

    import x690.types as t
    >>> data = b'0\t\x02\x01\x0c\x02\x01\x0c\x02\x01\x0cjunk-bytes'
    >>> decoded, remaining_bytes = t.pop_tlv(data, strict=True)
    Traceback (most recent call last):
      ...
    x690.exc.IncompleteDecoding: Strict decoding still had 10 remaining bytes!
