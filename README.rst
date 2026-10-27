x690
====

.. image:: https://img.shields.io/pypi/v/x690.svg
   :target: https://pypi.org/project/x690/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/x690.svg
   :target: https://pypi.org/project/x690/
   :alt: Supported Python versions

.. image:: https://github.com/exhuma/x690/actions/workflows/pythonpackage.yml/badge.svg
   :target: https://github.com/exhuma/x690/actions/workflows/pythonpackage.yml
   :alt: CI status

.. image:: https://github.com/exhuma/x690/actions/workflows/docs.yml/badge.svg
   :target: https://exhuma.github.io/x690/
   :alt: Documentation

Encode and decode ASN.1 data in BER (ITU-T X.690) with pure Python. x690
turns every encoded value into a typed Python object, decodes documents of a
million values in a few megabytes of memory, and takes new types with a few
lines of code. It is the encoding layer of `puresnmp
<https://github.com/exhuma/puresnmp>`_.

Documentation: https://exhuma.github.io/x690/

Installation
------------

x690 needs Python 3.11 or newer::

    pip install x690

Example
-------

::

    >>> from x690 import decode
    >>> from x690.types import Integer, OctetString, Sequence
    >>> data = bytes(Sequence([Integer(42), OctetString(b"hello")]))
    >>> data
    b'0\n\x02\x01*\x04\x05hello'
    >>> decode(data)
    (Sequence([Integer(42), OctetString(b'hello')]), 12)

The documentation covers `how to encode and decode values
<https://exhuma.github.io/x690/usage.html>`_, `how to add custom types
<https://exhuma.github.io/x690/custom-types.html>`_ and `which types
convert to which Python values <https://exhuma.github.io/x690/types.html>`_.

Project status
--------------

The API is stable. Context-specific tags resolve per enclosing type, so
structures that reuse a tag such as ``[0]``, as X.509 and LDAP do, can be
described. Work continues on declaring types by position and on Python
values for more universal types. `Choosing x690
<https://exhuma.github.io/x690/choosing.html>`_ compares x690 with other
ASN.1 libraries and lists its current limitations.

x690 follows Semantic Versioning. The `compatibility policy
<https://exhuma.github.io/x690/#compatibility>`_ defines what counts as a
breaking change and how deprecation works.
