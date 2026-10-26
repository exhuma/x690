"""
Encode and decode ASN.1 values in BER (ITU-T X.690).

:func:`decode` reads one value from a bytes object and returns it with the
index of the next value:

>>> from x690 import decode
>>> decode(b"\x02\x01\x01\x02\x01\x03")
(Integer(1), 3)

The type classes live in :mod:`x690.types`. The usage guide in the
documentation covers streams, ``enforce_type`` and ``strict``.
"""

from .types import decode

try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:  # pragma: no cover
    import importlib_metadata  # type: ignore


__version__ = importlib_metadata.version("x690")
__all__ = [
    "__version__",
    "decode",
]
