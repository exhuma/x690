"""
x690 is a library allowing to decode and encode values according to the ITU
X.690 standard.

For decoding, use the function *pop_tlv* provided by this module. When used
as-is on a bytes object, it will return the first value in the blob and the
remaining bytes:

>>> from x690 import pop_tlv
>>> data, remainer = pop_tlv(b"\x02\01\01\x02\01\03")
Integer(1), b"\x02\01\01"

For a stream of data with an unknown number of items, you can loop on the
remaining bytes:

>>> from x690 import pop_tlv
>>> item, remainder = pop_tlv(data)
>>> while remainder:
...     item, remainder = pop_tlv(remainder)

If you expect exactly one element, it is possible to pass the "strict"
argument. This will raise an error if the stream contains any "junk" data.

Finally, a x690 data-stream may contain various types. For this reason, the
"pop_tlv" function is type-hinted to return a vague, imprecise type. If you
*know* what your are decoding, you can pass the expected type into the
function:

>>> from x690 import pop_tlv
>>> from x690.types import Integer
>>> pop_tlv(b"\x02\x01\x01", enforce_type=Integer)
Integer(1)

This will do two things:

* It runs a type-check upon decoding and will raise a
  :py:exc:`x690.exc.UnexpectedType` error if it does not match.
* Inform the type-checker of the return-type, improving type-checker output.
"""

from .types import pop_tlv
from .version import VERSION as __version__

__all__ = [
    "__version__",
    "pop_tlv",
]
