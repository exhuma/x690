"""
x690: decode with offsets, no schema needed for universal types.
"""

from collections.abc import Callable

from x690 import decode
from x690.types import Sequence


def setup(workload: str) -> Callable[[bytes], int]:
    """
    Return the decode function for *workload*.
    """

    def stream(data: bytes) -> int:
        total = 0
        index = 0
        while index < len(data):
            record, index = decode(data, index, enforce_type=Sequence)
            total += record[3].value
        return total

    def full(data: bytes) -> int:
        document, _ = decode(data, enforce_type=Sequence)
        return sum(record[3].value for record in document)

    def partial(data: bytes) -> int:
        document, _ = decode(data, enforce_type=Sequence)
        last = document[-1]
        assert isinstance(last, Sequence)
        return int(last[3].value)

    def indexed(data: bytes) -> int:
        document, _ = decode(data, enforce_type=Sequence)
        total = 0
        for index in range(len(document)):
            record = document[index]
            assert isinstance(record, Sequence)
            total += record[3].value
        return total

    return {
        "stream": stream,
        "full": full,
        "partial": partial,
        "indexed": indexed,
    }[workload]
