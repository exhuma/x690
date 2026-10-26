"""
asn1crypto: schema as classes with field lists, parses lazily.
"""

from collections.abc import Callable

from asn1crypto import core
from data import spans


class Volume(core.Sequence):  # type: ignore[misc]
    _fields = [("uplink", core.Integer), ("downlink", core.Integer)]


class Volumes(core.SequenceOf):  # type: ignore[misc]
    _child_spec = Volume


class Record(core.Sequence):  # type: ignore[misc]
    _fields = [
        ("record-type", core.Integer),
        ("imsi", core.OctetString),
        ("opening-time", core.OctetString),
        ("duration", core.Integer),
        ("cell-id", core.OctetString),
        ("charging-id", core.Integer),
        ("volumes", Volumes),
    ]


class File(core.SequenceOf):  # type: ignore[misc]
    _child_spec = Record


def setup(workload: str) -> Callable[[bytes], int]:
    """
    Return the decode function for *workload*.
    """

    def stream(data: bytes) -> int:
        total = 0
        for start, end in spans(data):
            total += Record.load(data[start:end])["duration"].native
        return total

    def full(data: bytes) -> int:
        document = File.load(data)
        return sum(record["duration"].native for record in document)

    def partial(data: bytes) -> int:
        return int(File.load(data)[-1]["duration"].native)

    def indexed(data: bytes) -> int:
        document = File.load(data)
        return sum(
            document[index]["duration"].native for index in range(len(document))
        )

    return {
        "stream": stream,
        "full": full,
        "partial": partial,
        "indexed": indexed,
    }[workload]
