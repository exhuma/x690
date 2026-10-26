"""
pyasn1: schema as pyasn1 classes.
"""

from collections.abc import Callable

from data import spans
from pyasn1.codec.ber import decoder
from pyasn1.type import namedtype, univ


class Volume(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("uplink", univ.Integer()),
        namedtype.NamedType("downlink", univ.Integer()),
    )


class Record(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("record-type", univ.Integer()),
        namedtype.NamedType("imsi", univ.OctetString()),
        namedtype.NamedType("opening-time", univ.OctetString()),
        namedtype.NamedType("duration", univ.Integer()),
        namedtype.NamedType("cell-id", univ.OctetString()),
        namedtype.NamedType("charging-id", univ.Integer()),
        namedtype.NamedType("volumes", univ.SequenceOf(componentType=Volume())),
    )


class File(univ.SequenceOf):  # type: ignore[misc]
    componentType = Record()


def setup(workload: str) -> Callable[[bytes], int]:
    """
    Return the decode function for *workload*.
    """

    def stream(data: bytes) -> int:
        total = 0
        for start, end in spans(data):
            record, _ = decoder.decode(data[start:end], asn1Spec=Record())
            total += int(record["duration"])
        return total

    def full(data: bytes) -> int:
        document, _ = decoder.decode(data, asn1Spec=File())
        return sum(int(record["duration"]) for record in document)

    def partial(data: bytes) -> int:
        document, _ = decoder.decode(data, asn1Spec=File())
        return int(document[-1]["duration"])

    def indexed(data: bytes) -> int:
        document, _ = decoder.decode(data, asn1Spec=File())
        return sum(
            int(document[index]["duration"]) for index in range(len(document))
        )

    return {
        "stream": stream,
        "full": full,
        "partial": partial,
        "indexed": indexed,
    }[workload]
