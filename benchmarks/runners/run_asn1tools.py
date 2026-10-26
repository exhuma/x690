"""
asn1tools: compiles the ASN.1 module at runtime, returns dictionaries.
"""

from collections.abc import Callable

import asn1tools
from data import SPEC, spans


def setup(workload: str) -> Callable[[bytes], int]:
    """
    Return the decode function for *workload*.
    """
    spec = asn1tools.compile_string(SPEC, "ber")

    def stream(data: bytes) -> int:
        total = 0
        for start, end in spans(data):
            total += spec.decode("Record", data[start:end])["duration"]
        return total

    def full(data: bytes) -> int:
        document = spec.decode("File", data)
        return sum(record["duration"] for record in document)

    def partial(data: bytes) -> int:
        document = spec.decode("File", data)
        return int(document[-1]["duration"])

    def indexed(data: bytes) -> int:
        document = spec.decode("File", data)
        return sum(
            document[index]["duration"] for index in range(len(document))
        )

    return {
        "stream": stream,
        "full": full,
        "partial": partial,
        "indexed": indexed,
    }[workload]
