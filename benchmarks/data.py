"""
Synthetic input for the decode benchmark.

The records are shaped like charging data records (CDRs): a few integers and
octet strings and a nested list of usage volumes. They are encoded by the small
BER encoder in this module, so the input does not depend on any of the
libraries under test.
"""

from collections.abc import Iterator
from pathlib import Path

#: The ASN.1 module of the benchmark data, for libraries that compile one.
SPEC = """
Bench DEFINITIONS IMPLICIT TAGS ::= BEGIN
  Record ::= SEQUENCE {
    record-type INTEGER,
    imsi OCTET STRING,
    opening-time OCTET STRING,
    duration INTEGER,
    cell-id OCTET STRING,
    charging-id INTEGER,
    volumes SEQUENCE OF Volume
  }
  Volume ::= SEQUENCE {
    uplink INTEGER,
    downlink INTEGER
  }
  File ::= SEQUENCE OF Record
END
"""

#: Workloads: records one after another, a whole document read by
#: iteration, only the last record of a document, and a whole document read
#: by index.
WORKLOADS = ("stream", "full", "partial", "indexed")


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def _integer(value: int) -> bytes:
    size = value.bit_length() // 8 + 1
    return _tlv(0x02, value.to_bytes(size, "big", signed=True))


def _record(index: int) -> bytes:
    volumes = b"".join(
        _tlv(0x30, _integer(index * 7 + k) + _integer(index * 13 + k * 1000))
        for k in range(3)
    )
    return _tlv(
        0x30,
        _integer(18)
        + _tlv(0x04, (2620100000000000 + index).to_bytes(8, "big"))
        + _tlv(0x04, b"\x25\x10\x26\x12\x00\x00\x2b\x01\x00")
        + _integer(index % 3600)
        + _tlv(0x04, (index % 65536).to_bytes(4, "big"))
        + _integer(1_000_000 + index)
        + _tlv(0x30, volumes),
    )


def input_kind(workload: str) -> str:
    """
    Return ``stream`` or ``document``: the shape of input *workload* reads.
    """
    return "stream" if workload == "stream" else "document"


def make_input(kind: str, records: int) -> bytes:
    """
    Return the encoded input of *kind*.

    ``stream`` is the records one after another; ``document`` wraps them in
    one ``SEQUENCE OF``.
    """
    data = b"".join(_record(index) for index in range(records))
    if kind == "stream":
        return data
    return _tlv(0x30, data)


def input_file(cache_dir: Path, workload: str, records: int) -> Path:
    """
    Return the path of the input file for *workload*, creating it if needed.
    """
    kind = input_kind(workload)
    path = cache_dir / f"{kind}-{records}.ber"
    if not path.exists():
        cache_dir.mkdir(parents=True, exist_ok=True)
        partial_path = path.with_suffix(".tmp")
        partial_path.write_bytes(make_input(kind, records))
        partial_path.rename(path)
    return path


def expected(workload: str, records: int) -> int:
    """
    Return the result a runner must produce for *workload*.

    Runners sum the ``duration`` of every record, or return the ``duration``
    of the last record for ``partial``.
    """
    if workload == "partial":
        return (records - 1) % 3600
    return sum(index % 3600 for index in range(records))


def spans(data: bytes) -> Iterator[tuple[int, int]]:
    """
    Yield the start and end of each top-level value in *data*.

    Libraries without an offset-based decoder use this to split a stream.
    """
    offset = 0
    while offset < len(data):
        first = data[offset + 1]
        if first < 0x80:
            length, header = first, 2
        else:
            size = first & 0x7F
            length = int.from_bytes(data[offset + 2 : offset + 2 + size], "big")
            header = 2 + size
        yield offset, offset + header + length
        offset += header + length
