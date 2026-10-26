"""
pycrate: compiles the ASN.1 module into a generated Python module.
"""

import importlib.util
import tempfile
from collections.abc import Callable
from pathlib import Path

from data import SPEC, spans
from pycrate_asn1c.asnproc import (
    PycrateGenerator,
    compile_text,
    generate_modules,
)


def _generated_module() -> object:
    compile_text(SPEC)
    path = Path(tempfile.mkdtemp()) / "bench_gen.py"
    generate_modules(PycrateGenerator, str(path))
    spec = importlib.util.spec_from_file_location("bench_gen", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Bench  # type: ignore[attr-defined]


def setup(workload: str) -> Callable[[bytes], int]:
    """
    Return the decode function for *workload*.
    """
    bench = _generated_module()
    record_type = bench.Record  # type: ignore[attr-defined]
    file_type = bench.File  # type: ignore[attr-defined]

    def stream(data: bytes) -> int:
        total = 0
        for start, end in spans(data):
            record_type.from_ber(data[start:end])
            total += record_type.get_val()["duration"]
        return total

    def full(data: bytes) -> int:
        file_type.from_ber(data)
        return sum(record["duration"] for record in file_type.get_val())

    def partial(data: bytes) -> int:
        file_type.from_ber(data)
        return int(file_type.get_val()[-1]["duration"])

    def indexed(data: bytes) -> int:
        file_type.from_ber(data)
        document = file_type.get_val()
        return sum(
            document[index]["duration"] for index in range(len(document))
        )

    return {
        "stream": stream,
        "full": full,
        "partial": partial,
        "indexed": indexed,
    }[workload]
