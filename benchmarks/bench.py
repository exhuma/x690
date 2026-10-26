"""
Run one benchmark case and print the result as one JSON line.

Usage: python benchmarks/bench.py LIBRARY WORKLOAD RECORDS INPUT_FILE
       [MEMORY_LIMIT_BYTES]

The peak memory is measured after the input is loaded and the library is set
up, so it shows what decoding adds on top of the input. On Linux the kernel's
peak counter is reset at that point; elsewhere the growth of ``ru_maxrss`` is
used, which can under-report when setup temporarily used more memory than
decoding.
"""

import gc
import importlib
import json
import resource
import sys
import time
from pathlib import Path

from data import expected

PROC_STATUS = Path("/proc/self/status")
PROC_CLEAR_REFS = Path("/proc/self/clear_refs")


def _proc_bytes(key: str) -> int:
    for line in PROC_STATUS.read_text().splitlines():
        if line.startswith(key):
            return int(line.split()[1]) * 1024
    raise KeyError(key)


def _maxrss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes, macOS bytes.
    return value * 1024 if sys.platform.startswith("linux") else value


class PeakMemory:
    """
    Measures the peak memory used after :meth:`start`.
    """

    def __init__(self) -> None:
        self.method = "proc" if PROC_CLEAR_REFS.exists() else "ru_maxrss"
        self._base = 0

    def start(self) -> None:
        """
        Remember the current memory use as the baseline.
        """
        if self.method == "proc":
            PROC_CLEAR_REFS.write_text("5")
            self._base = _proc_bytes("VmRSS")
        else:
            self._base = _maxrss_bytes()

    def peak(self) -> int:
        """
        Return the peak memory above the baseline, in bytes.
        """
        if self.method == "proc":
            return _proc_bytes("VmHWM") - self._base
        return max(0, _maxrss_bytes() - self._base)


def run(
    library: str,
    workload: str,
    records: int,
    input_path: Path,
    memory_limit: int | None,
) -> dict[str, object]:
    """
    Decode the input for one case and return time, memory and correctness.
    """
    if memory_limit:
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
    data = input_path.read_bytes()
    runner = importlib.import_module(f"runners.run_{library}")
    decode = runner.setup(workload)
    memory = PeakMemory()
    gc.collect()
    memory.start()
    result: dict[str, object] = {
        "library": library,
        "workload": workload,
        "records": records,
        "input_bytes": len(data),
        "memory_method": memory.method,
    }
    try:
        start = time.perf_counter()
        value = decode(data)
        result["seconds"] = time.perf_counter() - start
        result["peak_bytes"] = memory.peak()
        result["correct"] = value == expected(workload, records)
    except MemoryError:
        result["error"] = "out of memory"
    return result


if __name__ == "__main__":
    limit = int(sys.argv[5]) if len(sys.argv) > 5 else None
    case = run(
        sys.argv[1], sys.argv[2], int(sys.argv[3]), Path(sys.argv[4]), limit
    )
    print(json.dumps(case))
