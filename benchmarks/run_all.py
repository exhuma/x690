"""
Run the decode benchmark and write a JSON report.

Usage: python benchmarks/run_all.py [options]

Run ``python benchmarks/run_all.py --help`` for the options. Each case runs in
its own process. A library skips the larger sizes of a workload once one of
its runs fails or takes longer than ``--slow`` seconds.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from data import WORKLOADS, input_file
from report import render

LIBRARIES = ("x690", "asn1crypto", "asn1tools", "pycrate", "pyasn1")
PACKAGES = ("x690", "asn1crypto", "asn1tools", "pycrate", "pyasn1")
SIZES = (10_000, 100_000, 1_000_000)
HERE = Path(__file__).parent

#: Format version of the JSON report.
SCHEMA = 1


def parse_size(text: str) -> int:
    """
    Parse a byte size such as ``2G`` or ``512M``.
    """
    units = {"K": 1024, "M": 1024**2, "G": 1024**3}
    suffix = text[-1].upper()
    if suffix in units:
        return int(float(text[:-1]) * units[suffix])
    return int(text)


def arguments() -> argparse.Namespace:
    """
    Parse the command line.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--sizes",
        type=int,
        nargs="+",
        default=SIZES,
        help="record counts to run (default: %(default)s)",
    )
    parser.add_argument(
        "--libraries",
        nargs="+",
        default=LIBRARIES,
        choices=LIBRARIES,
        help="libraries to run (default: all)",
    )
    parser.add_argument(
        "--workloads",
        nargs="+",
        default=WORKLOADS,
        choices=WORKLOADS,
        help="workloads to run (default: all)",
    )
    parser.add_argument(
        "--memory-limit",
        type=parse_size,
        help="address-space limit per case, such as 2G (default: none)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="seconds before a case is stopped (default: %(default)s)",
    )
    parser.add_argument(
        "--slow",
        type=float,
        default=60,
        help="skip larger sizes after a case slower than this "
        "(default: %(default)s s)",
    )
    parser.add_argument(
        "--label",
        default="local",
        help="name of this machine in the report (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="report file (default: benchmarks/results/LABEL-DATE.json)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "x690-benchmark",
        help="where generated inputs are kept (default: %(default)s)",
    )
    return parser.parse_args()


def _cpu_model() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    if sys.platform == "darwin":
        output = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        if output.strip():
            return output.strip()
    return platform.processor() or platform.machine()


def machine(label: str) -> dict[str, object]:
    """
    Describe the machine without identifying it.
    """
    memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    return {
        "label": label,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "memory_bytes": memory,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
    }


def versions() -> dict[str, str | None]:
    """
    Return the installed version of every library under test.
    """
    found: dict[str, str | None] = {}
    for package in PACKAGES:
        try:
            found[package] = version(package)
        except PackageNotFoundError:
            found[package] = None
    return found


def commit() -> dict[str, object]:
    """
    Return the x690 commit the benchmark runs on.
    """

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            cwd=HERE,
            check=False,
        ).stdout.strip()

    return {
        "sha": git("rev-parse", "HEAD"),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
    }


def run_case(
    library: str,
    workload: str,
    records: int,
    options: argparse.Namespace,
) -> dict[str, object]:
    """
    Run one case in a new process and return its result.
    """
    path = input_file(options.cache_dir, workload, records)
    command = [
        sys.executable,
        str(HERE / "bench.py"),
        library,
        workload,
        str(records),
        str(path),
    ]
    if options.memory_limit:
        command.append(str(options.memory_limit))
    failed: dict[str, object] = {
        "library": library,
        "workload": workload,
        "records": records,
    }
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=options.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {**failed, "error": f"timeout after {options.timeout} s"}
    if not completed.stdout.strip():
        last_line = (completed.stderr.strip().splitlines() or ["crash"])[-1]
        return {**failed, "error": last_line[:200]}
    result: dict[str, object] = json.loads(completed.stdout)
    return result


def main() -> None:
    """
    Run all cases, print progress and write the report.
    """
    options = arguments()
    started = datetime.now(UTC)
    output = options.output or (
        HERE
        / "results"
        / f"{options.label}-{started.strftime('%Y%m%d-%H%M')}.json"
    )
    report: dict[str, object] = {
        "schema": SCHEMA,
        "started": started.isoformat(timespec="seconds"),
        "machine": machine(options.label),
        "versions": versions(),
        "x690_commit": commit(),
        "settings": {
            "sizes": list(options.sizes),
            "memory_limit_bytes": options.memory_limit,
            "timeout_seconds": options.timeout,
            "slow_seconds": options.slow,
        },
        "results": [],
    }
    results: list[dict[str, object]] = []
    report["results"] = results
    output.parent.mkdir(parents=True, exist_ok=True)
    for library in options.libraries:
        for workload in options.workloads:
            skip_reason = ""
            for records in sorted(options.sizes):
                if skip_reason:
                    result: dict[str, object] = {
                        "library": library,
                        "workload": workload,
                        "records": records,
                        "skipped": skip_reason,
                    }
                else:
                    result = run_case(library, workload, records, options)
                    if "error" in result:
                        skip_reason = "a smaller size failed"
                    elif float(str(result["seconds"])) > options.slow:
                        skip_reason = (
                            f"a smaller size took over {options.slow:g} s"
                        )
                results.append(result)
                print(json.dumps(result), file=sys.stderr, flush=True)
                output.write_text(json.dumps(report, indent=2) + "\n")
    report["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(render([report]))
    print(f"\nReport written to {output}", file=sys.stderr)


if __name__ == "__main__":
    main()
