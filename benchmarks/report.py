"""
Render benchmark reports as Markdown tables.

Usage: python benchmarks/report.py REPORT.json [REPORT.json ...]

With several reports, every cell lists the results in the order the reports
are given, separated by an arrow, for example to compare runs before and
after a change.
"""

import json
import sys
from pathlib import Path


def cell(result: dict[str, object] | None) -> str:
    """
    Format one result as "seconds / megabytes", or why there is none.
    """
    if result is None:
        return "–"
    if "skipped" in result:
        return "skipped"
    if "error" in result:
        error = str(result["error"])
        return "out of memory" if "memory" in error.lower() else error
    if not result.get("correct"):
        return "wrong result"
    seconds = float(str(result["seconds"]))
    megabytes = int(str(result["peak_bytes"])) / 1e6
    return f"{seconds:.2f} s / {megabytes:,.0f} MB"


def _key(result: dict[str, object]) -> tuple[str, str, int]:
    return (
        str(result["library"]),
        str(result["workload"]),
        int(str(result["records"])),
    )


def render(reports: list[dict[str, object]]) -> str:
    """
    Return one Markdown table per workload for *reports*.
    """
    indexes = []
    order: list[tuple[str, str, int]] = []
    for report in reports:
        index = {}
        for result in report["results"]:  # type: ignore[attr-defined]
            key = _key(result)
            index[key] = result
            if key not in order:
                order.append(key)
        indexes.append(index)
    workloads = list(dict.fromkeys(key[1] for key in order))
    labels = " → ".join(
        str(report["machine"]["label"])  # type: ignore[index]
        for report in reports
    )
    lines = []
    for workload in workloads:
        lines += [
            f"### {workload}",
            "",
            f"| Library | Records | {labels} |",
            "|---|---:|---|",
        ]
        for library, name, records in order:
            if name != workload:
                continue
            key = (library, name, records)
            cells = " → ".join(cell(index.get(key)) for index in indexes)
            lines.append(f"| {library} | {records:,} | {cells} |")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    loaded = [json.loads(Path(name).read_text()) for name in sys.argv[1:]]
    print(render(loaded))
