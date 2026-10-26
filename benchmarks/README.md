# Decode benchmark

Compares decode time and memory of x690 with
[pyasn1](https://github.com/pyasn1/pyasn1),
[asn1tools](https://github.com/eerimoq/asn1tools),
[asn1crypto](https://github.com/wbond/asn1crypto) and
[pycrate](https://github.com/pycrate-org/pycrate) on large BER data.

## Run

```console
$ uv run --group bench python benchmarks/run_all.py
```

This runs every library and workload at 10,000, 100,000 and 1,000,000 records,
prints Markdown tables and writes a JSON report to
`benchmarks/results/local-DATE.json`. Progress goes to standard error, one JSON
line per case. A full run takes from several minutes to over an hour, depending
on the machine.

Useful options (see `--help` for all):

- `--label NAME` names the machine in the report and the file name.
- `--sizes 10000 100000` runs only these record counts.
- `--libraries x690 asn1crypto` and `--workloads full indexed` narrow the run.
- `--memory-limit 2G` limits the address space of every case, to reproduce a
  small machine.
- `--timeout 600` stops a case after that many seconds, and `--slow 60` skips
  the larger sizes of a workload after a case slower than that.

The generated inputs are kept in the system's temporary directory
(`--cache-dir`), about 80 MB per 1,000,000 records and input shape.

To compare reports, for example before and after a change:

```console
$ uv run python benchmarks/report.py before.json after.json
```

Every cell then lists the results of the reports in order, separated by `→`.
The output starts with the machine, library versions, x690 commit and settings
of each report, so numbers are never read without their hardware.

## Data

Synthetic records shaped like charging data records (CDRs): integers, octet
strings and a nested list of three usage volumes, about 80 bytes per record.
`data.py` encodes them with its own small BER encoder, so the input does not
depend on any library under test. The ASN.1 module is `data.SPEC`.

All fields use universal tags, so every library decodes the same structure.
Real CDRs tag nearly every field with a context-specific tag, which x690
cannot resolve per structure yet (#6).

## Workloads

| Workload | Input | Access |
|---|---|---|
| `stream` | records one after another | every record, one at a time |
| `full` | one `SEQUENCE OF` all records | every record, by iteration |
| `partial` | one `SEQUENCE OF` all records | the last record only |
| `indexed` | one `SEQUENCE OF` all records | every record, by index |

Each run sums the `duration` field of the records it reads and checks the
result, so no library can skip work. Each library uses its usual API. For
`stream`, libraries without an offset-based decoder get each record from
`data.spans`; x690 uses the offsets `decode` returns.

## Measurements

Each case runs in its own process. The time covers decoding only: imports,
schema compilation and loading the input are excluded.

Memory is the peak resident memory on top of the loaded input. On Linux the
kernel's peak counter is reset just before decoding. Elsewhere the growth of
`ru_maxrss` is used, which can under-report when setup used more memory than
decoding; the report records the method per case (`memory_method`).

## Report format

The JSON report (`schema` 1) contains:

- `machine`: system, CPU model and count, total memory, Python version. It
  does not include the host name.
- `versions`: the installed version of every library.
- `x690_commit`: the commit the benchmark ran on, and whether tracked files
  had changes.
- `settings`: sizes, memory limit, timeout and slow threshold.
- `results`: one entry per case with `library`, `workload`, `records`,
  `input_bytes`, and either `seconds`, `peak_bytes` and `correct`, or
  `error`, or `skipped`.

## Results

`results/` holds the reports referenced in the documentation.
