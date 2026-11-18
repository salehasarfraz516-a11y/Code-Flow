# CodeFlow

CodeFlow is a lab-only Python taint tracker. It parses Python source with `ast`,
marks untrusted values, follows assignments, performs a one-level
cross-function analysis, and reports flows to dangerous sinks.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Run

```bash
python3 codeflow.py lab/vulnerable_demo.py -o lab/vulnerable_report.txt
python3 codeflow.py lab/safe_demo.py -o lab/safe_report.txt
python3 codeflow.py lab/vulnerable_demo.py --format json -o lab/vulnerable_report.json
python3 codeflow.py lab/vulnerable_demo.py --print-functions
```

Exit status is `1` when flows are found and `0` otherwise. Parse errors and
missing files use exit status `2`.

## Tests

```bash
python3 -m unittest -v
```

## Source table

- `input()` and `raw_input()`
- `open(...)` (used when reading files)
- `sys.stdin.read()`, `readline()`, and `readlines()`
- Flask-style `request.args`, `request.form`, `request.values`, `request.json`,
  `request.data`, and `request.cookies`
- `os.environ` and common `environ` attributes

## Sink table

| Kind | Functions |
|---|---|
| Code execution | `eval`, `exec`, `compile` |
| Command execution | `os.system`, `os.popen`, `subprocess.run`, `subprocess.call`, `subprocess.Popen`, `subprocess.check_call`, `subprocess.check_output` |
| SQL query | `cursor.execute`, `cursor.executemany`, `connection.execute`, `connection.executemany` |

## Analysis scope

CodeFlow performs intra-function propagation and follows tainted arguments into
one level of called user-defined functions. It reports source and sink line
numbers and a path. It is an educational heuristic, not a replacement for a
production static analyzer.

Only analyze code you own or have written permission to review.
