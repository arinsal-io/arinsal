# Unsafe source census

From the repository root, run `mkdir -p tmp && python3 tools/unsafe_census/census.py --csv tmp/unsafe-sites.csv --json tmp/unsafe-summary.json`. The script uses only Python's standard library and scans `crates/**/*.rs`. It masks comments and string/character literals, then records each source-level `unsafe` keyword with file, line, syntactic kind, and one primary reason. Macro expansions and dependencies are outside scope. Classification is heuristic; the CSV is the audit ledger, and an API migration should inspect its rows. A site with several hazards is assigned one primary reason, so totals are additive rather than risk-weighted.

## Ratchet

`baseline.json` stores a maximum site count for every crate directory. `python3 tools/unsafe_census/census.py --check` exits 1 if any crate is above its maximum, if a crate directory is missing from the file, or if a baseline entry no longer has a directory. A count that falls stays green: the maximum is what blocks a later increase. `tools/check.sh` runs this check (about 4 seconds).

Crates whose maximum is 0 should also carry `#![forbid(unsafe_code)]` on `src/lib.rs` or `src/main.rs`. That attribute covers the library or binary, including unit tests and `include!`d code. Integration tests under `tests/` are separate crates; the ratchet still counts a source-level `unsafe` keyword there.

### Lowering the baseline after a cleanup

1. Run `python3 tools/unsafe_census/census.py` and read the `crates:` map. Crates omitted there have zero sites.
2. In `baseline.json`, set `max_sites` for each cleaned crate to its new count. Do not raise a maximum to make `--check` pass. Do not hide an operation inside a macro to shrink the count; the scanner does not see macro expansions, and the point of the ratchet is the source that reviewers read.
3. Add a new directory under `crates/` to `max_sites` (use 0 when it has no sites). Remove a key only after that directory is gone.
4. When a crate reaches 0, add `#![forbid(unsafe_code)]` to its crate root.
5. Run `python3 tools/unsafe_census/census.py --check`. It prints a `note:` line for every crate still under its maximum.
