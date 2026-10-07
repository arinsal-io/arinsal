# Data path probes

## ETS access flags

Question: what is the cost of reading table protection through `Table::info()`
versus the stored `TableOptions`? The kernel creates a 2,000-row set, then
performs 2,000 access checks, matching the `ETS lookup` scenario's table and
lookup counts. The code uses `black_box` to preserve both reads. It excludes VM
dispatch and term copy-out, so the ratio is a mechanism measurement only.

Command: `PF_ROWS=2000 cargo run --manifest-path experiments/perf/pf_data/Cargo.toml --release --bin pf-data-probe`

`PF_ROWS=500,2000,8000` with 2,000 checks produced 33.6–34.1,
129.3–132.0, and 506.2–519.1 ms for `info()`. Direct
`options.protection` took about 0.001 ms at every size. Quadrupling the row
count quadrupled old access-check time: it is a table scan. The compiler can
hoist the immutable direct flag load in this standalone loop, so its number is
a control showing no table scan, not a per-access latency estimate.

## List reversal allocation

Question: how much work comes from making a heap fragment per cons cell?
`src/bin/list_reverse.rs` builds a 10,000-element source list and compares the
old two-`Vec`/per-cons output loop with the new direct traversal and one output
reservation. Both use the Arinsal `FragmentingHeap` and return the same list
shape; the full differential test checks values and exceptions against erts.

Command: `cargo run --manifest-path experiments/perf/pf_data/Cargo.toml --release --bin list_reverse`

Three release runs per ten reversals: old 1.72–2.33 ms, new 0.40–0.43 ms.
This excludes VM dispatch and later GC; the full scenario improved about 58×.

## Map lookup and BIF body floors

`src/bin/map_get.rs` compares one million lookups on Arinsal's 10,000-key
persistent HAMT with a Rust `HashMap` using the same integer keys. Three runs:
26.56–27.19 ns versus 7.13–7.22 ns per lookup. Command:
`cargo run --manifest-path experiments/perf/pf_data/Cargo.toml --release --bin map_get`.

`src/bin/map_update.rs` compares 200,000 existing-key replacements on a
1,000-key Arinsal persistent HAMT with mutable Rust `HashMap` replacement.
Three runs: 68–113 ns and 8,528,112 Arinsal heap words versus 8.5–8.8 ns.
Command: `cargo run --manifest-path experiments/perf/pf_data/Cargo.toml --release --bin map_update`.
The editable control has no BEAM alias/escape proof, term tags, GC, or ETF
requirements. It is a mechanism floor, not a production speed claim.

`src/bin/bif_call.rs` calls `lists:reverse([], Tail)` directly through the
Arinsal BIF function pointer one million times. Three runs: 1.93–2.33 ms total
against a 0.33–0.72 ms value-only loop. Command:
`cargo run --manifest-path experiments/perf/pf_data/Cargo.toml --release --bin bif_call`.
The difference is an approximate 1–2 ns BIF body cost; it omits VM import and
argument handling.

## Full-VM outliers

`outliers.exs` is a small `mix run -e` driver for the six requested kernels.
For example, from `examples/arinsal_demo`:

`PF_CASE=ets PF_REPS=3 MIX_ENV=bench timeout 300 mix run --no-compile --no-deps-check -e 'Code.require_file("../../experiments/perf/pf_data/outliers.exs")'`

Use a `PATH` with `tmp/shim-release` at the front for Arinsal, and the normal
`PATH` for OTP 29.1.1. The elapsed values are nanoseconds for one scenario run;
the last value is nanoseconds per inner operation or input byte.

`scaling.exs` repeats the Base64, record, map-get, and Unicode kernels at
several sizes. `pf_call.erl`/`call.exs` compare a tail loop, a local call, and a
`call_ext` to the empty-list `lists:reverse/2` BIF. Compile the Erlang fixture
with `erlc +debug_info -o tmp/pf_data experiments/perf/pf_data/pf_call.erl`.
`beam_disasm:file/1` confirms that the BIF variant contains a `call_ext`.
