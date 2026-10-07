# Execution engine probe

## Question

How much of the dispatch floor can a loader fusion, a Cranelift lowering, and a
single-pass AArch64 template emitter remove? The probe uses five **models** of
the BEAM kernels in `kernels.erl`. It has integer registers, explicit branches,
calls and returns, and helpers for list, tuple, and binary operations. It does
not model OTP terms, garbage collection, reductions, exceptions, or code
loading. Its native timings are therefore mechanism tests, not predictions for
the full Arinsal VM.

## Run

```sh
python3 experiments/perf/pf_exec/measure.py --runs 5
CARGO_TARGET_DIR=target cargo run --manifest-path experiments/perf/pf_exec/Cargo.toml --release --bin pf-exec-probe -- 200000
CARGO_TARGET_DIR=target cargo run --manifest-path experiments/perf/pf_exec/Cargo.toml --release --bin pf-exec-probe -- --compile-scale
OTP_LIB="${ARINSAL_OTP_ROOT:-$(erl -noshell -eval 'io:format("~s",[code:root_dir()]),halt().')}/lib"
ELIXIR_LIB="${ARINSAL_ELIXIR_ROOT:-$(elixir -e 'IO.write(Path.dirname(Path.dirname(:code.lib_dir(:elixir))))')}/lib"
CARGO_TARGET_DIR=target cargo run --manifest-path experiments/perf/pf_exec/Cargo.toml --release --bin coverage -- "$OTP_LIB" "$ELIXIR_LIB"
```

Build `target/release/arinsal` with `cargo build --release -p arinsal-cli`
before `measure.py`. All Arinsal invocations in that script use `timeout 300`.
For dynamic BEAM operation counts, use:

```sh
cargo build --release -p arinsal-cli --features instr-count
timeout 300 env ARINSAL_JIT=0 ARINSAL_STATS=1 \
  target/release/arinsal eval --schedulers 1 -pa tmp/pf_exec kernels tail 200000
```

Rebuild without `instr-count` for timing.
The five Erlang kernels return the same integer on erts and Arinsal. The Go
versions implement analogous algorithms with Go arrays and slices; they are
useful gate context, but their allocation semantics differ.

`pf-exec-probe` applies one general load-time decrement/increment/backedge
fusion. Cranelift lowers simple operations and emits calls to `slow` for every
complex operation in its model. The AArch64 emitter uses the same helper ABI;
it emits raw instructions into a private `MAP_JIT` mapping. It is an
experimental backend and is **not** wired into Arinsal.

## Results

Apple Silicon, Rust 1.98.1, OTP 29.1.1. Below are representative medians from three
back-to-back runs at N=200,000; fib uses fib(22). Unit means one recursive
fib call, one list element, or one tail/tuple/binary loop step. The binary
model processes 4N bytes. Timings exclude compilation and input cloning.

| Kernel | Rust match | fused | Cranelift | AArch64 | Cranelift/AArch64 code bytes |
|---|---:|---:|---:|---:|---:|
| tail, ns/step | 5.18 | 3.57 | 0.584 | 0.412 | 44 / 76 |
| list map/fold, ns/element | 9.60 | 9.79 | 4.95 | 4.26 | 168 / 168 |
| fib, ns/call | 16.20 | 16.19 | 8.71 | 7.45 | 348 / 308 |
| tuple, ns/step | 7.04 | 6.64 | 3.94 | 3.67 | 148 / 152 |
| binary, ns/byte | 8.01 | 7.96 | 2.42 | 2.44 | 128 / 128 |

The 1,000-operation straight-line compile probe (999 adds and one return),
five runs, gave Cranelift **4,412 us** and **11,996 bytes**, versus AArch64
**14 us** and **12,024 bytes**. The small function timings include compiler
setup and are printed by the program; extrapolating them to 1,000 operations
would be misleading. AArch64 generation is 315 times faster on this one
straight-line mix, but it handles only the model's operation set. No backend
replacement is proposed from this result.

The real `.beam` scan loaded all **1,356 OTP** and **578 Elixir** files. The
current JIT compiled 4,940 / 103,394 OTP functions and 1,201 / 18,300 Elixir
functions, and compiled every function in zero modules from either corpus.
Successful current-JIT compilations took 34,076 us/1k accepted OTP operations
and 32,099 us/1k accepted Elixir operations; failed attempts and engine setup
are excluded. Most accepted functions are small, so these figures include
substantial per-function overhead.
The model compiler accepts its 16 source operation variants and two fusion-only variants; it is not an executable
BEAM compiler. Its hypothetical generic helper path would make all loaded
modules structurally lowerable, but actual BEAM semantic coverage is untested.

`xctrace` was unavailable because Instruments could not create its cache under
`com.apple.dt.InstrumentsCLI`; no retired CPU instruction count is claimed.
The real VM's `instr-count` feature supplies executed **BEAM operation
equivalent** counts, reported in `docs/perf/execution-survey.md`.
