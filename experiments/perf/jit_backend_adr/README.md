# Baseline backend probes

## Questions

How much startup work does OTP actually load? How much of the current
Cranelift cost survives fastalloc and reusable compilation contexts? Can the
pinned Cranelift encoder or Rust object stencils support a cheap baseline?
These are research probes, not BEAM compilers. The isolated `jit_copy/` is a
copy of `crates/jit` with flags, context reuse, and code-byte counters; no
production crate is changed.

## Commands

From the repository root, with OTP 29.1.1 and Elixir 1.20.4-otp-29 on `PATH`:

```sh
mkdir -p tmp/jit_backend_adr
cargo build --release --manifest-path experiments/perf/jit_backend_adr/Cargo.toml --bins
python3 experiments/perf/jit_backend_adr/measure_boot.py
python3 experiments/perf/jit_backend_adr/measure_otp.py
python3 experiments/perf/jit_backend_adr/measure_real.py
experiments/perf/jit_backend_adr/target/release/thread_probe
experiments/perf/jit_backend_adr/target/release/encoder_x64
experiments/perf/jit_backend_adr/target/release/stencil
experiments/perf/jit_backend_adr/target/release/cl_blocks
```

The model comparison uses the copied `pf_exec` project. This copy adds
`ADR_CL_FAST=1` to select `opt_level=none` plus `single_pass` register
allocation.

```sh
CARGO_TARGET_DIR="$PWD/experiments/perf/jit_backend_adr/target" \
  cargo build --release --manifest-path experiments/perf/pf_exec/Cargo.toml --bin pf-exec-probe
python3 experiments/perf/jit_backend_adr/measure_model.py
experiments/perf/jit_backend_adr/target/release/pf-exec-probe --compile-scale
```

`measure_commands.py` and `measure_arinsal.py` need the demo dependencies and
build products. Keep those generated files under the ignored `tmp/` directory:

```sh
cd examples/arinsal_demo
MIX_DEPS_PATH="$PWD/../../tmp/jit_backend_adr/deps" \
  MIX_BUILD_PATH="$PWD/../../tmp/jit_backend_adr/build_test" mix deps.get
cd ../..
python3 experiments/perf/jit_backend_adr/measure_commands.py
cargo build --release -p arinsal-cli
mkdir -p tmp/jit_backend_adr/shim
ln -sf "$PWD/target/release/arinsal" tmp/jit_backend_adr/shim/erl
python3 experiments/perf/jit_backend_adr/measure_arinsal.py
```

`measure_arinsal.py` runs every Arinsal invocation under `timeout 60`.
`measure_otp.py` runs one-shot `erl -noshell -eval '..., halt().'` nodes only.
Its `+JDdump` pass writes `.asm` files under `tmp/jit_backend_adr/`; load-time
medians exclude that pass because dump I/O dominates it.

For loaded module and call-count projections, run `loaded.exs` or
`trace_loaded.exs` with arguments `ok`, `test`, or `compile`, redirect output
to `tmp/`, then pipe it to `jit-backend-adr` and `hot_stats`. The Mix cases
need `MIX_ENV=test` or `dev`, `MIX_DEPS_PATH`, and `MIX_BUILD_PATH` as above.
`trace_loaded.exs` installs OTP's `call_count` on existing and future modules
before running the task. Function-entry counts do not include loop backedges.

## Numbers

Apple Silicon, Rust 1.98.1, Cranelift 0.136.1. Five-run medians unless stated.
The host is shared; small differences are not decision-grade.

| Probe | Result |
| --- | ---: |
| OTP boot, external wall | 176.4 and 180.4 ms in two five-run passes; 108 modules, about 242,526 resolved ops including preloaded reference beams |
| `elixir -e ':ok'` OTP / Arinsal current / Arinsal interpreter wall | 319.9 / 504.4 / 488.6 ms |
| Demo `mix test` OTP / Arinsal current / Arinsal interpreter wall | 569.2 / 5,474.3 / 4,959.6 ms; 11 passed |
| Demo `mix compile --force` OTP / Arinsal current / Arinsal interpreter wall | 869.2 / 7,724.0 / 6,772.2 ms; 12 files |
| OTP boot, BeamAsm text reconstructed from `+JDdump` | about 3,671,000 B, or 15.1 B/resolved op; alignment varies by a few hundred bytes |
| Real accepted JIT functions, 532-file OTP/Elixir corpus | 1,943 functions, 19,148 ops |
| Cranelift default compile / code | 645,795 us; 33,726 us/1k accepted ops; 1,372,920 B |
| Cranelift `single_pass` compile / code | 503,289 us; 26,284 us/1k accepted ops; 2,775,720 B |
| Default with reused main `Context` and `FunctionBuilderContext` | 634,778 us; 1,372,920 B |
| Fastalloc plus reuse | 468,416 us; 2,775,720 B |
| One versus two off-caller compile workers, no dependency retries | 856 versus 438 ms, with 32 versus 43 us enqueue median |
| Model 999 adds plus return, Cranelift / own AArch64 emitter | 4,821 / 14 us; 11,996 / 12,024 B |
| Cranelift one block per operation / one block for 999 adds | 4,103 / 2,921 us; 11,996 / 11,996 B |
| Same block comparison with Fastalloc | 3,502 / 2,314 us; 20,060 / 12,056 B |
| Public Cranelift x64 encoder, 999 adds plus return | 7.6 us; 5,995 B; encoding only on the AArch64 host |
| Rust Mach-O stencil, copy and patch 1,000 stencils | 28.8 us; 12 B/stencil; patched function returns 12 for input 5 |

Fastalloc model runtime median ns per unit, default → fast: tail
0.566 → 2.141; list 4.795 → 4.816; fib 8.309 → 9.761; tuple
3.832 → 3.833; binary 2.382 → 2.607. The model omits BEAM terms,
GC, reductions, exceptions, tracing, and code generations.

The x64 encoder probe proves that `cranelift-assembler-x64` 0.136.1 is
callable directly; it does not provide an AArch64 encoder or runnable BEAM
code. The stencil probe compiles `stencil_source.rs` with pinned `rustc` at
build time, parses a Mach-O object with `object` 0.39.1, finds one external
helper relocation, patches a `MOVZ` immediate, and executes the simple
relocation-free function under macOS `MAP_JIT` write protection. It does not
resolve that helper relocation, join stencils into a control-flow graph, or
preserve BEAM state. Rust 1.98.1 rejects `extern "ghccc"` (`E0703`), so a
CPython-style calling convention is not available from stable Rust here.
