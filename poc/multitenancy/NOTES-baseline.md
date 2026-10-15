# NOTES: step 0 baseline (stream `baseline`)

## Result

Both bench apps run unmodified as plain apps on Arinsal. No Arinsal change was needed.

## Build

```sh
export PATH=/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
cargo build --release -p arinsal-cli          # needs erl on PATH (crates/nif/build.rs queries the erl include dir); ~1m10s
mkdir -p $CARGO_TARGET_DIR/release/arinsal-erl-shim
ln -sf $CARGO_TARGET_DIR/release/arinsal $CARGO_TARGET_DIR/release/arinsal-erl-shim/erl
```

The shim is a symlink named `erl` to the `arinsal` binary (same as `Arinsal.Mix.install_erl_shim!`).
Put the shim dir first on `PATH`; `elixir` and `mix` then run on Arinsal
(`system_version`: `Erlang/OTP 29 [erts-17.1] [arinsal 0.0.1] ... [jit]`).
The process shows as `erl` in `ps`; its executable is `.../release/arinsal`.

## App A: bench/rest (Bandit + Plug + Jason + telemetry_poller)

Deps and compile with the Homebrew toolchain, then run with Arinsal selected:

```sh
cd poc/multitenancy/bench/rest
MIX_ENV=prod mix deps.get && MIX_ENV=prod mix compile
PATH=<shim dir>:$PATH MIX_ENV=prod RT_PORT=4400 RT_TENANTS=10 mix run --no-halt
```

Verified on Arinsal:
- `GET /ready` -> 200
- `GET /t/2/items/5` -> `{"id":5,"name":"item-5",...}`
- `POST /t/2/items` with JSON -> `{"id":201,...}`
- `POST /admin/suspend/2` -> `{"bytes":17117,"us":6970}`, then `GET /t/2/items/5` returns the same item (resume from snapshot)

The `mix compile` type warning in `lib/rt/host.ex:19` (`resume(id) && ...`) is from Elixir 1.20 and unrelated to Arinsal.

## App B: bench/phxn (Phoenix 1.8.15)

`ACCEPTORS=1 mix run bench.exs 5 true` on Arinsal printed `check: HTTP/1.1 200 OK`.
Output: 18 procs/project, 22 KB state/project, 260 KB unique code/project, tree start p50 0.45 ms (max 75 ms, first project).

## Numbers

Script: `bench/arinsal_baseline.py` (`all` runs the whole matrix, one runtime after the other).
Setup on both runtimes: `MIX_ENV=prod mix run --no-halt` in `bench/rest`, Homebrew OTP 29 / Elixir 1.20.4
first on PATH for ERTS, the `arinsal-erl-shim` dir first for Arinsal. macOS arm64, 12 cores, single run each.

Idle: every tenant warmed with one GET, 20 s settle, 60 s window. Footprint is `footprint -p` summed over
the node processes (ERTS: beam.smp + erl_child_setup; Arinsal: the one `arinsal` process).

| | ERTS | Arinsal | ratio |
|---|---|---|---|
| footprint, 0 tenants | 88.8 MB | 336.0 MB | 3.8x |
| footprint, 1000 tenants | 254.8 MB | 575.0 MB | 2.3x |
| per tenant (delta / 1000) | 166 KB | 239 KB | 1.4x |
| idle CPU, 0 tenants | 60 ms/min | 2010 ms/min | 34x |
| idle CPU, 1000 tenants | 110 ms/min | 2400 ms/min | 22x |
| idle CPU per tenant (delta / 1000) | 0.05 ms/min | 0.39 ms/min | 8x |
| ready (boot + 1000 tenants) | 0.5 s | 3.9 s | |

Load: RT_TENANTS=100, `elixir --erl "+S 4" loadgen.exs host PORT 100 64 20` on stock ERTS, 64 keep-alive
connections, 20 s, all tenants warmed first.

| | rps | p50 | p99 | p99.9 | footprint after |
|---|---|---|---|---|---|
| ERTS | 52,598 | 0.83 ms | 9.9 ms | 14.1 ms | 139.8 MB |
| Arinsal | 47,168 | 1.13 ms | 4.8 ms | 8.6 ms | 450.0 MB |

Remarks:
- The ERTS rps is well below RESULTS.md (115k, release with its own flags); here the Mix project is compiled
  from `mix run` and the machine had other load. The tail latency of ERTS is noisy. Use the rows for relative
  comparison only and repeat before quoting.
- Arinsal base footprint (336 MB at 0 tenants) is dominated by the runtime itself, not by tenants; the per-tenant
  delta is the number that matters for density.
- Arinsal idle CPU is high already with 0 tenants (2 s/min). Not investigated yet (out of scope for this chunk).
- Arinsal footprint after load (450 MB) is 3x ERTS for the same 100 tenants (ERTS 139.8 MB); not investigated.

## Blockers

None found.
