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

## Numbers (partial, not final)

One measurement was taken before the scope change; the rest is deferred to the follow-up task.
`mix run` (not a release), RT_TENANTS=1000, all tenants warmed, 20 s settle:

| runtime | footprint | idle CPU / min |
|---|---|---|
| Arinsal | 593 MB | 4040 ms |

No ERTS run under the same `mix run` setup was completed, so this is not yet comparable with
bench/RESULTS.md (ERTS release, 1k tenants: 292 MB, 340 ms/min). Idle CPU of 4 s/min on Arinsal is
high and needs a look (a timer or poller wakeup cost per tenant) before step 7. Load run with
loadgen.exs was not done.

The measurement script lives in the session scratchpad, not in the repo; it starts `mix run --no-halt`,
warms every tenant, then reads `footprint -p` and the `ps -o time=` delta over 60 s.

## Blockers

None found.
