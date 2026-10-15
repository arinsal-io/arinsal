# NOTES: memory footprint (stream `footprint`)

Workload: `bench/rest` as `MIX_ENV=prod mix run --no-halt` (same as `NOTES-baseline.md`), macOS arm64.
All numbers are `phys_footprint` read through `proc_pid_rusage` (the value `footprint -p` prints as
"Footprint"). The machine was heavily shared during this work (load average above 100 at times), so
use single numbers for relative comparison only. `footprint(1)` and `vmmap(1)` started hanging
after an `lldb` attach attempt, which is why the second half uses `proc_pid_rusage`
(`pf.py`-style helper, not committed).

## Result

| | ERTS | Arinsal before | Arinsal after |
|---|---|---|---|
| footprint, 0 tenants | 87.9 MB | 324.3 MB | 174.2 MB |
| footprint, 1000 tenants | 250.8 MB | 654.3 MB | 403.2 MB |
| (1000 tenants - 0) / 1000 | 163 KB | 330 KB | 229 KB |
| footprint, 100 tenants | 104.8 MB | 446.9 MB | 266.3 MB |
| (1000 - 100 tenants) / 900 | 162 KB | 230 KB | 152 KB |
| 100 tenants, after 20 s load | 132.0 MB | 501.6 MB | 299.8 MB |
| growth during the load run | +27 MB | +55 MB | +34 MB |

The per-tenant delta depends on the baseline it is taken from. With the old build the first requests
also load more modules (Bandit, Plug paths), and malloc reuses memory freed at boot for tenant
allocations, so the 0 -> 1000 delta is not a clean marginal cost and the 100 -> 1000 delta of the new
build (152 KB) is probably too low for the same reason. The live-bytes tables below are the reliable
per-tenant numbers: Arinsal spends about 230 KB of live malloc and carrier bytes per tenant (232 MB over 1000 tenants in
`malloc_history`) against ERTS 163 KB, and the two commits do not touch it. Treat the per-tenant gap as open.

Two commits on `poc/mt-footprint`:

1. `perf(vm): drop parsed code and per-instruction metadata kept after load`
2. `perf(loader): store source locations as runs instead of one entry per instruction`

Idle 0-tenant footprint 324 MB -> 174 MB. Nothing else changed in behavior: stack traces still show
file and line, `module_info(attributes|compile|md5)` and `erlang:get_debug_info/1` read the same data.
Tests: `cargo test -p arinsal-loader` (incl. the new `line_table_tests` and the OTP/Elixir corpus),
a stack-trace smoke test through `elixir` on Arinsal, and the bench app itself.

## How the breakdown was made

`erlang:memory()` on Arinsal does not cover Rust-side allocations (28 MB at 0 tenants while the process
had 354 MB), so it cannot be used. Instead:

- `footprint -p` categories: Arinsal's Rust code allocates through the system `malloc` (no
  `#[global_allocator]`), so most of the process shows as `MALLOC_TINY/SMALL/MEDIUM`. ERTS-style
  `arinsal-alloc` carriers (process heaps, binaries) show as `VM_ALLOCATE`.
- `MallocStackLogging=1` plus `malloc_history <pid> -callTree -ignoreThreads` gives live bytes per call
  path with Rust symbols. That is where the Arinsal file:line below come from.

## Base footprint (0 tenants), Arinsal before, live malloc bytes per call path (394 modules loaded)

| bytes | where | what |
|---|---|---|
| 95 MB | `crates/vm/src/load.rs` `CodeMeta::from_beam` (`beam.clone()`) | full clone of the parsed BEAM file (every instruction's `Vec<Operand>`) kept for the life of the module. Only attributes, compile info and the `DbgB` chunk are read later |
| 21.6 MB | `crates/loader/src/lib.rs` `Module.types` | per-instruction `Vec<Vec<(usize, BeamType)>>`, never read |
| 28.9 MB | `Module.lines` | `Option<(String, u64)>` per instruction |
| 14.2 MB | same, 639k `String` clones | one owned filename per instruction |
| 17.1 MB | `Module.line_terms` | per-instruction cached filename term |
| 23 MB | `Module.code` | compact instructions (24 B each); the interpreter needs them |
| 24 MB | `CodeMemory::new` mmap | JIT code, same job as ERTS |
| ~45 MB | `crates/vm/src/beamasm_integration.rs:2090-2160`, `native_bridge.rs:132,725` | per-function bookkeeping (see plan) |
| 9.3 MB | `crates/term/src/atom.rs` atom table | mmap |

Fixed: the first five rows (about 170 MB retained plus the transient clone). Left as is: `Module.code`
(interpreter), JIT code, atom table.

## Per-tenant (1000 tenants), Arinsal before, live malloc bytes per call path

Per tenant: 6 processes, 1 ETS table with 200 `{Id, Map}` objects, a few Registry entries.

| bytes (1000 tenants) | where | per unit |
|---|---|---|
| 61 MB | `crates/ets/src/lib.rs:979` `StoredTerm::copy_heap_for_table` (object words) | 305 B per object, ERTS stores about the same words |
| 37 MB | `Table::insert` -> `put_hashed` (`lib.rs:2566`) | 183 B per entry for index structure, ERTS about 40 B |
| 16 MB | `crates/vm/src/proc_create.rs:1274` `allocate_cold` | 2.9 KB `ProcessCold` per process, allocated for nearly every process here |
| 10 MB | `signals.rs:1049` process insert / spawn bookkeeping | 450 B per process |
| 7 MB | `Registry::create` (`ets/src/lib.rs:4793,4806`) | 5.8 KB per table (lock array and bucket map), ERTS similar |
| 32+16+6 MB | `arinsal-alloc` carriers (`mseg.rs:296`) | process heap carriers, virtual until touched, comparable to ERTS `processes` |

`process_info(memory)` of each tenant process and `ets:info(memory)` match ERTS word for word
(heap sizes 233 and 4185 words, `ets` 74.7 MB vs 76.7 MB), so the process heap and the stored term
words are not the gap. The gap is the Rust-side structure around them:

- ETS index: `HashStorage.buckets: HashMap<u64, Vec<StoredTerm>>` (`ets/src/lib.rs:1683-1691`). `StoredTerm`
  (`lib.rs:884-899`) is about 152 B: `inline_pair`, two `Vec`s and a counter for compressed tables
  (unused for plain tables), `order`, `group_order`, `hvalue`, `db_size_words`. Every entry costs one
  `Vec` allocation of that size plus a hashbrown slot.
- Process: `ProcessCold` (`proc_create.rs:701-`) holds roughly 90 fields inline (links, monitors,
  aliases, dirty-job state, native resume state, trace state), so one cold part is 2.9 KB.

The two commits do not change these rows; the staged plan below does.

## After-load footprint (100 tenants, 20 s of load)

The 450 MB vs 140 MB in `NOTES-baseline.md` is mostly the base gap, not memory kept by the load:
the same run grows by +27 MB on ERTS, +55 MB on the old Arinsal build and +34 MB on the new one.
What is left of that growth is `MALLOC_LARGE` (a 33 MB dirty region plus 8 MB "empty") and freed medium
blocks the system `malloc` keeps. The live malloc heap after load is small (largest live node 4.8 MB), so
it is freed memory that macOS `malloc` did not give back, unlike ERTS carriers (mseg cache decay). The only
API that returns it is `malloc_zone_pressure_relief`, which needs an `extern "C"` declaration and an
`unsafe` call. That raises the `unsafe` census maximum, which `tools/unsafe_census/README.md` says not to
do, so it is not in this branch. I did not find which allocation site makes the large blocks:
`lldb`-based inspection hung the host tools (see top of this file).

Freed transient memory also shows up at 0 tenants: about 90 MB of the 174 MB is "reclaimable" in
`footprint` (freed by Rust, not returned) after the parse and prepare steps of 394 module loads.

## Staged plan (not done)

1. Free-memory return (after-load gap, and the freed transient of boot, about 90 MB reclaimable at 0
   tenants): decide whether one audited `unsafe` call to `malloc_zone_pressure_relief` (macOS only,
   throttled, called after module loads and from scheduler idle) is acceptable, or route the large
   Rust buffers through `arinsal-alloc`. Needs the census maximum for one crate to move, and the idle
   hook belongs to the idle-CPU stream.
2. JIT bookkeeping (about 45 MB at 394 modules, 1.9 KB per function): `NativeFunction` with its
   `line_table: Vec<NativeLine>` is built three times: `CompiledVersion.native_functions`
   (`beamasm_integration.rs:2090`), the global registry (`native_bridge.rs:725`) and `FunctionRange`
   (`native_bridge.rs:132`, `line_addrs` and `locs` arrays). Each `NativeLine` also allocates its own
   `Arc<str>` filename (`beamasm_integration.rs:2078`). Keep one copy keyed by module version and intern
   filenames per module.
3. ETS entry: make `StoredTerm` about 80 B by moving the compressed-table fields behind one
   `Option<Box<_>>` (35 uses in `ets/src/lib.rs`), and replace `HashMap<u64, Vec<StoredTerm>>` with
   ERTS-style chained buckets (`Box<node>` with `next`, `hvalue`, object words in the same
   allocation). Target about 60 B per entry instead of 183 B: 25 KB per tenant here.
4. `ProcessCold`: split into a small always-present part (native wait/resume flags, group leader,
   links) and a boxed rare part (trace, dirty, hibernate, save_calls). Target 300 B per process:
   about 15 KB per tenant here.
5. `Module.code` plus `lines` still dominate module memory. Dropping the interpreter copy for modules
   the JIT compiled needs the interpreter fallbacks audited first (`interp.rs`, `funs.rs`, NIF stubs).

## Reproducing

```sh
export PATH=/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
export CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-footprint
cargo build --release -p arinsal-cli
mkdir -p $CARGO_TARGET_DIR/release/arinsal-erl-shim
ln -sf $CARGO_TARGET_DIR/release/arinsal $CARGO_TARGET_DIR/release/arinsal-erl-shim/erl
# footprint of one run
PATH=$CARGO_TARGET_DIR/release/arinsal-erl-shim:$PATH MIX_ENV=prod RT_PORT=4400 RT_TENANTS=0 \
  mix run --no-halt   # in poc/multitenancy/bench/rest; then: footprint -p <pid>
# call tree of live allocations
MallocStackLogging=1 <same command>; malloc_history <pid> -callTree -ignoreThreads
cargo test --release -p arinsal-loader
```
