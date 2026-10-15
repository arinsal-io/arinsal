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

## Chunk 2: ProcessCold (process side of the per-tenant gap)

Cause: `ProcessCold` (2840 B, `crates/vm/src/proc_create.rs`) was allocated by nearly every process.
Found by tagging `cold_mut` / `allocate_cold` with `#[track_caller]` and printing the caller of each
allocation (temporary, not committed), running bench/rest with 100 tenants and a 30000-process spawn
loop:

| trigger (before) | count in 100 tenants |
|---|---|
| `signals.rs` spawn with link: `links.insert(parent)` | 1072 of 1136 |
| `signals.rs` spawn with monitor: `monitored_by.insert` | 47 |
| first run of every process: `signal_probe` (`process.rs`) | 11 more, every process after the links are gone |
| native receive exit: `native_error_pc`, `native_wait`, `native_wait_timeout`, `native_wait_self` | every process that blocks |
| native resume/call state: `native_retry_site`, `native_continuation_resume`, `native_resume_live`, ... | every native trap |
| each received message: `prio_len` | every process that receives |

Fix: those small always-used fields moved from `ProcessCold` to `Process` (about 330 B, empty trees
do not allocate), same names and types, so behavior is unchanged:

- supervision: `links`, `prio_links`, `monitors`, `prio_monitors`, `monitored_by`, `unlinking`
- receive: `signal_probe`, `prio_len`, `priority_resume_cursor`, `native_wait`, `native_wait_timeout`,
  `native_wait_self`, `native_signal_fetch`, `native_reserve_fetch`
- native call state: `native_error_pc`, `native_call_pc`, `native_apply`, `native_retry`,
  `native_retry_site`, `native_resume_after_call`, `native_continuation_resume`, `native_resume_live`,
  `native_transfer`

`Process::exit` used to return when `cold` was `None`; it now always runs the link and monitor
notification from the process fields and only skips the port and NIF monitors when there is no cold part.
Remaining cold triggers in the same runs: trace and dirty NIF state, `max_heap`, `initial_bif`,
`process_flag` paths, about 1% of processes.

Measured (idle process blocked in `receive`, linked to its parent, 30000 of them, `spawn_link` from the
node's repl process, footprint delta per process, three runs for the new build):

| | bytes per process |
|---|---|
| ERTS | 2649 |
| Arinsal before | 7291 |
| Arinsal after | 4145 to 4247 |

That is 3.1 KB per process, about 6 processes per tenant in bench/rest: about 19 KB of the 230 KB
per tenant. The whole-node numbers (1000 tenants) varied by 25 MB between identical runs on this shared
host (380 to 424 MB), so they cannot show a 19 MB change. `malloc_history`, the method used for the live
byte tables above, hung host-wide after the `lldb` attempt and could not be repeated.

Tests: `process_differential` (17, includes monitor and link scenarios against OTP), `link_exit_race`,
`demonitor_flush_trap`, `process_info_self_light` (3) and the vm lib tests for `receive`, `signals`,
`proc_create`.

## Chunk 3: the remaining 4.2 KB per idle process

Method: temporary counting `#[global_allocator]` (size-bucket counters, dumped on request) and a
sampling backtrace table (`backtrace(3)` into a static table, resolved with `atos`) around the
30000-process spawn_link loop. Neither is committed. Per-process cost after chunk 2, fun-argument spawn:

| item | bytes | where |
|---|---|---|
| process heap (233 words) in `arinsal-alloc` carriers | about 1750 | same as ERTS |
| scheduler `Arc<sched::Process<vm::Process>>`, one allocation | 1536 | `crates/sched/src/lib.rs:1152` (`Process` 1312 B in `crates/vm/src/proc_create.rs:122`, scheduler fields 264 B) |
| `HeapOwners` box, created when the spawn arguments hold a fun (`retain_fun`) | 248 | `crates/term/src/heap.rs:878` |
| scheduler input queue `Arc` | 152 | `sched/src/lib.rs:1168` (`input: Arc::default()`) |
| link node of `links: BTreeSet<Pid>` | 104 | `signals.rs:1040` |
| persistent-term accounting `Arc<ProcessAccount>` | 64 | `pterm/src/lib.rs:410` |
| fun reference vectors (`retain_fun`, argument list) | 32 + 32 | `heap.rs:1698`, `signals.rs:562` |
| `exit_flags` Arc, slot box, misc | 24 + 8 + 8 | `sched/src/lib.rs:1168,1180` |

ERTS spends about 780 B outside the heap (PCB, 2649 B total); Arinsal about 2.3 KB. The gap is the
size of `Process` (1312 B) plus the scheduler wrapper (264 B): ERTS keeps its x registers, most of the
JIT header and the trace state elsewhere or not at all.

Fixed: `ProcessHeap::set_min_bin_vheap_size` created the 248 B owner box on every spawn just to store
the default value. It now leaves the box absent for the default (absent reports the same values).
That saves the box for every spawn whose arguments hold no fun, funs still create it through
`retain_fun`. Measured with `spawn_link(:timer, :sleep, [:infinity])` (no fun): 4009 to 4117 B per
process, against 4145 to 4247 B in chunk 2 with a fun, ERTS 2698 B. The difference is within
the noise of this host, so treat it as a small, not a measured, win.

Staged (not done, ordered by size):
1. Shrink `Process` (1312 B). Candidates by size: `dictionary` 80 B inline (box it, but OTP processes
   nearly all have one), `stats` 72, `x` 72 (`ArgRegs` inline 6 + boxed tail), 6 supervision trees 144,
   the native resume and wait state I moved in chunk 2 (about 190 B, pack into one small struct and
   narrow `usize` to `u32`), `seq_trace_*` 45 B, `apply_inline` 24 B. Realistic: 300 to 400 B.
2. `HeapOwners` 248 B -> about 160 B by moving the four `old_*` vectors (96 B) behind an
   `Option<Box<_>>` (27 sites in `term/src/gc.rs` and `heap.rs`). Needed for every fun spawn, and
   OTP's `proc_lib` spawns always pass a fun.
3. Scheduler side (`sched/src/lib.rs:1152-1180`): `input` 152 B, `exit_flags` 24 B and the slot box 8 B
   are three more allocations per process; one `Arc` with the queue inline would save about 100 B.
   Not touched because the idle-CPU stream works in `crates/sched`.
4. `links: BTreeSet<Pid>` allocates a 104 B leaf for the first link. A one-element inline form
   (enum `One(Pid) | Many(BTreeSet)`) saves 104 B for the common single link of a supervised process.

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
4. Per-process remainder (4.2 KB vs ERTS 2.6 KB): 1.6 KB per process is still to find (initial heap
   carriers, `Process` struct size, registers).
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
