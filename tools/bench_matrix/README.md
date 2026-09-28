# Benchmark Matrix: erts vs Arinsal vs Go

This directory contains a standalone benchmark suite comparing identical workload kernels across:
1. **ERTS** (Erlang/OTP 29.1.1, erts-17.1)
2. **Arinsal** (default JIT/interpreter configuration)
3. **Arinsal** with `ARINSAL_BEAMASM=1`
4. **Go** (native `go build` release executable)

## Workload Kernels and Semantics

Each kernel is implemented with equivalent semantics across Erlang and Go:

1. **int loop sum**:
   - *Semantics*: Sums integers from 1 to 10,000,000 (10M) using 64-bit integers without overflow.
   - *Erlang*: Tail-recursive function accumulator loop.
   - *Go*: Standard `for` loop accumulating into `int64`.
   - *Expected Checksum*: `50000005000000`.

2. **fib(27) recursive calls**:
   - *Semantics*: Naive double-recursive Fibonacci calculation (`fib(N-1) + fib(N-2)`). Measures function call and recursion dispatch overhead across 635,621 recursive calls.
   - *Erlang*: Direct recursive pattern-matching function calls.
   - *Go*: Recursive function calls in Go.
   - *Expected Checksum*: `196418`.

3. **list build+map+fold 100k**:
   - *Semantics*: Build a sequence of 100,000 elements, map over each element adding 1 (allocating new list cells), then fold to compute the total sum.
   - *Erlang*: Standard immutable singly-linked list (`lists:seq`, `lists:map`, `lists:foldl`).
   - *Go*: Explicit heap-allocated singly-linked list of boxed nodes (`*ListNode`), not a contiguous slice, ensuring equivalent pointer-chasing and heap allocation behavior.
   - *Expected Checksum*: `5000150000`.

4. **tuple setelement loop**:
   - *Semantics*: 100,000 iterations updating element 2 of a 3-element tuple using `setelement/3` and summing the updated element.
   - *Erlang*: `setelement(2, Tuple, I)` creating updated tuple values.
   - *Go*: 3-element struct (`Tuple3{e1, e2, e3}`) copied by value on each step.
   - *Expected Checksum*: `5000050000`.

5. **binary byte scan 1 MiB**:
   - *Semantics*: Scan a 1 MiB binary payload (repeating pattern `<<1, 2, 3, 4>>`) byte-by-byte, counting occurrences of byte value `2`.
   - *Erlang*: Binary pattern matching (`<<2, Rest/binary>>`).
   - *Go*: Byte slice range loop over 1 MiB `[]byte`.
   - *Expected Checksum*: `262144`.

6. **map put/get 100k small-int keys**:
   - *Semantics*: Insert 100,000 integer keys (0..99,999) with values `I + 1`, then look up every key and sum the values.
   - *Erlang*: Functional map (`maps:put`, `maps:get`).
   - *Go*: Standard hash map (`map[int]int`).
   - *Expected Checksum*: `5000050000`.

7. **ETS-like hash table insert/lookup**:
   - *Semantics*: Concurrent/thread-safe hash table insert and lookup of 100,000 items.
   - *Erlang*: ETS `set` table (`ets:insert`, `ets:lookup`).
   - *Go*: Hash map protected by `sync.Mutex`.
   - *Expected Checksum*: `5000050000`.

8. **process/goroutine spawn+exit 100k (with backlog)**:
   - *Semantics*: Spawn 100,000 lightweight processes or goroutines that send a completion integer (1) to the consumer/parent, but parent receives only after all 100k have been spawned. In ERTS (which defaults to `on_heap` message queues), this accumulates a 100k-message backlog in the parent process mailbox before draining, measuring mailbox growth, GC rootset scanning, and heap reallocation rather than pure spawn cost.
   - *Erlang*: `spawn` of 100k processes sending to parent mailbox with deferred drain.
   - *Go*: 100k goroutines sending into a buffered channel with deferred drain.
   - *Expected Checksum*: `100000`.

9. **process/goroutine spawn+exit+recv 100k (no backlog)**:
   - *Semantics*: Spawn 100,000 processes or goroutines where the parent receives each completion signal (1) immediately before spawning the next. Mailbox queue depth remains at 0..1, isolating pure spawn, context switch, message round-trip, and process exit overhead without queue backlog or GC scanning artifacts.
   - *Erlang*: Sequential `spawn` and immediate `receive 1` in loop.
   - *Go*: Sequential `go func() { ch <- 1 }()` and immediate `<-ch` in loop.
   - *Expected Checksum*: `100000`.

10. **message ping-pong 1M**:
    - *Semantics*: 1,000,000 synchronous message round-trips between two concurrent entities.
    - *Erlang*: Two processes sending `ping`/`pong` messages.
    - *Go*: Two goroutines exchanging over unbuffered channels.
    - *Expected Checksum*: `1000000`.

11. **fan-in 8 producers**:
    - *Semantics*: 8 concurrent producers each sending 125,000 messages (total 1,000,000 messages) to a single consumer.
    - *Erlang*: 8 producer processes sending into consumer mailbox.
    - *Go*: 8 producer goroutines sending into a shared channel.
    - *Expected Checksum*: `1000000`.

12. **float math**:
    - *Semantics*: 1,000,000 iterations of `x = x * 1.0000001 + 0.5` starting from `0.0`.
    - *Erlang*: Tail-recursive function with boxed floats on heap, returning `trunc(X)`.
    - *Go*: Loop accumulating into standard `float64`, returning `int64(x)`.
    - *Expected Checksum*: `525854`.

13. **closure calls**:
    - *Semantics*: 1,000,000 calls of a captured fun `F(X) -> X + K` (with `K = 10`) through `lists:foldl` vs Go closure in a loop.
    - *Erlang*: `lists:foldl(fun(X, Acc) -> Acc + X + K end, 0, List)` over pre-generated 1..1M sequence.
    - *Go*: Loop calling `f := func(x int64) int64 { return x + k }` capturing outer variable `k := 10`.
    - *Expected Checksum*: `500010500000`.

14. **binary build**:
    - *Semantics*: Build a 1 MiB binary by appending 1 byte at a time (`<<Acc/binary, B>>`, private_append optimisation applies) vs Go append to `[]byte`.
    - *Erlang*: Loop appending byte `B = N rem 256` to binary accumulator, returning `byte_size(Acc)`.
    - *Go*: Loop appending `byte(i % 256)` to empty slice `make([]byte, 0)` with dynamic growth, returning `int64(len(buf))`.
    - *Expected Checksum*: `1048576`.

15. **record/tuple update**:
    - *Semantics*: 1,000,000 updates of a 5-field record (setelement semantics) vs Go struct copy.
    - *Erlang*: Loop updating 5-field tuple `{rec5, 0, 0, 0, 0, 0}` via `setelement(4, Rec, I)` and summing `element(4, Next)`.
    - *Go*: 5-field struct `Rec5{f1, f2, f3, f4, f5}` copied by value on each iteration.
    - *Expected Checksum*: `500000500000`.

16. **string→atom→string**:
    - *Semantics*: 100,000 `list_to_atom/atom_to_list` conversions of existing atoms vs Go `map[string]int` interning.
    - *Erlang*: Pre-interned pool of 1,000 strings (`atom_0`..`atom_999`) duplicated to 100,000 elements; timed loop calls `list_to_atom(S)`, `atom_to_list(A)`, and sums string lengths.
    - *Go*: Pre-interned lookup map `map[string]int` and reverse table `[]string`; timed loop looks up ID, gets string from reverse table, and sums string lengths.
    - *Expected Checksum*: `789000`.

17. **sort 100k ints**:
    - *Semantics*: `lists:sort` of 100,000 pseudo-random integers (fixed LCG seed) vs Go `sort.Ints` on a copy.
    - *Erlang*: Pre-generated list with LCG generator `(I * 1664525 + 1013904223) band 16#7FFFFFFF`; timed execution sorts via `lists:sort(List)` and computes checksum `hd + lists:nth(50000) + lists:last`.
    - *Go*: Pre-generated slice with identical sequence; timed execution copies into work slice, sorts via `sort.Ints(work)`, and computes checksum `work[0] + work[49999] + work[len-1]`.
    - *Expected Checksum*: `3227487306`.

18. **gen_server call**:
    - *Semantics*: 100,000 `gen_server:call` round-trips to a local server vs Go request/response over two unbuffered channels. Concurrent kernel evaluated under both scheduler configs (`1` and `default`).
    - *Erlang*: Local `gen_server` process replying with incremented counter.
    - *Go*: Dedicated goroutine receiving on unbuffered `req` channel and replying on unbuffered `resp` channel.
    - *Expected Checksum*: `100000`.

## Methodology & Rules

- **In-process timing**: All timings exclude runtime startup and compilation. Erlang uses `timer:tc` around each kernel execution inside the VM; Go uses `time.Now()` / `time.Since()` around the loop.
- **Process isolation**: To prevent dirty register or stack pollution between repeated runs on JIT runtimes, Erlang kernels execute inside a dedicated worker process spawned within the VM.
- **Warmup & Repeats**: Each kernel executes 1 warmup iteration followed by repeats (5 repeats by default, 3 repeats under `--quick`).
- **Scheduler Configurations**:
  - When running `--sched both` (the default), both scheduler configs (`1` and `default`) are executed **only for concurrent kernels** (`spawn_exit`, `spawn_exit_recv`, `ping_pong`, `fan_in`, `gen_server_call`). Non-concurrent kernels execute under the default scheduler config only.
  - If `--sched 1` or `--sched default` is explicitly requested, all selected kernels run under that specific configuration.
  - Scheduler details:
    - **Single scheduler (`1`)**:
      - ERTS: `erl +S 1:1` (1 scheduler thread, 1 online scheduler).
      - Go: `GOMAXPROCS=1` (single OS thread executing goroutines).
      - Arinsal: `+S 1` / `--schedulers 1` flag on `arinsal eval` (configures 1 scheduler worker in `arinsal-sched`).
    - **Default schedulers (`default`)**:
      - ERTS: default 10 schedulers on Apple M1 Pro (10 logical cores).
      - Go: default `GOMAXPROCS=10` on Apple M1 Pro.
      - Arinsal: default worker count (`available_parallelism().saturating_sub(2).max(1)` = 8 on Apple M1 Pro).
- **Reporting**: Reports median and `min..max` spread for each runtime in nanoseconds per operation (`ns/op`), plus relative performance ratios against ERTS under the matching scheduler configuration. The table includes a dedicated `sched` column.
- **Correctness Verification**: Every runtime's return value is verified against an expected checksum. If any runtime produces an incorrect checksum, `MISMATCH` is reported.
- **Dead-Code Elimination**: Go results are accumulated into an exported sink (`Sink`) and asserted against expected values.

## Usage

```bash
# Run full benchmark suite with both scheduler configs (1 warmup + 5 repeats)
tools/bench_matrix/run.sh

# Run quick benchmark suite with both scheduler configs (1 warmup + 3 repeats)
tools/bench_matrix/run.sh --quick

# Run single scheduler only
tools/bench_matrix/run.sh --sched 1

# Run default schedulers only
tools/bench_matrix/run.sh --sched default

# Filter specific kernels (comma-separated ID or substring)
tools/bench_matrix/run.sh --quick --kernels spawn,ping,fan

# Combine filters and scheduler configuration
tools/bench_matrix/run.sh --quick --sched 1 --kernels spawn_exit,fib_27
```

Results are printed as a Markdown table to stdout and written as structured JSON to `tmp/bench_matrix.json`.

## Spawn Probe: Explaining the spawn+exit Numbers

The baseline `spawn+exit 100k` kernel measures 8.6 µs/op at `+S 1` and 11.1 µs/op at default schedulers on ERTS, whereas Arinsal measures 2.7 µs/op and Go 0.5 µs/op. Because ERTS is known to spawn an empty process in ~0.7–1.0 µs, the probe in `tools/bench_matrix/probes/spawn_probe.erl` was written to isolate the constituent costs.

### Probe Variants

1. **(a) spawn only**: Spawns 100,000 processes executing `fun() -> ok end` in a loop; no messages sent, processes exit immediately.
2. **(b) spawn + immediate recv (no backlog)**: Parent spawns a process sending `Parent ! 1` and receives the message immediately before spawning the next. Mailbox queue depth remains 0..1.
3. **(c) original backlog**: Parent spawns 100,000 processes each sending `Parent ! 1` without receiving, queueing 100,000 messages in the parent's mailbox, followed by draining all 100,000 messages.
4. **(d) off_heap backlog**: Variant (c) executed with `process_flag(message_queue_data, off_heap)` on the parent process.
5. **(e) spawn_opt min_heap_size variations**:
   - `e_child_233`: Variant (c) with child processes spawned via `spawn_opt(..., [{min_heap_size, 233}])`.
   - `e_child_1024`: Variant (c) with child processes spawned via `spawn_opt(..., [{min_heap_size, 1024}])`.
   - `e_parent_233`: Variant (c) where parent process has default `min_heap_size` 233 words.
   - `e_parent_large`: Variant (c) where parent process has initial `min_heap_size` 262,144 words.

### Running the Probe

```bash
# On ERTS (default 10 schedulers):
erl -noshell +P 2000000 -pa tmp/bench_matrix/ebin -run spawn_probe main

# On ERTS (single scheduler):
erl -noshell +S 1:1 +P 2000000 -pa tmp/bench_matrix/ebin -run spawn_probe main

# On Arinsal full boot (default schedulers):
target/release/arinsal -noshell -pa tmp/bench_matrix/ebin -eval 'spawn_probe:main([]), halt().'

# On Arinsal full boot (single scheduler):
target/release/arinsal +S 1 -noshell -pa tmp/bench_matrix/ebin -eval 'spawn_probe:main([]), halt().'

# On Arinsal bare eval (no OTP boot, default schedulers):
target/release/arinsal eval -pa tmp/bench_matrix/ebin spawn_probe run

# On Arinsal bare eval (no OTP boot, single scheduler):
target/release/arinsal eval +S 1 -pa tmp/bench_matrix/ebin spawn_probe run
```

### Probe Results (Apple M1 Pro, median of 5 repeats, in-process timer:tc)

| Variant | Description | ERTS (+S 1:1) | ERTS (default) | Arinsal full boot (+S 1) | Arinsal full boot (default) | Arinsal bare eval (no OTP boot) (+S 1) | Arinsal bare eval (no OTP boot) (default) |
|---|---|---|---|---|---|---|---|
| **(a) spawn only** | spawn only, no message, exit immediately | 1,000.9 ns | 675.5 ns | 20,251.3 ns | 19,839.8 ns | 1,561.7 ns | 1,529.5 ns |
| **(b) spawn+recv no backlog** | spawn + message, recv immediately | 1,793.3 ns | 687.5 ns | 20,808.0 ns | 19,915.6 ns | 2,378.6 ns | 2,287.2 ns |
| **(c) original backlog** | spawn 100k, then recv 100k (on_heap) | 8,558.5 ns | 11,280.0 ns | 19,485.9 ns | 20,276.3 ns | 2,763.1 ns | 2,621.0 ns |
| **(d) off_heap backlog** | c with `message_queue_data, off_heap` | 1,105.7 ns | 854.9 ns | 19,308.0 ns | 20,871.7 ns | 2,876.0 ns | 2,618.0 ns |
| **(e1) child min_heap 233** | spawn_opt child `{min_heap_size, 233}` | 8,876.2 ns | 17,552.0 ns | 19,377.2 ns | 21,324.6 ns | 2,895.0 ns | 2,727.5 ns |
| **(e2) child min_heap 1024** | spawn_opt child `{min_heap_size, 1024}` | 9,177.7 ns | 15,129.9 ns | 19,533.7 ns | 21,546.1 ns | 3,165.9 ns | 2,862.9 ns |
| **(e3) parent min_heap 233** | spawn_opt parent `{min_heap_size, 233}` | 8,621.0 ns | 13,612.1 ns | 19,569.8 ns | 20,011.3 ns | 2,750.9 ns | 2,625.0 ns |
| **(e4) parent min_heap large** | spawn_opt parent `{min_heap_size, 262144}` | 1,120.0 ns | 1,021.5 ns | 19,541.0 ns | 21,317.9 ns | 2,347.1 ns | 2,256.9 ns |

### What the Original Kernel Actually Measures

**Fact (numbers)**: On ERTS default, pure process spawning without messaging (a) takes 675.5 ns/op and spawning with immediate message consumption (b) takes 687.5 ns/op. In contrast, accumulating all 100,000 messages before receiving (c) inflates execution time 16.4x to 11,280.0 ns/op. Setting `process_flag(message_queue_data, off_heap)` on the parent process (d) collapses this time down by 13.2x to 854.9 ns/op. Sizing the parent process initial heap to 262,144 words (e4) similarly drops execution time down to 1,021.5 ns/op. On Arinsal, backlog variant (c) takes 2,621.0 ns/op while off_heap variant (d) takes 2,618.0 ns/op (identical within measurement noise).

**Hypothesis (explanation)**: The original kernel `spawn_exit` does not measure raw process spawn or exit performance; it predominantly measures the cost of ERTS's default `on_heap` message queue under massive message backlogs. In ERTS, when `message_queue_data` is `on_heap`, messages residing in or moving through the process mailbox must be tracked as part of the garbage collector's rootset (`erts/emulator/beam/erl_gc.c:2740-2765`). As 100,000 messages arrive, the parent process's nursery heap quickly exhausts its initial 233-word capacity, triggering repeated generational GC passes. Each GC pass allocates an array of 100,000 root references and traverses every message pointer to adjust heap offsets (`offset_mqueue`). Switching to `off_heap` detaches message queue memory into separate heap fragments outside the main GC rootset, eliminating the O(N * num_gcs) mailbox rescanning. Arinsal does not exhibit this slowdown because its scheduler mailbox is already decoupled from the process nursery heap (`crates/sched/src/mailbox.rs` stores private messages in a `VecDeque` off-heap), so mailbox depth does not induce nursery GC traversal overhead.

## Spawn Breakdown: Where Does Arinsal's Spawn Time Go?

To break down where Arinsal's spawn overhead originates compared to ERTS, probe `tools/bench_matrix/probes/spawn_breakdown.erl` measures isolated constituent variants across 100,000 operations (`N = 100,000`), using median in-process `timer:tc` across 5 repetitions under both single-scheduler (`+S 1` / `+S 1:1`) and default multi-core scheduler configurations on macOS Apple M1 Pro.

### Breakdown Variants

1. **(a) spawn closure**: Spawns `fun() -> ok end`; child terminates immediately with `normal`.
2. **(b) spawn blocked**: Spawns `fun() -> receive stop -> ok end end` that immediately blocks in `receive`. Measures spawn time only; all 100k processes are killed outside the timer.
3. **(c1) spawn_link**: Spawns `spawn_link(fun() -> ok end)`; child exits immediately with `normal`.
4. **(c2) spawn_monitor**: Spawns `spawn_monitor(fun() -> ok end)`; child exits immediately, sending `{'DOWN', ...}`.
5. **(d) spawn MFA**: Spawns `spawn(?MODULE, exported_noop, [])` of an exported zero-arity function vs closure (a).
6. **(e) min_heap_size 1000**: Spawns `spawn_opt(fun() -> ok end, [{min_heap_size, 1000}])`.
7. **(f) exit to DOWN**: Pre-spawns 100k monitored blocked processes; measures time from `exit(P, kill)` to receiving all 100k `{'DOWN', ...}` messages.
8. **(g) processes() length**: Pre-spawns 100k live blocked processes; measures time to execute `length(erlang:processes())` (sanity check: verified 100,043 on ERTS and 100,001 on Arinsal).

### Measurement Results (Apple M1 Pro, median of 5 repeats, in-process timer:tc)

### Measurement Results (Apple M1 Pro, median of 5 repeats, in-process timer:tc)

| Variant | Description | ERTS (+S 1:1) | ERTS (default) | Arinsal full boot (+S 1) | Arinsal full boot (default) | Arinsal bare eval (no OTP boot) (+S 1) | Arinsal bare eval (no OTP boot) (default) |
|---|---|---|---|---|---|---|---|
| **(a) spawn closure** | `spawn(fun() -> ok end)`, exits immediately | 1,006.8 ns | 673.6 ns | 19,821.0 ns | 21,050.2 ns | 1,691.5 ns | 1,671.5 ns |
| **(b) spawn blocked** | `spawn(fun() -> receive end)`, measure spawn only | 1,039.6 ns | 467.0 ns | 2,156.3 ns | 2,087.6 ns | 8,140.7 ns | 7,582.5 ns |
| **(c1) spawn_link** | `spawn_link(fun() -> ok end)`, exits immediately | 1,440.1 ns | 1,261.3 ns | 21,597.1 ns | 23,354.7 ns | 4,104.6 ns | 3,652.8 ns |
| **(c2) spawn_monitor** | `spawn_monitor(fun() -> ok end)`, exits immediately | 5,124.2 ns | 2,486.8 ns | 19,988.0 ns | 22,626.0 ns | 35,622.2 ns | 34,436.2 ns |
| **(d) spawn MFA** | `spawn(?MODULE, exported_noop, [])`, exits immediately | 1,104.3 ns | 977.2 ns | 19,150.8 ns | 22,466.2 ns | 1,992.8 ns | 1,870.4 ns |
| **(e) min_heap_size 1000** | `spawn_opt(fun() -> ok end, [{min_heap_size, 1000}])` | 1,067.1 ns | 1,435.0 ns | 20,160.7 ns | 22,874.0 ns | 2,223.2 ns | 2,413.0 ns |
| **(f) exit to DOWN** | `exit(P, kill)` to `'DOWN'` for 100k blocked processes | 2,260.7 ns | 2,215.4 ns | 26,938.1 ns | 27,954.1 ns | 8,928.1 ns | 9,072.1 ns |
| **(g) processes() length** | `erlang:processes()` length after 100k live processes | 42.8 ns | 34.2 ns | 73.6 ns | 67.3 ns | 81.3 ns | 82.5 ns |

### Runtime Mode Matching and Superseded Conclusions

**Fact (matching setup)**: The full boot mode (`arinsal -noshell -pa <dir> -eval '...'`) is the configuration that directly matches the ERTS benchmark environment (`erl -noshell ... -eval '...'`), because ERTS always boots the full OTP application hierarchy (preloaded modules, `kernel`, `stdlib`, `code_server`, and system ETS tables). In contrast, the bare evaluation mode (`target/release/arinsal eval`) executes directly on the minimal VM without an OTP boot.

**Fact (superseded earlier conclusions)**: Earlier conclusions based solely on the bare eval columns are superseded by the full boot measurements. Under bare eval, ephemeral process spawn and immediate exit was measured at ~1,670–1,690 ns/op, leading to the hypothesis that blocked receive thread contention (variant b) and monitor signaling (variant c2) were the primary bottlenecks. Under full boot matching ERTS, the numbers show a different reality:
1. Pure process spawning without exit (variant b `spawn blocked`) costs only 2,156.3 ns/op on `+S 1` and 2,087.6 ns/op on default schedulers — closely matching bare eval (~2.1 µs).
2. Every variant where the child process exits immediately (`a`, `c1`, `c2`, `d`, `e`) jumps to ~19,000–23,000 ns/op (e.g. variant a costs 19,821.0 ns/op on `+S 1` and 21,050.2 ns/op on default), which is ~12x higher than bare eval and ~28x slower than ERTS (732.2 ns/op).
3. The true bottleneck under the matching OTP boot environment is process exit teardown, not process creation or monitor signal dispatch.

### Breakdown Facts and Hypotheses

- **Fact (exit overhead across all exit variants)**: In full boot, whether spawning a closure (a: 21,050.2 ns), linked process (c1: 23,354.7 ns), monitored process (c2: 22,626.0 ns), MFA (d: 22,466.2 ns), or customized initial heap (e: 22,874.0 ns), all variants that exit immediately cluster tightly around 20–23 µs/op. In contrast, variant (b) where processes block rather than exit takes only 2.1 µs/op.
- **Fact (allocation cost parity)**: Requesting `{min_heap_size, 1000}` (e) adds ~1,824 ns/op on Arinsal full boot default (21,050.2 → 22,874.0 ns) and ~154 ns/op on ERTS (732.2 → 886.7 ns). In bare eval, the delta was ~741 ns on Arinsal vs ~761 ns on ERTS.
- **Fact (exit & table scan overhead)**: Asynchronous kill-to-DOWN delivery (f) takes 27,954.1 ns/op on Arinsal full boot vs 2,381.5 ns/op on ERTS (11.7x gap; 8,928.1 ns/op in bare eval). Scanning 100k live pids via `erlang:processes()` (g) takes 67.3 ns/op on Arinsal full boot vs 34.2 ns/op on ERTS (2.0x gap), confirming process table traversal scales linearly.
- **Fact (bare eval artifacts)**: In bare eval mode without OTP boot, variant (b) originally showed 7,582.5 ns/op and variant (c2) showed 34,436.2 ns/op; both figures reflect unbooted VM artifacts (such as synthetic monitor signal queues and thread parking under empty runqueues) that are superseded by the full boot environment.

- **Hypothesis (cause of full boot process exit overhead)**: In full boot mode, the runtime initializes multiple system ETS tables. On every process exit, Arinsal locks the global ETS registry, traverses `registry.all()`, and constructs `table.info()` for every table to inspect ownership and heir transfer, in addition to querying environment variables (`std::env::var_os`) on hot paths. ERTS avoids this by maintaining a per-process list of owned ETS tables (`ERTS_PSD_ETS_OWNED_TABLES`), enabling processes that own no ETS tables to bypass table scans entirely on exit.
- **Hypothesis (bare eval variant c2 gap)**: In Arinsal bare eval mode, `spawn_monitor` creates a monitor via `ctx.signal(child, Signal::Monitor(id))` through the cross-thread signal queue (`crates/vm/src/natives/proc.rs:1586`). When the child exits immediately, `notify_exit` delivers a synthetic `MonitorDown` signal back through the parent's inbox queue (`crates/vm/src/process.rs:1513`), incurring event allocations, signal queue locks, and mailbox wakeups for every monitor. In full boot mode, this cost is dwarfed by the ~20 µs process exit overhead.


