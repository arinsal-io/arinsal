# Arinsal CPU Profiles for bench_matrix Kernels

## Overview and Methodology

- **Platform:** macOS arm64 (Apple Silicon), Erlang/OTP 29.1.1 bytecode.
- **Runtime:** Arinsal `release` build (`target/release/arinsal +S 1 -noshell`).
- **Execution Mode:** Full OTP boot (not bare `eval`).
- **Profiling Protocol:** For each kernel in `tools/bench_matrix/kernels.erl`, an endless loop driver is spawned with `arinsal +S 1 -noshell -pa <ebin> -eval 'bench_driver:loop(<kernel>).'`. After a 4 s warmup period to ensure steady-state execution, macOS `/usr/bin/sample <pid> 4` collects execution stacks at 1 ms intervals for 4 s (yielding ~3,000 total samples per kernel thread).
- **Idle Filtering:** Idle/waiting thread frames (`kevent`, `poll`, `read`, `semaphore_wait_trap`, `semaphore_timedwait_trap`, `__psynch_*`, `mach_msg*`) are dropped. All metrics report shares as a percentage of non-idle top-of-stack execution samples.
- **Demangling:** Rust v0 and legacy mangled symbols are demangled using `rustfilt`.

---

## Kernel Profiles: Top 5 Symbols by Share

Each kernel's top 15 symbols with counts are saved in `<kernel>.txt`. Below are the top 5 symbols per kernel with sample counts and % share of non-idle execution time.

### `binary_build`
- **Total Non-Idle Samples:** 2994

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 811 | 27.1% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 474 | 15.8% | `<arinsal_vm::Vm>::exec_bif_op` |
| 3 | 299 | 10.0% | `arinsal_vm::interp::exec_hot` |
| 4 | 259 | 8.7% | `arinsal_bifs::arith::rem` |
| 5 | 213 | 7.1% | `arinsal_bits::append_inner::<arinsal_term::heap::ProcessHeap>` |

### `binary_scan`
- **Total Non-Idle Samples:** 2972

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 1402 | 47.2% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 461 | 15.5% | `arinsal_vm::jit_hook::jit_step` |
| 3 | 375 | 12.6% | `arinsal_vm::interp::exec_hot` |
| 4 | 215 | 7.2% | `arinsal_bits::match_uint_be` |
| 5 | 149 | 5.0% | `_tlv_get_addr` |

### `closure_calls`
- **Total Non-Idle Samples:** 2995

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 568 | 19.0% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 319 | 10.7% | `__findenv_locked` |
| 3 | 241 | 8.0% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |
| 4 | 215 | 7.2% | `<arinsal_vm::Vm>::call_fun_term` |
| 5 | 150 | 5.0% | `arinsal_vm::jit_hook::run` |

### `ets_insert_lookup`
- **Total Non-Idle Samples:** 2930

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 561 | 19.1% | `__findenv_locked` |
| 2 | 495 | 16.9% | `<arinsal_vm::Vm>::run_slice_inner` |
| 3 | 229 | 7.8% | `<arinsal_ets::Table>::lookup::<arinsal_bifs::FragmentingHeap>` |
| 4 | 150 | 5.1% | `<arinsal_ets::Table>::put_hashed` |
| 5 | 142 | 4.8% | `_xzm_free` |

### `fan_in`
- **Total Non-Idle Samples:** 2946

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 743 | 25.2% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 524 | 17.8% | `arinsal_vm::jit_hook::jit_step` |
| 3 | 216 | 7.3% | `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&arinsal_sched::Pid>` |
| 4 | 193 | 6.6% | `<arinsal_sched::Runner<arinsal_vm::proc_create::Process> as arinsal_sched::ContextOps<arinsal_vm::process::Message>>::deliver` |
| 5 | 183 | 6.2% | `<arinsal_term::heap::ProcessHeap>::set_min_heap_size` |

### `fib_27`
- **Total Non-Idle Samples:** 2777

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 2452 | 88.3% | `???` |
| 2 | 99 | 3.6% | `<arinsal_vm::Vm>::run_slice_inner` |
| 3 | 65 | 2.3% | `__findenv_locked` |
| 4 | 26 | 0.9% | `arinsal_vm::jit_hook::run` |
| 5 | 25 | 0.9% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |

### `float_math`
- **Total Non-Idle Samples:** 2952

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 2175 | 73.7% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 602 | 20.4% | `arinsal_vm::interp::exec_hot` |
| 3 | 66 | 2.2% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |
| 4 | 27 | 0.9% | `__munmap` |
| 5 | 16 | 0.5% | `_platform_memmove` |

### `gen_server_call`
- **Total Non-Idle Samples:** 2806

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 623 | 22.2% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 348 | 12.4% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |
| 3 | 237 | 8.4% | `__findenv_locked` |
| 4 | 135 | 4.8% | `arinsal_vm::signals::call` |
| 5 | 95 | 3.4% | `arinsal_sched::run_one::<arinsal_vm::proc_create::Process>` |

### `int_loop_sum`
- **Total Non-Idle Samples:** 2883

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 2567 | 89.0% | `arinsal_vm::interp::exec_hot` |
| 2 | 149 | 5.2% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |
| 3 | 41 | 1.4% | `mach_absolute_time` |
| 4 | 21 | 0.7% | `<arinsal_vm::process::Executor>::run` |
| 5 | 17 | 0.6% | `<arinsal_vm::proc_create::Process>::run_task` |

### `list_100k`
- **Total Non-Idle Samples:** 2885

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 1909 | 66.2% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |
| 2 | 215 | 7.5% | `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&usize>` |
| 3 | 169 | 5.9% | `<hashbrown::map::HashMap<usize, (), std::hash::random::RandomState>>::insert` |
| 4 | 116 | 4.0% | `<arinsal_vm::Vm>::run_slice_inner` |
| 5 | 104 | 3.6% | `arinsal_term::native_code::is_native_code_pointer` |

### `map_put_get`
- **Total Non-Idle Samples:** 2956

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 548 | 18.5% | `arinsal_term::native_code::is_native_code_pointer` |
| 2 | 449 | 15.2% | `<hashbrown::map::HashMap<usize, (), std::hash::random::RandomState>>::insert` |
| 3 | 329 | 11.1% | `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&usize>` |
| 4 | 238 | 8.1% | `<arinsal_term::gc::Copier>::copy` |
| 5 | 202 | 6.8% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |

### `ping_pong`
- **Total Non-Idle Samples:** 2915

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 748 | 25.7% | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` |
| 2 | 327 | 11.2% | `<arinsal_vm::Vm>::run_slice_inner` |
| 3 | 206 | 7.1% | `__findenv_locked` |
| 4 | 153 | 5.2% | `mach_absolute_time` |
| 5 | 126 | 4.3% | `<arinsal_sched::mailbox::Incoming<arinsal_sched::Event<arinsal_vm::process::Message>>>::drain_into` |

### `record_update`
- **Total Non-Idle Samples:** 2953

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 754 | 25.5% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 305 | 10.3% | `arinsal_vm::interp::exec_hot` |
| 3 | 242 | 8.2% | `_xzm_free` |
| 4 | 202 | 6.8% | `_platform_memmove` |
| 5 | 136 | 4.6% | `_malloc_zone_malloc` |

### `sort_100k`
- **Total Non-Idle Samples:** 2912

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 637 | 21.9% | `__findenv_locked` |
| 2 | 376 | 12.9% | `arinsal_term::native_code::is_native_code_pointer` |
| 3 | 228 | 7.8% | `<arinsal_vm::Vm>::run_slice_inner` |
| 4 | 221 | 7.6% | `???` |
| 5 | 216 | 7.4% | `<hashbrown::map::HashMap<usize, (), std::hash::random::RandomState>>::insert` |

### `spawn_exit`
- **Total Non-Idle Samples:** 2888

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 1120 | 38.8% | `<arinsal_ets::Table>::info` |
| 2 | 407 | 14.1% | `arinsal_term::ops::exact_eq` |
| 3 | 290 | 10.0% | `_xzm_free` |
| 4 | 131 | 4.5% | `<arinsal_term::atom::AtomTable>::text` |
| 5 | 126 | 4.4% | `_xzm_xzone_malloc` |

### `spawn_exit_recv`
- **Total Non-Idle Samples:** 2933

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 1079 | 36.8% | `<arinsal_ets::Table>::info` |
| 2 | 393 | 13.4% | `arinsal_term::ops::exact_eq` |
| 3 | 284 | 9.7% | `_xzm_free` |
| 4 | 136 | 4.6% | `_xzm_xzone_malloc` |
| 5 | 133 | 4.5% | `_malloc_zone_malloc` |

### `string_atom_string`
- **Total Non-Idle Samples:** 2919

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 442 | 15.1% | `arinsal_vm::signals::call` |
| 2 | 397 | 13.6% | `__findenv_locked` |
| 3 | 312 | 10.7% | `_platform_memcmp` |
| 4 | 187 | 6.4% | `<arinsal_vm::Vm>::run_slice_inner` |
| 5 | 98 | 3.4% | `arinsal_vm::natives::proc::call` |

### `tuple_loop`
- **Total Non-Idle Samples:** 2882

| Rank | Samples | Share (%) | Symbol |
| :---: | :---: | :---: | :--- |
| 1 | 774 | 26.9% | `<arinsal_vm::Vm>::run_slice_inner` |
| 2 | 350 | 12.1% | `arinsal_vm::interp::exec_hot` |
| 3 | 261 | 9.1% | `_xzm_free` |
| 4 | 158 | 5.5% | `_platform_memmove` |
| 5 | 127 | 4.4% | `_malloc_zone_malloc` |

---

## Non-Runtime Overhead Appearing Across Kernels (2+ Kernels)

The profile data reveals significant non-runtime overhead from system libraries, hashing, allocation, and locking appearing across multiple benchmark kernels. Measured facts are documented below, with interpretations explicitly marked as hypotheses.

### 1. Environment Lookups (`getenv` / `__findenv_locked`)

**Description:** Repeated environment variable lookups in hot loops.

| Symbol | Total Samples | Kernel Count | Kernels and Sample Counts |
| :--- | :---: | :---: | :--- |
| `__findenv_locked` | 2571 | 10 | `sort_100k` (637), `ets_insert_lookup` (561), `string_atom_string` (397), `closure_calls` (319), `gen_server_call` (237), `ping_pong` (206), `fib_27` (65), `list_100k` (54), `spawn_exit_recv` (48), `spawn_exit` (47) |
| `std::sys::env::unix::getenv::{closure#0}` | 28 | 4 | `closure_calls` (8), `ping_pong` (8), `ets_insert_lookup` (7), `sort_100k` (5) |
| `getenv` | 15 | 2 | `sort_100k` (8), `ets_insert_lookup` (7) |

**Interpretation:** Hypothesis: Arinsal inspects environment variables (such as debug/trace flags like `ARINSAL_TRACE_BOOT`) dynamically on reduction loop or process execution paths instead of caching them in a static `LazyLock` at initialization. On macOS libc, `getenv()` acquires a global environment lock (`__findenv_locked`), causing serialization and substantial CPU burn in tight loops.

### 2. Memory Allocation and Deallocation (`malloc` / `free`)

**Description:** System allocator activity in process execution and object mutation.

| Symbol | Total Samples | Kernel Count | Kernels and Sample Counts |
| :--- | :---: | :---: | :--- |
| `_xzm_free` | 1566 | 14 | `spawn_exit` (290), `spawn_exit_recv` (284), `tuple_loop` (261), `record_update` (242), `ets_insert_lookup` (142), `closure_calls` (93), `string_atom_string` (85), `gen_server_call` (71), `ping_pong` (42), `fan_in` (22), `map_put_get` (13), `list_100k` (10), `binary_scan` (6), `int_loop_sum` (5) |
| `_xzm_xzone_malloc` | 700 | 11 | `spawn_exit_recv` (136), `spawn_exit` (126), `record_update` (124), `tuple_loop` (111), `string_atom_string` (56), `ets_insert_lookup` (48), `gen_server_call` (35), `ping_pong` (26), `closure_calls` (23), `map_put_get` (9), `fan_in` (6) |
| `_malloc_zone_malloc` | 642 | 10 | `record_update` (136), `spawn_exit_recv` (133), `tuple_loop` (127), `spawn_exit` (103), `closure_calls` (37), `ets_insert_lookup` (34), `gen_server_call` (33), `ping_pong` (18), `string_atom_string` (14), `fan_in` (7) |
| `_free` | 531 | 11 | `record_update` (102), `tuple_loop` (97), `spawn_exit_recv` (93), `spawn_exit` (83), `closure_calls` (31), `ets_insert_lookup` (29), `ping_pong` (27), `string_atom_string` (25), `gen_server_call` (22), `list_100k` (17), `map_put_get` (5) |
| `DYLD-STUB$$free` | 133 | 8 | `tuple_loop` (26), `record_update` (25), `spawn_exit_recv` (23), `spawn_exit` (20), `closure_calls` (14), `ets_insert_lookup` (11), `ping_pong` (9), `gen_server_call` (5) |
| `xzm_malloc_zone_size` | 60 | 4 | `string_atom_string` (35), `gen_server_call` (10), `fan_in` (8), `map_put_get` (7) |
| `_malloc_zone_realloc` | 33 | 3 | `string_atom_string` (17), `fan_in` (10), `gen_server_call` (6) |
| `_malloc_zone_calloc` | 24 | 2 | `ets_insert_lookup` (17), `string_atom_string` (7) |
| `xzm_malloc_zone_realloc` | 22 | 2 | `string_atom_string` (16), `map_put_get` (6) |

**Interpretation:** Hypothesis: High malloc/free overhead in `tuple_loop`, `record_update`, and `spawn_exit` indicates that process allocations, tuple updates, or intermediate vectors escape the pre-allocated process bump heap and trigger system allocator calls (`libsystem_malloc.dylib`). In contrast, ERTS satisfies most per-process allocations via bump allocation on contiguous heap blocks.

### 3. Cryptographic Hashing (`SipHash` / `RandomState`)

**Description:** Hash calculation overhead in collections and process lookups.

| Symbol | Total Samples | Kernel Count | Kernels and Sample Counts |
| :--- | :---: | :---: | :--- |
| `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` | 4356 | 18 | `list_100k` (1909), `ping_pong` (748), `gen_server_call` (348), `closure_calls` (241), `map_put_get` (202), `sort_100k` (170), `int_loop_sum` (149), `fan_in` (144), `ets_insert_lookup` (99), `spawn_exit_recv` (88), `float_math` (66), `string_atom_string` (38), `tuple_loop` (35), `record_update` (30), `spawn_exit` (30), `fib_27` (25), `binary_build` (21), `binary_scan` (13) |
| `<hashbrown::map::HashMap<usize, (), std::hash::random::RandomState>>::insert` | 920 | 10 | `map_put_get` (449), `sort_100k` (216), `list_100k` (169), `ping_pong` (26), `gen_server_call` (13), `int_loop_sum` (12), `tuple_loop` (11), `record_update` (10), `spawn_exit_recv` (8), `float_math` (6) |
| `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&usize>` | 854 | 10 | `map_put_get` (329), `list_100k` (215), `sort_100k` (158), `ping_pong` (58), `gen_server_call` (35), `record_update` (19), `int_loop_sum` (12), `string_atom_string` (12), `float_math` (8), `tuple_loop` (8) |
| `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&arinsal_sched::Pid>` | 275 | 5 | `fan_in` (216), `ping_pong` (37), `gen_server_call` (12), `int_loop_sum` (5), `spawn_exit_recv` (5) |
| `<hashbrown::raw::RawTable<(usize, ())>>::reserve_rehash::<hashbrown::map::make_hasher<usize, (), std::hash::random::RandomState>::{closure#0}>` | 207 | 4 | `map_put_get` (140), `sort_100k` (48), `list_100k` (12), `record_update` (7) |
| `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&(usize, usize)>` | 187 | 8 | `closure_calls` (68), `sort_100k` (40), `ets_insert_lookup` (29), `gen_server_call` (15), `fib_27` (12), `string_atom_string` (9), `ping_pong` (8), `list_100k` (6) |
| `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&alloc::string::String>` | 145 | 3 | `closure_calls` (133), `gen_server_call` (7), `list_100k` (5) |
| `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&arinsal_ets::Tid>` | 60 | 3 | `ets_insert_lookup` (38), `spawn_exit_recv` (12), `spawn_exit` (10) |
| `<hashbrown::map::HashMap<alloc::sync::Arc<str>, arinsal_term::atom::Atom, std::hash::random::RandomState>>::get::<str>` | 34 | 2 | `string_atom_string` (24), `ets_insert_lookup` (10) |
| `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&str>` | 17 | 2 | `gen_server_call` (9), `ping_pong` (8) |

**Interpretation:** Hypothesis: Rust standard library and hashbrown structures default to SipHash 1-3 with randomized keys (`RandomState`). In `list_100k`, SipHash alone accounts for 75.7% of all execution samples. Using a fast, non-cryptographic hash builder (such as `foldhash` or `fxhash`) for internal runtime maps, PID registries, and lookups would eliminate the bulk of this overhead.

### 4. Synchronization Locks (`pthread_mutex_*`, `os_unfair_lock_*`)

**Description:** Lock acquisition and release in single-scheduler execution (+S 1).

| Symbol | Total Samples | Kernel Count | Kernels and Sample Counts |
| :--- | :---: | :---: | :--- |
| `__findenv_locked` | 2571 | 10 | `sort_100k` (637), `ets_insert_lookup` (561), `string_atom_string` (397), `closure_calls` (319), `gen_server_call` (237), `ping_pong` (206), `fib_27` (65), `list_100k` (54), `spawn_exit_recv` (48), `spawn_exit` (47) |
| `pthread_mutex_lock` | 131 | 6 | `string_atom_string` (44), `ping_pong` (34), `ets_insert_lookup` (19), `gen_server_call` (16), `spawn_exit` (10), `spawn_exit_recv` (8) |
| `pthread_mutex_unlock` | 91 | 6 | `ping_pong` (27), `string_atom_string` (21), `ets_insert_lookup` (13), `spawn_exit` (12), `gen_server_call` (10), `spawn_exit_recv` (8) |
| `os_unfair_lock_unlock` | 65 | 6 | `sort_100k` (19), `ets_insert_lookup` (14), `string_atom_string` (11), `closure_calls` (8), `gen_server_call` (7), `ping_pong` (6) |
| `std::sys::env::unix::env_read_lock` | 53 | 6 | `closure_calls` (9), `ets_insert_lookup` (9), `gen_server_call` (9), `ping_pong` (9), `sort_100k` (9), `string_atom_string` (8) |
| `os_unfair_lock_lock_with_options` | 46 | 5 | `sort_100k` (16), `string_atom_string` (9), `ets_insert_lookup` (8), `gen_server_call` (7), `ping_pong` (6) |

**Interpretation:** Hypothesis: Even with a single scheduler (`+S 1`), Arinsal process mailboxes, ETS table registries, and atom tables acquire POSIX mutexes and OS unfair locks on message send/recv and table operations. Fine-grained lock-free queues or scheduler-local un-synchronized fast paths would avoid kernel lock operations.

### 5. Thread-Local Storage Resolution (`_tlv_get_addr`)

**Description:** Dynamic TLS variable address lookup overhead.

| Symbol | Total Samples | Kernel Count | Kernels and Sample Counts |
| :--- | :---: | :---: | :--- |
| `_tlv_get_addr` | 897 | 13 | `binary_scan` (149), `fan_in` (146), `closure_calls` (143), `sort_100k` (99), `ping_pong` (79), `record_update` (51), `string_atom_string` (49), `ets_insert_lookup` (48), `tuple_loop` (40), `gen_server_call` (39), `list_100k` (27), `fib_27` (16), `spawn_exit_recv` (11) |

**Interpretation:** Hypothesis: On macOS arm64, accesses to thread-local variables (`thread_local!`) compile to runtime calls to `_tlv_get_addr` in `libdyld.dylib`. Hot paths frequently reading thread-local execution context, reduction counters, or scheduler pointers pay this dynamic TLS lookup cost on every invocation.

### 6. Reference Counting (`Arc` Clone / Drop / RawVec Growth)

**Description:** Atomic reference count manipulation and drop glue.

| Symbol | Total Samples | Kernel Count | Kernels and Sample Counts |
| :--- | :---: | :---: | :--- |
| `<alloc::raw_vec::RawVec<alloc::sync::Arc<alloc::vec::Vec<u8>>>>::grow_one` | 72 | 3 | `spawn_exit` (30), `spawn_exit_recv` (30), `string_atom_string` (12) |
| `<hashbrown::map::HashMap<alloc::sync::Arc<str>, arinsal_term::atom::Atom, std::hash::random::RandomState>>::get::<str>` | 34 | 2 | `string_atom_string` (24), `ets_insert_lookup` (10) |
| `core::ptr::drop_glue::<arinsal_sched::Runner<arinsal_vm::proc_create::Process>>` | 19 | 2 | `ping_pong` (14), `spawn_exit_recv` (5) |

**Interpretation:** Hypothesis: Shared ownership of process contexts, scheduler queues, and message envelopes via `Arc` triggers atomic increment/decrement and complex `drop_glue` destruction overhead on message delivery and process termination.

---

## Reproducing Profiles

The complete profiling run can be reproduced with a single command:

```bash
bash tools/bench_matrix/profiles/profile.sh
```

