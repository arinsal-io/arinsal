# CPU Profile Analysis: Why is JIT Code Slower Than the Interpreter?

## 1. Executive Summary & Measured Facts

On Erlang/OTP 29.1.1 bytecode running on Apple Silicon (macOS arm64), a counting loop (`kernels:tail/1` from `crates/vm/tests/fixtures/kernels.erl`) exhibits the following execution speeds:

| Implementation / Mode | Configuration | Measured Time / Iteration | Relative to Interpreter |
| :--- | :--- | :---: | :---: |
| **Arinsal JIT (BeamAsm)** | `ARINSAL_BEAMASM=1 ARINSAL_BEAMASM_MODULES=kernels` | **19.1 – 19.8 ns** | **2.25x slower** |
| **Arinsal Interpreter** | Default (no BeamAsm) | **8.5 – 8.8 ns** | 1.00x (baseline) |
| **ERTS 17.1 (Reference)** | `erl -noshell` (OTP 29.1.1) | **1.68 ns** | 0.19x (5.1x faster than Arinsal interp) |

Profiling was conducted using macOS `/usr/bin/sample <pid> 5` sampling at 1 ms intervals during steady-state execution over $\ge 5$ seconds:
- **JIT run:** `kernels:tail(400000000)` running for 7.55 s (3,768 execution samples collected).
- **Interpreter run:** `kernels:tail(800000000)` running for 6.70 s (3,783 execution samples collected).

---

## 2. Share of Execution Time: JIT Code vs. Rust Runtime vs. OS

The primary question is how much time is spent executing generated native machine instructions versus transitioning through or executing within the Rust runtime and system libraries.

| Code Region | JIT Samples (Self) | JIT Share (%) | Interpreter Samples (Self) | Interpreter Share (%) |
| :--- | :---: | :---: | :---: | :---: |
| **Native JIT Code** (`???` in JIT code memory) | 537 | **14.23%** | 0 | **0.00%** |
| **Bytecode Interpreter Loop** (`exec_hot`) | 0 | **0.00%** | 3,625 | **95.82%** |
| **Rust Runtime Functions** | 1,844 | **48.94%** | 106 | **2.80%** |
| **OS / System Libraries** (`libsystem_*`, `libc`) | 1,387 | **36.83%** | 52 | **1.37%** |
| **Total Rust + OS Overhead** | 3,231 | **85.77%** | 158 | **4.18%** |

### Key Observations (Facts)
1. In the JIT run, **only 14.23%** of CPU self time is spent executing instructions inside the JIT-compiled native code block (`???`).
2. **85.77%** of CPU self time is spent outside the JIT-compiled code: in Rust runtime helper functions (48.94%) and operating system libraries/syscalls (36.83%).
3. In contrast, the interpreter spends **95.82%** of its CPU time inside `arinsal_vm::exec_hot` executing the bytecode dispatch loop, with negligible OS/runtime overhead (4.18%).

---

## 3. Targeted Component Analysis (Facts)

The task specifically requests measurements for `run_native`, `CodeMemory::new`/`mmap`, the scheduler loop, and runtime helpers.

| Target Component | JIT Inclusive Samples | JIT Inclusive % | JIT Self Samples | JIT Self % | Interp Inclusive % | Interp Self % |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`run_native` Entry Point** | 3,710 | **98.30%** | 4 | **0.11%** | 0.00% | 0.00% |
| **`CodeMemory::new` & `mmap`** | 77 | **2.04%** | 77 | **2.04%** | 0.00% | 0.00% |
| **`CodeMemory::write_bytes` & I-Cache** | 681 | **18.04%** | 92 | **2.44%** | 0.00% | 0.00% |
| **`CodeMemory::drop` & `__munmap`** | 166 | **4.40%** | 166 | **4.40%** | 0.00% | 0.00% |
| **Guard Helper (`arinsal_beamasm_guard`)** | 2,169 | **57.47%** | 1,038 | **27.50%** | 0.00% | 0.00% |
| **Equality Check (`exact_eq`)** | 750 | **19.87%** | 750 | **19.87%** | 0.00% | 0.00% |
| **Memory Moves (`_platform_memmove`)** | 947 | **25.09%** | 947 | **25.09%** | 0.19% | 0.19% |
| **Scheduler (`run_one` / `Executor::run`)** | 3,761 | **99.66%** | 3 | **0.08%** | 99.29% | 0.87% |

### Specific Component Breakdowns:
1. **`run_native` (`crates/vm/src/lib.rs:139`)**:
   - In JIT: Present in 3,710 samples (**98.30%** inclusive). Every reduction slice enters native execution via `run_native`.
   - In Interpreter: 0 samples (**0.00%**).
2. **`CodeMemory::new` / `mmap` / Veneer Lifecycle**:
   - In JIT: Every single invocation of `run_native` creates an ephemeral 8-byte entry veneer via `CodeMemory::new(4)` (`crates/vm/src/lib.rs:185`), issues an `mmap` syscall, writes veneer bytes, calls `pthread_jit_write_protect_np` and `sys_icache_invalidate` (flushing CPU instruction caches), and unmaps the page via `__munmap` when `run_native` exits on reduction yield (`ExitReason::Yield`).
   - Combined veneer allocation, cache flushing, and deallocation accounts for **24.48%** inclusive time and **8.88%** self time (`__mmap` 2.01%, `sys_icache_invalidate` 2.44%, `__munmap` 4.40%).
   - In Interpreter: 0 samples (**0.00%**).
3. **Runtime Helpers (`arinsal_beamasm_guard` + `exact_eq`)**:
   - In JIT: `arinsal_beamasm_guard` accounts for 2,169 inclusive samples (**57.47%**) and 1,038 self samples (**27.50%**). It calls `exact_eq` which accounts for 750 self samples (**19.87%**) and memory moves (947 samples, **25.09%**).
   - In Interpreter: 0 samples (**0.00%**). Equality checking for small integers in `exec_hot` is completely inlined via `compare::eq_exact` (`a == b || slow_exact_eq(a, b)`).
4. **Scheduler Loop (`crates/sched/src/lib.rs`, `crates/vm/src/process.rs`)**:
   - In JIT: `arinsal_sched::run_one` is 99.66% inclusive, with only 0.08% self time. Scheduler bookkeeping outside of process execution is ~1.36% of inclusive time.
   - In Interpreter: `arinsal_sched::run_one` is 99.29% inclusive, with 0.24% self time. Scheduler bookkeeping outside of process execution is ~1.49% of inclusive time.

---

## 4. Top 25 Frames by Self Time (JIT Run)

Active execution thread (`Thread_28240422`), 3,768 total samples:

| Rank | Symbol (Demangled) | Binary / Module | Self Samples | Self % | Inclusive Samples | Inclusive % |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| 1 | `arinsal_vm::native_hooks::arinsal_beamasm_guard` | `arinsal` | 1038 | 27.50% | 2169 | 57.47% |
| 2 | `_platform_memmove` | `libsystem_platform.dylib` | 947 | 25.09% | 947 | 25.09% |
| 3 | `arinsal_term::ops::exact_eq` | `arinsal` | 750 | 19.87% | 750 | 19.87% |
| 4 | `???` | `<unknown binary>` | 537 | 14.23% | 2573 | 68.18% |
| 5 | `__munmap` | `libsystem_kernel.dylib` | 166 | 4.40% | 166 | 4.40% |
| 6 | `sys_icache_invalidate` | `libsystem_platform.dylib` | 92 | 2.44% | 92 | 2.44% |
| 7 | `__mmap` | `libsystem_kernel.dylib` | 76 | 2.01% | 76 | 2.01% |
| 8 | `DYLD-STUB$$memcpy` | `arinsal` | 62 | 1.64% | 62 | 1.64% |
| 9 | `__findenv_locked` | `libsystem_c.dylib` | 18 | 0.48% | 18 | 0.48% |
| 10 | `pthread_jit_write_protect_np` | `libsystem_pthread.dylib` | 11 | 0.29% | 11 | 0.29% |
| 11 | `pthread_mutex_lock` | `libsystem_pthread.dylib` | 6 | 0.16% | 6 | 0.16% |
| 12 | `_xzm_free` | `libsystem_malloc.dylib` | 6 | 0.16% | 6 | 0.16% |
| 13 | `arinsal_vm::run_native` | `arinsal` | 4 | 0.11% | 3710 | 98.30% |
| 14 | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` | `arinsal` | 4 | 0.11% | 4 | 0.11% |
| 15 | `mach_absolute_time` | `libsystem_kernel.dylib` | 4 | 0.11% | 4 | 0.11% |
| 16 | `arinsal_sched::run_one::<arinsal_vm::Process>` | `arinsal` | 3 | 0.08% | 3761 | 99.66% |
| 17 | `<arinsal_vm::Process>::run_task` | `arinsal` | 2 | 0.05% | 3755 | 99.50% |
| 18 | `std::sys::env::unix::getenv::{closure#0}` | `arinsal` | 2 | 0.05% | 22 | 0.58% |
| 19 | `<arinsal_sched::timer::Wheel<arinsal_vm::process::Message>>::advance` | `arinsal` | 2 | 0.05% | 2 | 0.05% |
| 20 | `_xzm_xzone_malloc` | `libsystem_malloc.dylib` | 2 | 0.05% | 2 | 0.05% |
| 21 | `_free` | `libsystem_malloc.dylib` | 2 | 0.05% | 2 | 0.05% |
| 22 | `<arinsal_vm::Process as arinsal_sched::Task>::run` | `arinsal` | 1 | 0.03% | 3756 | 99.52% |
| 23 | `std::sys::backtrace::__rust_begin_short_backtrace::<<arinsal_sched::Scheduler<arinsal_vm::Process>>::build::{closure#9}, ()>` | `arinsal` | 1 | 0.03% | 3768 | 99.84% |
| 24 | `mmap` | `libsystem_kernel.dylib` | 1 | 0.03% | 77 | 2.04% |
| 25 | `core::ptr::drop_glue::<arinsal_sched::Runner<arinsal_vm::Process>>` | `arinsal` | 1 | 0.03% | 1 | 0.03% |

---

## 5. Top 25 Frames by Inclusive Time (JIT Run)

Active execution thread (`Thread_28240422`), 3,768 total samples:

| Rank | Symbol (Demangled) | Binary / Module | Inclusive Samples | Inclusive % | Self Samples | Self % |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| 1 | `thread_start` | `libsystem_pthread.dylib` | 3768 | 99.84% | 0 | 0.00% |
| 2 | `_pthread_start` | `libsystem_pthread.dylib` | 3768 | 99.84% | 0 | 0.00% |
| 3 | `<std::sys::thread::unix::Thread>::new::thread_start` | `arinsal` | 3768 | 99.84% | 0 | 0.00% |
| 4 | `<std::thread::lifecycle::spawn_unchecked<<arinsal_sched::Scheduler<arinsal_vm::Process>>::build::{closure#9}, ()>::{closure#1} as core::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}` | `arinsal` | 3768 | 99.84% | 0 | 0.00% |
| 5 | `std::sys::backtrace::__rust_begin_short_backtrace::<<arinsal_sched::Scheduler<arinsal_vm::Process>>::build::{closure#9}, ()>` | `arinsal` | 3768 | 99.84% | 1 | 0.03% |
| 6 | `arinsal_sched::run_one::<arinsal_vm::Process>` | `arinsal` | 3761 | 99.66% | 3 | 0.08% |
| 7 | `<arinsal_vm::Process as arinsal_sched::Task>::run` | `arinsal` | 3756 | 99.52% | 1 | 0.03% |
| 8 | `<arinsal_vm::Process>::run_task` | `arinsal` | 3755 | 99.50% | 2 | 0.05% |
| 9 | `<arinsal_vm::process::Executor>::run` | `arinsal` | 3747 | 99.28% | 0 | 0.00% |
| 10 | `arinsal_vm::run_native` | `arinsal` | 3710 | 98.30% | 4 | 0.11% |
| 11 | `???` | `<unknown binary>` | 2573 | 68.18% | 537 | 14.23% |
| 12 | `arinsal_vm::native_hooks::arinsal_beamasm_guard` | `arinsal` | 2169 | 57.47% | 1038 | 27.50% |
| 13 | `_platform_memmove` | `libsystem_platform.dylib` | 947 | 25.09% | 947 | 25.09% |
| 14 | `arinsal_term::ops::exact_eq` | `arinsal` | 750 | 19.87% | 750 | 19.87% |
| 15 | `<arinsal_a64::exec::CodeMemory>::write_bytes` | `arinsal` | 681 | 18.04% | 0 | 0.00% |
| 16 | `__munmap` | `libsystem_kernel.dylib` | 166 | 4.40% | 166 | 4.40% |
| 17 | `core::ptr::drop_glue::<arinsal_a64::exec::CodeMemory>` | `arinsal` | 163 | 4.32% | 0 | 0.00% |
| 18 | `sys_icache_invalidate` | `libsystem_platform.dylib` | 92 | 2.44% | 92 | 2.44% |
| 19 | `mmap` | `libsystem_kernel.dylib` | 77 | 2.04% | 1 | 0.03% |
| 20 | `<arinsal_a64::exec::CodeMemory>::new` | `arinsal` | 76 | 2.01% | 0 | 0.00% |
| 21 | `__mmap` | `libsystem_kernel.dylib` | 76 | 2.01% | 76 | 2.01% |
| 22 | `DYLD-STUB$$memcpy` | `arinsal` | 62 | 1.64% | 62 | 1.64% |
| 23 | `std::sys::env::unix::getenv::{closure#0}` | `arinsal` | 22 | 0.58% | 2 | 0.05% |
| 24 | `getenv` | `libsystem_c.dylib` | 20 | 0.53% | 0 | 0.00% |
| 25 | `__findenv_locked` | `libsystem_c.dylib` | 18 | 0.48% | 18 | 0.48% |

---

## 6. Top 25 Frames by Self Time (Interpreter Run)

Active execution thread (`Thread_28240423`), 3,783 total samples:

| Rank | Symbol (Demangled) | Binary / Module | Self Samples | Self % | Inclusive Samples | Inclusive % |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| 1 | `arinsal_vm::exec_hot` | `arinsal` | 3625 | 95.82% | 3625 | 95.82% |
| 2 | `<arinsal_vm::process::Executor>::run` | `arinsal` | 24 | 0.63% | 3704 | 97.91% |
| 3 | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` | `arinsal` | 23 | 0.61% | 23 | 0.61% |
| 4 | `mach_absolute_time` | `libsystem_kernel.dylib` | 14 | 0.37% | 14 | 0.37% |
| 5 | `<arinsal_vm::Vm>::run_slice_inner` | `arinsal` | 13 | 0.34% | 3639 | 96.19% |
| 6 | `arinsal_sched::run_one::<arinsal_vm::Process>` | `arinsal` | 9 | 0.24% | 3756 | 99.29% |
| 7 | `_xzm_free` | `libsystem_malloc.dylib` | 7 | 0.19% | 8 | 0.21% |
| 8 | `_platform_memmove` | `libsystem_platform.dylib` | 7 | 0.19% | 7 | 0.19% |
| 9 | `pthread_mutex_lock` | `libsystem_pthread.dylib` | 6 | 0.16% | 6 | 0.16% |
| 10 | `arinsal_vm::native_function_for` | `arinsal` | 6 | 0.16% | 6 | 0.16% |
| 11 | `<crossbeam_deque::deque::Worker<arinsal_sched::Scheduled<arinsal_vm::Process>>>::pop` | `arinsal` | 5 | 0.13% | 5 | 0.13% |
| 12 | `_free` | `libsystem_malloc.dylib` | 4 | 0.11% | 4 | 0.11% |
| 13 | `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&usize>` | `arinsal` | 4 | 0.11% | 23 | 0.61% |
| 14 | `<arinsal_vm::Vm>::sync_module` | `arinsal` | 3 | 0.08% | 3 | 0.08% |
| 15 | `<deduplicated_symbol>` | `libsystem_malloc.dylib` | 3 | 0.08% | 3 | 0.08% |
| 16 | `pthread_mutex_unlock` | `libsystem_pthread.dylib` | 3 | 0.08% | 3 | 0.08% |
| 17 | `<arinsal_vm::process::Runtime>::note_status` | `arinsal` | 3 | 0.08% | 5 | 0.13% |
| 18 | `DYLD-STUB$$pthread_mutex_unlock` | `arinsal` | 2 | 0.05% | 2 | 0.05% |
| 19 | `DYLD-STUB$$memcpy` | `arinsal` | 2 | 0.05% | 2 | 0.05% |
| 20 | `<arinsal_vm::Process>::run_task` | `arinsal` | 2 | 0.05% | 3744 | 98.97% |
| 21 | `<hashbrown::map::HashMap<usize, (), std::hash::random::RandomState>>::insert` | `arinsal` | 2 | 0.05% | 17 | 0.45% |
| 22 | `_tlv_get_addr` | `libdyld.dylib` | 2 | 0.05% | 2 | 0.05% |
| 23 | `mach_timebase_info` | `libsystem_kernel.dylib` | 2 | 0.05% | 2 | 0.05% |
| 24 | `<arinsal_sched::timer::Wheel<arinsal_vm::process::Message>>::advance` | `arinsal` | 2 | 0.05% | 2 | 0.05% |
| 25 | `<arinsal_vm::jit_hook::JitHook>::on_entry` | `arinsal` | 1 | 0.03% | 1 | 0.03% |

---

## 7. Top 25 Frames by Inclusive Time (Interpreter Run)

Active execution thread (`Thread_28240423`), 3,783 total samples:

| Rank | Symbol (Demangled) | Binary / Module | Inclusive Samples | Inclusive % | Self Samples | Self % |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| 1 | `thread_start` | `libsystem_pthread.dylib` | 3783 | 100.00% | 0 | 0.00% |
| 2 | `_pthread_start` | `libsystem_pthread.dylib` | 3783 | 100.00% | 0 | 0.00% |
| 3 | `<std::sys::thread::unix::Thread>::new::thread_start` | `arinsal` | 3783 | 100.00% | 0 | 0.00% |
| 4 | `<std::thread::lifecycle::spawn_unchecked<<arinsal_sched::Scheduler<arinsal_vm::Process>>::build::{closure#9}, ()>::{closure#1} as core::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}` | `arinsal` | 3783 | 100.00% | 0 | 0.00% |
| 5 | `std::sys::backtrace::__rust_begin_short_backtrace::<<arinsal_sched::Scheduler<arinsal_vm::Process>>::build::{closure#9}, ()>` | `arinsal` | 3783 | 100.00% | 1 | 0.03% |
| 6 | `arinsal_sched::run_one::<arinsal_vm::Process>` | `arinsal` | 3756 | 99.29% | 9 | 0.24% |
| 7 | `<arinsal_vm::Process as arinsal_sched::Task>::run` | `arinsal` | 3744 | 98.97% | 0 | 0.00% |
| 8 | `<arinsal_vm::Process>::run_task` | `arinsal` | 3744 | 98.97% | 2 | 0.05% |
| 9 | `<arinsal_vm::process::Executor>::run` | `arinsal` | 3704 | 97.91% | 24 | 0.63% |
| 10 | `<arinsal_vm::Vm>::run_slice` | `arinsal` | 3641 | 96.25% | 0 | 0.00% |
| 11 | `<arinsal_vm::Vm>::run_slice_inner` | `arinsal` | 3639 | 96.19% | 13 | 0.34% |
| 12 | `arinsal_vm::exec_hot` | `arinsal` | 3625 | 95.82% | 3625 | 95.82% |
| 13 | `<core::hash::sip::Hasher<core::hash::sip::Sip13Rounds> as core::hash::Hasher>::write` | `arinsal` | 23 | 0.61% | 23 | 0.61% |
| 14 | `<std::hash::random::RandomState as core::hash::BuildHasher>::hash_one::<&usize>` | `arinsal` | 23 | 0.61% | 4 | 0.11% |
| 15 | `<arinsal_sched::Inner<arinsal_vm::Process>>::poll_timers` | `arinsal` | 20 | 0.53% | 1 | 0.03% |
| 16 | `<arinsal_vm::Process>::refresh_code_refs` | `arinsal` | 19 | 0.50% | 0 | 0.00% |
| 17 | `<hashbrown::map::HashMap<usize, (), std::hash::random::RandomState>>::insert` | `arinsal` | 17 | 0.45% | 2 | 0.05% |
| 18 | `<arinsal_sched::RealClock as arinsal_sched::Clock>::now_ms` | `arinsal` | 17 | 0.45% | 0 | 0.00% |
| 19 | `<std::sys::pal::unix::time::Timespec>::now` | `arinsal` | 17 | 0.45% | 0 | 0.00% |
| 20 | `clock_gettime` | `libsystem_c.dylib` | 17 | 0.45% | 0 | 0.00% |
| 21 | `clock_gettime_nsec_np` | `libsystem_c.dylib` | 16 | 0.42% | 0 | 0.00% |
| 22 | `mach_absolute_time` | `libsystem_kernel.dylib` | 14 | 0.37% | 14 | 0.37% |
| 23 | `_xzm_free` | `libsystem_malloc.dylib` | 8 | 0.21% | 7 | 0.19% |
| 24 | `<arinsal_vm::process::Runtime>::is_hibernating` | `arinsal` | 7 | 0.19% | 1 | 0.03% |
| 25 | `_platform_memmove` | `libsystem_platform.dylib` | 7 | 0.19% | 7 | 0.19% |

---

## 8. Root Cause Analysis (Hypotheses Supported by Code Inspection)

Based on the quantitative profile data and codebase examination, two distinct mechanisms explain why JIT execution of `kernels:tail` (19.5 ns/iteration) is more than 2x slower than the bytecode interpreter (8.6 ns/iteration):

### Hypothesis 1: Guard Helper Trampoline Invoked on Every Non-Terminating Iteration
- **Bytecode:** The counting loop `tail_loop/2` in `kernels.erl` begins with:
  ```erlang
  tail_loop(0, Sum) -> Sum;
  tail_loop(N, Sum) -> tail_loop(N - 1, Sum + 1).
  ```
  The compiler translates this to:
  `{test, is_eq_exact, {f, 5}, [{x, 0}, {integer, 0}]}`.
- **JIT Codegen (`crates/beamasm/src/guard.rs:453-482`):**
  `emit_comparison` compiles `is_eq_exact` with `equal_result = true` as follows:
  ```rust
  self.code.emit(|e| e.cmp_reg(Gpr::x(11), Gpr::x(12), Shift::Lsl, 0))?;
  if equal_result {
      self.code.b_cond(Cond::Ne, slow)?;  // <-- BRANCHES TO SLOW PATH WHEN X0 != 0
      self.code.b(done)?;
  }
  self.code.bind(slow)?;
  self.emit_guard_helper(op, lhs, rhs, fail, runtime)?;
  ```
- **Consequence:** For 399,999,999 out of 400,000,000 iterations, $N \neq 0$, so `Cond::Ne` is true. The generated native code branches to `slow` and issues a foreign C-ABI call (`blr`) into the Rust runtime helper `arinsal_beamasm_guard` on **every single iteration**.
- **Helper Cost:** Inside `arinsal_beamasm_guard` (`crates/vm/src/native_hooks.rs:292`), the helper marshals registers, copies arguments, calls `exact_eq(N, 0)`, and performs memory copies. This accounts for **58.20%** of total CPU self time (`arinsal_beamasm_guard` 27.50% + `exact_eq` 19.87% + helper `memmove`/`memcpy` 10.83%).
- **Contrast with Interpreter:** The interpreter (`crates/vm/src/compare.rs:47`) executes:
  `pub fn eq_exact(a: Term, b: Term) -> bool { a == b || slow_exact_eq(a, b) }`.
  Because both operands are immediate small integers with tag bits, `a == b` is an inlined, single-instruction 64-bit integer equality check that directly evaluates to `false` and branches to the next instruction without a function call.

### Hypothesis 2: Ephemeral `CodeMemory` Allocation and I-Cache Flushing in `run_native`
- **Native Invocation Bridge (`crates/vm/src/lib.rs:185-194`):**
  Every time a process is scheduled to enter or resume native code, `run_native` dynamically constructs a 2-instruction entry veneer (`mov x17, code_addr; br x17`) using `CodeMemory::new`:
  ```rust
  let mut veneer_memory = arinsal_a64::exec::CodeMemory::new(veneer_bytes.len().max(4))?;
  let veneer_offset = veneer_memory.alloc(veneer_bytes.len().max(4))?;
  veneer_memory.write_bytes(veneer_offset, &veneer_bytes)
      .and_then(|()| veneer_memory.flush_all())?;
  ```
- **Yield Lifecycle:** The counting loop decrements reductions and periodically yields to the scheduler (`ExitReason::Yield`). Upon yield, `veneer_memory` is dropped, issuing a `__munmap` system call. On the next scheduling quantum, `run_native` issues another `mmap` system call, sets page write permissions, and flushes CPU instruction caches (`sys_icache_invalidate`).
- **Consequence:** Across 400,000,000 loop iterations, thousands of reduction yields cause repeated kernel context switches for page mapping, unmapping, and CPU instruction cache invalidation.
- **Cost:** This lifecycle accounts for **24.48%** inclusive time and **8.88%** self time (`__mmap` 2.01%, `sys_icache_invalidate` 2.44%, `__munmap` 4.40%).

---

## 9. Reproduction

To reproduce these measurements:

```bash
# Build the release binary and run the profiling suite
./tools/jit_profile/run.sh

# Or inspect individual sample files using the standalone analyzer
python3 tools/jit_profile/analyze.py tools/jit_profile/samples/jit_tail.sample
python3 tools/jit_profile/analyze.py tools/jit_profile/samples/interp_tail.sample
```
