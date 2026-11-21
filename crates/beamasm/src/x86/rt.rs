//! Audited native runtime transition core on x86-64: the native exit fragment's fixed
//! address and the trace return addresses.
//!
//! The scheduler loop is erts' generated `process_main` (`x86::process_main`): it allocates
//! the register file on the scheduler thread's C stack, so every `emit_enter_runtime`
//! switches to the runtime stack with `lea rsp, [registers + runtime_stack]`, as erts.
//!
//! Deviation (Step D of the generated_process_main plan): the exit fragment
//! `arinsal_enter_native_return` is a CP erts does not have. The Rust slice running inside
//! `erts_schedule` enters functions with it as their return address and reads the exit kind
//! `process_main` leaves in `tmp_mem[3]` ([`take_native_exit`]).

use crate::{ExitReason, ProcessHeader, RUNTIME_STACK_DISP, SchedulerRegisters, tmp_mem_disp};
use core::ffi::c_void;

/// Code address of an erts runtime symbol for BeamAsm `runtime_call`.
///
/// `f` is an `extern "C"` function item coerced to `*const ()` at the call site. This does
/// not call the function; generated code calls the C symbol.
#[inline(always)]
pub fn addr(f: *const ()) -> usize {
    f as usize
}

// The pointer exposes the fixed C-layout prefix; trailing BIF bookkeeping is Rust-only.
#[allow(improper_ctypes)]
unsafe extern "C" {
    /// The native exit fragment (see the module documentation); forwards to the fragment
    /// `process_main` emits.
    pub fn arinsal_enter_native_return();
    /// erts `beam_return_trace`: the return address of a return_trace frame.
    pub fn arinsal_return_trace();
    /// erts `beam_exception_trace`: the return address of an exception_trace frame.
    pub fn arinsal_exception_trace();
    /// erts `beam_return_to_trace`: the return address of a return_to frame.
    pub fn arinsal_return_to_trace();
    /// erts `beam_call_trace_return`: the return address of a call time/memory frame.
    pub fn arinsal_call_trace_return();
    /// `Process *erts_schedule(ErtsSchedulerData *esdp, Process *p, int calls)` (VM), the
    /// call at `schedule_next` of `process_main`.
    pub fn erts_schedule(
        esdp: *mut c_void,
        p: *mut ProcessHeader,
        calls: i32,
    ) -> *mut ProcessHeader;
}

/// The exit of the native code `process_main` jumped to last, left in the register file at
/// `schedule_next`; consumed.
pub fn take_native_exit(regs: &mut SchedulerRegisters) -> ExitReason {
    match core::mem::take(&mut regs.tmp_mem[3]) {
        1 => ExitReason::Returned,
        3 => ExitReason::CallUnported {
            target_pc: regs.tmp_mem[0] as usize,
            resume_pc: regs.tmp_mem[1] as usize,
        },
        _ => ExitReason::Yield,
    }
}

/// The native exit fragment `process_main` emitted, which `arinsal_enter_native_return`
/// jumps to.
static PROCESS_MAIN_NATIVE_EXIT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Publishes the native exit fragment of the emitted `process_main`
/// (`BeamGlobalAssembler::native_exit_ptr`).
pub fn set_process_main_labels(native_exit: usize) {
    PROCESS_MAIN_NATIVE_EXIT.store(native_exit, core::sync::atomic::Ordering::Release);
}

// Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1136 (get_on_load_address), OTP-29.1.1.
// The VM exports this static erts helper's C symbol to generated code.
unsafe extern "C" {
    /// `ErtsCodePtr get_on_load_address(Process *, Eterm)`.
    pub fn get_on_load_address(c_p: *mut crate::ProcessHeader, module: u64) -> usize;
}

// Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:28-32 (`extern "C" { #include
// "bif.h" #include "beam_common.h" }`) and erl_gc.h, OTP-29.1.1: the runtime functions the
// fragments of this file call by address (`runtime_call`). They are defined with these erts
// names and C signatures by the VM (docs/design/jit_runtime_symbols.md); fragments take their
// address with `addr(f as *const ())`. The declarations live in this raw module (`unsafe
// extern`); `beam_asm_global` re-exports them.
unsafe extern "C" {
    /// `ErtsCodePtr handle_error(Process *c_p, ErtsCodePtr pc, Eterm *reg,
    /// const ErtsCodeMFA *bif_mfa)` (beam_common.h): the handler to continue at, or null.
    pub fn handle_error(
        c_p: *mut crate::ProcessHeader,
        pc: usize,
        reg: *mut u64,
        bif_mfa: *const arinsal_term::ErtsCodeMfa,
    ) -> usize;
    /// `const Export *call_error_handler(Process *p, const ErtsCodeMFA *mfa, Eterm *reg,
    /// Eterm func)` (beam_common.h): the `Export` address, or null. `Export` is read only by
    /// native code, so it crosses as an address.
    pub fn call_error_handler(
        c_p: *mut crate::ProcessHeader,
        mfa: *const arinsal_term::ErtsCodeMfa,
        reg: *mut u64,
        func: u64,
    ) -> usize;
    /// `ErtsCodeIndex the_active_code_index` (code_ix.h): the node's active code index,
    /// read by `emit_leave_runtime<eCodeIndex>`.
    pub safe static the_active_code_index: u32;
    /// `int erts_garbage_collect_nobump(Process *p, Uint need, Eterm *objv, int nobj,
    /// int fcalls)` (erl_gc.h:171): reductions spent.
    pub fn erts_garbage_collect_nobump(
        c_p: *mut crate::ProcessHeader,
        need: usize,
        objv: *mut u64,
        nobj: i32,
        fcalls: i32,
    ) -> i32;
}

// Port of erts/emulator/beam/jit/x86/instr_bif.cpp runtime-call declarations (erl_gc.h),
// OTP-29.1.1.
unsafe extern "C" {
    /// `Eterm erts_gc_after_bif_call_lhf(Process *p, ErlHeapFragment *live_hf_end,
    /// Eterm result, Eterm *regs, Uint arity)` (erl_gc.h): collects after a BIF whose result
    /// left a collection desired; `live_hf_end` is `c_p->mbuf` before the call.
    pub fn erts_gc_after_bif_call_lhf(
        c_p: *mut crate::ProcessHeader,
        live_hf_end: usize,
        result: u64,
        regs: *mut u64,
        arity: u64,
    ) -> u64;
}

// Port of erts/emulator/beam/jit/x86/instr_arith.cpp runtime-call declarations, OTP-29.1.1.
unsafe extern "C" {
    /// `Eterm erts_band(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_band(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bnot(Process *p, Eterm arg)`.
    pub fn erts_bnot(c_p: *mut crate::ProcessHeader, arg: u64) -> u64;
    /// `Eterm erts_bor(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bor(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bsl(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bsl(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bsr(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bsr(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bxor(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bxor(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `int erts_int_div_rem(Process *p, Eterm arg1, Eterm arg2, Eterm *q, Eterm *r)`.
    pub fn erts_int_div_rem(
        c_p: *mut crate::ProcessHeader,
        arg1: u64,
        arg2: u64,
        quotient: *mut u64,
        remainder: *mut u64,
    ) -> i32;
    /// `Eterm erts_mixed_div(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_div(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_minus(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_minus(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_plus(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_plus(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_times(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_times(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mul_add(Process *p, Eterm arg1, Eterm arg2, Eterm arg3, Eterm *pp)`.
    pub fn erts_mul_add(
        c_p: *mut crate::ProcessHeader,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        result: *mut u64,
    ) -> u64;
    /// `Eterm erts_unary_minus(Process *p, Eterm arg1)`.
    pub fn erts_unary_minus(c_p: *mut crate::ProcessHeader, arg1: u64) -> u64;
}

// Port of erts/emulator/beam/jit/x86/instr_float.cpp (`extern "C" { #include "big.h" }`),
// OTP-29.1.1: `big_to_double` writes the converted float to TMP_MEM1.
unsafe extern "C" {
    /// `int big_to_double(Eterm x, double *resp)` (big.h).
    pub fn big_to_double(x: u64, resp: *mut f64) -> i32;
}

// Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp (`erl_utils.h`), OTP-29.1.1:
// exact comparison runtime function called by address. The map lookup declaration is shared
// with instr_map below.
unsafe extern "C" {
    /// `int eq(Eterm a, Eterm b)` (erl_utils.h / utils.c).
    pub fn eq(a: u64, b: u64) -> i32;
}

// Port of erts/emulator/beam/erl_process_dict.h, erl_bif_op.h, erl_utils.h and
// erts/emulator/sys/{unix/erl_unix_sys.h,win32/erl_win_sys.h}: runtime calls and the
// perf-counter callback table consumed by instr_common.cpp, OTP-29.1.1.
unsafe extern "C" {
    /// `Eterm erts_pd_hash_get(Process *p, Eterm id)` (erl_process_dict.h).
    pub fn erts_pd_hash_get(c_p: *mut crate::ProcessHeader, id: u64) -> u64;
    /// `Eterm erts_pd_hash_get_with_hx(Process *p, erts_ihash_t hx, Eterm id)`
    /// (erl_process_dict.h); `erts_ihash_t` is a machine word.
    pub fn erts_pd_hash_get_with_hx(c_p: *mut crate::ProcessHeader, hx: u64, id: u64) -> u64;
    /// `Eterm erl_is_function(Process *p, Eterm term, Eterm arity)` (erl_bif_op.h).
    pub fn erl_is_function(c_p: *mut crate::ProcessHeader, term: u64, arity: u64) -> u64;
    /// `Sint erts_cmp_compound(Eterm a, Eterm b, int exact, int eq_only)` (utils.h).
    pub fn erts_cmp_compound(a: u64, b: u64, exact: i32, eq_only: i32) -> i64;
    /// `int erts_cmp_atoms(Eterm a, Eterm b)` (erl_utils.h).
    pub fn erts_cmp_atoms(a: u64, b: u64) -> i32;
}

/// The perf-counter function table in erts' `ErtsSysTimeData__`.
// Port of erts/emulator/sys/unix/erl_unix_sys.h:215-245, OTP-29.1.1.
#[cfg(not(target_os = "windows"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErtsSysTimeReadOnlyData {
    #[cfg(target_os = "linux")]
    /// `os_monotonic_time`, present when Linux uses the runtime function-pointer call path.
    pub os_monotonic_time: extern "C" fn() -> u64,
    #[cfg(target_os = "linux")]
    /// `os_times`, present when Linux uses the runtime function-pointer call path.
    pub os_times: extern "C" fn(*mut u64, *mut u64),
    /// `perf_counter`.
    pub perf_counter: extern "C" fn() -> u64,
    /// `perf_counter_unit`.
    pub perf_counter_unit: u64,
    /// `ticks_per_sec`.
    pub ticks_per_sec: i32,
}

/// The perf-counter function table in erts' Windows `ErtsSysTimeData__`.
// Port of erts/emulator/sys/win32/erl_win_sys.h:185-201, OTP-29.1.1.
#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErtsSysTimeReadOnlyData {
    /// `os_monotonic_time`.
    pub os_monotonic_time: extern "C" fn() -> u64,
    /// `os_times`.
    pub os_times: extern "C" fn(*mut u64, *mut u64),
    /// `sys_hrtime`, the perf counter on Windows.
    pub sys_hrtime: extern "C" fn() -> u64,
}

/// The cache-line-sized `r` union in erts' `ErtsSysTimeData__`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union ErtsSysTimeDataReadOnly {
    /// The initialized read-only time callbacks.
    pub o: ErtsSysTimeReadOnlyData,
    /// The erts cache-line alignment member.
    pub align: [u8; 64],
}

/// The `r` member of `ErtsSysTimeData__`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErtsSysTimeData {
    /// The callback table union.
    pub r: ErtsSysTimeDataReadOnly,
}

unsafe extern "C" {
    /// `ErtsSysTimeData__ erts_sys_time_data__` (erl_unix_sys.h / erl_win_sys.h).
    pub safe static erts_sys_time_data__: ErtsSysTimeData;
}

/// Returns the initialized callback address embedded by `i_perf_counter`.
pub fn perf_counter_address() -> usize {
    // SAFETY: BeamAsm compiles modules only after erts initializes this process-lifetime table;
    // the target-specific C-layout declarations above select the same callback member as
    // instr_common.cpp (`perf_counter` on Unix, `sys_hrtime` on Windows).
    unsafe {
        #[cfg(target_os = "windows")]
        {
            addr(erts_sys_time_data__.r.o.sys_hrtime as *const ())
        }
        #[cfg(not(target_os = "windows"))]
        {
            addr(erts_sys_time_data__.r.o.perf_counter as *const ())
        }
    }
}

// Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:397-399 (i_emit_nyi) and
// erts/emulator/beam/beam_catches.h:38 (beam_catches_cons), OTP-29.1.1. erts defines
// `i_emit_nyi` static in beam_asm_module.cpp around `erts_exit(ERTS_ERROR_EXIT, "NYI: %s\n",
// msg)`; `erts_exit` belongs to the VM, which therefore defines the symbol. `beam_catches_cons`
// is called by the loader side of `patchCatches`. `beam_asm_module` re-exports both.
unsafe extern "C" {
    /// `static void i_emit_nyi(char *msg)`: halts the emulator with `NYI: <msg>`.
    pub fn i_emit_nyi(msg: *const core::ffi::c_char);
    /// `unsigned beam_catches_cons(ErtsCodePtr cp, unsigned cdr, ErtsCodePtr **)`: a new
    /// catch index for the handler `cp`, chained to `cdr`.
    pub fn beam_catches_cons(cp: usize, cdr: u32, cdrpp: *mut *mut usize) -> u32;
}

/// `patchCatches` (`beam_jit_common.cpp:506-531`): `beam_catches_cons(cp, cdr, NULL)`.
pub fn beam_catches_cons_nil(cp: usize, cdr: u32) -> u32 {
    // SAFETY: erts `patchCatches` passes a null `cdrpp`; the VM owns the catch table.
    unsafe { beam_catches_cons(cp, cdr, core::ptr::null_mut()) }
}

// Port of erts/emulator/beam/jit/x86/instr_common.cpp and instr_call.cpp (`extern "C" {
// #include "beam_common.h" }`), OTP-29.1.1: the beam_common.h functions their global fragments
// call by address. `instr_common` and `instr_call` re-export them.
unsafe extern "C" {
    /// `Eterm add_stacktrace(Process *c_p, Eterm Value, Eterm exc)` (beam_common.h).
    pub fn add_stacktrace(c_p: *mut crate::ProcessHeader, value: u64, exc: u64) -> u64;
    /// `void erts_sanitize_freason(Process *c_p, Eterm exc)` (beam_common.h).
    pub fn erts_sanitize_freason(c_p: *mut crate::ProcessHeader, exc: u64);
    /// `void save_calls(Process *p, const Export *)` (beam_common.h). `Export` crosses as an
    /// address, as for `call_error_handler`.
    pub fn save_calls(c_p: *mut crate::ProcessHeader, export: usize);
    /// `const Export *fixed_apply(Process *p, Eterm *reg, Uint arity, ErtsCodePtr I,
    /// Uint flags)` (beam_common.h); the export address, or null after setting the process
    /// exception.
    pub fn fixed_apply(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        arity: u64,
        i: usize,
        flags: u64,
    ) -> usize;
    /// `const Export *apply(Process *p, Eterm *reg, ErtsCodePtr I, Uint flags)`
    /// (beam_common.h); the export address, or null after setting the process exception.
    pub fn apply(c_p: *mut crate::ProcessHeader, reg: *mut u64, i: usize, flags: u64) -> usize;
}

// Port of erts/emulator/beam/jit/x86/instr_common.cpp runtime declarations, OTP-29.1.1.
unsafe extern "C" {
    /// `int raw_raise(Eterm stacktrace, Eterm exc_class, Eterm value, Process *c_p)`
    /// (beam_common.h).
    pub fn raw_raise(
        stacktrace: u64,
        exc_class: u64,
        value: u64,
        c_p: *mut crate::ProcessHeader,
    ) -> i32;
    /// `Eterm build_stacktrace(Process *c_p, Eterm exc)` (global.h).
    pub fn build_stacktrace(c_p: *mut crate::ProcessHeader, exc: u64) -> u64;
    /// `void erts_do_exit_process(Process *p, Eterm reason)` (erl_process.h).
    pub fn erts_do_exit_process(c_p: *mut crate::ProcessHeader, reason: u64);
    /// `void erts_continue_exit_process(Process *p)` (erl_process.h).
    pub fn erts_continue_exit_process(c_p: *mut crate::ProcessHeader);
}

// Port of erts/emulator/beam/jit/x86/instr_records.cpp and instr_trace.cpp runtime-call
// declarations, OTP-29.1.1. These helpers are part of the BeamAsm runtime ABI.
unsafe extern "C" {
    /// `bool erl_get_record_elements(Process *, Eterm *, Eterm, Uint, const Eterm *)`.
    pub fn erl_get_record_elements(
        c_p: *mut crate::ProcessHeader,
        registers: *mut u64,
        source: u64,
        count: usize,
        elements: *const u64,
    ) -> bool;
    /// `Eterm erl_create_local_native_record(Process *, Eterm *, Eterm, Uint, Uint, const Eterm *)`.
    pub fn erl_create_local_native_record(
        c_p: *mut crate::ProcessHeader,
        registers: *mut u64,
        definition: u64,
        live: u64,
        count: usize,
        elements: *const u64,
    ) -> u64;
    /// `Eterm erl_create_native_record(Process *, Eterm *, Eterm, Uint, Uint, const Eterm *)`.
    pub fn erl_create_native_record(
        c_p: *mut crate::ProcessHeader,
        registers: *mut u64,
        definition_id: u64,
        live: u64,
        count: usize,
        elements: *const u64,
    ) -> u64;
    /// `Eterm erl_update_native_record(Process *, Eterm *, Eterm, Uint, Uint, const Eterm *)`.
    pub fn erl_update_native_record(
        c_p: *mut crate::ProcessHeader,
        registers: *mut u64,
        source: u64,
        live: u64,
        count: usize,
        elements: *const u64,
    ) -> u64;
    /// `Eterm erl_get_local_record_field(Process *, Eterm, Eterm, Eterm)`.
    pub fn erl_get_local_record_field(
        c_p: *mut crate::ProcessHeader,
        source: u64,
        definition_id: u64,
        name: u64,
    ) -> u64;
    /// `Eterm erl_get_record_field(Process *, Eterm, Eterm, Eterm)`.
    pub fn erl_get_record_field(
        c_p: *mut crate::ProcessHeader,
        source: u64,
        definition_id: u64,
        name: u64,
    ) -> u64;
    /// `void erts_call_trace_return(Process *, const ErtsCodeInfo *, Eterm, Eterm)`.
    pub fn erts_call_trace_return(
        c_p: *mut crate::ProcessHeader,
        previous_info: *const core::ffi::c_void,
        value: u64,
        tracer: u64,
    );
    /// `void erts_trace_return(Process *, ErtsCodeMFA *, Eterm, ErtsTracer, Eterm)`.
    pub fn erts_trace_return(
        c_p: *mut crate::ProcessHeader,
        mfa: *mut arinsal_term::ErtsCodeMfa,
        value: u64,
        tracer: u64,
        session_id: u64,
    );
    /// `void erts_hibernate(Process *, Eterm *, int)`.
    pub fn erts_hibernate(c_p: *mut crate::ProcessHeader, registers: *mut u64, arg: i32);
    /// `void beam_jit_return_to_trace(Process *, Eterm, Eterm *)`.
    pub fn beam_jit_return_to_trace(
        c_p: *mut crate::ProcessHeader,
        session_id: u64,
        continuation: *mut u64,
    );
}

/// The runtime wrapper around `erts_trace_return` used by the static helper in erts.
///
/// # Safety
/// Generated code calls this with the live process and the return-trace frame; the same
/// contract as erts `return_trace` in instr_trace.cpp.
// Port of erts/emulator/beam/jit/x86/instr_trace.cpp:172-180 (return_trace), OTP-29.1.1.
pub unsafe extern "C" fn return_trace(
    c_p: *mut crate::ProcessHeader,
    mfa: *mut arinsal_term::ErtsCodeMfa,
    value: u64,
    tracer: u64,
    session_id: u64,
) {
    // `ERTS_UNREQ_PROC_MAIN_LOCK` / `ERTS_REQ_PROC_MAIN_LOCK` compile to no-ops in release
    // builds without ERTS_ENABLE_LOCK_CHECK, which is the runtime this assembler emits for.
    // SAFETY: generated code calls this with the live process and the return-trace frame.
    unsafe { erts_trace_return(c_p, mfa, value, tracer, session_id) }
}

// Port of erts/emulator/beam/jit/x86/instr_bif.cpp runtime-call declarations, OTP-29.1.1.
unsafe extern "C" {
    /// `Eterm erts_trapping_length_1(Process *, Eterm *)`.
    pub fn erts_trapping_length_1(c_p: *mut crate::ProcessHeader, args: *mut u64) -> u64;
    /// `ErtsCodeMFA *ubif2mfa(void *)`.
    pub fn ubif2mfa(function: *const core::ffi::c_void) -> *const arinsal_term::ErtsCodeMfa;
    /// `ErtsCodePtr erts_call_nif_early(Process *, const ErtsCodeInfo *)`.
    pub fn erts_call_nif_early(
        c_p: *mut crate::ProcessHeader,
        code_info: *const crate::common::beam_asm_h::ErtsCodeInfo,
    ) -> usize;
    /// `ErtsCodePtr erts_printable_return_address(const Process *, const Eterm *)`.
    pub fn erts_printable_return_address(
        c_p: *const crate::ProcessHeader,
        stack: *const u64,
    ) -> usize;
    /// `Eterm beam_jit_call_bif(Process *, Eterm *, ErtsCodePtr, ErtsBifFunc, Uint)`.
    pub fn beam_jit_call_bif(
        c_p: *mut crate::ProcessHeader,
        registers: *mut u64,
        instruction: usize,
        function: usize,
        arity: usize,
    ) -> u64;
    /// `Eterm beam_jit_call_nif(Process *, ErtsCodePtr, Eterm *, BeamJitNifF *, erl_module_nif *)`.
    pub fn beam_jit_call_nif(
        c_p: *mut crate::ProcessHeader,
        instruction: usize,
        registers: *mut u64,
        function: usize,
        module: usize,
    ) -> u64;
    /// `enum beam_jit_nif_load_ret beam_jit_load_nif(Process *, ErtsCodePtr, Eterm *)`.
    pub fn beam_jit_load_nif(
        c_p: *mut crate::ProcessHeader,
        instruction: usize,
        registers: *mut u64,
    ) -> i32;
    /// `int erts_alcu_enable_code_atags`.
    pub safe static erts_alcu_enable_code_atags: i32;
}

// Port of erts/emulator/beam/jit/beam_jit_common.hpp, OTP-29.1.1: the JIT-only runtime
// helpers of jit/beam_jit_common.cpp the x86 fragments call by address. `instr_fun` re-exports
// them.
unsafe extern "C" {
    /// `const Export *beam_jit_handle_unloaded_fun(Process *c_p, Eterm *reg, int arity,
    /// Eterm fun_thing, ErtsCodeIndex code_ix)`: the export to call, or null with
    /// `c_p->freason` set. `Export` crosses as an address.
    pub fn beam_jit_handle_unloaded_fun(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        arity: i32,
        fun_thing: u64,
        code_ix: u32,
    ) -> usize;
    /// `Eterm beam_jit_build_argument_list(Process *c_p, const Eterm *regs, int arity)`.
    pub fn beam_jit_build_argument_list(
        c_p: *mut crate::ProcessHeader,
        regs: *const u64,
        arity: i32,
    ) -> u64;
}

// Port of erts/emulator/beam/jit/beam_jit_common.hpp, global.h and beam_bp.h, OTP-29.1.1:
// runtime entries called by the x86 BIF, NIF and export-breakpoint fragments.
unsafe extern "C" {
    /// `BeamInstr erts_generic_breakpoint(Process *, ErtsCodeInfo *, Eterm *)`.
    pub fn erts_generic_breakpoint(
        c_p: *mut crate::ProcessHeader,
        code_info: *mut crate::common::beam_asm_h::ErtsCodeInfo,
        reg: *mut u64,
    ) -> usize;
    /// `int erts_call_dirty_nif(ErtsSchedulerData *, Process *, ErtsCodePtr, const Eterm *)`.
    pub fn erts_call_dirty_nif(
        scheduler_data: *mut c_void,
        c_p: *mut crate::ProcessHeader,
        instruction: usize,
        reg: *const u64,
    ) -> i32;
}

// Port of erts/emulator/beam/jit/x86/instr_bs.cpp (`extern "C" { #include "erl_binary.h"
// #include "erl_bits.h" #include "beam_common.h" }` and the beam_jit_bs_* helpers of
// jit/beam_jit_common.hpp), OTP-29.1.1: the runtime functions the bit syntax emitters and
// fragments call by address. `ErlSubBits *` and `const BinRef *` cross as addresses (native
// code only passes them on); `instr_bs` re-exports them.
unsafe extern "C" {
    /// `void beam_jit_bs_field_size_argument_error(Process *c_p, Eterm size)`
    /// (beam_jit_common.hpp).
    pub fn beam_jit_bs_field_size_argument_error(c_p: *mut crate::ProcessHeader, size: u64);
    /// `Eterm beam_jit_bs_get_integer(Process *c_p, Eterm *reg, Eterm context, Uint flags,
    /// Uint size, Uint Live)` (beam_jit_common.hpp).
    pub fn beam_jit_bs_get_integer(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        context: u64,
        flags: u64,
        size: u64,
        live: u64,
    ) -> u64;
    /// `void beam_jit_bs_construct_fail_info(Process *c_p, Uint packed_error_info,
    /// Eterm arg3, Eterm arg1)` (beam_jit_common.hpp).
    pub fn beam_jit_bs_construct_fail_info(
        c_p: *mut crate::ProcessHeader,
        packed_error_info: u64,
        arg3: u64,
        arg1: u64,
    );
    /// `Eterm beam_jit_bs_init_bits(Process *c_p, Eterm *reg, struct erl_bits_state *EBS,
    /// Uint num_bits, Uint alloc, unsigned Live)` (beam_jit_common.hpp).
    pub fn beam_jit_bs_init_bits(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        ebs: *mut u64,
        num_bits: u64,
        alloc: u64,
        live: u32,
    ) -> u64;
    /// `ErlSubBits *erts_bs_start_match_3(Process *p, Eterm Bin)` (erl_bits.h).
    pub fn erts_bs_start_match_3(c_p: *mut crate::ProcessHeader, bin: u64) -> usize;
    /// `Eterm erts_bs_get_integer_2(Process *p, Uint num_bits, unsigned flags,
    /// ErlSubBits *sb)` (erl_bits.h).
    pub fn erts_bs_get_integer_2(
        c_p: *mut crate::ProcessHeader,
        num_bits: u64,
        flags: u32,
        sb: usize,
    ) -> u64;
    /// `Eterm erts_bs_get_float_2(Process *p, Uint num_bits, unsigned flags,
    /// ErlSubBits *sb)` (erl_bits.h).
    pub fn erts_bs_get_float_2(
        c_p: *mut crate::ProcessHeader,
        num_bits: u64,
        flags: u32,
        sb: usize,
    ) -> u64;
    /// `Eterm erts_bs_get_binary_2(Process *p, Uint num_bits, ErlSubBits *sb)` (erl_bits.h).
    pub fn erts_bs_get_binary_2(c_p: *mut crate::ProcessHeader, num_bits: u64, sb: usize) -> u64;
    /// `Eterm erts_bs_get_utf8(ErlSubBits *sb)` (erl_bits.h).
    pub fn erts_bs_get_utf8(sb: usize) -> u64;
    /// `Eterm erts_bs_get_utf16(ErlSubBits *sb, Uint flags)` (erl_bits.h).
    pub fn erts_bs_get_utf16(sb: usize, flags: u64) -> u64;
    /// `Eterm erts_bs_init_writable(Process *p, Eterm sz)` (erl_bits.h).
    pub fn erts_bs_init_writable(c_p: *mut crate::ProcessHeader, sz: u64) -> u64;
    /// `int erts_cmp_bits(const byte *a_ptr, Uint a_offs, const byte *b_ptr, Uint b_offs,
    /// Uint size)` (erl_bits.h).
    pub fn erts_cmp_bits(
        a_ptr: *const u8,
        a_offs: u64,
        b_ptr: *const u8,
        b_offs: u64,
        size: u64,
    ) -> i32;
    /// `Eterm erts_build_sub_bitstring(Eterm **hp, Eterm br_flags, const BinRef *br,
    /// const byte *base, Uint offset, Uint size)` (erl_bits.h).
    pub fn erts_build_sub_bitstring(
        hp: *mut *mut u64,
        br_flags: u64,
        br: usize,
        base: *const u8,
        offset: u64,
        size: u64,
    ) -> u64;
}

// Port of erts/emulator/beam/jit/x86/instr_bs.cpp (emit_i_bs_create_bin), OTP-29.1.1.
// These are the erts bit-syntax construction entry points addressed by `runtime_call`.
unsafe extern "C" {
    /// `Eterm erts_bs_append_checked(Process *p, Eterm *reg, Uint live, Uint size,
    /// Uint extra_words, Uint unit)` (erl_bits.h).
    pub fn erts_bs_append_checked(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        size: u64,
        extra_words: u64,
        unit: u64,
    ) -> u64;
    /// `Eterm erts_bs_private_append_checked(ErlBitsState *EBS, Process *p, Eterm bin,
    /// Uint size)` (erl_bits.h).
    pub fn erts_bs_private_append_checked(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        bin: u64,
        size: u64,
    ) -> u64;
    /// `int erts_bs_put_binary(ErlBitsState *EBS, Process *p, Eterm bin, Uint num_bits)`
    /// (erl_bits.h).
    pub fn erts_bs_put_binary(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        bin: u64,
        num_bits: u64,
    ) -> i32;
    /// `int erts_bs_put_binary_all(ErlBitsState *EBS, Process *p, Eterm bin, Uint unit)`
    /// (erl_bits.h).
    pub fn erts_bs_put_binary_all(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        bin: u64,
        unit: u64,
    ) -> i32;
    /// `void beam_jit_bs_put_binary_all(ErlBitsState *EBS, Process *p, Eterm bin)`
    /// (beam_jit_common.hpp).
    pub fn beam_jit_bs_put_binary_all(ebs: *mut u64, c_p: *mut crate::ProcessHeader, bin: u64);
    /// `Eterm erts_bs_put_float(ErlBitsState *EBS, Process *p, Eterm float, Uint num_bits,
    /// int flags)` (erl_bits.h).
    pub fn erts_bs_put_float(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        float: u64,
        num_bits: u64,
        flags: i32,
    ) -> u64;
    /// `int erts_bs_put_integer_be(ErlBitsState *EBS, Eterm integer, Uint num_bits)`
    /// (erl_bits.h).
    pub fn erts_bs_put_integer_be(ebs: *mut u64, integer: u64, num_bits: u64) -> i32;
    /// `int erts_bs_put_integer_le(ErlBitsState *EBS, Eterm integer, Uint num_bits)`
    /// (erl_bits.h).
    pub fn erts_bs_put_integer_le(ebs: *mut u64, integer: u64, num_bits: u64) -> i32;
    /// `int erts_bs_put_utf16(ErlBitsState *EBS, Eterm integer, Uint flags)` (erl_bits.h).
    pub fn erts_bs_put_utf16(ebs: *mut u64, integer: u64, flags: u64) -> i32;
    /// `void erts_bs_put_string(ErlBitsState *EBS, byte *iptr, Uint num_bytes)` (erl_bits.h).
    pub fn erts_bs_put_string(ebs: *mut u64, string: *const u8, num_bytes: u64);
}

// These link-only entry points let the code emitter tests run without linking the VM.
#[cfg(test)]
#[allow(unsafe_code)]
mod bs_create_bin_test_symbols {
    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_append_checked(
        _c_p: *mut crate::ProcessHeader,
        _reg: *mut u64,
        _live: u64,
        _size: u64,
        _extra_words: u64,
        _unit: u64,
    ) -> u64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_private_append_checked(
        _ebs: *mut u64,
        _c_p: *mut crate::ProcessHeader,
        _bin: u64,
        _size: u64,
    ) -> u64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_put_binary(
        _ebs: *mut u64,
        _c_p: *mut crate::ProcessHeader,
        _bin: u64,
        _num_bits: u64,
    ) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_put_binary_all(
        _ebs: *mut u64,
        _c_p: *mut crate::ProcessHeader,
        _bin: u64,
        _unit: u64,
    ) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn beam_jit_bs_put_binary_all(
        _ebs: *mut u64,
        _c_p: *mut crate::ProcessHeader,
        _bin: u64,
    ) {
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_put_float(
        _ebs: *mut u64,
        _c_p: *mut crate::ProcessHeader,
        _float: u64,
        _num_bits: u64,
        _flags: i32,
    ) -> u64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_put_integer_be(_ebs: *mut u64, _integer: u64, _num_bits: u64) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_put_integer_le(_ebs: *mut u64, _integer: u64, _num_bits: u64) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_put_utf16(_ebs: *mut u64, _integer: u64, _flags: u64) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn erts_bs_put_string(_ebs: *mut u64, _string: *const u8, _num_bytes: u64) {}
}

// Port of erts/emulator/beam/jit/x86/instr_msg.cpp (`extern "C" { #include "bif.h"
// #include "code_ix.h" #include "erl_proc_sig_queue.h" }` and the beam_jit_* receive helpers
// of jit/beam_jit_common.hpp) and jit/x86/process_main.cpp (`copy_out_registers` of
// beam_common.h), OTP-29.1.1: the runtime functions the receive emitters, `i_loop_rec_shared`
// and the schedule-out half of `process_main` call by address. `ErtsMessage *` crosses as an
// address (native code only loads `m[0]` and passes it on); `instr_msg` re-exports them.
unsafe extern "C" {
    /// `int erts_proc_sig_receive_helper(Process *c_p, int fcalls, int neg_o_reds,
    /// ErtsMessage **msgpp, int *get_outp)` (erl_proc_sig_queue.h): reductions used.
    pub fn erts_proc_sig_receive_helper(
        c_p: *mut crate::ProcessHeader,
        fcalls: i32,
        neg_o_reds: i32,
        msgpp: *mut usize,
        get_outp: *mut i32,
    ) -> i32;
    /// `ErtsMessage *beam_jit_decode_dist(Process *c_p, ErtsMessage *msgp)`
    /// (beam_jit_common.hpp): the decoded message, or null when it was dropped.
    pub fn beam_jit_decode_dist(c_p: *mut crate::ProcessHeader, msgp: usize) -> usize;
    /// `Eterm erts_msgq_recv_marker_insert(Process *c_p)` (erl_proc_sig_queue.h).
    pub fn erts_msgq_recv_marker_insert(c_p: *mut crate::ProcessHeader) -> u64;
    /// `void erts_msgq_recv_marker_bind(Process *c_p, Eterm insert_id, Eterm bind_id)`
    /// (erl_proc_sig_queue.h).
    pub fn erts_msgq_recv_marker_bind(c_p: *mut crate::ProcessHeader, insert_id: u64, bind_id: u64);
    /// `void erts_msgq_recv_marker_clear(Process *c_p, Eterm id)` (erl_proc_sig_queue.h).
    pub fn erts_msgq_recv_marker_clear(c_p: *mut crate::ProcessHeader, id: u64);
    /// `void erts_msgq_recv_marker_set_save(Process *c_p, Eterm id)` (erl_proc_sig_queue.h).
    pub fn erts_msgq_recv_marker_set_save(c_p: *mut crate::ProcessHeader, id: u64);
    /// `void erts_msgq_set_save_next(Process *c_p)` (erl_proc_sig_queue.h).
    pub fn erts_msgq_set_save_next(c_p: *mut crate::ProcessHeader);
    /// `Sint32 beam_jit_remove_message(Process *c_p, Sint32 FCALLS, Eterm *HTOP, Eterm *E,
    /// Uint32 active_code_ix)` (beam_jit_common.hpp): the remaining reductions.
    pub fn beam_jit_remove_message(
        c_p: *mut crate::ProcessHeader,
        fcalls: i32,
        htop: *mut u64,
        e: *mut u64,
        active_code_ix: u32,
    ) -> i32;
    /// `void beam_jit_wait_unlocked(Process *c_p, ErtsCodePtr cp)` (beam_jit_common.hpp).
    pub fn beam_jit_wait_unlocked(c_p: *mut crate::ProcessHeader, cp: usize);
    /// `void beam_jit_wait_locked(Process *c_p, ErtsCodePtr cp)` (beam_jit_common.hpp).
    pub fn beam_jit_wait_locked(c_p: *mut crate::ProcessHeader, cp: usize);
    /// `void beam_jit_take_receive_lock(Process *c_p)` (beam_jit_common.hpp).
    pub fn beam_jit_take_receive_lock(c_p: *mut crate::ProcessHeader);
    /// `enum beam_jit_tmo_ret beam_jit_wait_timeout(Process *c_p, Eterm timeout_value,
    /// ErtsCodePtr next)` (beam_jit_common.hpp): `RET_next` 0, `RET_wait` 1, `RET_badarg` 2.
    pub fn beam_jit_wait_timeout(
        c_p: *mut crate::ProcessHeader,
        timeout_value: u64,
        next: usize,
    ) -> u32;
    /// `void beam_jit_timeout(Process *c_p)` (beam_jit_common.hpp).
    pub fn beam_jit_timeout(c_p: *mut crate::ProcessHeader);
    /// `void beam_jit_timeout_locked(Process *c_p)` (beam_jit_common.hpp).
    pub fn beam_jit_timeout_locked(c_p: *mut crate::ProcessHeader);
    /// `void copy_out_registers(Process *c_p, Eterm *reg)` (beam_common.h): saves the
    /// `c_p->arity` live X registers into the process before it is scheduled out.
    pub fn copy_out_registers(c_p: *mut crate::ProcessHeader, reg: *mut u64);
    /// `void copy_in_registers(Process *c_p, Eterm *reg)` (beam_common.h): loads the saved
    /// argument registers into the scheduler's array after `erts_schedule`.
    pub fn copy_in_registers(c_p: *mut crate::ProcessHeader, reg: *mut u64);
    /// `int arinsal_slice_step(Process *c_p, int resume)`: the Rust slice of `c_p`; nonzero
    /// when `process_main` jumps to `c_p->i`. Deviation (Step D, see `x86::process_main`):
    /// erts has no such call.
    pub fn arinsal_slice_step(c_p: *mut crate::ProcessHeader, resume: i32) -> i32;
}

/// Displacements (from `registers`) the bridge shares with native fragments and the VM, as on
/// arm64. `tmp_mem[0..2]`: the exit target and resume address a trace hook leaves.
const TMP_MEM0: i32 = tmp_mem_disp(0);
const TMP_MEM1: i32 = tmp_mem_disp(1);
/// `tmp_mem[3]`: the exit kind marker a fragment leaves before jumping to the exit fragment.
#[cfg(test)]
const EXIT_MARKER: i32 = tmp_mem_disp(3);
/// `tmp_mem[4]`: the exit fragment address, for runtime error fragments.
#[cfg(test)]
const EXIT_FRAGMENT: i32 = tmp_mem_disp(4);
/// `tmp_mem[5]`: the Rust trace return hook.
const TRACE_HOOK: i32 = tmp_mem_disp(5);

const HTOP: usize = core::mem::offset_of!(ProcessHeader, htop);
const STOP: usize = core::mem::offset_of!(ProcessHeader, stop);
const FCALLS: usize = core::mem::offset_of!(ProcessHeader, fcalls);

#[cfg(windows)]
compile_error!("the x86-64 BeamAsm entry bridge implements the System V ABI only");

// Mach-O prepends an underscore to C symbols; ELF does not.
#[cfg(target_vendor = "apple")]
macro_rules! asm_sym {
    ($name:literal) => {
        concat!("_", $name)
    };
}
#[cfg(not(target_vendor = "apple"))]
macro_rules! asm_sym {
    ($name:literal) => {
        $name
    };
}

core::arch::global_asm!(
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:255-270 (the `erts_beamasm` trace
    // return addresses) and jit/x86/instr_trace.cpp (emit_return_trace,
    // emit_i_return_to_trace, emit_i_call_trace_return), OTP-29.1.1: one return address per
    // trace frame kind, each entered by a `ret` with `E` in rsp. Each passes its kind
    // (`TRACE_FRAME_*`) to the shared Rust hook in ARG2.
    concat!(".global ", asm_sym!("arinsal_return_trace")),
    concat!(asm_sym!("arinsal_return_trace"), ":"),
    "mov esi, 0",
    "jmp 2f",
    concat!(".global ", asm_sym!("arinsal_exception_trace")),
    concat!(asm_sym!("arinsal_exception_trace"), ":"),
    "mov esi, 1",
    "jmp 2f",
    concat!(".global ", asm_sym!("arinsal_return_to_trace")),
    concat!(asm_sym!("arinsal_return_to_trace"), ":"),
    "mov esi, 2",
    "jmp 2f",
    concat!(".global ", asm_sym!("arinsal_call_trace_return")),
    concat!(asm_sym!("arinsal_call_trace_return"), ":"),
    "mov esi, 3",
    "2:",
    // emit_enter_runtime<eStack | eHeap | eReductions> (jit/x86/beam_asm.hpp:700-800).
    "mov [r13 + {htop}], r15",
    "mov [r13 + {stop}], rsp",
    "mov [r13 + {fcalls}], r14d",
    "lea rsp, [rbx + {runtime_stack}]",
    "mov rdi, r13",
    // `reg`: the hook roots and reloads the X registers through it.
    "mov rdx, rbx",
    "call qword ptr [rbx + {trace_hook}]",
    // emit_leave_runtime<eStack | eHeap | eReductions> (jit/x86/beam_asm.hpp:803-850).
    "mov rsp, [r13 + {stop}]",
    "mov r15, [r13 + {htop}]",
    "mov r14d, [r13 + {fcalls}]",
    // A hook that hands the return to the scheduler leaves the exit target and resume
    // address in tmp_mem[0..2] and returns the exit fragment; ARG2/ARG3 are free at a return.
    "mov rsi, [rbx + {tmp_mem0}]",
    "mov rdx, [rbx + {tmp_mem1}]",
    "jmp rax",
    htop = const HTOP,
    stop = const STOP,
    fcalls = const FCALLS,
    runtime_stack = const RUNTIME_STACK_DISP,
    trace_hook = const TRACE_HOOK,
    tmp_mem0 = const TMP_MEM0,
    tmp_mem1 = const TMP_MEM1,
);

core::arch::global_asm!(
    // The native exit fragment's fixed address (a CP the VM recognises and native code
    // returns to): forwards to the fragment `process_main` emits (`x86::process_main`).
    // Deviation: erts has no such CP; see the module documentation.
    concat!(".global ", asm_sym!("arinsal_enter_native_return")),
    ".p2align 2",
    concat!(asm_sym!("arinsal_enter_native_return"), ":"),
    "jmp qword ptr [rip + {native_exit}]",
    native_exit = sym PROCESS_MAIN_NATIVE_EXIT,
);

// Port of erts/emulator/beam/jit/x86/instr_map.cpp runtime call prototypes, OTP-29.1.1.
unsafe extern "C" {
    /// `Eterm erts_gc_new_map(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub fn erts_gc_new_map(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm erts_gc_update_map_assoc(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub fn erts_gc_update_map_assoc(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm erts_gc_update_map_exact(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub fn erts_gc_update_map_exact(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm get_map_element(Eterm, Eterm)`.
    pub fn get_map_element(map: u64, key: u64) -> u64;
    /// `Eterm get_map_element_hash(Eterm, Eterm, erts_ihash_t)`.
    pub fn get_map_element_hash(map: u64, key: u64, hash: u64) -> u64;
    /// `Uint beam_jit_get_map_elements(Eterm, Eterm *, Eterm *, Uint, Eterm *)`.
    pub fn beam_jit_get_map_elements(
        map: u64,
        reg: *mut u64,
        stack: *mut u64,
        n: u64,
        fs: *mut u64,
    ) -> u64;
    /// `Eterm erts_maps_put(Process *, Eterm, Eterm, Eterm)`.
    pub fn erts_maps_put(c_p: *mut crate::ProcessHeader, key: u64, value: u64, map: u64) -> u64;
    /// `int erts_maps_update(Process *, Eterm, Eterm, Eterm, Eterm *)`.
    pub fn erts_maps_update(
        c_p: *mut crate::ProcessHeader,
        key: u64,
        value: u64,
        map: u64,
        result: *mut u64,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Runtime symbols referenced by the BIF and trace fragment byte comparisons.
    #[unsafe(no_mangle)]
    extern "C" fn get_on_load_address(_: *mut ProcessHeader, _: u64) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_trapping_length_1(_: *mut ProcessHeader, _: *mut u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn ubif2mfa(_: *const core::ffi::c_void) -> *const arinsal_term::ErtsCodeMfa {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_call_bif(
        _: *mut crate::ProcessHeader,
        _: *mut u64,
        _: usize,
        _: usize,
        _: usize,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_call_nif(
        _: *mut crate::ProcessHeader,
        _: usize,
        _: *mut u64,
        _: usize,
        _: usize,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_call_nif_early(
        _: *mut crate::ProcessHeader,
        _: *const crate::common::beam_asm_h::ErtsCodeInfo,
    ) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_load_nif(_: *mut ProcessHeader, _: usize, _: *mut u64) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_printable_return_address(
        _: *const crate::ProcessHeader,
        _: *const u64,
    ) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_generic_breakpoint(
        _: *mut crate::ProcessHeader,
        _: *mut crate::common::beam_asm_h::ErtsCodeInfo,
        _: *mut u64,
    ) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_call_trace_return(
        _: *mut ProcessHeader,
        _: *const core::ffi::c_void,
        _: u64,
        _: u64,
    ) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_trace_return(
        _: *mut ProcessHeader,
        _: *mut arinsal_term::ErtsCodeMfa,
        _: u64,
        _: u64,
        _: u64,
    ) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_hibernate(_: *mut ProcessHeader, _: *mut u64, _: i32) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_return_to_trace(_: *mut ProcessHeader, _: u64, _: *mut u64) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_cmp_compound(_: u64, _: u64, _: i32, _: i32) -> i64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_cmp_atoms(_: u64, _: u64) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_pd_hash_get(_: *mut crate::ProcessHeader, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_pd_hash_get_with_hx(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erl_is_function(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    extern "C" fn test_perf_counter() -> u64 {
        0
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    extern "C" fn test_os_times(_: *mut u64, _: *mut u64) {}

    #[cfg(all(not(target_os = "windows"), target_os = "linux"))]
    const TEST_TIME_READ_ONLY: ErtsSysTimeReadOnlyData = ErtsSysTimeReadOnlyData {
        os_monotonic_time: test_perf_counter,
        os_times: test_os_times,
        perf_counter: test_perf_counter,
        perf_counter_unit: 1,
        ticks_per_sec: 1,
    };

    #[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
    const TEST_TIME_READ_ONLY: ErtsSysTimeReadOnlyData = ErtsSysTimeReadOnlyData {
        perf_counter: test_perf_counter,
        perf_counter_unit: 1,
        ticks_per_sec: 1,
    };

    #[cfg(target_os = "windows")]
    const TEST_TIME_READ_ONLY: ErtsSysTimeReadOnlyData = ErtsSysTimeReadOnlyData {
        os_monotonic_time: test_perf_counter,
        os_times: test_os_times,
        sys_hrtime: test_perf_counter,
    };

    #[unsafe(no_mangle)]
    static erts_sys_time_data__: ErtsSysTimeData = ErtsSysTimeData {
        r: ErtsSysTimeDataReadOnly {
            o: TEST_TIME_READ_ONLY,
        },
    };
    // Runtime symbols referenced by map fragment byte comparisons.
    #[unsafe(no_mangle)]
    extern "C" fn erts_gc_new_map(
        _: *mut crate::ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_gc_update_map_assoc(
        _: *mut crate::ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_gc_update_map_exact(
        _: *mut crate::ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_maps_put(_: *mut crate::ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_maps_update(
        _: *mut crate::ProcessHeader,
        _: u64,
        _: u64,
        _: u64,
        _: *mut u64,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_get_map_elements(
        _: u64,
        _: *mut u64,
        _: *mut u64,
        _: u64,
        _: *mut u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn get_map_element(_: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn get_map_element_hash(_: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    // The global arithmetic-fragment byte comparison only takes these erts function
    // addresses; it never runs the generated fragments.
    #[unsafe(no_mangle)]
    extern "C" fn erts_band(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bnot(_: *mut crate::ProcessHeader, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bor(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bsl(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bsr(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bxor(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_int_div_rem(
        _: *mut crate::ProcessHeader,
        _: u64,
        _: u64,
        _: *mut u64,
        _: *mut u64,
    ) -> i32 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_div(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_minus(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_plus(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_times(_: *mut crate::ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_mul_add(
        _: *mut crate::ProcessHeader,
        _: u64,
        _: u64,
        _: u64,
        _: *mut u64,
    ) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_unary_minus(_: *mut crate::ProcessHeader, _: u64) -> u64 {
        unreachable!("arithmetic byte-test fixture")
    }

    // Fixtures for the receive and schedule-out runtime functions (instr_msg, process_main).
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_init_bits(
        _: *mut crate::ProcessHeader,
        _: *mut u64,
        _: *mut u64,
        _: u64,
        _: u64,
        _: u32,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_garbage_collect_nobump(
        _: *mut crate::ProcessHeader,
        _: usize,
        _: *mut u64,
        _: i32,
        _: i32,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_proc_sig_receive_helper(
        _: *mut crate::ProcessHeader,
        _: i32,
        _: i32,
        _: *mut usize,
        _: *mut i32,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_decode_dist(_: *mut crate::ProcessHeader, _: usize) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_msgq_recv_marker_insert(_: *mut crate::ProcessHeader) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_msgq_recv_marker_bind(_: *mut crate::ProcessHeader, _: u64, _: u64) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_msgq_recv_marker_clear(_: *mut crate::ProcessHeader, _: u64) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_msgq_recv_marker_set_save(_: *mut crate::ProcessHeader, _: u64) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_msgq_set_save_next(_: *mut crate::ProcessHeader) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_remove_message(
        _: *mut crate::ProcessHeader,
        _: i32,
        _: *mut u64,
        _: *mut u64,
        _: u32,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_wait_unlocked(_: *mut crate::ProcessHeader, _: usize) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_wait_locked(_: *mut crate::ProcessHeader, _: usize) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_take_receive_lock(_: *mut crate::ProcessHeader) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_wait_timeout(_: *mut crate::ProcessHeader, _: u64, _: usize) -> u32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_timeout(_: *mut crate::ProcessHeader) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_timeout_locked(_: *mut crate::ProcessHeader) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn copy_out_registers(_: *mut crate::ProcessHeader, _: *mut u64) {}
    #[unsafe(no_mangle)]
    extern "C" fn copy_in_registers(_: *mut crate::ProcessHeader, _: *mut u64) {}
    #[unsafe(no_mangle)]
    extern "C" fn arinsal_slice_step(p: *mut crate::ProcessHeader, resume: i32) -> i32 {
        crate::x86::test_sched::arinsal_slice_step(p, resume != 0)
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_schedule(
        _: *mut c_void,
        p: *mut crate::ProcessHeader,
        _: i32,
    ) -> *mut crate::ProcessHeader {
        crate::x86::test_sched::erts_schedule(p)
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_gc_after_bif_call_lhf(
        _c_p: *mut crate::ProcessHeader,
        _live_hf_end: usize,
        _result: u64,
        _regs: *mut u64,
        _arity: u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    /// Fixture for the VM's `the_active_code_index`, so byte tests of
    /// `emit_leave_runtime(Update::CODE_INDEX)` link.
    #[unsafe(no_mangle)]
    static the_active_code_index: u32 = 0;

    // Fixtures for the native record emitters' runtime-call addresses.
    #[unsafe(no_mangle)]
    extern "C" fn erl_get_record_elements(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> bool {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erl_create_local_native_record(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erl_create_native_record(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erl_update_native_record(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erl_get_local_record_field(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erl_get_record_field(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    // Fixtures for the runtime functions the fragments of the byte tests call, so the test
    // binary links; the tests only take their addresses.
    #[unsafe(no_mangle)]
    extern "C" fn handle_error(
        _c_p: *mut crate::ProcessHeader,
        _pc: usize,
        _reg: *mut u64,
        _bif_mfa: *const arinsal_term::ErtsCodeMfa,
    ) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn call_error_handler(
        _: *mut crate::ProcessHeader,
        _: *const arinsal_term::ErtsCodeMfa,
        _: *mut u64,
        _: u64,
    ) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn add_stacktrace(_c_p: *mut crate::ProcessHeader, _value: u64, _exc: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn build_stacktrace(_c_p: *mut crate::ProcessHeader, _exc: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn raw_raise(
        _stacktrace: u64,
        _exc_class: u64,
        _value: u64,
        _c_p: *mut crate::ProcessHeader,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_do_exit_process(_c_p: *mut crate::ProcessHeader, _reason: u64) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_continue_exit_process(_c_p: *mut crate::ProcessHeader) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_sanitize_freason(_c_p: *mut crate::ProcessHeader, _exc: u64) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_handle_unloaded_fun(
        _c_p: *mut crate::ProcessHeader,
        _reg: *mut u64,
        _arity: i32,
        _fun_thing: u64,
        _code_ix: u32,
    ) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_build_argument_list(
        _c_p: *mut crate::ProcessHeader,
        _regs: *const u64,
        _arity: i32,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn save_calls(_c_p: *mut crate::ProcessHeader, _export: usize) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn fixed_apply(
        _c_p: *mut crate::ProcessHeader,
        _reg: *mut u64,
        _arity: u64,
        _i: usize,
        _flags: u64,
    ) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn apply(
        _c_p: *mut crate::ProcessHeader,
        _reg: *mut u64,
        _i: usize,
        _flags: u64,
    ) -> usize {
        unreachable!("byte-test fixture")
    }

    // Fixtures for guard and float runtime symbols; byte tests only take their addresses.
    #[unsafe(no_mangle)]
    extern "C" fn big_to_double(_x: u64, _resp: *mut f64) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn eq(_a: u64, _b: u64) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn i_emit_nyi(_msg: *const core::ffi::c_char) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_catches_cons(_cp: usize, _cdr: u32, _cdrpp: *mut *mut usize) -> u32 {
        unreachable!("byte-test fixture")
    }

    // Fixtures for the instr_bs.cpp runtime functions.
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_field_size_argument_error(_c_p: *mut crate::ProcessHeader, _s: u64) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_get_integer(
        _c_p: *mut crate::ProcessHeader,
        _reg: *mut u64,
        _context: u64,
        _flags: u64,
        _size: u64,
        _live: u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_construct_fail_info(
        _c_p: *mut crate::ProcessHeader,
        _info: u64,
        _arg3: u64,
        _arg1: u64,
    ) {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_start_match_3(_c_p: *mut crate::ProcessHeader, _bin: u64) -> usize {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_integer_2(
        _c_p: *mut crate::ProcessHeader,
        _bits: u64,
        _flags: u32,
        _sb: usize,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_float_2(
        _c_p: *mut crate::ProcessHeader,
        _bits: u64,
        _flags: u32,
        _sb: usize,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_binary_2(
        _c_p: *mut crate::ProcessHeader,
        _bits: u64,
        _sb: usize,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_utf8(_sb: usize) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_utf16(_sb: usize, _flags: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_init_writable(_c_p: *mut crate::ProcessHeader, _sz: u64) -> u64 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_cmp_bits(_a: *const u8, _ao: u64, _b: *const u8, _bo: u64, _n: u64) -> i32 {
        unreachable!("byte-test fixture")
    }
    #[unsafe(no_mangle)]
    extern "C" fn erts_build_sub_bitstring(
        _hp: *mut *mut u64,
        _br_flags: u64,
        _br: usize,
        _base: *const u8,
        _offset: u64,
        _size: u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    // Native functions following the x86-64 BeamAsm register contract, entered from the
    // generated `process_main`.
    core::arch::global_asm!(
        concat!(asm_sym!("arinsal_x86_test_return"), ":"),
        // RET holds XREG0 on entry.
        "mov [rbx + 8], rax",
        "add r15, 16",
        "sub r14d, 1",
        "ret",
        concat!(asm_sym!("arinsal_x86_test_handoff"), ":"),
        "mov qword ptr [rbx + {exit_marker}], 2",
        "mov esi, 0x1234",
        "mov edx, 0x5678",
        "ret",
        concat!(asm_sym!("arinsal_x86_test_runtime_call"), ":"),
        // emit_enter_runtime<eStack>, runtime_call, emit_leave_runtime<eStack>.
        "mov [r13 + {stop}], rsp",
        "lea rsp, [rbx + {runtime_stack}]",
        "mov rdi, r13",
        "call {hook}",
        "mov rsp, [r13 + {stop}]",
        "mov [rbx + 16], rax",
        "ret",
        concat!(asm_sym!("arinsal_x86_test_yield_jump"), ":"),
        // A fragment leaving by jump: E is rsp with no CP popped.
        "mov qword ptr [rbx + {exit_marker}], 1",
        "push 0",
        "pop rax",
        "jmp qword ptr [rbx + {exit_fragment}]",
        concat!(asm_sym!("arinsal_x86_test_exception_trace"), ":"),
        // Returns through an exception_trace frame.
        concat!("lea rax, [rip + ", asm_sym!("arinsal_exception_trace"), "]"),
        "push rax",
        "ret",
        exit_marker = const EXIT_MARKER,
        exit_fragment = const EXIT_FRAGMENT,
        stop = const STOP,
        runtime_stack = const RUNTIME_STACK_DISP,
        hook = sym runtime_hook,
    );

    unsafe extern "C" {
        fn arinsal_x86_test_return();
        fn arinsal_x86_test_handoff();
        fn arinsal_x86_test_runtime_call();
        fn arinsal_x86_test_yield_jump();
        fn arinsal_x86_test_exception_trace();
    }

    /// A runtime function called from native code on the runtime stack. Heap allocation and
    /// formatting exercise the 16-byte stack alignment the C ABI requires; the stack it runs
    /// on is the scheduler thread's, just below the register file.
    extern "C" fn runtime_hook(c_p: *mut ProcessHeader) -> u64 {
        let words: Vec<u64> = (0..64).collect();
        let text = format!("{:?}", &words[..4]);
        let probe = 0u8;
        let sp = &raw const probe as usize;
        // SAFETY: the test passes the live header it was entered with.
        let fcalls = unsafe { (*c_p).fcalls };
        RUNTIME_SP.store(sp, core::sync::atomic::Ordering::Relaxed);
        fcalls as u64 + text.len() as u64
    }
    static RUNTIME_SP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// The Rust trace return hook: records its kind and continues at the exit fragment. Like
    /// the VM's `arinsal_beamasm_native_trace_return`, it gets `reg` (`x_reg_array`), not the
    /// start of the register file.
    extern "C" fn trace_hook(_c_p: *mut ProcessHeader, kind: u64, reg: *mut u64) -> usize {
        let registers = SchedulerRegisters::from_reg(reg);
        // SAFETY: the trace fragment passes the `reg` of the live register file it runs with.
        unsafe { (*registers).tmp_mem[7] = kind + 10 };
        addr(arinsal_enter_native_return as *const ())
    }

    struct Fixture {
        header: ProcessHeader,
        regs: Box<SchedulerRegisters>,
        stack: Vec<u64>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut fixture = Self {
                header: ProcessHeader::default(),
                regs: Box::default(),
                stack: vec![0; 64],
            };
            let heap = fixture.stack.as_mut_ptr();
            fixture.header.htop = heap;
            // SAFETY: 32 is within the 64-word stack allocation.
            fixture.header.stop = unsafe { heap.add(32) };
            fixture.header.fcalls = 100;
            fixture.regs.x_reg_array[0] = arinsal_term::Term::NIL;
            fixture
        }

        fn enter(&mut self, code: unsafe extern "C" fn()) -> ExitReason {
            crate::x86::test_sched::enter(&mut self.header, &mut self.regs, code as usize)
        }

        fn stop_offset(&self) -> isize {
            // SAFETY: both pointers are into `stack`.
            unsafe { self.header.stop.offset_from(self.stack.as_ptr()) }
        }
    }

    #[test]
    fn plain_return_publishes_cursors() {
        let mut fixture = Fixture::new();
        let htop = fixture.header.htop;
        assert_eq!(fixture.enter(arinsal_x86_test_return), ExitReason::Returned);
        // SAFETY: 2 words stay within the stack allocation.
        assert_eq!(fixture.header.htop, unsafe { htop.add(2) });
        assert_eq!(fixture.header.fcalls, 99);
        assert_eq!(fixture.stop_offset(), 32);
        assert_eq!(
            fixture.regs.x_reg_array[1].tagged_word(),
            arinsal_term::Term::NIL.tagged_word()
        );
        // schedule_next pushed the exit fragment just below `stop`, 4-byte aligned.
        let cp = fixture.stack[31];
        assert_eq!(cp, arinsal_enter_native_return as *const () as u64);
        assert_eq!(cp & 3, 0);
    }

    #[test]
    fn handoff_marker_selects_call_unported() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.enter(arinsal_x86_test_handoff),
            ExitReason::CallUnported {
                target_pc: 0x1234,
                resume_pc: 0x5678
            }
        );
        assert_eq!(fixture.regs.tmp_mem[3], 0);
        assert_eq!(
            fixture.regs.tmp_mem[4],
            arinsal_enter_native_return as *const () as u64
        );
    }

    #[test]
    fn entry_return_becomes_callee_cp() {
        let mut fixture = Fixture::new();
        fixture.regs.entry_return = arinsal_enter_native_return as *const () as u64;
        assert_eq!(fixture.enter(arinsal_x86_test_return), ExitReason::Returned);
        assert_eq!(fixture.regs.entry_return, 0);
        assert_eq!(fixture.stop_offset(), 32);
    }

    #[test]
    fn runtime_call_runs_on_runtime_stack() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.enter(arinsal_x86_test_runtime_call),
            ExitReason::Returned
        );
        assert_eq!(fixture.regs.x_reg_array[2].tagged_word(), 100 + 12);
        assert_eq!(fixture.stop_offset(), 32);
        // The runtime function ran below the register file on the scheduler thread's C
        // stack, never on the heap or the Erlang stack.
        let sp = RUNTIME_SP.load(core::sync::atomic::Ordering::Relaxed);
        let stack = fixture.stack.as_ptr_range();
        assert!(!(stack.start as usize..stack.end as usize).contains(&sp));
        let mirror = std::ptr::from_ref(&*fixture.regs) as usize;
        assert!(!(mirror..mirror + core::mem::size_of::<SchedulerRegisters>()).contains(&sp));
    }

    #[test]
    fn jump_to_exit_fragment_yields() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.enter(arinsal_x86_test_yield_jump),
            ExitReason::Yield
        );
        // A jump leaves schedule_next's CP on the Erlang stack: `stop` is below it.
        assert_eq!(fixture.stop_offset(), 31);
    }

    #[test]
    fn trace_return_calls_hook_on_runtime_stack() {
        let mut fixture = Fixture::new();
        fixture.regs.tmp_mem[5] = trace_hook as *const () as u64;
        assert_eq!(
            fixture.enter(arinsal_x86_test_exception_trace),
            ExitReason::Returned
        );
        assert_eq!(fixture.regs.tmp_mem[7], 11);
        // The trace frame's address was popped; the hook's jump to the exit fragment leaves
        // schedule_next's CP below `stop`.
        assert_eq!(fixture.stop_offset(), 31);
    }
}
