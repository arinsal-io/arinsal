//! Audited native runtime transition core on x86-64: the C-to-Erlang entry bridge, its exit
//! fragment and the trace return addresses.
//!
//! Port of the process entry and exit of erts/emulator/beam/jit/x86/process_main.cpp
//! (emit_process_main: `schedule_next` hands a process to native code with
//! `emit_leave_runtime<eStack | eHeap>` and a jump to `c_p->i`; `context_switch*` /
//! `do_schedule` come back with `emit_enter_runtime<eStack | eHeap>`), OTP-29.1.1. erts runs
//! the scheduler loop on the runtime stack below `process_main`; here the Rust scheduler calls
//! the bridge once per slice, so the bridge is the native side of that loop.
//!
//! erts selects `NATIVE_ERLANG_STACK` on x86-64: `E` is `rsp`. Native code therefore leaves
//! the runtime (scheduler thread) stack on entry and returns to it before every runtime call;
//! the runtime stack position lives in `SchedulerRegisters::runtime_stack`, which the bridge
//! sets to its own frame.

use crate::{
    ACTIVE_CODE_IX_DISP, ENTRY_RETURN_DISP, ExitReason, ProcessHeader, RUNTIME_STACK_DISP,
    SchedulerRegisters, X_REG_ARRAY_OFFSET, tmp_mem_disp,
};
use core::ffi::c_void;

/// Per-call exit fragment result passed between the assembly bridge and Rust.
#[repr(C)]
#[derive(Default)]
struct NativeExit {
    kind: u64,
    target: usize,
    resume: usize,
}

/// Enters generated code by raw address through the process-wide pinned-register trampoline.
///
/// Native code returns to the exit fragment `arinsal_enter_native_return` (or jumps there
/// with `E` in `rsp`). A non-zero `tmp_mem[3]` marker is the exit kind: 2 hands the call at
/// `ARG2` (resume address `ARG3`) to the scheduler, any other non-zero value yields; zero is
/// a plain return.
///
/// # Safety
/// `code_ptr` must point into a live executable mapping at a function entry that follows the
/// x86-64 BeamAsm register contract (`register` in `beam_asm`) and leaves through the exit
/// fragment with `E` in `rsp`.
// Inlined so the scheduler's slice calls the trampoline directly, as on arm64.
#[inline(always)]
pub unsafe fn enter_native_raw(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    code_ptr: *const c_void,
) -> ExitReason {
    let mut exit = NativeExit::default();
    // SAFETY: The assembly bridge saves the System V callee-saved registers, loads the
    // documented ProcessHeader/SchedulerRegisters layout, switches to the Erlang stack, jumps to
    // code_ptr and comes back to this frame on the runtime stack through its exit fragment.
    unsafe { arinsal_enter_native(header, regs, code_ptr, &mut exit) };
    match exit.kind {
        2 => ExitReason::CallUnported {
            target_pc: exit.target,
            resume_pc: exit.resume,
        },
        0 => ExitReason::Returned,
        _ => ExitReason::Yield,
    }
}

// The pointer exposes the fixed C-layout prefix; trailing BIF bookkeeping is Rust-only.
#[allow(improper_ctypes)]
unsafe extern "C" {
    pub fn arinsal_enter_native_return();
    /// The Rust scheduler loop's `schedule_next`: where `context_switch`,
    /// `context_switch_simplified` and `do_schedule` leave native code (see the bridge).
    pub fn arinsal_schedule_next();
    /// erts `beam_return_trace`: the return address of a return_trace frame.
    pub fn arinsal_return_trace();
    /// erts `beam_exception_trace`: the return address of an exception_trace frame.
    pub fn arinsal_exception_trace();
    /// erts `beam_return_to_trace`: the return address of a return_to frame.
    pub fn arinsal_return_to_trace();
    /// erts `beam_call_trace_return`: the return address of a call time/memory frame.
    pub fn arinsal_call_trace_return();
    fn arinsal_enter_native(
        header: *mut ProcessHeader,
        regs: *mut SchedulerRegisters,
        code: *const c_void,
        exit: *mut NativeExit,
    );
}

// Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:28-32 (`extern "C" { #include
// "bif.h" #include "beam_common.h" }`) and erl_gc.h, OTP-29.1.1: the runtime functions the
// fragments of this file call by address (`runtime_call`). They are defined with these erts
// names and C signatures by the VM (docs/design/jit_runtime_symbols.md); fragments take their
// address with `f as usize`. The declarations live in this raw module (`unsafe extern`);
// `beam_asm_global` re-exports them.
unsafe extern "C" {
    /// `ErtsCodePtr handle_error(Process *c_p, ErtsCodePtr pc, Eterm *reg,
    /// const ErtsCodeMFA *bif_mfa)` (beam_common.h): the handler to continue at, or null.
    pub safe fn handle_error(
        c_p: *mut crate::ProcessHeader,
        pc: usize,
        reg: *mut u64,
        bif_mfa: *const arinsal_term::ErtsCodeMfa,
    ) -> usize;
    /// `const Export *call_error_handler(Process *p, const ErtsCodeMFA *mfa, Eterm *reg,
    /// Eterm func)` (beam_common.h): the `Export` address, or null. `Export` is read only by
    /// native code, so it crosses as an address.
    pub safe fn call_error_handler(
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
    pub safe fn erts_garbage_collect_nobump(
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
    pub safe fn erts_gc_after_bif_call_lhf(
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
    pub safe fn erts_band(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bnot(Process *p, Eterm arg)`.
    pub safe fn erts_bnot(c_p: *mut crate::ProcessHeader, arg: u64) -> u64;
    /// `Eterm erts_bor(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_bor(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bsl(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_bsl(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bsr(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_bsr(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bxor(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_bxor(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `int erts_int_div_rem(Process *p, Eterm arg1, Eterm arg2, Eterm *q, Eterm *r)`.
    pub safe fn erts_int_div_rem(
        c_p: *mut crate::ProcessHeader,
        arg1: u64,
        arg2: u64,
        quotient: *mut u64,
        remainder: *mut u64,
    ) -> i32;
    /// `Eterm erts_mixed_div(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_mixed_div(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_minus(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_mixed_minus(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_plus(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_mixed_plus(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_times(Process *p, Eterm arg1, Eterm arg2)`.
    pub safe fn erts_mixed_times(c_p: *mut crate::ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mul_add(Process *p, Eterm arg1, Eterm arg2, Eterm arg3, Eterm *pp)`.
    pub safe fn erts_mul_add(
        c_p: *mut crate::ProcessHeader,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        result: *mut u64,
    ) -> u64;
    /// `Eterm erts_unary_minus(Process *p, Eterm arg1)`.
    pub safe fn erts_unary_minus(c_p: *mut crate::ProcessHeader, arg1: u64) -> u64;
}

// Port of erts/emulator/beam/jit/x86/instr_float.cpp (`extern "C" { #include "big.h" }`),
// OTP-29.1.1: `big_to_double` writes the converted float to TMP_MEM1.
unsafe extern "C" {
    /// `int big_to_double(Eterm x, double *resp)` (big.h).
    pub safe fn big_to_double(x: u64, resp: *mut f64) -> i32;
}

// Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp (`erl_utils.h`), OTP-29.1.1:
// exact comparison runtime function called by address. The map lookup declaration is shared
// with instr_map below.
unsafe extern "C" {
    /// `int eq(Eterm a, Eterm b)` (erl_utils.h / utils.c).
    pub safe fn eq(a: u64, b: u64) -> i32;
}

// Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:397-399 (i_emit_nyi) and
// erts/emulator/beam/beam_catches.h:38 (beam_catches_cons), OTP-29.1.1. erts defines
// `i_emit_nyi` static in beam_asm_module.cpp around `erts_exit(ERTS_ERROR_EXIT, "NYI: %s\n",
// msg)`; `erts_exit` belongs to the VM, which therefore defines the symbol. `beam_catches_cons`
// is called by the loader side of `patchCatches`. `beam_asm_module` re-exports both.
unsafe extern "C" {
    /// `static void i_emit_nyi(char *msg)`: halts the emulator with `NYI: <msg>`.
    pub safe fn i_emit_nyi(msg: *const core::ffi::c_char);
    /// `unsigned beam_catches_cons(ErtsCodePtr cp, unsigned cdr, ErtsCodePtr **)`: a new
    /// catch index for the handler `cp`, chained to `cdr`.
    pub safe fn beam_catches_cons(cp: usize, cdr: u32, cdrpp: *mut *mut usize) -> u32;
}

// Port of erts/emulator/beam/jit/x86/instr_common.cpp and instr_call.cpp (`extern "C" {
// #include "beam_common.h" }`), OTP-29.1.1: the beam_common.h functions their global fragments
// call by address. `instr_common` and `instr_call` re-export them.
unsafe extern "C" {
    /// `Eterm add_stacktrace(Process *c_p, Eterm Value, Eterm exc)` (beam_common.h).
    pub safe fn add_stacktrace(c_p: *mut crate::ProcessHeader, value: u64, exc: u64) -> u64;
    /// `void erts_sanitize_freason(Process *c_p, Eterm exc)` (beam_common.h).
    pub safe fn erts_sanitize_freason(c_p: *mut crate::ProcessHeader, exc: u64);
    /// `void save_calls(Process *p, const Export *)` (beam_common.h). `Export` crosses as an
    /// address, as for `call_error_handler`.
    pub safe fn save_calls(c_p: *mut crate::ProcessHeader, export: usize);
    /// `const Export *fixed_apply(Process *p, Eterm *reg, Uint arity, ErtsCodePtr I,
    /// Uint flags)` (beam_common.h); the export address, or null after setting the process
    /// exception.
    pub safe fn fixed_apply(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        arity: u64,
        i: usize,
        flags: u64,
    ) -> usize;
    /// `const Export *apply(Process *p, Eterm *reg, ErtsCodePtr I, Uint flags)`
    /// (beam_common.h); the export address, or null after setting the process exception.
    pub safe fn apply(c_p: *mut crate::ProcessHeader, reg: *mut u64, i: usize, flags: u64)
    -> usize;
}

// Port of erts/emulator/beam/jit/x86/instr_common.cpp runtime declarations, OTP-29.1.1.
unsafe extern "C" {
    /// `int raw_raise(Eterm stacktrace, Eterm exc_class, Eterm value, Process *c_p)`
    /// (beam_common.h).
    pub safe fn raw_raise(
        stacktrace: u64,
        exc_class: u64,
        value: u64,
        c_p: *mut crate::ProcessHeader,
    ) -> i32;
    /// `Eterm build_stacktrace(Process *c_p, Eterm exc)` (global.h).
    pub safe fn build_stacktrace(c_p: *mut crate::ProcessHeader, exc: u64) -> u64;
    /// `void erts_do_exit_process(Process *p, Eterm reason)` (erl_process.h).
    pub safe fn erts_do_exit_process(c_p: *mut crate::ProcessHeader, reason: u64);
    /// `void erts_continue_exit_process(Process *p)` (erl_process.h).
    pub safe fn erts_continue_exit_process(c_p: *mut crate::ProcessHeader);
}

// Port of erts/emulator/beam/jit/beam_jit_common.hpp, OTP-29.1.1: the JIT-only runtime
// helpers of jit/beam_jit_common.cpp the x86 fragments call by address. `instr_fun` re-exports
// them.
unsafe extern "C" {
    /// `const Export *beam_jit_handle_unloaded_fun(Process *c_p, Eterm *reg, int arity,
    /// Eterm fun_thing, ErtsCodeIndex code_ix)`: the export to call, or null with
    /// `c_p->freason` set. `Export` crosses as an address.
    pub safe fn beam_jit_handle_unloaded_fun(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        arity: i32,
        fun_thing: u64,
        code_ix: u32,
    ) -> usize;
    /// `Eterm beam_jit_build_argument_list(Process *c_p, const Eterm *regs, int arity)`.
    pub safe fn beam_jit_build_argument_list(
        c_p: *mut crate::ProcessHeader,
        regs: *const u64,
        arity: i32,
    ) -> u64;
}

// Port of erts/emulator/beam/jit/x86/instr_bs.cpp (`extern "C" { #include "erl_binary.h"
// #include "erl_bits.h" #include "beam_common.h" }` and the beam_jit_bs_* helpers of
// jit/beam_jit_common.hpp), OTP-29.1.1: the runtime functions the bit syntax emitters and
// fragments call by address. `ErlSubBits *` and `const BinRef *` cross as addresses (native
// code only passes them on); `instr_bs` re-exports them.
unsafe extern "C" {
    /// `void beam_jit_bs_field_size_argument_error(Process *c_p, Eterm size)`
    /// (beam_jit_common.hpp).
    pub safe fn beam_jit_bs_field_size_argument_error(c_p: *mut crate::ProcessHeader, size: u64);
    /// `Eterm beam_jit_bs_get_integer(Process *c_p, Eterm *reg, Eterm context, Uint flags,
    /// Uint size, Uint Live)` (beam_jit_common.hpp).
    pub safe fn beam_jit_bs_get_integer(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        context: u64,
        flags: u64,
        size: u64,
        live: u64,
    ) -> u64;
    /// `void beam_jit_bs_construct_fail_info(Process *c_p, Uint packed_error_info,
    /// Eterm arg3, Eterm arg1)` (beam_jit_common.hpp).
    pub safe fn beam_jit_bs_construct_fail_info(
        c_p: *mut crate::ProcessHeader,
        packed_error_info: u64,
        arg3: u64,
        arg1: u64,
    );
    /// `Eterm beam_jit_bs_init_bits(Process *c_p, Eterm *reg, struct erl_bits_state *EBS,
    /// Uint num_bits, Uint alloc, unsigned Live)` (beam_jit_common.hpp).
    pub safe fn beam_jit_bs_init_bits(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        ebs: *mut u64,
        num_bits: u64,
        alloc: u64,
        live: u32,
    ) -> u64;
    /// `ErlSubBits *erts_bs_start_match_3(Process *p, Eterm Bin)` (erl_bits.h).
    pub safe fn erts_bs_start_match_3(c_p: *mut crate::ProcessHeader, bin: u64) -> usize;
    /// `Eterm erts_bs_get_integer_2(Process *p, Uint num_bits, unsigned flags,
    /// ErlSubBits *sb)` (erl_bits.h).
    pub safe fn erts_bs_get_integer_2(
        c_p: *mut crate::ProcessHeader,
        num_bits: u64,
        flags: u32,
        sb: usize,
    ) -> u64;
    /// `Eterm erts_bs_get_float_2(Process *p, Uint num_bits, unsigned flags,
    /// ErlSubBits *sb)` (erl_bits.h).
    pub safe fn erts_bs_get_float_2(
        c_p: *mut crate::ProcessHeader,
        num_bits: u64,
        flags: u32,
        sb: usize,
    ) -> u64;
    /// `Eterm erts_bs_get_binary_2(Process *p, Uint num_bits, ErlSubBits *sb)` (erl_bits.h).
    pub safe fn erts_bs_get_binary_2(
        c_p: *mut crate::ProcessHeader,
        num_bits: u64,
        sb: usize,
    ) -> u64;
    /// `Eterm erts_bs_get_utf8(ErlSubBits *sb)` (erl_bits.h).
    pub safe fn erts_bs_get_utf8(sb: usize) -> u64;
    /// `Eterm erts_bs_get_utf16(ErlSubBits *sb, Uint flags)` (erl_bits.h).
    pub safe fn erts_bs_get_utf16(sb: usize, flags: u64) -> u64;
    /// `Eterm erts_bs_init_writable(Process *p, Eterm sz)` (erl_bits.h).
    pub safe fn erts_bs_init_writable(c_p: *mut crate::ProcessHeader, sz: u64) -> u64;
    /// `int erts_cmp_bits(const byte *a_ptr, Uint a_offs, const byte *b_ptr, Uint b_offs,
    /// Uint size)` (erl_bits.h).
    pub safe fn erts_cmp_bits(
        a_ptr: *const u8,
        a_offs: u64,
        b_ptr: *const u8,
        b_offs: u64,
        size: u64,
    ) -> i32;
    /// `Eterm erts_build_sub_bitstring(Eterm **hp, Eterm br_flags, const BinRef *br,
    /// const byte *base, Uint offset, Uint size)` (erl_bits.h).
    pub safe fn erts_build_sub_bitstring(
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
    pub safe fn erts_bs_append_checked(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        size: u64,
        extra_words: u64,
        unit: u64,
    ) -> u64;
    /// `Eterm erts_bs_private_append_checked(ErlBitsState *EBS, Process *p, Eterm bin,
    /// Uint size)` (erl_bits.h).
    pub safe fn erts_bs_private_append_checked(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        bin: u64,
        size: u64,
    ) -> u64;
    /// `int erts_bs_put_binary(ErlBitsState *EBS, Process *p, Eterm bin, Uint num_bits)`
    /// (erl_bits.h).
    pub safe fn erts_bs_put_binary(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        bin: u64,
        num_bits: u64,
    ) -> i32;
    /// `int erts_bs_put_binary_all(ErlBitsState *EBS, Process *p, Eterm bin, Uint unit)`
    /// (erl_bits.h).
    pub safe fn erts_bs_put_binary_all(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        bin: u64,
        unit: u64,
    ) -> i32;
    /// `void beam_jit_bs_put_binary_all(ErlBitsState *EBS, Process *p, Eterm bin)`
    /// (beam_jit_common.hpp).
    pub safe fn beam_jit_bs_put_binary_all(ebs: *mut u64, c_p: *mut crate::ProcessHeader, bin: u64);
    /// `Eterm erts_bs_put_float(ErlBitsState *EBS, Process *p, Eterm float, Uint num_bits,
    /// int flags)` (erl_bits.h).
    pub safe fn erts_bs_put_float(
        ebs: *mut u64,
        c_p: *mut crate::ProcessHeader,
        float: u64,
        num_bits: u64,
        flags: i32,
    ) -> u64;
    /// `int erts_bs_put_integer_be(ErlBitsState *EBS, Eterm integer, Uint num_bits)`
    /// (erl_bits.h).
    pub safe fn erts_bs_put_integer_be(ebs: *mut u64, integer: u64, num_bits: u64) -> i32;
    /// `int erts_bs_put_integer_le(ErlBitsState *EBS, Eterm integer, Uint num_bits)`
    /// (erl_bits.h).
    pub safe fn erts_bs_put_integer_le(ebs: *mut u64, integer: u64, num_bits: u64) -> i32;
    /// `int erts_bs_put_utf16(ErlBitsState *EBS, Eterm integer, Uint flags)` (erl_bits.h).
    pub safe fn erts_bs_put_utf16(ebs: *mut u64, integer: u64, flags: u64) -> i32;
    /// `void erts_bs_put_string(ErlBitsState *EBS, byte *iptr, Uint num_bytes)` (erl_bits.h).
    pub safe fn erts_bs_put_string(ebs: *mut u64, string: *const u8, num_bytes: u64);
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
    pub safe fn erts_proc_sig_receive_helper(
        c_p: *mut crate::ProcessHeader,
        fcalls: i32,
        neg_o_reds: i32,
        msgpp: *mut usize,
        get_outp: *mut i32,
    ) -> i32;
    /// `ErtsMessage *beam_jit_decode_dist(Process *c_p, ErtsMessage *msgp)`
    /// (beam_jit_common.hpp): the decoded message, or null when it was dropped.
    pub safe fn beam_jit_decode_dist(c_p: *mut crate::ProcessHeader, msgp: usize) -> usize;
    /// `Eterm erts_msgq_recv_marker_insert(Process *c_p)` (erl_proc_sig_queue.h).
    pub safe fn erts_msgq_recv_marker_insert(c_p: *mut crate::ProcessHeader) -> u64;
    /// `void erts_msgq_recv_marker_bind(Process *c_p, Eterm insert_id, Eterm bind_id)`
    /// (erl_proc_sig_queue.h).
    pub safe fn erts_msgq_recv_marker_bind(
        c_p: *mut crate::ProcessHeader,
        insert_id: u64,
        bind_id: u64,
    );
    /// `void erts_msgq_recv_marker_clear(Process *c_p, Eterm id)` (erl_proc_sig_queue.h).
    pub safe fn erts_msgq_recv_marker_clear(c_p: *mut crate::ProcessHeader, id: u64);
    /// `void erts_msgq_recv_marker_set_save(Process *c_p, Eterm id)` (erl_proc_sig_queue.h).
    pub safe fn erts_msgq_recv_marker_set_save(c_p: *mut crate::ProcessHeader, id: u64);
    /// `void erts_msgq_set_save_next(Process *c_p)` (erl_proc_sig_queue.h).
    pub safe fn erts_msgq_set_save_next(c_p: *mut crate::ProcessHeader);
    /// `Sint32 beam_jit_remove_message(Process *c_p, Sint32 FCALLS, Eterm *HTOP, Eterm *E,
    /// Uint32 active_code_ix)` (beam_jit_common.hpp): the remaining reductions.
    pub safe fn beam_jit_remove_message(
        c_p: *mut crate::ProcessHeader,
        fcalls: i32,
        htop: *mut u64,
        e: *mut u64,
        active_code_ix: u32,
    ) -> i32;
    /// `void beam_jit_wait_unlocked(Process *c_p, ErtsCodePtr cp)` (beam_jit_common.hpp).
    pub safe fn beam_jit_wait_unlocked(c_p: *mut crate::ProcessHeader, cp: usize);
    /// `void beam_jit_wait_locked(Process *c_p, ErtsCodePtr cp)` (beam_jit_common.hpp).
    pub safe fn beam_jit_wait_locked(c_p: *mut crate::ProcessHeader, cp: usize);
    /// `void beam_jit_take_receive_lock(Process *c_p)` (beam_jit_common.hpp).
    pub safe fn beam_jit_take_receive_lock(c_p: *mut crate::ProcessHeader);
    /// `enum beam_jit_tmo_ret beam_jit_wait_timeout(Process *c_p, Eterm timeout_value,
    /// ErtsCodePtr next)` (beam_jit_common.hpp): `RET_next` 0, `RET_wait` 1, `RET_badarg` 2.
    pub safe fn beam_jit_wait_timeout(
        c_p: *mut crate::ProcessHeader,
        timeout_value: u64,
        next: usize,
    ) -> u32;
    /// `void beam_jit_timeout(Process *c_p)` (beam_jit_common.hpp).
    pub safe fn beam_jit_timeout(c_p: *mut crate::ProcessHeader);
    /// `void beam_jit_timeout_locked(Process *c_p)` (beam_jit_common.hpp).
    pub safe fn beam_jit_timeout_locked(c_p: *mut crate::ProcessHeader);
    /// `void copy_out_registers(Process *c_p, Eterm *reg)` (beam_common.h): saves the
    /// `c_p->arity` live X registers into the process before it is scheduled out.
    pub safe fn copy_out_registers(c_p: *mut crate::ProcessHeader, reg: *mut u64);
}

/// Displacements (from `registers`) the bridge shares with native fragments and the VM, as on
/// arm64. `tmp_mem[0..2]`: the exit target and resume address a trace hook leaves.
const TMP_MEM0: i32 = tmp_mem_disp(0);
const TMP_MEM1: i32 = tmp_mem_disp(1);
/// `tmp_mem[3]`: the exit kind marker a fragment leaves before jumping to the exit fragment.
const EXIT_MARKER: i32 = tmp_mem_disp(3);
/// `tmp_mem[4]`: the exit fragment address, for runtime error fragments.
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
    "mov rsp, [rbx + {runtime_stack}]",
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
    concat!(".global ", asm_sym!("arinsal_enter_native")),
    concat!(asm_sym!("arinsal_enter_native"), ":"),
    // Port of erts/emulator/beam/jit/x86/process_main.cpp:53-110 and 270-293
    // (emit_process_main), OTP-29.1.1. Arguments (System V): rdi = c_p, rsi = registers,
    // rdx = code, rcx = exit record. Preserve the System V callee-saved registers; together
    // with the exit record pointer and the return address the frame is 64 bytes, so the
    // runtime stack stays 16-byte aligned for runtime calls.
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "push rcx",
    // `registers` points at x_reg_array (process_main.cpp:72-77); c_p is r13.
    "lea rbx, [rsi + {x_reg_array}]",
    "mov r13, rdi",
    // The runtime stack every emit_enter_runtime switches back to is this frame.
    "mov [rbx + {runtime_stack}], rsp",
    // Setup reduction counting and the active code index (process_main.cpp:252-286): the
    // runtime already resolved the process's code index (save_calls or the active one).
    "mov r14d, [r13 + {fcalls}]",
    "mov r12, [rbx + {active_code_ix}]",
    // Runtime error fragments find the exit fragment here after a runtime call.
    concat!("lea rax, [rip + ", asm_sym!("arinsal_enter_native_return"), "]"),
    "mov [rbx + {exit_fragment}], rax",
    // emit_leave_runtime<eStack | eHeap>: switch to the Erlang stack.
    "mov r15, [r13 + {htop}]",
    "mov rsp, [r13 + {stop}]",
    // A call entered from the scheduler returns to its caller's continuation: it is the
    // callee's CP, which on x86-64 is the word on top of the Erlang stack (`entry_return`).
    "mov rax, [rbx + {entry_return}]",
    "test rax, rax",
    "jz 2f",
    "mov qword ptr [rbx + {entry_return}], 0",
    "push rax",
    // Port of erts/emulator/beam/jit/x86/process_main.cpp:288-293, OTP-29.1.1: a scheduler
    // re-entry can target a BIF continuation, whose result is in RET.
    "mov rax, [rbx]",
    "jmp rdx",
    "2:",
    "mov rax, [rbx]",
    // The call pushes the exit fragment as the callee's CP, which must be 4-byte aligned
    // (`aligned_call`, jit/x86/beam_asm.hpp:420-440): pad so the 2-byte `call rdx` ends on a
    // 4-byte boundary. A call (not a jump) also keeps the return stack buffer balanced.
    ".p2align 2",
    ".byte 0x66, 0x90",
    "call rdx",
    // This label must directly follow the `call rdx` above: its return address is the exit
    // fragment. Arrives by a `ret` or a jump, with `E` in rsp either way.
    concat!(".global ", asm_sym!("arinsal_enter_native_return")),
    concat!(asm_sym!("arinsal_enter_native_return"), ":"),
    // The marker distinguishes a scheduler handoff without adding work to each BEAM return;
    // consume it so a later plain return is not taken for a handoff.
    "mov rcx, [rbx + {exit_marker}]",
    "mov qword ptr [rbx + {exit_marker}], 0",
    "mov rax, rcx",
    // emit_enter_runtime<eStack | eHeap | eReductions>: publish the cursors, back to the
    // runtime stack.
    "mov [r13 + {htop}], r15",
    "mov [r13 + {stop}], rsp",
    "mov [r13 + {fcalls}], r14d",
    "3:",
    "mov rsp, [rbx + {runtime_stack}]",
    "pop rcx",
    "mov [rcx], rax",
    "mov [rcx + 8], rsi",
    "mov [rcx + 16], rdx",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    // `schedule_next` of erts' process_main (process_main.cpp:195-293), reached by a jump from
    // the schedule-out half of the `process_main` fragment (beam_asm_global
    // `emit_process_main`) on the runtime stack, with HTOP, E and FCALLS published to `c_p`
    // and the live X registers copied out: back to the Rust scheduler loop, which runs
    // `erts_schedule` and re-enters through this bridge. Kind 1: the process was scheduled
    // out.
    concat!(".global ", asm_sym!("arinsal_schedule_next")),
    concat!(asm_sym!("arinsal_schedule_next"), ":"),
    "mov eax, 1",
    "jmp 3b",
    htop = const HTOP,
    stop = const STOP,
    fcalls = const FCALLS,
    x_reg_array = const X_REG_ARRAY_OFFSET,
    runtime_stack = const RUNTIME_STACK_DISP,
    active_code_ix = const ACTIVE_CODE_IX_DISP,
    entry_return = const ENTRY_RETURN_DISP,
    exit_fragment = const EXIT_FRAGMENT,
    exit_marker = const EXIT_MARKER,
);

// Port of erts/emulator/beam/jit/x86/instr_map.cpp runtime call prototypes, OTP-29.1.1.
unsafe extern "C" {
    /// `Eterm erts_gc_new_map(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub safe fn erts_gc_new_map(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm erts_gc_update_map_assoc(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub safe fn erts_gc_update_map_assoc(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm erts_gc_update_map_exact(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub safe fn erts_gc_update_map_exact(
        c_p: *mut crate::ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm get_map_element(Eterm, Eterm)`.
    pub safe fn get_map_element(map: u64, key: u64) -> u64;
    /// `Eterm get_map_element_hash(Eterm, Eterm, erts_ihash_t)`.
    pub safe fn get_map_element_hash(map: u64, key: u64, hash: u64) -> u64;
    /// `Uint beam_jit_get_map_elements(Eterm, Eterm *, Eterm *, Uint, Eterm *)`.
    pub safe fn beam_jit_get_map_elements(
        map: u64,
        reg: *mut u64,
        stack: *mut u64,
        n: u64,
        fs: *mut u64,
    ) -> u64;
    /// `Eterm erts_maps_put(Process *, Eterm, Eterm, Eterm)`.
    pub safe fn erts_maps_put(
        c_p: *mut crate::ProcessHeader,
        key: u64,
        value: u64,
        map: u64,
    ) -> u64;
    /// `int erts_maps_update(Process *, Eterm, Eterm, Eterm, Eterm *)`.
    pub safe fn erts_maps_update(
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
    extern "C" fn copy_out_registers(_: *mut crate::ProcessHeader, _: *mut u64) {
        unreachable!("byte-test fixture")
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

    // Native functions following the x86-64 BeamAsm register contract, entered through the
    // bridge. `preserve` is a host-side caller that checks the bridge keeps every System V
    // callee-saved register.
    core::arch::global_asm!(
        concat!(asm_sym!("arinsal_x86_test_return"), ":"),
        // Clobber registers the host expects preserved; the bridge must restore them.
        "mov rbp, 0x1111",
        "mov r12, 0x2222",
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
        "mov rsp, [rbx + {runtime_stack}]",
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
        concat!(asm_sym!("arinsal_x86_test_preserve"), ":"),
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub rsp, 8",
        "mov rbx, 0x0b0b",
        "mov rbp, 0x5005",
        "mov r12, 0x1212",
        "mov r13, 0x1313",
        "mov r14, 0x1414",
        "mov r15, 0x1515",
        concat!("call ", asm_sym!("arinsal_enter_native")),
        "xor eax, eax",
        "cmp rbx, 0x0b0b",
        "jne 4f",
        "cmp rbp, 0x5005",
        "jne 4f",
        "cmp r12, 0x1212",
        "jne 4f",
        "cmp r13, 0x1313",
        "jne 4f",
        "cmp r14, 0x1414",
        "jne 4f",
        "cmp r15, 0x1515",
        "jne 4f",
        "mov eax, 1",
        "4:",
        "add rsp, 8",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
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
        fn arinsal_x86_test_preserve(
            header: *mut ProcessHeader,
            regs: *mut SchedulerRegisters,
            code: *const c_void,
            exit: *mut NativeExit,
        ) -> u64;
    }

    /// A runtime function called from native code on the runtime stack. Heap allocation and
    /// formatting exercise the 16-byte stack alignment the C ABI requires.
    extern "C" fn runtime_hook(c_p: *mut ProcessHeader) -> u64 {
        let words: Vec<u64> = (0..64).collect();
        let text = format!("{:?}", &words[..4]);
        // SAFETY: the test bridge passes the live header it was entered with.
        let fcalls = unsafe { (*c_p).fcalls };
        fcalls as u64 + text.len() as u64
    }

    /// The Rust trace return hook: records its kind and continues at the exit fragment. Like
    /// the VM's `arinsal_beamasm_native_trace_return`, it gets `reg` (`x_reg_array`), not the
    /// start of the register file.
    extern "C" fn trace_hook(_c_p: *mut ProcessHeader, kind: u64, reg: *mut u64) -> usize {
        let registers = SchedulerRegisters::from_reg(reg);
        // SAFETY: the trace fragment passes the `reg` of the live register file it runs with.
        unsafe { (*registers).tmp_mem[7] = kind + 10 };
        arinsal_enter_native_return as *const () as usize
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
            // SAFETY: the test functions above follow the bridge contract.
            unsafe { enter_native_raw(&mut self.header, &mut self.regs, code as *const c_void) }
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
        // The bridge's CP was pushed just below `stop`, 4-byte aligned.
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
    }

    #[test]
    fn jump_to_exit_fragment_yields() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.enter(arinsal_x86_test_yield_jump),
            ExitReason::Yield
        );
        // A jump leaves the bridge's CP on the Erlang stack: `stop` is below it.
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
        // the bridge's own CP below `stop`.
        assert_eq!(fixture.stop_offset(), 31);
    }

    #[test]
    fn bridge_preserves_callee_saved_registers() {
        let mut fixture = Fixture::new();
        let mut exit = NativeExit::default();
        // SAFETY: the test native function follows the bridge contract.
        let preserved = unsafe {
            arinsal_x86_test_preserve(
                &mut fixture.header,
                &mut *fixture.regs,
                arinsal_x86_test_return as *const c_void,
                &mut exit,
            )
        };
        assert_eq!(preserved, 1);
        assert_eq!(exit.kind, 0);
    }
}
