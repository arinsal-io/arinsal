//! Audited native runtime transition core.

use super::{ExitReason, NativeEntry, ProcessHeader, SchedulerRegisters};
use core::ffi::c_void;

/// Returns the tagged word for a test-owned term whose heap remains live.
pub fn term_bits(term: arinsal_term::Term) -> u64 {
    // SAFETY: Callers use terms created by TermBuilder and retain their owning heap.
    unsafe { term.raw_bits() }
}

/// Reads a tuple view for a test-owned term with a live owner heap.
pub fn tuple_ref(term: arinsal_term::Term) -> Option<arinsal_term::TupleRef<'static>> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.tuple_ref() }
}

/// Reads a cons cell for a test-owned term with a live owner heap.
pub fn cons_ref(term: arinsal_term::Term) -> Option<(arinsal_term::Term, arinsal_term::Term)> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.cons_ref() }
}

/// Reads a binary view for a test-owned term with a live owner heap.
pub fn binary_bit_len(term: arinsal_term::Term) -> Option<usize> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.binary_ref() }.map(|view| view.bit_len())
}

/// Reads a flat map view for a test-owned term with a live owner heap.
pub fn flatmap_ref(term: arinsal_term::Term) -> Option<arinsal_term::FlatMapRef<'static>> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.flatmap_ref() }
}

/// Reads a fun view for a test-owned term with a live owner heap.
pub fn fun_ref(term: arinsal_term::Term) -> Option<arinsal_term::FunRef<'static>> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.fun_ref() }
}

/// Exposes a native process header to a C ABI hook during its call.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn process_header_mut<R>(
    pointer: *mut ProcessHeader,
    f: impl FnOnce(&mut ProcessHeader) -> R,
) -> R {
    // SAFETY: The BeamAsm entry bridge passes the unique live header pointer for this invocation.
    unsafe { f(&mut *pointer) }
}

/// Exposes scheduler registers to a C ABI hook during its call.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn scheduler_registers_mut<R>(
    pointer: *mut SchedulerRegisters,
    f: impl FnOnce(&mut SchedulerRegisters) -> R,
) -> R {
    // SAFETY: x19 points to the unique live register area for this invocation.
    unsafe { f(&mut *pointer) }
}

/// Copies initialized test heap words into a new allocation.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn copy_words(source: *const u64, destination: *mut u64, count: usize) {
    // SAFETY: Test GC hooks pass live, disjoint allocations and the initialized source prefix.
    unsafe { core::ptr::copy_nonoverlapping(source, destination, count) }
}

/// Reads a heap word from a tagged boxed pointer in a retained test fixture.
pub fn read_heap_word(tagged: u64, index: usize) -> u64 {
    let pointer = (tagged & !7) as *const u64;
    // SAFETY: The test fixture retains the allocated object and callers select a valid field.
    unsafe { *pointer.add(index) }
}

/// Per-call exit fragment result passed between the assembly bridge and Rust.
#[repr(C)]
#[derive(Default)]
struct NativeExit {
    kind: u64,
    target: usize,
    resume: usize,
}

/// Enters generated native code with BeamAsm's pinned register map.
///
/// Native code returns to the private exit fragment with `x0 = 0` for return,
/// `x0 = 2` and `x1 = target_pc` for an unported function, or any other value
/// to use reductions (`fcalls <= 0` yields).
///
/// # Safety
/// `code_ptr` must point to executable AArch64 code that follows the BeamAsm
/// register contract and returns to the bridge exit address in `x30`.
// Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1
pub(super) fn enter_native(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    entry: &NativeEntry<'_>,
) -> ExitReason {
    let code_ptr = entry.memory.ptr_at(entry.offset).cast::<c_void>();
    // SAFETY: a NativeEntry is only created by `finalize` and borrows its live code mapping.
    unsafe { enter_native_raw(header, regs, code_ptr) }
}

/// Enters generated code by raw address through the process-wide pinned-register trampoline.
/// Callers keep code alive themselves (the VM's native code registry).
///
/// # Safety
/// `code_ptr` must point into a live executable mapping produced by the module assembler, at a
/// function entry that follows the BeamAsm register contract.
pub unsafe fn enter_native_raw(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    code_ptr: *const c_void,
) -> ExitReason {
    #[cfg(target_arch = "aarch64")]
    {
        let mut exit = NativeExit::default();
        // SAFETY: The assembly bridge saves host callee-saved registers, loads the documented
        // ProcessHeader/SchedulerRegisters layout, branches to code_ptr, and returns via its exit label.
        unsafe { arinsal_enter_native(header, regs, code_ptr, &mut exit) };
        match exit.kind {
            2 => ExitReason::CallUnported {
                target_pc: exit.target,
                resume_pc: exit.resume,
            },
            0 if header.fcalls > 0 => ExitReason::Returned,
            _ => ExitReason::Yield,
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (header, regs, code_ptr);
        ExitReason::Unsupported
    }
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    pub fn arinsal_enter_native_return();
    pub fn arinsal_enter_native_yield();
    pub fn arinsal_enter_native_trace_return();
    fn arinsal_enter_native(
        header: *mut ProcessHeader,
        regs: *mut SchedulerRegisters,
        code: *const c_void,
        exit: *mut NativeExit,
    );
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global _arinsal_enter_native",
    "_arinsal_enter_native:",
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1.
    // Keep this entry trampoline and the exit fragment below shared across entries.
    // Preserve AAPCS64 callee-saved GPRs, frame/link registers, and d8-d15.
    "stp x29, x30, [sp, #-16]!",
    "stp x19, x20, [sp, #-16]!",
    "stp x21, x22, [sp, #-16]!",
    "stp x23, x24, [sp, #-16]!",
    "stp x25, x26, [sp, #-16]!",
    "stp x27, x28, [sp, #-16]!",
    "stp d8, d9, [sp, #-16]!",
    "stp d10, d11, [sp, #-16]!",
    "stp d12, d13, [sp, #-16]!",
    "stp d14, d15, [sp, #-16]!",
    "sub sp, sp, #16",
    "str x3, [sp, #0]",
    // x19 is exactly x_reg_array's address; x21 is c_p.
    "mov x19, x1",
    "mov x21, x0",
    "ldr x20, [x21, #8]",
    "ldr w22, [x21, #32]",
    "ldr x23, [x21, #0]",
    "mov x24, xzr",
    "ldp x25, x26, [x19, #0]",
    "ldp x27, x28, [x19, #16]",
    "ldp x15, x16, [x19, #32]",
    // Resume the Erlang FP_RA chain; zero in a fresh register area is its terminator.
    "ldr x29, [x19, #16400]",
    "add x14, x19, #8192",
    "ldp d8, d9, [x14, #0]",
    "ldp d10, d11, [x14, #16]",
    "ldp d12, d13, [x14, #32]",
    "ldp d14, d15, [x14, #48]",
    // The native function's RET lands at the ABI exit fragment.
    "adrp x30, _arinsal_enter_native_return@PAGE",
    "add x30, x30, _arinsal_enter_native_return@PAGEOFF",
    // Runtime error fragments use this slot after runtime hooks replace x30.
    "str x30, [x19, #16416]",
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:284-288, OTP-29.1.1.
    // A scheduler re-entry can target a BIF continuation, whose result is in XREG0.
    "ldr x0, [x19]",
    "br x2",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global _arinsal_enter_native_trace_return",
    "_arinsal_enter_native_trace_return:",
    // Publish the BEAM cursors and register cache before the Rust trace hook.
    "str x20, [x21, #8]",
    "str x23, [x21, #0]",
    "str w22, [x21, #32]",
    "stp x25, x26, [x19, #0]",
    "stp x27, x28, [x19, #16]",
    "stp x15, x16, [x19, #32]",
    "add x15, x19, #8192",
    "stp d8, d9, [x15, #0]",
    "stp d10, d11, [x15, #16]",
    "stp d12, d13, [x15, #32]",
    "stp d14, d15, [x15, #48]",
    "mov x0, x21",
    "ldr x16, [x19, #16424]",
    "blr x16",
    "mov x14, x0",
    "ldr x20, [x21, #8]",
    "ldr x23, [x21, #0]",
    "ldr w22, [x21, #32]",
    "ldp x25, x26, [x19, #0]",
    "ldp x27, x28, [x19, #16]",
    "ldp x15, x16, [x19, #32]",
    "add x17, x19, #8192",
    "ldp d8, d9, [x17, #0]",
    "ldp d10, d11, [x17, #16]",
    "ldp d12, d13, [x17, #32]",
    "ldp d14, d15, [x17, #48]",
    "br x14",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global _arinsal_enter_native_return",
    "_arinsal_enter_native_return:",
    // The marker distinguishes an interpreter handoff without adding work to each BEAM return.
    "ldr x9, [x19, #16408]",
    "cbnz x9, 1f",
    "mov x0, xzr",
    "b 2f",
    "1:",
    "mov x0, x9",
    "2:",
    "b 3f",
    ".global _arinsal_enter_native_yield",
    "_arinsal_enter_native_yield:",
    "mov x0, #1",
    "3:",
    // Spill native process state and all six register-backed X registers.
    "str x29, [x19, #16400]",
    "str x23, [x21, #0]",
    "str x20, [x21, #8]",
    "str w22, [x21, #32]",
    "stp x25, x26, [x19, #0]",
    "stp x27, x28, [x19, #16]",
    "stp x15, x16, [x19, #32]",
    "add x14, x19, #8192",
    "stp d8, d9, [x14, #0]",
    "stp d10, d11, [x14, #16]",
    "stp d12, d13, [x14, #32]",
    "stp d14, d15, [x14, #48]",
    // Keep the output pointer in this bridge's own stack frame across native code.
    "ldr x9, [sp, #0]",
    "stp x0, x1, [x9]",
    "str x2, [x9, #16]",
    "add sp, sp, #16",
    "ldp d14, d15, [sp], #16",
    "ldp d12, d13, [sp], #16",
    "ldp d10, d11, [sp], #16",
    "ldp d8, d9, [sp], #16",
    "ldp x27, x28, [sp], #16",
    "ldp x25, x26, [sp], #16",
    "ldp x23, x24, [sp], #16",
    "ldp x21, x22, [sp], #16",
    "ldp x19, x20, [sp], #16",
    "ldp x29, x30, [sp], #16",
    "ret",
);
