//! Port of erts/emulator/beam/jit/x86/beam_asm.hpp (register assignments, C ABI argument
//! registers, `Update`, scheduler register and Erlang stack addressing) and the frame layout
//! selection and layout checks of erts/emulator/beam/jit/beam_jit_main.cpp
//! (beamasm_init), OTP-29.1.1.
//!
//! Registers are named by their hardware number (the ModRM/REX encoding), as the x86-64
//! encoder addresses them; `FCALLS` is the 32-bit view of its register, as in erts.

use crate::{
    F_REG_ARRAY_DISP, ProcessHeader, RUNTIME_STACK_DISP, X_REG_ARRAY_OFFSET, scheduler_reg_disp,
    tmp_mem_disp,
};

/// x86-64 general purpose register numbers.
pub mod gp {
    pub const RAX: u8 = 0;
    pub const RCX: u8 = 1;
    pub const RDX: u8 = 2;
    pub const RBX: u8 = 3;
    pub const RSP: u8 = 4;
    pub const RBP: u8 = 5;
    pub const RSI: u8 = 6;
    pub const RDI: u8 = 7;
    pub const R8: u8 = 8;
    pub const R9: u8 = 9;
    pub const R10: u8 = 10;
    pub const R11: u8 = 11;
    pub const R12: u8 = 12;
    pub const R13: u8 = 13;
    pub const R14: u8 = 14;
    pub const R15: u8 = 15;
}

/// BeamAsm's pinned registers on x86-64.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:105-181 (BeamAssembler), OTP-29.1.1.
pub mod register {
    use super::gp;

    /// `registers`: points at `x_reg_array` inside the scheduler's `SchedulerRegisters`.
    pub const REGISTERS: u8 = gp::RBX;
    /// `E`: the Erlang stack pointer. erts defines `NATIVE_ERLANG_STACK` on every x86-64
    /// target but OpenBSD (configure.ac), so the Erlang stack is the native stack and `E` is
    /// `rsp`, invalid while running on the runtime stack.
    pub const E: u8 = gp::RSP;
    /// `E_saved`: holds `E` across a runtime call that does not publish the stack.
    pub const E_SAVED: u8 = gp::RBP;
    /// `frame_pointer` under `ERLANG_FRAME_POINTERS` (Linux), used by the `FP_RA` layout.
    #[cfg(target_os = "linux")]
    pub const FRAME_POINTER: u8 = gp::RBP;
    /// `c_p`: the current process.
    pub const C_P: u8 = gp::R13;
    /// `FCALLS`: remaining reductions, the 32-bit view `r14d`.
    pub const FCALLS: u8 = gp::R14;
    /// `HTOP`: the young heap top.
    pub const HTOP: u8 = gp::R15;
    /// `active_code_ix`: local copy of the active code index (or `ERTS_SAVE_CALLS_CODE_IX`).
    pub const ACTIVE_CODE_IX: u8 = gp::R12;

    /// C argument registers, `ARG1`..`ARG6` (System V AMD64).
    #[cfg(not(windows))]
    pub const ARG: [u8; 6] = [gp::RDI, gp::RSI, gp::RDX, gp::RCX, gp::R8, gp::R9];
    /// Caller-saved scratch registers `TMP1`, `TMP2` (System V AMD64).
    #[cfg(not(windows))]
    pub const TMP: [u8; 2] = [gp::R10, gp::R11];

    /// C argument registers, `ARG1`..`ARG6` (`ERTS_JIT_ABI_WIN32`). The Win64 convention
    /// passes four arguments in registers; `runtime_call` pushes ARG5/ARG6 for the callee.
    #[cfg(windows)]
    pub const ARG: [u8; 6] = [gp::RCX, gp::RDX, gp::R8, gp::R9, gp::R10, gp::R11];
    /// Caller-saved scratch registers `TMP1`, `TMP2` (`ERTS_JIT_ABI_WIN32`).
    #[cfg(windows)]
    pub const TMP: [u8; 2] = [gp::RDI, gp::RSI];

    /// `RET`: C return value.
    pub const RET: u8 = gp::RAX;
}

/// Bytes `runtime_call` reserves below the arguments for the callee: Win64's shadow space.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:497-529 (runtime_call), OTP-29.1.1.
#[cfg(windows)]
pub const RUNTIME_CALL_SHADOW_SPACE: i32 = 4 * 8;
/// Bytes `runtime_call` reserves below the arguments for the callee: none on System V.
#[cfg(not(windows))]
pub const RUNTIME_CALL_SHADOW_SPACE: i32 = 0;

/// Erlang stack frame layout, erts `ErtsFrameLayout`.
// Port of erts/emulator/beam/erl_vm.h:70-86, OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameLayout {
    /// Each frame holds only its return address (`ERTS_FRAME_LAYOUT_RA`).
    Ra,
    /// Each frame holds a frame pointer and the return address (`ERTS_FRAME_LAYOUT_FP_RA`).
    FpRa,
}

/// The frame layout native code is emitted for.
///
/// erts hardcodes `ERTS_FRAME_LAYOUT_RA` without `ERLANG_FRAME_POINTERS` (every x86-64
/// target but Linux). On Linux `beamasm_init` picks `FP_RA` only for `+JPperf fp`; without it
/// the layout is `RA`, the only one this port emits.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:276-289 (beamasm_init), OTP-29.1.1.
pub const FRAME_LAYOUT: FrameLayout = FrameLayout::Ra;

/// Words a return address takes in an Erlang frame (`CP_SIZE` for the `RA` layout).
// Port of erts/emulator/beam/erl_vm.h:85 (CP_SIZE), OTP-29.1.1.
pub const CP_SIZE: usize = 1;

/// Selects process fields synchronized at a native/runtime boundary (erts `Update`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:655-667 (enum Update), OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Update(u8);

impl Update {
    /// No state synchronization.
    pub const NONE: Self = Self(0);
    /// `eStack`: publish/reload `E` through `c_p->stop`.
    pub const STACK: Self = Self(1 << 0);
    /// `eHeap`: publish/reload `HTOP` through `c_p->htop`.
    pub const HEAP: Self = Self(1 << 1);
    /// `eReductions`: publish/reload `FCALLS` through `c_p->fcalls`.
    pub const REDUCTIONS: Self = Self(1 << 2);
    /// `eCodeIndex`: reload `active_code_ix`, keeping save_calls.
    pub const CODE_INDEX: Self = Self(1 << 3);
    /// `eHeapAlloc`: runtime functions that allocate heap.
    pub const HEAP_ALLOC: Self = Self(Self::HEAP.0 | Self::STACK.0);
    /// `eHeapOnlyAlloc` in a release build.
    pub const HEAP_ONLY_ALLOC: Self = Self::HEAP;

    /// Combines synchronization flags.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every flag of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Displacement from `registers` of X register `index` (`getXRef`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:252-258 (getXRef), OTP-29.1.1.
pub const fn x_ref_disp(index: u32) -> i32 {
    assert!(index < 1024);
    scheduler_reg_disp(X_REG_ARRAY_OFFSET + index as usize * 8)
}

/// Displacement from `registers` of float register `index` (`getFRef`).
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:244-250 (getFRef), OTP-29.1.1.
pub const fn f_ref_disp(index: u32) -> i32 {
    assert!(index < 1024);
    F_REG_ARRAY_DISP + index as i32 * 8
}

/// Displacement from `registers` of `TMP_MEM{index+1}q`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:183-207 (TMP_MEM1q..TMP_MEM5q), OTP-29.1.1.
pub const fn tmp_mem_q_disp(index: u32) -> i32 {
    assert!(index < 5);
    tmp_mem_disp(index as usize)
}

/// Displacement from `E` of Y register `index` (`getYRef`). With `NATIVE_ERLANG_STACK` the
/// return address sits above the Y registers, so Y0 is at `E` itself.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:260-268 (getYRef), OTP-29.1.1.
pub const fn y_ref_disp(index: u32) -> i32 {
    assert!(index < 1024);
    index as i32 * 8
}

// Port of erts/emulator/beam/jit/beam_jit_main.cpp:291-305 (beamasm_init), OTP-29.1.1: the
// commonly used process fields must be reachable with an 8-bit displacement from `c_p`.
const _: () = {
    assert!(core::mem::offset_of!(ProcessHeader, htop) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, stop) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, fcalls) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, exc.freason) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, exc.fvalue) < 128);
    assert!(core::mem::offset_of!(ProcessHeader, flags) < 128);
    // jit/x86/beam_asm.hpp:711-712 (emit_enter_runtime): `htop` and `stop` are stored together
    // with one 16-byte vector store.
    assert!(
        core::mem::offset_of!(ProcessHeader, stop) - core::mem::offset_of!(ProcessHeader, htop)
            == 8
    );
    // `registers` points at x_reg_array; the auxiliary registers before it take 8-bit
    // displacements (getSchedulerRegRef's ERTS_CT_ASSERT(x_reg_offset <= 128)).
    assert!(x_ref_disp(0) == 0);
    assert!(f_ref_disp(0) == 8192);
    assert!(tmp_mem_q_disp(4) >= -128 && tmp_mem_q_disp(4) < 0);
    assert!(RUNTIME_STACK_DISP >= -128);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_registers_match_erts() {
        assert_eq!(register::REGISTERS, gp::RBX);
        assert_eq!(register::E, gp::RSP);
        assert_eq!(register::C_P, gp::R13);
        assert_eq!(register::FCALLS, gp::R14);
        assert_eq!(register::HTOP, gp::R15);
        assert_eq!(register::ACTIVE_CODE_IX, gp::R12);
        assert_eq!(register::RET, gp::RAX);
    }

    #[cfg(not(windows))]
    #[test]
    fn sysv_argument_registers() {
        assert_eq!(
            register::ARG,
            [gp::RDI, gp::RSI, gp::RDX, gp::RCX, gp::R8, gp::R9]
        );
        assert_eq!(register::TMP, [gp::R10, gp::R11]);
    }

    #[test]
    fn update_sets() {
        assert!(Update::HEAP_ALLOC.contains(Update::STACK));
        assert!(Update::HEAP_ALLOC.contains(Update::HEAP));
        assert!(!Update::HEAP_ALLOC.contains(Update::REDUCTIONS));
        assert_eq!(Update::HEAP_ONLY_ALLOC, Update::HEAP);
    }

    #[test]
    fn stack_and_register_displacements() {
        assert_eq!(x_ref_disp(1023), 1023 * 8);
        assert_eq!(f_ref_disp(1), 8200);
        assert_eq!(tmp_mem_q_disp(4), -120 + 32);
        assert_eq!(y_ref_disp(3), 24);
    }
}
