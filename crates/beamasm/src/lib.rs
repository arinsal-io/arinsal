//! Runtime ABI for BeamAsm native code.
//!
//! As erts builds erts/emulator/beam/jit/ with exactly one of jit/arm or jit/x86, the crate
//! holds the architecture-neutral port of jit/beam_jit_*.{cpp,hpp} in `common`, the AArch64
//! emitters in `arm` and the x86-64 ABI and native entry in `x86`, re-exported here as the
//! single public facade.

#![deny(unsafe_code)]

pub mod common;
pub use arinsal_term::exc;
pub use arinsal_term::exc::ExcFields;
pub use common::types;

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "aarch64")]
pub use arm::*;

#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
pub use x86::*;

/// C-layout process header consumed directly by BeamAsm generated code.
///
/// Native fields live at their fixed erts offsets in the process heap.
pub type ProcessHeader = arinsal_term::NativeAbi;

const _: () = assert!(std::mem::offset_of!(ProcessHeader, fcalls) == 0x20);
const _: () = assert!(std::mem::offset_of!(ProcessHeader, exc) == 0x28);
const _: () = assert!(std::mem::offset_of!(ProcessHeader, catches) == 0x40);
const _: () = assert!(std::mem::offset_of!(ProcessHeader, high_water) == 0x70);
const _: () = assert!(std::mem::offset_of!(SchedulerRegisters, x_reg_array) == 0);

/// Register backing storage addressed by BeamAsm's x19.
#[repr(C)]
pub struct SchedulerRegisters {
    /// X register array; x19 points to element zero. Typed like erts' `Eterm *reg`, so the
    /// runtime hands BIFs `&reg[..arity]` as their arguments without a copy.
    // Port of erts/emulator/beam/bif.h:33-40 (BIF_ARG_n is reg[n]), OTP-29.1.1.
    pub x_reg_array: [arinsal_term::Term; 1024],
    /// Floating point register array.
    pub f_reg_array: [f64; 1024],
    /// Scratch words accessed by runtime fragments; word 6 records the pc of a native error.
    pub tmp_mem: [u64; 8],
    /// Operands of a `bs_match` command for its runtime hook. They are kept out of the X
    /// register array, whose registers above the command's live count may still be in use.
    pub match_staging: [u64; 4],
    /// Code index loaded into `active_code_ix` (x24) on every entry into native code:
    /// the node's active code index, or `ERTS_SAVE_CALLS_CODE_IX` for a process saving calls.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:236-247, OTP-29.1.1.
    pub active_code_ix: u64,
    /// Return address the next native entry starts with in `x30`; zero means the exit
    /// bridge. The entry trampoline consumes it.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:256-261 (emit_i_apply_only), OTP-29.1.1:
    // a call entered from the scheduler gets its caller's continuation in LR, like any other
    // call, so the callee's frame holds that one CP.
    pub entry_return: u64,
    /// Return address a trapping BIF call site leaves for the shared helper fragment: the
    /// point after the call where XREG0 holds the result, as after any Erlang call. The trap
    /// target returns there directly, so it is the address the fragment pushes as CP.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:527-540, OTP-29.1.1: erts pushes the
    // call site's return address, behind which the BIF result is in XREG0.
    pub trap_return: u64,
    /// Binary construction cursor (`erts_current_bin`, `erts_bin_offset`).
    /// Appended after the frozen prefix so existing BeamAsm offsets stay put.
    // Port of erts/emulator/beam/erl_bits.h:181 (struct erl_bits_state), OTP-29.1.1.
    pub erl_bits_state: [u64; 2],
    /// `aux_regs.d.runtime_stack`: on x86-64 the Erlang stack is the native stack, so native
    /// code switches `rsp` back to the runtime (scheduler thread) stack held here before every
    /// runtime call. Unused on arm64, where `E` is a separate register, as in erts.
    // Port of erts/emulator/beam/erl_process.h (ErtsSchedulerRegisters.aux_regs.d.runtime_stack)
    // and erts/emulator/beam/jit/x86/beam_asm.hpp (getRuntimeStackRef), OTP-29.1.1.
    pub runtime_stack: u64,
}

/// Offset of `SchedulerRegisters::active_code_ix`, read by the native entry trampoline.
pub const ACTIVE_CODE_IX_OFFSET: usize = std::mem::offset_of!(SchedulerRegisters, active_code_ix);
const _: () = assert!(ACTIVE_CODE_IX_OFFSET == 16480);

/// Offset of `SchedulerRegisters::entry_return`, read by the native entry trampoline.
pub const ENTRY_RETURN_OFFSET: usize = std::mem::offset_of!(SchedulerRegisters, entry_return);
const _: () = assert!(ENTRY_RETURN_OFFSET == 16488);

/// Offset of `SchedulerRegisters::trap_return`, read by the shared helper fragment.
pub const TRAP_RETURN_OFFSET: usize = std::mem::offset_of!(SchedulerRegisters, trap_return);
const _: () = assert!(TRAP_RETURN_OFFSET == 16496);

/// Offset of `SchedulerRegisters::runtime_stack`, the x86-64 runtime stack slot.
pub const RUNTIME_STACK_OFFSET: usize = std::mem::offset_of!(SchedulerRegisters, runtime_stack);
const _: () = assert!(RUNTIME_STACK_OFFSET == 16520);

impl Default for SchedulerRegisters {
    fn default() -> Self {
        Self {
            x_reg_array: [arinsal_term::Term::NIL; 1024],
            f_reg_array: [0.0; 1024],
            tmp_mem: [0; 8],
            match_staging: [0; 4],
            active_code_ix: 0,
            entry_return: 0,
            trap_return: 0,
            erl_bits_state: [0, 0],
            runtime_stack: 0,
        }
    }
}

/// BeamAsm register assignments on arm64.
/// Native execution outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Native code returned with reductions remaining.
    Returned,
    /// Native code returned after exhausting reductions.
    Yield,
    /// Native code requested interpretation at the supplied instruction pointer.
    CallUnported { target_pc: usize, resume_pc: usize },
    /// Native execution is unavailable on this target architecture.
    Unsupported,
}

// ProcessHeader is a fixed prefix copied from the OTP Process offsets used by BeamAsm.
const _: () = {
    assert!(core::mem::offset_of!(ProcessHeader, htop) == 0x00);
    assert!(core::mem::offset_of!(ProcessHeader, stop) == 0x08);
    assert!(core::mem::offset_of!(ProcessHeader, heap) == 0x10);
    assert!(core::mem::offset_of!(ProcessHeader, hend) == 0x18);
    assert!(core::mem::offset_of!(ProcessHeader, fcalls) == 0x20);
    assert!(core::mem::offset_of!(ProcessHeader, exc.freason) == 0x28);
    assert!(core::mem::offset_of!(ProcessHeader, exc.fvalue) == 0x30);
    assert!(core::mem::offset_of!(ProcessHeader, exc.ftrace) == 0x38);
    assert!(core::mem::offset_of!(ProcessHeader, catches) == 0x40);
    assert!(core::mem::offset_of!(ProcessHeader, i) == 0x48);
    assert!(core::mem::offset_of!(ProcessHeader, arity) == 0x50);
    assert!(core::mem::offset_of!(ProcessHeader, current) == 0x58);
    assert!(core::mem::offset_of!(ProcessHeader, flags) == 0x60);
    assert!(core::mem::offset_of!(ProcessHeader, self_pid) == 0x68);
    assert!(core::mem::offset_of!(SchedulerRegisters, x_reg_array) == 0);
    assert!(core::mem::offset_of!(SchedulerRegisters, f_reg_array) == 8192);
    assert!(core::mem::offset_of!(SchedulerRegisters, tmp_mem) == 16384);
};
