//! Port of erts/emulator/beam/jit/x86/process_main.cpp (emit_process_main), OTP-29.1.1: the
//! schedule-out half of `process_main`, i.e. the `context_switch`, `context_switch_simplified`
//! and `do_schedule` entries and the code they share up to `schedule_next`.
//!
//! erts' `process_main` is the scheduler thread's loop: it allocates `ErtsSchedulerRegisters`
//! on the runtime stack, then repeatedly calls `erts_schedule`, `copy_in_registers`, sets up
//! reductions and the code index, and jumps to `c_p->i`; native code comes back through the
//! three entries above. In Arinsal the loop (`erts_schedule` and everything after it up to the
//! jump to `c_p->i`) is the Rust scheduler plus the entry bridge `arinsal_enter_native`
//! (`x86::rt`), which the scheduler calls once per slice. The schedule-out half below is
//! erts' code byte for byte up to `schedule_next`; there it publishes `FCALLS` (from which the
//! Rust loop computes `reds_used`, erts' `def_arg_reg[5] - FCALLS`) and jumps to the bridge's
//! `arinsal_schedule_next`, which returns to the Rust loop.

use arinsal_x64::enc::{CondCode, Mem, byte_ptr, dword_ptr, qword_ptr};

use super::beam_asm::register::{ARG1, ARG1D, ARG2, ARG3, C_P, FCALLS};
use super::beam_asm::{AsmError, Update, process, process_ref};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
pub use super::rt::copy_out_registers;

/// `ERTS_PSFLG_EXITING`: `ERTS_PSFLG_BIT(5)`.
// Port of erts/emulator/beam/erl_process.h (ERTS_PSFLG_BIT, ERTS_PSFLG_EXITING), OTP-29.1.1.
pub const ERTS_PSFLG_EXITING: u32 = 1 << (6 + 5);

impl BeamGlobalAssembler {
    /// The schedule-out half of `process_main` (see the module documentation): binds the
    /// `context_switch`, `context_switch_simplified` and `do_schedule` labels.
    // Port of erts/emulator/beam/jit/x86/process_main.cpp:53-353 (emit_process_main),
    // OTP-29.1.1.
    pub(crate) fn emit_process_main(&mut self) -> Result<(), AsmError> {
        let context_switch_local = self.asm.new_label();
        let context_switch_simplified_local = self.asm.new_label();
        let do_schedule_local = self.asm.new_label();
        let schedule_next = self.asm.new_label();
        let process_exit = self.label(GlobalLabels::ProcessExit);
        let state = dword_ptr(C_P, self.offsets.state as i32);
        let a = &mut self.asm;

        // The loop entry (registers on the runtime stack, start_time, c_p = 0, the first
        // `jmp schedule_next`) is the Rust scheduler's: see the module documentation.

        a.bind(do_schedule_local)?;
        // reds_used = def_arg_reg[5] - FCALLS is computed by the Rust loop from c_p->fcalls,
        // published at schedule_next.
        a.jmp(schedule_next)?;

        a.bind(context_switch_local)?;
        // Context switch, unknown arity/MFA.
        {
            let mfa_size = core::mem::size_of::<arinsal_term::ErtsCodeMfa>() as i32;
            let arity_offset =
                core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity) as i32 - mfa_size;
            a.emit(|e| e.movzx_rm(ARG1D, byte_ptr(ARG3, arity_offset)))?;
            a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG1.r8()))?;
            a.emit(|e| e.lea(ARG1, qword_ptr(ARG3, -mfa_size)))?;
            a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG1))?;
        }

        a.bind(context_switch_simplified_local)?;
        // Context switch, known arity and MFA.
        {
            let not_exiting = a.new_label();
            // ERLANG_FRAME_POINTERS: kill the current frame pointer to avoid confusing `perf`.
            #[cfg(target_os = "linux")]
            {
                use super::beam_asm::register::FRAME_POINTER;
                a.emit(|e| e.sub_rr(FRAME_POINTER, FRAME_POINTER))?;
            }
            a.emit(|e| e.mov_mr(process_ref(process::I, 8), ARG3))?;
            a.emit(|e| e.mov_rm(ARG1D, state))?;
            a.emit(|e| e.test_ri(ARG1D, i64::from(ERTS_PSFLG_EXITING)))?;
            a.short_jcc(CondCode::E, not_exiting)?;
            {
                // Process exiting.
                a.a.emit_rip_label(process_exit, |e| e.lea(ARG1, Mem::rip(0, 8)))?;
                a.emit(|e| e.mov_mr(process_ref(process::I, 8), ARG1))?;
                a.emit(|e| e.mov_mi(process_ref(process::ARITY, 1), 0))?;
                a.emit(|e| e.mov_mi(process_ref(process::CURRENT, 8), 0))?;
                a.jmp(do_schedule_local)?;
            }
            a.bind(not_exiting)?;
            // reds_used: see do_schedule_local.
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.runtime_call(copy_out_registers as *const () as usize)?;
        }

        a.bind(schedule_next)?;
        // schedule_next: the Rust scheduler loop (`erts_schedule` .. `jmp c_p->i`).
        a.emit(|e| e.mov_mr(process_ref(process::FCALLS, 4), FCALLS))?;
        a.abs_jmp(super::rt::arinsal_schedule_next as *const () as usize)?;

        // Processes may jump to the exported entry points below, executing on the Erlang
        // stack when entering.
        for (label, local) in [
            (GlobalLabels::ContextSwitch, context_switch_local),
            (
                GlobalLabels::ContextSwitchSimplified,
                context_switch_simplified_local,
            ),
            (GlobalLabels::DoSchedule, do_schedule_local),
        ] {
            let exported = self.label(label);
            let a = &mut self.asm;
            a.bind(exported)?;
            a.emit_enter_runtime(Update::STACK.union(Update::HEAP))?;
            a.jmp(local)?;
        }
        Ok(())
    }
}
