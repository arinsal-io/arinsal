//! Port of erts/emulator/beam/jit/x86/process_main.cpp (emit_process_main), OTP-29.1.1: the
//! scheduler thread's loop. `process_main(esdp)` allocates `ErtsSchedulerRegisters` on its own
//! C stack, then loops over `erts_schedule` and `jmp c_p->i`; native code comes back through
//! `context_switch`, `context_switch_simplified` and `do_schedule` (and, in this port, the
//! native exit fragment), which lead back to `schedule_next`.
//!
//! Deviation (Step D of the generated_process_main plan): between `copy_in_registers` /
//! `REDS_IN` and `jmp c_p->i`, and on every native exit, the loop calls the Rust slice
//! (`arinsal_slice_step`), which still finishes some exits itself and prepares the next
//! entry. It reads the exit kind this loop leaves in `tmp_mem[3]` (1 returned to the exit
//! fragment, 2 scheduled out through `context_switch*` / `do_schedule`, 3 a call handed to
//! the slice with its target and resume address in `tmp_mem[0]`/`[1]`). When the slice ends
//! the loop takes erts' `context_switch` tail (`reds_used`, `copy_out_registers`) into
//! `schedule_next`; `erts_schedule` itself only schedules.

use arinsal_x64::enc::{CondCode, Mem, byte_ptr, dword_ptr, qword_ptr};

use super::beam_asm::register::{
    ACTIVE_CODE_IX, ARG1, ARG1D, ARG2, ARG3, ARG3D, C_P, E, FCALLS, REGISTERS, RET, RETD,
};
use super::beam_asm::{AsmError, Update, get_scheduler_reg_ref, process, process_ref};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::rt::addr;
pub use super::rt::copy_out_registers;
use crate::{SchedulerRegisters, X_REG_ARRAY_OFFSET, tmp_mem_disp};

pub use crate::common::process_offsets::ERTS_PSFLG_EXITING;

/// `ERTS_CACHE_LINE_SIZE`.
const CACHE_LINE_SIZE: i64 = 64;

/// `tmp_mem[index]` of the register file, addressed from `registers`.
const fn tmp_mem(index: usize) -> Mem {
    Mem::base_disp(REGISTERS, tmp_mem_disp(index), 8)
}

/// The exit kind `schedule_next` hands the slice: scheduled out through `context_switch*` or
/// `do_schedule` (see the module documentation).
const EXIT_SCHEDULED_OUT: i64 = 2;

impl BeamGlobalAssembler {
    /// `process_main(esdp)`: binds the `context_switch`, `context_switch_simplified` and
    /// `do_schedule` labels and the native exit fragment ([`Self::native_exit_label`]).
    ///
    /// Called (System V) with `ARG1` = `&esdp->registers`; never returns.
    // Port of erts/emulator/beam/jit/x86/process_main.cpp:53-353 (emit_process_main),
    // OTP-29.1.1.
    pub(crate) fn emit_process_main(&mut self) -> Result<(), AsmError> {
        let context_switch_local = self.asm.new_label();
        let context_switch_simplified_local = self.asm.new_label();
        let do_schedule_local = self.asm.new_label();
        let schedule_out = self.asm.new_label();
        let schedule_next = self.asm.new_label();
        let slice_continue = self.asm.new_label();
        let slice_ended = self.asm.new_label();
        let native_exit = self.asm.new_label();
        self.native_exit = Some(native_exit);
        let process_exit = self.label(GlobalLabels::ProcessExit);
        let dispatch_nif = self.label(GlobalLabels::DispatchNif);
        let state = dword_ptr(C_P, self.offsets.state as i32);
        let def_arg_reg5 = qword_ptr(C_P, self.offsets.def_arg_reg5 as i32);
        let a = &mut self.asm;

        // Allocate the register structure on the stack to allow computing the runtime stack
        // address from it, greatly reducing the cost of stack swapping.
        let size = core::mem::size_of::<SchedulerRegisters>() as i64;
        a.emit(|e| e.sub_ri(E, size + CACHE_LINE_SIZE))?;
        a.emit(|e| e.and_ri(E, !(CACHE_LINE_SIZE - 1)))?;
        a.emit(|e| e.mov_mr(qword_ptr(ARG1, 0), E))?;
        // Center `registers` at the base of x_reg_array so we can use negative 8-bit
        // displacement to address the commonly used aux_regs.
        a.emit(|e| e.lea(REGISTERS, qword_ptr(E, X_REG_ARRAY_OFFSET as i32)))?;
        // start_time_i / start_time: the long_schedule timestamps are the slice's (see the
        // module documentation).
        a.mov_imm(C_P, 0)?;
        a.mov_imm(FCALLS, 0)?;
        a.mov_imm(ARG3, 0)?;
        a.jmp(schedule_next)?;

        a.bind(do_schedule_local)?;
        // reds_used = def_arg_reg[5] - FCALLS is computed at slice_ended, once the slice has
        // seen the exit (module documentation).
        a.jmp(schedule_out)?;

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
            // reds_used and copy_out_registers: at slice_ended, after the slice saw the exit.
        }

        a.bind(schedule_out)?;
        a.emit(|e| e.mov_mr(process_ref(process::FCALLS, 4), FCALLS))?;
        a.emit(|e| e.mov_mi(tmp_mem(3), EXIT_SCHEDULED_OUT))?;
        a.jmp(slice_continue)?;

        // The native exit fragment (`rt::arinsal_enter_native_return` forwards here): a
        // function the slice entered returned (its CP was this fragment), or native code
        // jumped here with an exit marker in tmp_mem[3] and the handoff target and resume
        // address in ARG2/ARG3. Executes on the Erlang stack.
        a.bind(native_exit)?;
        a.emit_enter_runtime(Update::STACK.union(Update::HEAP).union(Update::REDUCTIONS))?;
        a.emit(|e| e.inc_m(tmp_mem(3)))?;
        a.emit(|e| e.mov_mr(tmp_mem(0), ARG2))?;
        a.emit(|e| e.mov_mr(tmp_mem(1), ARG3))?;

        // The Rust slice continues after the exit (module documentation).
        let enter = a.new_label();
        a.bind(slice_continue)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.mov_imm(ARG2, 1)?;
        a.runtime_call(addr(super::rt::arinsal_slice_step as *const ()))?;
        a.emit(|e| e.test_rr(RETD, RETD))?;
        a.jcc(CondCode::NE, enter)?;

        // The slice ended: the tail of erts' context_switch_simplified.
        a.bind(slice_ended)?;
        {
            a.emit(|e| e.mov_rm(FCALLS, process_ref(process::FCALLS, 4)))?;
            // Figure out reds_used. def_arg_reg[5] = REDS_IN.
            a.emit(|e| e.mov_rm(ARG3, def_arg_reg5))?;
            a.emit(|e| e.sub_rr(ARG3D, FCALLS))?;
            // Spill reds_used to FCALLS as we no longer need that value.
            a.emit(|e| e.mov_rr(FCALLS, ARG3D))?;
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.runtime_call(addr(copy_out_registers as *const ()))?;
            // Restore reds_used from FCALLS.
            a.emit(|e| e.mov_rr(ARG3D, FCALLS))?;
        }

        a.bind(schedule_next)?;
        // schedule_next. The long_schedule check (check_monitor_long_schedule) and the
        // msacc cache update are the slice's (module documentation).
        {
            let not_nif = a.new_label();
            let push_exit = a.new_label();
            let jump = a.new_label();
            a.mov_imm(ARG1, 0)?;
            a.emit(|e| e.mov_rr(ARG2, C_P))?;
            a.runtime_call(addr(super::rt::erts_schedule as *const ()))?;
            a.emit(|e| e.mov_rr(C_P, RET))?;

            // Copy arguments.
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.runtime_call(addr(super::rt::copy_in_registers as *const ()))?;

            // Setup reduction counting.
            a.emit(|e| e.mov_rm(FCALLS, process_ref(process::FCALLS, 4)))?;
            a.emit(|e| e.mov_mr(def_arg_reg5, FCALLS.r64()))?;

            // The Rust slice starts (module documentation).
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.mov_imm(ARG2, 0)?;
            a.runtime_call(addr(super::rt::arinsal_slice_step as *const ()))?;
            a.emit(|e| e.test_rr(RETD, RETD))?;
            a.jcc(CondCode::E, slice_ended)?;

            a.bind(enter)?;
            // Setup reduction counting; the slice resolved the active code index (save_calls
            // or the active one) into the register file.
            a.emit(|e| e.mov_rm(FCALLS, process_ref(process::FCALLS, 4)))?;
            a.emit(|e| {
                e.mov_rm(
                    ACTIVE_CODE_IX,
                    get_scheduler_reg_ref(
                        core::mem::offset_of!(SchedulerRegisters, active_code_ix),
                        8,
                    ),
                )
            })?;
            // Runtime error fragments leave through the native exit fragment.
            let exit_fragment = addr(super::rt::arinsal_enter_native_return as *const ());
            a.emit(|e| e.mov_ri(RET, exit_fragment as i64))?;
            a.emit(|e| e.mov_mr(tmp_mem(4), RET))?;

            // Start executing the Erlang process.
            a.emit_leave_runtime(Update::STACK.union(Update::HEAP))?;

            // Returning from a dirty nif call: continue in dispatch_nif.
            a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
            a.emit(|e| e.cmp_mi(qword_ptr(ARG3, 0), arinsal_term::OP_CALL_NIF_WWW as i64))?;
            a.short_jcc(CondCode::NE, not_nif)?;
            a.a.emit_rip_label(dispatch_nif, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
            a.bind(not_nif)?;
            // Deviation (see the module documentation): a call the slice performs for native
            // code gets its caller's CP (`entry_return`), any other entry the exit fragment.
            let entry_return =
                get_scheduler_reg_ref(core::mem::offset_of!(SchedulerRegisters, entry_return), 8);
            a.emit(|e| e.mov_rm(RET, entry_return))?;
            a.emit(|e| e.test_rr(RET, RET))?;
            a.short_jcc(CondCode::E, push_exit)?;
            a.emit(|e| e.mov_mi(entry_return, 0))?;
            a.emit(|e| e.push_r(RET))?;
            a.short_jmp(jump)?;
            a.bind(push_exit)?;
            a.emit(|e| e.mov_ri(RET, exit_fragment as i64))?;
            a.emit(|e| e.push_r(RET))?;
            a.bind(jump)?;
            // A scheduler re-entry can target a BIF continuation, whose result is in RET.
            a.emit(|e| e.mov_rm(RET, qword_ptr(REGISTERS, 0)))?;
            a.emit(|e| e.jmp_r(ARG3))?;
        }

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

    /// The native exit fragment of `process_main` after [`Self::codegen`], which
    /// `rt::arinsal_enter_native_return` forwards to (`rt::set_process_main_labels`).
    pub fn native_exit_ptr(&self) -> Option<usize> {
        self.native_exit.and_then(|label| self.asm.get_code(label))
    }
}
