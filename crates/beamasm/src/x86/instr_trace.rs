//! Breakpoint, return-trace and hibernate instructions.
//!
//! Port of erts/emulator/beam/jit/x86/instr_trace.cpp, OTP-29.1.1.

use arinsal_term::{ErtsCodeMfa, Term, atoms};
use arinsal_x64::enc::{CondCode, Mem, qword_ptr};

use super::beam_asm::register::{ARG1, ARG2, ARG3, ARG4, ARG5, C_P, E, RET};
use super::beam_asm::{AsmError, Update, get_x_ref, get_y_ref, process, process_ref};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, ErtsCodeInfo};
use super::rt::{
    beam_jit_return_to_trace, erts_call_trace_return, erts_generic_breakpoint, erts_hibernate,
    erts_trace_return,
};
use crate::common::args::ArgVal;

const BEAM_RETURN_TRACE_FRAME_SZ: u32 = 3;
const BEAM_RETURN_TO_TRACE_FRAME_SZ: u32 = 1;
const BEAM_RETURN_CALL_ACC_TRACE_FRAME_SZ: u32 = 3;
const CP_MASK: i64 = 3;
const CP_SIZE_BYTES: i64 = 8;
const F_HIBERNATE_SCHED: i64 = 1;

/// The runtime wrapper around `erts_trace_return` used by the static helper in erts.
// Port of erts/emulator/beam/jit/x86/instr_trace.cpp:172-180 (return_trace), OTP-29.1.1.
extern "C" fn return_trace(
    c_p: *mut crate::ProcessHeader,
    mfa: *mut ErtsCodeMfa,
    value: u64,
    tracer: u64,
    session_id: u64,
) {
    // `ERTS_UNREQ_PROC_MAIN_LOCK` / `ERTS_REQ_PROC_MAIN_LOCK` compile to no-ops in release
    // builds without ERTS_ENABLE_LOCK_CHECK, which is the runtime this assembler emits for.
    // The release body calls the trace helper directly between those no-op macros.
    erts_trace_return(c_p, mfa, value, tracer, session_id)
}

impl BeamGlobalAssembler {
    /// Dispatches a trace breakpoint attached to an export entry.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:35-57 (emit_generic_bp_global),
    // OTP-29.1.1.
    pub(crate) fn emit_generic_bp_global(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit_enter_frame()?;
        let spec = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        a.emit_enter_runtime(spec)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| {
            e.lea(
                ARG2,
                qword_ptr(RET, arinsal_term::EXPORT_INFO_OFFSET as i32),
            )
        })?;
        a.load_x_reg_array(ARG3)?;
        a.runtime_call(erts_generic_breakpoint as *const () as usize)?;
        a.emit_leave_runtime(spec)?;
        a.emit_leave_frame()?;
        a.emit(|e| e.jmp_r(RET))
    }

    /// Dispatches a trace breakpoint attached to a local function's code info.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:59-129 (emit_generic_bp_local),
    // OTP-29.1.1.
    pub(crate) fn emit_generic_bp_local(&mut self) -> Result<(), AsmError> {
        let debug_bp = self.label(GlobalLabels::DebugBp);
        let a = &mut self.asm;
        a.emit_assert_erlang_stack();
        #[cfg(not(target_os = "openbsd"))]
        {
            a.emit(|e| e.pop_m(tmp_mem(1)))?;
            a.emit(|e| e.pop_r(ARG2))?;
        }
        #[cfg(target_os = "openbsd")]
        a.emit(|e| e.mov_rm(ARG2, qword_ptr(arinsal_x64::enc::RSP, 8)))?;
        a.emit(|e| e.mov_mr(tmp_mem(0), ARG2))?;
        a.emit(|e| {
            e.sub_ri(
                ARG2,
                CP_SIZE_BYTES + core::mem::size_of::<ErtsCodeInfo>() as i64,
            )
        })?;
        a.emit_enter_frame()?;
        let spec = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        a.emit_enter_runtime(spec)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG3)?;
        a.runtime_call(erts_generic_breakpoint as *const () as usize)?;
        a.emit_leave_runtime(spec)?;
        a.emit_leave_frame()?;
        // `BeamOpCodeAddr` is the BEAMASM opcode index from jit/x86/ops.tab.
        a.emit(|e| e.cmp_ri(RET, 101))?;
        a.jcc(CondCode::E, debug_bp)?;
        #[cfg(not(target_os = "openbsd"))]
        {
            a.emit(|e| e.push_m(tmp_mem(0)))?;
            a.emit(|e| e.push_m(tmp_mem(1)))?;
        }
        a.emit(|e| e.ret())
    }

    /// Handles the debug breakpoint result from `erts_generic_breakpoint`.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:131-170 (emit_debug_bp),
    // OTP-29.1.1.
    pub(crate) fn emit_debug_bp(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        let error = a.new_label();
        #[cfg(target_os = "openbsd")]
        a.emit(|e| e.add_ri(arinsal_x64::enc::RSP, 2 * CP_SIZE_BYTES))?;
        a.emit_assert_erlang_stack();
        a.emit_enter_frame()?;
        let spec = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        a.emit_enter_runtime(spec)?;
        a.emit(|e| e.mov_rm(ARG2, tmp_mem(0)))?;
        a.emit(|e| e.sub_ri(ARG2, CP_SIZE_BYTES))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| {
            e.lea(
                ARG2,
                qword_ptr(ARG2, -(core::mem::size_of::<ErtsCodeMfa>() as i32)),
            )
        })?;
        a.load_x_reg_array(ARG3)?;
        a.mov_imm(ARG4, Term::atom(atoms::BREAKPOINT).word())?;
        a.runtime_call(super::rt::call_error_handler as *const () as usize)?;
        a.emit_leave_runtime(spec)?;
        a.emit_leave_frame()?;
        a.emit(|e| e.test_rr(RET, RET))?;
        a.jcc(CondCode::E, error)?;
        let target = a.emit_setup_dispatchable_call_active(RET)?;
        a.emit(|e| e.jmp_m(target))?;
        a.bind(error)?;
        a.emit(|e| e.mov_rm(ARG2, tmp_mem(0)))?;
        self.asm.jmp(self.label(GlobalLabels::RaiseException))
    }
}

impl BeamModuleAssembler {
    /// Installs a return-trace frame and continues at its continuation pointer.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:182-201 (emit_return_trace),
    // OTP-29.1.1.
    pub fn emit_return_trace(&mut self) -> Result<(), AsmError> {
        self.asm.emit(|e| e.mov_rm(ARG2, get_y_ref(0, 8)))?;
        self.asm.emit(|e| e.mov_rm(ARG3, get_x_ref(0, 8)))?;
        self.asm.emit(|e| e.mov_rm(ARG4, get_y_ref(1, 8)))?;
        self.asm.emit(|e| e.mov_rm(ARG5, get_y_ref(2, 8)))?;
        self.asm.emit_enter_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.runtime_call(return_trace as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::HEAP_ALLOC)?;
        self.emit_deallocate(ArgVal::Word(u64::from(BEAM_RETURN_TRACE_FRAME_SZ)))?;
        self.emit_return_do(true)
    }

    /// Returns from a call-trace frame, normalizing its optional previous code info.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:203-227 (emit_i_call_trace_return),
    // OTP-29.1.1.
    pub fn emit_i_call_trace_return(&mut self) -> Result<(), AsmError> {
        self.asm.emit(|e| e.mov_rm(ARG2, get_y_ref(0, 8)))?;
        self.asm.mov_imm(ARG4, 0)?;
        self.asm.emit(|e| e.test_ri(ARG2, CP_MASK))?;
        self.asm.emit(|e| {
            e.lea(
                ARG2,
                qword_ptr(ARG2, -(core::mem::size_of::<ErtsCodeInfo>() as i32)),
            )
        })?;
        self.asm.emit(|e| e.cmovcc_rr(CondCode::NE, ARG2, ARG4))?;
        self.asm.emit(|e| e.mov_rm(ARG3, get_y_ref(1, 8)))?;
        self.asm.emit(|e| e.mov_rm(ARG4, get_y_ref(2, 8)))?;
        self.asm.emit_enter_runtime(Update::HEAP_ALLOC)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(erts_call_trace_return as *const () as usize)?;
        self.asm.emit_leave_runtime(Update::HEAP_ALLOC)?;
        self.emit_deallocate(ArgVal::Word(u64::from(BEAM_RETURN_CALL_ACC_TRACE_FRAME_SZ)))?;
        self.emit_return_do(true)
    }

    /// Returns from an instrumented call to its saved continuation.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:229-252 (emit_i_return_to_trace),
    // OTP-29.1.1.
    pub fn emit_i_return_to_trace(&mut self) -> Result<(), AsmError> {
        #[cfg(not(target_os = "openbsd"))]
        let frame_size = BEAM_RETURN_TO_TRACE_FRAME_SZ;
        #[cfg(target_os = "openbsd")]
        let frame_size = BEAM_RETURN_TO_TRACE_FRAME_SZ + 1;
        self.asm.emit(|e| e.mov_rm(ARG2, get_y_ref(0, 8)))?;
        self.asm
            .emit(|e| e.lea(ARG3, qword_ptr(E, (frame_size * 8) as i32)))?;
        let spec = Update::REDUCTIONS.union(Update::HEAP_ALLOC);
        self.asm.emit_enter_runtime(spec)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm
            .runtime_call(beam_jit_return_to_trace as *const () as usize)?;
        self.asm.emit_leave_runtime(spec)?;
        self.emit_deallocate(ArgVal::Word(u64::from(BEAM_RETURN_TO_TRACE_FRAME_SZ)))?;
        self.emit_return_do(true)
    }

    /// Calls `erts_hibernate` and schedules the process out through `dispatch_return`.
    // Port of erts/emulator/beam/jit/x86/instr_trace.cpp:254-279 (emit_i_hibernate),
    // OTP-29.1.1.
    pub fn emit_i_hibernate(&mut self) -> Result<(), AsmError> {
        let spec = Update::REDUCTIONS.union(Update::HEAP).union(Update::STACK);
        self.asm.emit_enter_runtime(spec)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm
            .runtime_call(erts_hibernate as *const () as usize)?;
        self.asm.emit_leave_runtime(spec)?;
        self.asm
            .emit(|e| e.and_mi(process_ref(process::FLAGS, 4), !F_HIBERNATE_SCHED))?;
        self.asm
            .emit(|e| e.mov_mi(get_x_ref(0, 8), Term::atom(atoms::OK).word() as i64))?;
        let dispatch_return = self.ga_get(GlobalLabels::DispatchReturn)?;
        #[cfg(not(target_os = "openbsd"))]
        {
            let dispatch_return = self.resolve_fragment(dispatch_return);
            self.asm.fragment_call(dispatch_return)?;
        }
        #[cfg(target_os = "openbsd")]
        {
            let next = self.asm.new_label();
            self.asm
                .a
                .emit_rip_label(next, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
            let dispatch_return = self.resolve_fragment(dispatch_return);
            self.asm.jmp(dispatch_return)?;
            self.asm.align_code(8)?;
            self.asm.bind(next)?;
        }
        Ok(())
    }
}

fn tmp_mem(index: u32) -> Mem {
    super::beam_asm::tmp_mem_q(index)
}
