//! BIF, NIF, length and send instructions.
//!
//! Port of erts/emulator/beam/jit/x86/instr_bif.cpp, OTP-29.1.1.

use arinsal_term::{ErtsCodeMfa, Term, atoms};
use arinsal_x64::buf::Label;
use arinsal_x64::enc::{self, CondCode, Mem, byte_ptr, dword_ptr, qword_ptr};

use crate::common::args::{ArgVal, Relation, memory_relation};

use super::beam_asm::register::{
    ACTIVE_CODE_IX, ARG1, ARG1D, ARG2, ARG2D, ARG3, ARG4, ARG5, ARG5D, ARG6, C_P, E, FCALLS, HTOP,
    RET,
};
use super::beam_asm::{
    AsmError, ERTS_SAVE_CALLS_CODE_IX, Update, get_arg_ref, get_x_ref, process, process_ref,
    tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label};
use super::rt::{
    addr, beam_jit_call_bif, beam_jit_call_nif, beam_jit_load_nif, erts_gc_after_bif_call_lhf,
    erts_printable_return_address, erts_trapping_length_1, get_on_load_address, ubif2mfa,
};
use crate::common::beam_asm_h::ErtsCodeInfo;
use crate::common::beam_asm_h::{BEAM_ASM_FUNC_PROLOGUE_SIZE, BEAM_ASM_NFUNC_SIZE};
use arinsal_term::{EXPORT_MFA_OFFSET, ExportEntry};

/// `offsetof(Export, is_bif_traced)`.
// Port of erts/emulator/beam/export.h:57-58 (Export.is_bif_traced), OTP-29.1.1.
const EXPORT_IS_BIF_TRACED: i32 = core::mem::offset_of!(ExportEntry, is_bif_traced) as i32;
/// `offsetof(Export, info.mfa)`.
const EXPORT_MFA: i32 = EXPORT_MFA_OFFSET as i32;
/// `offsetof(Export, info.mfa.arity)`.
const EXPORT_MFA_ARITY: i32 = EXPORT_MFA + core::mem::offset_of!(ErtsCodeMfa, arity) as i32;
/// `offsetof(Export, trampoline.common.op)`.
const EXPORT_TRAMPOLINE_OP: i32 = arinsal_term::EXPORT_TRAMPOLINE_OP_OFFSET as i32;
/// `offsetof(Export, trampoline.bif.address)`.
const EXPORT_TRAMPOLINE_BIF_ADDRESS: i32 = (core::mem::offset_of!(ExportEntry, trampoline)
    + core::mem::offset_of!(arinsal_term::ExportTrampoline, address))
    as i32;
/// `offsetof(ErtsNativeFunc, trampoline.info.mfa) - offsetof(...call_bif_nif)`.
const NATIVE_FUNC_MFA_FROM_CALL: i32 =
    core::mem::offset_of!(ErtsCodeInfo, mfa) as i32 - core::mem::size_of::<ErtsCodeInfo>() as i32;
/// `offsetof(ErtsNativeFunc, trampoline.dfunc) - offsetof(...call_bif_nif)`.
const NATIVE_FUNC_DFUNC_FROM_CALL: i32 = BEAM_ASM_NFUNC_SIZE as i32;
/// `F_FORCE_GC | F_DISABLE_GC` of `c_p->flags`.
const F_FORCE_OR_DISABLE_GC: i64 =
    (arinsal_term::pflags::F_FORCE_GC | arinsal_term::pflags::F_DISABLE_GC) as i64;

const F_HIBERNATE_SCHED: i64 = 1;
const RET_NIF_SUCCESS: i64 = 0;
const RET_NIF_YIELD: i64 = 2;

const fn mfa(function: arinsal_term::Atom, arity: usize) -> ErtsCodeMfa {
    ErtsCodeMfa {
        module: Term::atom(atoms::ERLANG).word(),
        function: Term::atom(function).word(),
        arity,
    }
}

pub(crate) static LENGTH_MFA: ErtsCodeMfa = mfa(atoms::LENGTH, 1);
pub(crate) static LOAD_NIF_MFA: ErtsCodeMfa = mfa(atoms::LOAD_NIF, 2);
pub(crate) static CALL_ON_LOAD_MFA: ErtsCodeMfa = mfa(atoms::CALL_ON_LOAD_FUNCTION, 1);

fn mfa_address(mfa: &'static ErtsCodeMfa) -> u64 {
    std::ptr::from_ref(mfa) as u64
}

fn small(value: i64) -> i64 {
    (value << 4) | 0xF
}

impl BeamGlobalAssembler {
    /// Runs a guard BIF with a prepared argument vector and function pointer.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:47-72 (emit_i_bif_guard_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_bif_guard_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit_enter_frame()?;
        a.emit_enter_runtime(Update::REDUCTIONS)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.mov_imm(ARG3, 0)?;
        a.dynamic_runtime_call(ARG4)?;
        a.emit_leave_runtime(Update::REDUCTIONS)?;
        a.emit_leave_frame()?;
        a.emit_test_the_non_value(RET)?;
        a.emit(|e| e.ret())
    }

    /// Runs a body BIF and restores its arguments and MFA before raising on failure.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:74-123 (emit_i_bif_body_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_bif_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        let raise = self.label(GlobalLabels::RaiseException);
        let a = &mut self.asm;
        a.emit_enter_frame()?;
        a.emit_enter_runtime(Update::REDUCTIONS)?;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        a.emit(|e| e.mov_mr(tmp_mem_q(1), ARG4))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.mov_imm(ARG3, 0)?;
        a.dynamic_runtime_call(ARG4)?;
        a.emit_test_the_non_value(RET)?;
        a.short_jcc(CondCode::E, error)?;
        a.emit_leave_runtime(Update::REDUCTIONS)?;
        a.emit_leave_frame()?;
        a.emit(|e| e.ret())?;
        a.bind(error)?;
        a.emit(|e| e.mov_rm(ARG2, tmp_mem_q(0)))?;
        for index in 0..3u32 {
            a.emit(|e| e.mov_rm(ARG1, qword_ptr(ARG2, (index * 8) as i32)))?;
            a.emit(|e| e.mov_mr(get_x_ref(index, 8), ARG1))?;
        }
        a.emit(|e| e.mov_rm(ARG1, tmp_mem_q(1)))?;
        a.runtime_call(addr(ubif2mfa as *const ()))?;
        a.emit_leave_runtime(Update::REDUCTIONS)?;
        a.emit_leave_frame()?;
        a.emit(|e| e.mov_rr(ARG4, RET))?;
        a.jmp(raise)
    }

    /// Shared non-yielding length implementation; `ARG2` is Live and `ARG3` is the entry CP.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:266-320 (emit_i_length_common),
    // OTP-29.1.1.
    fn emit_i_length_common(&mut self, fail: Label, state_size: i64) -> Result<Mem, AsmError> {
        assert!((2..=3).contains(&state_size));
        let trap = self.asm.new_label();
        let trap_state = Mem::base_index(super::beam_asm::register::REGISTERS, ARG2, 3, 0, 8);
        let context_switch = self.label(GlobalLabels::ContextSwitchSimplified);
        let a = &mut self.asm;
        a.emit_enter_frame()?;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        a.emit(|e| e.mov_mr(tmp_mem_q(1), ARG3))?;
        a.emit_enter_runtime(Update::REDUCTIONS)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.lea(ARG2, trap_state))?;
        a.runtime_call(addr(erts_trapping_length_1 as *const ()))?;
        a.emit_leave_runtime(Update::REDUCTIONS)?;
        a.emit_leave_frame()?;
        a.emit_test_the_non_value(RET)?;
        a.short_jcc(CondCode::E, trap)?;
        a.emit(|e| e.ret())?;
        a.bind(trap)?;
        a.emit(|e| e.mov_rm(ARG2, tmp_mem_q(0)))?;
        a.emit(|e| e.mov_rm(ARG3, tmp_mem_q(1)))?;
        a.emit(|e| e.cmp_mi(process_ref(process::FREASON, 8), crate::exc::TRAP as i64))?;
        a.jcc(CondCode::NE, fail)?;
        a.emit(|e| e.add_ri(ARG2, state_size))?;
        a.emit(|e| e.add_ri(enc::RSP, 8))?;
        a.emit(|e| e.mov_mi(process_ref(process::CURRENT, 8), 0))?;
        a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG2.r8()))?;
        a.jmp(context_switch)?;
        Ok(trap_state)
    }

    /// Body length fragment preserving the original list for the `badarg` frame.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:322-356
    // (emit_i_length_body_shared), OTP-29.1.1.
    pub(crate) fn emit_i_length_body_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        let raise = self.label(GlobalLabels::RaiseException);
        self.emit_i_length_common(error, 3)?;
        self.asm.bind(error)?;
        self.asm.emit(|e| {
            e.mov_rm(
                ARG1,
                Mem::base_index(super::beam_asm::register::REGISTERS, ARG2, 3, 16, 8),
            )
        })?;
        self.asm.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG1))?;
        self.asm.mov_imm(ARG4, mfa_address(&LENGTH_MFA))?;
        self.asm.jmp(raise)?;
        Ok(())
    }

    /// Guard length fragment; false is returned in ZF when length traps or fails.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:346
    // (emit_i_length_guard_shared), OTP-29.1.1.
    pub(crate) fn emit_i_length_guard_shared(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        self.emit_i_length_common(error, 2)?;
        self.asm.bind(error)?;
        self.asm.emit(|e| e.sub_rr(RET, RET))?;
        self.asm.emit(|e| e.ret())
    }
}

impl BeamGlobalAssembler {
    /// Restores native state after a BIF or NIF and dispatches return, trap, hibernate or error.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:711-817
    // (emit_bif_nif_epilogue), OTP-29.1.1.
    pub(crate) fn emit_bif_nif_epilogue(&mut self) -> Result<(), AsmError> {
        let check_trap = self.asm.new_label();
        let trap = self.asm.new_label();
        let error = self.asm.new_label();
        let raise = self.label(GlobalLabels::RaiseExceptionShared);
        let do_schedule = self.label(GlobalLabels::DoSchedule);
        let context_switch = self.label(GlobalLabels::ContextSwitchSimplified);
        let a = &mut self.asm;
        let spec = Update::REDUCTIONS
            .union(Update::STACK)
            .union(Update::HEAP)
            .union(Update::CODE_INDEX);
        a.emit_leave_runtime(spec)?;
        a.emit_test_the_non_value(RET)?;
        a.short_jcc(CondCode::E, check_trap)?;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        a.emit_leave_frame()?;
        #[cfg(not(target_os = "openbsd"))]
        a.emit(|e| e.ret())?;
        #[cfg(target_os = "openbsd")]
        {
            a.emit(|e| e.mov_rm(RET, qword_ptr(E, 0)))?;
            a.emit(|e| e.mov_mi(qword_ptr(E, 0), Term::NIL.word() as i64))?;
            a.emit(|e| e.jmp_r(RET))?;
        }

        a.bind(check_trap)?;
        a.emit(|e| e.cmp_mi(process_ref(process::FREASON, 8), crate::exc::TRAP as i64))?;
        a.jcc(CondCode::NE, error)?;
        a.emit(|e| e.mov_rm(ARG1D, process_ref(process::FLAGS, 4)))?;
        a.emit(|e| e.mov_rr(ARG2D, ARG1D))?;
        a.emit(|e| e.and_ri(ARG2D, F_HIBERNATE_SCHED))?;
        a.short_jcc(CondCode::E, trap)?;
        a.emit(|e| e.and_ri(ARG1D, !F_HIBERNATE_SCHED))?;
        a.emit(|e| e.mov_mr(process_ref(process::FLAGS, 4), ARG1D))?;
        a.jmp(do_schedule)?;

        a.bind(trap)?;
        a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        a.jmp(context_switch)?;

        a.bind(error)?;
        a.emit(|e| e.mov_rr(ARG2, E))?;
        a.emit_enter_runtime(Update::STACK)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(addr(erts_printable_return_address as *const ()))?;
        a.emit_leave_runtime(Update::STACK)?;
        a.emit(|e| e.mov_rr(ARG2, RET))?;
        a.emit(|e| e.mov_rm(ARG4, process_ref(process::CURRENT, 8)))?;
        a.jmp(raise)
    }

    /// Calls a BIF through `beam_jit_call_bif(c_p, reg, I, func, arity)`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:819-870 (emit_call_bif_shared),
    // OTP-29.1.1. Release build without `ERTS_MSACC_EXTENDED_STATES`.
    pub(crate) fn emit_call_bif_shared(&mut self) -> Result<(), AsmError> {
        {
            let a = &mut self.asm;
            a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG2))?;
            a.emit(|e| {
                e.movzx_rm(
                    ARG5D,
                    byte_ptr(ARG2, core::mem::offset_of!(ErtsCodeMfa, arity) as i32),
                )
            })?;
            a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG5.r8()))?;
            a.emit(|e| e.mov_mr(process_ref(process::I, 8), ARG3))?;
            let spec = Update::REDUCTIONS.union(Update::STACK).union(Update::HEAP);
            a.emit_enter_runtime(spec)?;
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.runtime_call(addr(beam_jit_call_bif as *const ()))?;
        }
        self.emit_bif_nif_epilogue()
    }

    /// Routes export trampoline entries to generic breakpoints, BIFs, or the error handler.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:170-263
    // (emit_export_trampoline), OTP-29.1.1. Release build with `NATIVE_ERLANG_STACK`.
    pub(crate) fn emit_export_trampoline(&mut self) -> Result<(), AsmError> {
        let (call_bif, error_handler) = (self.asm.new_label(), self.asm.new_label());
        let generic_bp = self.label(GlobalLabels::GenericBpGlobal);
        let call_bif_shared = self.label(GlobalLabels::CallBifShared);
        let raise_exception = self.label(GlobalLabels::RaiseException);
        let a = &mut self.asm;

        a.emit(|e| e.mov_rm(ARG1, qword_ptr(RET, EXPORT_TRAMPOLINE_OP)))?;
        a.emit(|e| e.cmp_ri(ARG1, arinsal_term::OP_I_GENERIC_BREAKPOINT as i64))?;
        a.jcc(CondCode::E, generic_bp)?;
        a.emit(|e| e.cmp_ri(ARG1, arinsal_term::OP_CALL_BIF_W as i64))?;
        a.jcc(CondCode::E, call_bif)?;
        a.emit(|e| e.cmp_ri(ARG1, arinsal_term::OP_CALL_ERROR_HANDLER as i64))?;
        a.jcc(CondCode::E, error_handler)?;
        a.emit(|e| e.ud2())?;

        a.bind(call_bif)?;
        a.emit(|e| e.lea(ARG2, qword_ptr(RET, EXPORT_MFA)))?;
        a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        a.emit(|e| e.mov_rm(ARG4, qword_ptr(RET, EXPORT_TRAMPOLINE_BIF_ADDRESS)))?;
        a.emit_enter_frame()?;
        a.jmp(call_bif_shared)?;

        a.bind(error_handler)?;
        a.emit(|e| e.lea(ARG2, qword_ptr(RET, EXPORT_MFA)))?;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        a.emit_enter_frame()?;
        a.emit_enter_runtime(Update::REDUCTIONS.union(Update::HEAP_ALLOC))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG3)?;
        a.mov_imm(
            ARG4,
            arinsal_term::Term::atom(arinsal_term::atoms::UNDEFINED_FUNCTION).word(),
        )?;
        a.runtime_call(addr(super::rt::call_error_handler as *const ()))?;
        a.emit_leave_runtime(Update::REDUCTIONS.union(Update::HEAP_ALLOC))?;
        a.emit_leave_frame()?;
        a.emit(|e| e.mov_rm(ARG4, tmp_mem_q(0)))?;
        a.emit(|e| e.test_rr(RET, RET))?;
        a.jcc(CondCode::E, raise_exception)?;
        let destination = a.emit_setup_dispatchable_call_active(RET)?;
        a.emit(|e| e.jmp_m(destination))
    }

    /// Unpacks an `ErtsNativeFunc` BIF trampoline and tail-calls `call_bif_shared`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:872-889 (emit_dispatch_bif),
    // OTP-29.1.1.
    pub(crate) fn emit_dispatch_bif(&mut self) -> Result<(), AsmError> {
        let target = self.label(GlobalLabels::CallBifShared);
        let a = &mut self.asm;
        a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        a.emit(|e| e.lea(ARG2, Mem::base_disp(ARG3, NATIVE_FUNC_MFA_FROM_CALL, 8)))?;
        a.emit(|e| e.mov_rm(ARG4, qword_ptr(ARG3, NATIVE_FUNC_DFUNC_FROM_CALL)))?;
        a.jmp(target)
    }

    /// Calls the NIF or BIF addressed by a native-function trampoline.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:929-976 (emit_call_nif_early), OTP-29.1.1.
    pub(crate) fn emit_call_nif_early(&mut self) -> Result<(), AsmError> {
        let call_nif = self.label(GlobalLabels::CallNifShared);
        let a = &mut self.asm;
        let info_size = core::mem::size_of::<crate::common::beam_asm_h::ErtsCodeInfo>() as i64;
        a.emit(|e| e.mov_rm(ARG2, qword_ptr(enc::RSP, 0)))?;
        a.emit(|e| e.sub_ri(ARG2, 8 + info_size))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(addr(super::rt::erts_call_nif_early as *const ()))?;
        a.emit_leave_runtime(Update::NONE)?;
        a.emit(|e| e.add_ri(enc::RSP, 8))?;
        a.emit_enter_frame()?;
        a.emit(|e| e.mov_rr(ARG3, RET))?;
        a.jmp(call_nif)
    }

    /// Calls the NIF described by the native-function trampoline at `ARG3`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:978-1013
    // (emit_call_nif_shared), OTP-29.1.1.
    pub(crate) fn emit_call_nif_shared(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        let spec = Update::REDUCTIONS.union(Update::STACK).union(Update::HEAP);
        a.emit_enter_runtime(spec)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.mov_rr(ARG2, ARG3))?;
        a.load_x_reg_array(ARG3)?;
        a.emit(|e| {
            e.mov_rm(
                ARG4,
                qword_ptr(ARG2, 8 + BEAM_ASM_FUNC_PROLOGUE_SIZE as i32),
            )
        })?;
        a.emit(|e| {
            e.mov_rm(
                ARG5,
                qword_ptr(ARG2, 16 + BEAM_ASM_FUNC_PROLOGUE_SIZE as i32),
            )
        })?;
        a.emit(|e| {
            e.mov_rm(
                ARG6,
                qword_ptr(ARG2, 24 + BEAM_ASM_FUNC_PROLOGUE_SIZE as i32),
            )
        })?;
        a.runtime_call(addr(beam_jit_call_nif as *const ()))?;
        self.emit_bif_nif_epilogue()
    }

    /// Calls `beam_jit_load_nif`, retaining its entry address when it yields.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1095-1134
    // (emit_i_load_nif_shared), OTP-29.1.1.
    pub(crate) fn emit_i_load_nif_shared(&mut self) -> Result<(), AsmError> {
        let yield_label = self.asm.new_label();
        let error = self.asm.new_label();
        let raise = self.label(GlobalLabels::RaiseException);
        let context_switch = self.label(GlobalLabels::ContextSwitchSimplified);
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        a.emit_enter_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG3)?;
        a.runtime_call(addr(beam_jit_load_nif as *const ()))?;
        a.emit_leave_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.cmp_ri(RET, RET_NIF_YIELD))?;
        a.short_jcc(CondCode::E, yield_label)?;
        a.emit_leave_frame()?;
        a.emit(|e| e.cmp_ri(RET, RET_NIF_SUCCESS))?;
        a.short_jcc(CondCode::NE, error)?;
        a.emit(|e| e.ret())?;
        a.bind(error)?;
        a.mov_imm(ARG4, mfa_address(&LOAD_NIF_MFA))?;
        a.jmp(raise)?;
        a.bind(yield_label)?;
        a.emit(|e| e.mov_rm(ARG3, tmp_mem_q(0)))?;
        a.jmp(context_switch)
    }

    /// Dispatches a native-function trampoline laid out as a NIF call.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1015-1025 (emit_dispatch_nif), OTP-29.1.1.
    pub(crate) fn emit_dispatch_nif(&mut self) -> Result<(), AsmError> {
        self.asm
            .emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        self.asm.jmp(self.label(GlobalLabels::CallNifShared))
    }

    /// Checks reductions before entering `call_nif_shared`, resuming at the NIF MFA on yield.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1027-1057
    // (emit_call_nif_yield_helper), OTP-29.1.1.
    pub(crate) fn emit_call_nif_yield_helper(&mut self) -> Result<(), AsmError> {
        let yield_label = self.asm.new_label();
        let call_nif = self.label(GlobalLabels::CallNifShared);
        let context_switch = self.label(GlobalLabels::ContextSwitchSimplified);
        let a = &mut self.asm;
        a.emit(|e| e.dec_r(FCALLS))?;
        a.short_jcc(CondCode::L, yield_label)?;
        a.jmp(call_nif)?;
        a.bind(yield_label)?;
        let mfa_offset = -(core::mem::size_of::<crate::common::beam_asm_h::ErtsCodeInfo>() as i32)
            + core::mem::offset_of!(crate::common::beam_asm_h::ErtsCodeInfo, mfa) as i32;
        let arity_offset = mfa_offset + core::mem::size_of::<u64>() as i32 * 2;
        a.emit(|e| e.movzx_rm(ARG1D, byte_ptr(ARG3, arity_offset)))?;
        a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG1.r8()))?;
        a.emit(|e| e.lea(ARG1, qword_ptr(ARG3, mfa_offset)))?;
        a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG1))?;
        a.emit(|e| e.add_ri(ARG3, BEAM_ASM_NFUNC_SIZE as i64 + 24))?;
        a.jmp(context_switch)
    }

    /// Calls a light BIF through its `(c_p, reg, I)` function and handles GC, traps and errors.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:420-671 (emit_call_light_bif_shared),
    // OTP-29.1.1. Release build: no `debug_call_light_bif`, no `ERTS_CCONV_DEBUG`
    // trampoline, no `ERTS_MSACC_EXTENDED_STATES`.
    pub(crate) fn emit_call_light_bif_shared(&mut self) -> Result<(), AsmError> {
        let (entry_mem, export_mem, mbuf_mem) = (tmp_mem_q(0), tmp_mem_q(1), tmp_mem_q(2));
        let context_switch_simplified = self.label(GlobalLabels::ContextSwitchSimplified);
        let raise_exception_shared = self.label(GlobalLabels::RaiseExceptionShared);
        let a = &mut self.asm;
        let trace = a.new_label();
        let r#yield = a.new_label();

        a.emit_enter_frame()?;

        a.emit(|e| e.mov_rm(ARG1, process_ref(process::MBUF, 8)))?;
        a.emit(|e| e.mov_mr(entry_mem, ARG3))?;
        a.emit(|e| e.mov_mr(export_mem, ARG4))?;
        a.emit(|e| e.mov_mr(mbuf_mem, ARG1))?;

        a.emit(|e| e.cmp_mi(dword_ptr(ARG4, EXPORT_IS_BIF_TRACED), 0))?;
        a.jcc(CondCode::NE, trace)?;
        a.emit(|e| e.cmp_ri(ACTIVE_CODE_IX, i64::from(ERTS_SAVE_CALLS_CODE_IX)))?;
        a.jcc(CondCode::E, trace)?;

        a.emit(|e| e.dec_r(FCALLS))?;
        a.jcc(CondCode::LE, r#yield)?;

        {
            let check_bif_return = a.new_label();
            let gc_after_bif_call = a.new_label();
            let spec = Update::REDUCTIONS.union(Update::STACK).union(Update::HEAP);

            a.emit_enter_runtime(spec)?;
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.emit(|e| e.mov_rr(ARG4, RET))?;
            a.dynamic_runtime_call(ARG4)?;
            a.emit_leave_runtime(spec.union(Update::CODE_INDEX))?;

            a.emit(|e| e.test_mi(process_ref(process::FLAGS, 4), F_FORCE_OR_DISABLE_GC))?;
            a.jcc(CondCode::NE, gc_after_bif_call)?;
            a.emit(|e| e.mov_rm(ARG1, process_ref(process::BIN_VHEAP_SZ, 8)))?;
            a.emit(|e| e.cmp_mr(process_ref(process::OFF_HEAP_OVERHEAD, 8), ARG1))?;
            a.jcc(CondCode::A, gc_after_bif_call)?;
            a.emit(|e| e.mov_rm(ARG2, process_ref(process::MBUF_SZ, 8)))?;
            a.emit(|e| e.lea(ARG1, Mem::base_index(HTOP, ARG2, 0, 3, 8)))?;
            a.emit(|e| e.cmp_rr(E, ARG1))?;
            a.jcc(CondCode::L, gc_after_bif_call)?;

            a.bind(check_bif_return)?;
            {
                let trap = a.new_label();
                let error = a.new_label();
                a.emit_test_the_non_value(RET)?;
                a.short_jcc(CondCode::E, trap)?;
                a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
                a.emit_leave_frame()?;
                a.emit(|e| e.ret())?;

                a.bind(trap)?;
                a.emit(|e| {
                    e.cmp_mi(
                        process_ref(process::FREASON, 8),
                        arinsal_term::exc::TRAP as i64,
                    )
                })?;
                a.short_jcc(CondCode::NE, error)?;
                a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
                a.jmp(context_switch_simplified)?;

                a.bind(error)?;
                a.emit(|e| e.mov_rm(ARG2, entry_mem))?;
                a.emit(|e| e.mov_rm(ARG4, export_mem))?;
                a.emit(|e| e.add_ri(ARG4, i64::from(EXPORT_MFA)))?;
                const {
                    assert!(matches!(
                        super::beam_asm::FRAME_LAYOUT,
                        super::beam_asm::FrameLayout::Ra
                    ))
                };
                a.emit(|e| e.mov_mr(qword_ptr(E, 0), ARG2))?;
                a.jmp(raise_exception_shared)?;
            }

            a.bind(gc_after_bif_call)?;
            a.emit(|e| e.mov_rm(ARG2, mbuf_mem))?;
            a.emit(|e| e.mov_rm(ARG5, export_mem))?;
            a.emit(|e| e.movzx_rm(ARG5D, byte_ptr(ARG5, EXPORT_MFA_ARITY)))?;
            a.emit_enter_runtime(spec)?;
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.emit(|e| e.mov_rr(ARG3, RET))?;
            a.load_x_reg_array(ARG4)?;
            a.runtime_call(addr(erts_gc_after_bif_call_lhf as *const ()))?;
            a.emit_leave_runtime(spec)?;
            a.jmp(check_bif_return)?;
        }

        a.bind(trace)?;
        a.emit_leave_frame()?;
        let destination = a.emit_setup_dispatchable_call_active(ARG4)?;
        a.emit(|e| e.jmp_m(destination))?;

        a.bind(r#yield)?;
        a.emit(|e| e.movzx_rm(ARG2D, byte_ptr(ARG4, EXPORT_MFA_ARITY)))?;
        a.emit(|e| e.lea(ARG4, qword_ptr(ARG4, EXPORT_MFA)))?;
        a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG2.r8()))?;
        a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG4))?;
        a.emit_unwind_frame()?;
        a.jmp(context_switch_simplified)
    }
}

impl BeamModuleAssembler {
    /// Calls a BIF through its `ErtsNativeFunc` function pointer.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:890-909 (emit_call_bif), OTP-29.1.1.
    pub fn emit_call_bif(&mut self, function: ArgVal) -> Result<(), AsmError> {
        let function = function
            .word()
            .ok_or(AsmError::Operand("call_bif function pointer"))?;
        let entry = self.asm.new_label();
        let current = self
            .current_label()
            .ok_or(AsmError::Operand("call_bif without current function"))?;
        self.asm.emit_enter_frame()?;
        self.asm.bind(entry)?;
        self.asm.a.emit_rip_label(current, |e| {
            e.lea(
                ARG2,
                Mem::rip(-(core::mem::size_of::<ErtsCodeMfa>() as i32), 8),
            )
        })?;
        self.asm
            .a
            .emit_rip_label(entry, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
        self.asm.mov_imm(ARG4, function)?;
        let fragment = self.ga_get(GlobalLabels::CallBifShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.jmp(target)
    }

    /// Resolves `M:F/A` in the loader and emits the same BIF call stub as `call_bif`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:912 (emit_call_bif_mfa),
    // OTP-29.1.1.
    pub fn emit_call_bif_mfa(
        &mut self,
        _module: ArgVal,
        _function: ArgVal,
        _arity: ArgVal,
    ) -> Result<(), AsmError> {
        let function = self
            .current_bif_mfa_function
            .take()
            .ok_or(AsmError::Operand(
                "call_bif_mfa was not resolved by the loader",
            ))?;
        self.emit_call_bif(ArgVal::Word(function as u64))
    }

    /// Emits the position-independent NIF body trampoline.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1059 (emit_call_nif), OTP-29.1.1.
    pub fn emit_call_nif(
        &mut self,
        function: ArgVal,
        module: ArgVal,
        dirty_function: ArgVal,
    ) -> Result<(), AsmError> {
        let words = [function, module, dirty_function]
            .map(|arg| arg.word().ok_or(AsmError::Operand("call_nif word")))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let entry = self.asm.new_label();
        let dispatch = self.asm.new_label();
        self.asm.bind(entry)?;
        self.asm.emit_enter_frame()?;
        self.asm.short_jmp(dispatch)?;
        self.asm.align_code(8)?;
        for word in words {
            self.asm.a.embed_u64(word)?;
        }
        self.asm.bind(dispatch)?;
        self.asm
            .a
            .emit_rip_label(dispatch, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
        let fragment = self.ga_get(GlobalLabels::CallNifYieldHelper)?;
        self.asm.pic_jmp(fragment)
    }

    /// Emits `call_light_bif`; the export operand remains an import patch until code loading.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:673 (emit_call_light_bif),
    // OTP-29.1.1.
    pub fn emit_call_light_bif(&mut self, bif: ArgVal, export: ArgVal) -> Result<(), AsmError> {
        let bif = bif
            .word()
            .ok_or(AsmError::Operand("light BIF function pointer"))?;
        let entry = self.asm.new_label();
        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;
        self.mov_arg_to_reg(ARG4, export)?;
        self.asm.mov_imm(super::beam_asm::register::RET, bif)?;
        self.asm
            .a
            .emit_rip_label(entry, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
        let fragment = self.ga_get(GlobalLabels::CallLightBifShared)?;
        self.asm.fragment_call_abs(fragment)
    }

    /// Calls `send_2` through its trap export, sharing the light-BIF completion path.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:691 (emit_send), OTP-29.1.1.
    pub fn emit_send(&mut self) -> Result<(), AsmError> {
        let (export, function) = self.send_target.take().ok_or(AsmError::Operand(
            "send target was not resolved by the loader",
        ))?;
        self.emit_call_light_bif(ArgVal::Word(function as u64), ArgVal::Word(export as u64))
    }

    /// `nif_start` marks the function as a replaceable NIF body in the loader.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:707 (emit_nif_start), OTP-29.1.1.
    pub fn emit_nif_start(&mut self) -> Result<(), AsmError> {
        Ok(())
    }

    /// Resolves and calls the module's on-load function, or raises `badarg` if absent.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1154 (emit_i_call_on_load_function),
    // OTP-29.1.1.
    pub fn emit_i_call_on_load_function(&mut self) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.asm.emit_enter_runtime(Update::NONE)?;
        self.asm
            .emit(|e| e.mov_rr(ARG1, super::beam_asm::register::C_P))?;
        self.asm.emit(|e| e.mov_rm(ARG2, get_x_ref(0, 8)))?;
        self.asm
            .runtime_call(addr(get_on_load_address as *const ()))?;
        self.asm.emit_leave_runtime(Update::NONE)?;
        self.asm.emit(|e| {
            e.test_rr(
                super::beam_asm::register::RET,
                super::beam_asm::register::RET,
            )
        })?;
        self.asm.jcc(CondCode::NE, next)?;
        self.emit_raise_exception_mfa(&CALL_ON_LOAD_MFA)?;
        self.asm.bind(next)?;
        self.asm.erlang_call_r(super::beam_asm::register::RET)
    }

    /// Rewrites `load_nif` as a body call so the call frame survives a yield.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1177 (emit_i_load_nif), OTP-29.1.1.
    pub fn emit_i_load_nif(&mut self) -> Result<(), AsmError> {
        let entry = self.asm.new_label();
        let next = self.asm.new_label();
        let yield_label = self.asm.new_label();
        self.asm.fragment_call(entry)?;
        self.asm.short_jmp(next)?;
        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;
        self.asm.emit_enter_frame()?;
        self.asm.bind(yield_label)?;
        self.asm
            .a
            .emit_rip_label(yield_label, |e| e.lea(ARG2, Mem::rip(0, 8)))?;
        let fragment = self.ga_get(GlobalLabels::ILoadNifShared)?;
        let fragment = self.resolve_fragment(fragment);
        self.asm.jmp(fragment)?;
        self.asm.bind(next)
    }

    /// Copies BIF arguments to a contiguous vector where required and sets the BIF function.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:125-159 (emit_setup_guard_bif),
    // OTP-29.1.1.
    fn emit_setup_guard_bif(&mut self, args: &[ArgVal], bif: ArgVal) -> Result<(), AsmError> {
        assert!(!args.is_empty() && args.len() <= 3);
        let mut contiguous = args[0].is_register();
        for pair in args.windows(2) {
            if !contiguous {
                break;
            }
            contiguous = memory_relation(pair[0], pair[1]) == Relation::Consecutive;
        }
        if contiguous {
            let first =
                get_arg_ref(args[0], 8).ok_or(AsmError::Operand("BIF register argument"))?;
            self.asm.emit(|e| e.lea(ARG2, first))?;
        } else {
            self.asm.emit(|e| e.lea(ARG2, tmp_mem_q(2)))?;
            for (index, arg) in args.iter().copied().enumerate() {
                self.mov_arg_to_mem(qword_ptr(ARG2, (index * 8) as i32), arg, ARG1)?;
            }
        }
        self.mov_arg_to_reg(ARG4, bif)
    }

    /// Emits one-argument BIF opcode, branching on false when Fail is nonzero.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:161-176 (emit_i_bif1), OTP-29.1.1.
    pub fn emit_i_bif1(
        &mut self,
        src: ArgVal,
        fail: ArgVal,
        bif: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_i_bif(&[src], fail, bif, dst)
    }

    /// Emits two-argument BIF opcode, branching on false when Fail is nonzero.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:177 (emit_i_bif2), OTP-29.1.1.
    pub fn emit_i_bif2(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        fail: ArgVal,
        bif: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_i_bif(&[src1, src2], fail, bif, dst)
    }

    /// Emits three-argument BIF opcode, branching on false when Fail is nonzero.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:194 (emit_i_bif3), OTP-29.1.1.
    pub fn emit_i_bif3(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        fail: ArgVal,
        bif: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_i_bif(&[src1, src2, src3], fail, bif, dst)
    }

    fn emit_i_bif(
        &mut self,
        args: &[ArgVal],
        fail: ArgVal,
        bif: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_setup_guard_bif(args, bif)?;
        let fail_label = arg_label(fail)?;
        if fail_label != 0 {
            let fragment = self.ga_get(GlobalLabels::IBifGuardShared)?;
            self.safe_fragment_call(fragment)?;
            let target = self
                .resolve_beam_label(fail_label)
                .ok_or(AsmError::Operand("BIF failure label"))?;
            self.asm.jcc(CondCode::E, target)?;
        } else {
            let fragment = self.ga_get(GlobalLabels::IBifBodyShared)?;
            self.safe_fragment_call(fragment)?;
        }
        self.mov_arg_from_reg(dst, RET)
    }

    /// Calls a guard BIF that cannot fail.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:218-233 (emit_nofail_bif1/2),
    // OTP-29.1.1.
    pub fn emit_nofail_bif1(
        &mut self,
        src: ArgVal,
        bif: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_setup_guard_bif(&[src], bif)?;
        let fragment = self.ga_get(GlobalLabels::IBifGuardShared)?;
        self.safe_fragment_call(fragment)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Calls a two-argument guard BIF that cannot fail.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:225-233 (emit_nofail_bif2), OTP-29.1.1.
    pub fn emit_nofail_bif2(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        bif: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.emit_setup_guard_bif(&[src1, src2], bif)?;
        let fragment = self.ga_get(GlobalLabels::IBifGuardShared)?;
        self.safe_fragment_call(fragment)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Stores the trapped tail and accumulated length in the X registers above Live.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:235-264 (emit_i_length_setup),
    // OTP-29.1.1.
    pub fn emit_i_length_setup(
        &mut self,
        fail: ArgVal,
        live: ArgVal,
        src: ArgVal,
    ) -> Result<(), AsmError> {
        let live = live.word().ok_or(AsmError::Operand("length live count"))? as u32;
        assert!(live < 1024);
        let state = get_x_ref(live, 8);
        self.mov_arg_to_mem(state, src, ARG1)?;
        self.asm
            .emit(|e| e.mov_mi(get_x_ref(live + 1, 8), small(0)))?;
        if arg_label(fail)? == 0 {
            self.mov_arg_to_mem(get_x_ref(live + 2, 8), src, ARG1)?;
        }
        Ok(())
    }

    /// Calls the shared length guard/body fragment and stores its result.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:358 (emit_i_length), OTP-29.1.1.
    pub fn emit_i_length(
        &mut self,
        fail: ArgVal,
        live: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        let entry = self.asm.new_label();
        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;
        self.mov_arg_to_reg(ARG2, live)?;
        self.asm
            .a
            .emit_rip_label(entry, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
        let fail_label = arg_label(fail)?;
        if fail_label != 0 {
            let fragment = self.ga_get(GlobalLabels::ILengthGuardShared)?;
            self.safe_fragment_call(fragment)?;
            let target = self
                .resolve_beam_label(fail_label)
                .ok_or(AsmError::Operand("length failure label"))?;
            self.asm.jcc(CondCode::E, target)?;
        } else {
            let fragment = self.ga_get(GlobalLabels::ILengthBodyShared)?;
            self.safe_fragment_call(fragment)?;
        }
        self.mov_arg_from_reg(dst, RET)
    }
}
