//! Port of erts/emulator/beam/jit/x86/instr_fun.cpp, OTP-29.1.1: so far the global fragments
//! `dispatch_save_calls_fun`, `unloaded_fun` and `handle_call_fun_error`.

use arinsal_x64::enc::{CondCode, dword_ptr, qword_ptr};

use super::beam_asm::register::{
    ACTIVE_CODE_IX, ARG1, ARG1D, ARG2, ARG3, ARG4, ARG5, C_P, E, HTOP, RET,
};
use super::beam_asm::{
    AsmError, Distance, Update, emit_boxed_val, get_x_ref, process, process_ref, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
pub use super::rt::{beam_jit_build_argument_list, beam_jit_handle_unloaded_fun};
use crate::exc::{EXC_BADARITY, EXC_BADFUN};

/// `FUN_HEADER_ARITY_OFFS`: the arity byte of a fun's header word (erl_fun.h).
const FUN_HEADER_ARITY_OFFS: i64 = 8;
/// `FUN_SUBTAG` (erl_term.h).
const FUN_SUBTAG: i64 = 0x14;

impl BeamGlobalAssembler {
    /// Continues a fun call made while saving calls with the actual code index.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:159-165 (emit_dispatch_save_calls_fun),
    // OTP-29.1.1.
    pub(crate) fn emit_dispatch_save_calls_fun(&mut self) -> Result<(), AsmError> {
        let active = &raw const super::rt::the_active_code_index as i64;
        let a = &mut self.asm;
        a.emit(|e| e.mov_ri(ARG1, active))?;
        a.emit(|e| e.mov_rm(ARG1D, dword_ptr(ARG1, 0)))?;
        let target = a.emit_setup_dispatchable_call(RET, ARG1)?;
        a.emit(|e| e.jmp_m(target))
    }

    /// Calls a fun whose module is not loaded: `beam_jit_handle_unloaded_fun` (ARG3 the fun
    /// header, ARG4 the fun, ARG5 the call's PC) gives the export to call, or raises.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:30-71 (emit_unloaded_fun), OTP-29.1.1.
    pub(crate) fn emit_unloaded_fun(&mut self) -> Result<(), AsmError> {
        let raise_exception = self.label(GlobalLabels::RaiseException);
        let a = &mut self.asm;
        let error = a.new_label();
        a.emit_enter_frame()?;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG5))?;
        let spec = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        a.emit_enter_runtime(spec)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG2)?;
        a.emit(|e| e.shr_ri(ARG3, FUN_HEADER_ARITY_OFFS))?;
        // ARG4 has already been set.
        a.emit(|e| e.mov_rr(ARG5, ACTIVE_CODE_IX))?;
        a.runtime_call(beam_jit_handle_unloaded_fun as *const () as usize)?;
        a.emit_leave_runtime(spec.union(Update::CODE_INDEX))?;
        a.emit(|e| e.test_rr(RET, RET))?;
        a.jcc(CondCode::E, error)?;
        a.emit_leave_frame()?;
        let target = a.emit_setup_dispatchable_call_active(RET)?;
        a.emit(|e| e.jmp_m(target))?;

        a.bind(error)?;
        // The `raise_exception` fragment expects that the PC is on the stack.
        a.emit(|e| e.push_m(tmp_mem_q(0)))?;
        a.mov_imm(ARG4, 0)?;
        a.jmp(raise_exception)
    }

    /// Raises `badfun` for a non-fun in ARG4, or `badarity` with `{Fun, Args}` for a fun
    /// called with the wrong arity (ARG3); ARG5 is the call's PC.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:73-157 (emit_handle_call_fun_error),
    // OTP-29.1.1.
    pub(crate) fn emit_handle_call_fun_error(&mut self) -> Result<(), AsmError> {
        let raise_exception = self.label(GlobalLabels::RaiseException);
        let garbage_collect = self.label(GlobalLabels::GarbageCollect);
        let a = &mut self.asm;
        let (bad_arity, bad_fun) = (a.new_label(), a.new_label());
        a.emit_enter_frame()?;
        a.emit_is_boxed(bad_fun, ARG4, Distance::Long)?;
        let fun_thing = a.emit_ptr_val(RET, ARG4);
        a.emit(|e| e.cmp_mi(emit_boxed_val(fun_thing, 0, 1), FUN_SUBTAG))?;
        a.short_jcc(CondCode::E, bad_arity)?;

        a.bind(bad_fun)?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADFUN as i64))?;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), ARG4))?;
        // The `raise_exception` fragment expects that the PC is on the stack.
        a.emit(|e| e.push_r(ARG5))?;
        a.mov_imm(ARG4, 0)?;
        a.jmp(raise_exception)?;

        a.bind(bad_arity)?;
        // Stash our fun and current PC. Note that we don't move the fun to {x,0} straight
        // away as that would clobber the first argument.
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG4))?;
        a.emit(|e| e.mov_mr(tmp_mem_q(1), ARG5))?;
        a.emit_enter_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG2)?;
        a.emit(|e| e.shr_ri(ARG3, FUN_HEADER_ARITY_OFFS))?;
        a.runtime_call(beam_jit_build_argument_list as *const () as usize)?;
        a.emit_leave_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG1))?;
        a.emit(|e| e.mov_mr(get_x_ref(1, 8), RET))?;
        // Create the {Fun, Args} tuple.
        let bytes_needed = ((3 + arinsal_term::S_RESERVED) * 8) as i32;
        let after_gc = a.new_label();
        a.emit(|e| e.lea(ARG3, qword_ptr(HTOP, bytes_needed)))?;
        a.emit(|e| e.cmp_rr(ARG3, E))?;
        a.short_jcc(CondCode::BE, after_gc)?;
        a.mov_imm(ARG4, 2)?;
        a.aligned_call_label(garbage_collect)?;
        a.bind(after_gc)?;
        a.emit(|e| e.mov_rm(ARG1, get_x_ref(0, 8)))?;
        a.emit(|e| e.mov_rm(ARG2, get_x_ref(1, 8)))?;
        // make_arityval(2).
        a.emit(|e| e.mov_mi(qword_ptr(HTOP, 0), 2 << 6))?;
        a.emit(|e| e.mov_mr(qword_ptr(HTOP, 8), ARG1))?;
        a.emit(|e| e.mov_mr(qword_ptr(HTOP, 16), ARG2))?;
        a.emit(|e| e.lea(ARG1, qword_ptr(HTOP, 2)))?;
        a.emit(|e| e.add_ri(HTOP, 24))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARITY as i64))?;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), ARG1))?;
        // The `raise_exception` fragment expects that the PC is on the stack.
        a.emit(|e| e.push_m(tmp_mem_q(1)))?;
        a.mov_imm(ARG4, 0)?;
        a.jmp(raise_exception)
    }
}
