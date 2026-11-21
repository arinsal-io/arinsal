//! Port of erts/emulator/beam/jit/x86/instr_fun.cpp, OTP-29.1.1.

use arinsal_term::{ErtsCodeMfa, Term, atoms};
use arinsal_x64::enc::{CondCode, Xmm, dword_ptr, qword_ptr, xmmword_ptr};

use super::beam_asm::register::{
    ACTIVE_CODE_IX, ARG1, ARG1D, ARG2, ARG3, ARG4, ARG5, C_P, E, HTOP, RET,
};
use super::beam_asm::{
    AsmError, BeamAssembler, CpuFeature, Distance, Update, emit_boxed_val, get_arg_ref,
    get_car_ref, get_cdr_ref, get_x_ref, process, process_ref, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, arg_label, arg_word};
use super::rt::addr;
pub use super::rt::{beam_jit_build_argument_list, beam_jit_handle_unloaded_fun};
use crate::common::args::{ArgVal, MAX_REG, Relation, memory_relation};
use crate::common::types::{BeamModuleAssemblerCommon, type_id};
use crate::exc::{EXC_BADARG, EXC_BADARITY, EXC_BADFUN, EXC_SYSTEM_LIMIT};

const FUN_HEADER_ARITY_OFFS: u32 = 8;
const FUN_HEADER_ENV_SIZE_OFFS: u32 = 16;
const FUN_SUBTAG: u64 = 0x14;
const ERL_FUN_SIZE: u64 = 2;
const FUN_ENTRY_OFFSET: i32 = 8;
const FUN_ENV_OFFSET: i32 = 16;
const TAG_PRIMARY_LIST_I64: i64 = 1;
const TAG_PRIMARY_MASK_I64: i64 = 0x3;
const NIL: i64 = 0x3b;

// Port of the `apply_mfa` initializer in instr_fun.cpp:290, OTP-29.1.1.
const fn mfa(function: arinsal_term::Atom, arity: usize) -> ErtsCodeMfa {
    ErtsCodeMfa {
        module: Term::atom(atoms::ERLANG).word(),
        function: Term::atom(function).word(),
        arity,
    }
}

/// `erlang:apply/2`, used by `apply_fun_shared` for list errors.
// Port of erts/emulator/beam/jit/x86/instr_fun.cpp:290-292 (apply_mfa), OTP-29.1.1.
pub(crate) static APPLY2_MFA: ErtsCodeMfa = mfa(atoms::APPLY, 2);

// Port of erl_term.h:417-423 (MAKE_FUN_HEADER with External=0), OTP-29.1.1.
const fn make_fun_header(arity: u64, num_free: u64) -> u64 {
    FUN_SUBTAG | (arity << FUN_HEADER_ARITY_OFFS) | (num_free << FUN_HEADER_ENV_SIZE_OFFS)
}

impl BeamGlobalAssembler {
    /// Resolves a call to a fun whose module is unloaded.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:30-71 (emit_unloaded_fun), OTP-29.1.1.
    pub(crate) fn emit_unloaded_fun(&mut self) -> Result<(), AsmError> {
        let error = self.asm.new_label();
        let raise_exception = self.label(GlobalLabels::RaiseException);
        let a = &mut self.asm;
        a.emit_enter_frame()?;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG5))?;
        let update = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        a.emit_enter_runtime(update)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG2)?;
        a.emit(|e| e.shr_ri(ARG3, i64::from(FUN_HEADER_ARITY_OFFS)))?;
        a.emit(|e| e.mov_rr(ARG5, ACTIVE_CODE_IX))?;
        a.runtime_call(addr(beam_jit_handle_unloaded_fun as *const ()))?;
        a.emit_leave_runtime(update.union(Update::CODE_INDEX))?;
        a.emit(|e| e.test_rr(RET, RET))?;
        a.jcc(CondCode::E, error)?;
        a.emit_leave_frame()?;
        let target = a.emit_setup_dispatchable_call_active(RET)?;
        a.emit(|e| e.jmp_m(target))?;

        a.bind(error)?;
        a.emit(|e| e.push_m(tmp_mem_q(0)))?;
        a.mov_imm(ARG4, 0)?;
        a.jmp(raise_exception)
    }

    /// Raises `badfun` or builds `{Fun, Args}` and raises `badarity` for `call_fun`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:73-157
    // (emit_handle_call_fun_error), OTP-29.1.1.
    pub(crate) fn emit_handle_call_fun_error(&mut self) -> Result<(), AsmError> {
        let bad_arity = self.asm.new_label();
        let bad_fun = self.asm.new_label();
        let raise_exception = self.label(GlobalLabels::RaiseException);
        let garbage_collect = self.label(GlobalLabels::GarbageCollect);
        let a = &mut self.asm;
        a.emit_enter_frame()?;
        a.emit_is_boxed(bad_fun, ARG4, Distance::Long)?;
        let fun_thing = a.emit_ptr_val(RET, ARG4);
        a.emit(|e| e.cmp_mi(emit_boxed_val(fun_thing, 0, 1), FUN_SUBTAG as i64))?;
        a.short_jcc(CondCode::E, bad_arity)?;

        a.bind(bad_fun)?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADFUN as i64))?;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), ARG4))?;
        a.emit(|e| e.push_r(ARG5))?;
        a.mov_imm(ARG4, 0)?;
        a.jmp(raise_exception)?;

        a.bind(bad_arity)?;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG4))?;
        a.emit(|e| e.mov_mr(tmp_mem_q(1), ARG5))?;
        a.emit_enter_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG2)?;
        a.emit(|e| e.shr_ri(ARG3, i64::from(FUN_HEADER_ARITY_OFFS)))?;
        a.runtime_call(addr(beam_jit_build_argument_list as *const ()))?;
        a.emit_leave_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.mov_rm(ARG1, tmp_mem_q(0)))?;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG1))?;
        a.emit(|e| e.mov_mr(get_x_ref(1, 8), RET))?;

        let bytes_needed = (3 + arinsal_term::S_RESERVED) * 8;
        let after_gc = a.new_label();
        a.emit(|e| e.lea(ARG3, qword_ptr(HTOP, bytes_needed as i32)))?;
        a.emit(|e| e.cmp_rr(ARG3, E))?;
        a.short_jcc(CondCode::BE, after_gc)?;
        a.mov_imm(ARG4, 2)?;
        a.aligned_call_label(garbage_collect)?;
        a.bind(after_gc)?;

        a.emit(|e| e.mov_rm(ARG1, get_x_ref(0, 8)))?;
        a.emit(|e| e.mov_rm(ARG2, get_x_ref(1, 8)))?;
        a.emit(|e| e.mov_mi(qword_ptr(HTOP, 0), 2 << 6))?;
        a.emit(|e| e.mov_mr(qword_ptr(HTOP, 8), ARG1))?;
        a.emit(|e| e.mov_mr(qword_ptr(HTOP, 16), ARG2))?;
        a.emit(|e| e.lea(ARG1, qword_ptr(HTOP, 2)))?;
        a.emit(|e| e.add_ri(HTOP, 24))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARITY as i64))?;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), ARG1))?;
        a.emit(|e| e.push_m(tmp_mem_q(1)))?;
        a.mov_imm(ARG4, 0)?;
        a.jmp(raise_exception)
    }

    /// Continues a local fun call while the active code index saves calls.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:159-165
    // (emit_dispatch_save_calls_fun), OTP-29.1.1.
    pub(crate) fn emit_dispatch_save_calls_fun(&mut self) -> Result<(), AsmError> {
        let active = &raw const super::rt::the_active_code_index as i64;
        let a = &mut self.asm;
        a.emit(|e| e.mov_ri(ARG1, active))?;
        a.emit(|e| e.mov_rm(ARG1D, dword_ptr(ARG1, 0)))?;
        let target = a.emit_setup_dispatchable_call(RET, ARG1)?;
        a.emit(|e| e.jmp_m(target))
    }

    /// Unpacks the argument list of `apply(Fun, Args)` before entering `call_fun`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:269-343
    // (emit_apply_fun_shared), OTP-29.1.1.
    pub(crate) fn emit_apply_fun_shared(&mut self) -> Result<(), AsmError> {
        let finished = self.asm.new_label();
        let unpack_next = self.asm.new_label();
        let malformed_list = self.asm.new_label();
        let raise_error = self.asm.new_label();

        self.asm.emit_enter_frame()?;
        self.asm.mov_imm(ARG3, 0)?;
        self.asm.emit(|e| e.mov_rm(ARG4, get_x_ref(0, 8)))?;
        self.asm.emit(|e| e.mov_rm(ARG5, get_x_ref(1, 8)))?;

        let mut x_register = get_x_ref(0, 8);
        x_register.index = Some(ARG3);
        x_register.shift = 3;

        self.asm.emit(|e| e.mov_rr(ARG1, ARG5))?;
        self.asm.bind(unpack_next)?;
        self.asm.emit(|e| e.cmp_ri(ARG1D, NIL))?;
        self.asm.short_jcc(CondCode::E, finished)?;
        self.asm
            .emit(|e| e.test_ri(ARG1.r8(), TAG_PRIMARY_MASK_I64 - TAG_PRIMARY_LIST_I64))?;
        self.asm.short_jcc(CondCode::NE, malformed_list)?;
        let list = self.asm.emit_ptr_val(ARG1, ARG1);
        self.asm.emit(|e| e.mov_rm(RET, get_car_ref(list, 8)))?;
        self.asm.emit(|e| e.mov_rm(ARG1, get_cdr_ref(list, 8)))?;
        self.asm.emit(|e| e.mov_mr(x_register, RET))?;
        self.asm.emit(|e| e.inc_r(ARG3))?;
        self.asm.emit(|e| e.cmp_ri(ARG3, (MAX_REG - 1) as i64))?;
        self.asm.jcc(CondCode::B, unpack_next)?;
        self.asm.mov_imm(RET, EXC_SYSTEM_LIMIT)?;
        self.asm.jmp(raise_error)?;

        self.asm.bind(malformed_list)?;
        self.asm.mov_imm(RET, EXC_BADARG)?;

        self.asm.bind(raise_error)?;
        self.asm.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG4))?;
        self.asm.emit(|e| e.mov_mr(get_x_ref(1, 8), ARG5))?;
        self.asm
            .emit(|e| e.mov_mr(process_ref(process::FREASON, 8), RET))?;
        self.asm
            .mov_imm(ARG4, core::ptr::from_ref(&APPLY2_MFA) as u64)?;
        self.asm.emit_leave_frame()?;
        let raise_exception = self.label(GlobalLabels::RaiseException);
        self.asm.jmp(raise_exception)?;

        self.asm.bind(finished)?;
        self.asm
            .emit(|e| e.shl_ri(ARG3, i64::from(FUN_HEADER_ARITY_OFFS)))?;
        self.asm.emit(|e| e.or_ri(ARG3, FUN_SUBTAG as i64))?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.ret())
    }
}

impl BeamModuleAssembler {
    /// `i_lambda_trampoline Lambda Lbl Arity NumFree`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:174-193
    // (emit_i_lambda_trampoline), OTP-29.1.1.
    pub fn emit_i_lambda_trampoline(
        &mut self,
        lambda: ArgVal,
        label: ArgVal,
        arity: ArgVal,
        num_free: ArgVal,
    ) -> Result<(), AsmError> {
        let ArgVal::FunEntry(lambda) = lambda else {
            return Err(AsmError::Operand("lambda operand"));
        };
        let arity =
            i64::try_from(arg_word(arity)?).map_err(|_| AsmError::Operand("lambda arity"))?;
        let num_free = i64::try_from(arg_word(num_free)?)
            .map_err(|_| AsmError::Operand("lambda environment size"))?;
        let effective_arity = u32::try_from(arity - num_free)
            .map_err(|_| AsmError::Operand("lambda environment offset"))?;
        let num_free =
            i32::try_from(num_free).map_err(|_| AsmError::Operand("lambda environment size"))?;
        let trampoline = self.lambda_trampoline(lambda)?;
        self.asm.bind(trampoline)?;
        let fun_thing = self.asm.emit_ptr_val(ARG4, ARG4);
        debug_assert!(num_free > 0);
        self.asm.emit_copy_words(
            emit_boxed_val(fun_thing, FUN_ENV_OFFSET, 8),
            get_x_ref(effective_arity, 8),
            num_free,
            RET,
        )?;
        let target = self
            .resolve_beam_label(arg_label(label)?)
            .ok_or(AsmError::Operand("lambda body label"))?;
        self.asm.jmp(target)
    }

    /// Creates a local fun and moves its captured environment into the heap object.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:195-267 (emit_i_make_fun3),
    // OTP-29.1.1.
    pub fn emit_i_make_fun3(
        &mut self,
        lambda: ArgVal,
        dst: ArgVal,
        arity: ArgVal,
        num_free: ArgVal,
        env: &[ArgVal],
    ) -> Result<(), AsmError> {
        let arity = arg_word(arity)?;
        let num_free = arg_word(num_free)?;
        debug_assert_eq!(num_free as usize, env.len());
        debug_assert!(num_free + arity < 255);

        self.mov_arg_to_reg(RET, lambda)?;
        self.preserve_cache(&[], &[], |m| {
            m.asm
                .emit(|e| e.mov_mi(qword_ptr(HTOP, 0), make_fun_header(arity, num_free) as i64))?;
            m.asm
                .emit(|e| e.mov_mr(qword_ptr(HTOP, FUN_ENTRY_OFFSET), RET))
        })?;

        let mut index = 0;
        while index < env.len() {
            let next = env
                .get(index + 1)
                .copied()
                .unwrap_or(ArgVal::Immediate(0x3b));
            match memory_relation(env[index], next) {
                Relation::Consecutive => {
                    let source = get_arg_ref(env[index], 16)
                        .ok_or(AsmError::Operand("lambda environment register"))?;
                    let destination = xmmword_ptr(HTOP, FUN_ENV_OFFSET + (index as i32 * 8));
                    self.preserve_cache(&[], &[], |m| {
                        m.asm.vmovups_xm(Xmm(0), source)?;
                        m.asm.vmovups_mx(destination, Xmm(0))
                    })?;
                    index += 2;
                }
                Relation::ReverseConsecutive if BeamAssembler::has_cpu_feature(CpuFeature::Avx) => {
                    let source_arg = env[index + 1];
                    let source = get_arg_ref(source_arg, 16)
                        .ok_or(AsmError::Operand("lambda environment register"))?;
                    let destination = xmmword_ptr(HTOP, FUN_ENV_OFFSET + (index as i32 * 8));
                    self.preserve_cache(&[], &[], |m| {
                        m.asm.emit(|e| e.vpermilpd_xmi(Xmm(0), source, 1))?;
                        m.asm.emit(|e| e.vmovups_mx(destination, Xmm(0)))
                    })?;
                    index += 2;
                }
                Relation::None | Relation::ReverseConsecutive => {
                    let destination = qword_ptr(HTOP, FUN_ENV_OFFSET + (index as i32 * 8));
                    self.mov_arg_to_mem(destination, env[index], ARG1)?;
                    index += 1;
                }
            }
        }

        self.preserve_cache(&[RET, HTOP], &[], |m| {
            m.asm.emit(|e| e.lea(RET, qword_ptr(HTOP, 2)))?;
            m.asm
                .emit(|e| e.add_ri(HTOP, ((ERL_FUN_SIZE + num_free) * 8) as i64))
        })?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// `i_apply_fun`: unpacks `Args`, validates `Fun`, and calls its entry.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:345-352 (emit_i_apply_fun),
    // OTP-29.1.1.
    pub fn emit_i_apply_fun(&mut self) -> Result<(), AsmError> {
        let fragment = self.ga_get(GlobalLabels::ApplyFunShared)?;
        self.safe_fragment_call(fragment)?;
        let target = self.emit_call_fun(false, false)?;
        self.asm.erlang_call_r(target)
    }

    /// `i_apply_fun_last Deallocate`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:353-356
    // (emit_i_apply_fun_last), OTP-29.1.1.
    pub fn emit_i_apply_fun_last(&mut self, deallocate: ArgVal) -> Result<(), AsmError> {
        self.emit_deallocate(deallocate)?;
        self.emit_i_apply_fun_only()
    }

    /// `i_apply_fun_only`: tail-calls the validated fun entry.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:358-367
    // (emit_i_apply_fun_only), OTP-29.1.1.
    pub fn emit_i_apply_fun_only(&mut self) -> Result<(), AsmError> {
        let fragment = self.ga_get(GlobalLabels::ApplyFunShared)?;
        self.safe_fragment_call(fragment)?;
        let target = self.emit_call_fun(false, false)?;
        self.asm.emit_leave_frame()?;
        self.asm.emit(|e| e.jmp_r(target))
    }

    /// Validates a fun header and returns its active dispatch address, or the error fragment.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:369-413 (emit_call_fun), OTP-29.1.1.
    fn emit_call_fun(
        &mut self,
        skip_box_test: bool,
        skip_header_test: bool,
    ) -> Result<arinsal_x64::enc::Gp, AsmError> {
        let can_fail = !(skip_box_test && skip_header_test);
        let next = self.asm.new_label();
        let fun_thing = self.asm.emit_ptr_val(RET, ARG4);

        if can_fail {
            let error = self.ga_get(GlobalLabels::HandleCallFunError)?;
            self.asm.mov_imm(ARG1, error as u64)?;
        }
        self.asm
            .a
            .emit_rip_label(next, |e| e.lea(ARG5, arinsal_x64::enc::Mem::rip(0, 8)))?;

        if !skip_box_test {
            self.asm
                .emit(|e| e.test_ri(ARG4.r32(), TAG_PRIMARY_MASK_I64 - 2))?;
            self.asm.short_jcc(CondCode::NE, next)?;
        }
        if !skip_header_test {
            self.asm
                .emit(|e| e.cmp_mr(emit_boxed_val(fun_thing, 0, 2), ARG3.r16()))?;
            self.asm.short_jcc(CondCode::NE, next)?;
        }
        self.asm
            .emit(|e| e.mov_rm(RET, emit_boxed_val(fun_thing, FUN_ENTRY_OFFSET, 8)))?;
        let target = self.asm.emit_setup_dispatchable_call_active(RET)?;
        self.asm.emit(|e| e.mov_rm(ARG1, target))?;
        self.asm.bind(next)?;
        Ok(ARG1)
    }

    /// `i_call_fun2 Tag Arity Func`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:415-436 (emit_i_call_fun2),
    // OTP-29.1.1.
    pub fn emit_i_call_fun2(
        &mut self,
        tag: ArgVal,
        arity: ArgVal,
        func: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG4, func)?;
        if let Some(tag_word) = tag.immed() {
            let arity = arg_word(arity)?;
            self.asm.mov_imm(ARG3, make_fun_header(arity, 0) & 0xffff)?;
            let target = self.emit_call_fun(
                self.always_one_of(func, type_id::ALWAYS_BOXED),
                tag_word == Term::atom(atoms::SAFE).word(),
            )?;
            self.asm.erlang_call_r(target)
        } else if let ArgVal::FunEntry(lambda) = tag {
            let trampoline = self.lambda_trampoline(lambda)?;
            self.asm.erlang_call(trampoline)
        } else {
            Err(AsmError::Operand("call_fun tag"))
        }
    }

    /// `i_call_fun2_last Tag Arity Func Deallocate`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:438-466
    // (emit_i_call_fun2_last), OTP-29.1.1.
    pub fn emit_i_call_fun2_last(
        &mut self,
        tag: ArgVal,
        arity: ArgVal,
        func: ArgVal,
        deallocate: ArgVal,
    ) -> Result<(), AsmError> {
        self.mov_arg_to_reg(ARG4, func)?;
        if let Some(tag_word) = tag.immed() {
            let arity = arg_word(arity)?;
            self.asm.mov_imm(ARG3, make_fun_header(arity, 0) & 0xffff)?;
            let target = self.emit_call_fun(
                self.always_one_of(func, type_id::ALWAYS_BOXED),
                tag_word == Term::atom(atoms::SAFE).word(),
            )?;
            self.emit_deallocate(deallocate)?;
            self.asm.emit_leave_frame()?;
            self.asm.emit(|e| e.jmp_r(target))
        } else if let ArgVal::FunEntry(lambda) = tag {
            let trampoline = self.lambda_trampoline(lambda)?;
            self.emit_deallocate(deallocate)?;
            self.asm.emit_leave_frame()?;
            self.asm.jmp(trampoline)
        } else {
            Err(AsmError::Operand("call_fun tag"))
        }
    }

    /// `i_call_fun Arity`: the fun is in X[Arity] and the tag is `am_unsafe`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:469-474 (emit_i_call_fun),
    // OTP-29.1.1.
    pub fn emit_i_call_fun(&mut self, arity: ArgVal) -> Result<(), AsmError> {
        let index =
            u32::try_from(arg_word(arity)?).map_err(|_| AsmError::Operand("call_fun arity"))?;
        self.emit_i_call_fun2(
            ArgVal::Immediate(Term::atom(atoms::UNSAFE).word()),
            arity,
            ArgVal::X(index),
        )
    }

    /// `i_call_fun_last Arity Deallocate`.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:476-483
    // (emit_i_call_fun_last), OTP-29.1.1.
    pub fn emit_i_call_fun_last(
        &mut self,
        arity: ArgVal,
        deallocate: ArgVal,
    ) -> Result<(), AsmError> {
        let index =
            u32::try_from(arg_word(arity)?).map_err(|_| AsmError::Operand("call_fun arity"))?;
        self.emit_i_call_fun2_last(
            ArgVal::Immediate(Term::atom(atoms::UNSAFE).word()),
            arity,
            ArgVal::X(index),
            deallocate,
        )
    }

    /// `i_lambda_error`: this pseudo-instruction is never executed.
    // Port of erts/emulator/beam/jit/x86/instr_fun.cpp:485-489 (emit_i_lambda_error),
    // OTP-29.1.1.
    pub fn emit_i_lambda_error(&mut self, _dummy: ArgVal) -> Result<(), AsmError> {
        self.asm.emit(|e| e.ud2())
    }
}

#[cfg(test)]
mod differential_tests {
    use super::super::instr_call::differential_tests::{Target, TargetRewrite, assert_matches};
    use super::*;
    use crate::common::types::ArgType;

    fn error_handler(module: &BeamModuleAssembler) -> Vec<(&'static str, u64)> {
        vec![(
            "rdi",
            module
                .ga_get(GlobalLabels::HandleCallFunError)
                .expect("call_fun error fragment") as u64,
        )]
    }

    #[test]
    fn fun_emitters_match_erts_dump() {
        let erl_eval = crate::x86::jdump::erts_dump("erl_eval").expect("erl_eval +JDdump");
        let purger =
            crate::x86::jdump::erts_dump("erts_code_purger").expect("erts_code_purger +JDdump");
        let beam_lib = crate::x86::jdump::erts_dump("beam_lib").expect("beam_lib +JDdump");
        let c = crate::x86::jdump::erts_dump("c").expect("c +JDdump");
        let code_server = crate::x86::jdump::erts_dump("code_server").expect("code_server +JDdump");
        let unicode = crate::x86::jdump::erts_dump("unicode").expect("unicode +JDdump");
        let sets = crate::x86::jdump::erts_dump("sets").expect("sets +JDdump");

        let apply_fun_rewrite = [TargetRewrite {
            source: "L1658",
            target: Target::Fragment(GlobalLabels::ApplyFunShared),
        }];
        assert_matches(
            &erl_eval,
            "i_apply_fun",
            |_| true,
            BeamModuleAssembler::emit_i_apply_fun,
            &apply_fun_rewrite,
            error_handler,
            &[],
        );
        assert_matches(
            &erl_eval,
            "i_apply_fun_last_t",
            |block| block.iter().any(|line| line == "add rsp, 64"),
            |module| module.emit_i_apply_fun_last(ArgVal::Word(8)),
            &apply_fun_rewrite,
            error_handler,
            &[],
        );
        assert_matches(
            &purger,
            "i_apply_fun_only",
            |_| true,
            BeamModuleAssembler::emit_i_apply_fun_only,
            &[TargetRewrite {
                source: "L175",
                target: Target::Fragment(GlobalLabels::ApplyFunShared),
            }],
            error_handler,
            &[],
        );

        assert_matches(
            &beam_lib,
            "i_call_fun_t",
            |block| {
                block
                    .iter()
                    .any(|line| line == "mov rcx, qword ptr [rbx+8]")
            },
            |module| module.emit_i_call_fun(ArgVal::Word(1)),
            &[],
            error_handler,
            &[],
        );
        assert_matches(
            &c,
            "i_call_fun_last_tt",
            |_| true,
            |module| module.emit_i_call_fun_last(ArgVal::Word(1), ArgVal::Word(2)),
            &[],
            error_handler,
            &[],
        );

        assert_matches(
            &code_server,
            "i_call_fun2_last_atSt",
            |_| true,
            |module| {
                let fun = module.typed_arg(
                    ArgVal::X(1),
                    ArgType {
                        union_bits: type_id::FUN,
                        min: None,
                        max: None,
                        unit: 1,
                    },
                );
                module.emit_i_call_fun2_last(
                    ArgVal::Immediate(Term::atom(atoms::SAFE).word()),
                    ArgVal::Word(1),
                    fun,
                    ArgVal::Word(0),
                )
            },
            &[],
            error_handler,
            &[],
        );
        assert_matches(
            &unicode,
            "i_call_fun2_FtS",
            |block| {
                block
                    .iter()
                    .any(|line| line == "mov rcx, qword ptr [rbx+16]")
            },
            |module| module.emit_i_call_fun2(ArgVal::FunEntry(0), ArgVal::Word(2), ArgVal::X(2)),
            &[TargetRewrite {
                source: "L452",
                target: Target::Lambda(0),
            }],
            |_| Vec::new(),
            &[0],
        );
        assert_matches(
            &unicode,
            "i_call_fun2_last_FtSt",
            |_| true,
            |module| {
                module.emit_i_call_fun2_last(
                    ArgVal::FunEntry(0),
                    ArgVal::Word(2),
                    ArgVal::X(2),
                    ArgVal::Word(0),
                )
            },
            &[TargetRewrite {
                source: "L452",
                target: Target::Lambda(0),
            }],
            |_| Vec::new(),
            &[0],
        );

        assert_matches(
            &sets,
            "i_make_fun3_FStt",
            |block| {
                block
                    .iter()
                    .any(|line| line == "mov rdi, qword ptr [rsp+8]")
            },
            |module| {
                module.emit_i_make_fun3(
                    ArgVal::FunEntry(0),
                    ArgVal::X(0),
                    ArgVal::Word(1),
                    ArgVal::Word(1),
                    &[ArgVal::Y(1)],
                )
            },
            &[],
            |_| Vec::new(),
            &[0],
        );
        assert_matches(
            &sets,
            "i_lambda_trampoline_FfWW",
            |block| block.iter().any(|line| line == "mov [rbx+16], rax"),
            |module| {
                module.emit_i_lambda_trampoline(
                    ArgVal::FunEntry(0),
                    ArgVal::Label(1),
                    ArgVal::Word(3),
                    ArgVal::Word(1),
                )
            },
            &[TargetRewrite {
                source: "'-filtermap/2-fun-0-'/3",
                target: Target::Beam(1),
            }],
            |_| Vec::new(),
            &[0],
        );
    }

    #[test]
    fn lambda_error_matches_asmjit_ud2() {
        let mut module = BeamModuleAssembler::new(1);
        module
            .emit_i_lambda_error(ArgVal::Word(0))
            .expect("emit i_lambda_error");
        let expected = crate::x86::jdump::gnu_as(&["ud2".to_owned()]).expect("GNU as ud2");
        assert_eq!(
            module.asm.a.bytes(arinsal_x64::buf::Section::Code),
            expected
        );
    }
}
