//! Native record instructions.
//!
//! Port of erts/emulator/beam/jit/x86/instr_records.cpp, OTP-29.1.1.

use arinsal_term::{Term, atoms};
use arinsal_x64::enc::CondCode;

use crate::common::args::ArgVal;

use super::beam_asm::register::{ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, C_P, RET};
use super::beam_asm::{AsmError, Distance, Update, emit_boxed_val};
use super::beam_asm_module::{BeamModuleAssembler, arg_label};
use super::rt::{
    addr, erl_create_local_native_record, erl_create_native_record, erl_get_local_record_field,
    erl_get_record_elements, erl_get_record_field, erl_update_native_record,
};

const RECORD_INSTANCE_DEFINITION: i32 = 8;
const RECORD_DEFINITION_MODULE: i32 = 24;
const RECORD_DEFINITION_NAME: i32 = 32;
const RECORD_DEFINITION_IS_EXPORTED: i32 = 40;
const TAG_HEADER_RECORD: i64 = 0x3c;
const TAG_HEADER_MASK: i64 = 0xfc;

impl BeamModuleAssembler {
    /// Tests whether `src` has the native record header.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:30-45 (emit_is_any_native_record),
    // OTP-29.1.1.
    pub fn emit_is_any_native_record(&mut self, fail: ArgVal, src: ArgVal) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("record test to an unknown label"))?;
        self.mov_arg_to_reg(ARG3, src)?;
        self.emit_is_boxed(fail, ARG3, Distance::Long)?;
        let boxed_ptr = self.asm.emit_ptr_val(RET, ARG3);
        self.preserve_cache(&[RET], &[], |m| {
            m.asm
                .emit(|e| e.mov_rm(RET.r32(), emit_boxed_val(boxed_ptr, 0, 4)))?;
            m.asm.emit(|e| e.and_ri(RET.r8(), TAG_HEADER_MASK))?;
            m.asm.emit(|e| e.cmp_ri(RET.r8(), TAG_HEADER_RECORD))?;
            m.asm.jcc(CondCode::NE, fail)
        })
    }

    /// Tests a native record's defining module and record name.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:47-72 (emit_is_native_record),
    // OTP-29.1.1.
    pub fn emit_is_native_record(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        module: ArgVal,
        name: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("record test to an unknown label"))?;
        self.mov_arg_to_reg(ARG3, src)?;
        let mut boxed_ptr = self.asm.emit_ptr_val(RET, ARG3);
        let definition = emit_boxed_val(boxed_ptr, RECORD_INSTANCE_DEFINITION, 8);
        self.mov_preserve_cache_load(RET, definition)?;
        boxed_ptr = self.asm.emit_ptr_val(RET, RET);
        self.cmp_arg_mem(
            emit_boxed_val(boxed_ptr, RECORD_DEFINITION_MODULE, 8),
            module,
            ARG1,
        )?;
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::NE, fail))?;
        self.cmp_arg_mem(
            emit_boxed_val(boxed_ptr, RECORD_DEFINITION_NAME, 8),
            name,
            ARG1,
        )?;
        self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::NE, fail))
    }

    /// Tests whether a native record may be accessed from `scope`.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:74-112 (emit_is_record_accessible),
    // OTP-29.1.1.
    pub fn emit_is_record_accessible(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        scope: ArgVal,
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("record access test to an unknown label"))?;
        self.mov_arg_to_reg(ARG3, src)?;
        let boxed_ptr = self.asm.emit_ptr_val(RET, ARG3);
        let definition = emit_boxed_val(boxed_ptr, RECORD_INSTANCE_DEFINITION, 8);
        self.mov_preserve_cache_load(RET, definition)?;
        let boxed_ptr = self.asm.emit_ptr_val(RET, RET);
        let exported = Term::atom(atoms::TRUE).word();
        self.cmp_arg_mem(
            emit_boxed_val(boxed_ptr, RECORD_DEFINITION_IS_EXPORTED, 8),
            ArgVal::Immediate(exported),
            ARG1,
        )?;

        if scope == ArgVal::Immediate(Term::atom(atoms::EXTERNAL).word()) {
            self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::NE, fail))
        } else {
            let next = self.asm.new_label();
            self.preserve_cache(&[], &[], |m| m.asm.short_jcc(CondCode::E, next))?;
            let module = self
                .module
                .ok_or(AsmError::Operand("record access without module atom"))?;
            self.cmp_arg_mem(
                emit_boxed_val(boxed_ptr, RECORD_DEFINITION_MODULE, 8),
                ArgVal::Immediate(Term::atom(module).word()),
                ARG1,
            )?;
            self.preserve_cache(&[], &[], |m| m.asm.jcc(CondCode::NE, fail))?;
            self.asm.bind(next)
        }
    }

    /// Copies selected values from a native record into the requested registers.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:114-132 (emit_i_get_record_elements),
    // OTP-29.1.1.
    pub fn emit_i_get_record_elements(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        _size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let fail = self
            .resolve_beam_label(arg_label(fail)?)
            .ok_or(AsmError::Operand("record elements to an unknown label"))?;
        self.mov_arg_to_reg(ARG3, src)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.asm.mov_imm(ARG4, args.len() as u64)?;
        self.embed_vararg_rodata(args, ARG5, 0)?;
        self.asm.emit_enter_runtime(Update::STACK)?;
        self.asm
            .runtime_call(addr(erl_get_record_elements as *const ()))?;
        self.asm.emit_leave_runtime(Update::STACK)?;
        self.asm.emit(|e| e.test_rr(RET.r8(), RET.r8()))?;
        self.asm.jcc(CondCode::E, fail)
    }

    /// Constructs a local native record from its embedded definition.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:134-164
    // (emit_i_create_local_native_record), OTP-29.1.1.
    pub fn emit_i_create_local_native_record(
        &mut self,
        definition: ArgVal,
        dst: ArgVal,
        live: ArgVal,
        _size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.mov_arg_to_reg(ARG3, definition)?;
        self.mov_arg_to_reg(ARG4, live)?;
        self.asm.mov_imm(ARG5, args.len() as u64)?;
        self.embed_vararg_rodata(args, ARG6, 0)?;
        let spec = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        self.asm.emit_enter_runtime(spec)?;
        self.asm
            .runtime_call(addr(erl_create_local_native_record as *const ()))?;
        self.asm.emit_leave_runtime(spec)?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::NE, next)?;
        self.emit_raise_exception_current()?;
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Constructs a native record from its definition id.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:166-196 (emit_i_create_native_record),
    // OTP-29.1.1.
    pub fn emit_i_create_native_record(
        &mut self,
        id: ArgVal,
        dst: ArgVal,
        live: ArgVal,
        _size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.mov_arg_to_reg(ARG3, id)?;
        self.mov_arg_to_reg(ARG4, live)?;
        self.asm.mov_imm(ARG5, args.len() as u64)?;
        self.embed_vararg_rodata(args, ARG6, 0)?;
        let spec = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        self.asm.emit_enter_runtime(spec)?;
        self.asm
            .runtime_call(addr(erl_create_native_record as *const ()))?;
        self.asm.emit_leave_runtime(spec)?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::NE, next)?;
        self.emit_raise_exception_current()?;
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Updates the fields of an existing native record.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:198-228 (emit_i_update_native_record),
    // OTP-29.1.1.
    pub fn emit_i_update_native_record(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        live: ArgVal,
        _size: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.mov_arg_to_reg(ARG3, src)?;
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.asm.load_x_reg_array(ARG2)?;
        self.mov_arg_to_reg(ARG4, live)?;
        self.asm.mov_imm(ARG5, args.len() as u64)?;
        self.embed_vararg_rodata(args, ARG6, 0)?;
        let spec = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        self.asm.emit_enter_runtime(spec)?;
        self.asm
            .runtime_call(addr(erl_update_native_record as *const ()))?;
        self.asm.emit_leave_runtime(spec)?;
        self.asm.emit_test_the_non_value(RET)?;
        self.asm.short_jcc(CondCode::NE, next)?;
        self.emit_raise_exception_current()?;
        self.asm.bind(next)?;
        self.mov_arg_from_reg(dst, RET)
    }

    /// Looks up a field in a native record by definition id and field name.
    // Port of erts/emulator/beam/jit/x86/instr_records.cpp:230-267 (emit_get_record_field),
    // OTP-29.1.1.
    pub fn emit_get_record_field(
        &mut self,
        fail: ArgVal,
        src: ArgVal,
        id: ArgVal,
        name: ArgVal,
        dst: ArgVal,
    ) -> Result<(), AsmError> {
        self.asm.emit(|e| e.mov_rr(ARG1, C_P))?;
        self.mov_arg_to_reg(ARG2, src)?;
        self.mov_arg_to_reg(ARG3, id)?;
        self.mov_arg_to_reg(ARG4, name)?;
        self.asm.emit_enter_runtime(Update::HEAP_ALLOC)?;
        let function = if matches!(id, ArgVal::Immediate(_)) {
            addr(erl_get_local_record_field as *const ())
        } else {
            addr(erl_get_record_field as *const ())
        };
        self.asm.runtime_call(function)?;
        self.asm.emit_leave_runtime(Update::HEAP_ALLOC)?;

        let fail_label = arg_label(fail)?;
        if fail_label != 0 {
            let fail = self
                .resolve_beam_label(fail_label)
                .ok_or(AsmError::Operand("record field to an unknown label"))?;
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.jcc(CondCode::E, fail)?;
        } else {
            let next = self.asm.new_label();
            self.asm.emit_test_the_non_value(RET)?;
            self.asm.short_jcc(CondCode::NE, next)?;
            self.emit_raise_exception_current()?;
            self.asm.bind(next)?;
        }
        self.mov_arg_from_reg(dst, RET)
    }
}
