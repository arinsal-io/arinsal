//! Native record checks and operations.
//!
//! Port of erts/emulator/beam/jit/arm/instr_records.cpp, OTP-29.1.1.

use arinsal_a64::enc::{Cond, Gpr};

use crate::rt::addr;
use crate::{
    Update, emit_enter_runtime, emit_leave_runtime,
    module::{ArgVal, BeamModuleAssembler, ModuleError},
};

const C_P: Gpr = Gpr::x(21);
const E: Gpr = Gpr::x(20);
const X: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    logical_xreg(15),
    logical_xreg(16),
];
const SCHEDULER_REGS: Gpr = Gpr::x(19);
// erts' ARG1..ARG6 (arm/beam_asm.hpp).
const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(1);
const ARG3: Gpr = Gpr::x(2);
const ARG4: Gpr = Gpr::x(3);
const ARG5: Gpr = Gpr::x(4);
const ARG6: Gpr = Gpr::x(5);
const TMP: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const TMP3: Gpr = Gpr::x(10);
const TAG_BOXED: u16 = 2;
const HEADER_MASK: u16 = 0x3f;
const HEADER_RECORD: u16 = 0x1c;

// These entries map logical XREG4/5 to their caller-saved hardware registers.
const fn logical_xreg(index: u8) -> Gpr {
    Gpr::x(index)
}

impl BeamModuleAssembler {
    /// Tests whether a boxed term has OTP's native record header.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:29-45, OTP-29.1.1.
    pub fn emit_is_any_native_record(&mut self, fail: u32, src: ArgVal) -> Result<(), ModuleError> {
        let source = self.source_reg(src)?;
        let fail = self.label(fail);
        self.code.emit(|e| {
            e.and_imm(TMP, source, 7)?;
            e.cmp_imm(TMP, TAG_BOXED, false)
        })?;
        self.code.b_cond(Cond::Ne, fail)?;
        self.code.emit(|e| e.and_imm(TMP, source, !7))?;
        self.code.emit(|e| e.ldr_uoff(TMP, TMP, 0))?;
        self.code
            .emit(|e| e.and_imm(TMP, TMP, u64::from(HEADER_MASK)))?;
        self.code.emit(|e| e.cmp_imm(TMP, HEADER_RECORD, false))?;
        self.code.b_cond(Cond::Ne, fail)?;
        Ok(())
    }

    /// Tests a native record's module and name atoms.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:47-71, OTP-29.1.1.
    pub fn emit_is_native_record(
        &mut self,
        fail: u32,
        src: ArgVal,
        module: ArgVal,
        name: ArgVal,
    ) -> Result<(), ModuleError> {
        let source = self.source_reg(src)?;
        self.code.emit(|e| e.and_imm(TMP, source, !7))?;
        self.code.emit(|e| e.ldr_uoff(TMP, TMP, 8))?;
        self.code.emit(|e| e.and_imm(TMP, TMP, !7))?;
        self.code.emit(|e| e.ldp(TMP2, TMP3, TMP, 24))?;
        let module = self.source_reg(module)?;
        self.code
            .emit(|e| e.cmp_reg(TMP2, module, arinsal_a64::enc::Shift::Lsl, 0))?;
        let fail = self.label(fail);
        self.code.b_cond(Cond::Ne, fail)?;
        let name = self.source_reg(name)?;
        self.code
            .emit(|e| e.cmp_reg(TMP3, name, arinsal_a64::enc::Shift::Lsl, 0))?;
        self.code.b_cond(Cond::Ne, fail)?;
        Ok(())
    }

    /// Tests whether a record is accessible from an external or local operation.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:73-115, OTP-29.1.1.
    pub fn emit_is_record_accessible(
        &mut self,
        fail: u32,
        src: ArgVal,
        external: bool,
        current_module: ArgVal,
    ) -> Result<(), ModuleError> {
        let source = self.source_reg(src)?;
        self.code.emit(|e| e.and_imm(TMP, source, !7))?;
        self.code.emit(|e| e.ldr_uoff(TMP, TMP, 8))?;
        self.code.emit(|e| e.and_imm(TMP, TMP, !7))?;
        self.code.emit(|e| e.mov_reg(TMP3, TMP))?;
        let fail = self.label(fail);
        if external {
            // The true atom has bit 6 set, as in OTP's am_false/am_true assertion.
            self.code.emit(|e| e.ldr_uoff(TMP2, TMP3, 40))?;
            self.code.tbz(TMP2, 6, fail)?;
        } else {
            // Accessible when exported or defined by the current module: the module
            // comparison only counts when the record is not exported.
            let module = self.source_reg_into(current_module, TMP)?;
            let accessible = self.code.new_label();
            self.code.emit(|e| e.ldr_uoff(TMP2, TMP3, 40))?;
            self.code.tbnz(TMP2, 6, accessible)?;
            self.code.emit(|e| e.ldr_uoff(TMP2, TMP3, 24))?;
            self.code
                .emit(|e| e.cmp_reg(TMP2, module, arinsal_a64::enc::Shift::Lsl, 0))?;
            self.code.b_cond(Cond::Ne, fail)?;
            self.code.bind(accessible)?;
        }
        Ok(())
    }

    /// `get_record_field`: `erl_get_local_record_field` for an immediate ID, otherwise
    /// `erl_get_record_field`; THE_NON_VALUE branches to `fail` or raises.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:241-274 (emit_get_record_field),
    // OTP-29.1.1.
    pub fn emit_get_record_field(
        &mut self,
        fail: u32,
        src: ArgVal,
        id: ArgVal,
        name: ArgVal,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.mov_arg(ARG2, src)?;
        self.mov_arg(ARG3, id)?;
        self.mov_arg(ARG4, name)?;
        let local = match id {
            ArgVal::Immediate(_) => true,
            ArgVal::Literal(index) => !matches!(self.beamfile_get_literal(index) & 7, 1 | 2),
            _ => false,
        };
        let target = if local {
            addr(crate::rt::erl_get_local_record_field as *const ())
        } else {
            addr(crate::rt::erl_get_record_field as *const ())
        };
        self.emit_record_call(target, 6, Update::HEAP_ALLOC, Update::HEAP_ALLOC)?;
        if fail != 0 {
            let fail = self.label(fail);
            self.code.cbz(ARG1, fail)?;
        } else {
            self.emit_raise_if_not_value()?;
        }
        self.store_record_result(dst)
    }

    /// `i_create_local_native_record`.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:145-180, OTP-29.1.1.
    pub fn emit_i_create_local_native_record(
        &mut self,
        definition: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.emit_create(
            addr(crate::rt::erl_create_local_native_record as *const ()),
            definition,
            dst,
            live,
            args,
        )
    }

    /// `i_create_native_record`.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:182-207, OTP-29.1.1.
    pub fn emit_i_create_native_record(
        &mut self,
        id: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.emit_create(
            addr(crate::rt::erl_create_native_record as *const ()),
            id,
            dst,
            live,
            args,
        )
    }

    /// `i_get_record_elements`: `args` are the loader-sorted `{Key, Dst}` pairs, flattened.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:117-143, OTP-29.1.1.
    pub fn emit_i_get_record_elements(
        &mut self,
        fail: u32,
        src: ArgVal,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.mov_arg(ARG3, src)?;
        self.code.emit(|e| {
            e.mov_reg(ARG1, C_P)?;
            crate::arm::beam_asm::load_x_reg_array(e, ARG2)?;
            e.mov_const(ARG4, args.len() as u64)
        })?;
        self.embed_vararg_rodata(args, ARG5)?;
        self.emit_record_call(
            addr(crate::rt::erl_get_record_elements as *const ()),
            6,
            Update::STACK.union(Update::X_REGS),
            Update::X_REGS,
        )?;
        let fail = self.label(fail);
        self.code.tbz(Gpr::w(0), 0, fail)?;
        Ok(())
    }

    /// `i_update_native_record`.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:209-239, OTP-29.1.1.
    pub fn emit_i_update_native_record(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.mov_arg(ARG3, src)?;
        self.emit_vector_args(live, args)?;
        let update = Update::HEAP_ALLOC
            .union(Update::X_REGS)
            .union(Update::REDUCTIONS);
        self.emit_record_call(
            addr(crate::rt::erl_update_native_record as *const ()),
            6,
            update,
            update,
        )?;
        self.emit_raise_if_not_value()?;
        self.store_record_result(dst)
    }

    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:145-207
    // (emit_i_create_local_native_record, emit_i_create_native_record), OTP-29.1.1.
    fn emit_create(
        &mut self,
        target: usize,
        id: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
    ) -> Result<(), ModuleError> {
        self.mov_arg(ARG3, id)?;
        self.emit_vector_args(live, args)?;
        let update = Update::HEAP_ALLOC
            .union(Update::X_REGS)
            .union(Update::REDUCTIONS);
        let live = live as usize;
        self.emit_record_call(target, live, update, update)?;
        self.emit_raise_if_not_value()?;
        self.store_record_result(dst)
    }

    /// `a.mov(ARG1, c_p); load_x_reg_array(ARG2); mov_arg(ARG4, Live);
    /// mov_imm(ARG5, args.size()); embed_vararg_rodata(args, ARG6)`.
    fn emit_vector_args(&mut self, live: u32, args: &[ArgVal]) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.mov_reg(ARG1, C_P)?;
            crate::arm::beam_asm::load_x_reg_array(e, ARG2)?;
            e.mov_const(ARG4, u64::from(live))?;
            e.mov_const(ARG5, args.len() as u64)
        })?;
        self.embed_vararg_rodata(args, ARG6)
    }

    /// `mov_arg(reg, src)`.
    fn mov_arg(&mut self, reg: Gpr, src: ArgVal) -> Result<(), ModuleError> {
        let value = self.source_reg_into(src, reg)?;
        if value != reg {
            self.code.emit(|e| e.mov_reg(reg, value))?;
        }
        Ok(())
    }

    /// `emit_enter_runtime<enter>(live); runtime_call<target>(); emit_leave_runtime<leave>(live)`
    /// with `c_p` in ARG1.
    fn emit_record_call(
        &mut self,
        target: usize,
        live: usize,
        enter: Update,
        leave: Update,
    ) -> Result<(), ModuleError> {
        emit_enter_runtime(&mut self.code, live, enter)?;
        self.code.emit(|e| e.mov_reg(ARG1, C_P))?;
        self.fragment_call(target)?;
        emit_leave_runtime(&mut self.code, live, leave)?;
        Ok(())
    }

    /// `emit_branch_if_value(ARG1, next); emit_raise_exception(); next:`.
    fn emit_raise_if_not_value(&mut self) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        self.code.cbnz(ARG1, next)?;
        self.branch_error()?;
        self.code.bind(next)?;
        Ok(())
    }

    /// `mov_arg(Dst, ARG1)`.
    fn store_record_result(&mut self, dst: ArgVal) -> Result<(), ModuleError> {
        match dst {
            ArgVal::X(index) if index < 6 => {
                self.code
                    .emit(|e| e.mov_reg(X[index as usize], Gpr::x(0)))?;
                Ok(())
            }
            ArgVal::X(index) if index < 1024 => {
                self.code.emit(|e| {
                    e.str_uoff(
                        Gpr::x(0),
                        SCHEDULER_REGS,
                        crate::arm::beam_asm::x_ref(index),
                    )
                })?;
                Ok(())
            }
            ArgVal::Y(index) => {
                let offset = index.checked_mul(8).ok_or(ModuleError::InvalidOperand(
                    "record destination offset overflow",
                ))?;
                self.code.emit(|e| e.str_uoff(Gpr::x(0), E, offset))?;
                Ok(())
            }
            _ => Err(ModuleError::InvalidOperand(
                "record destination must be X or Y",
            )),
        }
    }
}
