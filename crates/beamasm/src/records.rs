//! Native record checks and helper-backed record operations.

use arinsal_a64::enc::{Cond, Gpr};

use crate::{
    ProcessHeader, SchedulerRegisters, Update, emit_enter_runtime, emit_leave_runtime,
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
const TMP: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const TMP3: Gpr = Gpr::x(10);
const TAG_BOXED: u16 = 2;
const HEADER_MASK: u16 = 0x3f;
const HEADER_RECORD: u16 = 0x1c;
/// Scratch X register of OTP (`SCRATCH_X_REG`): a destination whose value is not wanted.
const SCRATCH_X: u32 = 1023;
/// Top of the key staging area of `get_record_elements`, which has no live count.
const ELEMENTS_STAGING_TOP: u32 = 1020;

// These entries map logical XREG4/5 to their caller-saved hardware registers.
const fn logical_xreg(index: u8) -> Gpr {
    Gpr::x(index)
}

/// Runtime helper for `get_record_field` and `get_local_record_field`: process, record, id,
/// field and a flag that is nonzero when a failure must raise instead of returning zero.
pub type GetRecordFieldHook = extern "C" fn(*mut ProcessHeader, u64, u64, u64, u64) -> u64;
/// Runtime helper for record creation: process, registers, id (or definition literal), live
/// registers, staged word count and the first staged X register. Zero means an error was set.
pub type CreateNativeRecordHook =
    extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, u64, u64, u64, u64) -> u64;
/// Runtime helper for record element extraction: process, registers, record, key count and
/// the first staged X register, which holds the keys on entry and the values on success.
/// Zero means the operation failed.
pub type GetRecordElementsHook =
    extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, u64, u64, u64) -> u64;
/// Runtime helper for native record updates, same arguments as [`CreateNativeRecordHook`] but
/// receiving the source record.
pub type UpdateNativeRecordHook =
    extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, u64, u64, u64, u64) -> u64;

/// Helpers corresponding to OTP's native record runtime entry points.
#[derive(Clone, Copy)]
pub struct RecordRuntime {
    /// `erl_get_record_field`.
    pub get_field: GetRecordFieldHook,
    /// `erl_get_local_record_field`.
    pub get_local_field: GetRecordFieldHook,
    /// `erl_create_local_native_record`.
    pub create_local: CreateNativeRecordHook,
    /// `erl_create_native_record`.
    pub create: CreateNativeRecordHook,
    /// `erl_get_record_elements`.
    pub get_elements: GetRecordElementsHook,
    /// `erl_update_native_record`.
    pub update: UpdateNativeRecordHook,
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

    /// Looks up a record field using the local or external OTP helper selected by the ID tag.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:241-274, OTP-29.1.1.
    pub fn emit_get_record_field(
        &mut self,
        fail: u32,
        src: ArgVal,
        id: ArgVal,
        name: ArgVal,
        dst: ArgVal,
        runtime: RecordRuntime,
    ) -> Result<(), ModuleError> {
        for (register, value) in [(Gpr::x(1), src), (Gpr::x(2), id), (Gpr::x(3), name)] {
            let value = self.source_reg(value)?;
            self.code.emit(|e| e.mov_reg(register, value))?;
        }
        // With a failure label the helper only reports failure; without one it raises.
        let raise = u64::from(fail == 0);
        self.code.emit(|e| e.mov_const(Gpr::x(4), raise))?;
        let helper = if is_immediate_id(id) {
            runtime.get_local_field
        } else {
            runtime.get_field
        };
        emit_record_runtime(
            self,
            helper as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
            6,
            Update::HEAP_ALLOC,
            Update::HEAP_ALLOC,
        )?;
        if fail != 0 {
            let fail = self.label(fail);
            self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
            self.code.b_cond(Cond::Eq, fail)?;
        } else {
            let next = self.code.new_label();
            self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
            self.code.b_cond(Cond::Ne, next)?;
            self.branch_error()?;
            self.code.bind(next)?;
        }
        self.store_record_result(dst)
    }

    /// Creates a local native record from the supplied staged values.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:145-180, OTP-29.1.1.
    pub fn emit_i_create_local_native_record(
        &mut self,
        definition: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
        runtime: RecordRuntime,
    ) -> Result<(), ModuleError> {
        self.emit_create(definition, dst, live, args, runtime.create_local)
    }

    /// Creates a native record by its record ID.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:182-207, OTP-29.1.1.
    pub fn emit_i_create_native_record(
        &mut self,
        id: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
        runtime: RecordRuntime,
    ) -> Result<(), ModuleError> {
        self.emit_create(id, dst, live, args, runtime.create)
    }

    /// Extracts the requested fields into their destination registers. `keys` are sorted by
    /// the loader (`map_key_sort`) and `dsts` holds the destination of each key.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:117-143, OTP-29.1.1.
    pub fn emit_i_get_record_elements(
        &mut self,
        fail: u32,
        src: ArgVal,
        keys: &[ArgVal],
        dsts: &[ArgVal],
        runtime: RecordRuntime,
    ) -> Result<(), ModuleError> {
        if keys.len() != dsts.len() || keys.is_empty() {
            return Err(ModuleError::InvalidOperand(
                "get_record_elements needs one destination per key",
            ));
        }
        let base = ELEMENTS_STAGING_TOP
            .checked_sub(keys.len() as u32)
            .filter(|base| *base > 6)
            .ok_or(ModuleError::InvalidOperand(
                "too many native record elements",
            ))?;
        self.stage_args(keys, base)?;
        let source = self.source_reg(src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), source))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), SCHEDULER_REGS))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(3), keys.len() as u64))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(4), u64::from(base)))?;
        emit_record_runtime(
            self,
            runtime.get_elements as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4)],
            6,
            Update::STACK.union(Update::X_REGS),
            Update::X_REGS,
        )?;
        let fail = self.label(fail);
        self.code.tbz(Gpr::w(0), 0, fail)?;
        for (index, dst) in dsts.iter().copied().enumerate() {
            if matches!(dst, ArgVal::XMemory(SCRATCH_X)) {
                continue;
            }
            let offset = (base + index as u32) * 8;
            self.code
                .emit(|e| e.ldr_uoff(Gpr::x(0), SCHEDULER_REGS, offset))?;
            self.store_record_result(dst)?;
        }
        Ok(())
    }

    /// Copies a native record and applies its staged field updates.
    // Port of erts/emulator/beam/jit/arm/instr_records.cpp:209-239, OTP-29.1.1.
    pub fn emit_i_update_native_record(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
        runtime: RecordRuntime,
    ) -> Result<(), ModuleError> {
        let base = live.max(6);
        self.stage_args(args, base)?;
        let source = self.source_reg(src)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), SCHEDULER_REGS))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), source))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(3), u64::from(live)))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(4), args.len() as u64))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(5), u64::from(base)))?;
        emit_record_runtime(
            self,
            runtime.update as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4), Gpr::x(5)],
            6,
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
        )?;
        self.emit_helper_result(dst)
    }

    fn emit_create(
        &mut self,
        id: ArgVal,
        dst: ArgVal,
        live: u32,
        args: &[ArgVal],
        hook: CreateNativeRecordHook,
    ) -> Result<(), ModuleError> {
        let base = live.max(6);
        self.stage_args(args, base)?;
        let id = self.source_reg(id)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(1), SCHEDULER_REGS))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(2), id))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(3), u64::from(live)))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(4), args.len() as u64))?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(5), u64::from(base)))?;
        emit_record_runtime(
            self,
            hook as usize,
            &[Gpr::x(1), Gpr::x(2), Gpr::x(3), Gpr::x(4), Gpr::x(5)],
            6,
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
        )?;
        self.emit_helper_result(dst)
    }

    fn emit_helper_result(&mut self, dst: ArgVal) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
        self.code.b_cond(Cond::Ne, next)?;
        self.branch_error()?;
        self.code.bind(next)?;
        self.store_record_result(dst)
    }

    /// Stores operands as consecutive words of the scheduler X register array from `base`.
    fn stage_args(&mut self, args: &[ArgVal], base: u32) -> Result<(), ModuleError> {
        if args.len() + base as usize > 1022 {
            return Err(ModuleError::InvalidOperand(
                "native record operands exceed scheduler register capacity",
            ));
        }
        for (index, arg) in args.iter().copied().enumerate() {
            let value = self.source_reg(arg)?;
            let offset = (base as usize + index) * 8;
            let offset = u32::try_from(offset)
                .map_err(|_| ModuleError::InvalidOperand("record operand offset overflow"))?;
            self.code
                .emit(|e| e.str_uoff(value, SCHEDULER_REGS, offset))?;
        }
        Ok(())
    }

    /// Writes x0 to an X or Y register.
    fn store_record_result(&mut self, dst: ArgVal) -> Result<(), ModuleError> {
        match dst {
            ArgVal::X(index) if index < 6 => {
                self.code
                    .emit(|e| e.mov_reg(X[index as usize], Gpr::x(0)))?;
                Ok(())
            }
            ArgVal::XMemory(index) if index < 1024 => {
                self.code
                    .emit(|e| e.str_uoff(Gpr::x(0), SCHEDULER_REGS, index * 8))?;
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

// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1.
fn emit_record_runtime(
    asm: &mut BeamModuleAssembler,
    helper: usize,
    args: &[Gpr],
    live: usize,
    enter_update: Update,
    leave_update: Update,
) -> Result<(), ModuleError> {
    if args.len() > 5 {
        return Err(ModuleError::InvalidOperand(
            "runtime hook has too many arguments",
        ));
    }
    emit_enter_runtime(&mut asm.code, live, enter_update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), C_P)?;
        for (index, arg) in args.iter().copied().enumerate() {
            e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
        }
        e.mov_const(Gpr::x(17), helper as u64)?;
        e.str_uoff(Gpr::x(30), C_P, 72)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(&mut asm.code, live, leave_update)?;
    asm.code.emit(|e| {
        e.ldr_uoff(Gpr::x(30), C_P, 72)?;
        e.ldr_uoff(Gpr::x(9), C_P, 40)
    })?;
    asm.error_if_nonzero(Gpr::x(9))?;
    Ok(())
}

fn is_immediate_id(id: ArgVal) -> bool {
    match id {
        ArgVal::Immediate(_) => true,
        ArgVal::Literal(term) => !matches!(term & 7, 1 | 2),
        _ => false,
    }
}
