//! Process-wide exception fragments shared by every compiled module.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::Gpr,
    exec::{CodeMemory, ExecError},
};

use crate::{
    Update, emit_enter_runtime, emit_leave_runtime,
    guard::{EXC_BADKEY, EXC_BADMAP, MAP_GET_MFA_INDEX, MAP_SIZE_MFA_INDEX},
};

const E: Gpr = Gpr::x(20);
const C_P: Gpr = Gpr::x(21);
const SCHEDULER_REGS: Gpr = Gpr::x(19);
const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(1);
const ARG3: Gpr = Gpr::x(2);
const TMP1: Gpr = Gpr::x(8);
const SUPER_TMP: Gpr = Gpr::x(17);
const TMP2: Gpr = Gpr::x(9);
const XREG0: Gpr = Gpr::x(25);
const XREG1: Gpr = Gpr::x(26);
const VALUE: Gpr = Gpr::x(26);
const TRACE: Gpr = Gpr::x(27);
const PROCESS_FREASON: u32 = 40;
const PROCESS_FVALUE: u32 = 48;
const PROCESS_I: u32 = 72;
const PROCESS_HTOP_STOP: u32 = 8;
const NATIVE_ERROR_PC_SLOT: u32 = 16_432;
const SCHEDULER_RETURN_SLOT: u32 = 16_416;
const BADARG_MFA_SLOT: u32 = 16_440;

/// Exception fragments: `raise_shared` (the `raise/2` instruction) and `raise_exception`.
pub struct RaiseFragments {
    memory: CodeMemory,
    raise_offset: usize,
    raise_exception_offset: usize,
    map_get_badmap_offset: usize,
    map_get_badkey_offset: usize,
    map_size_error_offset: usize,
}

impl RaiseFragments {
    /// Emits the shared raise fragments once for the VM. `resolver` is the native catch
    /// resolver (`handle_error`) and `class_helper` restores the class of a saved stacktrace
    /// (`erts_sanitize_freason`).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_raise_shared) and
    // erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_raise_exception,
    // emit_raise_exception_shared), OTP-29.1.1.
    pub fn new(resolver: usize, class_helper: usize) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let fail = |_: BufferError| ExecError::InvalidSize("raise fragment");
        let raise = code.new_label();
        let raise_exception = code.new_label();
        let caught = code.new_label();

        code.bind(raise).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(TRACE, ARG2)?;
            e.mov_reg(VALUE, ARG1)?;
            e.str_uoff(VALUE, C_P, PROCESS_FVALUE)
        })
        .map_err(fail)?;
        emit_enter_runtime(&mut code, 3, Update::NONE).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(ARG1, C_P)?;
            e.mov_reg(ARG2, TRACE)?;
            e.mov_reg(ARG3, VALUE)?;
            e.mov_const(SUPER_TMP, class_helper as u64)?;
            e.str_uoff(Gpr::x(30), C_P, PROCESS_I)?;
            e.blr(SUPER_TMP)
        })
        .map_err(fail)?;
        emit_leave_runtime(&mut code, 3, Update::NONE).map_err(fail)?;
        code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, PROCESS_I)?;
            e.ldr_uoff(ARG2, C_P, PROCESS_FVALUE)?;
            e.mov_reg(ARG3, TRACE)
        })
        .map_err(fail)?;

        code.bind(raise_exception).map_err(fail)?;
        code.emit(|e| {
            // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp,
            // OTP-29.1.1: the fake CP makes a catch in the raising frame visible to handle_error.
            e.str_pre(Gpr::x(30), E, -8)?;
            e.str_uoff(Gpr::x(30), SCHEDULER_REGS, NATIVE_ERROR_PC_SLOT)
        })
        .map_err(fail)?;
        let update = Update::HEAP_ALLOC.union(Update::X_REGS);
        emit_enter_runtime(&mut code, 6, update).map_err(fail)?;
        code.emit(|e| {
            e.str_uoff(ARG1, C_P, PROCESS_FREASON)?;
            e.stp(ARG2, ARG3, C_P, PROCESS_FVALUE as i16)?;
            e.str_uoff(Gpr::x(30), C_P, PROCESS_I)?;
            e.mov_reg(ARG1, C_P)?;
            e.mov_reg(ARG2, SCHEDULER_REGS)?;
            e.mov_reg(ARG3, E)?;
            e.mov_const(SUPER_TMP, resolver as u64)?;
            e.blr(SUPER_TMP)
        })
        .map_err(fail)?;
        emit_leave_runtime(&mut code, 6, update).map_err(fail)?;
        code.emit(|e| e.ldr_uoff(Gpr::x(30), C_P, PROCESS_I))
            .map_err(fail)?;
        code.cbnz(ARG1, caught).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(ARG1, Gpr::xzr())?;
            e.ldr_uoff(Gpr::x(30), SCHEDULER_REGS, SCHEDULER_RETURN_SLOT)?;
            e.br(Gpr::x(30))
        })
        .map_err(fail)?;
        code.bind(caught).map_err(fail)?;
        code.emit(|e| {
            e.ldr_uoff(E, C_P, PROCESS_HTOP_STOP)?;
            e.br(ARG1)
        })
        .map_err(fail)?;

        let map_get_badmap = code.new_label();
        let map_get_badkey = code.new_label();
        let map_size_error = code.new_label();
        let bif_error = code.new_label();

        // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_handle_map_get_badmap):
        // map in ARG1, key in ARG2; fvalue is the map.
        code.bind(map_get_badmap).map_err(fail)?;
        code.emit(|e| {
            e.mov_const(TMP1, EXC_BADMAP)?;
            e.stp(TMP1, ARG1, C_P, PROCESS_FREASON as i16)?;
            e.mov_reg(XREG0, ARG2)?;
            e.mov_reg(XREG1, ARG1)?;
            e.mov_const(TMP2, u64::from(MAP_GET_MFA_INDEX) + 1)
        })
        .map_err(fail)?;
        code.b(bif_error).map_err(fail)?;

        // Port of instr_guard_bifs.cpp (emit_handle_map_get_badkey): fvalue is the key.
        code.bind(map_get_badkey).map_err(fail)?;
        code.emit(|e| {
            e.mov_const(TMP1, EXC_BADKEY)?;
            e.stp(TMP1, ARG2, C_P, PROCESS_FREASON as i16)?;
            e.mov_reg(XREG0, ARG2)?;
            e.mov_reg(XREG1, ARG1)?;
            e.mov_const(TMP2, u64::from(MAP_GET_MFA_INDEX) + 1)
        })
        .map_err(fail)?;
        code.b(bif_error).map_err(fail)?;

        // Port of instr_guard_bifs.cpp (emit_handle_map_size_error): the argument is in XREG0.
        code.bind(map_size_error).map_err(fail)?;
        code.emit(|e| {
            e.mov_const(TMP1, EXC_BADMAP)?;
            e.stp(TMP1, XREG0, C_P, PROCESS_FREASON as i16)?;
            e.mov_const(TMP2, u64::from(MAP_SIZE_MFA_INDEX) + 1)
        })
        .map_err(fail)?;

        // Shared tail of the three fragments, the global counterpart of the module's
        // `error_label`: names the BIF, records the raising address (`x30` is the return
        // address of the calling `bl`) and leaves native code for the scheduler's `handle_error`.
        code.bind(bif_error).map_err(fail)?;
        code.emit(|e| {
            e.str_uoff(TMP2, SCHEDULER_REGS, BADARG_MFA_SLOT)?;
            e.sub_imm(TMP1, Gpr::x(30), 4, false)?;
            e.str_uoff(TMP1, SCHEDULER_REGS, NATIVE_ERROR_PC_SLOT)?;
            e.mov_reg(ARG1, Gpr::xzr())?;
            e.ldr_uoff(Gpr::x(30), SCHEDULER_REGS, SCHEDULER_RETURN_SLOT)?;
            e.br(Gpr::x(30))
        })
        .map_err(fail)?;

        let (words, labels) = code.finish_with_labels().map_err(fail)?;
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let mut memory = CodeMemory::new(bytes.len().max(4))?;
        let offset = memory.alloc(bytes.len().max(4))?;
        memory.write_bytes(offset, &bytes)?;
        Ok(Self {
            memory,
            raise_offset: labels[&raise],
            raise_exception_offset: labels[&raise_exception],
            map_get_badmap_offset: labels[&map_get_badmap],
            map_get_badkey_offset: labels[&map_get_badkey],
            map_size_error_offset: labels[&map_size_error],
        })
    }

    /// Entry of `raise_shared`: value in X0, saved stacktrace in X1; the caller's `x30` is
    /// the return address of the raising instruction.
    pub fn raise_shared(&self) -> usize {
        self.memory.ptr_at(self.raise_offset) as usize
    }

    /// Entry of `raise_exception`: freason in X0, value in X1, trace in X2; the caller's
    /// `x30` is the return address of the raising instruction.
    pub fn raise_exception(&self) -> usize {
        self.memory.ptr_at(self.raise_exception_offset) as usize
    }

    /// Entry of `handle_map_get_badmap`: map in X0 (ARG1), key in X1 (ARG2); raises
    /// `{badmap, Map}` from `erlang:map_get/2`. Never returns.
    pub fn map_get_badmap(&self) -> usize {
        self.memory.ptr_at(self.map_get_badmap_offset) as usize
    }

    /// Entry of `handle_map_get_badkey`: map in X0 (ARG1), key in X1 (ARG2); raises
    /// `{badkey, Key}` from `erlang:map_get/2`. Never returns.
    pub fn map_get_badkey(&self) -> usize {
        self.memory.ptr_at(self.map_get_badkey_offset) as usize
    }

    /// Entry of `handle_map_size_error`: the argument is in XREG0; raises `{badmap, Term}`
    /// from `erlang:map_size/1`. Never returns.
    pub fn map_size_error(&self) -> usize {
        self.memory.ptr_at(self.map_size_error_offset) as usize
    }
}
