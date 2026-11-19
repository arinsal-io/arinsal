//! Process-wide exception fragments shared by every compiled module.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::{Cond, Gpr},
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
const PROCESS_FTRACE: u32 = 56;
const PROCESS_CURRENT: u32 = 88;
const PROCESS_HTOP_STOP: u32 = 8;
const NATIVE_ERROR_PC_SLOT: u32 = crate::arm::beam_asm::tmp_mem_ref(6);
const SCHEDULER_RETURN_SLOT: u32 = crate::arm::beam_asm::tmp_mem_ref(4);

/// Shared `raise/2`, exception, and function-info fragments emitted by the ARM global assembler.
pub struct RaiseFragments {
    memory: CodeMemory,
    raise_offset: usize,
    raise_exception_shared_offset: usize,
    func_info_shared_offset: usize,
    map_get_badmap_offset: usize,
    map_get_badkey_offset: usize,
    map_size_error_offset: usize,
}

impl RaiseFragments {
    /// Emits shared ARM fragments once for the VM. `resolver` is `handle_error` and
    /// `sanitize_freason` writes the primary exception code from a saved stacktrace.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3020-3044 (emit_raise_shared) and
    // beam_asm_global.cpp:300-329 (emit_raise_exception, emit_raise_exception_shared), OTP-29.1.1.
    pub fn new(resolver: usize, sanitize_freason: usize) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let fail = |_: BufferError| ExecError::InvalidSize("raise fragment");
        let raise = code.new_label();
        let raise_exception = code.new_label();
        let raise_exception_null_exp = code.new_label();
        let raise_exception_shared = code.new_label();
        let func_info_shared = code.new_label();
        let caught = code.new_label();

        code.bind(raise).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(TRACE, ARG2)?;
            e.mov_reg(VALUE, ARG1)?;
            e.str_uoff(VALUE, C_P, PROCESS_FVALUE)?;
            e.str_uoff(TRACE, C_P, PROCESS_FTRACE)
        })
        .map_err(fail)?;
        emit_enter_runtime(&mut code, 0, Update::NONE).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(ARG1, C_P)?;
            e.mov_const(SUPER_TMP, sanitize_freason as u64)?;
            e.blr(SUPER_TMP)
        })
        .map_err(fail)?;
        emit_leave_runtime(&mut code, 0, Update::NONE).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(Gpr::x(3), Gpr::xzr())?;
            e.mov_reg(ARG2, Gpr::x(30))
        })
        .map_err(fail)?;
        code.b(raise_exception_shared).map_err(fail)?;

        // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:484-497
        // (emit_i_func_info_shared), OTP-29.1.1: the link register points four bytes into
        // ErtsCodeInfo, so derive and publish its MFA before raising function_clause.
        code.bind(func_info_shared).map_err(fail)?;
        code.emit(|e| {
            e.add_imm(
                ARG1,
                Gpr::x(30),
                (std::mem::offset_of!(crate::common::beam_asm_h::ErtsCodeInfo, mfa) - 4) as u16,
                false,
            )?;
            e.mov_const(ARG2, arinsal_term::exc::EXC_FUNCTION_CLAUSE)?;
            e.str_uoff(ARG2, C_P, PROCESS_FREASON)?;
            e.str_uoff(ARG1, C_P, PROCESS_CURRENT)?;
            e.mov_reg(ARG2, Gpr::xzr())?;
            e.mov_reg(Gpr::x(3), Gpr::xzr())
        })
        .map_err(fail)?;
        code.b(raise_exception_shared).map_err(fail)?;

        // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:295-298
        // (emit_raise_exception), OTP-29.1.1. Map-error fragments pass their MFA in ARG4.
        code.bind(raise_exception).map_err(fail)?;
        code.emit(|e| e.mov_reg(ARG2, Gpr::x(30))).map_err(fail)?;
        code.b(raise_exception_shared).map_err(fail)?;

        // Port of beam_asm_global.cpp:288-292 (emit_raise_exception_null_exp), OTP-29.1.1.
        code.bind(raise_exception_null_exp).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(Gpr::x(3), Gpr::xzr())?;
            e.mov_reg(ARG2, Gpr::x(30))
        })
        .map_err(fail)?;
        code.b(raise_exception_shared).map_err(fail)?;

        code.bind(raise_exception_shared).map_err(fail)?;
        // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:295-330
        // (emit_raise_exception_shared), OTP-29.1.1.
        code.emit(|e| {
            // The fake CP makes a catch in the raising frame visible to handle_error.
            e.str_pre(ARG2, E, -8)?;
            e.str_uoff(ARG2, SCHEDULER_REGS, NATIVE_ERROR_PC_SLOT)
        })
        .map_err(fail)?;
        let update = Update::HEAP_ALLOC.union(Update::X_REGS);
        emit_enter_runtime(&mut code, 6, update).map_err(fail)?;
        let crash = code.new_label();
        code.emit(|e| e.tst_imm(ARG2, 3)).map_err(fail)?;
        code.b_cond(Cond::Ne, crash).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(ARG1, C_P)?;
            crate::arm::beam_asm::load_x_reg_array(e, ARG3)?;
            e.mov_const(SUPER_TMP, resolver as u64)?;
            e.blr(SUPER_TMP)
        })
        .map_err(fail)?;
        emit_leave_runtime(&mut code, 6, update).map_err(fail)?;
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
        code.bind(crash).map_err(fail)?;
        code.emit(|e| {
            e.udf(0xbad);
            Ok(())
        })
        .map_err(fail)?;

        let map_get_badmap = code.new_label();
        let map_get_badkey = code.new_label();
        let map_size_error = code.new_label();
        let bif_error = code.new_label();
        let map_get_mfa = crate::bif::guard_bif_mfa(usize::from(MAP_GET_MFA_INDEX))
            .expect("map_get MFA descriptor");
        let map_size_mfa = crate::bif::guard_bif_mfa(usize::from(MAP_SIZE_MFA_INDEX))
            .expect("map_size MFA descriptor");

        // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_handle_map_get_badmap):
        // map in ARG1, key in ARG2; fvalue is the map.
        code.bind(map_get_badmap).map_err(fail)?;
        code.emit(|e| {
            e.mov_const(TMP1, EXC_BADMAP)?;
            e.stp(TMP1, ARG1, C_P, PROCESS_FREASON as i16)?;
            e.mov_reg(XREG0, ARG2)?;
            e.mov_reg(XREG1, ARG1)?;
            e.mov_const(TMP2, map_get_mfa as u64)
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
            e.mov_const(TMP2, map_get_mfa as u64)
        })
        .map_err(fail)?;
        code.b(bif_error).map_err(fail)?;

        // Port of instr_guard_bifs.cpp (emit_handle_map_size_error): the argument is in XREG0.
        code.bind(map_size_error).map_err(fail)?;
        code.emit(|e| {
            e.mov_const(TMP1, EXC_BADMAP)?;
            e.stp(TMP1, XREG0, C_P, PROCESS_FREASON as i16)?;
            e.mov_const(TMP2, map_size_mfa as u64)
        })
        .map_err(fail)?;

        // Port of instr_guard_bifs.cpp:832-858: the failure words are already in Process, while
        // ARG4 carries the BIF MFA through `emit_raise_exception`.
        code.bind(bif_error).map_err(fail)?;
        code.emit(|e| e.mov_reg(Gpr::x(3), TMP2)).map_err(fail)?;
        code.b(raise_exception).map_err(fail)?;

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
            raise_exception_shared_offset: labels[&raise_exception_shared],
            func_info_shared_offset: labels[&func_info_shared],
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

    /// Entry of `raise_exception_shared`: the PC is in ARG2, the BIF MFA is in ARG4, and
    /// exception terms are stored in the process header.
    pub fn raise_exception_shared(&self) -> usize {
        self.memory.ptr_at(self.raise_exception_shared_offset) as usize
    }

    /// Entry of `emit_i_func_info_shared`: x30 points four bytes into `ErtsCodeInfo`.
    pub fn func_info_shared(&self) -> usize {
        self.memory.ptr_at(self.func_info_shared_offset) as usize
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
