//! Process-wide exception fragments shared by every compiled module.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::{Cond, Gpr},
    exec::{CodeMemory, ExecError},
};

use crate::{
    Update, emit_enter_runtime, emit_leave_runtime,
    guard::{EXC_BADKEY, EXC_BADMAP, LENGTH_MFA_INDEX, MAP_GET_MFA_INDEX, MAP_SIZE_MFA_INDEX},
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

/// Addresses of the BIF-call global fragments a module calls (0: not installed).
#[derive(Clone, Copy, Debug, Default)]
pub struct BifFragments {
    /// `i_length_body_shared`.
    pub i_length_body: usize,
    /// `i_length_guard_shared`.
    pub i_length_guard: usize,
    /// `i_bif_body_shared`.
    pub i_bif_body: usize,
    /// `i_bif_guard_shared`.
    pub i_bif_guard: usize,
    /// Arithmetic fragments (instr_arith.cpp).
    pub arith: ArithFragments,
}

/// Addresses of the arithmetic global fragments of instr_arith.cpp (0: not installed).
#[derive(Clone, Copy, Debug, Default)]
pub struct ArithFragments {
    /// `plus_body_shared`.
    pub plus_body: usize,
    /// `minus_body_shared`.
    pub minus_body: usize,
    /// `unary_minus_body_shared`.
    pub unary_minus_body: usize,
    /// `mul_body_shared`.
    pub mul_body: usize,
    /// `mul_guard_shared`.
    pub mul_guard: usize,
    /// `mul_add_body_shared`.
    pub mul_add_body: usize,
    /// `mul_add_guard_shared`.
    pub mul_add_guard: usize,
    /// `int128_to_big_shared`.
    pub int128_to_big: usize,
    /// `int_div_rem_body_shared`.
    pub int_div_rem_body: usize,
    /// `int_div_rem_guard_shared`.
    pub int_div_rem_guard: usize,
    /// `i_band_body_shared`.
    pub band_body: usize,
    /// `i_bor_body_shared`.
    pub bor_body: usize,
    /// `i_bxor_body_shared`.
    pub bxor_body: usize,
    /// `i_bsl_body_shared`.
    pub bsl_body: usize,
    /// `i_bsr_body_shared`.
    pub bsr_body: usize,
    /// `i_bnot_body_shared`.
    pub bnot_body: usize,
    /// `i_bnot_guard_shared`.
    pub bnot_guard: usize,
}

/// Shared `raise/2`, exception, and function-info fragments emitted by the ARM global assembler.
pub struct RaiseFragments {
    memory: CodeMemory,
    raise_offset: usize,
    raise_exception_offset: usize,
    raise_exception_shared_offset: usize,
    func_info_shared_offset: usize,
    map_get_badmap_offset: usize,
    map_get_badkey_offset: usize,
    map_size_error_offset: usize,
    i_length_body_offset: usize,
    i_length_guard_offset: usize,
    i_bif_body_offset: usize,
    i_bif_guard_offset: usize,
    arith_offsets: [usize; 17],
}

impl RaiseFragments {
    /// Emits shared ARM fragments once for the VM. `resolver` is `handle_error`,
    /// `sanitize_freason` writes the primary exception code from a saved stacktrace and
    /// `context_switch` is the `context_switch_simplified` entry a trapping `length/1` yields
    /// through.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3020-3044 (emit_raise_shared) and
    // beam_asm_global.cpp:300-329 (emit_raise_exception, emit_raise_exception_shared), OTP-29.1.1.
    pub fn new(
        resolver: usize,
        sanitize_freason: usize,
        context_switch: usize,
    ) -> Result<Self, ExecError> {
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

        let i_length_body = code.new_label();
        let i_length_guard = code.new_label();
        code.bind(i_length_body).map_err(fail)?;
        emit_i_length_body_shared(&mut code, context_switch, raise_exception).map_err(fail)?;
        code.bind(i_length_guard).map_err(fail)?;
        emit_i_length_guard_shared(&mut code, context_switch).map_err(fail)?;
        let i_bif_body = code.new_label();
        let i_bif_guard = code.new_label();
        code.bind(i_bif_guard).map_err(fail)?;
        emit_i_bif_guard_shared(&mut code).map_err(fail)?;
        code.bind(i_bif_body).map_err(fail)?;
        emit_i_bif_body_shared(&mut code, raise_exception).map_err(fail)?;
        let arith_labels = emit_arith_fragments(&mut code, raise_exception).map_err(fail)?;

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
            raise_exception_shared_offset: labels[&raise_exception_shared],
            func_info_shared_offset: labels[&func_info_shared],
            map_get_badmap_offset: labels[&map_get_badmap],
            map_get_badkey_offset: labels[&map_get_badkey],
            map_size_error_offset: labels[&map_size_error],
            i_length_body_offset: labels[&i_length_body],
            i_length_guard_offset: labels[&i_length_guard],
            i_bif_body_offset: labels[&i_bif_body],
            i_bif_guard_offset: labels[&i_bif_guard],
            arith_offsets: arith_labels.map(|label| labels[&label]),
        })
    }

    /// Entry of `raise_shared`: value in X0, saved stacktrace in X1; the caller's `x30` is
    /// the return address of the raising instruction.
    pub fn raise_shared(&self) -> usize {
        self.memory.ptr_at(self.raise_offset) as usize
    }

    /// Entry of `raise_exception`: `x30` is the return address of the raising call, the BIF
    /// MFA (or zero) is in ARG4 and the exception is in `c_p->freason`/`fvalue`. Never returns.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:295-298 (emit_raise_exception),
    // OTP-29.1.1.
    pub fn raise_exception(&self) -> usize {
        self.memory.ptr_at(self.raise_exception_offset) as usize
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

    /// Entry of `i_length_body_shared`: live X count in ARG2, entry address in ARG3, the trap
    /// state (list, length so far, original argument) in the X registers from ARG2. The length
    /// is returned in ARG1; an error raises `badarg` from `erlang:length/1`.
    pub fn i_length_body_shared(&self) -> usize {
        self.memory.ptr_at(self.i_length_body_offset) as usize
    }

    /// Entry of `i_length_guard_shared`: as `i_length_body_shared` without the original
    /// argument; an error returns THE_NON_VALUE in ARG1.
    pub fn i_length_guard_shared(&self) -> usize {
        self.memory.ptr_at(self.i_length_guard_offset) as usize
    }

    /// The BIF-call fragments a module installs with `set_bif_fragments`.
    pub fn bif_fragments(&self) -> BifFragments {
        BifFragments {
            i_length_body: self.i_length_body_shared(),
            i_length_guard: self.i_length_guard_shared(),
            i_bif_body: self.i_bif_body_shared(),
            i_bif_guard: self.i_bif_guard_shared(),
            arith: self.arith_fragments(),
        }
    }

    /// The instr_arith.cpp global fragments.
    pub fn arith_fragments(&self) -> ArithFragments {
        let at = |index: usize| self.memory.ptr_at(self.arith_offsets[index]) as usize;
        ArithFragments {
            plus_body: at(0),
            minus_body: at(1),
            unary_minus_body: at(2),
            mul_body: at(3),
            mul_guard: at(4),
            mul_add_body: at(5),
            mul_add_guard: at(6),
            int128_to_big: at(7),
            int_div_rem_body: at(8),
            int_div_rem_guard: at(9),
            band_body: at(10),
            bor_body: at(11),
            bxor_body: at(12),
            bsl_body: at(13),
            bsr_body: at(14),
            bnot_body: at(15),
            bnot_guard: at(16),
        }
    }

    /// Entry of `i_bif_body_shared`: the arguments in X0..X2 of the register array, the BIF
    /// function in ARG4. The result is returned in ARG1; an error raises with the BIF's MFA
    /// (`ubif2mfa`).
    pub fn i_bif_body_shared(&self) -> usize {
        self.memory.ptr_at(self.i_bif_body_offset) as usize
    }

    /// Entry of `i_bif_guard_shared`: as `i_bif_body_shared`, but an error returns
    /// THE_NON_VALUE in ARG1.
    pub fn i_bif_guard_shared(&self) -> usize {
        self.memory.ptr_at(self.i_bif_guard_offset) as usize
    }
}

const ARG4: Gpr = Gpr::x(3);
// erts calls `i_bif*` with only `Update::eReductions` (instr_bif.cpp:47-64) because its guard
// BIFs never allocate on the process heap. This port's BIFs may build terms on the heap, so the
// call also publishes and reloads HTOP and E.
const I_BIF_UPDATE: Update = Update::HEAP_ALLOC.union(Update::REDUCTIONS);

/// ARG2 = argument vector, ARG4 (!) = BIF function pointer; the result is returned in ARG1
/// (THE_NON_VALUE if the BIF call failed).
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:44-63 (emit_i_bif_guard_shared), OTP-29.1.1.
fn emit_i_bif_guard_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, I_BIF_UPDATE)?;
    code.emit(|e| {
        e.mov_reg(ARG1, C_P)?;
        crate::arm::beam_asm::load_x_reg_array(e, ARG2)?;
        // ARG3 is never used by guard BIFs.
        e.mov_reg(ARG3, Gpr::xzr())?;
        e.blr(ARG4)
    })?;
    emit_leave_runtime(code, 6, I_BIF_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

/// ARG2 = argument vector, ARG4 (!) = BIF function pointer; the result is returned in ARG1.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:65-101 (emit_i_bif_body_shared), OTP-29.1.1.
fn emit_i_bif_body_shared(
    code: &mut CodeBuffer,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let error = code.new_label();
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, I_BIF_UPDATE)?;
    // Save the current BIF for the error path.
    code.emit(|e| {
        e.mov_reg(ARG1, C_P)?;
        crate::arm::beam_asm::load_x_reg_array(e, ARG2)?;
        e.str_uoff(ARG4, SCHEDULER_REGS, TMP_MEM1)?;
        // ARG3 is never used by guard BIFs.
        e.mov_reg(ARG3, Gpr::xzr())?;
        e.blr(ARG4)
    })?;
    code.cbz(ARG1, error)?;
    emit_leave_runtime(code, 6, I_BIF_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(error)?;
    // Find the correct MFA from the BIF's function address.
    code.emit(|e| {
        e.ldr_uoff(ARG1, SCHEDULER_REGS, TMP_MEM1)?;
        e.mov_const(SUPER_TMP, crate::rt::ubif2mfa as *const () as u64)?;
        e.blr(SUPER_TMP)
    })?;
    // The argument registers must be reloaded on error, as the machine registers may contain
    // garbage, which `raise_exception` would swap into the register array.
    emit_leave_runtime(code, 3, I_BIF_UPDATE.union(Update::X_REGS))?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.mov_reg(ARG4, ARG1))?;
    code.b(raise_exception)
}

/// `emit_enter_runtime_frame`.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp (emit_enter_runtime_frame), OTP-29.1.1.
fn enter_runtime_frame(code: &mut CodeBuffer) -> Result<(), BufferError> {
    code.emit(|e| {
        e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        e.mov_reg(Gpr::x(29), Gpr::sp())
    })
}

/// `emit_leave_runtime_frame`.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp (emit_leave_runtime_frame), OTP-29.1.1.
fn leave_runtime_frame(code: &mut CodeBuffer) -> Result<(), BufferError> {
    code.emit(|e| {
        e.mov_reg(Gpr::sp(), Gpr::x(29))?;
        e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)
    })
}

const LENGTH_UPDATE: Update = Update::REDUCTIONS.union(Update::X_REGS);
const TMP_MEM1: u32 = crate::arm::beam_asm::tmp_mem_ref(0);
const TMP_MEM2: u32 = crate::arm::beam_asm::tmp_mem_ref(1);
const PROCESS_ARITY: u16 = 80;

/// ARG2 = live registers, ARG3 = entry address; the result is returned in ARG1. Binds no
/// label of its own except `fail`'s callers: the error path is the caller's `fail`.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:230-277 (emit_i_length_common), OTP-29.1.1.
fn emit_i_length_common(
    code: &mut CodeBuffer,
    fail: arinsal_a64::buf::Label,
    state_size: u16,
    context_switch: usize,
) -> Result<(), BufferError> {
    let trap_or_error = code.new_label();
    // Save arguments for error/trapping path.
    code.emit(|e| {
        e.str_uoff(ARG2, SCHEDULER_REGS, TMP_MEM1)?;
        e.str_uoff(ARG3, SCHEDULER_REGS, TMP_MEM2)
    })?;
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, LENGTH_UPDATE)?;
    code.emit(|e| {
        e.mov_reg(ARG1, C_P)?;
        crate::arm::beam_asm::load_x_reg_array(e, TMP1)?;
        e.add_reg(ARG2, TMP1, ARG2, arinsal_a64::enc::Shift::Lsl, 3)?;
        e.mov_const(
            SUPER_TMP,
            crate::rt::erts_trapping_length_1 as *const () as u64,
        )?;
        e.blr(SUPER_TMP)
    })?;
    code.cbz(ARG1, trap_or_error)?;
    emit_leave_runtime(code, 6, LENGTH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(trap_or_error)?;
    code.emit(|e| {
        e.ldr_uoff(ARG2, SCHEDULER_REGS, TMP_MEM1)?;
        e.ldr_uoff(ARG3, SCHEDULER_REGS, TMP_MEM2)?;
        e.ldr_uoff(TMP1, C_P, PROCESS_FREASON)?;
        e.cmp_imm(TMP1, arinsal_term::exc::TRAP as u16, false)
    })?;
    code.b_cond(Cond::Ne, fail)?;
    emit_leave_runtime(code, 6, LENGTH_UPDATE)?;
    leave_runtime_frame(code)?;
    // The trap state is stored in the registers above the current live ones, so the state
    // size (in words) is added to keep it alive. The entry address (ARG3) resumes here.
    code.emit(|e| {
        e.add_imm(ARG2, ARG2, state_size, false)?;
        e.str_uoff(Gpr::xzr(), C_P, PROCESS_CURRENT)?;
        e.strb_uoff(Gpr::w(1), C_P, PROCESS_ARITY)?;
        e.mov_const(SUPER_TMP, context_switch as u64)?;
        e.br(SUPER_TMP)
    })
}

/// ARG2 = live registers, ARG3 = entry address; the result is returned in ARG1.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:279-305 (emit_i_length_body_shared),
// OTP-29.1.1.
fn emit_i_length_body_shared(
    code: &mut CodeBuffer,
    context_switch: usize,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let error = code.new_label();
    // `state_size = 3` to include the original argument.
    emit_i_length_common(code, error, 3, context_switch)?;
    code.bind(error)?;
    let length_mfa =
        crate::bif::guard_bif_mfa(usize::from(LENGTH_MFA_INDEX)).expect("length MFA descriptor");
    // Move the original argument to x0. It's stored in the third word of the trap state.
    code.emit(|e| {
        crate::arm::beam_asm::load_x_reg_array(e, TMP1)?;
        e.add_reg(ARG2, TMP1, ARG2, arinsal_a64::enc::Shift::Lsl, 3)?;
        e.ldr_uoff(TMP1, ARG2, 16)
    })?;
    emit_leave_runtime(code, 6, LENGTH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| {
        e.mov_reg(XREG0, TMP1)?;
        e.mov_const(Gpr::x(3), length_mfa as u64)
    })?;
    code.b(raise_exception)
}

/// ARG2 = live registers, ARG3 = entry address; the result is returned in ARG1, an error is
/// THE_NON_VALUE.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:307-322 (emit_i_length_guard_shared),
// OTP-29.1.1.
fn emit_i_length_guard_shared(
    code: &mut CodeBuffer,
    context_switch: usize,
) -> Result<(), BufferError> {
    let error = code.new_label();
    emit_i_length_common(code, error, 2, context_switch)?;
    code.bind(error)?;
    emit_leave_runtime(code, 6, LENGTH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

// erts calls the arithmetic runtime with `Update::eReductions` alone because erl_arith.c
// allocates with `HeapFragOnlyAlloc`. The arinsal_arith bodies behind erl_arith.rs may still
// build on the process heap, so the calls also publish and reload HTOP and E (as I_BIF_UPDATE).
const ARITH_UPDATE: Update = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
const ARG5: Gpr = Gpr::x(4);
const TMP3: Gpr = Gpr::x(10);
const TMP4: Gpr = Gpr::x(11);
// erts TMP_MEM3q and TMP_MEM4q. TMP_MEM4q/5q (`tmp_mem[3]`/`[4]`) hold the native bridge's exit
// marker and exit fragment here, so the fourth and fifth scratch words are `tmp_mem[7]` and
// `tmp_mem[2]`; see `emit_int_div_rem_generic`.
const TMP_MEM3: u32 = crate::arm::beam_asm::tmp_mem_ref(2);
const TMP_MEM4: u32 = crate::arm::beam_asm::tmp_mem_ref(7);
const MAKE_SMALL_0: u64 = 0xf;
const SMALL_BITS: u8 = 60;

fn mfa_address(mfa: &'static crate::bif::ErtsCodeMfa) -> u64 {
    std::ptr::from_ref(mfa) as u64
}

/// Emits the instr_arith.cpp global fragments in [`ArithFragments`] order.
fn emit_arith_fragments(
    code: &mut CodeBuffer,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<[arinsal_a64::buf::Label; 17], BufferError> {
    use crate::bif::{
        ERLANG_BAND_MFA, ERLANG_BNOT_MFA, ERLANG_BOR_MFA, ERLANG_BSL_MFA, ERLANG_BSR_MFA,
        ERLANG_BXOR_MFA, ERLANG_MINUS_MFA, ERLANG_NEGATE_MFA, ERLANG_PLUS_MFA,
    };
    let labels: [arinsal_a64::buf::Label; 17] = std::array::from_fn(|_| code.new_label());
    let rt = |f: *const ()| f as u64;
    code.bind(labels[0])?;
    emit_binary_body_shared(
        code,
        rt(crate::rt::erts_mixed_plus as *const ()),
        &ERLANG_PLUS_MFA,
        raise_exception,
    )?;
    code.bind(labels[1])?;
    emit_binary_body_shared(
        code,
        rt(crate::rt::erts_mixed_minus as *const ()),
        &ERLANG_MINUS_MFA,
        raise_exception,
    )?;
    code.bind(labels[2])?;
    emit_unary_body_shared(
        code,
        rt(crate::rt::erts_unary_minus as *const ()),
        &ERLANG_NEGATE_MFA,
        false,
        raise_exception,
    )?;
    // Port of instr_arith.cpp:526-540 (emit_mul_body_shared, emit_mul_guard_shared).
    code.bind(labels[3])?;
    code.emit(|e| e.mov_const(ARG4, MAKE_SMALL_0))?;
    code.b(labels[5])?;
    code.bind(labels[4])?;
    code.emit(|e| e.mov_const(ARG4, MAKE_SMALL_0))?;
    code.b(labels[6])?;
    code.bind(labels[5])?;
    emit_mul_add_body_shared(code, raise_exception)?;
    code.bind(labels[6])?;
    emit_mul_add_guard_shared(code)?;
    code.bind(labels[7])?;
    emit_int128_to_big_shared(code)?;
    code.bind(labels[8])?;
    emit_int_div_rem_body_shared(code, raise_exception)?;
    code.bind(labels[9])?;
    emit_int_div_rem_guard_shared(code)?;
    // Port of instr_arith.cpp:1166-1170, 1262-1266, 1337-1341, 1501-1505, 1612-1616
    // (emit_i_band/bor/bxor/bsr/bsl_body_shared via emit_bitwise_fallback_body).
    for (label, (f, mfa)) in labels[10..15].iter().zip([
        (rt(crate::rt::erts_band as *const ()), &ERLANG_BAND_MFA),
        (rt(crate::rt::erts_bor as *const ()), &ERLANG_BOR_MFA),
        (rt(crate::rt::erts_bxor as *const ()), &ERLANG_BXOR_MFA),
        (rt(crate::rt::erts_bsl as *const ()), &ERLANG_BSL_MFA),
        (rt(crate::rt::erts_bsr as *const ()), &ERLANG_BSR_MFA),
    ]) {
        code.bind(*label)?;
        emit_binary_body_shared(code, f, mfa, raise_exception)?;
    }
    code.bind(labels[15])?;
    emit_unary_body_shared(
        code,
        rt(crate::rt::erts_bnot as *const ()),
        &ERLANG_BNOT_MFA,
        true,
        raise_exception,
    )?;
    code.bind(labels[16])?;
    emit_i_bnot_guard_shared(code)?;
    Ok(labels)
}

/// ARG2 = LHS, ARG3 = RHS; the module code has executed `emit_enter_runtime`. The result is
/// returned in ARG1; an error raises from `mfa` with the operands in X0/X1.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:114-143 (emit_plus_body_shared),
// :303-332 (emit_minus_body_shared) and :1137-1164 (emit_bitwise_fallback_body), OTP-29.1.1.
fn emit_binary_body_shared(
    code: &mut CodeBuffer,
    function: u64,
    mfa: &'static crate::bif::ErtsCodeMfa,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let error = code.new_label();
    // Save original arguments for the error path.
    code.emit(|e| e.stp(ARG2, ARG3, SCHEDULER_REGS, TMP_MEM1 as i16))?;
    enter_runtime_frame(code)?;
    code.emit(|e| {
        e.mov_reg(ARG1, C_P)?;
        e.mov_const(SUPER_TMP, function)?;
        e.blr(SUPER_TMP)
    })?;
    leave_runtime_frame(code)?;
    code.cbz(ARG1, error)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;
    code.bind(error)?;
    // emit_enter_runtime() was done in the module code.
    emit_leave_runtime(code, 0, ARITH_UPDATE)?;
    // Place the original arguments in X registers.
    code.emit(|e| {
        e.ldp(XREG0, XREG1, SCHEDULER_REGS, TMP_MEM1 as i16)?;
        e.mov_const(ARG4, mfa_address(mfa))
    })?;
    code.b(raise_exception)
}

/// ARG2 = Src (`unary_minus`), ARG1 = Src with its value bits inverted (`bnot`); the module code
/// has executed `emit_enter_runtime`. The result is returned in ARG1.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:215-244 (emit_unary_minus_body_shared)
// and :1423-1454 (emit_i_bnot_body_shared), OTP-29.1.1.
fn emit_unary_body_shared(
    code: &mut CodeBuffer,
    function: u64,
    mfa: &'static crate::bif::ErtsCodeMfa,
    undo_inversion: bool,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let error = code.new_label();
    enter_runtime_frame(code)?;
    code.emit(|e| {
        if undo_inversion {
            // Undo the speculative inversion in module code.
            e.eor_imm(ARG2, ARG1, !15u64)?;
        }
        // Save the original argument for the error path.
        e.str_uoff(ARG2, SCHEDULER_REGS, TMP_MEM1)?;
        e.mov_reg(ARG1, C_P)?;
        e.mov_const(SUPER_TMP, function)?;
        e.blr(SUPER_TMP)
    })?;
    leave_runtime_frame(code)?;
    code.cbz(ARG1, error)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;
    code.bind(error)?;
    emit_leave_runtime(code, 0, ARITH_UPDATE)?;
    code.emit(|e| {
        e.ldr_uoff(XREG0, SCHEDULER_REGS, TMP_MEM1)?;
        e.mov_const(ARG4, mfa_address(mfa))
    })?;
    code.b(raise_exception)
}

/// ARG1 = Src with its value bits inverted; the module code has executed
/// `emit_enter_runtime`. The result is returned in ARG1 (THE_NON_VALUE on failure).
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1401-1414 (emit_i_bnot_guard_shared),
// OTP-29.1.1.
fn emit_i_bnot_guard_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    enter_runtime_frame(code)?;
    code.emit(|e| {
        e.eor_imm(ARG2, ARG1, !15u64)?;
        e.mov_reg(ARG1, C_P)?;
        e.mov_const(SUPER_TMP, crate::rt::erts_bnot as *const () as u64)?;
        e.blr(SUPER_TMP)
    })?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

/// ARG2 = Src1, ARG3 = Src2, ARG4 = Src4; the result is returned in ARG1.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:437-489 (emit_mul_add_body_shared),
// OTP-29.1.1.
fn emit_mul_add_body_shared(
    code: &mut CodeBuffer,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let mul_only = code.new_label();
    let error = code.new_label();
    let mul_error = code.new_label();
    let do_error = code.new_label();
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, ARITH_UPDATE)?;
    // Save original arguments.
    code.emit(|e| {
        e.stp(ARG2, ARG3, SCHEDULER_REGS, TMP_MEM1 as i16)?;
        e.mov_reg(ARG1, C_P)?;
        e.cmp_imm(ARG4, MAKE_SMALL_0 as u16, false)
    })?;
    code.b_cond(Cond::Eq, mul_only)?;
    code.emit(|e| {
        e.str_uoff(ARG4, SCHEDULER_REGS, TMP_MEM4)?;
        e.add_imm(ARG5, SCHEDULER_REGS, TMP_MEM3 as u16, false)?;
        e.mov_const(SUPER_TMP, crate::rt::erts_mul_add as *const () as u64)?;
        e.blr(SUPER_TMP)
    })?;
    emit_leave_runtime(code, 6, ARITH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.cbz(ARG1, error)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(mul_only)?;
    code.emit(|e| {
        e.mov_const(SUPER_TMP, crate::rt::erts_mixed_times as *const () as u64)?;
        e.blr(SUPER_TMP)
    })?;
    emit_leave_runtime(code, 6, ARITH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.cbz(ARG1, mul_error)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(error)?;
    code.emit(|e| {
        e.ldr_uoff(XREG0, SCHEDULER_REGS, TMP_MEM3)?;
        e.ldr_uoff(XREG1, SCHEDULER_REGS, TMP_MEM4)?;
        e.mov_const(ARG4, mfa_address(&crate::bif::ERLANG_PLUS_MFA))
    })?;
    // The product is a value: the addition failed.
    code.cbnz(XREG0, do_error)?;
    code.bind(mul_error)?;
    code.emit(|e| {
        e.ldp(XREG0, XREG1, SCHEDULER_REGS, TMP_MEM1 as i16)?;
        e.mov_const(ARG4, mfa_address(&crate::bif::ERLANG_TIMES_MFA))
    })?;
    code.bind(do_error)?;
    code.b(raise_exception)
}

/// ARG2 = Src1, ARG3 = Src2, ARG4 = Src4; the result is returned in ARG1 (THE_NON_VALUE if the
/// call failed).
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:497-519 (emit_mul_add_guard_shared),
// OTP-29.1.1.
fn emit_mul_add_guard_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let mul_failed = code.new_label();
    code.emit(|e| e.str_uoff(ARG4, SCHEDULER_REGS, TMP_MEM1))?;
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, ARITH_UPDATE)?;
    code.emit(|e| {
        e.mov_reg(ARG1, C_P)?;
        e.mov_const(SUPER_TMP, crate::rt::erts_mixed_times as *const () as u64)?;
        e.blr(SUPER_TMP)
    })?;
    code.cbz(ARG1, mul_failed)?;
    code.emit(|e| {
        e.ldr_uoff(ARG3, SCHEDULER_REGS, TMP_MEM1)?;
        e.mov_reg(ARG2, ARG1)?;
        e.mov_reg(ARG1, C_P)?;
        e.mov_const(SUPER_TMP, crate::rt::erts_mixed_plus as *const () as u64)?;
        e.blr(SUPER_TMP)
    })?;
    code.bind(mul_failed)?;
    emit_leave_runtime(code, 6, ARITH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

/// ARG1 = low 64 bits, TMP2 = high 64 bits of a tagged 128-bit product; the bignum is returned
/// in ARG1.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:403-428 (emit_int128_to_big_shared),
// OTP-29.1.1.
fn emit_int128_to_big_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let positive = code.new_label();
    code.emit(|e| {
        e.extr(ARG3, TMP2, ARG1, 4)?;
        e.asr_imm(ARG4, TMP2, 4)?;
        e.mov_reg(ARG1, C_P)?;
        e.cmp_imm(ARG4, 0, false)?;
        e.cset(ARG2, Cond::Mi)
    })?;
    code.b_cond(Cond::Pl, positive)?;
    code.emit(|e| {
        e.negs(ARG3, ARG3)?;
        e.ngc(ARG4, ARG4)
    })?;
    code.bind(positive)?;
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, ARITH_UPDATE)?;
    code.emit(|e| {
        e.mov_const(
            SUPER_TMP,
            crate::rt::beam_jit_int128_to_big as *const () as u64,
        )?;
        e.blr(SUPER_TMP)
    })?;
    emit_leave_runtime(code, 6, ARITH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

/// The speculative small division shared by both `int_div_rem` fragments: quotient in TMP3,
/// remainder in TMP4; branches to `zero` for a zero divisor and to `generic` unless both
/// operands are small and the quotient fits; otherwise tags the results into ARG1/ARG2.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:744-772 and :812-839, OTP-29.1.1.
fn emit_int_div_rem_small(
    code: &mut CodeBuffer,
    zero: arinsal_a64::buf::Label,
    generic: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    use arinsal_a64::enc::{Shift, Shifted};
    // Speculatively go ahead with the division.
    code.emit(|e| {
        e.asr_imm(TMP1, ARG2, 4)?;
        e.asr_imm(TMP2, ARG3, 4)?;
        e.sdiv(TMP3, TMP1, TMP2)?;
        e.msub(TMP4, TMP3, TMP2, TMP1)?;
        e.cmp_imm(ARG3, MAKE_SMALL_0 as u16, false)
    })?;
    code.b_cond(Cond::Eq, zero)?;
    // Check whether both operands are small integers.
    code.emit(|e| {
        e.and_reg(
            TMP1,
            ARG2,
            Shifted {
                reg: ARG3,
                shift: Shift::Lsl,
                amount: 0,
            },
        )?;
        e.and_imm(TMP1, TMP1, 15)?;
        e.cmp_imm(TMP1, 15, false)
    })?;
    code.b_cond(Cond::Ne, generic)?;
    // MIN_SMALL divided by -1 will overflow, and we'll need to fall back to the generic handler
    // in that case.
    code.emit(|e| {
        e.asr_imm(TMP1, TMP3, SMALL_BITS - 1)?;
        e.cmp_imm(TMP1, 1, false)
    })?;
    code.b_cond(Cond::Ge, generic)?;
    // The Z flag is now clear (meaning no error).
    code.emit(|e| {
        e.mov_const(TMP1, 15)?;
        e.orr_reg(
            ARG1,
            TMP1,
            Shifted {
                reg: TMP3,
                shift: Shift::Lsl,
                amount: 4,
            },
        )?;
        e.orr_reg(
            ARG2,
            TMP1,
            Shifted {
                reg: TMP4,
                shift: Shift::Lsl,
                amount: 4,
            },
        )
    })
}

/// `erts_int_div_rem(c_p, ARG2, ARG3, &q, &r)`; leaves `tst` of its result in the flags (Z set
/// on error) and the quotient and remainder in ARG1/ARG2. The two result words are TMP_MEM4q
/// and TMP_MEM3q here (erts: TMP_MEM4q/TMP_MEM5q, held by the native bridge); `erts_int_div_rem`
/// writes them only on success, so the body fragment's saved MFA in TMP_MEM3q survives an error.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:777-797 and :841-857, OTP-29.1.1.
fn emit_int_div_rem_generic(code: &mut CodeBuffer) -> Result<(), BufferError> {
    use arinsal_a64::enc::Shift;
    code.emit(|e| {
        e.mov_reg(ARG1, C_P)?;
        e.add_imm(ARG4, SCHEDULER_REGS, TMP_MEM4 as u16, false)?;
        e.add_imm(ARG5, SCHEDULER_REGS, TMP_MEM3 as u16, false)?;
        e.mov_const(SUPER_TMP, crate::rt::erts_int_div_rem as *const () as u64)?;
        e.blr(SUPER_TMP)
    })?;
    emit_leave_runtime(code, 6, ARITH_UPDATE)?;
    leave_runtime_frame(code)?;
    code.emit(|e| {
        // The result is a C `int`: only w0 is defined.
        e.tst_reg(Gpr::w(0), Gpr::w(0), Shift::Lsl, 0)?;
        e.ldr_uoff(ARG1, SCHEDULER_REGS, TMP_MEM4)?;
        e.ldr_uoff(ARG2, SCHEDULER_REGS, TMP_MEM3)
    })
}

/// ARG2 = LHS, ARG3 = RHS. Quotient is returned in ARG1, remainder in ARG2; an error is
/// indicated by the Z flag.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:740-800 (emit_int_div_rem_guard_shared),
// OTP-29.1.1.
fn emit_int_div_rem_guard_shared(code: &mut CodeBuffer) -> Result<(), BufferError> {
    let exit = code.new_label();
    let generic = code.new_label();
    emit_int_div_rem_small(code, exit, generic)?;
    code.bind(exit)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;
    code.bind(generic)?;
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, ARITH_UPDATE)?;
    emit_int_div_rem_generic(code)?;
    code.emit(|e| e.ret(Gpr::x(30)))
}

/// ARG2 = LHS, ARG3 = RHS, ARG4 = error MFA. Quotient is returned in ARG1, remainder in ARG2.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:802-875 (emit_int_div_rem_body_shared),
// OTP-29.1.1.
fn emit_int_div_rem_body_shared(
    code: &mut CodeBuffer,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
    let div_zero = code.new_label();
    let generic_div = code.new_label();
    let generic_error = code.new_label();
    emit_int_div_rem_small(code, div_zero, generic_div)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(generic_div)?;
    enter_runtime_frame(code)?;
    emit_enter_runtime(code, 6, ARITH_UPDATE)?;
    // Save MFA and original arguments for the error path.
    code.emit(|e| {
        e.stp(ARG2, ARG3, SCHEDULER_REGS, TMP_MEM1 as i16)?;
        e.str_uoff(ARG4, SCHEDULER_REGS, TMP_MEM3)
    })?;
    emit_int_div_rem_generic(code)?;
    code.b_cond(Cond::Eq, generic_error)?;
    code.emit(|e| e.ret(Gpr::x(30)))?;

    code.bind(div_zero)?;
    code.emit(|e| {
        e.mov_const(TMP1, arinsal_term::exc::EXC_BADARITH)?;
        e.str_uoff(TMP1, C_P, PROCESS_FREASON)?;
        e.mov_reg(XREG0, ARG2)?;
        e.mov_reg(XREG1, ARG3)
    })?;
    code.b(raise_exception)?;

    code.bind(generic_error)?;
    code.emit(|e| {
        e.ldp(XREG0, XREG1, SCHEDULER_REGS, TMP_MEM1 as i16)?;
        // MFA.
        e.ldr_uoff(ARG4, SCHEDULER_REGS, TMP_MEM3)
    })?;
    code.b(raise_exception)
}
