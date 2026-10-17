//! Process-wide context-switch fragments shared by every compiled module.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::Gpr,
    exec::{CodeMemory, ExecError},
};

use crate::{Update, emit_enter_runtime, rt::arinsal_enter_native_yield};

const C_P: Gpr = Gpr::x(21);
const ARG2: Gpr = Gpr::x(1);
const ARG3: Gpr = Gpr::x(2);
const TMP2: Gpr = Gpr::x(9);
const PROCESS_I: u32 = 72;
const PROCESS_ARITY: u16 = 80;
const PROCESS_CURRENT: u32 = 88;
const CODE_MFA_BYTES: u16 = 24;
const CODE_MFA_ARITY: u32 = 16;

/// Bytes between a function's entry and the instruction after its `i_test_yield`: the
/// breakpoint trampoline (`str`, `b`, `bl`) and the `adr`, `subs`, `b.le` of the test itself.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp (TEST_YIELD_RETURN_OFFSET),
// OTP-29.1.1.
pub(crate) const TEST_YIELD_RETURN_OFFSET: usize = 24;

/// Entry-relative offset of the `i_test_yield` of a function: right after its trampoline.
pub(crate) const FUNC_PROLOGUE_SIZE: usize = 12;

/// Context-switch fragments: `dispatch_return` and `i_test_yield_shared`.
pub struct YieldFragments {
    memory: CodeMemory,
    dispatch_return_offset: usize,
    test_yield_offset: usize,
    context_switch_offset: usize,
}

impl YieldFragments {
    /// Emits the shared yield fragments once for the VM.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_context_switch_simplified),
    // erts/emulator/beam/jit/arm/instr_call.cpp (emit_dispatch_return) and
    // erts/emulator/beam/jit/arm/instr_common.cpp (emit_i_test_yield_shared),
    // OTP-29.1.1.
    pub fn new() -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let fail = |_: BufferError| ExecError::InvalidSize("yield fragment");
        let context_switch = code.new_label();
        let dispatch_return = code.new_label();
        let test_yield = code.new_label();

        code.bind(dispatch_return).map_err(fail)?;
        code.emit(|e| {
            e.str_uoff(Gpr::x(30), C_P, PROCESS_I)?;
            e.mov_const(TMP2, 1)?;
            e.strb_uoff(TMP2, C_P, PROCESS_ARITY)
        })
        .map_err(fail)?;
        code.b(context_switch).map_err(fail)?;

        code.bind(test_yield).map_err(fail)?;
        code.emit(|e| {
            e.sub_imm(ARG2, ARG3, CODE_MFA_BYTES, false)?;
            e.add_imm(ARG3, ARG3, TEST_YIELD_RETURN_OFFSET as u16, false)?;
            e.str_uoff(ARG3, C_P, PROCESS_I)?;
            e.str_uoff(ARG2, C_P, PROCESS_CURRENT)?;
            e.ldr_uoff(Gpr::w(9), ARG2, CODE_MFA_ARITY)?;
            e.strb_uoff(TMP2, C_P, PROCESS_ARITY)
        })
        .map_err(fail)?;

        code.bind(context_switch).map_err(fail)?;
        emit_enter_runtime(
            &mut code,
            6,
            Update::HEAP_ALLOC
                .union(Update::REDUCTIONS)
                .union(Update::X_REGS),
        )
        .map_err(fail)?;
        code.emit(|e| {
            e.mov_const(Gpr::x(30), arinsal_enter_native_yield as *const () as u64)?;
            e.ret(Gpr::x(30))
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
        memory.flush_all()?;
        Ok(Self {
            memory,
            dispatch_return_offset: labels[&dispatch_return],
            test_yield_offset: labels[&test_yield],
            context_switch_offset: labels[&context_switch],
        })
    }

    /// Entry of `context_switch_simplified`: the continuation is in `c_p->i` and the live X
    /// count in `c_p->arity`.
    pub fn context_switch(&self) -> usize {
        self.memory.ptr_at(self.context_switch_offset) as usize
    }

    /// Entry of `dispatch_return`: the caller's `x30` is the return address to resume at.
    pub fn dispatch_return(&self) -> usize {
        self.memory.ptr_at(self.dispatch_return_offset) as usize
    }

    /// Entry of `i_test_yield_shared`: x2 holds the function's entry address.
    pub fn i_test_yield_shared(&self) -> usize {
        self.memory.ptr_at(self.test_yield_offset) as usize
    }
}
