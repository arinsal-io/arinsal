//! Process-wide BeamAsm dispatch fragments.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::Gpr,
    exec::{CodeMemory, ExecError},
};

use crate::{Update, emit_enter_runtime, emit_leave_runtime, rt::arinsal_enter_native_return};

const RUNTIME_UPDATE: Update = Update::HEAP_ALLOC
    .union(Update::REDUCTIONS)
    .union(Update::X_REGS);
const THE_NON_VALUE: u16 = 0;
const TRAP_REASON: u16 = 1 << 10;

/// Executable fragments shared by every compiled module in one VM process.
pub struct DispatchFragments {
    memory: CodeMemory,
    export_offset: usize,
    light_bif_offset: usize,
    call_fun_unported_offset: usize,
}

/// Sentinel `CallUnported.target_pc` for a fun call that must resume in the interpreter.
pub const CALL_FUN_UNPORTED: usize = usize::MAX - 0xF0;
/// Identity sent through the light-BIF fragment to hand native `send` to the executor.
pub const SEND_DISPATCH_IDENTITY: usize = usize::MAX - 0xF1;
/// Sentinel `CallUnported.target_pc` for a scheduler-owned native `send` operation.
pub const SEND_UNPORTED: usize = usize::MAX - 0xF2;

impl DispatchFragments {
    /// Emits the export and light-BIF runtime fragments once for the VM.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210 and
    // erts/emulator/beam/jit/arm/instr_bif.cpp:378-471, OTP-29.1.1.
    pub fn new(export_helper: usize, light_bif_helper: usize) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let export = code.new_label();
        let light_bif = code.new_label();
        let call_fun_unported = code.new_label();
        code.bind(export)
            .map_err(|_error| ExecError::InvalidSize("dispatch fragment"))?;
        emit_export_fragment(&mut code, export_helper)
            .map_err(|_| ExecError::InvalidSize("export trampoline"))?;
        code.bind(light_bif)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_helper_fragment(&mut code, light_bif_helper)
            .map_err(|_| ExecError::InvalidSize("light BIF fragment"))?;
        code.bind(call_fun_unported)
            .map_err(|_error| ExecError::InvalidSize("dispatch fragment"))?;
        emit_call_fun_unported_fragment(&mut code)
            .map_err(|_| ExecError::InvalidSize("call_fun unported fragment"))?;
        let (words, labels) = code
            .finish_with_labels()
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
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
            export_offset: labels[&export],
            light_bif_offset: labels[&light_bif],
            call_fun_unported_offset: labels[&call_fun_unported],
        })
    }

    /// Shared export-entry trampoline address.
    pub fn export_trampoline(&self) -> usize {
        self.memory.ptr_at(self.export_offset) as usize
    }

    /// Shared light-BIF fragment address.
    pub fn call_light_bif(&self) -> usize {
        self.memory.ptr_at(self.light_bif_offset) as usize
    }

    /// Entry used when a fun has no native trampoline yet.
    pub fn call_fun_unported(&self) -> usize {
        self.memory.ptr_at(self.call_fun_unported_offset) as usize
    }
}

// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210, OTP-29.1.1.
fn emit_export_fragment(code: &mut CodeBuffer, helper: usize) -> Result<(), BufferError> {
    let interpreted = code.new_label();
    code.emit(|encoder| {
        // Interpreted targets have no native prologue to save this continuation.
        encoder.str_pre(Gpr::x(30), Gpr::x(20), -8)?;
        encoder.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -32)?;
        encoder.mov_reg(Gpr::x(29), Gpr::sp())?;
        encoder.str_uoff(Gpr::x(1), Gpr::sp(), 16)?;
        // The caller supplies c_p in x0 and the export identity in x1.
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1.
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))?;
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:539-601, OTP-29.1.1.
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), 1, false))?;
    code.b_cond(arinsal_a64::enc::Cond::Eq, interpreted)?;
    // A BIF returns through the call site after its result was published to X0.
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(25), Gpr::x(19), 0)?;
        encoder.ldr_post(Gpr::x(9), Gpr::x(20), 8)?;
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 32)?;
        encoder.ret(Gpr::x(30))
    })?;
    code.bind(interpreted)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(17), Gpr::sp(), 16)?;
        encoder.add_imm(Gpr::sp(), Gpr::sp(), 32, false)?;
        encoder.mov_const(Gpr::x(0), 2)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(17))?;
        encoder.mov_reg(Gpr::x(2), Gpr::xzr())?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}

// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:527-540, OTP-29.1.1.
fn emit_helper_fragment(code: &mut CodeBuffer, helper: usize) -> Result<(), BufferError> {
    code.emit(|encoder| {
        encoder.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        encoder.mov_reg(Gpr::x(29), Gpr::sp())?;
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1.
    emit_enter_runtime(code, 6, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))?;
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:539-601, OTP-29.1.1.
    emit_leave_runtime(code, 6, RUNTIME_UPDATE)?;
    let normal = code.new_label();
    let trap = code.new_label();
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), THE_NON_VALUE, false))?;
    code.b_cond(arinsal_a64::enc::Cond::Ne, normal)?;
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.cmp_imm(Gpr::x(9), TRAP_REASON, false)
    })?;
    code.b_cond(arinsal_a64::enc::Cond::Ne, normal)?;
    code.bind(trap)?;
    code.emit(|encoder| {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:533-540, OTP-29.1.1.
        // The context switch resumes at c_p->i; its caller continuation stays on E.
        encoder.ldr_uoff(Gpr::x(17), Gpr::sp(), 8)?;
        encoder.str_pre(Gpr::x(17), Gpr::x(20), -8)?;
        // The native bridge restores these two arguments when resume_pc is nonzero.
        encoder.str_uoff(Gpr::x(25), Gpr::x(19), 16_384)?;
        encoder.str_uoff(Gpr::x(26), Gpr::x(19), 16_392)?;
        encoder.ldr_uoff(Gpr::x(1), Gpr::x(21), 72)?;
        encoder.ldr_uoff(Gpr::x(2), Gpr::sp(), 8)?;
        encoder.mov_reg(Gpr::x(9), Gpr::xzr())?;
        encoder.str_uoff(Gpr::x(9), Gpr::x(21), 40)?;
        encoder.mov_const(Gpr::x(0), 2)
    })?;
    emit_restore_and_exit(code)?;
    code.bind(normal)?;
    code.emit(|encoder| {
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
        encoder.ret(Gpr::x(30))
    })?;
    Ok(())
}

// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:context_switch_simplified,
// OTP-29.1.1.
fn emit_restore_and_exit(code: &mut CodeBuffer) -> Result<(), BufferError> {
    code.emit(|encoder| {
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}

/// Leaves native execution so the scheduler can interpret a fun call.
///
/// Expects the fun call continuation in `x30` (set by `i_call_fun` before the branch)
/// and the call arity already stored in `c_p->arity` by the fun resolver.
fn emit_call_fun_unported_fragment(code: &mut CodeBuffer) -> Result<(), BufferError> {
    code.emit(|encoder| {
        // Preserve the native continuation as a BEAM CP for the interpreter return path.
        encoder.str_pre(Gpr::x(30), Gpr::x(20), -8)?;
        encoder.mov_const(Gpr::x(0), 2)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_const(Gpr::x(1), CALL_FUN_UNPORTED as u64)?;
        encoder.mov_reg(Gpr::x(2), Gpr::xzr())?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}
