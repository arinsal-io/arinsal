//! Process-wide BeamAsm dispatch fragments.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::Gpr,
    exec::{CodeMemory, ExecError},
};

use crate::{Update, emit_enter_runtime, emit_leave_runtime, rt::arinsal_enter_native_return};

const RUNTIME_UPDATE: Update = Update::HEAP_ALLOC
    .union(Update::STACK)
    .union(Update::REDUCTIONS)
    .union(Update::X_REGS);
const THE_NON_VALUE: u16 = 0;
pub(crate) const TRAP_REASON: u16 = 1 << 10;

/// Executable fragments shared by every compiled module in one VM process.
pub struct DispatchFragments {
    memory: CodeMemory,
    export_offset: usize,
    light_bif_offset: usize,
    send_offset: usize,
    call_fun_unported_offset: usize,
    apply_fixed_offset: usize,
    apply2_offset: usize,
    apply3_offset: usize,
}

/// Sentinel `CallUnported.target_pc` for a fun call that must resume in the interpreter.
pub const CALL_FUN_UNPORTED: usize = usize::MAX - 0xF0;
/// Sentinel `CallUnported.target_pc` for `apply Arity`; the arity is in `c_p->arity`.
pub const APPLY_FIXED_UNPORTED: usize = usize::MAX - 0xF2;
/// Sentinel `CallUnported.target_pc` for `apply/2` (fun and argument list in X0/X1).
pub const APPLY2_UNPORTED: usize = usize::MAX - 0xF3;
/// Sentinel `CallUnported.target_pc` for `apply/3` (module, function, arguments in X0..X2).
pub const APPLY3_UNPORTED: usize = usize::MAX - 0xF4;
/// Identity sent through the light-BIF fragment to hand native `send` to the executor.
pub const SEND_DISPATCH_IDENTITY: usize = usize::MAX - 0xF1;
/// Identity sent through the light-BIF fragment to hand a native entry breakpoint to the
/// executor, which owns the VM and run context that tracer modules and meta tracing need.
pub const BREAKPOINT_DISPATCH_IDENTITY: usize = usize::MAX - 0xF5;
/// Top byte of the identity a native line-breakpoint site sends through the light-BIF
/// fragment; bits 32..48 hold the live X register count and bits 0..32 the source line.
const LINE_BREAKPOINT_TAG: usize = 0xF8 << 56;

/// Identity of an enabled `i_line_breakpoint_trampoline` hit at `line` with `live` X registers.
// Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:257-350, OTP-29.1.1: erts passes
// the live count in a register and recovers the line from the pc; here both ride in the
// trap identity so the executor needs no per-site table.
pub const fn line_breakpoint_identity(line: u32, live: u16) -> usize {
    LINE_BREAKPOINT_TAG | (live as usize) << 32 | line as usize
}

/// Decodes [`line_breakpoint_identity`] into `(line, live)`.
pub const fn decode_line_breakpoint_identity(identity: usize) -> Option<(u32, u16)> {
    if identity >> 56 != 0xF8 {
        return None;
    }
    Some((identity as u32, (identity >> 32) as u16))
}
/// `target_pc` of the exit a traced native return takes so the executor can emit its
/// `return_to` event; `resume_pc` is the caller continuation.
pub const RETURN_TO_DISPATCH_IDENTITY: usize = usize::MAX - 0xF6;
/// `target_pc` of the exit a dirty NIF called on a normal scheduler takes, so the executor
/// can move the process to a dirty scheduler; `resume_pc` is the NIF body's return point.
pub const DIRTY_NIF_DISPATCH_IDENTITY: usize = usize::MAX - 0xF7;

impl DispatchFragments {
    /// Emits the export and light-BIF runtime fragments once for the VM.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210 and
    // erts/emulator/beam/jit/arm/instr_bif.cpp:378-471, OTP-29.1.1.
    pub fn new(
        export_helper: usize,
        light_bif_helper: usize,
        exception_resolver: usize,
    ) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let export = code.new_label();
        let light_bif = code.new_label();
        let send = code.new_label();
        let call_fun_unported = code.new_label();
        let raise_exception = code.new_label();
        let apply_fixed = code.new_label();
        let apply2 = code.new_label();
        let apply3 = code.new_label();
        code.bind(export)
            .map_err(|_error| ExecError::InvalidSize("dispatch fragment"))?;
        emit_export_fragment(&mut code, export_helper, raise_exception)
            .map_err(|_| ExecError::InvalidSize("export trampoline"))?;
        code.bind(light_bif)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_helper_fragment(&mut code, light_bif_helper, 6)
            .map_err(|_| ExecError::InvalidSize("light BIF fragment"))?;
        code.bind(send)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_helper_fragment(&mut code, light_bif_helper, 2)
            .map_err(|_| ExecError::InvalidSize("send fragment"))?;
        code.bind(call_fun_unported)
            .map_err(|_error| ExecError::InvalidSize("dispatch fragment"))?;
        emit_unported_fragment(&mut code, CALL_FUN_UNPORTED)
            .map_err(|_| ExecError::InvalidSize("call_fun unported fragment"))?;
        for (label, sentinel) in [
            (apply_fixed, APPLY_FIXED_UNPORTED),
            (apply2, APPLY2_UNPORTED),
            (apply3, APPLY3_UNPORTED),
        ] {
            code.bind(label)
                .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
            emit_unported_fragment(&mut code, sentinel)
                .map_err(|_| ExecError::InvalidSize("apply unported fragment"))?;
        }
        code.bind(raise_exception)
            .map_err(|_| ExecError::InvalidSize("dispatch fragment"))?;
        emit_raise_exception_fragment(&mut code, exception_resolver)
            .map_err(|_| ExecError::InvalidSize("raise exception fragment"))?;
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
            send_offset: labels[&send],
            call_fun_unported_offset: labels[&call_fun_unported],
            apply_fixed_offset: labels[&apply_fixed],
            apply2_offset: labels[&apply2],
            apply3_offset: labels[&apply3],
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

    /// Shared `send/2` fragment with only its two live X registers saved.
    pub fn send(&self) -> usize {
        self.memory.ptr_at(self.send_offset) as usize
    }

    /// Entry that hands `apply Arity` to the interpreter (arity in `c_p->arity`).
    pub fn apply_fixed_unported(&self) -> usize {
        self.memory.ptr_at(self.apply_fixed_offset) as usize
    }

    /// Entry that hands `apply/2` to the interpreter.
    pub fn apply2_unported(&self) -> usize {
        self.memory.ptr_at(self.apply2_offset) as usize
    }

    /// Entry that hands `apply/3` to the interpreter.
    pub fn apply3_unported(&self) -> usize {
        self.memory.ptr_at(self.apply3_offset) as usize
    }

    /// Entry used when a fun has no native trampoline yet.
    pub fn call_fun_unported(&self) -> usize {
        self.memory.ptr_at(self.call_fun_unported_offset) as usize
    }
}

// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210, OTP-29.1.1.
fn emit_export_fragment(
    code: &mut CodeBuffer,
    helper: usize,
    raise_exception: arinsal_a64::buf::Label,
) -> Result<(), BufferError> {
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
    code.emit(|encoder| encoder.cmp_imm(Gpr::x(0), 0, false))?;
    code.b_cond(arinsal_a64::enc::Cond::Eq, raise_exception)?;
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
        // The native call site is the CP pushed on entry; it names the calling module.
        encoder.ldr_uoff(Gpr::x(2), Gpr::x(20), 0)?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}

// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:220-286, OTP-29.1.1.
fn emit_raise_exception_fragment(
    code: &mut CodeBuffer,
    resolver: usize,
) -> Result<(), BufferError> {
    let exit = code.new_label();
    // The export trampoline's BEAM continuation remains on E as the current
    // exception PC; only its host ABI frame is removed here.
    code.emit(|encoder| {
        encoder.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 32)?;
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
        encoder.mov_reg(Gpr::x(2), Gpr::x(20))?;
        encoder.mov_const(Gpr::x(17), resolver as u64)?;
        encoder.blr(Gpr::x(17))
    })?;
    code.cbz(Gpr::x(0), exit)?;
    // next_catch updates c_p->stop to the catch frame's resumed E. The
    // resolver is a runtime call, so native registers must reload that cursor.
    // Port of erts/emulator/beam/beam_common.c:545-561, OTP-29.1.1.
    code.emit(|encoder| {
        encoder.ldr_uoff(Gpr::x(20), Gpr::x(21), 8)?;
        encoder.ldr_uoff(Gpr::x(23), Gpr::x(21), 0)?;
        encoder.br(Gpr::x(0))
    })?;
    code.bind(exit)?;
    // The host frame was already popped above; only the exit bridge remains.
    code.emit(|encoder| {
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })
}

// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:527-540, OTP-29.1.1.
fn emit_helper_fragment(
    code: &mut CodeBuffer,
    helper: usize,
    live: usize,
) -> Result<(), BufferError> {
    code.emit(|encoder| {
        encoder.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
        encoder.mov_reg(Gpr::x(29), Gpr::sp())?;
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1.
    emit_enter_runtime(code, live, RUNTIME_UPDATE)?;
    code.emit(|encoder| {
        encoder.mov_const(Gpr::x(17), helper as u64)?;
        encoder.blr(Gpr::x(17))?;
        Ok(())
    })?;
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:539-601, OTP-29.1.1.
    emit_leave_runtime(code, live, RUNTIME_UPDATE)?;
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

/// Leaves native execution so the scheduler can interpret a call named by `sentinel`.
///
/// Expects the call continuation in `x30` (set by the caller before the branch); any
/// argument the scheduler needs (the arity, the fun) is already published in `c_p`.
fn emit_unported_fragment(code: &mut CodeBuffer, sentinel: usize) -> Result<(), BufferError> {
    code.emit(|encoder| {
        // Preserve the native continuation as a BEAM CP for the interpreter return path.
        encoder.str_pre(Gpr::x(30), Gpr::x(20), -8)?;
        encoder.mov_const(Gpr::x(0), 2)?;
        encoder.str_uoff(Gpr::x(0), Gpr::x(19), 16_408)?;
        encoder.mov_const(Gpr::x(1), sentinel as u64)?;
        encoder.mov_reg(Gpr::x(2), Gpr::xzr())?;
        encoder.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
        encoder.br(Gpr::x(17))
    })?;
    Ok(())
}
