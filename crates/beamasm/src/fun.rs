//! Closure allocation, lambda entry trampolines, and fun calls.

use arinsal_a64::enc::{Cond, Gpr};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::{Update, emit_enter_runtime, emit_leave_runtime};

const XREGS: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    logical_xreg(15),
    logical_xreg(16),
];
const FUN_SUBTAG: u64 = 0x14;

// These entries map logical XREG4/5 to their caller-saved hardware registers.
const fn logical_xreg(index: u8) -> Gpr {
    Gpr::x(index)
}

/// Resolves a fun term to a native entry, setting `freason` and `fvalue` on failure.
pub type FunResolver = extern "C" fn(*mut crate::ProcessHeader, u64, u32) -> usize;

/// Identifies a statically known lambda trampoline or a dynamically resolved fun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunCallTag {
    /// Resolve the fun term at runtime, including external funs.
    Dynamic,
    /// Call the lambda trampoline registered with this identifier.
    Lambda(u32),
}

impl BeamModuleAssembler {
    /// Allocates a closure whose entry is a trampoline label in this module.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:211-251, OTP-29.1.1.
    pub fn emit_i_make_fun3_label(
        &mut self,
        dst: ArgVal,
        entry_label: u32,
        arity: u8,
        env: &[ArgVal],
    ) -> Result<(), ModuleError> {
        if env.len() > u8::MAX as usize || arity as usize + env.len() >= 64 {
            return Err(ModuleError::InvalidOperand(
                "invalid fun arity or environment size",
            ));
        }
        let destination = x_destination(dst)?;
        let header = FUN_SUBTAG | (u64::from(arity) << 8) | ((env.len() as u64) << 16);
        let entry = self.lambda_label(entry_label);
        self.code.emit(|e| {
            e.mov_const(Gpr::x(9), header)?;
            e.str_uoff(Gpr::x(9), Gpr::x(23), 0)
        })?;
        self.code.adr(Gpr::x(9), entry)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(9), Gpr::x(23), 8))?;
        for (index, source) in env.iter().copied().enumerate() {
            let value = self.source_reg(source)?;
            self.code
                .emit(|e| e.str_uoff(value, Gpr::x(23), 16 + index as u32 * 8))?;
        }
        self.code.emit(|e| {
            e.add_imm(destination, Gpr::x(23), 2, false)?;
            e.add_imm(
                Gpr::x(23),
                Gpr::x(23),
                ((2 + env.len() as u32) * 8) as u16,
                false,
            )
        })?;
        Ok(())
    }

    /// Allocates an OTP local fun using its retained module lambda entry.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:211-251, OTP-29.1.1.
    pub fn emit_i_make_fun3_entry(
        &mut self,
        dst: ArgVal,
        entry: usize,
        arity: u8,
        env: &[ArgVal],
    ) -> Result<(), ModuleError> {
        if env.len() > u8::MAX as usize || arity as usize + env.len() >= 64 {
            return Err(ModuleError::InvalidOperand(
                "invalid fun arity or environment size",
            ));
        }
        let destination = x_destination(dst)?;
        let header = FUN_SUBTAG | (u64::from(arity) << 8) | ((env.len() as u64) << 16);
        self.code.emit(|e| {
            e.mov_const(Gpr::x(9), header)?;
            e.str_uoff(Gpr::x(9), Gpr::x(23), 0)?;
            e.mov_const(Gpr::x(9), entry as u64)?;
            e.str_uoff(Gpr::x(9), Gpr::x(23), 8)
        })?;
        for (index, source) in env.iter().copied().enumerate() {
            let value = self.source_reg(source)?;
            self.code
                .emit(|e| e.str_uoff(value, Gpr::x(23), 16 + index as u32 * 8))?;
        }
        self.code.emit(|e| {
            e.add_imm(destination, Gpr::x(23), 2, false)?;
            e.add_imm(
                Gpr::x(23),
                Gpr::x(23),
                ((2 + env.len() as u32) * 8) as u16,
                false,
            )
        })?;
        Ok(())
    }

    /// Allocates an OTP two-word fun header and copies its environment terms.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:211-251, OTP-29.1.1
    pub fn emit_i_make_fun3(
        &mut self,
        dst: ArgVal,
        entry: usize,
        arity: u8,
        env: &[ArgVal],
    ) -> Result<(), ModuleError> {
        if env.len() > u8::MAX as usize || arity as usize + env.len() >= 64 {
            return Err(ModuleError::InvalidOperand(
                "invalid fun arity or environment size",
            ));
        }
        let destination = x_destination(dst)?;
        let header = FUN_SUBTAG | (u64::from(arity) << 8) | ((env.len() as u64) << 16);
        self.code.emit(|e| {
            e.mov_const(Gpr::x(9), header)?;
            e.str_uoff(Gpr::x(9), Gpr::x(23), 0)?;
            e.mov_const(Gpr::x(9), entry as u64)?;
            e.str_uoff(Gpr::x(9), Gpr::x(23), 8)
        })?;
        for (index, source) in env.iter().copied().enumerate() {
            let value = self.source_reg(source)?;
            let offset = 16 + index as u32 * 8;
            self.code.emit(|e| e.str_uoff(value, Gpr::x(23), offset))?;
        }
        self.code.emit(|e| {
            e.add_imm(destination, Gpr::x(23), 2, false)?;
            e.add_imm(
                Gpr::x(23),
                Gpr::x(23),
                ((2 + env.len() as u32) * 8) as u16,
                false,
            )
        })?;
        Ok(())
    }

    /// Emits an environment-unpacking entry for a statically known lambda.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:167-205, OTP-29.1.1
    pub fn emit_i_lambda_trampoline(
        &mut self,
        lambda: u32,
        target: u32,
        total_arity: u8,
        num_free: u8,
    ) -> Result<(), ModuleError> {
        if usize::from(total_arity) > XREGS.len() {
            return Err(ModuleError::InvalidOperand(
                "lambda arity exceeds X register capacity",
            ));
        }
        if self.defined_lambdas.insert(lambda, ()).is_some() {
            return Err(ModuleError::DuplicateLabel(lambda));
        }
        let trampoline = self.lambda_label(lambda);
        self.code.bind(trampoline)?;
        if num_free != 0 {
            self.code.emit(|e| {
                e.and_imm(Gpr::x(9), Gpr::x(4), !7)?;
                e.add_imm(Gpr::x(9), Gpr::x(9), 16, false)
            })?;
            let start = usize::from(total_arity - num_free);
            let mut i = 0;
            while i + 1 < usize::from(num_free) {
                self.code.emit(|e| {
                    e.ldr_uoff(XREGS[start + i], Gpr::x(9), (i as u32) * 8)?;
                    e.ldr_uoff(XREGS[start + i + 1], Gpr::x(9), ((i + 1) as u32) * 8)
                })?;
                i += 2;
            }
            if i < usize::from(num_free) {
                self.code
                    .emit(|e| e.ldr_uoff(XREGS[start + i], Gpr::x(9), (i as u32) * 8))?;
            }
        }
        let label = self.label(target);
        self.code.b(label)?;
        Ok(())
    }

    /// Calls a fun with arity taken from the `i_call_fun` operand.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:457-462, OTP-29.1.1
    pub fn emit_i_call_fun(&mut self, arity: u8, resolver: FunResolver) -> Result<(), ModuleError> {
        self.emit_i_call_fun2(FunCallTag::Dynamic, arity, ArgVal::X(arity), resolver)
    }

    /// Tail-calls a fun with arity taken from the `i_call_fun` operand.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:464-470, OTP-29.1.1
    pub fn emit_i_call_fun_last(
        &mut self,
        arity: u8,
        deallocate: u32,
        resolver: FunResolver,
    ) -> Result<(), ModuleError> {
        self.emit_i_call_fun2_last(
            FunCallTag::Dynamic,
            arity,
            ArgVal::X(arity),
            deallocate,
            resolver,
        )
    }

    /// Calls a statically tagged lambda or dynamically resolved fun.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:402-423, OTP-29.1.1
    pub fn emit_i_call_fun2(
        &mut self,
        tag: FunCallTag,
        arity: u8,
        func: ArgVal,
        resolver: FunResolver,
    ) -> Result<(), ModuleError> {
        self.emit_fun_call(tag, arity, func, resolver, false, 0)
    }

    /// Deallocates the frame and tail-calls a statically tagged or dynamic fun.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:425-455, OTP-29.1.1
    pub fn emit_i_call_fun2_last(
        &mut self,
        tag: FunCallTag,
        arity: u8,
        func: ArgVal,
        deallocate: u32,
        resolver: FunResolver,
    ) -> Result<(), ModuleError> {
        self.emit_fun_call(tag, arity, func, resolver, true, deallocate)
    }

    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:39-57,402-470, OTP-29.1.1.
    // Dynamic resolution mirrors beam_jit_handle_unloaded_fun's runtime boundary.
    fn emit_fun_call(
        &mut self,
        tag: FunCallTag,
        arity: u8,
        func: ArgVal,
        resolver: FunResolver,
        tail: bool,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        let source = self.source_reg(func)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(4), source))?;
        let continuation = self.code.new_label();
        match tag {
            FunCallTag::Lambda(id) => {
                if tail {
                    self.deallocate(deallocate)?;
                    self.emit_leave_frame()?;
                } else {
                    self.code.adr(Gpr::x(30), continuation)?;
                }
                let trampoline = self.lambda_label(id);
                self.code.b(trampoline)?;
            }
            FunCallTag::Dynamic => {
                self.code
                    .emit(|e| e.mov_const(Gpr::x(2), u64::from(arity)))?;
                let resolver_path = self.code.new_label();
                let call_target = self.code.new_label();

                // OTP first validates the boxed fun header and dispatches a local
                // fun directly through its dispatchable entry. Export funs and
                // every malformed or wrong-arity term go through the resolver.
                self.code.emit(|e| {
                    e.and_imm(Gpr::x(9), Gpr::x(4), 3)?;
                    e.cmp_imm(Gpr::x(9), 2, false)
                })?;
                self.code.b_cond(Cond::Ne, resolver_path)?;
                self.code.emit(|e| {
                    e.and_imm(Gpr::x(10), Gpr::x(4), !7)?;
                    e.ldp(Gpr::x(11), Gpr::x(12), Gpr::x(10), 0)
                })?;
                self.code.emit(|e| {
                    e.and_imm(Gpr::x(13), Gpr::x(11), 0xffff)?;
                    e.lsl_imm(Gpr::x(14), Gpr::x(2), 8)?;
                    e.add_imm(Gpr::x(14), Gpr::x(14), FUN_SUBTAG as u16, false)?;
                    e.cmp_reg(Gpr::x(13), Gpr::x(14), arinsal_a64::enc::Shift::Lsl, 0)
                })?;
                self.code.b_cond(Cond::Ne, resolver_path)?;
                self.code.emit(|e| {
                    e.and_imm(Gpr::x(13), Gpr::x(11), 1 << 24)?;
                    e.cmp_imm(Gpr::x(13), 0, false)
                })?;
                self.code.b_cond(Cond::Ne, resolver_path)?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp call_fun
                // dispatchable load: `ErlFunEntry` begins with `ErtsDispatchable`.
                // Unpublished entries keep address 0; fall through to the resolver
                // (OTP jumps to `beam_unloaded_fun` instead).
                self.code.emit(|e| e.ldr_uoff(Gpr::x(0), Gpr::x(12), 0))?;
                self.code.cbz(Gpr::x(0), resolver_path)?;
                self.code.b(call_target)?;

                self.code.bind(resolver_path)?;
                emit_fun_resolver(self, resolver as usize)?;
                self.code.bind(call_target)?;
                if tail {
                    self.deallocate(deallocate)?;
                    self.emit_leave_frame()?;
                    self.code.emit(|e| e.br(Gpr::x(0)))?;
                } else {
                    self.code.adr(Gpr::x(30), continuation)?;
                    self.code.emit(|e| e.br(Gpr::x(0)))?;
                    self.code.bind(continuation)?;
                }
                return Ok(());
            }
        }
        if !tail {
            self.code.bind(continuation)?;
        }
        Ok(())
    }
}

// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:39-57, OTP-29.1.1.
fn emit_fun_resolver(asm: &mut BeamModuleAssembler, helper: usize) -> Result<(), ModuleError> {
    let update = Update::HEAP_ALLOC
        .union(Update::X_REGS)
        .union(Update::REDUCTIONS);
    emit_enter_runtime(&mut asm.code, 6, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), Gpr::x(21))?;
        e.mov_reg(Gpr::x(1), Gpr::x(4))?;
        e.mov_const(Gpr::x(17), helper as u64)?;
        e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(&mut asm.code, 6, update)?;
    asm.code.emit(|e| {
        e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
    })?;
    asm.code.cbnz(Gpr::x(9), asm.error_label)?;
    Ok(())
}

/// Routes the task-local operation to BeamAsm's shared guard emitter.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:1263-1306, OTP-29.1.1
pub fn emit_is_function2(
    asm: &mut BeamModuleAssembler,
    src: ArgVal,
    arity: ArgVal,
    helper: crate::guard::GuardHelper,
) -> Result<(), ModuleError> {
    asm.emit_is_function2(src, arity, helper)
}

fn x_destination(dst: ArgVal) -> Result<Gpr, ModuleError> {
    match dst {
        ArgVal::X(index) if index < 6 => Ok(XREGS[index as usize]),
        _ => Err(ModuleError::InvalidOperand(
            "fun destination must be an X register",
        )),
    }
}
