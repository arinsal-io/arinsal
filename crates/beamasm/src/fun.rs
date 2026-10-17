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
const ACTIVE_CODE_IX: Gpr = Gpr::x(24);

// These entries map logical XREG4/5 to their caller-saved hardware registers.
const fn logical_xreg(index: u8) -> Gpr {
    Gpr::x(index)
}

/// Resolves a fun term to a native entry, setting `freason` and `fvalue` on failure.
pub type FunResolver = extern "C" fn(*mut crate::ProcessHeader, u64, u32) -> usize;

/// Identifies a statically known lambda trampoline or a dynamically resolved fun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunCallTag {
    /// `unsafe`: test that the operand is a fun of the right arity before calling it.
    Dynamic,
    /// `safe`: the compiler proved the operand is a fun of the right arity, so the call skips
    /// the fun and arity tests.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:402-423 (`Tag == am_safe`), OTP-29.1.1.
    DynamicSafe,
    /// Call the lambda trampoline registered with this identifier.
    Lambda(u32),
}

/// The register holding the fun of an `i_call_fun`: X registers above the register cache
/// live in the scheduler's X array.
fn fun_register(arity: u8) -> ArgVal {
    if arity < 6 {
        ArgVal::X(arity)
    } else {
        ArgVal::XMemory(u32::from(arity))
    }
}

impl BeamModuleAssembler {
    /// Register that receives a new fun term; memory destinations go through a scratch register.
    fn fun_destination(&self, dst: ArgVal) -> Result<(Gpr, bool), ModuleError> {
        match dst {
            ArgVal::X(index) if index < 6 => Ok((XREGS[index as usize], false)),
            ArgVal::Y(_) | ArgVal::XMemory(_) => Ok((Gpr::x(8), true)),
            _ => Err(ModuleError::InvalidOperand(
                "fun destination must be an X or Y register",
            )),
        }
    }

    fn finish_fun_destination(&mut self, dst: ArgVal, spill: bool) -> Result<(), ModuleError> {
        if spill {
            self.store_register(dst, Gpr::x(8))?;
        }
        Ok(())
    }

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
        let (destination, spill) = self.fun_destination(dst)?;
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
        self.finish_fun_destination(dst, spill)
    }

    /// Allocates an OTP local fun using its retained module lambda entry.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:211-251, OTP-29.1.1.
    pub fn emit_i_make_fun3_entry(
        &mut self,
        dst: ArgVal,
        entry: usize,
        arity: u8,
        env: &[ArgVal],
        retain_helper: usize,
    ) -> Result<(), ModuleError> {
        if env.len() > u8::MAX as usize || arity as usize + env.len() >= 64 {
            return Err(ModuleError::InvalidOperand(
                "invalid fun arity or environment size",
            ));
        }
        if retain_helper == 0 {
            return Err(ModuleError::InvalidOperand(
                "local fun owner retention helper is missing",
            ));
        }
        let (destination, spill) = self.fun_destination(dst)?;
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
        self.finish_fun_destination(dst, spill)?;
        self.code.emit(|e| e.mov_const(Gpr::x(13), entry as u64))?;
        self.emit_runtime_fragment_with(
            retain_helper,
            &[Gpr::x(13)],
            6,
            Update::HEAP_ALLOC
                .union(Update::X_REGS)
                .union(Update::REDUCTIONS),
        )?;
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
        let (destination, spill) = self.fun_destination(dst)?;
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
        self.finish_fun_destination(dst, spill)
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
        if self.defined_lambdas.insert(lambda, ()).is_some() {
            return Err(ModuleError::DuplicateLabel(lambda));
        }
        let trampoline = self.lambda_label(lambda);
        self.code.bind(trampoline)?;
        if num_free != 0 {
            self.code.emit(|e| {
                e.and_imm(Gpr::x(9), Gpr::x(3), !7)?;
                e.add_imm(Gpr::x(9), Gpr::x(9), 16, false)
            })?;
            let start = usize::from(total_arity - num_free);
            for i in 0..usize::from(num_free) {
                let index = start + i;
                let offset = (i as u32) * 8;
                if index < XREGS.len() {
                    self.code
                        .emit(|e| e.ldr_uoff(XREGS[index], Gpr::x(9), offset))?;
                } else {
                    // X registers above the register cache live in the X register array.
                    self.code.emit(|e| {
                        e.ldr_uoff(Gpr::x(10), Gpr::x(9), offset)?;
                        e.str_uoff(Gpr::x(10), Gpr::x(19), (index as u32) * 8)
                    })?;
                }
            }
        }
        let label = self.label(target);
        self.code.b(label)?;
        Ok(())
    }

    /// Calls a fun with arity taken from the `i_call_fun` operand.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:457-462, OTP-29.1.1
    pub fn emit_i_call_fun(&mut self, arity: u8, resolver: FunResolver) -> Result<(), ModuleError> {
        self.emit_i_call_fun2(FunCallTag::Dynamic, arity, fun_register(arity), resolver)
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
            fun_register(arity),
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

    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:402-455 (emit_i_call_fun2,
    // emit_i_call_fun2_last), OTP-29.1.1.
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
        self.code.emit(|e| e.mov_reg(Gpr::x(3), source))?;
        match tag {
            FunCallTag::Lambda(id) => {
                let trampoline = self.lambda_label(id);
                if tail {
                    self.deallocate(deallocate)?;
                    self.emit_leave_frame()?;
                    self.code.b(trampoline)?;
                } else {
                    // erlang_call (beam_asm.hpp:310-332): `bl` keeps the return-address
                    // predictor paired with the callee's `ret`.
                    self.code.bl(trampoline)?;
                }
                Ok(())
            }
            FunCallTag::Dynamic | FunCallTag::DynamicSafe => {
                // Make the lower 16 bits of x2 equal those of the header word of all funs
                // with this arity (erts ARG3).
                self.code
                    .emit(|e| e.mov_const(Gpr::x(2), FUN_SUBTAG | (u64::from(arity) << 8)))?;
                self.emit_call_fun(tag == FunCallTag::DynamicSafe, resolver, tail, deallocate)
            }
        }
    }

    /// Calls the fun in ARG4 (x3) whose expected header bits (`FUN_SUBTAG` and arity) are in
    /// ARG3 (x2). `skip_header_test` is the `safe` tag; otherwise a non-fun or a fun of another
    /// arity lands in the module's `call_fun` error handler through the same call instruction.
    /// The entry (an `ErlFunEntry` or an `Export`) is loaded into ARG1 (x0) and its address for
    /// the active code index into TMP1 (x8), so the code, the export trampoline, the
    /// `unloaded_fun` and the `save_calls_fun` fragments all start from ARG1 like erts.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:346-400 (emit_call_fun), OTP-29.1.1.
    pub(crate) fn emit_call_fun(
        &mut self,
        skip_header_test: bool,
        resolver: FunResolver,
        tail: bool,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        let next = self.code.new_label();
        // Speculatively untag the ErlFunThing.
        self.code
            .emit(|e| e.sub_imm(Gpr::x(9), Gpr::x(3), 2, false))?;
        if !skip_header_test {
            // Load the error handler into TMP1 so that any failed test lands there.
            let error = self.call_fun_error_label(resolver as usize);
            self.code.adr(Gpr::x(8), error)?;
        }
        // The `handle_call_fun_error` and `unloaded_fun` fragments expect the current pc in
        // ARG5 (x4); LR points elsewhere for tail calls.
        self.code.adr(Gpr::x(4), next)?;
        if skip_header_test {
            self.code.emit(|e| e.ldr_uoff(Gpr::x(0), Gpr::x(9), 8))?;
        } else {
            // As emit_is_boxed(): anything but a boxed term has bit 0 set.
            self.code.emit(|e| e.tst_imm(Gpr::x(3), 1))?;
            self.code.b_cond(Cond::Ne, next)?;
            // Header word and `ErlFunThing->entry`: boxed terms are at least two words.
            self.code
                .emit(|e| e.ldp(Gpr::x(9), Gpr::x(0), Gpr::x(9), 0))?;
            // Combined fun type and arity test.
            self.code.emit(|e| {
                e.cmp_ext(
                    Gpr::x(2),
                    arinsal_a64::enc::Extended {
                        reg: Gpr::w(9),
                        extend: arinsal_a64::enc::Extend::Uxth,
                        amount: 0,
                    },
                )
            })?;
            self.code.b_cond(Cond::Ne, next)?;
        }
        // emit_setup_dispatchable_call: `addresses[active_code_ix]` of the fun or export entry.
        self.code
            .emit(|e| e.ldr_regoff(Gpr::x(8), Gpr::x(0), ACTIVE_CODE_IX, 3))?;
        self.code.bind(next)?;
        crate::emit_validate_native_cursor(&mut self.code)?;
        if tail {
            self.deallocate(deallocate)?;
            self.emit_leave_frame()?;
            self.code.emit(|e| e.br(Gpr::x(8)))?;
        } else {
            // erlang_call (beam_asm.hpp:310-332): `blr` keeps the return-address
            // predictor paired with the callee's `ret`.
            self.code.emit(|e| e.blr(Gpr::x(8)))?;
            crate::emit_validate_native_cursor(&mut self.code)?;
        }
        Ok(())
    }

    /// Calls the fun in x3 with the argument count in x2 (`apply/2`).
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:253-344 (emit_apply_fun_shared sets
    // ARG3 to the fun header of that arity, then emit_i_apply_fun), OTP-29.1.1.
    pub(crate) fn emit_dynamic_fun_call(
        &mut self,
        resolver: FunResolver,
        tail: bool,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.lsl_imm(Gpr::x(2), Gpr::x(2), 8)?;
            e.add_imm(Gpr::x(2), Gpr::x(2), FUN_SUBTAG as u16, false)
        })?;
        self.emit_call_fun(false, resolver, tail, deallocate)
    }
}

/// Raises `badfun` or `badarity` for a failed `call_fun` test. Entered through the call
/// instruction with x2 = expected header bits, x3 = fun and x4 = the call site.
// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:64-131 (emit_handle_call_fun_error),
// OTP-29.1.1: the resolver builds the exception like beam_jit_handle_call_fun_error's paths.
pub(crate) fn emit_call_fun_error(
    asm: &mut BeamModuleAssembler,
    helper: usize,
) -> Result<(), ModuleError> {
    let update = Update::HEAP_ALLOC
        .union(Update::X_REGS)
        .union(Update::REDUCTIONS);
    asm.code.emit(|e| e.str_uoff(Gpr::x(4), Gpr::x(21), 72))?;
    emit_enter_runtime(&mut asm.code, 6, update)?;
    asm.code.emit(|e| {
        e.mov_reg(Gpr::x(0), Gpr::x(21))?;
        e.mov_reg(Gpr::x(1), Gpr::x(3))?;
        e.lsr_imm(Gpr::x(2), Gpr::x(2), 8)?;
        e.mov_const(Gpr::x(17), helper as u64)?;
        e.blr(Gpr::x(17))
    })?;
    emit_leave_runtime(&mut asm.code, 6, update)?;
    asm.code.emit(|e| e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72))?;
    asm.branch_error_from_lr()?;
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
