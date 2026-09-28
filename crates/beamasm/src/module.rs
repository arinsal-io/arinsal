//! Module-local BeamAsm code generation for calls, frames, and register moves.

use std::collections::HashMap;
use std::path::Path;

use crate::rt::arinsal_enter_native_return;
use arinsal_a64::{
    buf::{BufferError, CodeBuffer, Label},
    enc::{Cond, Emitter, Gpr},
    exec::{CodeMemory, ExecError},
};

const E: Gpr = Gpr::x(20);
const FCALLS: Gpr = Gpr::w(22);
const C_P: Gpr = Gpr::x(21);
const SCHEDULER_REGS: Gpr = Gpr::x(19);
const XREGS: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    Gpr::x(15),
    Gpr::x(16),
];
const TMP: Gpr = Gpr::x(9);

/// Typed operand accepted by the first BeamAsm emitter slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgVal {
    /// Register backed X value, numbered X0 through X5.
    X(u8),
    /// Erlang stack Y value, numbered from the current stack pointer.
    Y(u32),
    /// An immediate machine word.
    Immediate(u64),
    /// A literal machine word.
    Literal(u64),
    /// A module label number.
    Label(u32),
    /// An export table index (external call emission is currently unported).
    Export(u32),
}

/// Errors while emitting or finalizing a native module.
#[derive(Debug)]
pub enum ModuleError {
    /// Underlying branch or instruction encoding error.
    Buffer(BufferError),
    /// Executable memory allocation or write error.
    Exec(ExecError),
    /// An operand or label is invalid for this operation.
    InvalidOperand(&'static str),
    /// A label was defined more than once.
    DuplicateLabel(u32),
    /// Optional machine-code dump could not be written.
    Dump(crate::DumpError),
}

impl From<BufferError> for ModuleError {
    fn from(value: BufferError) -> Self {
        Self::Buffer(value)
    }
}
impl From<ExecError> for ModuleError {
    fn from(value: ExecError) -> Self {
        Self::Exec(value)
    }
}

/// Finalized executable module and native entry addresses.
pub struct FinalizedModule {
    /// Owns the executable mapping; entry addresses remain valid while this is alive.
    pub memory: CodeMemory,
    /// Native entry address by BEAM label number.
    pub entries: HashMap<u32, *const u8>,
    entry_offsets: HashMap<u32, usize>,
    /// Native trampoline by zero-based BEAM lambda-table index.
    pub lambda_entries: HashMap<u32, *const u8>,
    /// Native catch handler addresses in this module's `make_catch` order.
    pub catch_table: Vec<*const u8>,
}

impl FinalizedModule {
    /// Returns a native entry handle that keeps this module's executable mapping alive.
    pub fn entry(&self, label: u32) -> Option<crate::NativeEntry<'_>> {
        self.entry_offsets
            .get(&label)
            .copied()
            .map(|offset| crate::NativeEntry {
                memory: &self.memory,
                offset,
            })
    }
}

/// Builds one module's native code and associates BEAM labels with code offsets.
pub struct BeamModuleAssembler {
    pub(super) code: CodeBuffer,
    labels: HashMap<u32, Label>,
    defined: HashMap<u32, ()>,
    lambda_labels: HashMap<u32, Label>,
    lambda_specs: HashMap<u32, (u32, u8, u8)>,
    pub(super) defined_lambdas: HashMap<u32, ()>,
    yield_label: Label,
    pub(super) error_label: Label,
    catch_patches: Vec<(usize, Label)>,
    dump_module: Option<String>,
    dump_functions: Vec<crate::dump::FunctionRecord>,
    dump_recording_function: bool,
}

impl Default for BeamModuleAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl BeamModuleAssembler {
    /// Creates an empty module assembler.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:84-104, OTP-29.1.1
    pub fn new() -> Self {
        let mut code = CodeBuffer::new();
        let yield_label = code.new_label();
        let error_label = code.new_label();
        Self {
            code,
            labels: HashMap::new(),
            defined: HashMap::new(),
            lambda_labels: HashMap::new(),
            lambda_specs: HashMap::new(),
            defined_lambdas: HashMap::new(),
            yield_label,
            error_label,
            catch_patches: Vec::new(),
            dump_module: None,
            dump_functions: Vec::new(),
            dump_recording_function: false,
        }
    }

    /// Enables optional instruction-range capture for one module.
    pub fn enable_dump(&mut self, module: &str) {
        if std::env::var_os("ARINSAL_BEAMASM_DUMP").is_some() {
            self.dump_module = Some(module.to_owned());
        }
    }

    /// Reports whether this assembler is collecting optional dump metadata.
    pub fn dump_enabled(&self) -> bool {
        self.dump_module.is_some()
    }

    /// Starts collecting BEAM operation records for a function.
    pub fn begin_dump_function(&mut self, name: &str, arity: u8) {
        self.dump_recording_function = self.dump_module.is_some() && name != "<unknown>";
        if self.dump_recording_function {
            self.dump_functions.push(crate::dump::FunctionRecord {
                name: name.to_owned(),
                arity,
                instructions: Vec::new(),
            });
        }
    }

    /// Returns the current module-local machine-code offset.
    pub fn code_offset(&self) -> usize {
        self.code.offset()
    }

    /// Records the code range emitted for one BEAM operation.
    pub fn record_dump_instruction(&mut self, text: String, start: usize, end: usize) {
        if self.dump_recording_function
            && let Some(function) = self.dump_functions.last_mut()
        {
            function
                .instructions
                .push(crate::dump::InstructionRecord { text, start, end });
        }
    }

    pub(super) fn label(&mut self, id: u32) -> Label {
        *self
            .labels
            .entry(id)
            .or_insert_with(|| self.code.new_label())
    }

    pub(super) fn lambda_label(&mut self, id: u32) -> Label {
        *self
            .lambda_labels
            .entry(id)
            .or_insert_with(|| self.code.new_label())
    }

    /// Reserves the entry address represented by one BEAM lambda-table slot.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:355-370, OTP-29.1.1.
    pub fn register_lambda(
        &mut self,
        index: u32,
        target: u32,
        total_arity: u8,
        num_free: u8,
    ) -> Result<(), ModuleError> {
        if self.lambda_specs.contains_key(&index) {
            return Err(ModuleError::DuplicateLabel(index));
        }
        if usize::from(total_arity) > 6 || num_free > total_arity {
            return Err(ModuleError::InvalidOperand("invalid lambda table entry"));
        }
        let trampoline = if num_free == 0 {
            self.label(target)
        } else {
            self.code.new_label()
        };
        self.lambda_labels.insert(index, trampoline);
        self.lambda_specs
            .insert(index, (target, total_arity, num_free));
        Ok(())
    }

    /// Emits table trampolines that had no corresponding operation in the code stream.
    pub fn emit_missing_lambda_trampolines(&mut self) -> Result<(), ModuleError> {
        let mut specs = self
            .lambda_specs
            .iter()
            .map(|(&index, &(target, arity, free))| (index, target, arity, free))
            .collect::<Vec<_>>();
        specs.sort_unstable_by_key(|spec| spec.0);
        for (index, target, arity, free) in specs {
            if free != 0 && !self.defined_lambdas.contains_key(&index) {
                self.emit_i_lambda_trampoline(index, target, arity, free)?;
            }
        }
        Ok(())
    }

    pub(super) fn add_catch_patch(&mut self, offset: usize, handler: Label) {
        self.catch_patches.push((offset, handler));
    }

    /// Emits a four-byte aligned function entry label.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:556-560, OTP-29.1.1
    pub fn emit_i_func_label(&mut self, id: u32) -> Result<(), ModuleError> {
        if self.defined.insert(id, ()).is_some() {
            return Err(ModuleError::DuplicateLabel(id));
        }
        let label = self.label(id);
        self.code.bind(label)?;
        Ok(())
    }

    /// Emits the metadata placeholder associated with an `i_func_info` entry.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:499-554, OTP-29.1.1
    pub fn emit_i_func_info(
        &mut self,
        _label: u32,
        _module: u32,
        _function: u32,
        _arity: u8,
    ) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.nop();
            Ok(())
        })?;
        Ok(())
    }

    /// Pushes the BEAM continuation pointer onto the Erlang stack.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:429-433, OTP-29.1.1
    pub fn emit_enter_frame(&mut self) -> Result<(), ModuleError> {
        let frame_bytes = (arinsal_term::FrameLayout::WORDS * 8) as i16;
        self.code.emit(|e| {
            e.stp_pre(Gpr::x(29), Gpr::x(30), E, -frame_bytes)?;
            e.mov_reg(Gpr::x(29), E)
        })?;
        Ok(())
    }

    /// Pops the BEAM continuation pointer from the Erlang stack.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:429-433, OTP-29.1.1
    pub fn emit_leave_frame(&mut self) -> Result<(), ModuleError> {
        let frame_bytes = (arinsal_term::FrameLayout::WORDS * 8) as i16;
        self.code
            .emit(|e| e.ldp_post(Gpr::x(29), Gpr::x(30), E, frame_bytes))?;
        Ok(())
    }

    /// Emits a direct local call with an Erlang continuation on the stack.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:71-74, OTP-29.1.1
    pub fn call(&mut self, target: u32) -> Result<(), ModuleError> {
        let continuation = self.code.new_label();
        let veneer = self.code.new_label();
        self.code.adr(Gpr::x(30), continuation)?;
        self.code.b(veneer)?;
        self.code.bind(veneer)?;
        let target_label = self.label(target);
        self.code.b(target_label)?;
        self.code.bind(continuation)?;
        Ok(())
    }

    /// Emits a tail call after releasing the requested Y frame.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:77-80, OTP-29.1.1
    pub fn call_last(&mut self, target: u32, deallocate: u32) -> Result<(), ModuleError> {
        self.deallocate(deallocate)?;
        self.call_only(target)
    }

    /// Moves a value and performs a local call.
    pub fn move_call(&mut self, src: ArgVal, dst: ArgVal, target: u32) -> Result<(), ModuleError> {
        self.move_(src, dst)?;
        self.call(target)
    }

    /// Moves a value, deallocates the frame, and performs a local tail call.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:77-115, OTP-29.1.1
    pub fn move_call_last(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        target: u32,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        self.move_(src, dst)?;
        self.call_last(target, deallocate)
    }

    /// Dispatches through the VM-owned native address word for an export.
    ///
    /// Port of erts/emulator/beam/jit/arm/instr_call.cpp:150-200, OTP-29.1.1.
    pub fn dispatch_export(&mut self, entry: usize, tail: bool) -> Result<(), ModuleError> {
        let continuation = self.code.new_label();
        if tail {
            self.emit_leave_frame()?;
        } else {
            self.code.adr(Gpr::x(30), continuation)?;
        }
        self.code.emit(|e| {
            e.mov_const(Gpr::x(13), entry as u64)?;
            e.ldr_uoff(Gpr::x(14), Gpr::x(13), 0)?;
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), Gpr::x(13))
        })?;
        self.code.emit(|e| {
            if tail {
                e.br(Gpr::x(14))
            } else {
                e.blr(Gpr::x(14))
            }
        })?;
        if !tail {
            self.code.bind(continuation)?;
        }
        Ok(())
    }

    /// Dispatches a light BIF without manufacturing an Erlang stack frame.
    ///
    /// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610, OTP-29.1.1.
    pub fn dispatch_light_bif(
        &mut self,
        fragment: usize,
        identity: usize,
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610, OTP-29.1.1.
        let call = self.code.new_label();
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        self.code.b_cond(Cond::Gt, call)?;
        self.code.adr(Gpr::x(8), call)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), C_P, 72))?;
        self.code.b(self.yield_label)?;
        self.code.bind(call)?;
        self.code
            .emit(|e| e.mov_const(Gpr::x(13), identity as u64))?;
        self.emit_runtime_fragment(fragment, &[Gpr::x(13)])?;
        self.code.emit(|e| e.mov_reg(XREGS[0], Gpr::x(0)))?;
        Ok(())
    }

    /// Exits native execution so the scheduler can interpret a fun or apply call.
    pub fn call_fun_or_apply(&mut self, target_pc: usize) -> Result<(), ModuleError> {
        self.call_unported(target_pc)
    }

    /// Checks reductions and saves the native continuation before yielding.
    pub fn test_yield(&mut self) -> Result<(), ModuleError> {
        let continuation = self.code.new_label();
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        self.code.b_cond(Cond::Gt, continuation)?;
        self.code.adr(Gpr::x(8), continuation)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), C_P, 72))?;
        self.code.b(self.yield_label)?;
        self.code.bind(continuation)?;
        Ok(())
    }

    fn emit_redundant_bridge_cp_pop(&mut self) -> Result<(), ModuleError> {
        let keep = self.code.new_label();
        let bridge = arinsal_enter_native_return as *const () as u64;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(9), E, 0)?;
            e.mov_const(Gpr::x(10), bridge)?;
            e.cmp_reg(Gpr::x(9), Gpr::x(10), arinsal_a64::enc::Shift::Lsl, 0)
        })?;
        self.code.b_cond(Cond::Ne, keep)?;
        self.code.emit(|e| e.add_imm(E, E, 8, false))?;
        self.code.bind(keep)?;
        Ok(())
    }

    fn call_unported(&mut self, target_pc: usize) -> Result<(), ModuleError> {
        let continuation = self.code.new_label();
        self.code.emit(|e| {
            // Preserve the BEAM call arguments before returning the interpreter
            // call target to the scheduler in x0/x1.
            e.str_uoff(XREGS[0], SCHEDULER_REGS, 16_384)?;
            e.str_uoff(XREGS[1], SCHEDULER_REGS, 16_392)?;
            Ok(())
        })?;
        self.code.adr(Gpr::x(2), continuation)?;
        crate::emit_enter_runtime(
            &mut self.code,
            6,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::REDUCTIONS)
                .union(crate::Update::X_REGS),
        )?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(1), target_pc as u64)?;
            e.mov_const(Gpr::x(0), 2)?;
            e.ret(Gpr::x(30))
        })?;
        self.code.bind(continuation)?;
        self.emit_redundant_bridge_cp_pop()?;
        Ok(())
    }

    /// Emits a local tail call without pushing another continuation.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:118-123, OTP-29.1.1
    pub fn call_only(&mut self, target: u32) -> Result<(), ModuleError> {
        self.emit_leave_frame()?;
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        let target = self.label(target);
        self.code.b_cond(Cond::Pl, target)?;
        self.code.adr(Gpr::x(8), target)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), C_P, 72))?;
        self.code.b(self.yield_label)?;
        Ok(())
    }

    /// Emits an unconditional local branch without changing frame or reduction state.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1127-1129, OTP-29.1.1
    pub fn jump(&mut self, target: u32) -> Result<(), ModuleError> {
        let target = self.label(target);
        self.code.b(target)?;
        Ok(())
    }

    /// Branches to a module label when an X register contains zero.
    pub fn branch_if_zero(&mut self, reg: ArgVal, target: u32) -> Result<(), ModuleError> {
        let ArgVal::X(index) = reg else {
            return Err(ModuleError::InvalidOperand("CBZ requires X register"));
        };
        if index >= 6 {
            return Err(ModuleError::InvalidOperand(
                "X register index must be below 6",
            ));
        }
        let label = self.label(target);
        self.code.cbz(XREGS[index as usize], label)?;
        Ok(())
    }

    /// Branches to a module label when the supplied hardware register is zero.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1127-1129, OTP-29.1.1.
    pub fn branch_if_zero_register(&mut self, reg: Gpr, target: u32) -> Result<(), ModuleError> {
        let label = self.label(target);
        self.code.cbz(reg, label)?;
        Ok(())
    }

    /// Branches when the immediately preceding comparison guard failed.
    ///
    /// Comparison guards use x10 for their predicate so their X-register
    /// operands remain available on the failure edge.
    pub fn branch_if_guard_false(&mut self, target: u32) -> Result<(), ModuleError> {
        let label = self.label(target);
        self.code.cbz(Gpr::x(10), label)?;
        Ok(())
    }

    /// Emits the standard BEAM return and reduction accounting fragment.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:45-68, OTP-29.1.1
    pub fn return_(&mut self) -> Result<(), ModuleError> {
        self.emit_leave_frame()?;
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        self.code.emit(|e| e.str_uoff(Gpr::x(30), C_P, 72))?;
        let returned = self.code.new_label();
        self.code.b_cond(Cond::Pl, returned)?;
        self.code.b(self.yield_label)?;
        self.code.bind(returned)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })?;
        Ok(())
    }

    /// Emits a deallocation followed by the standard return.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:223-230 and instr_call.cpp:45-68, OTP-29.1.1
    pub fn deallocate_return(&mut self, words: u32) -> Result<(), ModuleError> {
        self.deallocate(words)?;
        self.return_()
    }

    /// Moves a value, deallocates the frame, and returns to the saved continuation.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:79-115, OTP-29.1.1
    pub fn move_deallocate_return(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        words: u32,
    ) -> Result<(), ModuleError> {
        self.move_(src, dst)?;
        self.deallocate_return(words)
    }

    /// Reserves stack words for a Y frame and initializes them to nil.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:218-221, OTP-29.1.1
    pub fn allocate(&mut self, words: u32, _live: u32) -> Result<(), ModuleError> {
        if words != 0 {
            let bytes = words
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("stack allocation overflow"))?;
            let imm = u16::try_from(bytes).map_err(|_| {
                ModuleError::InvalidOperand("stack allocation exceeds immediate range")
            })?;
            self.code.emit(|e| e.sub_imm(E, E, imm, false))?;
        }
        Ok(())
    }

    /// Checks stack and heap space before reserving a Y frame.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:218-221, OTP-29.1.1.
    pub fn allocate_checked(
        &mut self,
        words: u32,
        live: u32,
        hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_stack_check(words, live, hook)?;
        self.allocate(words, live)
    }

    /// Stack allocation variant with explicit nil initialization.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:218-221, OTP-29.1.1
    pub fn allocate_zero(&mut self, words: u32, _live: u32) -> Result<(), ModuleError> {
        self.allocate(words, 0)?;
        self.init_yregs(0, words)
    }

    /// Checks stack and heap space before reserving and initializing a Y frame.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:218-221, OTP-29.1.1.
    pub fn allocate_zero_checked(
        &mut self,
        words: u32,
        live: u32,
        hook: crate::construct::GcHook,
    ) -> Result<(), ModuleError> {
        self.emit_stack_check(words, live, hook)?;
        self.allocate_zero(words, live)
    }

    /// Releases stack words.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:223-230, OTP-29.1.1
    pub fn deallocate(&mut self, words: u32) -> Result<(), ModuleError> {
        if words != 0 {
            let bytes = words
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("stack deallocation overflow"))?;
            let imm = u16::try_from(bytes).map_err(|_| {
                ModuleError::InvalidOperand("stack deallocation exceeds immediate range")
            })?;
            self.code.emit(|e| e.add_imm(E, E, imm, false))?;
        }
        Ok(())
    }

    /// Removes words from the top of a frame, preserving the remaining Y slots.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:511-513, OTP-29.1.1
    pub fn trim(&mut self, words: u32, remaining: u32) -> Result<(), ModuleError> {
        for i in 0..remaining {
            self.move_(ArgVal::Y(i + words), ArgVal::Y(i))?;
        }
        self.deallocate(words)
    }

    /// Initializes Y slots to the nil immediate (`0x3b`).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:424-508, OTP-29.1.1
    pub fn init_yregs(&mut self, first: u32, count: u32) -> Result<(), ModuleError> {
        self.code.emit(|e| e.mov_const(TMP, 0x3b))?;
        for i in first..first.saturating_add(count) {
            let offset = i
                .checked_mul(8)
                .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
            self.code.emit(|e| e.str_uoff(TMP, E, offset))?;
        }
        Ok(())
    }

    /// Moves a typed value between X registers, Y slots, and immediates.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:760-780, OTP-29.1.1
    pub fn move_(&mut self, src: ArgVal, dst: ArgVal) -> Result<(), ModuleError> {
        let reg = match dst {
            ArgVal::X(i) if i < 6 => XREGS[i as usize],
            ArgVal::Y(i) => {
                let source = self.source_reg(src)?;
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.str_uoff(source, E, offset))?;
                return Ok(());
            }
            _ => return Err(ModuleError::InvalidOperand("destination must be X or Y")),
        };
        match src {
            ArgVal::X(i) if i < 6 => self.code.emit(|e| e.mov_reg(reg, XREGS[i as usize]))?,
            ArgVal::Immediate(v) | ArgVal::Literal(v) => self.code.emit(|e| e.mov_const(reg, v))?,
            ArgVal::Export(v) => self.code.emit(|e| e.mov_const(reg, u64::from(v)))?,
            ArgVal::Label(id) => {
                let label = self.label(id);
                self.code.adr(reg, label)?;
            }
            ArgVal::Y(i) => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.ldr_uoff(reg, E, offset))?;
            }
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "X register index must be below 6",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn source_reg(&mut self, src: ArgVal) -> Result<Gpr, ModuleError> {
        match src {
            ArgVal::X(i) if i < 6 => Ok(XREGS[i as usize]),
            ArgVal::Y(i) => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.ldr_uoff(TMP, E, offset))?;
                Ok(TMP)
            }
            ArgVal::Immediate(v) | ArgVal::Literal(v) => {
                self.code.emit(|e| e.mov_const(TMP, v))?;
                Ok(TMP)
            }
            ArgVal::Export(v) => {
                self.code.emit(|e| e.mov_const(TMP, u64::from(v)))?;
                Ok(TMP)
            }
            ArgVal::Label(id) => {
                let label = self.label(id);
                self.code.adr(TMP, label)?;
                Ok(TMP)
            }
            _ => Err(ModuleError::InvalidOperand("invalid move source")),
        }
    }

    /// Calls a C runtime hook with the process pointer in x0 and published BeamAsm state.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1
    pub(super) fn emit_runtime_hook(
        &mut self,
        helper: usize,
        args: &[Gpr],
    ) -> Result<(), ModuleError> {
        self.emit_runtime_fragment(helper, args)
    }

    pub(super) fn emit_runtime_hook_with(
        &mut self,
        helper: usize,
        args: &[Gpr],
        live: usize,
        update: crate::Update,
    ) -> Result<(), ModuleError> {
        self.emit_runtime_fragment_with(helper, args, live, update)
    }

    pub(super) fn emit_runtime_fragment(
        &mut self,
        fragment: usize,
        args: &[Gpr],
    ) -> Result<(), ModuleError> {
        self.emit_runtime_fragment_with(
            fragment,
            args,
            6,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::REDUCTIONS)
                .union(crate::Update::X_REGS),
        )
    }

    pub(super) fn emit_runtime_fragment_with(
        &mut self,
        fragment: usize,
        args: &[Gpr],
        live: usize,
        update: crate::Update,
    ) -> Result<(), ModuleError> {
        if args.len() > 5 {
            return Err(ModuleError::InvalidOperand(
                "runtime hook has too many arguments",
            ));
        }
        let error_label = self.error_label;
        crate::emit_enter_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            e.mov_const(Gpr::x(17), fragment as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.ldr_uoff(Gpr::x(9), C_P, 40)
        })?;
        self.code.cbnz(Gpr::x(9), error_label)?;
        Ok(())
    }

    /// Swaps two X/Y register values, including mixed register pairs.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:790-825, OTP-29.1.1
    pub fn swap(&mut self, left: ArgVal, right: ArgVal) -> Result<(), ModuleError> {
        let left_value = self.register_value(left)?;
        let right_value = self.register_value(right)?;
        self.load_register(left_value, TMP)?;
        self.load_register(right_value, Gpr::x(10))?;
        self.store_register(left_value, Gpr::x(10))?;
        self.store_register(right_value, TMP)
    }

    fn register_value(&self, arg: ArgVal) -> Result<ArgVal, ModuleError> {
        match arg {
            ArgVal::X(i) if i < 6 => Ok(arg),
            ArgVal::Y(_) => Ok(arg),
            _ => Err(ModuleError::InvalidOperand(
                "swap operands must be X or Y registers",
            )),
        }
    }

    fn load_register(&mut self, src: ArgVal, dst: Gpr) -> Result<(), ModuleError> {
        match src {
            ArgVal::X(i) if i < 6 => self.code.emit(|e| e.mov_reg(dst, XREGS[i as usize]))?,
            ArgVal::Y(i) => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.ldr_uoff(dst, E, offset))?;
            }
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "swap operands must be X or Y registers",
                ));
            }
        }
        Ok(())
    }

    fn store_register(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => self.code.emit(|e| e.mov_reg(XREGS[i as usize], src))?,
            ArgVal::Y(i) => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.str_uoff(src, E, offset))?;
            }
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "swap operands must be X or Y registers",
                ));
            }
        }
        Ok(())
    }

    /// Checks whether pending branch/literal stubs need to be emitted.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:796-814, OTP-29.1.1
    pub fn check_pending_stubs(&mut self) -> Result<(), ModuleError> {
        self.code.check_pending_stubs()?;
        Ok(())
    }

    /// Emits an encoded instruction sequence for specialized operations not yet wrapped here.
    pub fn emit_raw(
        &mut self,
        encode: impl FnOnce(&mut Emitter) -> Result<(), arinsal_a64::enc::EncodeError>,
    ) -> Result<(), ModuleError> {
        self.code.emit(encode)?;
        Ok(())
    }

    /// Finalizes veneers and copies the module into executable memory.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:556-610, 796-814, OTP-29.1.1
    pub fn finalize(mut self) -> Result<FinalizedModule, ModuleError> {
        let entry_label = self.yield_label;
        self.code.bind(entry_label)?;
        crate::emit_enter_runtime(
            &mut self.code,
            6,
            crate::Update::HEAP_ALLOC
                .union(crate::Update::REDUCTIONS)
                .union(crate::Update::X_REGS),
        )?;
        self.code.emit(|e| {
            e.mov_const(Gpr::x(0), 1)?;
            e.ldr_uoff(Gpr::x(30), SCHEDULER_REGS, 16_416)?;
            e.ret(Gpr::x(30))
        })?;
        self.code.bind(self.error_label)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ldr_uoff(Gpr::x(30), SCHEDULER_REGS, 16_416)?;
            e.br(Gpr::x(30))
        })?;
        let (mut words, labels) = self.code.finish_with_labels()?;
        // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:952-974 (patchCatches), OTP-29.1.1
        let catch_table = self
            .catch_patches
            .iter()
            .enumerate()
            .map(|(index, (offset, handler))| {
                let handler_offset = *labels.get(handler).expect("catch handler label is bound");
                let immediate = crate::catch::make_catch(index as u32);
                let word = offset / 4;
                words[word] = 0x5280_0009 | (((immediate & 0xffff) as u32) << 5);
                words[word + 1] = 0x72a0_0009 | ((((immediate >> 16) & 0xffff) as u32) << 5);
                handler_offset
            })
            .collect::<Vec<_>>();
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        if let Some(module) = &self.dump_module {
            let directory = std::env::var_os("ARINSAL_BEAMASM_DUMP")
                .expect("dump output directory was checked when enabled");
            crate::dump::write_module(Path::new(&directory), module, &self.dump_functions, &bytes)
                .map_err(ModuleError::Dump)?;
        }
        let mut memory = CodeMemory::new(bytes.len().max(4))?;
        let offset = memory.alloc(bytes.len().max(4))?;
        memory.write_bytes(offset, &bytes)?;
        let entry_offsets: HashMap<_, _> = self
            .labels
            .into_iter()
            .filter_map(|(id, label)| labels.get(&label).map(|&off| (id, offset + off)))
            .collect();
        let entries = entry_offsets
            .iter()
            .map(|(&id, &entry_offset)| (id, memory.ptr_at(entry_offset)))
            .collect();
        let lambda_entries = self
            .lambda_labels
            .into_iter()
            .filter_map(|(index, label)| {
                labels
                    .get(&label)
                    .map(|&lambda_offset| (index, memory.ptr_at(offset + lambda_offset)))
            })
            .collect();
        let catch_table = catch_table
            .into_iter()
            .map(|off| memory.ptr_at(offset + off))
            .collect();
        Ok(FinalizedModule {
            memory,
            entries,
            entry_offsets,
            lambda_entries,
            catch_table,
        })
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod runtime_sync_tests {
    use super::*;

    extern "C" fn update_runtime_state(
        header: *mut crate::ProcessHeader,
        registers: *mut crate::SchedulerRegisters,
    ) {
        crate::rt::process_header_mut(header, |header| {
            header.htop = 0x1234usize as *mut u64;
            header.stop = 0x5678usize as *mut u64;
            header.fcalls = 77;
        });
        crate::rt::scheduler_registers_mut(registers, |registers| {
            registers.x_reg_array[4] = 0x4444;
            registers.x_reg_array[5] = 0x5555;
        });
    }

    #[test]
    fn runtime_call_preserves_live_registers_and_reloads_updated_backing() {
        let mut assembler = BeamModuleAssembler::new();
        assembler.emit_i_func_label(1).unwrap();
        let update = crate::Update::HEAP_ALLOC
            .union(crate::Update::REDUCTIONS)
            .union(crate::Update::X_REGS);
        crate::emit_enter_runtime(&mut assembler.code, 6, update).unwrap();
        assembler
            .code
            .emit(|e| {
                e.mov_reg(Gpr::x(0), C_P)?;
                e.mov_reg(Gpr::x(1), SCHEDULER_REGS)?;
                e.str_uoff(Gpr::x(30), C_P, 72)?;
                e.mov_const(Gpr::x(17), update_runtime_state as *const () as u64)?;
                e.blr(Gpr::x(17))
            })
            .unwrap();
        crate::emit_leave_runtime(&mut assembler.code, 6, update).unwrap();
        assembler
            .code
            .emit(|e| {
                e.mov_reg(Gpr::x(0), Gpr::xzr())?;
                e.ldr_uoff(Gpr::x(30), C_P, 72)
            })
            .unwrap();
        assembler.code.emit(|e| e.ret(Gpr::x(30))).unwrap();
        let module = assembler.finalize().unwrap();
        let entry = module.entry(1).unwrap();
        let mut header = crate::ProcessHeader::default();
        let mut registers = crate::SchedulerRegisters::default();
        registers.x_reg_array[..6].copy_from_slice(&[11, 22, 33, 44, 55, 66]);

        assert_eq!(
            crate::enter_native(&mut header, &mut registers, &entry),
            crate::ExitReason::Returned
        );
        assert_eq!(registers.x_reg_array[..4], [11, 22, 33, 44]);
        assert_eq!(registers.x_reg_array[4..6], [0x4444, 0x5555]);
        assert_eq!(header.htop, 0x1234usize as *mut u64);
        assert_eq!(header.stop, 0x5678usize as *mut u64);
        assert_eq!(header.fcalls, 77);
    }
}
