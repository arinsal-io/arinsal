//! Module-local BeamAsm code generation for calls, frames, and register moves.

use std::collections::HashMap;
use std::path::Path;

use crate::rt::{arinsal_enter_native_return, arinsal_enter_native_yield};
use arinsal_a64::{
    buf::{BufferError, CodeBuffer, Label},
    enc::{Cond, Emitter, Gpr, Shift},
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

/// A destination of a paired load or store: a register-backed X register, or a temporary that
/// is written back to the memory slot of `slot`.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1472-1493 (Variable, init_destination),
// OTP-29.1.1.
#[derive(Clone, Copy)]
pub(super) struct PairVar {
    pub(super) reg: Gpr,
    slot: Option<ArgVal>,
}

/// Byte offset of a word from its base register for the operands that live in memory.
fn memory_slot(arg: ArgVal) -> Option<(Gpr, u32)> {
    match arg {
        ArgVal::Y(i) => i.checked_mul(8).map(|offset| (E, offset)),
        ArgVal::XMemory(i) => i.checked_mul(8).map(|offset| (SCHEDULER_REGS, offset)),
        _ => None,
    }
}

/// Typed operand accepted by the first BeamAsm emitter slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgVal {
    /// Register backed X value, numbered X0 through X5.
    X(u8),
    /// X value stored in the scheduler register array beyond the hardware cache.
    XMemory(u32),
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
    /// Static operand tables referenced by emitted `i_get_map_elements` instructions.
    pub map_lookups: Box<[crate::map::MapLookupTable]>,
    /// Native entry address by BEAM label number.
    pub entries: HashMap<u32, *const u8>,
    entry_offsets: HashMap<u32, usize>,
    /// Native trampoline by zero-based BEAM lambda-table index.
    pub lambda_entries: HashMap<u32, *const u8>,
    /// Native catch handler addresses in this module's `make_catch` order.
    pub catch_table: Vec<*const u8>,
    /// First globally unique catch index assigned to this module.
    pub catch_base: u32,
    /// Native code addresses associated with the nearest source line marker.
    pub line_table: Vec<ModuleLine>,
    /// Patch sites for per-function tracing breakpoints: label to entry word and skip branch.
    pub trace_breakpoints: HashMap<u32, (usize, u32)>,
    /// Patch sites of line breakpoints: source line, offset of the `b next` word and its
    /// original encoding (restored when the breakpoint is disabled).
    pub line_breakpoints: Vec<(u32, usize, u32)>,
    /// For each line-breakpoint site, ascending: the return-address offset after the `bl`
    /// and the branch site offset used to recover the instrumented function's source line.
    pub line_breakpoint_returns: Vec<(usize, usize)>,
    /// NIF load patch sites: function label to the word that skips the call-NIF body
    /// until `load_nif` replaces it with a NOP.
    pub nif_patches: HashMap<u32, usize>,
}

/// Source location attached to a native `line` instruction address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleLine {
    /// Byte offset from the start of the finalized code mapping.
    pub offset: usize,
    /// Source filename.
    pub file: String,
    /// One-based source line.
    pub line: u32,
}

impl FinalizedModule {
    /// Callable entry of the function at `label`: the code after its `i_func_info` slot.
    pub fn function_entry(&self, label: u32) -> Option<crate::NativeEntry<'_>> {
        self.entry_offsets
            .get(&label)
            .copied()
            .map(|offset| crate::NativeEntry {
                memory: &self.memory,
                offset: offset + FUNC_INFO_BYTES,
            })
    }

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
    pub(super) map_lookups: Vec<crate::map::MapLookupTable>,
    /// Failure label of the arithmetic instruction being emitted (0: raise the error).
    pub(super) arith_fail: u32,
    /// Compiler types of the next arithmetic instruction's operands, consumed by its emitter.
    pub(super) arith_types: Option<[crate::types::ArgType; 4]>,
    labels: HashMap<u32, Label>,
    defined: HashMap<u32, ()>,
    lambda_labels: HashMap<u32, Label>,
    lambda_specs: HashMap<u32, (u32, u8, u8)>,
    pub(super) defined_lambdas: HashMap<u32, ()>,
    pub(crate) yield_label: Label,
    /// Arity of the function being emitted: the live X registers at its `i_test_yield`.
    function_arity: u8,
    pub(super) error_label: Label,
    /// Address of `raise_exception_shared`'s resolver. `error_label` returns to the
    /// scheduler instead; the light-BIF fragment calls this when a catch is active.
    #[allow(dead_code)]
    exception_resolver: usize,
    catch_patches: Vec<(usize, Label)>,
    /// Shared out-of-line `function_clause` raiser, bound in `finalize` when any function uses it.
    func_clause_stub: Option<Label>,
    /// Shared `call_fun` error handler and its resolver, bound in `finalize` when used.
    call_fun_error_stub: Option<(Label, usize)>,
    /// Shared arithmetic slow-path fragments keyed by hook address and operation code.
    arith_fragments: Vec<((usize, u32), Label)>,
    /// Shared garbage-collection fragments of heap and stack checks, keyed by hook address.
    gc_fragments: Vec<(usize, Label)>,
    /// Module-local dispatch stubs for process-wide executable fragments.
    dispatch_fragments: HashMap<usize, Label>,
    /// Out-of-line `i_test_yield` continuations (stub, continuation, live X registers).
    yield_stubs: Vec<(Label, Label, u8)>,
    /// Failure and GC stubs for `bs_create_bin`, emitted with the yield stubs so the
    /// fall-through path is straight-line (erts `b.ls` / `b.ne` over a fragment).
    bs_cold: Vec<BsColdEmit>,
    line_table: Vec<ModuleLine>,
    trace_breakpoints: HashMap<u32, (usize, Label)>,
    /// Line, live count and word offset recorded by `i_debug_line` until its trampoline.
    pending_debug_line: Option<(u32, u16)>,
    line_breakpoints: Vec<(u32, usize, Label)>,
    line_breakpoint_returns: Vec<(usize, usize)>,
    nif_patches: HashMap<u32, usize>,
    current_function_label: Option<u32>,
    next_fresh_label: u32,
    dump_module: Option<String>,
    dump_functions: Vec<crate::dump::FunctionRecord>,
    dump_recording_function: bool,
}

/// Size of the `i_func_info` slot that precedes every function's call entry: the `ErtsCodeInfo`
/// of erts (a `bl`, the breakpoint flag, the generic breakpoint word and the 24-byte MFA).
pub const FUNC_INFO_BYTES: usize = 40;

type BsColdEmit = Box<dyn FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>>;
/// `tmp_mem[6]`: the native pc an exception is attributed to.
const NATIVE_ERROR_PC_SLOT: u32 = 16_432;
const TRAP_RETURN_SLOT: u32 = crate::TRAP_RETURN_OFFSET as u32;
/// Low bit of a recorded native error pc that is a call's return address (code is 4-aligned).
pub const RETURN_SITE_TAG: usize = 1;

/// erts `EXC_FUNCTION_CLAUSE` (error.h: `(6 << EXC_OFFSET) | EXC_ERROR`), OTP-29.1.1.
pub const EXC_FUNCTION_CLAUSE: u64 = (6 << 10) | 0x50;

impl Default for BeamModuleAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl BeamModuleAssembler {
    /// Loads the local node name from the word at `sysname` (`erts_this_node->sysname`).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:701-705, OTP-29.1.1.
    pub fn emit_node(&mut self, dst: ArgVal, sysname: usize) -> Result<(), ModuleError> {
        if sysname == 0 {
            return Err(ModuleError::InvalidOperand(
                "local node name word is missing",
            ));
        }
        self.code.emit(|e| {
            e.mov_const(Gpr::x(8), sysname as u64)?;
            e.ldr_uoff(Gpr::x(8), Gpr::x(8), 0)
        })?;
        self.store_register(dst, Gpr::x(8))
    }

    /// Creates an empty module assembler.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:84-104, OTP-29.1.1
    pub fn new() -> Self {
        let mut code = CodeBuffer::new();
        let yield_label = code.new_label();
        let error_label = code.new_label();
        Self {
            code,
            map_lookups: Vec::new(),
            labels: HashMap::new(),
            defined: HashMap::new(),
            lambda_labels: HashMap::new(),
            lambda_specs: HashMap::new(),
            defined_lambdas: HashMap::new(),
            yield_label,
            function_arity: 0,
            error_label,
            exception_resolver: 0,
            catch_patches: Vec::new(),
            func_clause_stub: None,
            call_fun_error_stub: None,
            arith_fragments: Vec::new(),
            dispatch_fragments: HashMap::new(),
            gc_fragments: Vec::new(),
            yield_stubs: Vec::new(),
            bs_cold: Vec::new(),
            line_table: Vec::new(),
            arith_fail: 0,
            arith_types: None,
            trace_breakpoints: HashMap::new(),
            pending_debug_line: None,
            line_breakpoints: Vec::new(),
            line_breakpoint_returns: Vec::new(),
            nif_patches: HashMap::new(),
            current_function_label: None,
            next_fresh_label: 0x7000_0000,
            dump_module: None,
            dump_functions: Vec::new(),
            dump_recording_function: false,
        }
    }

    /// Address of `handle_error`, used by the shared `error_label`.
    pub fn set_exception_resolver(&mut self, resolver: usize) {
        self.exception_resolver = resolver;
    }

    /// Points `error_label` at `resolver` when the module has not set one yet.
    pub(super) fn ensure_exception_resolver(&mut self, resolver: usize) {
        if self.exception_resolver == 0 && resolver != 0 {
            self.exception_resolver = resolver;
        }
    }

    /// Enables optional instruction-range capture for one module.
    pub fn enable_dump(&mut self, module: &str) {
        if crate::dump_directory().is_some() {
            self.dump_module = Some(module.to_owned());
        }
    }

    /// Reports whether this assembler is collecting optional dump metadata.
    pub fn dump_enabled(&self) -> bool {
        self.dump_module.is_some()
    }

    /// Records the native PC corresponding to a BEAM source line marker.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:612-620, OTP-29.1.1.
    pub fn record_line(&mut self, file: String, line: u32) {
        self.line_table.push(ModuleLine {
            offset: self.code.offset(),
            file,
            line,
        });
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
        if num_free > total_arity {
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

    /// Pads with NOPs to an 8-byte boundary, then binds a function's label: the start of its
    /// `i_func_info` slot.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:550-559 (emit_aligned_label and
    // emit_i_func_label), OTP-29.1.1.
    pub fn emit_i_func_label(&mut self, id: u32) -> Result<(), ModuleError> {
        while !self.code.offset().is_multiple_of(8) {
            self.code.emit(|e| {
                e.nop();
                Ok(())
            })?;
        }
        self.emit_label(id)?;
        self.current_function_label = Some(id);
        Ok(())
    }

    /// Binds a BEAM label at the current offset.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:541-548 (emit_label), OTP-29.1.1.
    pub fn emit_label(&mut self, id: u32) -> Result<(), ModuleError> {
        if self.defined.insert(id, ()).is_some() {
            return Err(ModuleError::DuplicateLabel(id));
        }
        let label = self.label(id);
        self.code.bind(label)?;
        Ok(())
    }

    /// Returns a label id that no BEAM label uses, for code the compiler synthesizes.
    pub fn fresh_label_id(&mut self) -> u32 {
        self.next_fresh_label += 1;
        self.next_fresh_label
    }

    /// Binds the aligned entry label without changing the owning function label.
    // Port of erts/emulator/beam/jit/arm/ops.tab:925-936, OTP-29.1.1.
    pub fn emit_i_entry_label(&mut self, id: u32) -> Result<(), ModuleError> {
        if self.defined.insert(id, ()).is_some() {
            return Err(ModuleError::DuplicateLabel(id));
        }
        let label = self.label(id);
        self.code.bind(label)?;
        Ok(())
    }

    /// Emits the patchable native entry trampoline used by local call tracing.
    ///
    /// Disabled, `b next` skips the call of the shared breakpoint fragment. Enabled, the
    /// branch becomes a NOP and the fragment runs the breakpoint, then returns to `next`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:231-250
    // (emit_i_breakpoint_trampoline), OTP-29.1.1.
    pub fn emit_i_breakpoint_trampoline(&mut self, fragment: usize) -> Result<(), ModuleError> {
        self.emit_enter_frame()?;
        let Some(function) = self.current_function_label else {
            return Err(ModuleError::InvalidOperand(
                "breakpoint trampoline has no owning function",
            ));
        };
        let patch = self.code.offset();
        let next = self.code.new_label();
        self.code.b(next)?;
        self.fragment_call(fragment)?;
        self.code.bind(next)?;
        if self
            .trace_breakpoints
            .insert(function, (patch, next))
            .is_some()
        {
            return Err(ModuleError::DuplicateLabel(function));
        }
        Ok(())
    }

    /// Records line metadata, loads the live count into `TMP1`, and aligns the next
    /// line-breakpoint trampoline so its branch can be rewritten atomically.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3203-3222 (emit_i_debug_line),
    // OTP-29.1.1.
    pub fn emit_i_debug_line(&mut self, line: u32, live: u16) -> Result<(), ModuleError> {
        self.pending_debug_line = Some((line, live));
        self.code
            .emit(|e| e.mov_const(Gpr::x(8), u64::from(live)))?;
        while !self.code.offset().is_multiple_of(8) {
            self.code.emit(|e| {
                e.nop();
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Emits the patchable line-breakpoint prologue that follows `i_debug_line`.
    ///
    /// Disabled, `b next` skips the shared line-breakpoint fragment. Enabled, the branch
    /// becomes a NOP and the fragment calls `erts_internal:breakpoint/4` in native code.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:337-348
    // (emit_i_line_breakpoint_trampoline), OTP-29.1.1.
    pub fn emit_i_line_breakpoint_trampoline(
        &mut self,
        fragment: usize,
    ) -> Result<(), ModuleError> {
        let Some((line, _live)) = self.pending_debug_line.take() else {
            return Err(ModuleError::InvalidOperand(
                "line breakpoint trampoline without i_debug_line",
            ));
        };
        let patch = self.code.offset();
        let next = self.code.new_label();
        self.code.b(next)?;
        self.fragment_call(fragment)?;
        self.code.bind(next)?;
        self.line_breakpoints.push((line, patch, next));
        self.line_breakpoint_returns.push((patch + 8, patch));
        Ok(())
    }

    /// Emits the call-NIF body of a function that `load_nif` may replace, behind a branch
    /// that skips it until the NIF is loaded.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:231-250 and erl_nif.c:5124-5196
    // (load_nif_1st_finisher copies the call_nif sequence behind the function prologue),
    // OTP-29.1.1: here the sequence is emitted up front and enabled by patching the branch.
    pub fn emit_nif_patch_site(
        &mut self,
        identity: usize,
        helper: usize,
        arity: usize,
    ) -> Result<(), ModuleError> {
        let Some(function) = self.current_function_label else {
            return Err(ModuleError::InvalidOperand(
                "NIF patch site has no owning function",
            ));
        };
        let patch = self.code.offset();
        let body = self.code.new_label();
        self.code.b(body)?;
        self.emit_call_nif_body(identity, helper, arity)?;
        self.code.bind(body)?;
        if self.nif_patches.insert(function, patch).is_some() {
            return Err(ModuleError::DuplicateLabel(function));
        }
        Ok(())
    }

    /// Emits the `ErtsCodeInfo` slot that precedes a function's entry: the `bl` into the
    /// function clause fragment, the breakpoint flag, the generic breakpoint word and the MFA.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:499-540 (emit_i_func_info) and
    // 484-497 (emit_i_func_info_shared), OTP-29.1.1: a failing head match branches here and
    // raises error:function_clause with the function's arguments as the top frame. Like erts'
    // `bl`, the link register points 4 bytes into the slot, inside the function's code range.
    pub fn emit_i_func_info(
        &mut self,
        _label: u32,
        module: u64,
        function: u64,
        arity: u8,
    ) -> Result<(), ModuleError> {
        self.function_arity = arity;
        let stub = match self.func_clause_stub {
            Some(stub) => stub,
            None => {
                let stub = self.code.new_label();
                self.func_clause_stub = Some(stub);
                stub
            }
        };
        let start = self.code.offset();
        self.code.bl(stub)?;
        self.code.emit(|e| {
            e.embed_uint32(0);
            e.embed_uint64(0);
            e.embed_uint64(module);
            e.embed_uint64(function);
            e.embed_uint64(u64::from(arity));
            Ok(())
        })?;
        debug_assert_eq!(self.code.offset() - start, FUNC_INFO_BYTES);
        Ok(())
    }

    /// Pushes the BEAM continuation pointer onto the Erlang stack.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:429-433, OTP-29.1.1
    pub fn emit_enter_frame(&mut self) -> Result<(), ModuleError> {
        self.code.emit(|e| e.str_pre(Gpr::x(30), E, -8))?;
        crate::emit_validate_native_cursor(&mut self.code)?;
        Ok(())
    }

    /// Pops the BEAM continuation pointer from the Erlang stack.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:429-433, OTP-29.1.1
    pub fn emit_leave_frame(&mut self) -> Result<(), ModuleError> {
        self.code.emit(|e| e.ldr_post(Gpr::x(30), E, 8))?;
        crate::emit_validate_native_cursor(&mut self.code)?;
        Ok(())
    }

    /// Emits a direct local call with an Erlang continuation on the stack.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:71-74, OTP-29.1.1
    pub fn call(&mut self, target: u32) -> Result<(), ModuleError> {
        crate::emit_validate_native_cursor(&mut self.code)?;
        let target_label = self.label(target);
        self.code.bl(target_label)?;
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
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:83-115 (emit_move_call_last), OTP-29.1.1
    pub fn move_call_last(
        &mut self,
        src: ArgVal,
        dst: ArgVal,
        target: u32,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        if let ArgVal::Y(src_index) = src
            && matches!(dst, ArgVal::X(_) | ArgVal::XMemory(_))
        {
            let bytes = u64::from(deallocate) * 8;
            if src_index == 0 && deallocate == 1 {
                let var = self.pair_destination(dst, TMP)?;
                self.code.emit(|e| e.ldp_post(var.reg, Gpr::x(30), E, 16))?;
                self.flush_var(var)?;
                return self.branch_to_label(target);
            } else if src_index == 0 && bytes < 256 {
                let var = self.pair_destination(dst, TMP)?;
                self.code.emit(|e| e.ldr_post(var.reg, E, bytes as i16))?;
                self.flush_var(var)?;
                return self.call_only(target);
            } else if src_index + 1 == deallocate {
                let var = self.pair_destination(dst, TMP)?;
                self.safe_ldp(var.reg, Gpr::x(30), E, src_index * 8)?;
                self.flush_var(var)?;
                let frame = (deallocate + 1) * 8;
                let imm = u16::try_from(frame).map_err(|_| {
                    ModuleError::InvalidOperand("stack deallocation exceeds immediate range")
                })?;
                self.code.emit(|e| e.add_imm(E, E, imm, false))?;
                return self.branch_to_label(target);
            }
        }
        self.move_(src, dst)?;
        self.call_last(target, deallocate)
    }

    fn branch_to_label(&mut self, target: u32) -> Result<(), ModuleError> {
        crate::emit_validate_native_cursor(&mut self.code)?;
        let target = self.label(target);
        self.code.b(target)?;
        Ok(())
    }

    /// Records this pc as the call site that names the calling function if the callee is a
    /// BIF that raises (erts keeps it in `c_p->i` for the BIF's stack frame).
    pub(crate) fn record_call_site(&mut self) -> Result<(), ModuleError> {
        let call_site = self.code.new_label();
        self.code.bind(call_site)?;
        self.code.adr(Gpr::x(9), call_site)?;
        self.code
            .emit(|e| e.str_uoff(Gpr::x(9), SCHEDULER_REGS, NATIVE_ERROR_PC_SLOT))?;
        Ok(())
    }

    /// Records the return address `ret` of a non-tail call as its call site, tagged with
    /// [`RETURN_SITE_TAG`]: erts attributes a raising BIF to the call's return address, which
    /// also hides that same continuation from the stacktrace (beam_common.c:792-835,
    /// OTP-29.1.1).
    pub(crate) fn record_return_site(&mut self, ret: Label) -> Result<(), ModuleError> {
        self.code.adr(Gpr::x(9), ret)?;
        self.code.emit(|e| {
            e.orr_imm(Gpr::x(9), Gpr::x(9), RETURN_SITE_TAG as u64)?;
            e.str_uoff(Gpr::x(9), SCHEDULER_REGS, NATIVE_ERROR_PC_SLOT)
        })?;
        Ok(())
    }

    /// Dispatches through the VM-owned native address word for an export.
    ///
    /// Port of erts/emulator/beam/jit/arm/instr_call.cpp:150-164 (emit_i_call_ext,
    /// emit_i_call_ext_only), OTP-29.1.1: the export is loaded into `x1` (ARG1), its address
    /// for the active code index is called or branched to, and nothing else is set up. The
    /// export trampoline and the other fragments between caller and callee take what they need
    /// from `x30`, which for a non-tail call is the return address (erts keeps it in the stack
    /// frame pushed by the trampoline). `x0` tells them which: `c_p` for a non-tail call, the
    /// address of this call site for a tail call, whose frame is gone and whose `x30` is the
    /// caller's continuation.
    pub fn dispatch_export(&mut self, entry: usize, tail: bool) -> Result<(), ModuleError> {
        if tail {
            let call_site = self.code.new_label();
            self.code.bind(call_site)?;
            self.code.adr(Gpr::x(0), call_site)?;
            self.emit_leave_frame()?;
        }
        self.code.emit(|e| {
            e.mov_const(Gpr::x(1), entry as u64)?;
            // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:388-403
            // (emit_setup_dispatchable_call), OTP-29.1.1.
            e.ldr_regoff(Gpr::x(14), Gpr::x(1), Gpr::x(24), 3)?;
            if tail {
                e.br(Gpr::x(14))
            } else {
                e.mov_reg(Gpr::x(0), C_P)?;
                e.blr(Gpr::x(14))
            }
        })?;
        Ok(())
    }

    /// Dispatches a light BIF without manufacturing an Erlang stack frame.
    ///
    /// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610 (emit_call_light_bif), OTP-29.1.1.
    /// The reduction check, the error pc and the trap continuation live in the shared
    /// fragment, the same place as `call_light_bif_shared`.
    pub fn dispatch_light_bif(
        &mut self,
        fragment: usize,
        identity: usize,
        arity: u8,
    ) -> Result<(), ModuleError> {
        // `arity` is `ExportEntry::arity`, published when the slot is created. The yield
        // path in the fragment loads it; the call site does not.
        let _ = arity;
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-609, OTP-29.1.1.
        let entry = self.code.new_label();
        self.code.bind(entry)?;
        // ARG4 = export. `mov` rather than a literal: the constant pool is flushed at
        // the end of the module, past the ±1MB literal reach on the largest OTP modules.
        // ARG3 = this entry (the address a yield resumes at).
        self.code
            .emit(|e| e.mov_const(Gpr::x(4), identity as u64))?;
        self.code.adr(Gpr::x(3), entry)?;
        // One module-local veneer per fragment. `x30` is the next instruction.
        self.fragment_call(fragment)
    }

    /// Calls `send/2` synchronously through its process-aware runtime helper.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624, OTP-29.1.1.
    pub fn dispatch_send(&mut self, fragment: usize, identity: usize) -> Result<(), ModuleError> {
        let call = self.code.new_label();
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        self.code.b_cond(Cond::Gt, call)?;
        self.code.adr(Gpr::x(8), call)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), C_P, 72))?;
        self.emit_yield_live(2)?;
        self.code.b(self.yield_label)?;
        self.code.bind(call)?;
        let done = self.code.new_label();
        self.code.adr(Gpr::x(9), done)?;
        self.code.emit(|e| {
            e.str_uoff(Gpr::x(9), SCHEDULER_REGS, TRAP_RETURN_SLOT)?;
            e.mov_const(Gpr::x(13), identity as u64)
        })?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), Gpr::x(13))?;
            // The send identity carries no export descriptor.
            e.mov_reg(Gpr::x(3), Gpr::xzr())?;
            e.mov_const(Gpr::x(17), fragment as u64)?;
            e.blr(Gpr::x(17))
        })?;
        self.code.emit(|e| e.ldr_uoff(Gpr::x(9), C_P, 40))?;
        self.error_if_nonzero(Gpr::x(9))?;
        self.code.emit(|e| e.mov_reg(XREGS[0], Gpr::x(0)))?;
        // A trapping send's target returns here with its result in XREG0.
        self.code.bind(done)?;
        Ok(())
    }

    /// Reads a process-dictionary value through the process runtime.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:319-329 (`emit_i_get`), OTP-29.1.1.
    // `emit_enter_runtime<>()` is an empty update set: `get/1` does not allocate, so
    // HTOP, E, FCALLS and the callee-saved X cache are not stored or reloaded.
    pub fn emit_process_dictionary_get(
        &mut self,
        source: ArgVal,
        destination: ArgVal,
        helper: usize,
    ) -> Result<(), ModuleError> {
        self.mov_arg_to_reg(Gpr::x(1), source)?;
        crate::emit_enter_runtime(&mut self.code, 6, crate::Update::NONE)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_const(Gpr::x(17), helper as u64)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 6, crate::Update::NONE)?;
        self.store_register(destination, Gpr::x(0))
    }

    /// Exits native execution so the scheduler can interpret a fun or apply call.
    pub fn call_fun_or_apply(&mut self, target_pc: usize) -> Result<(), ModuleError> {
        self.call_unported(target_pc)
    }

    /// Records the live X registers of a yielding continuation in `c_p->arity`, which the
    /// scheduler keeps across the context switch.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3097-3115 (i_test_yield) and
    // beam_asm_global.cpp (dispatch_bif, context_switch), OTP-29.1.1.
    pub(crate) fn emit_yield_live(&mut self, live: u8) -> Result<(), ModuleError> {
        self.code.emit(|e| {
            e.mov_const(Gpr::x(9), u64::from(live))?;
            e.strb_uoff(Gpr::x(9), C_P, 80)
        })?;
        Ok(())
    }

    /// Emits the out-of-line yield sequences of the function just ended, so that the
    /// `i_test_yield` branches stay within conditional-branch range.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp (emit_i_flush_stubs), OTP-29.1.1.
    pub fn flush_yield_stubs(&mut self) -> Result<(), ModuleError> {
        for (stub, continuation, live) in std::mem::take(&mut self.yield_stubs) {
            self.code.bind(stub)?;
            self.code.adr(Gpr::x(8), continuation)?;
            self.code.emit(|e| e.str_uoff(Gpr::x(8), C_P, 72))?;
            self.emit_yield_live(live)?;
            self.code.b(self.yield_label)?;
        }
        for emit in std::mem::take(&mut self.bs_cold) {
            emit(self)?;
        }
        Ok(())
    }

    /// Queues code that must not sit on a `bs_create_bin` fall-through path.
    pub(crate) fn push_bs_cold(&mut self, emit: BsColdEmit) {
        self.bs_cold.push(emit);
    }

    /// Checks reductions and saves the native continuation before yielding.
    pub fn test_yield(&mut self) -> Result<(), ModuleError> {
        // The yield sequence is out of line so the fall-through path has no taken branch,
        // like erts' `b.le` to the shared context-switch fragment.
        let continuation = self.code.new_label();
        let stub = self.code.new_label();
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        self.code.b_cond(Cond::Le, stub)?;
        self.code.bind(continuation)?;
        self.yield_stubs
            .push((stub, continuation, self.function_arity));
        Ok(())
    }

    /// `erlang:yield/0`: returns `true` after a context switch at the next instruction.
    // Port of erts/emulator/beam/emu/trace_instrs.tab:110 (i_yield) and
    // erts/emulator/beam/jit/arm/instr_common.cpp:3121 (emit_i_yield), OTP-29.1.1.
    pub fn emit_i_yield(&mut self) -> Result<(), ModuleError> {
        let continuation = self.code.new_label();
        let true_word = arinsal_term::Term::atom(arinsal_term::atoms::TRUE).tagged_word();
        self.code.emit(|e| e.mov_const(XREGS[0], true_word))?;
        self.code.adr(Gpr::x(8), continuation)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), C_P, 72))?;
        self.emit_yield_live(1)?;
        self.code.b(self.yield_label)?;
        self.code.bind(continuation)?;
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
            e.str_uoff(Gpr::x(0), SCHEDULER_REGS, 16_408)?;
            e.ret(Gpr::x(30))
        })?;
        self.code.bind(continuation)?;
        Ok(())
    }

    /// Emits a local tail call without pushing another continuation.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:118-123, OTP-29.1.1
    pub fn call_only(&mut self, target: u32) -> Result<(), ModuleError> {
        crate::emit_validate_native_cursor(&mut self.code)?;
        self.emit_leave_frame()?;
        let target = self.label(target);
        self.code.b(target)?;
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
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:30-66 (emit_dispatch_return,
    // emit_return), OTP-29.1.1.
    pub fn return_(&mut self) -> Result<(), ModuleError> {
        crate::emit_validate_native_cursor(&mut self.code)?;
        self.emit_leave_frame()?;
        // The yield path is the forward `b.mi`, so a return with reductions left falls
        // through to `ret`. erts keeps that sequence in the shared dispatch_return fragment.
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        let stub = self.code.new_label();
        self.code.b_cond(Cond::Mi, stub)?;
        self.code.emit(|e| e.ret(Gpr::x(30)))?;
        self.code.bind(stub)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(30), C_P, 72))?;
        self.emit_yield_live(1)?;
        self.code.b(self.yield_label)?;
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

    /// Removes words from the top of a frame by advancing the stack cursor.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1061-1073, OTP-29.1.1.
    pub fn trim(&mut self, words: u32, _remaining: u32) -> Result<(), ModuleError> {
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
            ArgVal::Y(_) | ArgVal::XMemory(_) => {
                let source = self.source_reg(src)?;
                return self.store_operand(dst, source);
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
            ArgVal::Y(_) | ArgVal::XMemory(_) => self.load_operand(src, reg)?,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "X register index must be below 6",
                ));
            }
        }
        Ok(())
    }

    /// Loads any source operand (cached X, X array, Y, immediate, literal, export or label)
    /// into `dst`.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1757-1762 (mov_arg(Gp, ArgVal)), OTP-29.1.1.
    pub fn mov_arg_to_reg(&mut self, dst: Gpr, src: ArgVal) -> Result<(), ModuleError> {
        let reg = self.source_reg_into(src, dst)?;
        if reg != dst {
            self.code.emit(|e| e.mov_reg(dst, reg))?;
        }
        Ok(())
    }

    /// Stores `src` into a register operand (cached X, X array or Y).
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1764-1767 (mov_arg(ArgVal, Gp)), OTP-29.1.1.
    pub fn mov_reg_to_arg(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        self.store_operand(dst, src)
    }

    /// Parallel move of two values: both sources are read before either destination is
    /// written (`load_two_xregs x10 x11 x11 x0` must read the old X11).
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:602-630 (emit_store_two_values,
    // emit_load_two_xregs), OTP-29.1.1.
    pub fn emit_store_two_values(
        &mut self,
        src1: ArgVal,
        dst1: ArgVal,
        src2: ArgVal,
        dst2: ArgVal,
    ) -> Result<(), ModuleError> {
        // Consecutive Y slots are one `stp`, the way flush_vars stores a register pair
        // (instr_common.cpp:602-614).
        if let (ArgVal::Y(first), ArgVal::Y(second)) = (dst1, dst2)
            && second == first + 1
            && let Ok(offset) = i16::try_from(first * 8)
            && (-512..504).contains(&offset)
        {
            let left = self.source_reg(src1)?;
            let right_scratch = if left == Gpr::x(10) {
                Gpr::x(11)
            } else {
                Gpr::x(10)
            };
            let right = self.source_reg_into(src2, right_scratch)?;
            self.code.emit(|e| e.stp(left, right, E, offset))?;
            return Ok(());
        }
        self.mov_arg_to_reg(TMP, src1)?;
        self.mov_arg_to_reg(Gpr::x(10), src2)?;
        self.store_operand(dst1, TMP)?;
        self.store_operand(dst2, Gpr::x(10))
    }

    /// Picks the register a destination is computed in: the register itself for a
    /// register-backed X register, `tmp` for one that lives in memory.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1482-1493 (init_destination), OTP-29.1.1.
    pub(super) fn pair_destination(&self, dst: ArgVal, tmp: Gpr) -> Result<PairVar, ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => Ok(PairVar {
                reg: XREGS[i as usize],
                slot: None,
            }),
            ArgVal::Y(_) | ArgVal::XMemory(_) => Ok(PairVar {
                reg: tmp,
                slot: Some(dst),
            }),
            _ => Err(ModuleError::InvalidOperand(
                "destination must be an X or Y register",
            )),
        }
    }

    /// Writes a destination back to memory when it does not live in a register.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1667-1673 (flush_var), OTP-29.1.1.
    pub(super) fn flush_var(&mut self, var: PairVar) -> Result<(), ModuleError> {
        if let Some(slot) = var.slot {
            self.store_operand(slot, var.reg)?;
        }
        Ok(())
    }

    /// Writes two destinations back to memory, as one `stp` when their slots are adjacent.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1696-1714 (flush_vars), OTP-29.1.1.
    pub(super) fn flush_vars(
        &mut self,
        first: PairVar,
        second: PairVar,
    ) -> Result<(), ModuleError> {
        if let (Some(slot1), Some(slot2)) = (first.slot, second.slot)
            && let (Some((base1, offset1)), Some((base2, offset2))) =
                (memory_slot(slot1), memory_slot(slot2))
            && base1 == base2
        {
            if offset1 + 8 == offset2 {
                return self.safe_stp(first.reg, second.reg, base1, offset1);
            } else if offset1 == offset2 + 8 {
                return self.safe_stp(second.reg, first.reg, base1, offset2);
            }
        }
        self.flush_var(first)?;
        self.flush_var(second)
    }

    /// Adds a byte offset that no load or store immediate reaches into x17.
    fn far_address(&mut self, base: Gpr, offset: u32) -> Result<Gpr, ModuleError> {
        let scratch = Gpr::x(17);
        self.code.emit(|e| {
            e.mov_const(scratch, u64::from(offset))?;
            e.add_reg(scratch, base, scratch, Shift::Lsl, 0)
        })?;
        Ok(scratch)
    }

    /// Loads two consecutive words, as one `ldp` when the offset is in its range.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1872-1896 (safe_ldp), OTP-29.1.1.
    pub(super) fn safe_ldp(
        &mut self,
        first: Gpr,
        second: Gpr,
        base: Gpr,
        offset: u32,
    ) -> Result<(), ModuleError> {
        if offset <= 8 * 0x3F {
            self.code
                .emit(|e| e.ldp(first, second, base, offset as i16))?;
        } else if offset < 8 * 0xFFF {
            self.code.emit(|e| {
                e.ldr_uoff(first, base, offset)?;
                e.ldr_uoff(second, base, offset + 8)
            })?;
        } else {
            let address = self.far_address(base, offset)?;
            self.code.emit(|e| e.ldp(first, second, address, 0))?;
        }
        Ok(())
    }

    /// Stores two consecutive words, as one `stp` when the offset is in its range.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1809-1826 (safe_stp), OTP-29.1.1.
    pub(super) fn safe_stp(
        &mut self,
        first: Gpr,
        second: Gpr,
        base: Gpr,
        offset: u32,
    ) -> Result<(), ModuleError> {
        if offset <= 8 * 0x3F {
            self.code
                .emit(|e| e.stp(first, second, base, offset as i16))?;
        } else if offset < 8 * 0xFFF {
            self.code.emit(|e| {
                e.str_uoff(first, base, offset)?;
                e.str_uoff(second, base, offset + 8)
            })?;
        } else {
            let address = self.far_address(base, offset)?;
            self.code.emit(|e| e.stp(first, second, address, 0))?;
        }
        Ok(())
    }

    /// Loads two consecutive memory words into two distinct X registers with one `ldp`.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:616-630 (emit_load_two_xregs),
    // OTP-29.1.1.
    pub fn emit_load_two_xregs(
        &mut self,
        src1: ArgVal,
        dst1: ArgVal,
        src2: ArgVal,
        dst2: ArgVal,
    ) -> Result<(), ModuleError> {
        let (Some((base, offset)), Some((base2, offset2))) = (memory_slot(src1), memory_slot(src2))
        else {
            return Err(ModuleError::InvalidOperand(
                "load_two_xregs sources must be memory words",
            ));
        };
        if base != base2 || offset + 8 != offset2 {
            return Err(ModuleError::InvalidOperand(
                "load_two_xregs sources must be consecutive",
            ));
        }
        let first = self.pair_destination(dst1, TMP)?;
        let second = self.pair_destination(dst2, Gpr::x(10))?;
        self.safe_ldp(first.reg, second.reg, base, offset)?;
        self.flush_vars(first, second)
    }

    pub(super) fn source_reg(&mut self, src: ArgVal) -> Result<Gpr, ModuleError> {
        self.source_reg_into(src, TMP)
    }

    /// Emits a `bl` to the module's shared garbage-collection fragment for `hook`.
    ///
    /// ARG3 (x8) holds `HTOP` plus the bytes the check needed, ARG4 (x3) the live X count.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:90-122 (`fragment_call` of
    // `ga->get_garbage_collect()`), OTP-29.1.1.
    pub(super) fn gc_fragment_call(&mut self, hook: usize) -> Result<(), ModuleError> {
        let label = match self.gc_fragments.iter().find(|(target, _)| *target == hook) {
            Some(&(_, label)) => label,
            None => {
                let label = self.code.new_label();
                self.gc_fragments.push((hook, label));
                label
            }
        };
        self.code.bl(label)?;
        Ok(())
    }

    /// Emits a direct call to a module-local stub for a process-wide executable fragment.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1440-1454 and
    // beam_asm_module.cpp:596-603,724-732 (fragment_call / resolve_fragment), OTP-29.1.1.
    pub(super) fn fragment_call(&mut self, target: usize) -> Result<(), ModuleError> {
        let label = match self.dispatch_fragments.get(&target) {
            Some(&label) => label,
            None => {
                let label = self.code.new_label();
                self.dispatch_fragments.insert(target, label);
                label
            }
        };
        self.code.bl(label)?;
        Ok(())
    }

    /// Like [`Self::source_reg`], but materializes memory and immediate operands in `scratch`
    /// so that two operands can be live at once.
    pub(super) fn source_reg_into(
        &mut self,
        src: ArgVal,
        scratch: Gpr,
    ) -> Result<Gpr, ModuleError> {
        match src {
            ArgVal::X(i) if i < 6 => Ok(XREGS[i as usize]),
            // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:252-259
            // (getXRef), OTP-29.1.1.
            ArgVal::XMemory(i) if i < 1024 => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("X register offset overflow"))?;
                self.code
                    .emit(|e| e.ldr_uoff(scratch, SCHEDULER_REGS, offset))?;
                Ok(scratch)
            }
            ArgVal::Y(i) => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.ldr_uoff(scratch, E, offset))?;
                Ok(scratch)
            }
            ArgVal::Immediate(v) | ArgVal::Literal(v) => {
                self.code.emit(|e| e.mov_const(scratch, v))?;
                Ok(scratch)
            }
            ArgVal::Export(v) => {
                self.code.emit(|e| e.mov_const(scratch, u64::from(v)))?;
                Ok(scratch)
            }
            ArgVal::Label(id) => {
                let label = self.label(id);
                self.code.adr(scratch, label)?;
                Ok(scratch)
            }
            _ => Err(ModuleError::InvalidOperand("invalid move source")),
        }
    }

    /// Calls a C runtime hook with the process pointer in x0 and published BeamAsm state.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-601, OTP-29.1.1
    /// Leaves the current instruction through `fail`, or raises `error:badarg` when there is
    /// no failure label.
    // Port of erts/emulator/beam/jit/arm/instr_guard_bifs.cpp (emit_raise_badarg / fail label), OTP-29.1.1.
    pub(super) fn emit_guard_fail(&mut self, fail: u32) -> Result<(), ModuleError> {
        if fail != 0 {
            let label = self.label(fail);
            self.code.b(label)?;
            return Ok(());
        }
        let badarg = arinsal_term::Term::atom(
            arinsal_term::global_atoms()
                .intern("badarg")
                .map_err(|_| ModuleError::InvalidOperand("badarg atom"))?,
        )
        .tagged_word();
        self.code.emit(|e| {
            e.mov_const(Gpr::x(9), 1)?;
            e.str_uoff(Gpr::x(9), C_P, 40)?;
            e.mov_const(Gpr::x(9), badarg)?;
            e.str_uoff(Gpr::x(9), C_P, 48)
        })?;
        self.branch_error()
    }

    /// Selects the failure label that arithmetic emitted next branches to instead of raising
    /// (guard context); 0 restores raising.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp (`Fail.get() != 0` guard variants),
    // OTP-29.1.1.
    pub fn set_arith_fail(&mut self, fail: u32) {
        self.arith_fail = fail;
    }

    /// Supplies the compiler types of the next arithmetic instruction's source operands
    /// (left, right); the next arithmetic emitter consumes them.
    // Port of erts/emulator/beam/jit/beam_jit_common.hpp:229-282 (getTypeEntry), OTP-29.1.1.
    pub fn set_arith_types(&mut self, lhs: crate::types::ArgType, rhs: crate::types::ArgType) {
        self.set_arith_types4([
            lhs,
            rhs,
            crate::types::ArgType::ANY,
            crate::types::ArgType::ANY,
        ]);
    }

    /// Supplies the compiler types of an `i_mul_add` (Src1, Src2, Src3, Src4).
    // Port of erts/emulator/beam/jit/beam_jit_common.hpp:229-282 (getTypeEntry), OTP-29.1.1.
    pub fn set_arith_types4(&mut self, types: [crate::types::ArgType; 4]) {
        self.arith_types = Some(types);
    }

    /// The label of the shared slow-path fragment calling `helper` with operation `op`
    /// (ARG2 = left, ARG3 = right, result in ARG1, pending exception flag in x9), created on
    /// first use and emitted by `finalize`.
    // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:114-143 (emit_plus_body_shared and
    // the other *_body_shared fragments), OTP-29.1.1
    pub(super) fn arith_fragment(&mut self, helper: usize, op: u32) -> Label {
        if let Some((_, label)) = self
            .arith_fragments
            .iter()
            .find(|(key, _)| *key == (helper, op))
        {
            return *label;
        }
        let label = self.code.new_label();
        self.arith_fragments.push(((helper, op), label));
        label
    }

    /// `init_destination`: the cached register of an X destination, otherwise `scratch`.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:1479-1491, OTP-29.1.1.
    pub(super) fn init_destination(&self, dst: ArgVal, scratch: Gpr) -> Gpr {
        match dst {
            ArgVal::X(i) if i < 6 => XREGS[i as usize],
            _ => scratch,
        }
    }

    /// Branches to the shared error exit when `reg` is nonzero, recording this pc for the
    /// stacktrace.
    pub(super) fn error_if_nonzero(&mut self, reg: Gpr) -> Result<(), ModuleError> {
        let ok = self.code.new_label();
        self.code.cbz(reg, ok)?;
        self.branch_error()?;
        self.code.bind(ok)?;
        Ok(())
    }

    /// Branches to the shared error exit, recording the address of this instruction in LR so
    /// the raised exception can name its source line.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp (emit_raise_exception ARG2 = pc), OTP-29.1.1.
    pub(super) fn branch_error(&mut self) -> Result<(), ModuleError> {
        let here = self.code.new_label();
        self.code.bind(here)?;
        self.code.adr(Gpr::x(30), here)?;
        self.code.b(self.error_label)?;
        Ok(())
    }

    /// Branches to the shared error exit with LR already holding the raising pc.
    pub(super) fn branch_error_from_lr(&mut self) -> Result<(), ModuleError> {
        self.code.b(self.error_label)?;
        Ok(())
    }

    /// The module's shared `call_fun` error handler (`handle_call_fun_error`).
    pub(super) fn call_fun_error_label(&mut self, helper: usize) -> Label {
        if let Some((label, _)) = self.call_fun_error_stub {
            return label;
        }
        let label = self.code.new_label();
        self.call_fun_error_stub = Some((label, helper));
        label
    }

    pub(super) fn emit_runtime_hook_with(
        &mut self,
        helper: usize,
        args: &[Gpr],
        live: usize,
        update: crate::Update,
    ) -> Result<(), ModuleError> {
        self.emit_runtime_fragment_with(helper, args, live, update)
            .map(|_| ())
    }

    /// Returns the code offset of the fragment call's return address.
    pub(super) fn emit_runtime_fragment_with(
        &mut self,
        fragment: usize,
        args: &[Gpr],
        live: usize,
        update: crate::Update,
    ) -> Result<usize, ModuleError> {
        if args.len() > 5 {
            return Err(ModuleError::InvalidOperand(
                "runtime hook has too many arguments",
            ));
        }
        crate::emit_enter_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            // Fragments reading a descriptor in x3 see none from a call that passes fewer.
            for index in args.len()..3 {
                e.mov_reg(Gpr::x(index as u8 + 1), Gpr::xzr())?;
            }
            e.mov_const(Gpr::x(17), fragment as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        let return_address = self.code.offset();
        crate::emit_leave_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), C_P, 72)?;
            e.ldr_uoff(Gpr::x(9), C_P, 40)
        })?;
        self.error_if_nonzero(Gpr::x(9))?;
        Ok(return_address)
    }

    /// Calls a loader-patched static NIF body through the process runtime.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900, OTP-29.1.1.
    pub fn emit_native_body(
        &mut self,
        identity: usize,
        helper: usize,
        arity: usize,
    ) -> Result<(), ModuleError> {
        if arity > 6 {
            return Err(ModuleError::InvalidOperand(
                "native body arity exceeds X register ABI",
            ));
        }
        self.emit_call_nif_body(identity, helper, arity)
    }

    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900 (call_nif), OTP-29.1.1: the
    // arguments above the register cache are already in the X register array.
    fn emit_call_nif_body(
        &mut self,
        identity: usize,
        helper: usize,
        arity: usize,
    ) -> Result<(), ModuleError> {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:924-952 (emit_call_nif_yield_helper),
        // OTP-29.1.1: `FCALLS--` and a context switch when it reaches zero, before the NIF
        // runs; the process resumes here with its arguments in the X registers.
        let continuation = self.code.new_label();
        let stub = self.code.new_label();
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        self.code.b_cond(Cond::Le, stub)?;
        self.code.bind(continuation)?;
        self.yield_stubs.push((
            stub,
            continuation,
            u8::try_from(arity).map_err(|_| {
                ModuleError::InvalidOperand("native body arity exceeds X register ABI")
            })?,
        ));
        let update = crate::Update::HEAP_ALLOC
            .union(crate::Update::REDUCTIONS)
            .union(crate::Update::X_REGS);
        self.code
            .emit(|e| e.mov_const(Gpr::x(13), identity as u64))?;
        // The helper may set c_p->i to a trap target, so the return address is kept on the
        // machine stack instead of being reloaded from c_p->i.
        self.code
            .emit(|e| e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16))?;
        crate::emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), C_P)?;
            e.mov_reg(Gpr::x(1), Gpr::x(13))?;
            e.mov_const(Gpr::x(17), helper as u64)?;
            e.str_uoff(Gpr::x(30), C_P, 72)?;
            e.blr(Gpr::x(17))
        })?;
        crate::emit_leave_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
            e.ldr_uoff(Gpr::x(9), C_P, 40)
        })?;
        // Port of erts/emulator/beam/erl_nif.c (schedule_dirty_nif), OTP-29.1.1: a dirty NIF
        // called on a normal scheduler traps to the executor, which runs it on a dirty
        // scheduler and resumes at `resume` with the result in x0.
        let not_trap = self.code.new_label();
        let resume = self.code.new_label();
        self.code
            .emit(|e| e.cmp_imm(Gpr::x(9), crate::dispatch::TRAP_REASON, false))?;
        self.code.b_cond(Cond::Ne, not_trap)?;
        // Same context switch as a trapping light BIF (instr_bif.cpp:533-540): the resume
        // point is pushed on E and handed over as the exit's continuation.
        self.code.adr(Gpr::x(2), resume)?;
        self.code.emit(|e| {
            e.str_pre(Gpr::x(2), E, -8)?;
            e.str_uoff(Gpr::xzr(), C_P, 40)?;
            e.mov_const(
                Gpr::x(1),
                crate::dispatch::DIRTY_NIF_DISPATCH_IDENTITY as u64,
            )?;
            e.mov_const(Gpr::x(0), 2)?;
            e.str_uoff(Gpr::x(0), SCHEDULER_REGS, 16_408)?;
            e.mov_const(Gpr::x(17), arinsal_enter_native_return as *const () as u64)?;
            e.br(Gpr::x(17))
        })?;
        self.code.bind(not_trap)?;
        self.error_if_nonzero(Gpr::x(9))?;
        self.code.bind(resume)?;
        self.emit_leave_frame()?;
        self.code.emit(|e| e.ret(Gpr::x(30)))?;
        Ok(())
    }

    /// Swaps two X/Y register values, including mixed register pairs.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:632-648 (emit_swap), OTP-29.1.1
    pub fn swap(&mut self, left: ArgVal, right: ArgVal) -> Result<(), ModuleError> {
        let left = self.register_value(left)?;
        let right = self.register_value(right)?;
        if let ArgVal::X(index) = left {
            let register = XREGS[index as usize];
            self.load_register(right, TMP)?;
            self.store_register(right, register)?;
            self.code.emit(|e| e.mov_reg(register, TMP))?;
            return Ok(());
        }
        if matches!(right, ArgVal::X(_)) {
            return self.swap(right, left);
        }
        let second_tmp = Gpr::x(10);
        match (memory_slot(left), memory_slot(right)) {
            (Some((base1, offset1)), Some((base2, offset2))) if base1 == base2 => {
                if offset1 + 8 == offset2 {
                    self.safe_ldp(TMP, second_tmp, base1, offset1)?;
                } else if offset1 == offset2 + 8 {
                    self.safe_ldp(second_tmp, TMP, base1, offset2)?;
                } else {
                    self.load_register(left, TMP)?;
                    self.load_register(right, second_tmp)?;
                }
            }
            _ => {
                self.load_register(left, TMP)?;
                self.load_register(right, second_tmp)?;
            }
        }
        let into_right = PairVar {
            reg: TMP,
            slot: Some(right),
        };
        let into_left = PairVar {
            reg: second_tmp,
            slot: Some(left),
        };
        self.flush_vars(into_right, into_left)
    }

    fn register_value(&self, arg: ArgVal) -> Result<ArgVal, ModuleError> {
        match arg {
            ArgVal::X(i) if i < 6 => Ok(arg),
            ArgVal::Y(_) => Ok(arg),
            ArgVal::XMemory(i) if i < 1024 => Ok(arg),
            _ => Err(ModuleError::InvalidOperand(
                "swap operands must be X or Y registers",
            )),
        }
    }

    fn load_register(&mut self, src: ArgVal, dst: Gpr) -> Result<(), ModuleError> {
        self.load_operand(src, dst)
    }

    pub(super) fn store_register(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        self.store_operand(dst, src)
    }

    /// Loads an X register (cached or in the scheduler register array) or a Y slot into `dst`.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:252-276 (getXRef, getYRef), OTP-29.1.1.
    pub(super) fn load_operand(&mut self, src: ArgVal, dst: Gpr) -> Result<(), ModuleError> {
        match src {
            ArgVal::X(i) if i < 6 => {
                if dst != XREGS[i as usize] {
                    self.code.emit(|e| e.mov_reg(dst, XREGS[i as usize]))?;
                }
            }
            ArgVal::XMemory(i) if i < 1024 => {
                self.code.emit(|e| e.ldr_uoff(dst, SCHEDULER_REGS, i * 8))?;
            }
            ArgVal::Y(i) => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.ldr_uoff(dst, E, offset))?;
            }
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "operand must be an X or Y register",
                ));
            }
        }
        Ok(())
    }

    /// Stores `src` into an X register (cached or in the scheduler register array) or a Y slot.
    // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:252-276 (getXRef, getYRef), OTP-29.1.1.
    pub(super) fn store_operand(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => {
                if src != XREGS[i as usize] {
                    self.code.emit(|e| e.mov_reg(XREGS[i as usize], src))?;
                }
            }
            ArgVal::XMemory(i) if i < 1024 => {
                self.code.emit(|e| e.str_uoff(src, SCHEDULER_REGS, i * 8))?;
            }
            ArgVal::Y(i) => {
                let offset = i
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code.emit(|e| e.str_uoff(src, E, offset))?;
            }
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "destination must be an X or Y register",
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
        // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:484-497 (emit_i_func_info_shared),
        // OTP-29.1.1: freason = EXC_FUNCTION_CLAUSE, then the shared exception exit. The runtime
        // takes the argument list from the published X registers and the function from the pc.
        let function_clause = arinsal_term::Term::atom(
            arinsal_term::global_atoms()
                .intern("function_clause")
                .map_err(|_| ModuleError::InvalidOperand("function_clause atom"))?,
        )
        .tagged_word();
        if let Some(stub) = self.func_clause_stub.take() {
            self.code.bind(stub)?;
            self.code.emit(|e| {
                e.mov_const(Gpr::x(8), EXC_FUNCTION_CLAUSE)?;
                e.str_uoff(Gpr::x(8), Gpr::x(21), 40)?;
                e.mov_const(Gpr::x(8), function_clause)?;
                e.str_uoff(Gpr::x(8), Gpr::x(21), 48)
            })?;
            // x30 points 4 bytes into the function's `i_func_info` slot (the `bl` in
            // `emit_i_func_info`). Registered native function ranges start at the entry after
            // the slot, so the recorded pc is moved there.
            self.code
                .emit(|e| e.add_imm(Gpr::x(30), Gpr::x(30), (FUNC_INFO_BYTES - 4) as u16, false))?;
            self.code.b(self.error_label)?;
        }
        self.flush_yield_stubs()?;
        if let Some((label, helper)) = self.call_fun_error_stub.take() {
            self.code.bind(label)?;
            crate::fun::emit_call_fun_error(&mut self, helper)?;
        }
        let gc_fragments = std::mem::take(&mut self.gc_fragments);
        for (hook, label) in gc_fragments {
            self.code.bind(label)?;
            self.emit_garbage_collect_fragment(hook)?;
        }
        let fragments = std::mem::take(&mut self.arith_fragments);
        for ((helper, op), label) in fragments {
            self.code.bind(label)?;
            let update = crate::Update::HEAP_ALLOC.union(crate::Update::REDUCTIONS);
            self.code
                .emit(|e| e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16))?;
            crate::emit_enter_runtime(&mut self.code, 6, update)?;
            self.code.emit(|e| {
                // x3 is the third operand (mul-add increment, int128 sign); unused ops ignore it.
                e.mov_reg(Gpr::x(4), Gpr::x(3))?;
                e.mov_reg(Gpr::x(0), C_P)?;
                e.mov_const(Gpr::x(1), u64::from(op))?;
                e.mov_reg(Gpr::x(2), Gpr::x(14))?;
                e.mov_reg(Gpr::x(3), Gpr::x(17))?;
                e.mov_const(Gpr::x(17), helper as u64)?;
                e.str_uoff(Gpr::x(30), C_P, 72)?;
                e.blr(Gpr::x(17))
            })?;
            crate::emit_leave_runtime(&mut self.code, 6, update)?;
            self.code.emit(|e| {
                e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
                e.ldr_uoff(Gpr::x(9), C_P, 40)?;
                e.ret(Gpr::x(30))
            })?;
        }
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
            e.mov_const(Gpr::x(30), arinsal_enter_native_yield as *const () as u64)?;
            e.ret(Gpr::x(30))
        })?;
        self.code.bind(self.error_label)?;
        // The scheduler runs `handle_error`. Resolving the catch in this fragment
        // drops the BIF frame and `function_clause` argument list the scheduler records.
        self.code.emit(|e| {
            e.str_uoff(Gpr::x(30), SCHEDULER_REGS, 16_432)?;
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ldr_uoff(Gpr::x(30), SCHEDULER_REGS, 16_416)?;
            e.br(Gpr::x(30))
        })?;
        let dispatch_fragments = std::mem::take(&mut self.dispatch_fragments);
        for (target, label) in dispatch_fragments {
            self.code.bind(label)?;
            self.code.emit(|e| {
                e.mov_const(Gpr::x(17), target as u64)?;
                e.br(Gpr::x(17))
            })?;
        }
        let (mut words, labels) = self.code.finish_with_labels()?;
        let trace_breakpoints = self
            .trace_breakpoints
            .iter()
            .filter_map(|(&function, &(offset, next))| {
                let next_offset = *labels.get(&next)?;
                let branch_offset = offset;
                let delta = i64::try_from(next_offset).ok()? - i64::try_from(branch_offset).ok()?;
                let immediate = u32::try_from(delta / 4).ok()?;
                let branch = 0x1400_0000 | (immediate & 0x03ff_ffff);
                Some((function, (offset, branch)))
            })
            .collect::<HashMap<_, _>>();
        let line_breakpoints = self
            .line_breakpoints
            .iter()
            .filter_map(|&(line, offset, next)| {
                let delta =
                    i64::try_from(*labels.get(&next)?).ok()? - i64::try_from(offset).ok()?;
                let immediate = u32::try_from(delta / 4).ok()?;
                Some((line, offset, 0x1400_0000 | (immediate & 0x03ff_ffff)))
            })
            .collect::<Vec<_>>();
        let catch_base = crate::catch::reserve_catch_indices(self.catch_patches.len())?;
        // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:952-974 (patchCatches), OTP-29.1.1
        let catch_table = self
            .catch_patches
            .iter()
            .enumerate()
            .map(|(index, (offset, handler))| {
                let handler_offset = *labels.get(handler).expect("catch handler label is bound");
                let catch_index = catch_base + index as u32;
                let immediate = crate::catch::make_catch(catch_index);
                let word = offset / 4;
                words[word] = 0x5280_0009 | (((immediate & 0xffff) as u32) << 5);
                words[word + 1] = 0x72a0_0009 | ((((immediate >> 16) & 0xffff) as u32) << 5);
                handler_offset
            })
            .collect::<Vec<_>>();
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        if let Some(module) = &self.dump_module {
            let directory =
                crate::dump_directory().expect("dump output directory was checked when enabled");
            crate::dump::write_module(Path::new(directory), module, &self.dump_functions, &bytes)
                .map_err(ModuleError::Dump)?;
        }
        let mut memory = CodeMemory::new(bytes.len().max(4))?;
        let offset = memory.alloc(bytes.len().max(4))?;
        memory.write_bytes(offset, &bytes)?;
        if let Some(module) = &self.dump_module
            && let Some(directory) = crate::dump_directory()
        {
            let _ = std::fs::write(
                Path::new(directory).join(format!("{module}.base")),
                format!("{:x}\n", memory.ptr_at(offset) as usize),
            );
        }
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
            map_lookups: self.map_lookups.into_boxed_slice(),
            entries,
            entry_offsets,
            lambda_entries,
            catch_table,
            catch_base,
            line_table: self
                .line_table
                .into_iter()
                .map(|mut entry| {
                    entry.offset += offset;
                    entry
                })
                .collect(),
            trace_breakpoints,
            line_breakpoints,
            line_breakpoint_returns: self.line_breakpoint_returns,
            nif_patches: self.nif_patches,
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
            registers.x_reg_array[4] = crate::rt::fixture_term(0x4444);
            registers.x_reg_array[5] = crate::rt::fixture_term(0x5555);
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
        registers.x_reg_array[..6].copy_from_slice(&[
            crate::rt::fixture_term(11),
            crate::rt::fixture_term(22),
            crate::rt::fixture_term(33),
            crate::rt::fixture_term(44),
            crate::rt::fixture_term(55),
            crate::rt::fixture_term(66),
        ]);

        assert_eq!(
            crate::enter_native(&mut header, &mut registers, &entry),
            crate::ExitReason::Returned
        );
        assert_eq!(
            crate::rt::fixture_words(&registers.x_reg_array[..4]),
            [11, 22, 33, 44]
        );
        assert_eq!(
            crate::rt::fixture_words(&registers.x_reg_array[4..6]),
            [0x4444, 0x5555]
        );
        assert_eq!(header.htop, 0x1234usize as *mut u64);
        assert_eq!(header.stop, 0x5678usize as *mut u64);
        assert_eq!(header.fcalls, 77);
    }
}
