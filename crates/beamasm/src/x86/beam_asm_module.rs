//! Port of the x86 `BeamModuleAssembler` state and patch sites: `BeamModuleAssemblerCommon`
//! of erts/emulator/beam/jit/beam_jit_common.hpp (rawLabels, patch lists), the constructor
//! of erts/emulator/beam/jit/beam_jit_common.cpp (label creation) and
//! erts/emulator/beam/jit/x86/beam_asm.hpp (make_move_patch, make_word_patch,
//! resolve_beam_label), OTP-29.1.1.

use std::collections::HashMap;

use arinsal_term::Atom;
use arinsal_x64::buf::{Label, Section};
use arinsal_x64::enc::{CondCode, Gp, Mem, MemBase};

use super::beam_asm::register::{
    ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, C_P, E, HTOP, REGISTERS, RET, TMP1, TMP2,
};
use super::beam_asm::{
    AsmError, BeamAssembler, Distance, Update, get_arg_ref, get_y_ref, tmp_mem_q,
};
use super::beam_asm_global::{BeamGlobalAssembler, GLOBAL_LABELS, GlobalLabels};
use super::raw;
pub use super::rt::{addr, beam_catches_cons, beam_catches_cons_nil, i_emit_nyi};
use crate::common::args::{ArgVal, REG_MASK};
use crate::common::beam_asm_h::{
    BEAM_ASM_FUNC_PROLOGUE_SIZE, BEAM_NATIVE_MIN_FUNC_SZ, ERTS_ASM_BP_FLAG_BP,
    ERTS_ASM_BP_FLAG_BP_NIF_CALL_NIF_EARLY, ERTS_ASM_BP_FLAG_CALL_NIF_EARLY, ERTS_ASM_BP_FLAG_NONE,
    ErtsCodeInfo,
};
use crate::common::register_cache::{CacheMem, RegisterCache};
use crate::common::types::{ArgType, BeamModuleAssemblerCommon};

/// `struct patch`: a word in the code to fill in once the value is known, `ptr_offs` bytes
/// after the label `where`, with `val_offs` added to the value.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:141-145 (struct patch), OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patch {
    /// `where`.
    pub at: Label,
    /// `ptr_offs`.
    pub ptr_offs: usize,
    /// `val_offs`.
    pub val_offs: usize,
}

/// `BeamModuleAssemblerCommon::patch_lambda`: uses of an `ArgLambda` and the entry label used
/// by `call_fun2` for that lambda.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:158-165 (struct patch_lambda), OTP-29.1.1.
#[derive(Debug)]
pub struct LambdaPatch {
    /// The immediate pointer patch sites for the lambda's `ErlFunEntry`.
    pub patches: Vec<Patch>,
    /// The direct body label for a zero-environment lambda or its environment-unpacking
    /// trampoline for a local closure.
    pub trampoline: Label,
}

impl super::beam_asm_global::BeamGlobalAssembler {
    /// Raises `function_clause` for the function whose `ErtsCodeInfo` called here: the
    /// return address of that call, with the call's offset masked off, is the code info.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:451-466 (emit_i_func_info_shared),
    // OTP-29.1.1.
    pub(crate) fn emit_i_func_info_shared(&mut self) -> Result<(), AsmError> {
        use super::beam_asm::register::ARG2;
        use super::beam_asm::{process, process_ref};
        let a = &mut self.asm;
        a.emit(|e| e.pop_r(ARG1))?;
        a.emit(|e| e.and_ri(ARG1, !0x7))?;
        let mfa = core::mem::offset_of!(ErtsCodeInfo, mfa) as i64;
        a.emit(|e| e.add_ri(ARG1, mfa))?;
        a.emit(|e| {
            e.mov_mi(
                process_ref(process::FREASON, 8),
                crate::exc::EXC_FUNCTION_CLAUSE as i64,
            )
        })?;
        a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG1))?;
        a.mov_imm(ARG2, 0)?;
        a.mov_imm(ARG4, 0)?;
        let label = self.label(super::beam_asm_global::GlobalLabels::RaiseExceptionShared);
        self.asm.jmp(label)
    }
}

impl super::beam_asm_global::BeamGlobalAssembler {
    /// Dispatches an enabled function prologue on the breakpoint flag of its `ErtsCodeInfo`,
    /// found from the return address of the prologue's call.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:166-209
    // (emit_i_breakpoint_trampoline_shared), OTP-29.1.1.
    pub(crate) fn emit_i_breakpoint_trampoline_shared(&mut self) -> Result<(), AsmError> {
        use super::beam_asm::register::RETD;
        use super::beam_asm_global::GlobalLabels;
        use arinsal_x64::enc::{CondCode, byte_ptr, qword_ptr};
        // `offsetof(ErtsCodeInfo, u.metadata.breakpoint_flag)` is the last byte of `u`.
        let flag_offset =
            (core::mem::size_of::<ErtsCodeInfo>() as i32) + BEAM_ASM_FUNC_PROLOGUE_SIZE as i32 - 7;
        let generic_bp_local = self.label(GlobalLabels::GenericBpLocal);
        let call_nif_early = self.label(GlobalLabels::CallNifEarly);
        let a = &mut self.asm;
        let (bp_and_nif, bp_only, nif_only) = (a.new_label(), a.new_label(), a.new_label());
        a.emit(|e| e.mov_rm(RET, qword_ptr(arinsal_x64::enc::RSP, 0)))?;
        a.emit(|e| e.movzx_rm(RETD, byte_ptr(RET, -flag_offset)))?;
        a.emit(|e| e.cmp_ri(RETD, i64::from(ERTS_ASM_BP_FLAG_BP_NIF_CALL_NIF_EARLY)))?;
        a.short_jcc(CondCode::E, bp_and_nif)?;
        a.emit(|e| e.cmp_ri(RETD, i64::from(ERTS_ASM_BP_FLAG_CALL_NIF_EARLY)))?;
        a.short_jcc(CondCode::E, nif_only)?;
        a.emit(|e| e.cmp_ri(RETD, i64::from(ERTS_ASM_BP_FLAG_BP)))?;
        a.short_jcc(CondCode::E, bp_only)?;
        a.emit(|e| e.ret())?;

        a.bind(bp_and_nif)?;
        a.aligned_call_label(generic_bp_local)?;
        // Falls through: call_nif_early returns on its own, unlike generic_bp_local.
        a.bind(nif_only)?;
        a.jmp(call_nif_early)?;

        a.bind(bp_only)?;
        a.aligned_call_label(generic_bp_local)?;
        a.emit(|e| e.ret())
    }

    /// Prepares a line-breakpoint call, lets its cleanup fragment restore live X registers,
    /// and returns to the interrupted native code.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:233-328
    // (emit_i_line_breakpoint_trampoline_shared), OTP-29.1.1.
    pub(crate) fn emit_i_line_breakpoint_trampoline_shared(&mut self) -> Result<(), AsmError> {
        let (exit_trampoline, dealloc_and_exit_trampoline, after_gc_check, dispatch_call) = {
            let a = &mut self.asm;
            (a.new_label(), a.new_label(), a.new_label(), a.new_label())
        };
        let saved_live = tmp_mem_q(0);
        let saved_pc = tmp_mem_q(1);
        let saved_stack_needed = tmp_mem_q(2);
        let cleanup = self.label(GlobalLabels::ILineBreakpointCleanup);
        let garbage_collect = self.label(GlobalLabels::GarbageCollect);
        let a = &mut self.asm;

        a.emit_enter_frame()?;
        a.emit(|e| e.mov_mr(saved_live, TMP1))?;
        a.emit(|e| e.mov_rm(TMP2, get_y_ref(0, 8)))?;
        a.emit(|e| e.sub_ri(TMP2, 8))?;
        a.emit(|e| e.mov_mr(saved_pc, TMP2))?;

        // x86-64 BeamAsm uses the native stack, so the reserved CP-space term is zero.
        a.emit(|e| e.mov_rr(ARG4, TMP1))?;
        a.emit(|e| {
            e.lea(
                RET,
                arinsal_x64::enc::Mem {
                    base: None,
                    index: Some(TMP1),
                    shift: 3,
                    disp: 0,
                    size: 8,
                },
            )
        })?;
        a.emit(|e| e.mov_mr(saved_stack_needed, RET))?;
        a.emit(|e| {
            e.lea(
                ARG3,
                arinsal_x64::enc::qword_ptr(RET, (arinsal_term::S_RESERVED * 8) as i32),
            )
        })?;
        a.emit(|e| e.lea(ARG3, arinsal_x64::enc::Mem::base_index(HTOP, ARG3, 0, 0, 8)))?;
        a.emit(|e| e.cmp_rr(ARG3, E))?;
        a.short_jcc(CondCode::BE, after_gc_check)?;

        a.fragment_call(garbage_collect)?;
        a.emit(|e| e.mov_rm(RET, saved_stack_needed))?;
        a.bind(after_gc_check)?;
        a.emit(|e| e.sub_rr(E, RET))?;

        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.emit(|e| e.mov_rm(ARG2, saved_pc))?;
        a.emit(|e| e.mov_rm(ARG3, saved_live))?;
        a.load_x_reg_array(ARG4)?;
        a.emit(|e| e.lea(ARG5, get_y_ref(0, 8)))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.runtime_call(raw::line_breakpoint_prepare())?;
        a.emit_leave_runtime(Update::NONE)?;

        a.emit(|e| e.test_rr(RET, RET))?;
        a.jcc(CondCode::NE, dispatch_call)?;
        a.emit(|e| e.mov_rm(RET, saved_stack_needed))?;
        a.jmp(dealloc_and_exit_trampoline)?;

        a.bind(dispatch_call)?;
        let target = a.emit_setup_dispatchable_call_active(RET)?;
        a.erlang_call_m(target)?;

        a.bind(cleanup)?;
        a.load_x_reg_array(ARG1)?;
        a.emit(|e| e.lea(ARG2, get_y_ref(0, 8)))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.runtime_call(raw::line_breakpoint_cleanup())?;
        a.emit_leave_runtime(Update::NONE)?;

        a.emit(|e| {
            e.lea(
                RET,
                arinsal_x64::enc::Mem {
                    base: None,
                    index: Some(RET),
                    shift: 3,
                    disp: 0,
                    size: 8,
                },
            )
        })?;
        a.bind(dealloc_and_exit_trampoline)?;
        a.emit(|e| e.add_rr(E, RET))?;
        a.bind(exit_trampoline)?;
        a.emit_leave_frame()?;
        a.emit(|e| e.ret())
    }

    /// Builds the position independent replacement stub that `load_nif` copies into a
    /// function body. `self` is the process-wide global assembler, whose executable fragments
    /// stay alive for the lifetime of every stub.
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:542-574 (beamasm_emit_call_nif),
    // erts/emulator/beam/jit/x86/beam_asm_module.cpp:468-500, 207-231, and
    // erts/emulator/beam/jit/x86/instr_bif.cpp:1059-1092, OTP-29.1.1.
    pub fn beamasm_emit_call_nif(
        &self,
        info: &ErtsCodeInfo,
        normal_fptr: usize,
        lib: usize,
        dirty_fptr: usize,
        buf: &mut [u8],
    ) -> Result<usize, AsmError> {
        let mut ba = BeamModuleAssembler::with_fragment_addresses(3, self.ptrs().to_vec());
        ba.emit_aligned_label(
            ArgVal::Label(1),
            ArgVal::Word(core::mem::size_of::<usize>() as u64),
        )?;
        ba.emit_i_func_info(
            ArgVal::Word(1),
            ArgVal::Immediate(info.mfa.module),
            ArgVal::Immediate(info.mfa.function),
            ArgVal::Word(info.mfa.arity as u64),
        )?;
        ba.emit_aligned_label(
            ArgVal::Label(2),
            ArgVal::Word(core::mem::size_of::<usize>() as u64),
        )?;
        ba.emit_i_breakpoint_trampoline()?;
        ba.emit_call_nif(
            ArgVal::Word(normal_fptr as u64),
            ArgVal::Word(lib as u64),
            ArgVal::Word(dirty_fptr as u64),
        )?;

        // Port of `BeamModuleAssembler::codegen(char *, size_t)`: flatten, resolve
        // cross-section fixups, relocate to `buff`, then copy the complete image there.
        let mut code = core::mem::take(&mut ba.asm.a).finish()?;
        let size = code.code_size();
        if size > buf.len() {
            return Err(AsmError::Operand("NIF call stub buffer too small"));
        }
        code.relocate(buf.as_mut_ptr() as u64)?;
        let image = code.image()?;
        buf[..image.len()].copy_from_slice(&image);
        Ok(size)
    }
}

/// erts `class BeamModuleAssembler : public BeamAssembler, public BeamModuleAssemblerCommon`.
// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1130-1875 and
// erts/emulator/beam/jit/beam_jit_common.hpp:130-198 (BeamModuleAssemblerCommon), OTP-29.1.1.
#[derive(Debug)]
pub struct BeamModuleAssembler {
    /// The `BeamAssembler` base.
    pub asm: BeamAssembler,
    /// `rawLabels`: the asmjit label of every BEAM label `1..num_labels`.
    raw_labels: HashMap<u32, Label>,
    /// `imports[index].patches`.
    pub imports: HashMap<u32, Vec<Patch>>,
    /// `lambdas[index].patches` and `lambdas[index].trampoline`.
    pub lambdas: HashMap<u32, LambdaPatch>,
    /// `literals[index].patches`.
    pub literals: HashMap<i64, Vec<Patch>>,
    /// The module's static literal table, including literals added by the loader.
    beam_literals: Vec<u64>,
    /// The module's dynamic literal table, indexed by the complement of a negative index.
    dynamic_literals: Vec<u64>,
    /// `strings`: every string patch.
    pub strings: Vec<Patch>,
    /// `CodeHolder::label_by_name`: addresses of named read-only data embedded in this module.
    rodata_labels: HashMap<String, Label>,
    /// `reg_cache`: `RegisterCache<20, x86::Mem, x86::Gp>` over X slots from `registers` and
    /// Y slots from `E`. ARG2 is excluded as it points to the currently active tuple.
    reg_cache: RegisterCache<20, Mem, Gp>,
    /// `_dispatchTable`: the module-local label of every global fragment called, bound to a
    /// thunk jumping to the fragment.
    dispatch_table: HashMap<usize, Label>,
    /// `last_error_offset`: the last code offset that may raise.
    pub last_error_offset: usize,
    /// `ga`: the address of every global fragment (`ga->get_<fragment>()`), indexed by
    /// [`GlobalLabels`]; empty for an assembler made without the global code.
    ga: Vec<Option<usize>>,
    /// Runtime `Process` field offsets shared with the global assembler.
    pub(crate) offsets: crate::common::process_offsets::ProcessOffsets,
    /// `catches`: the `catch` patch sites and their handlers.
    pub catches: Vec<PatchCatch>,
    /// `functions`: the label of every function seen so far (`i_func_info`).
    pub functions: Vec<u32>,
    /// `current_label`: the label bound last.
    current_label: Option<Label>,
    /// `code_header`: the module's `BeamCodeHeader`, if any.
    code_header: Option<Label>,
    /// `on_load`: the entry label of the `-on_load` function, if any.
    on_load: Option<Label>,
    /// `code_end`: the end of the last function; the dispatch table and data may follow.
    code_end: Option<Label>,
    /// `beam->types.entries`: the module's type table, which the type index of a register
    /// operand points into (`BeamModuleAssemblerCommon::getTypeEntry`).
    pub beam_types: Vec<ArgType>,
    /// `mod`: the atom of the module being assembled; used by `auto_local` record access.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp (`BeamModuleAssembler::mod`),
    // OTP-29.1.1.
    pub module: Option<Atom>,
    /// The `bif_table[e->bif_number].f` resolved by the loader for the current `call_bif_mfa`.
    /// erts resolves it while emitting that instruction from its active export table.
    pub(super) current_bif_mfa_function: Option<usize>,
    /// The `BIF_TRAP_EXPORT(BIF_send_2)` and `send_2` addresses supplied by the loader.
    pub(super) send_target: Option<(usize, usize)>,
}

impl BeamModuleAssemblerCommon for BeamModuleAssembler {
    fn beam_types(&self) -> &[ArgType] {
        &self.beam_types
    }

    fn beamfile_get_literal(&self, index: i64) -> u64 {
        BeamModuleAssembler::beamfile_get_literal(self, index)
    }
}

#[cfg(test)]
impl BeamModuleAssembler {
    /// Test support: appends `ty` to the type table and returns the register `arg` carrying
    /// its type index, as the loader packs a typed register; constants keep their own type.
    pub(crate) fn typed_arg(&mut self, arg: ArgVal, ty: ArgType) -> ArgVal {
        let index = self.beam_types.len() as u32;
        self.beam_types.push(ty);
        match (arg, arg.reg()) {
            (ArgVal::X(_), Some(reg)) => ArgVal::typed_x(reg, index),
            (ArgVal::Y(_), Some(reg)) => ArgVal::typed_y(reg, index),
            _ => arg,
        }
    }
}

/// `struct patch_catch`: a `mov` whose 32-bit immediate is filled with the catch tag of
/// `handler` once catch indices are allocated.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:147-150 (struct patch_catch), OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchCatch {
    /// `patch`.
    pub patch: Patch,
    /// `handler`.
    pub handler: Label,
}

/// `BeamCodeHeader` of a BeamAsm build: the module header the code begins with, followed by
/// the `functions` table (one entry per function plus the end of the last one). Pointers are
/// carried as addresses.
// Port of erts/emulator/beam/beam_code.h:58-146 (struct beam_code_header), OTP-29.1.1.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BeamCodeHeader {
    /// `num_functions`.
    pub num_functions: u64,
    /// `attr_ptr`.
    pub attr_ptr: usize,
    /// `attr_size`.
    pub attr_size: u64,
    /// `attr_size_on_heap`.
    pub attr_size_on_heap: u64,
    /// `compile_ptr`.
    pub compile_ptr: usize,
    /// `compile_size`.
    pub compile_size: u64,
    /// `compile_size_on_heap`.
    pub compile_size_on_heap: u64,
    /// `literal_area`.
    pub literal_area: usize,
    /// `on_load`: the `ErtsCodeInfo` of the `-on_load` function, or 0.
    pub on_load: usize,
    /// `line_table`.
    pub line_table: usize,
    /// `coverage_mode`.
    pub coverage_mode: u64,
    /// `coverage`.
    pub coverage: usize,
    /// `line_coverage_valid`.
    pub line_coverage_valid: usize,
    /// `loc_index_to_cover_id`.
    pub loc_index_to_cover_id: usize,
    /// `line_coverage_len`.
    pub line_coverage_len: u64,
    /// `debug`.
    pub debug: usize,
    /// `debugger_flags`.
    pub debugger_flags: u64,
    /// `md5_ptr`.
    pub md5_ptr: usize,
    /// `are_nifs`.
    pub are_nifs: usize,
    /// `functions[1]`: the first entry of the function table.
    pub functions: [usize; 1],
}

impl BeamCodeHeader {
    /// The words before `functions`, in field order (every field is one word).
    fn head_words(&self) -> [u64; 19] {
        [
            self.num_functions,
            self.attr_ptr as u64,
            self.attr_size,
            self.attr_size_on_heap,
            self.compile_ptr as u64,
            self.compile_size,
            self.compile_size_on_heap,
            self.literal_area as u64,
            self.on_load as u64,
            self.line_table as u64,
            self.coverage_mode,
            self.coverage as u64,
            self.line_coverage_valid as u64,
            self.loc_index_to_cover_id as u64,
            self.line_coverage_len,
            self.debug as u64,
            self.debugger_flags,
            self.md5_ptr as u64,
            self.are_nifs as u64,
        ]
    }
}

const _: () = assert!(core::mem::offset_of!(BeamCodeHeader, functions) == 19 * 8);

/// `BEAM_CATCHES_NIL`.
// Port of erts/emulator/beam/beam_catches.h:33, OTP-29.1.1.
pub const BEAM_CATCHES_NIL: u32 = u32::MAX;

/// `make_catch(x)`: `x << _TAG_IMMED2_SIZE | _TAG_IMMED2_CATCH`.
// Port of erts/emulator/beam/erl_term.h:89,1385 (make_catch), OTP-29.1.1.
const fn make_catch(index: u32) -> u64 {
    ((index as u64) << 6) | 0x1b
}

// Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1137-1142 (reg_cache), OTP-29.1.1.
impl CacheMem<Gp> for Mem {
    fn base_reg(&self) -> Option<Gp> {
        match self.base {
            Some(MemBase::Gp(base)) => Some(base),
            _ => None,
        }
    }

    /// `entry.mem.clone_adjusted(-bytes)`: erts keeps every Y entry, renumbered.
    fn trimmed(&self, bytes: u32) -> Option<Self> {
        Some(self.adjusted(-(bytes as i32)))
    }
}

/// `ArgWord::get()`: an untagged word operand (`t`/`I`/`W`/`A`/`P`), which the loader passes
/// as [`ArgVal::Word`].
// Port of erts/emulator/beam/jit/beam_jit_args.hpp (ArgWord), OTP-29.1.1.
pub fn arg_word(arg: ArgVal) -> Result<u64, AsmError> {
    match arg {
        ArgVal::Word(word) => Ok(word),
        _ => Err(AsmError::Operand("word operand")),
    }
}

/// `ArgLabel::get()`.
// Port of erts/emulator/beam/jit/beam_jit_args.hpp (ArgLabel), OTP-29.1.1.
pub fn arg_label(arg: ArgVal) -> Result<u32, AsmError> {
    match arg {
        ArgVal::Label(label) => Ok(label),
        _ => Err(AsmError::Operand("label operand")),
    }
}

/// asmjit `Support::is_int_n<32>`.
const fn is_int32(value: i64) -> bool {
    value as i32 as i64 == value
}

impl BeamModuleAssembler {
    /// A module assembler for `num_labels` BEAM labels, unnamed as when no assembly dump is
    /// requested.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:275-355
    // (BeamModuleAssembler::BeamModuleAssembler, the unnamed-label branch), OTP-29.1.1.
    pub fn new(num_labels: u32) -> Self {
        let mut asm = BeamAssembler::new();
        let raw_labels = (1..num_labels).map(|i| (i, asm.new_label())).collect();
        Self {
            asm,
            raw_labels,
            imports: HashMap::new(),
            lambdas: HashMap::new(),
            literals: HashMap::new(),
            beam_literals: Vec::new(),
            dynamic_literals: Vec::new(),
            strings: Vec::new(),
            rodata_labels: HashMap::new(),
            reg_cache: RegisterCache::with_temporaries(
                REGISTERS,
                E,
                &[TMP1, TMP2, ARG3, ARG4, ARG5, ARG6, ARG1, RET],
            ),
            dispatch_table: HashMap::new(),
            last_error_offset: 0,
            ga: Vec::new(),
            #[cfg(test)]
            offsets: crate::common::process_offsets::ProcessOffsets::ERTS_X86_64,
            #[cfg(not(test))]
            offsets: crate::common::process_offsets::ProcessOffsets {
                state: 0,
                sig_qs_save: 0,
                message_term: 0,
                def_arg_reg5: 0,
            },
            catches: Vec::new(),
            functions: Vec::new(),
            current_label: None,
            code_header: None,
            on_load: None,
            code_end: None,
            beam_types: vec![ArgType::ANY],
            module: None,
            current_bif_mfa_function: None,
            send_target: None,
        }
    }

    /// The assembler of a module load: calls the fragments of `ga` (already in executable
    /// memory) and starts with the module's `BeamCodeHeader` and its table of
    /// `num_functions + 1` function pointers, zeroed until [`Self::codegen`] fills them.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:83-95
    // (BeamModuleAssembler::BeamModuleAssembler(ga, mod, num_labels, num_functions, file)),
    // OTP-29.1.1.
    pub fn new_module(
        ga: &BeamGlobalAssembler,
        num_labels: u32,
        num_functions: usize,
        beam_types: Vec<ArgType>,
        lambdas: impl IntoIterator<Item = (u32, u32, u32)>,
    ) -> Result<Self, AsmError> {
        Self::new_module_with_module(ga, num_labels, num_functions, beam_types, lambdas, None)
    }

    /// Assembles a module with its `mod` atom, as the loader passes to erts' constructor.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp (`BeamModuleAssembler::mod`),
    // OTP-29.1.1.
    pub fn new_module_with_module(
        ga: &BeamGlobalAssembler,
        num_labels: u32,
        num_functions: usize,
        beam_types: Vec<ArgType>,
        lambdas: impl IntoIterator<Item = (u32, u32, u32)>,
        module: Option<Atom>,
    ) -> Result<Self, AsmError> {
        let mut m = Self::with_fragment_addresses(num_labels, ga.ptrs().to_vec());
        m.offsets = ga.offsets;
        m.beam_types = beam_types;
        for (index, label, num_free) in lambdas {
            let trampoline = if num_free > 0 {
                m.asm.new_label()
            } else {
                *m.raw_labels
                    .get(&label)
                    .ok_or(AsmError::Operand("lambda body label"))?
            };
            m.lambdas.insert(
                index,
                LambdaPatch {
                    patches: Vec::new(),
                    trampoline,
                },
            );
        }
        m.module = module;
        let code_header = m.asm.new_label();
        m.asm.align_code(8)?;
        m.asm.bind(code_header)?;
        m.code_header = Some(code_header);
        m.asm
            .embed_zeros(core::mem::size_of::<BeamCodeHeader>() + 8 * num_functions)?;
        Ok(m)
    }

    /// Stores a term in the module's `BeamFile` literal table.
    // Port of erts/emulator/beam/beam_file.c:1977-1990 (beamfile_get_literal table layout),
    // OTP-29.1.1.
    pub fn set_beam_literal(&mut self, index: i64, literal: u64) {
        if index >= 0 {
            let index = index as usize;
            self.beam_literals
                .resize(self.beam_literals.len().max(index + 1), 0);
            self.beam_literals[index] = literal;
        } else {
            let index = (!index) as usize;
            self.dynamic_literals
                .resize(self.dynamic_literals.len().max(index + 1), 0);
            self.dynamic_literals[index] = literal;
        }
    }

    /// `beamfile_get_literal(beam, index)`.
    // Port of erts/emulator/beam/beam_file.c:1977-1990 (beamfile_get_literal), OTP-29.1.1.
    pub fn beamfile_get_literal(&self, index: i64) -> u64 {
        if index >= 0 {
            self.beam_literals[index as usize]
        } else {
            self.dynamic_literals[(!index) as usize]
        }
    }

    /// `lambdas[index].trampoline` used by `emit_i_lambda_trampoline` and `emit_i_call_fun2`.
    // Port of erts/emulator/beam/jit/beam_asm_module.cpp:79-82 (getLambda), OTP-29.1.1.
    pub fn lambda_trampoline(&self, index: u32) -> Result<Label, AsmError> {
        self.lambdas
            .get(&index)
            .map(|lambda| lambda.trampoline)
            .ok_or(AsmError::Operand("lambda index"))
    }

    /// Supplies the loader's active-export resolution for the next `call_bif_mfa` instruction.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1154-1163 (call_bif_mfa resolves
    // `erts_active_export_entry` and `bif_table[e->bif_number].f`), OTP-29.1.1.
    pub fn set_call_bif_mfa_function(&mut self, function: usize) {
        self.current_bif_mfa_function = Some(function);
    }

    /// Supplies `BIF_TRAP_EXPORT(BIF_send_2)` and `send_2` for the next `send` instruction.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:648-660 (emit_send), OTP-29.1.1.
    pub fn set_send_target(&mut self, export: usize, function: usize) {
        self.send_target = Some((export, function));
    }

    /// A module assembler calling the fragments of `ga`, whose code is placed at `ga_base`.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:83-95
    // (BeamModuleAssembler::BeamModuleAssembler(BeamGlobalAssembler *ga, ...)), OTP-29.1.1.
    pub fn with_global(num_labels: u32, ga: &BeamGlobalAssembler, ga_base: usize) -> Self {
        let addresses = GLOBAL_LABELS.iter().map(|l| ga.get(ga_base, *l)).collect();
        let mut assembler = Self::with_fragment_addresses(num_labels, addresses);
        assembler.offsets = ga.offsets;
        assembler
    }

    /// A module assembler whose `ga->get_<fragment>()` is `addresses[fragment]`, indexed by
    /// [`GlobalLabels`].
    pub fn with_fragment_addresses(num_labels: u32, addresses: Vec<Option<usize>>) -> Self {
        let mut m = Self::new(num_labels);
        m.ga = addresses;
        m
    }

    /// `ga->get_<fragment>()`.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (decl_get_funcs), OTP-29.1.1.
    pub fn ga_get(&self, label: GlobalLabels) -> Result<usize, AsmError> {
        self.ga
            .get(label as usize)
            .copied()
            .flatten()
            .ok_or(AsmError::Operand("global fragment not emitted"))
    }

    fn offset(&self) -> usize {
        self.asm.a.offset()
    }

    /// Embeds nonempty `bytes` at named label `label` in the read-only data section.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:163-172 (embed_rodata), OTP-29.1.1.
    pub fn embed_rodata(&mut self, label: &str, bytes: &[u8]) -> Result<(), AsmError> {
        if bytes.is_empty() {
            return Ok(());
        }

        let label_id = self.asm.new_label();
        self.asm.a.select(Section::Data);
        let result: Result<(), AsmError> = (|| {
            self.asm.bind(label_id)?;
            self.asm.a.embed(bytes)?;
            Ok(())
        })();
        self.asm.a.select(Section::Code);
        result?;
        self.rodata_labels.insert(label.to_owned(), label_id);
        Ok(())
    }

    /// Returns the executable address of a named read-only data label after codegen.
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:598-601 (beamasm_get_rodata),
    // OTP-29.1.1.
    pub fn get_rodata(&self, label: &str) -> Option<usize> {
        self.asm.get_code(*self.rodata_labels.get(label)?)
    }

    /// `find_cache(mem)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1144-1146 (find_cache), OTP-29.1.1.
    pub fn find_cache(&mut self, mem: Mem) -> Option<Gp> {
        let offset = self.offset();
        self.reg_cache.find(offset, mem)
    }

    /// `store_cache(src, mem_dst)`: stores a register and records it in the cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1148-1154 (store_cache), OTP-29.1.1.
    pub fn store_cache(&mut self, src: Gp, mem_dst: Mem) -> Result<(), AsmError> {
        let offset = self.offset();
        self.reg_cache.consolidate(offset);
        self.asm.emit(|e| e.mov_mr(mem_dst, src))?;
        self.reg_cache.put(mem_dst, src);
        let offset = self.offset();
        self.reg_cache.update(offset);
        Ok(())
    }

    /// `load_cached(dst, mem)`: loads a BEAM register, reusing a cached copy.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1156-1176 (load_cached), OTP-29.1.1.
    pub fn load_cached(&mut self, dst: Gp, mem: Mem) -> Result<(), AsmError> {
        match self.find_cache(mem) {
            Some(cached) if cached == dst => {}
            Some(cached) => {
                self.asm.emit(|e| e.mov_rr(dst, cached))?;
                self.reg_cache.invalidate_reg(dst);
                let offset = self.offset();
                self.reg_cache.update(offset);
            }
            None => {
                self.asm.emit(|e| e.mov_rm(dst, mem))?;
                self.reg_cache.invalidate_reg(dst);
                self.reg_cache.put(mem, dst);
                let offset = self.offset();
                self.reg_cache.update(offset);
            }
        }
        Ok(())
    }

    /// `preserve_cache(generate, clobber...)`: runs `generate`, which leaves the cached
    /// registers intact except `regs` and the slots `mems`, and keeps the cache valid across
    /// it if it was valid before.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1178-1191 (preserve_cache), OTP-29.1.1.
    pub fn preserve_cache<T>(
        &mut self,
        regs: &[Gp],
        mems: &[Mem],
        generate: impl FnOnce(&mut Self) -> Result<T, AsmError>,
    ) -> Result<T, AsmError> {
        let valid = self.reg_cache.valid_at(self.offset());
        let result = generate(self)?;
        if valid {
            for reg in regs {
                self.reg_cache.invalidate_reg(*reg);
            }
            for mem in mems {
                self.reg_cache.invalidate_slot(*mem);
            }
            let offset = self.offset();
            self.reg_cache.update(offset);
        }
        Ok(result)
    }

    /// `trim_preserve_cache(Words)`: drops `words` from the frame, renumbering cached Y slots.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1193-1202 (trim_preserve_cache),
    // OTP-29.1.1.
    pub fn trim_preserve_cache(&mut self, words: u32) -> Result<(), AsmError> {
        if words > 0 {
            assert!(words <= 1023);
            self.preserve_cache(&[], &[], |m| {
                let bytes = words * 8;
                m.asm.emit(|e| e.add_ri(E, i64::from(bytes)))?;
                m.reg_cache.trim_yregs(bytes);
                Ok(())
            })?;
        }
        Ok(())
    }

    /// `mov_preserve_cache(Mem dst, Gp src)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1204-1210, OTP-29.1.1.
    pub fn mov_preserve_cache_store(&mut self, dst: Mem, src: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[dst], |m| m.asm.emit(|e| e.mov_mr(dst, src)))
    }

    /// `mov_preserve_cache(Gp dst, Gp src)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1212-1218, OTP-29.1.1.
    pub fn mov_preserve_cache_rr(&mut self, dst: Gp, src: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[dst], &[], |m| m.asm.emit(|e| e.mov_rr(dst, src)))
    }

    /// `mov_preserve_cache(Gp dst, Mem src)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1220-1226, OTP-29.1.1.
    pub fn mov_preserve_cache_load(&mut self, dst: Gp, src: Mem) -> Result<(), AsmError> {
        self.preserve_cache(&[dst], &[], |m| m.asm.emit(|e| e.mov_rm(dst, src)))
    }

    /// `cmp_preserve_cache(Gp, Gp)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1228-1232, OTP-29.1.1.
    pub fn cmp_preserve_cache_rr(&mut self, reg1: Gp, reg2: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_rr(reg1, reg2)))
    }

    /// `cmp_preserve_cache(Mem, Gp)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1234-1238, OTP-29.1.1.
    pub fn cmp_preserve_cache_mr(&mut self, mem: Mem, reg: Gp) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_mr(mem, reg)))
    }

    /// `alloc_temp_reg()`: a temporary register, preferring one not in the cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1240-1244 (alloc_temp_reg), OTP-29.1.1.
    pub fn alloc_temp_reg(&mut self) -> Gp {
        let offset = self.offset();
        self.reg_cache.allocate(offset)
    }

    /// `resolve_fragment(fragment)`: the module-local label standing for a global fragment;
    /// the thunk behind it is emitted with the module's dispatch table.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:576-584 (resolve_fragment),
    // OTP-29.1.1.
    pub fn resolve_fragment(&mut self, fragment: usize) -> Label {
        let asm = &mut self.asm;
        *self
            .dispatch_table
            .entry(fragment)
            .or_insert_with(|| asm.new_label())
    }

    /// `safe_fragment_call(fragment)` of the module assembler: a call to the module-local
    /// thunk of the global fragment at `fragment`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1541-1544 (safe_fragment_call),
    // OTP-29.1.1.
    pub fn safe_fragment_call(&mut self, fragment: usize) -> Result<(), AsmError> {
        self.asm.emit_assert_redzone_unused();
        let label = self.resolve_fragment(fragment);
        Ok(self.asm.a.call(label)?)
    }

    /// `aligned_call(FuncPtr *target)` of the module assembler: through the fragment's thunk.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1546-1549, OTP-29.1.1.
    pub fn aligned_call_fragment(&mut self, fragment: usize) -> Result<(), AsmError> {
        let label = self.resolve_fragment(fragment);
        self.asm.aligned_call_label(label)
    }

    /// The dispatch-table thunks at the end of the module: `jmp imm(fragment)` behind each
    /// label [`Self::resolve_fragment`] handed out. erts walks an `unordered_map`; the thunks
    /// are emitted here by fragment address.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:532-535 (emit_int_code_end,
    // the `_dispatchTable` loop), OTP-29.1.1.
    pub fn emit_dispatch_table(&mut self) -> Result<(), AsmError> {
        let mut thunks: Vec<(usize, Label)> = self.dispatch_table.drain().collect();
        thunks.sort_unstable_by_key(|(fragment, _)| *fragment);
        for (fragment, label) in thunks {
            self.asm.bind(label)?;
            self.asm.abs_jmp(fragment)?;
        }
        Ok(())
    }

    /// `embed_vararg_rodata(args, reg, y_offset)`: `lea reg, [label]` to a table of the
    /// operands in the read-only data section, one 8-byte-aligned word each: X and Y registers
    /// as loader-tagged words, literals as patch words, labels as their addresses.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:97-141 (embed_vararg_rodata),
    // OTP-29.1.1.
    pub fn embed_vararg_rodata(
        &mut self,
        args: &[ArgVal],
        reg: Gp,
        y_offset: u32,
    ) -> Result<(), AsmError> {
        // erl_term.h: `make_loader_x_reg`, `make_loader_y_reg` (the PID and PORT immediate
        // tags, `_TAG_IMMED1_SIZE` bits).
        const LOADER_TAG_SIZE: u32 = 4;
        const LOADER_X_REG: u64 = 0x3;
        const LOADER_Y_REG: u64 = 0x7;
        let label = self.asm.new_label();
        self.asm
            .a
            .emit_rip_label(label, |e| e.lea(reg, Mem::rip(0, 8)))?;
        self.asm.a.select(Section::Data);
        let result = (|| {
            self.asm.bind(label)?;
            for arg in args {
                self.asm.a.align(8)?;
                match *arg {
                    ArgVal::X(val) => {
                        self.asm.a.embed_u64(
                            (u64::from(val & REG_MASK) << LOADER_TAG_SIZE) | LOADER_X_REG,
                        )?;
                    }
                    ArgVal::Y(val) => {
                        self.asm.a.embed_u64(
                            (u64::from((val & REG_MASK) + y_offset) << LOADER_TAG_SIZE)
                                | LOADER_Y_REG,
                        )?;
                    }
                    ArgVal::Literal(index) => {
                        let mut patches = self.literals.remove(&index).unwrap_or_default();
                        let result = Self::make_word_patch(&mut self.asm, &mut patches);
                        self.literals.insert(index, patches);
                        result?;
                    }
                    ArgVal::Label(beam_label) => {
                        let target = self
                            .resolve_beam_label(beam_label)
                            .ok_or(AsmError::Operand("vararg label"))?;
                        self.asm.a.embed_label(target)?;
                    }
                    ArgVal::Immediate(word) | ArgVal::Word(word) => {
                        self.asm.a.embed_u64(word)?;
                    }
                    _ => return Err(AsmError::Operand("vararg rodata operand")),
                }
            }
            Ok(())
        })();
        self.asm.a.select(Section::Code);
        result
    }

    /// `flush_last_error()`: a `nop` when an instruction that may raise at its very end is
    /// followed by a new line, so the error refers to the preceding line.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:586-597 (flush_last_error),
    // OTP-29.1.1.
    pub fn flush_last_error(&mut self) -> Result<(), AsmError> {
        if self.offset() == self.last_error_offset {
            self.asm.emit(|e| e.nop())?;
        }
        Ok(())
    }

    /// `emit_is_boxed(Fail, Src, dist)` keeping the register cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1324-1328 (emit_is_boxed), OTP-29.1.1.
    pub fn emit_is_boxed(&mut self, fail: Label, src: Gp, dist: Distance) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit_is_boxed(fail, src, dist))
    }

    /// `emit_is_cons(Fail, Src, dist)` keeping the register cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1344-1353 (emit_is_cons), OTP-29.1.1.
    pub fn emit_is_cons(&mut self, fail: Label, src: Gp, dist: Distance) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit_is_cons(fail, src, dist))
    }

    /// `emit_is_not_cons(Fail, Src, dist)` keeping the register cache.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1355-1364 (emit_is_not_cons),
    // OTP-29.1.1.
    pub fn emit_is_not_cons(
        &mut self,
        fail: Label,
        src: Gp,
        dist: Distance,
    ) -> Result<(), AsmError> {
        self.preserve_cache(&[], &[], |m| m.asm.emit_is_not_cons(fail, src, dist))
    }

    fn arg_ref(arg: ArgVal) -> Result<Mem, AsmError> {
        get_arg_ref(arg, 8).ok_or(AsmError::Operand("BEAM register operand"))
    }

    /// `mov_arg(Gp to, ArgVal from, spill)`; may clear flags.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1672-1719 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_to_reg(&mut self, to: Gp, from: ArgVal) -> Result<(), AsmError> {
        match from {
            ArgVal::BytePtr(offset) => {
                Self::make_move_patch(&mut self.asm, to, &mut self.strings, offset as usize)
            }
            ArgVal::Export(index) => {
                let mut patches = self.imports.remove(&index).unwrap_or_default();
                let result = Self::make_move_patch(&mut self.asm, to, &mut patches, 0);
                self.imports.insert(index, patches);
                result
            }
            ArgVal::Immediate(value) => {
                self.preserve_cache(&[to], &[], |m| m.asm.mov_imm(to, value))
            }
            ArgVal::FunEntry(index) => self.preserve_cache(&[to], &[], |m| {
                let lambda = m
                    .lambdas
                    .get_mut(&index)
                    .ok_or(AsmError::Operand("lambda index"))?;
                Self::make_move_patch(&mut m.asm, to, &mut lambda.patches, 0)
            }),
            ArgVal::Literal(index) => self.preserve_cache(&[to], &[], |m| {
                let mut patches = m.literals.remove(&index).unwrap_or_default();
                let result = Self::make_move_patch(&mut m.asm, to, &mut patches, 0);
                m.literals.insert(index, patches);
                result
            }),
            ArgVal::X(_) | ArgVal::Y(_) => {
                let mem = Self::arg_ref(from)?;
                self.load_cached(to, mem)
            }
            ArgVal::Word(value) => self.preserve_cache(&[to], &[], |m| m.asm.mov_imm(to, value)),
            ArgVal::Label(_) | ArgVal::FReg(_) | ArgVal::Catch(_) => {
                Err(AsmError::Operand("mov_arg with incompatible type"))
            }
        }
    }

    /// `mov_arg(Mem to, ArgVal from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1721-1762 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_to_mem(&mut self, to: Mem, from: ArgVal, spill: Gp) -> Result<(), AsmError> {
        match from {
            ArgVal::Immediate(value) if is_int32(value as i64) => {
                self.preserve_cache(&[], &[to], |m| m.asm.emit(|e| e.mov_mi(to, value as i64)))
            }
            ArgVal::Immediate(value) => self.preserve_cache(&[spill], &[to], |m| {
                m.asm.emit(|e| e.mov_ri(spill, value as i64))?;
                m.asm.emit(|e| e.mov_mr(to, spill))
            }),
            _ => {
                self.mov_arg_to_reg(spill, from)?;
                self.mov_preserve_cache_store(to, spill)
            }
        }
    }

    /// `mov_arg(ArgRegister to, Gp from, spill)`: stores and caches.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1764-1769 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_from_reg(&mut self, to: ArgVal, from: Gp) -> Result<(), AsmError> {
        let mem = Self::arg_ref(to)?;
        self.store_cache(from, mem)
    }

    /// `mov_arg(ArgRegister to, Mem from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1771-1774 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_from_mem(&mut self, to: ArgVal, from: Mem, spill: Gp) -> Result<(), AsmError> {
        let mem = Self::arg_ref(to)?;
        self.asm.emit(|e| e.mov_rm(spill, from))?;
        self.asm.emit(|e| e.mov_mr(mem, spill))
    }

    /// `mov_arg(ArgRegister to, BeamInstr from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1776-1788 (mov_arg), OTP-29.1.1.
    pub fn mov_arg_word(&mut self, to: ArgVal, from: u64, spill: Gp) -> Result<(), AsmError> {
        let mem = Self::arg_ref(to)?;
        self.preserve_cache(&[spill], &[mem], |m| {
            if is_int32(from as i64) {
                m.asm.emit(|e| e.mov_mi(mem, from as i64))
            } else {
                m.asm.emit(|e| e.mov_ri(spill, from as i64))?;
                m.mov_arg_from_reg(to, spill)
            }
        })
    }

    /// `mov_arg(ArgRegister to, ArgVal from, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1790-1806 (mov_arg), OTP-29.1.1.
    pub fn mov_arg(&mut self, to: ArgVal, from: ArgVal, spill: Gp) -> Result<(), AsmError> {
        if !matches!(from, ArgVal::X(_) | ArgVal::Y(_)) {
            let mem = Self::arg_ref(to)?;
            return self.mov_arg_to_mem(mem, from, ARG1);
        }
        let from_reg = match self.find_cache(Self::arg_ref(from)?) {
            Some(cached) => cached,
            None => {
                self.mov_arg_to_reg(spill, from)?;
                spill
            }
        };
        self.mov_arg_from_reg(to, from_reg)
    }

    /// `cmp_arg(Mem, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1591-1624 (cmp_arg), OTP-29.1.1.
    pub fn cmp_arg_mem(&mut self, mem: Mem, val: ArgVal, spill: Gp) -> Result<(), AsmError> {
        let imm32 = match val {
            ArgVal::Immediate(value) if is_int32(value as i64) => Some(value as i64),
            _ => None,
        };
        match (self.find_cache(mem), imm32) {
            (Some(reg), Some(imm)) => {
                self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_ri(reg, imm)))
            }
            (Some(reg), None) if reg != spill => {
                self.mov_arg_to_reg(spill, val)?;
                self.cmp_preserve_cache_rr(reg, spill)
            }
            (None, Some(imm)) => {
                self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_mi(mem, imm)))
            }
            _ => {
                self.mov_arg_to_reg(spill, val)?;
                self.cmp_preserve_cache_mr(mem, spill)
            }
        }
    }

    /// `cmp_arg(Gp, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1626-1636 (cmp_arg), OTP-29.1.1.
    pub fn cmp_arg_reg(&mut self, gp: Gp, val: ArgVal, spill: Gp) -> Result<(), AsmError> {
        match val {
            ArgVal::Immediate(value) if is_int32(value as i64) => {
                self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_ri(gp, value as i64)))
            }
            _ => {
                self.mov_arg_to_reg(spill, val)?;
                self.cmp_preserve_cache_rr(gp, spill)
            }
        }
    }

    /// `cmp(gp, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1638-1652 (cmp), OTP-29.1.1.
    pub fn cmp(&mut self, gp: Gp, val: i64, spill: Gp) -> Result<(), AsmError> {
        if is_int32(val) {
            self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_ri(gp, val)))
        } else if gp.size() == 4 {
            self.asm.mov_imm(spill, val as u64)?;
            self.preserve_cache(&[], &[], |m| m.asm.emit(|e| e.cmp_rr(gp, spill.r32())))
        } else {
            self.asm.mov_imm(spill, val as u64)?;
            self.cmp_preserve_cache_rr(gp, spill)
        }
    }

    /// `sub(gp, val, spill)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1654-1670 (sub), OTP-29.1.1.
    pub fn sub(&mut self, gp: Gp, val: i64, spill: Gp) -> Result<(), AsmError> {
        if is_int32(val) {
            self.preserve_cache(&[gp], &[], |m| m.asm.emit(|e| e.sub_ri(gp, val)))
        } else {
            self.preserve_cache(&[gp, spill], &[], |m| {
                m.asm.mov_imm(spill, val as u64)?;
                m.asm.emit(|e| e.sub_rr(gp, spill))
            })
        }
    }

    /// `resolve_beam_label(Lbl)`: `rawLabels.at(Lbl)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1529-1531 (resolve_beam_label),
    // OTP-29.1.1.
    pub fn resolve_beam_label(&self, label: u32) -> Option<Label> {
        self.raw_labels.get(&label).copied()
    }

    /// `make_move_patch(to, patches, offset)`: a `mov to, imm64` whose 8-byte payload is
    /// patched with the value later.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1555-1565 (make_move_patch), OTP-29.1.1.
    pub fn make_move_patch(
        asm: &mut BeamAssembler,
        to: Gp,
        patches: &mut Vec<Patch>,
        offset: usize,
    ) -> Result<(), AsmError> {
        const MOV_IMM64_PAYLOAD_OFFSET: usize = 2;
        let label = asm.new_label();
        asm.bind(label)?;
        // `a.long_().mov(to, imm(LLONG_MAX))`: LLONG_MAX fits neither imm32 form, so this is
        // the 10-byte `REX.W B8+r imm64`.
        asm.emit(|e| e.mov_ri(to.r64(), i64::MAX))?;
        patches.push(Patch {
            at: label,
            ptr_offs: MOV_IMM64_PAYLOAD_OFFSET,
            val_offs: offset,
        });
        Ok(())
    }

    /// `make_word_patch(patches)`: an embedded word patched with the value later.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1567-1574 (make_word_patch), OTP-29.1.1.
    pub fn make_word_patch(
        asm: &mut BeamAssembler,
        patches: &mut Vec<Patch>,
    ) -> Result<(), AsmError> {
        let label = asm.new_label();
        asm.bind(label)?;
        asm.a.embed_u64(i64::MAX as u64)?;
        patches.push(Patch {
            at: label,
            ptr_offs: 0,
            val_offs: 0,
        });
        Ok(())
    }
}

/// The meta instructions of erts/emulator/beam/jit/x86/beam_asm_module.cpp: function and
/// label boundaries, line markers, breakpoint trampolines and the stubs of instructions that
/// are never executed.
impl BeamModuleAssembler {
    /// Calls the global `raise_exception_null_exp` fragment, using its return address as the
    /// exception PC.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:256-263
    // (BeamModuleAssembler::emit_raise_exception()), OTP-29.1.1.
    pub(crate) fn emit_raise_exception_current(&mut self) -> Result<(), AsmError> {
        let fragment = self.ga_get(GlobalLabels::RaiseExceptionNullExp)?;
        self.safe_fragment_call(fragment)?;
        self.last_error_offset = self.asm.a.offset();
        Ok(())
    }

    /// `emit_nyi(msg)`: calls `i_emit_nyi`, which halts the emulator; never returns.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:401-412 (emit_nyi), OTP-29.1.1.
    pub fn emit_nyi(&mut self, msg: &'static core::ffi::CStr) -> Result<(), AsmError> {
        self.asm.emit_enter_runtime(Update::NONE)?;
        let msg = msg.as_ptr() as i64;
        self.asm.emit(|e| e.mov_ri(ARG1, msg))?;
        self.asm.runtime_call(addr(i_emit_nyi as *const ()))
    }

    /// `emit_i_nif_padding()`: pads the previous function to the size a NIF stub replacing
    /// it needs.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:143-154 (emit_i_nif_padding),
    // OTP-29.1.1.
    pub fn emit_i_nif_padding(&mut self) -> Result<(), AsmError> {
        const MINIMUM_SIZE: usize = 8 * BEAM_NATIVE_MIN_FUNC_SZ;
        let last = *self
            .functions
            .last()
            .ok_or(AsmError::Operand("i_nif_padding outside a function"))?;
        let entry = self
            .resolve_beam_label(last + 1)
            .ok_or(AsmError::Operand("function entry label"))?;
        let prev_func_start = self
            .asm
            .a
            .label_location(entry)
            .ok_or(AsmError::Operand("function entry label not bound"))?
            .offset;
        let diff = self.offset() - prev_func_start;
        if diff < MINIMUM_SIZE {
            self.asm.embed_zeros(MINIMUM_SIZE - diff)?;
        }
        Ok(())
    }

    /// `emit_i_breakpoint_trampoline()`: the prologue NIF loading and tracing patch: a short
    /// jump over an aligned call to the breakpoint trampoline, which enabling a breakpoint
    /// turns into a fall-through.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:207-231
    // (emit_i_breakpoint_trampoline), OTP-29.1.1.
    pub fn emit_i_breakpoint_trampoline(&mut self) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.asm.short_jmp(next)?;
        if self.code_header.is_some() {
            let fragment = self.ga_get(GlobalLabels::IBreakpointTrampolineShared)?;
            self.aligned_call_fragment(fragment)?;
        } else {
            // NIF or BIF stub; this trampoline is not used as-is, but its space is reserved.
            self.asm.emit(|e| e.ud2())?;
            self.asm.align_code(8)?;
        }
        debug_assert!(self.offset().is_multiple_of(8));
        self.asm.bind(next)?;
        debug_assert_eq!(
            Some(self.offset() - BEAM_ASM_FUNC_PROLOGUE_SIZE),
            self.current_label_offset()
        );
        Ok(())
    }

    /// `emit_i_line_breakpoint_trampoline()`: a short jump over an aligned call to the line
    /// breakpoint fragment; enabling the breakpoint replaces the jump.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:329-340
    // (emit_i_line_breakpoint_trampoline), OTP-29.1.1.
    pub fn emit_i_line_breakpoint_trampoline(&mut self) -> Result<(), AsmError> {
        let next = self.asm.new_label();
        self.asm.short_jmp(next)?;
        let fragment = self.ga_get(GlobalLabels::ILineBreakpointTrampolineShared)?;
        self.aligned_call_fragment(fragment)?;
        self.asm.bind(next)
    }

    /// `emit_i_func_info(Label, Module, Function, Arity)`: the `ErtsCodeInfo` in front of a
    /// function. Its first word is a valid x86 `call` to `i_func_info_shared` (so a
    /// `function_clause` traces back to it) followed by two `nop`s and the breakpoint flag;
    /// then `gen_bp` and the MFA.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:468-500 (emit_i_func_info),
    // OTP-29.1.1.
    pub fn emit_i_func_info(
        &mut self,
        label: ArgVal,
        module: ArgVal,
        function: ArgVal,
        arity: ArgVal,
    ) -> Result<(), AsmError> {
        // `op_i_func_info_IaaI`: the label is a word, not a label operand.
        let label = u32::try_from(arg_word(label)?).map_err(|_| AsmError::Operand("label"))?;
        self.functions.push(label);
        let atom = |arg| match arg {
            ArgVal::Immediate(word) => Ok(word),
            _ => Err(AsmError::Operand("atom operand")),
        };
        let mfa = arinsal_term::ErtsCodeMfa {
            module: atom(module)?,
            function: atom(function)?,
            arity: arg_word(arity)? as usize,
        };
        let fragment = self.ga_get(GlobalLabels::IFuncInfoShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.a.call(target)?;
        if self.code_header.is_none() {
            // `beamasm_emit_call_nif` uses `codegen(buff, ...)` without an int_code_end
            // dispatch table. asmjit leaves this metadata-only call's rel32 unresolved (zero);
            // erl_nif.c copies the function body after it, so retain those same bytes while
            // satisfying CodeBuffer's requirement that every label be bound.
            self.asm.bind(target)?;
        }
        self.asm.emit(|e| e.nop())?;
        self.asm.emit(|e| e.nop())?;
        self.asm.a.embed_u8(ERTS_ASM_BP_FLAG_NONE)?;
        debug_assert!(self.offset().is_multiple_of(8));
        // `info.gen_bp`, then `info.mfa`.
        self.asm.a.embed_u64(0)?;
        self.asm.a.embed_u64(mfa.module)?;
        self.asm.a.embed_u64(mfa.function)?;
        self.asm.a.embed_u64(mfa.arity as u64)?;
        Ok(())
    }

    /// `emit_label(Label)`: binds a BEAM label; nothing is known about the registers there.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:502-509 (emit_label), OTP-29.1.1.
    pub fn emit_label(&mut self, label: ArgVal) -> Result<(), AsmError> {
        let label = self
            .resolve_beam_label(arg_label(label)?)
            .ok_or(AsmError::Operand("label number"))?;
        self.current_label = Some(label);
        self.asm.bind(label)?;
        self.reg_cache.invalidate_all();
        Ok(())
    }

    /// `emit_aligned_label(Label, Alignment)`.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:511-515 (emit_aligned_label),
    // OTP-29.1.1.
    pub fn emit_aligned_label(&mut self, label: ArgVal, alignment: ArgVal) -> Result<(), AsmError> {
        let alignment =
            u32::try_from(arg_word(alignment)?).map_err(|_| AsmError::Operand("alignment"))?;
        self.asm.align_code(alignment)?;
        self.emit_label(label)
    }

    /// `emit_i_func_label(Label)`: the 8-byte aligned label of a function's `ErtsCodeInfo`.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:517-520 (emit_i_func_label),
    // OTP-29.1.1.
    pub fn emit_i_func_label(&mut self, label: ArgVal) -> Result<(), AsmError> {
        self.flush_last_error()?;
        self.emit_aligned_label(label, ArgVal::Word(8))
    }

    /// `emit_on_load()`: the current function is the module's `-on_load` function.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:522-524 (emit_on_load),
    // OTP-29.1.1.
    pub fn emit_on_load(&mut self) -> Result<(), AsmError> {
        self.on_load = self.current_label;
        Ok(())
    }

    /// `emit_int_code_end()`: marks the end of the last function, guards it with a halt, and
    /// emits the dispatch-table thunks of the global fragments the module calls.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:526-536 (emit_int_code_end),
    // OTP-29.1.1.
    pub fn emit_int_code_end(&mut self) -> Result<(), AsmError> {
        let code_end = self.asm.new_label();
        self.asm.bind(code_end)?;
        self.code_end = Some(code_end);
        self.emit_nyi(c"int_code_end")?;
        self.emit_dispatch_table()
    }

    /// `emit_line(Loc)`: lines need no code; only an error at the very end of the previous
    /// instruction must not be attributed to this line.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:538-544 (emit_line), OTP-29.1.1.
    pub fn emit_line(&mut self, _loc: ArgVal) -> Result<(), AsmError> {
        self.flush_last_error()
    }

    /// `emit_func_line(Loc)`: emits nothing.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:546-547 (emit_func_line),
    // OTP-29.1.1.
    pub fn emit_func_line(&mut self, _loc: ArgVal) -> Result<(), AsmError> {
        Ok(())
    }

    /// `emit_empty_func_line()`: emits nothing.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:549-550 (emit_empty_func_line),
    // OTP-29.1.1.
    pub fn emit_empty_func_line(&mut self) -> Result<(), AsmError> {
        Ok(())
    }

    /// `emit_executable_line(Loc, Index)`: emits nothing; its coverage counter is emitted by
    /// the loader (`beamasm_emit_coverage`).
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:552-554 (emit_executable_line),
    // OTP-29.1.1.
    pub fn emit_executable_line(&mut self, _loc: ArgVal, _index: ArgVal) -> Result<(), AsmError> {
        Ok(())
    }

    /// `emit_i_debug_breakpoint()`: never executed.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:560-562, OTP-29.1.1.
    pub fn emit_i_debug_breakpoint(&mut self) -> Result<(), AsmError> {
        self.emit_nyi(c"i_debug_breakpoint should never be called")
    }

    /// `emit_i_generic_breakpoint()`: never executed.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:564-566, OTP-29.1.1.
    pub fn emit_i_generic_breakpoint(&mut self) -> Result<(), AsmError> {
        self.emit_nyi(c"i_generic_breakpoint should never be called")
    }

    /// `emit_trace_jump(_)`: never executed.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:568-570, OTP-29.1.1.
    pub fn emit_trace_jump(&mut self, _arg: ArgVal) -> Result<(), AsmError> {
        self.emit_nyi(c"trace_jump should never be called")
    }

    /// `emit_call_error_handler()`: never executed.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:572-574, OTP-29.1.1.
    pub fn emit_call_error_handler(&mut self) -> Result<(), AsmError> {
        self.emit_nyi(c"call_error_handler should never be called")
    }

    /// `code.label_offset_from_base(current_label)` while emitting.
    pub(crate) fn current_label_offset(&self) -> Option<usize> {
        Some(self.asm.a.label_location(self.current_label?)?.offset)
    }

    /// `current_label`.
    pub(crate) fn current_label(&self) -> Option<Label> {
        self.current_label
    }
}

/// Code generation and the patching of the loaded module, erts'
/// erts/emulator/beam/jit/beam_jit_common.cpp `BeamModuleAssembler::codegen` / `getCode` /
/// `patch*` on x86.
impl BeamModuleAssembler {
    /// `codegen(allocator, &executable, &writable, in_hdr, &out_exec_hdr, &out_rw_hdr)`:
    /// moves the code into executable memory, copies `in_hdr` into the module's header and
    /// fills its `on_load` and function table (each function's `ErtsCodeInfo`, then the end of
    /// the module code). Returns the span (both views) and the executable header address.
    /// The module stays writable through the span for the `patch_*` calls that follow.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:217-256 (BeamModuleAssembler::codegen),
    // OTP-29.1.1.
    pub fn codegen(
        &mut self,
        in_hdr: &BeamCodeHeader,
    ) -> Result<(arinsal_x64::exec::CodeMemory, usize), AsmError> {
        let code_header = self
            .code_header
            .ok_or(AsmError::Operand("module assembler without a code header"))?;
        let mut memory = self.asm.codegen()?;
        let offset = self
            .asm
            .label_offset_from_base(code_header)
            .ok_or(AsmError::Operand("code header"))?;
        let mut hdr = *in_hdr;
        hdr.on_load = self.get_on_load().unwrap_or(0);
        let write = |memory: &mut arinsal_x64::exec::CodeMemory, at: usize, word: u64| {
            memory
                .write(at, &word.to_le_bytes())
                .map_err(|_| AsmError::AllocCode)
        };
        for (i, word) in hdr.head_words().into_iter().enumerate() {
            write(&mut memory, offset + i * 8, word)?;
        }
        let functions = offset + core::mem::offset_of!(BeamCodeHeader, functions);
        for (i, label) in self.functions.iter().enumerate() {
            let ci = self
                .get_code(*label)
                .ok_or(AsmError::Operand("function label"))?;
            write(&mut memory, functions + i * 8, ci as u64)?;
        }
        let base = memory.as_ptr() as usize;
        let module_end = base + self.asm.get_offset();
        write(
            &mut memory,
            functions + self.functions.len() * 8,
            module_end as u64,
        )?;
        Ok((memory, base + offset))
    }

    /// `getCode(BeamLabel)`: the executable address of a BEAM label after codegen.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:73-76 (getCode), OTP-29.1.1.
    pub fn get_code(&self, label: u32) -> Option<usize> {
        self.asm.get_code(self.resolve_beam_label(label)?)
    }

    /// `getCodeHeader()`.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:494-496 (getCodeHeader), OTP-29.1.1.
    pub fn get_code_header(&self) -> Option<usize> {
        self.asm.get_code(self.code_header?)
    }

    /// `getCodeSize()`: the size of the whole module image.
    // Port of erts/emulator/beam/jit/x86/beam_asm.hpp:1294-1297 (getCodeSize), OTP-29.1.1.
    pub fn get_code_size(&self) -> Option<usize> {
        self.asm.code_size()
    }

    /// `getOnLoad()`: the `ErtsCodeInfo` of the `-on_load` function (`erts_code_to_codeinfo`
    /// of its entry), if any.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:498-504 (getOnLoad), OTP-29.1.1.
    pub fn get_on_load(&self) -> Option<usize> {
        Some(self.asm.get_code(self.on_load?)? - core::mem::size_of::<ErtsCodeInfo>())
    }

    /// `code_end` after codegen: the end of the last function.
    pub fn get_code_end(&self) -> Option<usize> {
        self.asm.get_code(self.code_end?)
    }

    /// Writes `value` over a patch site's `LLONG_MAX` placeholder.
    fn write_patch(
        &self,
        rw: &mut arinsal_x64::exec::CodeMemory,
        patch: &Patch,
        value: u64,
    ) -> Result<(), AsmError> {
        let offset = self
            .asm
            .label_offset_from_base(patch.at)
            .ok_or(AsmError::Operand("patch label"))?;
        let where_ = offset + patch.ptr_offs;
        if cfg!(debug_assertions) {
            // `ASSERT(LLONG_MAX == *where)`.
            let mut placeholder = [0; 8];
            rw.read(where_, &mut placeholder)
                .map_err(|_| AsmError::AllocCode)?;
            debug_assert_eq!(u64::from_le_bytes(placeholder), i64::MAX as u64);
        }
        rw.write(where_, &value.to_le_bytes())
            .map_err(|_| AsmError::AllocCode)
    }

    /// `patchCatches(rw_base)`: allocates a catch index for every `catch` handler, chaining
    /// them from `BEAM_CATCHES_NIL`, and patches each site's `mov` with its catch tag. Returns
    /// the head of the module's catch chain.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:506-531 (patchCatches), OTP-29.1.1.
    pub fn patch_catches(&self, rw: &mut arinsal_x64::exec::CodeMemory) -> Result<u32, AsmError> {
        let mut catch_no = BEAM_CATCHES_NIL;
        for c in &self.catches {
            let handler = self
                .asm
                .get_code(c.handler)
                .ok_or(AsmError::Operand("catch handler"))?;
            catch_no = beam_catches_cons_nil(handler, catch_no);
            let catch_term = make_catch(catch_no);
            // With the current tag scheme, more than 33 million catches can exist at once.
            assert!(catch_term >> 31 == 0);
            let offset = self
                .asm
                .label_offset_from_base(c.patch.at)
                .ok_or(AsmError::Operand("catch patch label"))?;
            let where_ = offset + c.patch.ptr_offs;
            if cfg!(debug_assertions) {
                // `ASSERT(INT_MAX == *where)`.
                let mut placeholder = [0; 4];
                rw.read(where_, &mut placeholder)
                    .map_err(|_| AsmError::AllocCode)?;
                debug_assert_eq!(u32::from_le_bytes(placeholder), i32::MAX as u32);
            }
            rw.write(where_, &(catch_term as u32).to_le_bytes())
                .map_err(|_| AsmError::AllocCode)?;
        }
        Ok(catch_no)
    }

    /// `patchImport(rw_base, index, import)`: `import + val_offs` into every use of the
    /// import entry `index`.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:533-543 (patchImport), OTP-29.1.1.
    pub fn patch_import(
        &self,
        rw: &mut arinsal_x64::exec::CodeMemory,
        index: u32,
        import: usize,
    ) -> Result<(), AsmError> {
        for patch in self.imports.get(&index).into_iter().flatten() {
            self.write_patch(rw, patch, import as u64 + patch.val_offs as u64)?;
        }
        Ok(())
    }

    /// `patchLambda(rw_base, index, fe)`: the fun entry `fe` into every use of lambda `index`.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:545-555 (patchLambda), OTP-29.1.1.
    pub fn patch_lambda(
        &self,
        rw: &mut arinsal_x64::exec::CodeMemory,
        index: u32,
        fe: usize,
    ) -> Result<(), AsmError> {
        for patch in self
            .lambdas
            .get(&index)
            .into_iter()
            .flat_map(|lambda| &lambda.patches)
        {
            self.write_patch(rw, patch, fe as u64 + patch.val_offs as u64)?;
        }
        Ok(())
    }

    /// `patchLiteral(rw_base, index, lit)`: the moved literal `lit` into every use of index.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:557-567 (patchLiteral), OTP-29.1.1.
    pub fn patch_literal(
        &self,
        rw: &mut arinsal_x64::exec::CodeMemory,
        index: i64,
        lit: u64,
    ) -> Result<(), AsmError> {
        for patch in self.literals.get(&index).into_iter().flatten() {
            self.write_patch(rw, patch, lit + patch.val_offs as u64)?;
        }
        Ok(())
    }

    /// `patchStrings(rw_base, string_table)`: the address of each string in the module's
    /// string table into its uses.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:569-579 (patchStrings), OTP-29.1.1.
    pub fn patch_strings(
        &self,
        rw: &mut arinsal_x64::exec::CodeMemory,
        string_table: usize,
    ) -> Result<(), AsmError> {
        for patch in &self.strings {
            self.write_patch(rw, patch, string_table as u64 + patch.val_offs as u64)?;
        }
        Ok(())
    }
}

impl BeamModuleAssembler {
    /// Raises with the error address taken implicitly from the call to
    /// `raise_exception_null_exp` (its return address, not a CP), through the module's
    /// fragment thunk as every module `safe_fragment_call`.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:256-262
    // (BeamModuleAssembler::emit_raise_exception()), OTP-29.1.1.
    pub(crate) fn emit_raise_exception(&mut self) -> Result<(), AsmError> {
        let fragment = self.ga_get(GlobalLabels::RaiseExceptionNullExp)?;
        self.safe_fragment_call(fragment)?;
        self.last_error_offset = self.asm.a.offset();
        Ok(())
    }

    /// Loads the exception MFA and calls the shared raise fragment, recording the throwing PC.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:264-271
    // (BeamModuleAssembler::emit_raise_exception(const ErtsCodeMFA *)), OTP-29.1.1.
    /// erts overloads `emit_raise_exception`; this is the `(const ErtsCodeMFA *)` overload.
    pub(crate) fn emit_raise_exception_mfa(
        &mut self,
        mfa: &'static arinsal_term::ErtsCodeMfa,
    ) -> Result<(), AsmError> {
        self.asm
            .mov_imm(ARG4, std::ptr::from_ref(mfa) as usize as u64)?;
        let fragment = self.ga_get(GlobalLabels::RaiseException)?;
        self.safe_fragment_call(fragment)?;
        self.last_error_offset = self.asm.a.offset();
        Ok(())
    }

    /// The `(Label I, const ErtsCodeMFA *)` overload of `emit_raise_exception`: raises with
    /// the address of `i` as the error address.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:273-277
    // (BeamModuleAssembler::emit_raise_exception(Label, const ErtsCodeMFA *)), OTP-29.1.1.
    pub(crate) fn emit_raise_exception_label(
        &mut self,
        i: Label,
        exp: Option<&'static arinsal_term::ErtsCodeMfa>,
    ) -> Result<(), AsmError> {
        self.asm
            .a
            .emit_rip_label(i, |e| e.lea(ARG2, Mem::rip(0, 8)))?;
        self.emit_raise_exception_gp(ARG2, exp)
    }

    /// The `(x86::Gp I, const ErtsCodeMFA *)` overload of `emit_raise_exception`: a faked
    /// call frame whose return address is the error address `i`, then `raise_exception_shared`.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:279-301
    // (BeamModuleAssembler::emit_raise_exception(x86::Gp, const ErtsCodeMFA *)), OTP-29.1.1.
    pub(crate) fn emit_raise_exception_gp(
        &mut self,
        i: Gp,
        exp: Option<&'static arinsal_term::ErtsCodeMfa>,
    ) -> Result<(), AsmError> {
        if i != ARG2 {
            self.asm.emit(|e| e.mov_rr(ARG2, i))?;
        }
        let exp = exp.map_or(0, |mfa| std::ptr::from_ref(mfa) as usize as u64);
        self.asm.mov_imm(ARG4, exp)?;
        // NATIVE_ERLANG_STACK: the CP must be reserved for try/catch to work, so fake a call
        // with the return address set to the error address (the RA frame layout pushes no
        // frame pointer).
        self.asm.emit(|e| e.push_r(ARG2))?;
        const {
            assert!(matches!(
                super::beam_asm::FRAME_LAYOUT,
                super::beam_asm::FrameLayout::Ra
            ))
        };
        let fragment = self.ga_get(GlobalLabels::RaiseExceptionShared)?;
        let label = self.resolve_fragment(fragment);
        self.asm.jmp(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm::register::{ARG1, ARG4};

    #[test]
    fn labels_cover_beam_labels() {
        let m = BeamModuleAssembler::new(5);
        assert!(m.resolve_beam_label(0).is_none());
        assert!(m.resolve_beam_label(4).is_some());
        assert!(m.resolve_beam_label(5).is_none());
    }

    #[test]
    fn move_and_word_patches() {
        let mut m = BeamModuleAssembler::new(1);
        let mut patches = Vec::new();
        BeamModuleAssembler::make_move_patch(&mut m.asm, ARG4, &mut patches, 3).unwrap();
        BeamModuleAssembler::make_word_patch(&mut m.asm, &mut patches).unwrap();
        BeamModuleAssembler::make_move_patch(&mut m.asm, ARG1.r32(), &mut patches, 0).unwrap();
        let code = m.asm.a.bytes(Section::Code);
        // movabs rcx, 0x7fffffffffffffff; .quad 0x7fff...; movabs rdi, 0x7fff...
        let max = i64::MAX.to_le_bytes();
        assert_eq!(&code[..2], &[0x48, 0xb9]);
        assert_eq!(&code[2..10], &max);
        assert_eq!(&code[10..18], &max);
        assert_eq!(&code[18..20], &[0x48, 0xbf]);
        assert_eq!(code.len(), 28);
        let at = |p: &Patch| m.asm.a.label_location(p.at).unwrap().offset;
        assert_eq!(
            patches
                .iter()
                .map(|p| (at(p), p.ptr_offs, p.val_offs))
                .collect::<Vec<_>>(),
            [(0, 2, 3), (10, 0, 0), (18, 2, 0)]
        );
    }

    // `lea ARG1, [rip+table]` to 8-byte rodata words: x0 and y1 (+1 for the frame) as loader
    // tags, a word, a label address; then a module's fragment thunk as `REX jmp rel32`.
    #[test]
    fn vararg_rodata_and_dispatch_thunks() {
        let mut m = BeamModuleAssembler::new(3);
        m.embed_vararg_rodata(
            &[
                ArgVal::X(0),
                ArgVal::Y(1),
                ArgVal::Word(42),
                ArgVal::Label(2),
            ],
            ARG1,
            1,
        )
        .unwrap();
        let label = m.resolve_beam_label(2).unwrap();
        m.asm.bind(label).unwrap();
        m.safe_fragment_call(0x5000).unwrap();
        m.emit_dispatch_table().unwrap();
        let mut code = m.asm.a.finish().unwrap();
        // lea rdi, [rip+disp]: the table starts at the 8-aligned end of the code.
        assert_eq!(&code.code[..3], &[0x48, 0x8d, 0x3d]);
        assert_eq!(code.data_offset, 24);
        assert_eq!(&code.code[3..7], &(24 - 7_i32).to_le_bytes());
        // call thunk (rel32 to offset 12), thunk: REX jmp rel32.
        assert_eq!(&code.code[7..12], &[0xe8, 0, 0, 0, 0]);
        assert_eq!(&code.code[12..14], &[0x40, 0xe9]);
        code.relocate(0x1000).unwrap();
        let word = |i: usize| u64::from_le_bytes(code.data[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!(word(0), 0x3);
        assert_eq!(word(1), (2 << 4) | 0x7);
        assert_eq!(word(2), 42);
        assert_eq!(word(3), 0x1007);
        assert_eq!(&code.code[14..18], &(0x5000_i32 - 0x1012).to_le_bytes());
    }

    #[test]
    fn named_rodata_round_trips_through_codegen() {
        let mut ga =
            BeamGlobalAssembler::new(crate::common::process_offsets::ProcessOffsets::ERTS_X86_64)
                .unwrap();
        ga.codegen().unwrap();
        let mut module =
            BeamModuleAssembler::new_module(&ga, 1, 0, vec![ArgType::ANY], []).unwrap();
        module.embed_rodata("str", &[0, 1, 2, 255]).unwrap();
        module.embed_rodata("empty", &[]).unwrap();

        let (memory, _) = module.codegen(&BeamCodeHeader::default()).unwrap();
        let base = memory.as_ptr() as usize;
        let address = module.get_rodata("str").unwrap();
        let mut bytes = [0; 4];
        memory.read(address - base, &mut bytes).unwrap();
        similar_asserts::assert_eq!(bytes, [0, 1, 2, 255]);
        assert_eq!(module.get_rodata("empty"), None);
    }

    #[test]
    fn nif_stub_copies_the_three_loader_words_after_its_prologue() {
        use arinsal_term::{ErtsCodeMfa, Term, atoms};

        let info = ErtsCodeInfo {
            u: core::sync::atomic::AtomicUsize::new(0),
            gen_bp: core::sync::atomic::AtomicUsize::new(0),
            mfa: ErtsCodeMfa {
                module: Term::atom(atoms::ERLANG).word(),
                function: Term::atom(atoms::LOAD_NIF).word(),
                arity: 2,
            },
        };
        let mut ga =
            BeamGlobalAssembler::new(crate::common::process_offsets::ProcessOffsets::ERTS_X86_64)
                .unwrap();
        let _global_code = ga.codegen().unwrap();
        let (normal_fptr, lib, dirty_fptr) = (0x1111_2222, 0x3333_4444, 0x5555_6666);
        // `ErtsNifBeamStub.code.call_nif` is 64 bytes; info precedes it in the C buffer.
        let capacity = core::mem::size_of::<ErtsCodeInfo>() + 64;
        let (mut first, mut second) = (vec![0; capacity], vec![0; capacity]);
        let first_size = ga
            .beamasm_emit_call_nif(&info, normal_fptr, lib, dirty_fptr, &mut first)
            .unwrap();
        let second_size = ga
            .beamasm_emit_call_nif(&info, normal_fptr, lib, dirty_fptr, &mut second)
            .unwrap();

        similar_asserts::assert_eq!(&first[..first_size], &second[..second_size]);
        assert!(first_size <= capacity);
        similar_asserts::assert_eq!(&first[..5], &[0xe8, 0, 0, 0, 0]);
        // erl_nif.c copies bytes beginning at the 8-byte function prologue. The three
        // ErtsNativeFunc words begin at ErtsCodeInfo + BEAM_ASM_NFUNC_SIZE (16 on x86).
        let words = core::mem::size_of::<ErtsCodeInfo>() + 16;
        assert!(first_size >= words + 3 * core::mem::size_of::<usize>());
        let read_word = |at: usize| {
            u64::from_le_bytes(first[at..at + 8].try_into().expect("word fits in stub"))
        };
        similar_asserts::assert_eq!(
            [
                read_word(words),
                read_word(words + 8),
                read_word(words + 16)
            ],
            [normal_fptr as u64, lib as u64, dirty_fptr as u64]
        );
    }
}
