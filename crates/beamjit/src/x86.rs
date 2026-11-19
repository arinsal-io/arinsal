//! The x86-64 module assembler driver: the x86 side of erts/emulator/beam/jit/beam_jit_main.cpp
//! (`beamasm_init`, `beamasm_new_assembler`, `beamasm_emit`, `beamasm_emit_coverage`,
//! `beamasm_codegen`, `beamasm_get_*`, `beamasm_patch_*`), which hands each specific
//! instruction of the loader to the x86 module assembler through the dispatch `beam_makeops`
//! generates from `beam/jit/x86/ops.tab` (`beamasm_emit.h`, here
//! `arinsal_beamops::beamasm_emit!`), and the emit half of erts/emulator/beam/jit/asm_load.c
//! (`beam_load_prepare_emit`, `add_line_entry`, the special cases of `beam_load_emit_op`),
//! OTP-29.1.1.
//!
//! An emitter the x86 `BeamModuleAssembler` does not have yet is a compile error naming it:
//! the remaining I-box inventory.

// The `op_*` constants keep the names beam_makeops generates.
#![allow(non_upper_case_globals)]

use crate::beam_asm::{
    CompileError, LoaderEnv, beam_load_emit_op, resolve_new_literal, with_transform_arena,
};
use arinsal_beam::BeamFile;
use arinsal_beamasm::beam_asm::AsmError;
use arinsal_beamasm::beam_asm_global::{BeamGlobalAssembler, ProcessOffsets};
use arinsal_beamasm::beam_asm_module::{BeamCodeHeader, BeamModuleAssembler};
use arinsal_beamasm::common::args::ArgVal;
use arinsal_beamasm::common::types::ArgType;
use arinsal_beamops::beam_opcodes::{
    op_aligned_label_Lt, op_call_bif_mfa_aaI, op_empty_func_line, op_executable_line_II,
    op_func_line_I, op_i_debug_line_IIt, op_i_func_info_IaaI, op_i_test_yield, op_int_code_end,
    op_line_I, op_nif_start, op_send,
};
use arinsal_beamops::{self as beamops, NewLiteral, OpSink, SpecificOperand};
pub use arinsal_x64::exec::CodeMemory;

/// erts' process-wide JIT state after `beamasm_init`: the global assembler `bga`, whose
/// fragments live in `global_code`, and the `erts_beamasm` stub module in `stub_code`, both
/// for as long as the emulator runs. The VM owns it; erts keeps it in statics.
pub struct BeamAsm {
    /// `bga`.
    pub bga: BeamGlobalAssembler,
    /// The executable memory of the global fragments.
    pub global_code: CodeMemory,
    /// The executable memory of the `erts_beamasm` module (`bma`'s code).
    pub stub_code: CodeMemory,
    /// The code pointers of the `erts_beamasm` module.
    pub stubs: BeamAsmStubs,
}

/// The `ErtsCodePtr` globals `beamasm_init` takes from the `erts_beamasm` module
/// (`*op.target = bma->getCode(op.operand)`).
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:256-269 (the `operands` table) and
// beam_common.h:280-289 (the globals), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Default)]
pub struct BeamAsmStubs {
    /// `beam_run_process`.
    pub run_process: usize,
    /// `beam_normal_exit`.
    pub normal_exit: usize,
    /// `beam_continue_exit`.
    pub continue_exit: usize,
    /// `beam_exception_trace`.
    pub exception_trace: usize,
    /// `beam_return_trace`.
    pub return_trace: usize,
    /// `beam_return_to_trace`.
    pub return_to_trace: usize,
    /// `beam_call_trace_return`.
    pub call_trace_return: usize,
}

/// `beamasm_init()`: the global assembler first, its code generated into executable memory,
/// then the `erts_beamasm` module of stubs (`run_process`, `normal_exit`, `continue_exit`,
/// the trace returns), each a function of its own whose entry label is the stub's address.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:243-381 (beamasm_init), OTP-29.1.1.
///
/// `offsets` are the VM's `offsetof(Process, ...)` values the fragments compile in
/// (`arinsal_vm::PROCESS_STATE_OFFSET`, `PROCESS_SIGQ_SAVE_OFFSET`, `ERTS_MESSAGE_TERM_OFFSET`).
pub fn beamasm_init(offsets: ProcessOffsets) -> Result<BeamAsm, AsmError> {
    use arinsal_beamops::beam_opcodes::{
        op_continue_exit, op_i_apply_only, op_i_call_trace_return, op_i_return_to_trace,
        op_normal_exit, op_return_trace,
    };
    use arinsal_term::{Term, atoms};
    let mut bga = BeamGlobalAssembler::new(offsets)?;
    let global_code = bga.codegen()?;
    let operands = [
        (atoms::RUN_PROCESS, 3, op_i_apply_only),
        (atoms::NORMAL_EXIT, 0, op_normal_exit),
        (atoms::CONTINUE_EXIT, 0, op_continue_exit),
        (atoms::EXCEPTION_TRACE, 0, op_return_trace),
        (atoms::RETURN_TRACE, 0, op_return_trace),
        (atoms::RETURN_TO_TRACE, 0, op_i_return_to_trace),
        (atoms::CALL_TRACE_RETURN, 0, op_i_call_trace_return),
    ];
    // `ERTS_DECL_AM(erts_beamasm)`.
    let mod_name = arinsal_term::global_atoms()
        .intern("erts_beamasm")
        .map_err(|_| AsmError::Operand("erts_beamasm atom"))?;
    let mut bma = BeamModuleAssembler::new_module_with_module(
        &bga,
        1 + operands.len() as u32 * 2,
        operands.len(),
        vec![ArgType::ANY],
        [],
        Some(mod_name),
    )?;
    let word = core::mem::size_of::<u64>() as u64;
    let mut label = 1;
    let mut entries = [0_u32; 7];
    for (entry, &(name, arity, op)) in entries.iter_mut().zip(&operands) {
        let func_label = label;
        let entry_label = label + 1;
        label += 2;
        beamasm_emit(
            &mut bma,
            usize::from(op_aligned_label_Lt),
            &[ArgVal::Label(func_label), ArgVal::Word(word)],
        )?;
        beamasm_emit(
            &mut bma,
            usize::from(op_i_func_info_IaaI),
            &[
                ArgVal::Word(u64::from(func_label)),
                ArgVal::Immediate(Term::atom(mod_name).word()),
                ArgVal::Immediate(Term::atom(name).word()),
                ArgVal::Word(arity),
            ],
        )?;
        beamasm_emit(
            &mut bma,
            usize::from(op_aligned_label_Lt),
            &[ArgVal::Label(entry_label), ArgVal::Word(word)],
        )?;
        beamasm_emit(&mut bma, usize::from(op), &[])?;
        *entry = entry_label;
    }
    beamasm_emit(&mut bma, usize::from(op_int_code_end), &[])?;
    let load_header = BeamCodeHeader {
        num_functions: operands.len() as u64,
        ..BeamCodeHeader::default()
    };
    let (stub_code, _code_hdr_ro) = bma.codegen(&load_header)?;
    let code = |index: usize| {
        bma.get_code(entries[index])
            .ok_or(AsmError::Operand("erts_beamasm entry label"))
    };
    let stubs = BeamAsmStubs {
        run_process: code(0)?,
        normal_exit: code(1)?,
        continue_exit: code(2)?,
        exception_trace: code(3)?,
        return_trace: code(4)?,
        return_to_trace: code(5)?,
        call_trace_return: code(6)?,
    };
    Ok(BeamAsm {
        bga,
        global_code,
        stub_code,
        stubs,
    })
}

/// `beamasm_new_assembler(mod, num_labels, num_functions, file)`: the module assembler the
/// load emits into, starting with the module's code header.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:508-517 (beamasm_new_assembler), OTP-29.1.1.
pub fn beamasm_new_assembler(
    jit: &BeamAsm,
    beam: &BeamFile,
) -> Result<BeamModuleAssembler, AsmError> {
    let module = arinsal_term::global_atoms()
        .intern(&beam.module)
        .map_err(|_| AsmError::Operand("module atom"))?;
    BeamModuleAssembler::new_module_with_module(
        &jit.bga,
        beam.code.label_count,
        beam.code.function_count as usize,
        beam_types(beam),
        beam.lambdas
            .iter()
            .map(|lambda| (lambda.index, lambda.label, lambda.num_free)),
        Some(module),
    )
}

/// `beam->types.entries`: the module's type table, or `init_fallback_type_table`'s single
/// `any` entry when the module has no `Type` chunk.
// Port of erts/emulator/beam/beam_file.c:607-705 (init_fallback_type_table,
// parse_type_chunk_data), OTP-29.1.1.
fn beam_types(beam: &BeamFile) -> Vec<ArgType> {
    match beam.types.as_ref() {
        Some(table) => table
            .entries
            .iter()
            .map(|entry| ArgType {
                union_bits: entry.union_bits,
                min: entry.lower_bound,
                max: entry.upper_bound,
                unit: entry.unit,
            })
            .collect(),
        None => vec![ArgType::ANY],
    }
}

/// `beamasm_emit(instance, specific_op, op)` after the operands are converted to `ArgVal`s:
/// `ba->emit(specific_op, args)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:519-532 (beamasm_emit) and
// erts/emulator/beam/jit/x86/beam_asm_module.cpp:419-445 (BeamModuleAssembler::emit),
// OTP-29.1.1.
pub fn beamasm_emit(
    ba: &mut BeamModuleAssembler,
    specific_op: usize,
    args: &[ArgVal],
) -> Result<(), AsmError> {
    arinsal_beamops::beamasm_emit!(ba, specific_op, args)
}

/// `beamasm_codegen(instance, &executable, &writable, in_hdr, &out_exec_hdr, &out_rw_hdr)`:
/// the span (both views) and the executable code header.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:620-633 (beamasm_codegen), OTP-29.1.1.
pub fn beamasm_codegen(
    ba: &mut BeamModuleAssembler,
    in_hdr: &BeamCodeHeader,
) -> Result<(CodeMemory, usize), AsmError> {
    ba.codegen(in_hdr)
}

/// `beamasm_get_code(instance, label)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:588-591 (beamasm_get_code), OTP-29.1.1.
pub fn beamasm_get_code(ba: &BeamModuleAssembler, label: u32) -> Option<usize> {
    ba.get_code(label)
}

/// `beamasm_get_lambda(instance, index)`: the code of the lambda `index` (its trampoline).
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:593-596 (beamasm_get_lambda), OTP-29.1.1.
pub fn beamasm_get_lambda(ba: &BeamModuleAssembler, index: u32) -> Option<usize> {
    ba.asm.get_code(ba.lambda_trampoline(index).ok()?)
}

/// `beamasm_get_header(instance, &hdr)`: the executable code header and the code size.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:642-648 (beamasm_get_header), OTP-29.1.1.
pub fn beamasm_get_header(ba: &BeamModuleAssembler) -> Option<(usize, usize)> {
    Some((ba.get_code_header()?, ba.get_code_size()?))
}

/// `beamasm_get_base(instance)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:650-653 (beamasm_get_base), OTP-29.1.1.
pub fn beamasm_get_base(ba: &BeamModuleAssembler) -> Option<usize> {
    ba.asm.get_base_address()
}

/// `beamasm_get_offset(instance)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:655-658 (beamasm_get_offset), OTP-29.1.1.
pub fn beamasm_get_offset(ba: &BeamModuleAssembler) -> usize {
    ba.asm.get_offset()
}

/// `beamasm_get_on_load(instance)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:660-663 (beamasm_get_on_load), OTP-29.1.1.
pub fn beamasm_get_on_load(ba: &BeamModuleAssembler) -> Option<usize> {
    ba.get_on_load()
}

/// `beamasm_patch_catches(instance, rw_base)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:665-668 (beamasm_patch_catches), OTP-29.1.1.
pub fn beamasm_patch_catches(
    ba: &BeamModuleAssembler,
    rw: &mut CodeMemory,
) -> Result<u32, AsmError> {
    ba.patch_catches(rw)
}

/// `beamasm_patch_import(instance, rw_base, index, import)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:670-676 (beamasm_patch_import), OTP-29.1.1.
pub fn beamasm_patch_import(
    ba: &BeamModuleAssembler,
    rw: &mut CodeMemory,
    index: u32,
    import: usize,
) -> Result<(), AsmError> {
    ba.patch_import(rw, index, import)
}

/// `beamasm_patch_literal(instance, rw_base, index, lit)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:678-684 (beamasm_patch_literal), OTP-29.1.1.
pub fn beamasm_patch_literal(
    ba: &BeamModuleAssembler,
    rw: &mut CodeMemory,
    index: i64,
    lit: u64,
) -> Result<(), AsmError> {
    ba.patch_literal(rw, index, lit)
}

/// `beamasm_patch_lambda(instance, rw_base, index, fe)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:686-692 (beamasm_patch_lambda), OTP-29.1.1.
pub fn beamasm_patch_lambda(
    ba: &BeamModuleAssembler,
    rw: &mut CodeMemory,
    index: u32,
    fe: usize,
) -> Result<(), AsmError> {
    ba.patch_lambda(rw, index, fe)
}

/// `beamasm_patch_strings(instance, rw_base, string_table)`.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:694-699 (beamasm_patch_strings), OTP-29.1.1.
pub fn beamasm_patch_strings(
    ba: &BeamModuleAssembler,
    rw: &mut CodeMemory,
    string_table: usize,
) -> Result<(), AsmError> {
    ba.patch_strings(rw, string_table)
}

/// `ERTS_COV_*`: the coverage mode of a module.
// Port of erts/emulator/beam/global.h:1258-1262, OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u64)]
pub enum CoverageMode {
    /// `ERTS_COV_NONE`.
    #[default]
    None = 0,
    /// `ERTS_COV_FUNCTION`.
    Function = 1,
    /// `ERTS_COV_FUNCTION_COUNTERS`.
    FunctionCounters = 2,
    /// `ERTS_COV_LINE`.
    Line = 3,
    /// `ERTS_COV_LINE_COUNTERS`.
    LineCounters = 4,
}

/// `BEAMFILE_EXECUTABLE_LINE` / `BEAMFILE_FORCE_LINE_COUNTERS` of the line chunk flags.
// Port of erts/emulator/beam/beam_file.h:129-132, OTP-29.1.1.
const BEAMFILE_EXECUTABLE_LINE: u32 = 1;
const BEAMFILE_FORCE_LINE_COUNTERS: u32 = 2;

/// `MAX_ARG`.
// Port of erts/emulator/beam/beam_load.h (MAX_ARG), OTP-29.1.1.
const MAX_ARG: u64 = 255;

/// `LineInstr`: a code offset and the source location there.
// Port of erts/emulator/beam/jit/load.h:41-44 (LineInstr), OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineInstr {
    /// `pos`: the offset in the code (`beamasm_get_offset`).
    pub pos: usize,
    /// `loc`: the location index.
    pub loc: u32,
}

/// The emit half of erts' `LoaderState` (jit/load.h): the module assembler, the function
/// and line bookkeeping of `beam_load_emit_op`, and the prepared code header with the
/// coverage tables the emitted code counts into. The labels, lambda literals and BIF imports
/// of erts' `LoaderState` are the transform engine's (`arinsal_beamops`) and the
/// [`LoaderEnv`]'s.
pub struct LoaderState<'a, E: LoaderEnv + ?Sized> {
    beam: &'a BeamFile,
    env: &'a E,
    /// `ba`.
    pub ba: BeamModuleAssembler,
    /// The `ArgVal`s of the instruction being emitted, reused across instructions.
    args: Vec<ArgVal>,
    /// `function_number`: the functions seen so far.
    pub function_number: u32,
    /// The functions emitted so far, for the code header's function table that
    /// `beam_load_finalize_code` writes from the assembler's `functions`.
    pub functions: Vec<EmittedFunction>,
    /// `function`: the name of the current function, for error messages.
    pub function: u64,
    /// `arity`: the arity of the current function.
    pub arity: u64,
    /// `current_li`: the line instructions recorded so far.
    pub current_li: u32,
    /// `line_instr`: allocated when the module has line items.
    pub line_instr: Option<Vec<LineInstr>>,
    /// `func_line`: the first line instruction of each function.
    pub func_line: Option<Vec<u32>>,
    /// `beam.debug.items[i].location_index`, one per item of the `DbgB` chunk (`-1`, here
    /// `None`, until its `i_debug_line` is emitted).
    pub debug_location_index: Vec<Option<u32>>,
    /// `load_hdr`: the prepared code header (`coverage_mode`, `line_coverage_len`, ...).
    pub load_hdr: BeamCodeHeader,
    /// `load_hdr->are_nifs`: the functions declared `-nifs()`.
    pub are_nifs: Option<Vec<u8>>,
    /// `coverage`: byte flags or word counters, at a stable address the code counts into.
    pub coverage: Option<Box<[u64]>>,
    /// `line_coverage_valid`.
    pub line_coverage_valid: Option<Vec<u8>>,
    /// `loc_index_to_cover_id`.
    pub loc_index_to_cover_id: Option<Vec<u32>>,
}

/// A function as the emit saw it: the name and arity of its `i_func_info`, the first
/// `aligned_label` after it (the entry, `int_func_start`'s `Entry_Label`) and whether its
/// body starts with `nif_start`.
// Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp (emit_i_func_info appends the
// function's ErtsCodeInfo to `functions`) and generators.tab (int_func_start), OTP-29.1.1.
#[derive(Clone, Copy, Debug)]
pub struct EmittedFunction {
    /// Global atom index of the function name.
    pub atom: u32,
    /// The function's arity.
    pub arity: u8,
    /// The entry label.
    pub entry_label: u32,
    /// The body starts with `nif_start`.
    pub nif_stub: bool,
}

/// `stp->beam.lines.item_count`: the items of the line chunk plus the undefined location 0,
/// or 0 without a line chunk.
// Port of erts/emulator/beam/beam_file.c:466-487 (parse_line_chunk, `item_count++`),
// OTP-29.1.1.
fn line_item_count(beam: &BeamFile) -> u32 {
    beam.lines
        .as_ref()
        .map_or(0, |lines| lines.items.len() as u32 + 1)
}

/// `beam_load_prepare_emit(stp)`: the module assembler, the code header with the coverage
/// mode and tables, and the line tables of a module with line items.
// Port of erts/emulator/beam/jit/asm_load.c:47-208 (beam_load_prepare_emit), OTP-29.1.1.
pub fn beam_load_prepare_emit<'a, E: LoaderEnv + ?Sized>(
    jit: &BeamAsm,
    beam: &'a BeamFile,
    env: &'a E,
    erts_coverage_mode: CoverageMode,
    erts_debugger_flags: u64,
) -> Result<LoaderState<'a, E>, AsmError> {
    let mut ba = beamasm_new_assembler(jit, beam)?;
    for index in 0..env.literal_count(beam) {
        let literal = env
            .literal(beam, index as i64)
            .map_err(|_| AsmError::Operand("module literal index"))?;
        ba.set_beam_literal(index as i64, literal);
    }
    let num_functions = u64::from(beam.code.function_count);
    let flags = beam.lines.as_ref().map_or(0, |lines| lines.flags);
    let instruction_count = beam
        .lines
        .as_ref()
        .map_or(0, |lines| lines.instruction_count as usize);
    let coverage_mode = if flags & BEAMFILE_FORCE_LINE_COUNTERS != 0 {
        CoverageMode::LineCounters
    } else if flags & BEAMFILE_EXECUTABLE_LINE == 0
        && matches!(
            erts_coverage_mode,
            CoverageMode::Line | CoverageMode::LineCounters
        )
    {
        // A line coverage mode is enabled, but this module has no executable_line
        // instructions: no coverage for it.
        CoverageMode::None
    } else {
        erts_coverage_mode
    };
    let zeroed = |bytes: usize| vec![0_u64; bytes.div_ceil(8)].into_boxed_slice();
    let (mut coverage, mut line_coverage_valid, mut loc_index_to_cover_id) = (None, None, None);
    let mut line_coverage_len = 0;
    match coverage_mode {
        CoverageMode::Function => coverage = Some(zeroed(num_functions as usize)),
        CoverageMode::FunctionCounters => coverage = Some(zeroed(num_functions as usize * 8)),
        CoverageMode::Line | CoverageMode::LineCounters => {
            let size = if coverage_mode == CoverageMode::Line {
                1
            } else {
                8
            };
            coverage = Some(zeroed(instruction_count * size));
            line_coverage_valid = Some(vec![0; instruction_count]);
            if coverage_mode == CoverageMode::LineCounters {
                loc_index_to_cover_id = Some(vec![0; instruction_count]);
            }
            line_coverage_len = instruction_count as u64;
        }
        CoverageMode::None => {}
    }
    let load_hdr = BeamCodeHeader {
        num_functions,
        debugger_flags: erts_debugger_flags,
        coverage_mode: coverage_mode as u64,
        line_coverage_len,
        ..BeamCodeHeader::default()
    };
    let has_lines = line_item_count(beam) > 0;
    Ok(LoaderState {
        beam,
        env,
        ba,
        args: Vec::new(),
        function_number: 0,
        functions: Vec::new(),
        function: 0,
        arity: 0,
        current_li: 0,
        line_instr: has_lines.then(|| Vec::with_capacity(instruction_count)),
        func_line: has_lines.then(|| vec![0; beam.code.function_count as usize]),
        debug_location_index: vec![None; beam.debug_items().map_or(0, |items| items.len())],
        load_hdr,
        are_nifs: None,
        coverage,
        line_coverage_valid,
        loc_index_to_cover_id,
    })
}

/// The value of a word or immediate operand (`tmp_op->a[n].val`).
fn arg_value(arg: ArgVal) -> u64 {
    match arg {
        ArgVal::Word(value) | ArgVal::Immediate(value) => value,
        _ => 0,
    }
}

impl<E: LoaderEnv + ?Sized> LoaderState<'_, E> {
    /// `add_line_entry(stp, item, insert_duplicates)`: records the code offset of a line
    /// instruction, skipping a repeat of the previous location unless asked not to.
    // Port of erts/emulator/beam/jit/asm_load.c:318-355 (add_line_entry), OTP-29.1.1.
    fn add_line_entry(&mut self, item: u64, insert_duplicates: bool) -> Result<(), String> {
        let item_count = line_item_count(self.beam);
        if item_count == 0 {
            return Ok(());
        }
        if item >= u64::from(item_count) {
            return Err(format!(
                "line instruction index overflow ({item}/{item_count})"
            ));
        }
        let instruction_count = self
            .beam
            .lines
            .as_ref()
            .map_or(0, |lines| lines.instruction_count);
        let li = self.current_li;
        if li >= instruction_count {
            return Err(format!(
                "line instruction table overflow ({li}/{instruction_count})"
            ));
        }
        let pos = beamasm_get_offset(&self.ba);
        let line_instr = self.line_instr.get_or_insert_with(Vec::new);
        let is_duplicate = line_instr
            .last()
            .is_some_and(|last| u64::from(last.loc) == item);
        if insert_duplicates || !is_duplicate {
            line_instr.push(LineInstr {
                pos,
                loc: item as u32,
            });
            self.current_li += 1;
        }
        Ok(())
    }

    /// `beamasm_emit_coverage(stp->ba, stp->coverage, index, size)`.
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:534-541 (beamasm_emit_coverage),
    // OTP-29.1.1.
    fn emit_coverage(&mut self, index: u64, size: u64) -> Result<(), String> {
        let coverage = self
            .coverage
            .as_ref()
            .ok_or("coverage table missing")?
            .as_ptr() as usize;
        self.ba
            .emit_coverage(coverage, index, size)
            .map_err(|error| format!("coverage: {error:?}"))
    }

    /// `beam_load_emit_op` from the massaged operands on: the function count and context, the
    /// first line of each function and `-nifs()` before the emit; the line entries and
    /// coverage counters after it, and the function count check at the end of the code.
    // Port of erts/emulator/beam/jit/asm_load.c:609-772 (beam_load_emit_op, after the
    // operand massaging), OTP-29.1.1.
    fn emit_specific(&mut self, specific: u16, operands: &[SpecificOperand]) -> Result<(), String> {
        let function_count = self.beam.code.function_count;
        match specific {
            op_i_func_info_IaaI => {
                if self.function_number >= function_count {
                    return Err(format!(
                        "too many functions in module (header said {function_count})"
                    ));
                }
                self.function_number += 1;
                let (Some(SpecificOperand::Atom(atom)), Some(SpecificOperand::Unsigned(arity))) =
                    (operands.get(2), operands.get(3))
                else {
                    return Err("i_func_info operands".into());
                };
                self.functions.push(EmittedFunction {
                    atom: *atom,
                    arity: *arity as u8,
                    entry_label: 0,
                    nif_stub: false,
                });
                // Save context for error messages.
                self.function = arg_value(self.args[2]);
                self.arity = arg_value(self.args[3]);
                if self.arity > MAX_ARG {
                    return Err(format!("too many arguments: {}", self.arity));
                }
            }
            // The first line instruction of a function, preceding the func_info instruction.
            op_empty_func_line | op_func_line_I => {
                let (n, li) = (self.function_number as usize, self.current_li);
                if let Some(func_line) = self.func_line.as_mut() {
                    func_line[n] = li;
                }
            }
            // The first aligned label after the `i_func_info` is the entry label.
            op_aligned_label_Lt => {
                // `L` is massaged from `TAG_u` to the label (asm_load.c, case 'L').
                if let (Some(function), Some(ArgVal::Label(label))) =
                    (self.functions.last_mut(), self.args.first())
                    && function.entry_label == 0
                {
                    function.entry_label = *label;
                }
            }
            op_nif_start => {
                let n = self.function_number as usize;
                if n == 0 {
                    return Err("nif_start outside a function".into());
                }
                if let Some(function) = self.functions.last_mut() {
                    function.nif_stub = true;
                }
                self.are_nifs
                    .get_or_insert_with(|| vec![0; function_count as usize])[n - 1] = 1;
            }
            _ => {}
        }

        match specific {
            op_call_bif_mfa_aaI => {
                let [
                    SpecificOperand::Atom(module),
                    SpecificOperand::Atom(function),
                    SpecificOperand::Unsigned(arity),
                ] = operands
                else {
                    return Err("call_bif_mfa operands".into());
                };
                // The transformed operands name global atoms (`SpecificOperand::Atom`).
                let atoms = arinsal_term::global_atoms();
                let module = atoms
                    .text(arinsal_term::Atom(*module))
                    .ok_or("call_bif_mfa module atom")?;
                let function = atoms
                    .text(arinsal_term::Atom(*function))
                    .ok_or("call_bif_mfa function atom")?;
                let arity = u8::try_from(*arity).map_err(|_| "call_bif_mfa arity")?;
                let function = self
                    .env
                    .bif_mfa_function(module, function, arity)?
                    .try_into()
                    .map_err(|_| "call_bif_mfa function pointer")?;
                self.ba.set_call_bif_mfa_function(function);
            }
            op_send => {
                let (export, function) = self.env.send_target()?;
                self.ba.set_send_target(export as usize, function as usize);
            }
            _ => {}
        }

        beamasm_emit(&mut self.ba, usize::from(specific), &self.args)
            .map_err(|error| format!("failed to emit asm for {specific}: {error:?}"))?;

        let coverage_mode = self.load_hdr.coverage_mode;
        let line = coverage_mode == CoverageMode::Line as u64;
        let line_counters = coverage_mode == CoverageMode::LineCounters as u64;
        match specific {
            // The beginning of a new function: insert the line entry even if it repeats the
            // previous one.
            op_func_line_I => self.add_line_entry(arg_value(self.args[0]), true)?,
            op_line_I => self.add_line_entry(arg_value(self.args[0]), false)?,
            op_executable_line_II => {
                self.add_line_entry(arg_value(self.args[0]), false)?;
                let coverage_size = if line {
                    1
                } else if line_counters {
                    8
                } else {
                    0
                };
                if coverage_size != 0 {
                    let loc_index = self.current_li - 1;
                    let cover_id = arg_value(self.args[1]) as u32;
                    if let Some(valid) = self.line_coverage_valid.as_mut() {
                        valid[loc_index as usize] = 1;
                    }
                    if let Some(ids) = self.loc_index_to_cover_id.as_mut() {
                        ids[loc_index as usize] = cover_id;
                    }
                    self.emit_coverage(u64::from(loc_index), coverage_size)?;
                }
            }
            op_i_debug_line_IIt => {
                let index = arg_value(self.args[1]).wrapping_sub(1) as usize;
                let item_count = self.debug_location_index.len();
                if index >= item_count {
                    return Err(format!(
                        "debug_line index {index} out of range (only {item_count} entries)"
                    ));
                }
                // Each i_debug_line is a distinct instrumentation point and none may be
                // missed (so they all can be selected): keep duplicates.
                self.add_line_entry(arg_value(self.args[0]), true)?;
                debug_assert!(self.debug_location_index[index].is_none());
                self.debug_location_index[index] = Some(self.current_li - 1);
            }
            op_int_code_end => {
                if self.function_number != function_count {
                    return Err(format!(
                        "too few functions ({}) in module (header said {function_count})",
                        self.function_number
                    ));
                }
                // `stp->function = THE_NON_VALUE` (0).
                self.function = 0;
                if line || line_counters {
                    self.load_hdr.line_coverage_len = u64::from(self.current_li);
                }
            }
            op_i_test_yield => {
                let index = u64::from(self.function_number.saturating_sub(1));
                if coverage_mode == CoverageMode::Function as u64 {
                    self.emit_coverage(index, 1)?;
                } else if coverage_mode == CoverageMode::FunctionCounters as u64 {
                    self.emit_coverage(index, 8)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl<E: LoaderEnv + ?Sized> OpSink for LoaderState<'_, E> {
    fn new_literal(&mut self, index: u32, literal: &NewLiteral) -> Result<(), String> {
        resolve_new_literal(self.beam, self.env, index, literal)?;
        let word = self.env.literal(self.beam, i64::from(index))?;
        self.ba.set_beam_literal(i64::from(index), word);
        Ok(())
    }

    // Port of erts/emulator/beam/jit/asm_load.c:357-772 (beam_load_emit_op), OTP-29.1.1.
    fn emit(&mut self, op: u16, specific: u16, operands: &[SpecificOperand]) -> Result<(), String> {
        let info = beamops::specific_op_info(specific)
            .ok_or_else(|| format!("no specific instruction {specific}"))?;
        beam_load_emit_op(self.beam, self.env, info.sign, operands, &mut self.args)
            .map_err(|error| format!("{}: {error}", info.name))?;
        for arg in &self.args {
            if let ArgVal::Literal(index @ ..=-1) = arg {
                let word = self.env.literal(self.beam, *index)?;
                self.ba.set_beam_literal(*index, word);
            }
        }
        self.emit_specific(specific, operands)
            .map_err(|error| format!("{} ({}): {error}", info.name, beamops::generic_op_name(op)))
    }
}

/// Emits the code of the module of `stp` into `stp.ba`: the transform engine's specific
/// instructions, each through `beam_load_emit_op` and `beamasm_emit`, as erts' `load_code`
/// does with `stp->ba`.
// Port of erts/emulator/beam/beam_load.c (load_code) with the BeamAsm emit of
// erts/emulator/beam/jit/asm_load.c, OTP-29.1.1.
pub fn load_code<E: LoaderEnv + ?Sized>(
    stp: &mut LoaderState<'_, E>,
    line_breakpoints: bool,
) -> Result<(), CompileError> {
    let beam = stp.beam;
    with_transform_arena(|arena| beamops::load_code(beam, line_breakpoints, true, arena, stp))
        .map_err(|error| CompileError::Assemble(format!("{}: {error}", beam.module)))
}
