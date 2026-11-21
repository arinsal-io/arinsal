//! Tests of the x86 code generation of erts/emulator/beam/jit/x86/beam_asm_module.cpp and
//! jit/beam_jit_common.cpp (`codegen`, `getCode`, `patch*`) and of beam_asm_global.cpp's
//! global code: a module compiled by `erlc` goes through the loader's transform engine
//! (`arinsal_beamops::load_code`), the x86 module assembler and codegen into dual-mapped
//! executable memory next to the global fragments, and its functions run through the native
//! entry bridge (`x86::rt`), OTP-29.1.1.
//!
//! The beamjit x86 driver does not compile until every emitter exists, so the operands are
//! massaged here as asm_load.c's `beam_load_emit_op` does for the instructions this module
//! uses, and dispatched by name to the emitters ported so far.

use std::ops::Range;
use std::path::PathBuf;
use std::process::Command;

use arinsal_beamops::{NewLiteral, OpSink, SpecificOperand, TransformArena};
use arinsal_term::Term;
use similar_asserts::assert_eq;

use super::beam_asm_global::{BeamGlobalAssembler, GLOBAL_LABELS};
use super::beam_asm_module::{BeamCodeHeader, BeamModuleAssembler};
use super::jdump::{
    erts_to_arinsal, gnu_as, matches_with_global_jumps, matches_with_global_jumps_at,
};
use crate::common::args::ArgVal;
use crate::common::types::ArgType;
use crate::{ExitReason, ProcessHeader, SchedulerRegisters};

const SOURCE: &str = "-module(x86_first).
-export([id/1, second/2, head/1, tail/1, sel/1, elem2/1, swap/2]).
id(X) -> X.
second(_, B) -> B.
head([H | _]) -> H.
tail([_ | T]) -> T.
sel(a) -> 1;
sel(b) -> 2;
sel(c) -> 3;
sel(_) -> 0.
elem2({_, B}) -> B.
swap(A, B) -> id2(B, A).
id2(X, _) -> X.
";

/// Compiles [`SOURCE`] with `erlc`; `None` (the test is skipped) without `erlc`.
fn compile() -> Option<Vec<u8>> {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("arinsal-x86-codegen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("x86_first.erl");
    std::fs::write(&source, SOURCE).unwrap();
    let status = match Command::new("erlc")
        .arg("+deterministic")
        .arg("-o")
        .arg(&dir)
        .arg(&source)
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            eprintln!("skipping: erlc not available ({error})");
            return None;
        }
    };
    assert!(status.success(), "erlc failed");
    let beam = std::fs::read(dir.join("x86_first.beam")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    Some(beam)
}

fn compile_source_with_dependencies(
    module: &str,
    source: &str,
    dependencies: &[(&str, &str)],
) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("arinsal-x86-{module}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    for (dependency, dependency_source) in dependencies {
        std::fs::write(dir.join(format!("{dependency}.erl")), dependency_source).ok()?;
        let status = Command::new("erlc")
            .args(["+deterministic", "-o"])
            .arg(&dir)
            .arg(dir.join(format!("{dependency}.erl")))
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
    }
    std::fs::write(dir.join(format!("{module}.erl")), source).ok()?;
    let status = Command::new("erlc")
        .args(["+deterministic", "-pa"])
        .arg(&dir)
        .arg("-o")
        .arg(&dir)
        .arg(dir.join(format!("{module}.erl")))
        .status()
        .ok()?;
    let beam = if status.success() {
        std::fs::read(dir.join(format!("{module}.beam"))).ok()?
    } else {
        return None;
    };
    let _ = std::fs::remove_dir_all(&dir);
    Some(beam)
}

const NIL: u64 = 0x3b;
const TEST_FUNCTION_POINTER: usize = 0x1234_5678_9abc_def0;
const TEST_EXPORT_POINTER: usize = 0x2345_6789_abcd_ef01;

fn module_types(beam: &arinsal_beam::BeamFile) -> Vec<ArgType> {
    beam.types.as_ref().map_or_else(
        || vec![ArgType::ANY],
        |types| {
            types
                .entries
                .iter()
                .map(|entry| ArgType {
                    union_bits: entry.union_bits,
                    min: entry.lower_bound,
                    max: entry.upper_bound,
                    unit: entry.unit,
                })
                .collect()
        },
    )
}

fn full_dump_blocks(dump: &str) -> Vec<(String, Vec<String>)> {
    let is_header = |line: &str| {
        line.strip_prefix("# ").is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    };
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in dump.lines() {
        if is_header(line) {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some((line[2..].to_owned(), Vec::new()));
        } else if let Some((_, lines)) = current.as_mut()
            && !line.starts_with('#')
        {
            lines.push(line.trim().to_owned());
        }
    }
    blocks.extend(current);
    blocks
}

fn module_code_lines(lines: &[String], op_name: &str, code_offset: usize) -> Vec<String> {
    let mut in_code = true;
    let mut result = lines
        .iter()
        .filter_map(|line| {
            if line.starts_with(".section .rodata") {
                in_code = false;
                return None;
            }
            if line.starts_with(".section .text") {
                in_code = true;
                return None;
            }
            if !in_code {
                return None;
            }
            let line = if let Some((prefix, address)) = line.split_once("ptr [") {
                let address = address.trim_end_matches(']');
                if address.starts_with('L')
                    || address.starts_with("label_")
                    || address.contains('/')
                {
                    format!("{prefix}ptr [rip + 0]")
                } else {
                    erts_to_arinsal(line)
                }
            } else {
                erts_to_arinsal(line)
            };
            let line = line
                .strip_prefix("align ")
                .map(|alignment| format!(".balign {alignment}"))
                .unwrap_or(line);
            let line = line
                .strip_prefix(".dq ")
                .map(|value| format!(".quad {value}"))
                .unwrap_or(line);
            // Native record headers use different immediate tag bits in the two term layouts.
            let line = match line.as_str() {
                "and al, 63" => "and al, 252".to_owned(),
                "cmp al, 28" => "cmp al, 60".to_owned(),
                _ => line,
            };
            let line = if let Some((op, value)) = line.split_once(", ")
                && op.starts_with("mov ")
                && value
                    .parse::<u64>()
                    .is_ok_and(|value| (1 << 32..1 << 47).contains(&value))
            {
                let register = op.trim_start_matches("mov ");
                let pointer = if (op_name.starts_with("call_light_bif") || op_name == "send")
                    && register == "rcx"
                {
                    TEST_EXPORT_POINTER
                } else if op_name == "i_call_on_load_function" && register == "rcx" {
                    std::ptr::from_ref(&super::instr_bif::CALL_ON_LOAD_MFA) as usize
                } else {
                    TEST_FUNCTION_POINTER
                };
                format!("{op}, {pointer}")
            } else {
                line
            };
            Some(line)
        })
        .collect::<Vec<_>>();
    let Some((align_at, alignment)) = result.iter().enumerate().find_map(|(index, line)| {
        line.strip_prefix(".balign ")
            .and_then(|alignment| alignment.parse::<usize>().ok())
            .map(|alignment| (index, alignment))
    }) else {
        return result;
    };
    if result[..align_at].iter().any(|line| !line.ends_with(':')) {
        return result;
    }
    let pad = (alignment - code_offset % alignment) % alignment;
    if pad == 0 {
        result.remove(align_at);
        return result;
    }
    let nops: [&[u8]; 9] = [
        &[0x90],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    let mut bytes = Vec::new();
    let mut remaining = pad;
    while remaining > 0 {
        let count = remaining.min(nops.len());
        bytes.extend_from_slice(nops[count - 1]);
        remaining -= count;
    }
    result[align_at] = format!(
        ".byte {}",
        bytes
            .iter()
            .map(|byte| format!("{byte:#04x}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    result
}

fn make_small(value: i64) -> u64 {
    ((value as u64) << 4) | 0xf
}

fn atom_word(name: &str) -> u64 {
    Term::atom(arinsal_term::global_atoms().intern(name).unwrap()).word()
}

/// asm_load.c `beam_load_emit_op` for the operand kinds of this module.
fn massage(sign: &str, operands: &[SpecificOperand]) -> Result<Vec<ArgVal>, String> {
    let mut args = Vec::new();
    let mut rest = operands.iter();
    for letter in sign.chars() {
        let curr = rest.next().ok_or("operand missing")?;
        args.push(match (letter, curr) {
            ('n', SpecificOperand::Nil) => ArgVal::Immediate(NIL),
            ('x' | 'd' | 'S' | 's', SpecificOperand::X(index)) => ArgVal::X(*index),
            ('x' | 'd' | 'S' | 's', SpecificOperand::TypedX { index, type_index }) => {
                ArgVal::typed_x(*index, *type_index)
            }
            ('y' | 'd' | 'S' | 's', SpecificOperand::Y(index)) => ArgVal::Y(*index),
            ('y' | 'd' | 'S' | 's', SpecificOperand::TypedY { index, type_index }) => {
                ArgVal::typed_y(*index, *type_index)
            }
            ('a' | 'c' | 's' | 'i', SpecificOperand::Atom(index)) => {
                ArgVal::Immediate(Term::atom(arinsal_term::Atom(*index)).word())
            }
            ('c' | 's', SpecificOperand::SmallInt(value)) => ArgVal::Immediate(make_small(*value)),
            ('c' | 's', SpecificOperand::Nil) => ArgVal::Immediate(NIL),
            ('t' | 'I' | 'W', SpecificOperand::Unsigned(value)) => ArgVal::Word(*value),
            ('A', SpecificOperand::Unsigned(value)) => ArgVal::Word(*value << 6),
            ('P', SpecificOperand::Unsigned(value)) => ArgVal::Word((*value + 1) * 8),
            ('f' | 'j', SpecificOperand::Label(label)) => ArgVal::Label(*label),
            // A defined label is verified as `TAG_u` and becomes `TAG_f`.
            ('L', SpecificOperand::Unsigned(label)) => ArgVal::Label(*label as u32),
            ('i', SpecificOperand::Unsigned(value)) => ArgVal::Immediate(*value),
            ('c' | 'q' | 's', SpecificOperand::Literal(index)) => {
                ArgVal::Literal(i64::from(*index))
            }
            ('e', SpecificOperand::Unsigned(value)) => ArgVal::Export(*value as u32),
            // The BIF function pointer of an import: only `module_info`'s substituted
            // instructions take one here.
            ('b', SpecificOperand::Unsigned(_)) => ArgVal::Word(TEST_FUNCTION_POINTER as u64),
            (letter, other) => return Err(format!("bad tag {other:?} for '{letter}'")),
        });
    }
    for curr in rest {
        args.push(match curr {
            SpecificOperand::SmallInt(value) => ArgVal::Immediate(make_small(*value)),
            SpecificOperand::Nil => ArgVal::Immediate(NIL),
            SpecificOperand::Atom(index) => {
                ArgVal::Immediate(Term::atom(arinsal_term::Atom(*index)).word())
            }
            SpecificOperand::Unsigned(value) => ArgVal::Word(*value),
            SpecificOperand::Label(label) => ArgVal::Label(*label),
            SpecificOperand::X(index) => ArgVal::X(*index),
            SpecificOperand::TypedX { index, type_index } => ArgVal::typed_x(*index, *type_index),
            SpecificOperand::Y(index) => ArgVal::Y(*index),
            SpecificOperand::TypedY { index, type_index } => ArgVal::typed_y(*index, *type_index),
            other => return Err(format!("unsupported primitive type {other:?}")),
        });
    }
    Ok(args)
}

/// An operand without type information (type index zero).
struct Loader<'a> {
    ba: &'a mut BeamModuleAssembler,
    emitted: Vec<&'static str>,
    spans: Vec<OpSpan>,
    /// The function being emitted (its name atom).
    function: ArgVal,
    /// The instructions emitted as `ud2`, with their function.
    substituted: Vec<(ArgVal, &'static str)>,
}

#[derive(Debug)]
struct OpSpan {
    name: &'static str,
    code: Range<usize>,
    data: Range<usize>,
}

impl OpSink for Loader<'_> {
    fn new_literal(&mut self, _index: u32, literal: &NewLiteral) -> Result<(), String> {
        match literal {
            NewLiteral::Record { .. } => Ok(()),
            _ => Err(format!("unexpected literal {literal:?}")),
        }
    }

    fn emit(
        &mut self,
        _op: u16,
        specific: u16,
        operands: &[SpecificOperand],
    ) -> Result<(), String> {
        let info = arinsal_beamops::specific_op_info(specific).ok_or("no specific op")?;
        let a = massage(info.sign, operands)?;
        let m = &mut *self.ba;
        let code_start = m.asm.a.bytes(arinsal_x64::buf::Section::Code).len();
        let data_start = m.asm.a.bytes(arinsal_x64::buf::Section::Data).len();
        // `opc[].name` is the print name: the instruction name and `_<signature>`.
        let suffix = format!("_{}", info.sign);
        let name = info.name.strip_suffix(suffix.as_str()).unwrap_or(info.name);
        let result = match name {
            "i_func_label" => m.emit_i_func_label(a[0]),
            "label" => m.emit_label(a[0]),
            "aligned_label" => m.emit_aligned_label(a[0], a[1]),
            "i_breakpoint_trampoline" => m.emit_i_breakpoint_trampoline(),
            "i_test_yield" => m.emit_i_test_yield(),
            "line" => m.emit_line(a[0]),
            "func_line" => m.emit_func_line(a[0]),
            "empty_func_line" => m.emit_empty_func_line(),
            "int_code_end" => m.emit_int_code_end(),
            "return" => m.emit_return(),
            "move" | "i_move" => m.emit_i_move(a[0], a[1]),
            "swap" => m.emit_swap(a[0], a[1]),
            "jump" => m.emit_jump(a[0]),
            "i_call" => m.emit_i_call(a[0]),
            "i_call_only" => m.emit_i_call_only(a[0]),
            "is_nonempty_list_get_hd" => m.emit_is_nonempty_list_get_hd(a[0], a[1], a[2]),
            "is_nonempty_list_get_tl" => m.emit_is_nonempty_list_get_tl(a[0], a[1], a[2]),
            "i_select_val_lins" => m.emit_i_select_val_lins(a[0], a[1], a[2], &a[3..]),
            "i_select_val_bins" => m.emit_i_select_val_bins(a[0], a[1], a[2], &a[3..]),
            "i_is_tuple_of_arity" => m.emit_i_is_tuple_of_arity(a[0], a[1], a[2]),
            "i_get_tuple_element" => m.emit_i_get_tuple_element(a[0], a[1], a[2]),
            "is_any_native_record" => m.emit_is_any_native_record(a[0], a[1]),
            "is_native_record" => m.emit_is_native_record(a[0], a[1], a[2], a[3]),
            "is_record_accessible" => m.emit_is_record_accessible(a[0], a[1], a[2]),
            "i_get_record_elements" => m.emit_i_get_record_elements(a[0], a[1], a[2], &a[3..]),
            "i_create_local_native_record" => {
                m.emit_i_create_local_native_record(a[0], a[1], a[2], a[3], &a[4..])
            }
            "i_create_native_record" => {
                m.emit_i_create_native_record(a[0], a[1], a[2], a[3], &a[4..])
            }
            "i_update_native_record" => {
                m.emit_i_update_native_record(a[0], a[1], a[2], a[3], &a[4..])
            }
            "get_record_field" => m.emit_get_record_field(a[0], a[1], a[2], a[3], a[4]),
            "return_trace" => m.emit_return_trace(),
            "i_call_trace_return" => m.emit_i_call_trace_return(),
            "i_return_to_trace" => m.emit_i_return_to_trace(),
            "i_hibernate" => m.emit_i_hibernate(),
            "call_bif" => m.emit_call_bif(a[0]),
            "call_bif_mfa" => {
                m.set_call_bif_mfa_function(TEST_FUNCTION_POINTER);
                m.emit_call_bif_mfa(a[0], a[1], a[2])
            }
            "call_nif" => m.emit_call_nif(a[0], a[1], a[2]),
            "call_light_bif" => m.emit_call_light_bif(a[0], a[1]),
            "send" => {
                m.set_send_target(TEST_EXPORT_POINTER, TEST_FUNCTION_POINTER);
                m.emit_send()
            }
            "nif_start" => m.emit_nif_start(),
            "i_call_on_load_function" => m.emit_i_call_on_load_function(),
            "i_load_nif" => m.emit_i_load_nif(),
            "i_bif1" => m.emit_i_bif1(a[0], a[1], a[2], a[3]),
            "i_bif2" => m.emit_i_bif2(a[0], a[1], a[2], a[3], a[4]),
            "i_bif3" => m.emit_i_bif3(a[0], a[1], a[2], a[3], a[4], a[5]),
            "nofail_bif1" => m.emit_nofail_bif1(a[0], a[1], a[2]),
            "nofail_bif2" => m.emit_nofail_bif2(a[0], a[1], a[2], a[3]),
            "i_length_setup" => m.emit_i_length_setup(a[0], a[1], a[2]),
            "i_length" => m.emit_i_length(a[0], a[1], a[2]),
            "current_tuple" => Ok(()),
            "i_func_info" => {
                self.function = a[2];
                m.emit_i_func_info(a[0], a[1], a[2], a[3])
            }
            // The `module_info` functions call BIFs whose instructions are not ported yet;
            // this test never calls them, so their instructions only trap.
            _ => {
                self.substituted.push((self.function, info.name));
                m.asm.emit(|e| e.ud2())
            }
        };
        self.emitted.push(info.name);
        self.spans.push(OpSpan {
            name: info.name,
            code: code_start..m.asm.a.bytes(arinsal_x64::buf::Section::Code).len(),
            data: data_start..m.asm.a.bytes(arinsal_x64::buf::Section::Data).len(),
        });
        result.map_err(|error| format!("{name}: {error:?}"))
    }
}

/// The global code as erts emits it, with every fragment not ported yet bound to `ud2`, so
/// that the labels the ported fragments jump to resolve. None of them is reached here.
fn global_assembler() -> (BeamGlobalAssembler, arinsal_x64::exec::CodeMemory) {
    let mut ga =
        BeamGlobalAssembler::new(crate::common::process_offsets::ProcessOffsets::ERTS_X86_64)
            .unwrap();
    for label in GLOBAL_LABELS {
        let l = ga.label(label);
        if ga.asm.a.label_location(l).is_none() {
            ga.asm.align_code(8).unwrap();
            ga.asm.bind(l).unwrap();
            ga.asm.emit(|e| e.ud2()).unwrap();
        }
    }
    let memory = ga.codegen().unwrap();
    (ga, memory)
}

fn global_assembler_code() -> (
    Vec<u8>,
    Vec<(super::beam_asm_global::GlobalLabels, Range<usize>)>,
) {
    let mut ga =
        BeamGlobalAssembler::new(crate::common::process_offsets::ProcessOffsets::ERTS_X86_64)
            .unwrap();
    for label in GLOBAL_LABELS {
        let label_id = ga.label(label);
        if ga.asm.a.label_location(label_id).is_none() {
            ga.asm.align_code(8).unwrap();
            ga.asm.bind(label_id).unwrap();
            ga.asm.emit(|e| e.ud2()).unwrap();
        }
    }
    let ranges = ga.ranges();
    let code = std::mem::take(&mut ga.asm.a).finish().unwrap().code;
    (code, ranges)
}

fn global_dump_fragment(dump: &str, name: &str) -> Option<Vec<String>> {
    let label = format!("global::{name}:");
    let lines = dump.lines().collect::<Vec<_>>();
    let start = lines.iter().position(|line| line.trim() == label)?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim().starts_with("global::"))
        .map_or(lines.len(), |offset| start + 1 + offset);
    Some(
        lines[start + 1..end]
            .iter()
            .map(|line| line.trim().to_owned())
            .collect(),
    )
}

struct Process {
    header: ProcessHeader,
    regs: Box<SchedulerRegisters>,
    stack: Vec<u64>,
}

impl Process {
    fn new() -> Self {
        let mut process = Self {
            header: ProcessHeader::default(),
            regs: Box::default(),
            stack: vec![0; 256],
        };
        let heap = process.stack.as_mut_ptr();
        process.header.htop = heap;
        process.header.stop = heap.wrapping_add(256);
        process.header.fcalls = 4000;
        process
    }

    /// Calls the native code at `entry` with `args` in x0.., returning x0.
    fn call(&mut self, entry: usize, args: &[u64]) -> u64 {
        for (i, arg) in args.iter().enumerate() {
            // SAFETY: boxed arguments point into `self.stack`, which outlives the call.
            self.regs.x_reg_array[i] = unsafe { Term::from_raw_bits(*arg) };
        }
        // `entry` is a function entry of a module generated for the x86-64 BeamAsm register
        // contract, alive in executable memory for the duration of the call; the process
        // heap and stack point into `self.stack`.
        let exit = super::test_sched::enter(&mut self.header, &mut self.regs, entry);
        assert_eq!(exit, ExitReason::Returned);
        self.regs.x_reg_array[0].tagged_word()
    }
}

#[test]
fn erlc_module_runs_as_x86_native_code() {
    let Some(bytes) = compile() else { return };
    let beam = arinsal_beam::parse(&bytes).unwrap();
    let (ga, _global) = global_assembler();

    let module = arinsal_term::global_atoms().intern("x86_first").unwrap();
    let mut ba = BeamModuleAssembler::new_module_with_module(
        &ga,
        beam.code.label_count,
        beam.code.function_count as usize,
        module_types(&beam),
        beam.lambdas
            .iter()
            .map(|lambda| (lambda.index, lambda.label, lambda.num_free)),
        Some(module),
    )
    .unwrap();
    let mut loader = Loader {
        ba: &mut ba,
        emitted: Vec::new(),
        spans: Vec::new(),
        function: ArgVal::Immediate(NIL),
        substituted: Vec::new(),
    };
    arinsal_beamops::load_code(&beam, false, true, &mut TransformArena::new(), &mut loader)
        .unwrap();
    let emitted = loader.emitted;
    let module_info = ArgVal::Immediate(atom_word("module_info"));
    assert!(
        loader.substituted.iter().all(|(f, _)| *f == module_info),
        "{:?}",
        loader.substituted
    );
    for op in [
        "i_func_info_IaaI",
        "i_breakpoint_trampoline",
        "i_test_yield",
        "return",
        "i_select_val_lins_sfI",
        "is_nonempty_list_get_hd_fSd",
        "i_get_tuple_element_sPS",
        "i_call_only_f",
        "int_code_end",
    ] {
        assert!(emitted.contains(&op), "{op} not emitted: {emitted:?}");
    }
    assert_eq!(ba.functions.len(), beam.code.function_count as usize);

    let in_hdr = BeamCodeHeader {
        num_functions: u64::from(beam.code.function_count),
        ..BeamCodeHeader::default()
    };
    let (memory, code_hdr) = ba.codegen(&in_hdr).unwrap();
    let base = memory.as_ptr() as usize;
    assert_eq!(ba.get_code_header(), Some(code_hdr));
    assert_eq!(code_hdr % 8, 0);
    assert_eq!(ba.asm.a.offset(), 0, "the buffer is consumed by codegen");

    // The header as erts' codegen leaves it: `num_functions` from `in_hdr`, then the table of
    // each function's `ErtsCodeInfo` and the end of the module code.
    let word = |address: usize| {
        let offset = address - base;
        // SAFETY: `offset` is inside the module image, which `memory` keeps mapped.
        unsafe { (memory.as_ptr().add(offset) as *const u64).read_unaligned() }
    };
    assert_eq!(word(code_hdr), u64::from(beam.code.function_count));
    let functions = code_hdr + core::mem::offset_of!(BeamCodeHeader, functions);
    for (i, label) in ba.functions.iter().enumerate() {
        let ci = ba.get_code(*label).unwrap();
        assert_eq!(word(functions + i * 8), ci as u64);
        // The `ErtsCodeInfo`: a 5-byte call, two nops, the breakpoint flag, gen_bp, the MFA.
        assert_eq!(word(ci + 8), 0);
        assert_eq!(word(ci + 16), atom_word("x86_first"));
    }
    let n = ba.functions.len();
    assert_eq!(word(functions + n * 8), (base + ba.asm.get_offset()) as u64);
    assert!(ba.get_code_end().unwrap() < base + ba.asm.get_offset());

    // Exported functions are called at the label after their `func_info`.
    let entry = |name: &str, arity: u32| {
        let export = beam
            .exports
            .iter()
            .find(|e| beam.atom(e.function_atom) == Some(name) && e.arity == arity)
            .unwrap();
        ba.get_code(export.label).unwrap()
    };
    let mut p = Process::new();
    let (a, b, c, d) = (
        atom_word("a"),
        atom_word("b"),
        atom_word("c"),
        atom_word("d"),
    );
    assert_eq!(p.call(entry("id", 1), &[a]), a);
    assert_eq!(p.call(entry("second", 2), &[a, b]), b);
    assert_eq!(p.call(entry("swap", 2), &[a, b]), b);
    assert_eq!(p.call(entry("sel", 1), &[a]), make_small(1));
    assert_eq!(p.call(entry("sel", 1), &[b]), make_small(2));
    assert_eq!(p.call(entry("sel", 1), &[c]), make_small(3));
    assert_eq!(p.call(entry("sel", 1), &[d]), make_small(0));
    assert_eq!(p.call(entry("sel", 1), &[make_small(7)]), make_small(0));

    // [a, b | c] and {c, d} built in the process heap.
    let heap = p.stack.as_mut_ptr();
    // SAFETY: indices 200..206 are inside the 256-word `stack`, above the Erlang stack in use.
    unsafe {
        let cons1 = heap.add(200);
        let cons2 = heap.add(202);
        *cons2 = b;
        *cons2.add(1) = c;
        *cons1 = a;
        *cons1.add(1) = cons2 as u64 | 0x1;
        let tuple = heap.add(204);
        *tuple = 2 << 6;
        *tuple.add(1) = c;
        *tuple.add(2) = d;
    }
    let list = heap.wrapping_add(200) as u64 | 0x1;
    let tail = heap.wrapping_add(202) as u64 | 0x1;
    let tuple = heap.wrapping_add(204) as u64 | 0x2;
    assert_eq!(p.call(entry("head", 1), &[list]), a);
    assert_eq!(p.call(entry("tail", 1), &[list]), tail);
    assert_eq!(p.call(entry("tail", 1), &[tail]), c);
    assert_eq!(p.call(entry("elem2", 1), &[tuple]), d);
    // Each call and return spends one reduction for the prologue and one for the return.
    assert!(p.header.fcalls < 4000);
    assert_eq!(p.header.stop, heap.wrapping_add(256));
}

#[test]
fn requested_module_emitters_match_erts_dump() {
    const MODULE: &str = "x86_rec_trace_bif";
    const EXT_MODULE: &str = "x86_rec_trace_bif_ext";
    const EXT_SOURCE: &str = r#"-module(x86_rec_trace_bif_ext).
-export_record([external]).
-record #external{a=17,b=23}.
"#;
    const SOURCE: &str = r#"-module(x86_rec_trace_bif).
-export([mk/2,get/1,put/2,isr/1,len/1,add/2,send_to/2,load/0,nif/1,init/0,
         get_any/1,put_any/3,accessible/1,call_on_load/0,abs1/1,elem/2,guard/1,
         record_test/2,equal/2,mk_ext/0,get_ext/1]).
-import_record(x86_rec_trace_bif_ext,[external]).
-export_record([r]).
-record #r{a=0,b=1}.
-nifs([nif/1]).
-on_load(init/0).
init() -> ok.
mk(A,B) -> #r{a=A,b=B}.
get(R) -> R#r.a.
put(R,A) -> R#r{a=A}.
isr(R) when is_record(R,r) -> true; isr(_) -> false.
len(X) -> length(X).
add(A,B) -> A+B.
send_to(P,M) -> P ! M.
load() -> erlang:load_nif("none",0).
nif(X) -> X.
get_any(#_{a=A,b=B}=R) -> {A,B,R#_.a,R#_.b};
get_any(_) -> none.
put_any(R,A,B) -> R#_{a=A,b=B}.
accessible(R) -> if is_integer(R#_.a) -> true; true -> false end.
call_on_load() -> erlang:call_on_load_function(?MODULE).
abs1(X) -> erlang:abs(X).
elem(T,I) -> element(I,T).
record_test(R,Tag) -> is_record(R,Tag).
equal(A,B) -> A == B.
mk_ext() -> #external{}.
get_ext(R) -> R#external.a.
guard(X) when is_atom(X), is_function(X,1) -> true; guard(_) -> false.
"#;
    let Some(beam_bytes) =
        compile_source_with_dependencies(MODULE, SOURCE, &[(EXT_MODULE, EXT_SOURCE)])
    else {
        eprintln!("skipping: erlc not available");
        return;
    };
    let Some(dumps) = erts_dump_of(&[(EXT_MODULE, EXT_SOURCE, &[]), (MODULE, SOURCE, &[])]) else {
        return;
    };
    let beam = arinsal_beam::parse(&beam_bytes).unwrap();
    let (ga, _global) = global_assembler();
    let module = arinsal_term::global_atoms().intern(MODULE).unwrap();
    let mut ba = BeamModuleAssembler::new_module_with_module(
        &ga,
        beam.code.label_count,
        beam.code.function_count as usize,
        module_types(&beam),
        beam.lambdas
            .iter()
            .map(|lambda| (lambda.index, lambda.label, lambda.num_free)),
        Some(module),
    )
    .unwrap();
    let mut loader = Loader {
        ba: &mut ba,
        emitted: Vec::new(),
        spans: Vec::new(),
        function: ArgVal::Immediate(NIL),
        substituted: Vec::new(),
    };
    arinsal_beamops::load_code(&beam, false, true, &mut TransformArena::new(), &mut loader)
        .unwrap();
    let spans = std::mem::take(&mut loader.spans);
    drop(loader);
    let dump_blocks = full_dump_blocks(&dumps[1]);
    let code = ba.asm.a.bytes(arinsal_x64::buf::Section::Code).to_vec();
    let mut checked = std::collections::HashSet::new();
    let mut occurrences = std::collections::HashMap::<&str, usize>::new();
    for span in spans {
        if !span.name.starts_with("is_any_native_record")
            && !span.name.starts_with("is_native_record")
            && !span.name.starts_with("is_record_accessible")
            && !span.name.starts_with("i_get_record_elements")
            && !span.name.starts_with("i_create_local_native_record")
            && !span.name.starts_with("i_create_native_record")
            && !span.name.starts_with("i_update_native_record")
            && !span.name.starts_with("get_record_field")
            && !span.name.starts_with("call_bif")
            && !span.name.starts_with("call_nif")
            && !span.name.starts_with("call_light_bif")
            && !span.name.starts_with("send")
            && !span.name.starts_with("i_bif")
            && !span.name.starts_with("nofail_bif")
            && !span.name.starts_with("i_length")
            && !span.name.starts_with("i_call_on_load_function")
            && !span.name.starts_with("i_load_nif")
            && !span.name.starts_with("nif_start")
        {
            continue;
        }
        checked.insert(span.name);
        let occurrence = occurrences.entry(span.name).or_default();
        let reference = dump_blocks
            .iter()
            .filter(|(name, _)| name == span.name)
            .nth(*occurrence)
            .map(|(_, lines)| lines)
            .unwrap_or_else(|| panic!("erts dump did not contain emitted {}", span.name));
        *occurrence += 1;
        let mut expected = module_code_lines(reference, span.name, span.code.start);
        if span.name == "i_call_on_load_function"
            && let Some(probe) = expected.iter().position(|line| line == "call rax")
        {
            // erts logs the sizing probe of `aligned_call(Target)` before rewinding the code
            // offset; only the second `call rax` remains in the machine code.
            expected.remove(probe);
        }
        let actual = &code[span.code.clone()];
        assert_eq!(
            matches_with_global_jumps_at(&expected, actual, &[], span.code.start),
            Some(true),
            "{}: expected={expected:?}; actual={actual:02x?}; code={:?}; data={:?}",
            span.name,
            span.code,
            span.data,
        );
    }
    for prefix in [
        "is_any_native_record",
        "is_native_record",
        "is_record_accessible",
        "i_get_record_elements",
        "i_create_local_native_record",
        "i_update_native_record",
        "i_create_native_record",
        "get_record_field",
        "call_light_bif",
        "send",
        "i_bif1",
        "i_bif2",
        "i_bif3",
        "nofail_bif1",
        "nofail_bif2",
        "i_length_setup",
        "i_length",
        "i_load_nif",
        "nif_start",
        "i_call_on_load_function",
    ] {
        assert!(
            checked.iter().any(|name| name.starts_with(prefix)),
            "{prefix} was not byte-compared: {checked:?}"
        );
    }
}

#[test]
fn trace_emitters_match_erts_boot_dump() {
    let Some(erts) = super::jdump::erts_dump("erts_beamasm") else {
        eprintln!("skipping: no erl +JDdump");
        return;
    };
    let Some(gen_server) = super::jdump::erts_dump("gen_server") else {
        eprintln!("skipping: no gen_server +JDdump");
        return;
    };
    let (ga, _global) = global_assembler();
    type Emit = fn(&mut BeamModuleAssembler) -> Result<(), super::beam_asm::AsmError>;
    for (dump, op, emit) in [
        (
            &erts,
            "return_trace",
            BeamModuleAssembler::emit_return_trace as Emit,
        ),
        (
            &erts,
            "i_call_trace_return",
            BeamModuleAssembler::emit_i_call_trace_return as Emit,
        ),
        (
            &erts,
            "i_return_to_trace",
            BeamModuleAssembler::emit_i_return_to_trace as Emit,
        ),
        (
            &gen_server,
            "i_hibernate",
            BeamModuleAssembler::emit_i_hibernate as Emit,
        ),
    ] {
        let blocks = full_dump_blocks(dump);
        let reference = blocks
            .iter()
            .find(|(name, _)| name == op)
            .unwrap_or_else(|| panic!("erts dump did not contain {op}"));
        let mut module =
            BeamModuleAssembler::new_module(&ga, 2, 0, vec![ArgType::ANY], []).unwrap();
        let start = module.asm.a.bytes(arinsal_x64::buf::Section::Code).len();
        emit(&mut module).unwrap();
        let code = module.asm.a.bytes(arinsal_x64::buf::Section::Code);
        let expected = module_code_lines(&reference.1, op, start);
        assert_eq!(
            matches_with_global_jumps_at(&expected, &code[start..], &[], start),
            Some(true),
            "{op}: expected={expected:?}; actual={:02x?}",
            &code[start..],
        );
    }
}

#[test]
fn bif_entry_emitters_match_erts_dump() {
    let Some(dump) = super::jdump::erts_dump("atomics") else {
        eprintln!("skipping: no atomics +JDdump");
        return;
    };
    let blocks = full_dump_blocks(&dump);
    let reference = blocks
        .iter()
        .find(|(name, _)| name == "call_bif_mfa_aaI")
        .expect("erts atomics dump has no call_bif_mfa");
    let (ga, _global) = global_assembler();
    let module_atom = ArgVal::Immediate(atom_word("atomics"));
    let function_atom = ArgVal::Immediate(atom_word("put"));
    for use_mfa in [false, true] {
        let mut module =
            BeamModuleAssembler::new_module(&ga, 3, 1, vec![ArgType::ANY], []).unwrap();
        module.emit_i_func_label(ArgVal::Label(1)).unwrap();
        module
            .emit_i_func_info(ArgVal::Word(1), module_atom, function_atom, ArgVal::Word(3))
            .unwrap();
        module
            .emit_aligned_label(ArgVal::Label(2), ArgVal::Word(4))
            .unwrap();
        if use_mfa {
            module.set_call_bif_mfa_function(TEST_FUNCTION_POINTER);
        }
        let start = module.asm.a.bytes(arinsal_x64::buf::Section::Code).len();
        if use_mfa {
            module
                .emit_call_bif_mfa(module_atom, function_atom, ArgVal::Word(3))
                .unwrap();
        } else {
            module
                .emit_call_bif(ArgVal::Word(TEST_FUNCTION_POINTER as u64))
                .unwrap();
        }
        let code = module.asm.a.bytes(arinsal_x64::buf::Section::Code);
        let expected = module_code_lines(&reference.1, &reference.0, start);
        assert_eq!(
            matches_with_global_jumps_at(&expected, &code[start..], &[], start),
            Some(true),
            "{}: expected={expected:?}; actual={:02x?}",
            reference.0,
            &code[start..],
        );
    }
}

#[test]
fn call_nif_emitter_matches_erts_dump() {
    let Some(dump) = super::jdump::erts_dump("prim_file") else {
        eprintln!("skipping: no prim_file +JDdump");
        return;
    };
    let blocks = full_dump_blocks(&dump);
    let reference = blocks
        .iter()
        .find(|(name, _)| name == "call_nif_WWW")
        .expect("erts prim_file dump has no call_nif");
    let words = reference
        .1
        .iter()
        .filter_map(|line| line.strip_prefix(".dq "))
        .map(|word| u64::from_str_radix(word.trim_start_matches("0x"), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(words.len(), 3, "{reference:?}");
    let (ga, _global) = global_assembler();
    let yield_helper = ga
        .asm
        .get_code(ga.label(super::beam_asm_global::GlobalLabels::CallNifYieldHelper))
        .unwrap();
    let mut module = BeamModuleAssembler::new_module(&ga, 2, 1, vec![ArgType::ANY], []).unwrap();
    let start = module.asm.a.bytes(arinsal_x64::buf::Section::Code).len();
    module
        .emit_call_nif(
            ArgVal::Word(words[0]),
            ArgVal::Word(words[1]),
            ArgVal::Word(words[2]),
        )
        .unwrap();
    let code = module.asm.a.bytes(arinsal_x64::buf::Section::Code);
    let mut expected = module_code_lines(&reference.1, &reference.0, start);
    for line in &mut expected {
        if line == &format!("mov r9, {TEST_FUNCTION_POINTER}") {
            *line = format!("mov r9, {yield_helper}");
        }
    }
    assert_eq!(
        matches_with_global_jumps_at(&expected, &code[start..], &[], start),
        Some(true),
        "{}: expected={expected:?}; actual={:02x?}",
        reference.0,
        &code[start..],
    );
}

#[test]
fn call_nif_global_fragments_match_erts_dump() {
    use super::beam_asm_global::GlobalLabels;

    let Some(dump) = super::jdump::erts_dump("beam_asm_global") else {
        eprintln!("skipping: no beam_asm_global +JDdump");
        return;
    };
    let (code, ranges) = global_assembler_code();
    for (label, name) in [
        (GlobalLabels::CallNifEarly, "call_nif_early"),
        (GlobalLabels::CallNifShared, "call_nif_shared"),
        (GlobalLabels::DispatchNif, "dispatch_nif"),
        (GlobalLabels::CallNifYieldHelper, "call_nif_yield_helper"),
    ] {
        let expected = global_dump_fragment(&dump, name)
            .unwrap_or_else(|| panic!("erts dump has no global::{name}"));
        let mut expected = expected
            .into_iter()
            .filter(|line| !line.starts_with("global::"))
            .map(|line| erts_to_arinsal(&line))
            .collect::<Vec<_>>();
        if expected.last().is_some_and(|line| line == "align 8") {
            expected.pop();
        }
        let layout = expected
            .iter()
            .map(|line| {
                if let Some((op, _)) = line.split_once(" global::") {
                    match op {
                        "jmp" => ".byte 0xe9, 0, 0, 0, 0".to_owned(),
                        "short jmp" => ".byte 0xeb, 0".to_owned(),
                        _ => panic!("unexpected global branch: {line}"),
                    }
                } else if let Some(target) = line.strip_prefix("call ")
                    && target.parse::<u64>().is_ok()
                {
                    ".byte 0x40, 0xe8, 0, 0, 0, 0".to_owned()
                } else {
                    line.clone()
                }
            })
            .collect::<Vec<_>>();
        let body_len = gnu_as(&layout)
            .unwrap_or_else(|| panic!("GNU as could not size global::{name}"))
            .len();
        let range = ranges
            .iter()
            .find(|(found, _)| *found == label)
            .map(|(_, range)| range.clone())
            .unwrap_or_else(|| panic!("Arinsal has no {label:?} fragment"));
        assert_eq!(
            matches_with_global_jumps(&expected, &code[range.start..range.start + body_len], &[],),
            Some(true),
            "global::{name}: expected={expected:?}; actual={:02x?}",
            &code[range.start..range.start + body_len],
        );
    }
}

/// The patch sites of a module after codegen: an import, a literal, a string and a fun entry
/// loaded into X registers by `mov_arg`, patched through the writable view the way
/// `beam_load_finish_emit` / `beam_load_finalize_code` do, then read back by running the code.
#[test]
fn patches_reach_the_running_code() {
    let (ga, _global) = global_assembler();
    let mut m =
        BeamModuleAssembler::new_module(&ga, 3, 1, vec![ArgType::ANY], [(0, 2, 0)]).unwrap();
    let (module, function) = (atom_word("x86_first"), atom_word("loaded"));
    m.emit_i_func_label(ArgVal::Label(1)).unwrap();
    m.emit_i_func_info(
        ArgVal::Word(1),
        ArgVal::Immediate(module),
        ArgVal::Immediate(function),
        ArgVal::Word(0),
    )
    .unwrap();
    m.emit_aligned_label(ArgVal::Label(2), ArgVal::Word(4))
        .unwrap();
    m.emit_on_load().unwrap();
    m.emit_i_breakpoint_trampoline().unwrap();
    m.emit_i_test_yield().unwrap();
    m.set_beam_literal(0, 0xaaa);
    m.set_beam_literal(1, 0xaaa);
    for (x, arg) in [
        ArgVal::Export(3),
        ArgVal::Literal(0),
        ArgVal::BytePtr(5),
        ArgVal::FunEntry(0),
        ArgVal::Literal(1),
    ]
    .into_iter()
    .enumerate()
    {
        m.mov_arg_to_reg(super::beam_asm::register::ARG1, arg)
            .unwrap();
        m.mov_arg_from_reg(ArgVal::X(x as u32), super::beam_asm::register::ARG1)
            .unwrap();
    }
    m.emit_return().unwrap();
    m.emit_int_code_end().unwrap();

    let (mut memory, code_hdr) = m.codegen(&BeamCodeHeader::default()).unwrap();
    m.patch_import(&mut memory, 3, 0x1000).unwrap();
    m.patch_literal(&mut memory, 0, 0x2002).unwrap();
    m.patch_literal(&mut memory, 1, 0x2222).unwrap();
    m.patch_strings(&mut memory, 0x3000).unwrap();
    m.patch_lambda(&mut memory, 0, 0x4000).unwrap();

    // `on_load` is the `ErtsCodeInfo` in front of the entry, also the first function.
    let entry = m.get_code(2).unwrap();
    assert_eq!(m.get_on_load(), Some(m.get_code(1).unwrap()));
    assert_eq!(
        m.get_on_load(),
        Some(entry - core::mem::size_of::<crate::common::beam_asm_h::ErtsCodeInfo>())
    );
    assert!(code_hdr < m.get_code(1).unwrap());

    let mut p = Process::new();
    p.call(entry, &[]);
    let x = |i: usize| p.regs.x_reg_array[i].tagged_word();
    assert_eq!(
        [x(0), x(1), x(2), x(3), x(4)],
        [0x1000, 0x2002, 0x3005, 0x4000, 0x2222]
    );
}

/// erts' dump lines of `block` as GNU `as` input: the rel32 of every call and jump to a
/// dispatch-table thunk (layout dependent) as zero, `entry` as the local label `entry`.
fn as_text(block: &[&str], entry: &str) -> Vec<String> {
    block
        .iter()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let l = l.trim();
            if l.starts_with("call L") {
                ".byte 0xe8, 0, 0, 0, 0".to_string()
            } else if l.starts_with("long jle L") {
                ".byte 0x0f, 0x8e, 0, 0, 0, 0".to_string()
            } else if l.starts_with("jl L") {
                ".byte 0x0f, 0x8c, 0, 0, 0, 0".to_string()
            } else if let Some(alignment) = l.strip_prefix("align ") {
                format!(".balign {alignment}")
            } else if l.starts_with("short jmp ") {
                l.replace("short jmp", "jmp")
            } else {
                l.replace(".db ", ".byte ")
                    .replace(&format!("qword ptr [{entry}+"), "[rip+entry+")
                    .replace(&format!("{entry}:"), "entry:")
            }
        })
        .collect()
}

/// The MFA words of an `i_func_info` block: the third `.db` line, after the breakpoint flag
/// and `gen_bp`.
fn block_mfa(block: &[&str]) -> [u64; 3] {
    let mfa_line = block
        .iter()
        .filter(|l| l.starts_with(".db "))
        .nth(2)
        .unwrap();
    let mfa: Vec<u8> = mfa_line[4..]
        .split(", ")
        .map(|b| u8::from_str_radix(b.trim_start_matches("0x"), 16).unwrap())
        .collect();
    let word = |i: usize| u64::from_le_bytes(mfa[i * 8..i * 8 + 8].try_into().unwrap());
    [word(0), word(1), word(2)]
}

/// `i_func_label`, `func_line`, `i_func_info`, `aligned_label`, `i_breakpoint_trampoline` and
/// `i_test_yield` of function label 1 (entry label 2) with `mfa`, as the loader emits them.
fn emit_prologue(m: &mut BeamModuleAssembler, mfa: [u64; 3]) {
    m.emit_i_func_label(ArgVal::Label(1)).unwrap();
    m.emit_func_line(ArgVal::Word(0)).unwrap();
    m.emit_i_func_info(
        ArgVal::Word(1),
        ArgVal::Immediate(mfa[0]),
        ArgVal::Immediate(mfa[1]),
        ArgVal::Word(mfa[2]),
    )
    .unwrap();
    m.emit_aligned_label(ArgVal::Label(2), ArgVal::Word(4))
        .unwrap();
    m.emit_i_breakpoint_trampoline().unwrap();
    m.emit_i_test_yield().unwrap();
}

/// Zeroes the thunk rel32s of a prologue from [`emit_prologue`]: `call i_func_info_shared` at
/// 0, `call i_breakpoint_trampoline_shared` after the short jump and its pad at the entry
/// (40), `jle i_test_yield_shared` after `lea` and `dec`.
fn zero_prologue_rel32(code: &mut [u8]) {
    for (opcode_at, width) in [(0, 1), (40 + 3, 1), (40 + 8 + 7 + 3, 2)] {
        code[opcode_at + width..opcode_at + width + 4].fill(0);
    }
}

/// erts' function prologues in its own dump of `lists` (`erl +JDdump true`): `i_func_label`,
/// `func_line`, `i_func_info`, `aligned_label`, `i_breakpoint_trampoline` and `i_test_yield`,
/// byte for byte. The rel32 of the calls and jump to the module's dispatch-table thunks is
/// layout dependent and compared as zero on both sides.
#[test]
fn function_prologues_match_erts_dump() {
    use super::jdump::erts_dump;
    let Some(dump) = erts_dump("lists") else {
        eprintln!("skipping: no erl +JDdump");
        return;
    };
    let (ga, _global) = global_assembler();
    let lines: Vec<&str> = dump.lines().collect();
    let expected_ops = [
        "# i_func_label_L",
        "# func_line_I",
        "# i_func_info_IaaI",
        "# aligned_label_Lt",
        "# i_breakpoint_trampoline",
        "# i_test_yield",
    ];
    let mut compared = 0;
    for (start, _) in lines
        .iter()
        .enumerate()
        .filter(|(_, l)| **l == "# i_func_label_L")
    {
        // The block runs to the `align 4` that ends `i_test_yield`.
        let Some(len) = lines[start..].iter().position(|l| *l == "    align 4") else {
            continue;
        };
        let Some(end) = lines[start + len + 1..]
            .iter()
            .position(|l| *l == "    align 4")
            .map(|i| start + len + 1 + i + 1)
        else {
            continue;
        };
        let block = &lines[start..end];
        let ops: Vec<&str> = block
            .iter()
            .copied()
            .filter(|l| l.starts_with("# ") && !l.contains(':'))
            .collect();
        // A `nop` of `flush_last_error` depends on the previous function's last instruction.
        if ops != expected_ops || block[1] == "    nop" {
            continue;
        }
        let mfa = block_mfa(block);
        let entry = block
            .iter()
            .find(|l| l.ends_with(':') && l.contains('/'))
            .unwrap()
            .trim_end_matches(':');

        let text = as_text(block, entry);
        let Some(theirs) = gnu_as(&text) else {
            eprintln!("skipping: no binutils");
            return;
        };

        let mut m = BeamModuleAssembler::new_module(&ga, 3, 1, vec![ArgType::ANY], []).unwrap();
        let at = m.asm.a.offset();
        emit_prologue(&mut m, mfa);
        let mut ours = m.asm.a.bytes(arinsal_x64::buf::Section::Code)[at..].to_vec();
        zero_prologue_rel32(&mut ours);
        assert_eq!(ours, theirs, "{block:#?}");
        compared += 1;
    }
    assert!(compared >= 20, "only {compared} prologues compared");
}

/// erts' `int_code_end` in its dump of `lists`: `emit_nyi("int_code_end")` (enter the
/// runtime, the message address in `ARG1`, the `REX call` of `i_emit_nyi`), then the
/// dispatch-table thunks.
#[test]
fn int_code_end_matches_erts_dump() {
    use super::jdump::{erts_dump, erts_to_arinsal};
    let Some(dump) = erts_dump("lists") else {
        eprintln!("skipping: no erl +JDdump");
        return;
    };
    let lines: Vec<&str> = dump.lines().collect();
    let start = lines.iter().position(|l| *l == "# int_code_end").unwrap();
    // `Lnnn:` (code_end), the runtime entry, `mov rdi, msg`, `call i_emit_nyi`.
    let runtime: Vec<String> = lines[start + 2..start + 5]
        .iter()
        .map(|l| erts_to_arinsal(l.trim()))
        .collect();
    assert!(lines[start + 5].trim().starts_with("mov rdi, "));
    assert!(lines[start + 6].trim().starts_with("call "));
    let Some(theirs) = gnu_as(&runtime) else {
        eprintln!("skipping: no binutils");
        return;
    };
    let mut m = BeamModuleAssembler::with_fragment_addresses(1, Vec::new());
    m.emit_int_code_end().unwrap();
    let ours = m.asm.a.bytes(arinsal_x64::buf::Section::Code).to_vec();
    assert_eq!(&ours[..theirs.len()], &theirs[..]);
    let rest = &ours[theirs.len()..];
    // `mov rdi, imm64` (the message is a static C string), then `REX call rel32`.
    assert_eq!(&rest[..2], &[0x48, 0xbf]);
    let msg = u64::from_le_bytes(rest[2..10].try_into().unwrap());
    assert_eq!(msg != 0, true);
    assert_eq!(&rest[10..12], &[0x40, 0xe8]);
    assert_eq!(rest.len(), 16);
}

/// Compiles `modules` (name, source, extra `erlc` flags) and loads them into
/// `erl +D +JDdump true` (the debugger with line breakpoints on), returning erts' dump of
/// each; `None` (the test is skipped) without `erlc`/`erl`.
fn erts_dump_of(modules: &[(&str, &str, &[&str])]) -> Option<Vec<String>> {
    let dir = std::env::temp_dir().join(format!("arinsal-x86-meta-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut loads = String::from("code:add_patha(\".\"), ");
    for (name, source, flags) in modules {
        std::fs::write(dir.join(format!("{name}.erl")), source).unwrap();
        let compiled = Command::new("erlc")
            .args(*flags)
            .arg(format!("{name}.erl"))
            .current_dir(&dir)
            .status()
            .is_ok_and(|status| status.success());
        if !compiled {
            eprintln!("skipping: erlc failed or is not available");
            return None;
        }
        loads.push_str(&format!("{{module, _}} = code:load_file({name}), "));
    }
    // A one-shot node: `halt()` ends it once the modules are loaded and dumped.
    let dumped = Command::new("erl")
        .args(["+D", "+JDdump", "true", "-noshell", "-eval"])
        .arg(format!("{loads}halt()."))
        .current_dir(&dir)
        .status()
        .is_ok_and(|status| status.success());
    let dumps = modules
        .iter()
        .map(|(name, _, _)| {
            let bytes = std::fs::read(dir.join(format!("{name}.asm"))).ok()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        })
        .collect::<Option<Vec<_>>>();
    let _ = std::fs::remove_dir_all(&dir);
    if !dumped || dumps.is_none() {
        eprintln!("skipping: erl +JDdump failed or is not available");
    }
    dumps.filter(|_| dumped)
}

/// erts' `i_nif_padding` after a `-nifs()` function in a module that may call `load_nif`:
/// zeros up to `BEAM_NATIVE_MIN_FUNC_SZ` words from the function's entry. The code header
/// in front of the module is `sizeof(BeamCodeHeader)` plus one pointer per function.
#[test]
fn nif_padding_and_code_header_match_erts_dump() {
    const SOURCE: &str = "-module(x86_nifpad).
-export([f/1, init/0]).
-nifs([f/1]).
f(X) -> X.
init() -> erlang:load_nif(\"nonexistent\", 0).
";
    let Some(dumps) = erts_dump_of(&[("x86_nifpad", SOURCE, &[])]) else {
        return;
    };
    let lines: Vec<&str> = dumps[0].lines().collect();

    // The header: `align 8`, its label, then the zeros of `embed_zeros`.
    let header_zeros = lines[2].matches("0x00").count();
    let functions = lines.iter().filter(|l| **l == "# i_func_info_IaaI").count();
    let (ga, _global) = global_assembler();
    let m = BeamModuleAssembler::new_module(&ga, 3, functions, vec![ArgType::ANY], []).unwrap();
    assert_eq!(m.asm.a.offset(), header_zeros);
    assert_eq!(
        header_zeros,
        core::mem::size_of::<BeamCodeHeader>() + 8 * functions
    );

    // `f/1`: the prologue, `nif_start` (load time only), `return`, then `i_nif_padding`.
    let start = lines.iter().position(|l| *l == "# x86_nifpad:f/1").unwrap() - 4;
    let end = start
        + lines[start..]
            .iter()
            .position(|l| *l == "# i_nif_padding")
            .unwrap()
        + 2;
    let block = &lines[start..end];
    let text = as_text(block, "f/1");
    let Some(theirs) = gnu_as(&text) else {
        eprintln!("skipping: no binutils");
        return;
    };

    let mut m = BeamModuleAssembler::new_module(&ga, 3, functions, vec![ArgType::ANY], []).unwrap();
    let at = m.asm.a.offset();
    emit_prologue(&mut m, block_mfa(block));
    m.emit_return().unwrap();
    m.emit_i_nif_padding().unwrap();
    let mut ours = m.asm.a.bytes(arinsal_x64::buf::Section::Code)[at..].to_vec();
    zero_prologue_rel32(&mut ours);
    // `jl dispatch_return` after the 24-byte trampoline and test, and `dec`.
    ours[40 + 24 + 3 + 2..40 + 24 + 3 + 6].fill(0);
    assert_eq!(ours, theirs, "{block:#?}");
    assert_eq!(
        ours.len() - 40,
        8 * crate::common::beam_asm_h::BEAM_NATIVE_MIN_FUNC_SZ
    );
}

/// erts' `i_line_breakpoint_trampoline` after an `i_debug_line` of a module compiled with
/// `+beam_debug_info` under `+D`: a disabled breakpoint (`jmp short +6`) over an aligned call,
/// whose thunk jumps to `i_line_breakpoint_trampoline_shared`, the shape erts'
/// `is_line_breakpoint_trampoline` recognizes.
#[test]
fn line_breakpoint_trampoline_matches_erts_dump() {
    const SOURCE: &str = "-module(x86_dbg).
-export([f/1]).
f(X) ->
    Y = X,
    Y.
";
    let Some(dumps) = erts_dump_of(&[("x86_dbg", SOURCE, &["+beam_debug_info"])]) else {
        return;
    };
    // `short jmp Lnext`, `.db 0x90`, `call Lthunk`, `Lnext:`.
    let lines: Vec<&str> = dumps[0].lines().collect();
    let blocks: Vec<&[&str]> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| **l == "# i_line_breakpoint_trampoline")
        .map(|(i, _)| &lines[i + 1..i + 5])
        .collect();
    assert!(blocks.len() >= 2);
    let (ga, _global) = global_assembler();
    for block in blocks {
        let text: Vec<String> = block
            .iter()
            .map(|l| {
                let l = l.trim();
                if l.starts_with("call L") {
                    ".byte 0xe8, 0, 0, 0, 0".to_string()
                } else {
                    l.replace("short jmp", "jmp").replace(".db ", ".byte ")
                }
            })
            .collect();
        let Some(theirs) = gnu_as(&text) else {
            eprintln!("skipping: no binutils");
            return;
        };

        let mut m = BeamModuleAssembler::new_module(&ga, 1, 0, vec![ArgType::ANY], []).unwrap();
        // `i_debug_line` ends 8-byte aligned.
        m.asm.align_code(8).unwrap();
        let at = m.asm.a.offset();
        m.emit_i_line_breakpoint_trampoline().unwrap();
        let mut ours = m.asm.a.bytes(arinsal_x64::buf::Section::Code)[at..].to_vec();
        ours[4..8].fill(0);
        assert_eq!(ours, theirs, "{block:#?}");

        // `is_line_breakpoint_trampoline`: the call goes to a thunk `REX jmp rel32` to the
        // shared fragment.
        m.emit_int_code_end().unwrap();
        let (memory, _) = m.codegen(&BeamCodeHeader::default()).unwrap();
        let base = memory.as_ptr() as usize;
        // SAFETY: every address read is inside the module image `memory` keeps mapped.
        let byte = |address: usize| unsafe { *memory.as_ptr().add(address - base) };
        let rel32 = |address: usize| {
            i32::from_le_bytes(core::array::from_fn(|i| byte(address + i))) as isize
        };
        let pc = base + at;
        assert_eq!(
            [byte(pc), byte(pc + 1), byte(pc + 2), byte(pc + 3)],
            [0xeb, 6, 0x90, 0xe8]
        );
        let thunk = pc.wrapping_add_signed(8 + rel32(pc + 4));
        assert_eq!([byte(thunk), byte(thunk + 1)], [0x40, 0xe9]);
        let target = thunk.wrapping_add_signed(6 + rel32(thunk + 2));
        assert_eq!(
            Some(target),
            ga.get_ptr(super::beam_asm_global::GlobalLabels::ILineBreakpointTrampolineShared)
        );
    }
}
