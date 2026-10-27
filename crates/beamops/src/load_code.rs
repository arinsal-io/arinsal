//! Port of `load_code` of erts/emulator/beam/beam_load.c and of `beam_load_emit_op` of
//! erts/emulator/beam/jit/asm_load.c (OTP-29.1.1): the loop that reads the generic instructions,
//! runs the transformation engine on the window at the head of the chain, selects the specific
//! instruction, verifies its operands and hands it to the assembler.

use crate::beam_op::*;
use crate::erts_tables::*;
use crate::loader_state::{LoaderState, TeResult, erts_transform_engine};
use crate::{NewLiteral, OpSink, SpecificOperand, TransformArena};
use arinsal_beam::BeamFile;
use std::sync::LazyLock;

/// Why a module cannot be loaded: the `BeamLoadError*` messages of `load_code`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadCodeError(pub String);

impl std::fmt::Display for LoadCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadCodeError {}

fn error(message: impl Into<String>) -> LoadCodeError {
    LoadCodeError(message.into())
}

/// `ERTS_DEBUGGER_ENABLED | ERTS_DEBUGGER_LINE_BREAKPOINTS`.
const DEBUGGER_LINE_BREAKPOINTS: u64 = 0b11;

/// Operations whose operands keep their `Type` chunk entry in the typed transform, by generic
/// operation number.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp and instr_guard_bifs.cpp, OTP-29.1.1.
static TYPED_OPS: LazyLock<Vec<bool>> = LazyLock::new(|| {
    const NAMES: &[&str] = &[
        "is_map",
        "bif_is_map_key",
        "bif_map_size",
        "i_plus",
        "i_minus",
        "i_band",
        "i_bor",
        "i_bxor",
        "i_bsl",
        "i_bsr",
        "i_rem",
        "i_int_div",
        "bif_map_get",
    ];
    GEN_OPC
        .iter()
        .map(|entry| NAMES.contains(&entry.name))
        .collect()
});

/// `load_code`: transforms the module's code and hands its specific instructions to `sink`.
pub(crate) fn load_code<S: OpSink>(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    typed: bool,
    arena: &mut TransformArena,
    sink: &mut S,
) -> Result<(), LoadCodeError> {
    // Port of erts/emulator/beam/beam_load.c:erts_prepare_loading (the `max_opcode` checks),
    // OTP-29.1.1.
    if beam.code.max_opcode as usize > MAX_GENERIC_OPCODE {
        return Err(error(format!(
            "This BEAM file was compiled for a later version of the runtime system than the \
             current (Erlang/OTP 29).\n  To fix this, please recompile this module with an OTP \
             29 compiler.\n  (Use of opcode {}; this emulator supports only up to {}.)",
            beam.code.max_opcode, MAX_GENERIC_OPCODE
        )));
    } else if (beam.code.max_opcode as i32) < GENOP_SWAP_2 {
        return Err(error(
            "This BEAM file was compiled for an old version of the runtime system.\n  To fix \
             this, please re-compile this module with Erlang/OTP 25 or later.\n",
        ));
    }
    let ops = std::mem::take(&mut arena.beam_ops);
    let debugger_flags = if instrument_line_breakpoints {
        DEBUGGER_LINE_BREAKPOINTS
    } else {
        0
    };
    let Some(mut st) = LoaderState::new(beam, ops, None, debugger_flags) else {
        return Err(error("the module's tables cannot be loaded"));
    };
    let result = run(&mut st, typed, &mut arena.operands, sink);
    arena.beam_ops = std::mem::take(&mut st.ops);
    result
}

fn run<S: OpSink>(
    st: &mut LoaderState,
    typed: bool,
    operands: &mut Vec<SpecificOperand>,
    sink: &mut S,
) -> Result<(), LoadCodeError> {
    let mut reader = BeamCodeReader::with_atoms(st.beam, st.atoms.clone());
    // `last_op_next`: `Some(tail)` is the last operation of the chain, `None` with an empty chain
    // is `&stp->genop`; `tail_unknown` is C's NULL, found again by walking the chain.
    let mut tail: Option<OpId> = None;
    let mut tail_unknown = false;
    // The literals of `st.literals.extra` the sink has been told about.
    let mut announced = 0;

    'get_next_instr: loop {
        reader.literal_base = st.literals.len();
        let last_op = reader
            .next(&mut st.ops)
            .map_err(|ReadError(message)| error(message))?;
        for text in std::mem::take(&mut reader.bignum_literals) {
            st.literals.add(NewLiteral::Bignum(text));
        }

        // Create a new generic operation and put it last in the chain.
        if tail_unknown {
            tail = None;
            let mut cursor = st.genop;
            while let Some(id) = cursor {
                tail = Some(id);
                cursor = st.ops.op(id).next;
            }
            tail_unknown = false;
        }
        st.ops.op_mut(last_op).next = None;
        match tail {
            Some(previous) => st.ops.op_mut(previous).next = Some(last_op),
            None => st.genop = Some(last_op),
        }
        tail = Some(last_op);

        'do_transform: loop {
            let genop = st.genop.expect("the chain has an instruction");
            let generic = st.ops.op(genop).op as usize;
            if GEN_OPC[generic].transform {
                if st.ops.op(genop).next.is_none() {
                    // Simple heuristic: most transformations require at least two
                    // instructions, so make sure that there are. That reduces the number of
                    // TE_SHORT_WINDOWs.
                    continue 'get_next_instr;
                }
                match erts_transform_engine(st) {
                    // No transformation found: load the instruction.
                    TeResult::Fail => {}
                    TeResult::Ok => {
                        // Some transformation was applied. The tail is no longer valid and the
                        // chain may be empty. Try to transform again.
                        if st.genop.is_none() {
                            tail = None;
                            tail_unknown = false;
                            continue 'get_next_instr;
                        }
                        tail_unknown = true;
                        continue 'do_transform;
                    }
                    // Fetch a new instruction before trying the transformation again.
                    TeResult::ShortWindow => continue 'get_next_instr,
                }
            }

            // From the collected generic instruction, find the specific instruction.
            let genop = st.genop.expect("the chain has an instruction");
            let specific = select_specific(st, genop)?;
            let is_end = st.ops.op(genop).op == GENOP_INT_CODE_END_0;
            emit_op(st, genop, specific, typed, operands, &mut announced, sink)?;

            if !is_end {
                // Delete the generic instruction just loaded.
                let next = st.ops.op(genop).next;
                st.ops.free_op(genop);
                st.genop = next;
                if next.is_some() {
                    continue 'do_transform;
                }
                tail = None;
                tail_unknown = false;
                continue 'get_next_instr;
            }
            // End of code found.
            break 'get_next_instr;
        }
    }
    Ok(())
}

/// The selection of the specific instruction in `load_code` (the BeamAsm variant: the first
/// specific instruction whose operand masks accept the operands). Returns its index in `OPC`.
fn select_specific(st: &mut LoaderState, genop: OpId) -> Result<usize, LoadCodeError> {
    let op = st.ops.op(genop).op as usize;
    let entry = &GEN_OPC[op];
    let num_specific = entry.num_specific;
    if num_specific == 1 {
        // There is only one possible specific instruction. Note that the operands for the
        // instruction will be verified later.
        return Ok(entry.specific as usize);
    }
    // Use bit masks to quickly find the most specific of the possible specific instructions
    // associated with this generic instruction.
    let mut mask = [0u32; 3];
    if num_specific != 0 {
        let arity = entry.arity;
        debug_assert!(2 * mask.len() >= arity);
        for arg in 0..arity {
            let ty = st.ops.op(genop).a(arg).ty;
            mask[arg / 2] |= (1u32 << ty) << ((arg % 2) << 4);
        }
    }
    for specific in (entry.specific as usize..).take(num_specific) {
        let m = &OPC[specific].mask;
        if (m[0] & mask[0]) == mask[0] && (m[1] & mask[1]) == mask[1] && (m[2] & mask[2]) == mask[2]
        {
            return Ok(specific);
        }
    }

    // No specific instruction found. No specific instructions and no transformations means that
    // the instruction is obsolete.
    if num_specific == 0 && !entry.transform {
        return Err(error(
            "please recompile this module with an OTP 29 compiler",
        ));
    }
    // Some generic instructions have a special error message.
    match op as i32 {
        GENOP_UNSUPPORTED_GUARD_BIF_3 => {
            let o = st.ops.op(genop);
            let text = |index: usize| {
                arinsal_term::global_atoms()
                    .text(arinsal_term::Atom(o.a(index).val as u32))
                    .unwrap_or("?")
                    .to_owned()
            };
            Err(error(format!(
                "unsupported guard BIF: {}:{}/{}\n",
                text(0),
                text(1),
                o.a(2).val
            )))
        }
        GENOP_BAD_BS_MATCH_1 => {
            let sub_command = st.ops.op(genop).a(0);
            if sub_command.ty == TAG_A {
                Err(error(format!(
                    "bs_match: invalid sub instruction '{}' (is this BEAM file generated by a future version of Erlang/OTP?)\n",
                    arinsal_term::global_atoms()
                        .text(arinsal_term::Atom(sub_command.val as u32))
                        .unwrap_or("?")
                )))
            } else {
                Err(error("bs_match: invalid operands (corrupt BEAM file?)\n"))
            }
        }
        _ => Err(error("no specific operation found")),
    }
}

/// `BeamLoadVerifyTag`: the tag of an operand must be the one its slot declares.
fn verify_tag(tag: u8, wanted: u8, slot: char) -> Result<(), LoadCodeError> {
    if tag == wanted {
        Ok(())
    } else {
        Err(error(format!(
            "bad tag {} for operand '{slot}'; expected {}",
            TAG_TO_LETTER[usize::from(tag)],
            TAG_TO_LETTER[usize::from(wanted)]
        )))
    }
}

/// The verification half of `beam_load_emit_op`: each operand of the specific instruction has the
/// tag its slot in the instruction's signature allows, and what the slot refers to exists. The
/// operands themselves go on as the loader has them (this runtime's assembler takes untagged
/// register indexes, byte offsets computed by itself, and import indexes).
fn verify_operands(
    st: &mut LoaderState,
    genop: OpId,
    specific: usize,
) -> Result<(), LoadCodeError> {
    let sign = OPC[specific].sign.as_bytes();
    let arity = st.ops.op(genop).arity;
    let mut arg = 0;
    for &letter in sign {
        if arg >= arity {
            return Err(error("too few operands"));
        }
        let a = st.ops.op(genop).a(arg);
        let tag = a.ty;
        let slot = char::from(letter);
        match letter {
            b'n' => verify_tag(tag, TAG_N, slot)?,
            b'x' => verify_tag(tag, TAG_X, slot)?,
            b'y' => verify_tag(tag, TAG_Y, slot)?,
            b'a' => verify_tag(tag, TAG_A, slot)?,
            // Tagged constant.
            b'c' => {
                if !matches!(tag, TAG_I | TAG_A | TAG_N | TAG_Q) {
                    return Err(error(format!(
                        "bad tag {} for tagged constant",
                        TAG_TO_LETTER[usize::from(tag)]
                    )));
                }
            }
            // Any source (tagged constant or register).
            b's' => {
                if !matches!(tag, TAG_X | TAG_Y | TAG_I | TAG_A | TAG_N | TAG_Q) {
                    return Err(error(format!(
                        "bad tag {} for general source",
                        TAG_TO_LETTER[usize::from(tag)]
                    )));
                }
            }
            // Destination or source register.
            b'd' | b'S' => {
                if !matches!(tag, TAG_X | TAG_Y) {
                    return Err(error(format!(
                        "bad tag {} for destination",
                        TAG_TO_LETTER[usize::from(tag)]
                    )));
                }
            }
            // Untagged integers, the arity and the tuple position, the fun entry.
            b't' | b'I' | b'W' | b'A' | b'P' | b'F' => verify_tag(tag, TAG_U, slot)?,
            // Destination label.
            b'f' => verify_tag(tag, TAG_F, slot)?,
            // `f` or `p`.
            b'j' => {
                if !matches!(tag, TAG_F | TAG_P) {
                    return Err(error(format!(
                        "bad tag {}; expected {} or {}",
                        TAG_TO_LETTER[usize::from(tag)],
                        TAG_TO_LETTER[usize::from(TAG_F)],
                        TAG_TO_LETTER[usize::from(TAG_P)]
                    )));
                }
            }
            // Define label.
            b'L' => {
                verify_tag(tag, TAG_U, slot)?;
                let label = a.val;
                let count = u64::from(st.beam.code.label_count);
                if label >= count {
                    return Err(error(format!(
                        "invalid label num {label} (0 < label < {count})"
                    )));
                }
                if std::mem::replace(&mut st.labels[label as usize].defined, true) {
                    return Err(error(format!("label {label} defined more than once")));
                }
            }
            // Export entry, and BIF import.
            b'e' | b'b' => {
                verify_tag(tag, TAG_U, slot)?;
                let index = a.val as usize;
                if index >= st.imports.len() {
                    return Err(error(format!("invalid import table index {index}")));
                }
                if letter == b'b' && st.bif_imports[index].is_none() {
                    return Err(error(format!("import {index} not a BIF")));
                }
            }
            // Floating point register.
            b'l' => verify_tag(tag, TAG_L, slot)?,
            // Literal.
            b'q' => verify_tag(tag, TAG_Q, slot)?,
            // Exception handler.
            b'H' => verify_tag(tag, TAG_F, slot)?,
            b'M' | b'i' => {}
            other => {
                return Err(error(format!("bad argument tag: {}", char::from(other))));
            }
        }
        arg += 1;
    }
    // Verify and massage any list arguments according to the primitive tags.
    while arg < arity {
        let tag = st.ops.op(genop).a(arg).ty;
        if !matches!(
            tag,
            TAG_I | TAG_N | TAG_A | TAG_V | TAG_U | TAG_F | TAG_X | TAG_Y | TAG_Q
        ) {
            return Err(error(format!(
                "unsupported primitive type '{}'",
                TAG_TO_LETTER[usize::from(tag)]
            )));
        }
        arg += 1;
    }
    Ok(())
}

/// `beam_load_emit_op`: verifies the operands of the instruction and hands the instruction to
/// the assembler.
fn emit_op<S: OpSink>(
    st: &mut LoaderState,
    genop: OpId,
    specific: usize,
    typed: bool,
    operands: &mut Vec<SpecificOperand>,
    announced: &mut usize,
    sink: &mut S,
) -> Result<(), LoadCodeError> {
    let (op, arity) = {
        let o = st.ops.op(genop);
        (o.op, o.arity)
    };
    verify_operands(st, genop, specific)?;
    if op == GENOP_I_FUNC_INFO_4 {
        if st.function_number >= st.beam.code.function_count as usize {
            return Err(error(format!(
                "too many functions in module (header said {})",
                st.beam.code.function_count
            )));
        }
        st.function_number += 1;
    }
    // Port of erts/emulator/beam/jit/asm_load.c:741 (beam_load_emit_op, op_int_code_end).
    if op == GENOP_INT_CODE_END_0 && st.function_number != st.beam.code.function_count as usize {
        return Err(error(format!(
            "too few functions ({}) in module (header said {})",
            st.function_number, st.beam.code.function_count
        )));
    }
    // The literals the load added so far are the assembler's from now on.
    while *announced < st.literals.extra.len() {
        let index = (st.literals.len() - st.literals.extra.len() + *announced) as u32;
        sink.new_literal(index, &st.literals.extra[*announced])
            .map_err(error)?;
        *announced += 1;
    }
    let use_types = typed && TYPED_OPS[op as usize];
    operands.clear();
    for index in 0..arity {
        let arg = st.ops.op(genop).a(index);
        operands.push(operand(arg, use_types)?);
    }
    sink.emit(op as u16, specific as u16, operands)
        .map_err(error)
}

/// The operand of the output for one `BeamOpArg`.
fn operand(arg: BeamOpArg, keep_type: bool) -> Result<SpecificOperand, LoadCodeError> {
    Ok(match arg.ty {
        // An untagged word: counts, indexes, hashes. Only values that fit a small integer are
        // `SmallInt`; a hash is a raw word whatever its value.
        TAG_U if arg.val < (1 << 59) => SpecificOperand::SmallInt(arg.val as i64),
        TAG_U => SpecificOperand::Unsigned(arg.val),
        TAG_I => SpecificOperand::SmallInt(arg.val as i64),
        TAG_A => SpecificOperand::Atom(arg.val as u32),
        TAG_X | TAG_Y => {
            let index = (arg.val & (MAX_REG - 1)) as u32;
            let type_index = (arg.val >> REG_TYPE_SHIFT) as u32;
            match (arg.ty == TAG_X, keep_type && type_index != 0) {
                (true, false) => SpecificOperand::X(index),
                (false, false) => SpecificOperand::Y(index),
                (true, true) => SpecificOperand::TypedX { index, type_index },
                (false, true) => SpecificOperand::TypedY { index, type_index },
            }
        }
        TAG_F => SpecificOperand::Label(arg.val as u32),
        TAG_P => SpecificOperand::Label(0),
        TAG_N => SpecificOperand::Nil,
        TAG_L => SpecificOperand::FloatRegister(arg.val as u32),
        TAG_Q => SpecificOperand::Literal(arg.val as u32),
        // The arity header of `select_tuple_arity`.
        TAG_V => SpecificOperand::Unsigned(arg.val >> 6),
        TAG_O => SpecificOperand::SmallInt(0),
        other => {
            return Err(error(format!(
                "unsupported operand type {}",
                TAG_TO_LETTER[usize::from(other)]
            )));
        }
    })
}
