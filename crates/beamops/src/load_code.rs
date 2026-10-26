//! Port of `load_code` of erts/emulator/beam/beam_load.c and of `beam_load_emit_op` of
//! erts/emulator/beam/jit/asm_load.c (OTP-29.1.1): the loop that reads the generic instructions,
//! runs the transformation engine on the window at the head of the chain, selects the specific
//! instruction and emits it. Emitting appends the instruction to the arena of the caller.

use crate::NewLiteral;
use crate::beam_op::*;
use crate::erts_tables::*;
use crate::loader_state::{LoaderState, TeResult, erts_transform_engine};
use crate::{SpecificOp, SpecificOperand, TYPED_OPS, TransformArena};
use arinsal_beam::BeamFile;
use smallvec::SmallVec;

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

/// `load_code`: transforms the module's code and appends its specific instructions to `arena`.
pub(crate) fn load_code(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    typed: bool,
    arena: &mut TransformArena,
) -> Result<(), LoadCodeError> {
    arena.reset();
    let ops = std::mem::take(&mut arena.beam_ops);
    let debugger_flags = if instrument_line_breakpoints {
        DEBUGGER_LINE_BREAKPOINTS
    } else {
        0
    };
    let Some(mut st) = LoaderState::new(beam, ops, None, debugger_flags) else {
        return Err(error("the module's tables cannot be loaded"));
    };
    let result = run(&mut st, typed, arena);
    arena.file_literals = beam.literals.len();
    arena.new_literals = std::mem::take(&mut st.literals.extra);
    arena.beam_ops = std::mem::take(&mut st.ops);
    result
}

fn run(st: &mut LoaderState, typed: bool, arena: &mut TransformArena) -> Result<(), LoadCodeError> {
    let mut reader = BeamCodeReader::with_atoms(st.beam, st.atoms.clone());
    // `last_op_next`: `Some(tail)` is the last operation of the chain, `None` with an empty chain
    // is `&stp->genop`; `tail_unknown` is C's NULL, found again by walking the chain.
    let mut tail: Option<OpId> = None;
    let mut tail_unknown = false;
    let mut function_start = 0;

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
            select_specific(st, genop)?;
            let is_end = st.ops.op(genop).op == GENOP_INT_CODE_END_0;
            emit_op(st, genop, typed, arena, &mut function_start)?;

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

    if arena.specific_ops.len() != function_start {
        arena.functions.push(crate::FunctionOps {
            start: function_start,
            len: arena.specific_ops.len() - function_start,
        });
    }
    Ok(())
}

/// The selection of the specific instruction in `load_code` (the BeamAsm variant: the first
/// specific instruction whose operand masks accept the operands).
fn select_specific(st: &mut LoaderState, genop: OpId) -> Result<(), LoadCodeError> {
    let (op, arity) = {
        let o = st.ops.op(genop);
        (o.op as usize, o.arity)
    };
    let entry = &GEN_OPC[op];
    let num_specific = entry.num_specific;
    if num_specific == 1 {
        // There is only one possible specific instruction. Note that the operands for the
        // instruction will be verified later.
        return Ok(());
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
            return Ok(());
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
    let _ = arity;
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

/// `beam_load_emit_op`: the operands of the instruction as the output of the loader.
fn emit_op(
    st: &mut LoaderState,
    genop: OpId,
    typed: bool,
    arena: &mut TransformArena,
    function_start: &mut usize,
) -> Result<(), LoadCodeError> {
    let (op, arity) = {
        let o = st.ops.op(genop);
        (o.op as usize, o.arity)
    };
    let name = GEN_OPC[op].name;
    if name == "i_func_label" && arena.specific_ops.len() != *function_start {
        arena.functions.push(crate::FunctionOps {
            start: *function_start,
            len: arena.specific_ops.len() - *function_start,
        });
        *function_start = arena.specific_ops.len();
    }
    if name == "i_func_info" {
        if st.function_number >= st.beam.code.function_count as usize {
            return Err(error(format!(
                "too many functions in module (header said {})",
                st.beam.code.function_count
            )));
        }
        st.function_number += 1;
    }
    let use_types = typed && TYPED_OPS.contains(&name);
    let mut operands: SmallVec<[SpecificOperand; 4]> = SmallVec::with_capacity(arity);
    for index in 0..arity {
        let arg = st.ops.op(genop).a(index);
        operands.push(operand(st, arg, use_types)?);
    }
    arena
        .specific_ops
        .push(SpecificOp::from_name(name, operands));
    Ok(())
}

/// The operand of the output for one massaged `BeamOpArg`.
fn operand(
    st: &LoaderState,
    arg: BeamOpArg,
    keep_type: bool,
) -> Result<SpecificOperand, LoadCodeError> {
    let register = |kind: u8, value: u64| {
        let index = (value & (MAX_REG - 1)) as u32;
        let register = if kind == TAG_X {
            SpecificOperand::X(index)
        } else {
            SpecificOperand::Y(index)
        };
        let type_index = (value >> REG_TYPE_SHIFT) as u32;
        if keep_type && type_index != 0 {
            SpecificOperand::Typed {
                reg: Box::new(register),
                type_index,
            }
        } else {
            register
        }
    };
    Ok(match arg.ty {
        // An untagged word: counts, indexes, hashes. Only values that fit a small integer are
        // `SmallInt`; a hash is a raw word whatever its value.
        TAG_U if arg.val < (1 << 59) => SpecificOperand::SmallInt(arg.val as i64),
        TAG_U => SpecificOperand::Unsigned(arg.val),
        TAG_I => SpecificOperand::SmallInt(arg.val as i64),
        TAG_A => SpecificOperand::Atom(arg.val as u32),
        TAG_X | TAG_Y => register(arg.ty, arg.val),
        TAG_F => SpecificOperand::Label(arg.val as u32),
        TAG_P => SpecificOperand::Label(0),
        TAG_N => SpecificOperand::Nil,
        TAG_L => SpecificOperand::FloatRegister(arg.val as u32),
        // A type index is not part of a literal.
        TAG_Q => match st
            .literals
            .extra
            .get((arg.val as usize).wrapping_sub(st.beam.literals.len()))
        {
            Some(NewLiteral::Bignum(text)) => SpecificOperand::BigInt(Box::new(text.clone())),
            _ => SpecificOperand::Literal(arg.val as u32),
        },
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
