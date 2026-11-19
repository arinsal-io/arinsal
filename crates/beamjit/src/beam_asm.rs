//! The target-independent loader side of BeamAsm: the operand massaging of
//! erts/emulator/beam/jit/asm_load.c (`beam_load_emit_op`) that turns the operands of a
//! specific instruction into the `ArgVal`s `beamasm_emit` hands the module assembler, the
//! literals the load adds (`beamfile_add_literal`), and the coverage and error types of
//! erts/emulator/beam/jit/beam_jit_main.cpp, OTP-29.1.1. The module assembler driver itself is
//! per target (`arm`, `x86`), as erts builds jit/ with exactly one of jit/arm or jit/x86.

use arinsal_beam::BeamFile;
use arinsal_beamasm::common::args::{ArgVal, REG_MASK};
use arinsal_beamops::{LiteralElement, NewLiteral, SpecificOperand, TransformArena};
use std::cell::RefCell;

thread_local! {
    static TRANSFORM_ARENA: RefCell<TransformArena> = RefCell::new(TransformArena::new());
}

/// Runs `load` with this thread's transform arena, reused across the modules it loads.
pub(crate) fn with_transform_arena<T>(load: impl FnOnce(&mut TransformArena) -> T) -> T {
    TRANSFORM_ARENA.with(|arena| load(&mut arena.borrow_mut()))
}

/// Native coverage storage selected by the loaded module's OTP coverage mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageProbe {
    /// Stable address of the byte flag or machine-word counter.
    pub address: usize,
    /// Byte flags are set to a nonzero value; counters are atomically incremented.
    pub flags: bool,
}

/// Error returned for invalid input files or module-wide emission failures.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// BEAM parser error.
    #[error("BEAM parse failed: {0}")]
    Parse(String),
    /// Module assembler failed while finalizing code.
    #[error("module assembly failed: {0}")]
    Assemble(String),
    /// Coverage traversal or file loading failed.
    #[error("I/O at {0}: {1}")]
    Io(String, String),
}

/// What the loader reads from the module's `BeamFile` and the node while it emits: the term
/// words of atoms and literals, the literals the load adds, and the BIF behind an import
/// (`stp->bif_imports`).
pub trait LoaderEnv {
    /// The tagged atom word of the global atom `index`.
    fn atom(&self, beam: &BeamFile, index: u32) -> Result<u64, String>;
    /// The term word of the literal at `index`: one of the file, or one the load added.
    fn literal(&self, beam: &BeamFile, index: u32) -> Result<u64, String>;
    /// Registers `word` as the literal at `index`, one the load added after the literals of
    /// the file (`beamfile_add_literal`).
    fn add_literal(&self, index: u32, word: u64) -> Result<(), String>;
    /// A bignum literal for an integer operand outside the small range.
    fn integer_literal(&self, value: i64) -> Result<u64, String>;
    /// A bignum literal from decimal text (integers outside `i64`).
    fn bigint_literal(&self, decimal: &str) -> Result<u64, String>;
    /// The fun of the lambda at `lambda` when it has no free variables (`erts_fun_entry_put`
    /// of the module's fun entry).
    fn zero_capture_fun(&self, beam: &BeamFile, lambda: u32) -> Result<u64, String>;
    /// A tuple literal of tagged element words.
    fn tuple_literal(&self, elements: &[u64]) -> Result<u64, String>;
    /// `stp->bif_imports[index]->f`: the C function of the BIF the import `index` names.
    fn bif_import(&self, beam: &BeamFile, index: u32) -> Result<u64, String>;
    /// `bif_table[erts_active_export_entry(M,F,A)->bif_number].f` for `call_bif_mfa`.
    fn bif_mfa_function(&self, module: &str, function: &str, arity: u8) -> Result<u64, String> {
        Err(format!(
            "module environment has no BIF function for {module}:{function}/{arity}"
        ))
    }
    /// `BIF_TRAP_EXPORT(BIF_send_2)` and `send_2` for the generated `send` instruction.
    fn send_target(&self) -> Result<(u64, u64), String> {
        Err("module environment has no send/2 export".into())
    }
}

/// The word of a literal the load added after the file's own (`beamfile_add_literal`): key
/// tuples, bignums and the funs of lambdas without free variables. The environment holds them
/// under their literal index, like the literals of the file.
pub(crate) fn resolve_new_literal(
    beam: &BeamFile,
    env: &(impl LoaderEnv + ?Sized),
    index: u32,
    literal: &NewLiteral,
) -> Result<(), String> {
    let word = match literal {
        // The environment has the record definitions after the literals of the file.
        NewLiteral::Record { .. } => return Ok(()),
        NewLiteral::Bignum(text) => env.bigint_literal(text),
        // The fun entry of a lambda without free variables is created with the module.
        NewLiteral::FunPlaceholder { lambda } => env.zero_capture_fun(beam, *lambda),
        NewLiteral::Tuple(elements) => elements
            .iter()
            .map(|element| match element {
                LiteralElement::Atom(atom) => env.atom(beam, *atom),
                LiteralElement::Small(value) => Ok(make_small(*value)),
                LiteralElement::Nil => Ok(NIL),
                LiteralElement::Literal(literal) => env.literal(beam, *literal),
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|words| env.tuple_literal(&words)),
    }?;
    env.add_literal(index, word)
}

/// `NIL`.
const NIL: u64 = 0x3b;

/// `make_small(value)`.
fn make_small(value: i64) -> u64 {
    ((value as u64) << 4) | 0xf
}

/// `make_arityval(arity)` (`make_arityval_zero()` for zero).
fn make_arityval(arity: u64) -> u64 {
    arity << 6
}

/// `IS_SSMALL(value)`: fits the 60-bit small integer payload.
fn is_ssmall(value: i64) -> bool {
    (-(1_i64 << 59)..(1_i64 << 59)).contains(&value)
}

/// A tagged integer `TAG_i` operand: an immediate small, or the bignum literal the loader
/// made of an integer outside the small range.
fn tagged_integer(env: &(impl LoaderEnv + ?Sized), value: i64) -> Result<ArgVal, String> {
    if is_ssmall(value) {
        Ok(ArgVal::Immediate(make_small(value)))
    } else {
        env.integer_literal(value).map(ArgVal::Literal)
    }
}

/// A word operand (`TAG_u`, `BeamLoadVerifyTag(stp, tag, TAG_u)`).
fn word(operand: &SpecificOperand, sign: char) -> Result<u64, String> {
    match operand {
        SpecificOperand::Unsigned(value) => Ok(*value),
        other => Err(format!("bad tag {other:?} for '{sign}'; expected u")),
    }
}

/// A `TAG_x` / `TAG_y` operand as `ArgVal`: the register number with the type index of a
/// typed register (`{tr, Reg, Type}`) packed above `REG_MASK`, as the reader of the code
/// chunk does; without a type table (stripped after compilation) a typed register is an
/// ordinary one.
// Port of erts/emulator/beam/beam_file.c:2415-2438 (read_code, register with type hint),
// OTP-29.1.1.
fn register(beam: &BeamFile, operand: &SpecificOperand) -> Result<ArgVal, String> {
    let (index, type_index) = match *operand {
        SpecificOperand::X(index) | SpecificOperand::Y(index) => (index, 0),
        SpecificOperand::TypedX { index, type_index }
        | SpecificOperand::TypedY { index, type_index } => {
            let type_index = match beam.types.as_ref() {
                Some(types) if (type_index as usize) < types.entries.len() => type_index,
                Some(types) => {
                    return Err(format!(
                        "type index {type_index} out of range ({} entries)",
                        types.entries.len()
                    ));
                }
                None => 0,
            };
            (index, type_index)
        }
        _ => return Err(format!("{operand:?} is not a register")),
    };
    if index > REG_MASK {
        return Err(format!("register {index} out of range"));
    }
    Ok(match operand {
        SpecificOperand::X(_) | SpecificOperand::TypedX { .. } => {
            ArgVal::typed_x(index, type_index)
        }
        _ => ArgVal::typed_y(index, type_index),
    })
}

/// The operands of the specific instruction `specific` as `beamasm_emit` hands them to the
/// module assembler: each operand verified and massaged according to the instruction's
/// signature (`opc[specific_op].sign`), then the variable argument list by its primitive
/// tags. `args` is cleared first.
// Port of erts/emulator/beam/jit/asm_load.c:357-640 (beam_load_emit_op), OTP-29.1.1.
pub fn beam_load_emit_op(
    beam: &BeamFile,
    env: &(impl LoaderEnv + ?Sized),
    sign: &str,
    operands: &[SpecificOperand],
    args: &mut Vec<ArgVal>,
) -> Result<(), String> {
    args.clear();
    let mut rest = operands.iter();
    for letter in sign.chars() {
        let curr = rest
            .next()
            .ok_or_else(|| format!("operand '{letter}' missing"))?;
        let arg = match (letter, curr) {
            ('n', SpecificOperand::Nil) => ArgVal::Immediate(NIL),
            ('x' | 'd' | 'S' | 's', SpecificOperand::X(_) | SpecificOperand::TypedX { .. })
            | ('y' | 'd' | 'S' | 's', SpecificOperand::Y(_) | SpecificOperand::TypedY { .. }) => {
                register(beam, curr)?
            }
            ('a' | 'c' | 's', SpecificOperand::Atom(index)) => {
                ArgVal::Immediate(env.atom(beam, *index)?)
            }
            ('c' | 's', SpecificOperand::SmallInt(value)) => tagged_integer(env, *value)?,
            ('c' | 's', SpecificOperand::Nil) => ArgVal::Immediate(NIL),
            ('c' | 's' | 'q', SpecificOperand::Literal(index)) => {
                ArgVal::Literal(env.literal(beam, *index)?)
            }
            ('t' | 'I' | 'W', operand) => ArgVal::Word(word(operand, letter)?),
            ('A', operand) => ArgVal::Word(make_arityval(word(operand, letter)?)),
            ('f' | 'j', SpecificOperand::Label(label)) => ArgVal::Label(*label),
            // `BeamLoadVerifyTag(stp, tag, TAG_u)`, then `curr->type = TAG_f`.
            ('L', operand) => ArgVal::Label(
                u32::try_from(word(operand, letter)?).map_err(|_| "label number overflow")?,
            ),
            ('e', operand) => {
                let index = word(operand, letter)?;
                if index >= beam.imports.len() as u64 {
                    return Err(format!("invalid import table index {index}"));
                }
                ArgVal::Export(index as u32)
            }
            ('b', operand) => {
                let index = word(operand, letter)?;
                if index >= beam.imports.len() as u64 {
                    return Err(format!("invalid import table index {index}"));
                }
                ArgVal::Word(env.bif_import(beam, index as u32)?)
            }
            ('P', operand) => ArgVal::Word((word(operand, letter)? + 1) * 8),
            ('l', SpecificOperand::FloatRegister(index)) => ArgVal::FReg(index * 8),
            ('F', operand) => ArgVal::FunEntry(
                u32::try_from(word(operand, letter)?).map_err(|_| "lambda index overflow")?,
            ),
            ('H', SpecificOperand::Label(label)) => ArgVal::Catch(*label),
            ('M', operand) => ArgVal::BytePtr(word(operand, letter)?),
            // `curr->type = 'I'` with the value as it is.
            ('i', SpecificOperand::SmallInt(value)) => ArgVal::Immediate(*value as u64),
            ('i', SpecificOperand::Unsigned(value)) => ArgVal::Immediate(*value),
            ('i', SpecificOperand::Atom(index)) => ArgVal::Immediate(env.atom(beam, *index)?),
            (letter, other) => return Err(format!("bad tag {other:?} for '{letter}'")),
        };
        args.push(arg);
    }
    // The variable argument list, by its primitive tags.
    for curr in rest {
        let arg = match curr {
            SpecificOperand::SmallInt(value) => tagged_integer(env, *value)?,
            SpecificOperand::Nil => ArgVal::Immediate(NIL),
            SpecificOperand::Atom(index) => ArgVal::Immediate(env.atom(beam, *index)?),
            SpecificOperand::Unsigned(value) => ArgVal::Word(*value),
            SpecificOperand::Label(label) => ArgVal::Label(*label),
            SpecificOperand::X(_)
            | SpecificOperand::TypedX { .. }
            | SpecificOperand::Y(_)
            | SpecificOperand::TypedY { .. } => register(beam, curr)?,
            SpecificOperand::Literal(index) => ArgVal::Literal(env.literal(beam, *index)?),
            other => return Err(format!("unsupported primitive type {other:?}")),
        };
        args.push(arg);
    }
    Ok(())
}
