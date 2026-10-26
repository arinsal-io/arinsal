//! The BeamAsm loader's instruction pipeline: the generic instructions of a BEAM file go through
//! the transformation engine and the specific-instruction selection of erts (`load_code`), a
//! port of beam_load.c, beam_file.c and the code `beam_makeops` generates, and come out as the
//! specific operations the module assembler emits.

#![forbid(unsafe_code)]

mod beam_op;
mod erts_tables;
mod load_code;
mod loader_state;
pub use load_code::LoadCodeError;
mod transform_helpers;
#[cfg(test)]
mod transform_helpers_tests;
use arinsal_beam::BeamFile;

/// The opcode tables of the erts build, as text (for comparison with a real erts's tables).
#[doc(hidden)]
pub fn erts_tables_dump() -> String {
    erts_tables::dump()
}

/// A literal that the load adds to the module's table (`beamfile_add_literal` of erts), in the
/// order of the table after the file's own literals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewLiteral {
    /// An integer too large for a word, as decimal text (`marshal_integer`).
    Bignum(String),
    /// The key tuple of a small map literal (generator `new_small_map_lit`).
    Tuple(Vec<LiteralElement>),
    /// The fun of lambda `lambda` without free variables: a fun thing whose entry the loader
    /// sets when the module is finalized (`lambda_literals` of asm_load.c).
    FunPlaceholder {
        /// Index in the lambda table.
        lambda: u32,
    },
    /// The definition of the record with this index in the record table (`def_literal`).
    Record {
        /// Index in the record table.
        index: u32,
    },
}

/// An element of a [`NewLiteral::Tuple`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteralElement {
    /// A global atom.
    Atom(u32),
    /// A small integer.
    Small(i64),
    /// The empty list.
    Nil,
    /// A literal of the module's table, by index.
    Literal(u32),
}

/// A typed operand accepted by a BeamAsm-specific operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecificOperand {
    /// X register index.
    X(u32),
    /// Y stack slot index.
    Y(u32),
    /// Float register index.
    FloatRegister(u32),
    /// Label index.
    Label(u32),
    /// Global atom index, as erts atoms are (the atom table of the node, not of the module).
    Atom(u32),
    /// Export-table entry index.
    Export(u32),
    /// Literal table index.
    Literal(u32),
    /// Small signed immediate.
    SmallInt(i64),
    /// Unsigned immediate.
    Unsigned(u64),
    /// Nil operand.
    Nil,
    /// Integer outside `i64`, as decimal text; the loader turns it into a literal.
    BigInt(Box<String>),
    /// A register operand with the compiler's `Type` chunk entry (`{tr, Reg, Type}`); only
    /// produced by the typed transform, for operations that use operand types.
    Typed {
        /// The register operand.
        reg: Box<SpecificOperand>,
        /// Index into the module's `Type` chunk.
        type_index: u32,
    },
}

/// Range of transformed operations belonging to one function or module preamble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionOps {
    /// First operation in the arena's flat operation buffer.
    pub start: usize,
    /// Number of operations in this range.
    pub len: usize,
}

/// Reusable storage for the transformed operations of a module and what they refer to.
///
/// Keep one arena for a compile stream so the operation allocator of the loader, with its freed
/// operations, is reused by later modules.
#[derive(Default)]
pub struct TransformArena {
    specific_ops: Vec<SpecificOp>,
    functions: Vec<FunctionOps>,
    /// The operation allocator of the loader (`op_allocator`), kept between modules.
    beam_ops: beam_op::BeamOpAllocator,
    /// The literals the load added after the file's (`beamfile_add_literal`).
    new_literals: Vec<NewLiteral>,
    /// The number of literals in the file: the index of the first new one.
    file_literals: usize,
}

impl TransformArena {
    /// Creates an empty reusable transformation arena.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a function's specific operations without copying its operation vector.
    pub fn ops(&self, function: FunctionOps) -> &[SpecificOp] {
        &self.specific_ops[function.start..function.start + function.len]
    }

    /// The number of functions (and the module preamble) of the last transformed module.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// The operation range of function `index`.
    pub fn function_range(&self, index: usize) -> FunctionOps {
        self.functions[index]
    }

    /// The literal a `Literal(index)` operand names when it is beyond the file's literal table.
    pub fn new_literal(&self, index: u32) -> Option<&NewLiteral> {
        self.new_literals
            .get((index as usize).checked_sub(self.file_literals)?)
    }

    fn reset(&mut self) {
        self.specific_ops.clear();
        self.functions.clear();
        self.new_literals.clear();
    }
}

/// Operations whose operands keep their `Type` chunk entry in the typed transform.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp and instr_guard_bifs.cpp, OTP-29.1.1.
const TYPED_OPS: &[&str] = &[
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
    "bif_is_map_key",
];

include!(concat!(env!("OUT_DIR"), "/specific_ops.rs"));

/// Transforms a module like `load_code` of erts and returns its operations per function; the
/// operations before the first function label (the module preamble) form the first range.
pub fn transform_module(beam: &BeamFile) -> Result<Vec<Vec<SpecificOp>>, LoadCodeError> {
    transform_module_with_line_breakpoints(beam, false)
}

/// Like [`transform_module`] for a node whose debugger instruments line breakpoints.
// Port of erts/emulator/beam/predicates.tab (instrumenting_line_breakpoints), OTP-29.1.1.
pub fn transform_module_with_line_breakpoints(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
) -> Result<Vec<Vec<SpecificOp>>, LoadCodeError> {
    materialize_module(beam, instrument_line_breakpoints, false)
}

/// Like [`transform_module_with_line_breakpoints`], but arithmetic operations keep the `Type`
/// chunk entry of their register operands as [`SpecificOperand::Typed`].
pub fn transform_module_typed(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
) -> Result<Vec<Vec<SpecificOp>>, LoadCodeError> {
    materialize_module(beam, instrument_line_breakpoints, true)
}

/// Transforms a module into reusable arena storage and leaves its function ranges there.
// Port of erts/emulator/beam/beam_load.c:load_code, OTP-29.1.1.
pub fn transform_module_typed_in_arena(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    arena: &mut TransformArena,
) -> Result<(), LoadCodeError> {
    load_code::load_code(beam, instrument_line_breakpoints, true, arena)
}

fn materialize_module(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    typed: bool,
) -> Result<Vec<Vec<SpecificOp>>, LoadCodeError> {
    let mut arena = TransformArena::new();
    load_code::load_code(beam, instrument_line_breakpoints, typed, &mut arena)?;
    Ok(arena
        .functions
        .iter()
        .map(|range| arena.ops(*range).to_vec())
        .collect())
}

/// The compiled transformation programs as text (see `tests/erts_programs.rs`).
#[doc(hidden)]
pub fn erts_programs_dump() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/erts_programs.txt"))
}

/// The text of a global atom, as [`SpecificOperand::Atom`] names one.
pub fn atom_name(index: u32) -> Option<&'static str> {
    arinsal_term::global_atoms().text(arinsal_term::Atom(index))
}

/// The global atom index of `name`, creating the atom when needed.
pub fn global_atom_index(name: &str) -> Option<u32> {
    arinsal_term::global_atoms()
        .intern(name)
        .ok()
        .map(|atom| atom.0)
}
