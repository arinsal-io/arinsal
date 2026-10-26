//! The BeamAsm loader's instruction pipeline: the generic instructions of a BEAM file go through
//! the transformation engine and the specific-instruction selection of erts (`load_code`), a
//! port of beam_load.c, beam_file.c and the code `beam_makeops` generates, and come out one by
//! one as the specific operations the module assembler emits (`beam_load_emit_op` handing each
//! to `beamasm_emit`).

#![forbid(unsafe_code)]

mod beam_op;
#[doc(hidden)]
pub mod erts_tables;
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

/// An operand of a specific operation: what `beam_load_emit_op` leaves in the operand array
/// that `beamasm_emit` takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Literal table index: a literal of the file, or one the load added ([`NewLiteral`]).
    Literal(u32),
    /// Small signed immediate.
    SmallInt(i64),
    /// Unsigned immediate.
    Unsigned(u64),
    /// Nil operand.
    Nil,
    /// An X register with the compiler's `Type` chunk entry (`{tr, Reg, Type}`); only produced
    /// by the typed transform, for operations that use operand types.
    TypedX {
        /// The register index.
        index: u32,
        /// Index into the module's `Type` chunk.
        type_index: u32,
    },
    /// A Y register with the compiler's `Type` chunk entry.
    TypedY {
        /// The register index.
        index: u32,
        /// Index into the module's `Type` chunk.
        type_index: u32,
    },
}

/// What the loader hands the module assembler: the receiver of `beamasm_emit`.
pub trait OpSink {
    /// A literal the load added is used from now on (`beamfile_add_literal`); `index` is its
    /// literal index, which operands name. Called once per literal, before the first operation
    /// that could use it.
    fn new_literal(&mut self, index: u32, literal: &NewLiteral) -> Result<(), String>;
    /// `beamasm_emit`: one specific operation, by the number of its generic operation
    /// ([`erts_tables::GENOP_I_FUNC_LABEL_1`] and its siblings), with its operands.
    fn emit(&mut self, op: u16, operands: &[SpecificOperand]) -> Result<(), String>;
}

/// The name of a generic operation, which is the name of its specific operation.
pub fn generic_op_name(op: u16) -> &'static str {
    erts_tables::GEN_OPC[usize::from(op)].name
}

/// The number of generic operations (the length of the table `generic_op_name` indexes).
pub const NUM_GENERIC_OPS: usize = erts_tables::NUM_GENERIC_OPS;

/// A specific operation, owned: what a tool that collects the output of the loader gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecificOp {
    op: u16,
    operands: Vec<SpecificOperand>,
}

impl SpecificOp {
    /// The generic operation number.
    pub fn id(&self) -> u16 {
        self.op
    }

    /// The OTP operation name.
    pub fn name(&self) -> &'static str {
        generic_op_name(self.op)
    }

    /// The operands.
    pub fn operands(&self) -> &[SpecificOperand] {
        &self.operands
    }
}

/// Reusable storage of the loader: its operation allocator, kept between modules so freed
/// operations are reused by later modules.
#[derive(Default)]
pub struct TransformArena {
    /// The operation allocator of the loader (`op_allocator`).
    beam_ops: beam_op::BeamOpAllocator,
    /// The operand array of the operation being emitted.
    operands: Vec<SpecificOperand>,
}

impl TransformArena {
    /// Creates an empty reusable transformation arena.
    pub fn new() -> Self {
        Self::default()
    }
}

include!(concat!(env!("OUT_DIR"), "/specific_ops.rs"));

/// Loads the code of a module like `load_code` of erts: the operations go to `sink` one by one,
/// as the engine produces them.
// Port of erts/emulator/beam/beam_load.c:load_code, OTP-29.1.1.
pub fn load_code<S: OpSink>(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    typed: bool,
    arena: &mut TransformArena,
    sink: &mut S,
) -> Result<(), LoadCodeError> {
    load_code::load_code(beam, instrument_line_breakpoints, typed, arena, sink)
}

/// Collects the operations of a module per function; a function starts at its
/// `i_func_label`, and the operations before the first one form the first range.
struct Collect {
    functions: Vec<Vec<SpecificOp>>,
}

impl OpSink for Collect {
    fn new_literal(&mut self, _index: u32, _literal: &NewLiteral) -> Result<(), String> {
        Ok(())
    }

    fn emit(&mut self, op: u16, operands: &[SpecificOperand]) -> Result<(), String> {
        if i32::from(op) == erts_tables::GENOP_I_FUNC_LABEL_1
            && self.functions.last().is_some_and(|range| !range.is_empty())
        {
            self.functions.push(Vec::new());
        }
        self.functions
            .last_mut()
            .expect("a first range")
            .push(SpecificOp {
                op,
                operands: operands.to_vec(),
            });
        Ok(())
    }
}

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
    collect_module(beam, instrument_line_breakpoints, false)
}

/// Like [`transform_module_with_line_breakpoints`], but arithmetic operations keep the `Type`
/// chunk entry of their register operands as [`SpecificOperand::TypedX`] and `TypedY`.
pub fn transform_module_typed(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
) -> Result<Vec<Vec<SpecificOp>>, LoadCodeError> {
    collect_module(beam, instrument_line_breakpoints, true)
}

fn collect_module(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    typed: bool,
) -> Result<Vec<Vec<SpecificOp>>, LoadCodeError> {
    let mut arena = TransformArena::new();
    let mut sink = Collect {
        functions: vec![Vec::new()],
    };
    load_code::load_code(
        beam,
        instrument_line_breakpoints,
        typed,
        &mut arena,
        &mut sink,
    )?;
    sink.functions.retain(|range| !range.is_empty());
    Ok(sink.functions)
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
