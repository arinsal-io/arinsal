//! Build generated BeamAsm operations and apply the OTP 29 direct rewrite rules.

#![forbid(unsafe_code)]

#[allow(dead_code)]
mod beam_op;
mod erts_tables;
#[path = "rule_syntax.rs"]
mod rule_syntax;
use arinsal_beam::{BeamFile, Instr, Operand};
use arinsal_etf::OwnedTerm;
use arinsal_spec::BifKind;
use rule_syntax::*;
use smallvec::SmallVec;
use std::{collections::HashMap, sync::OnceLock};

/// The generic instructions the module's code reader produces, as text, one per line: the name,
/// then every operand as `<tag letter>:<value>` (atoms by name). For tests of the reader.
#[doc(hidden)]
pub fn reader_dump(beam: &BeamFile) -> Vec<String> {
    let mut alloc = beam_op::BeamOpAllocator::new();
    let mut reader = beam_op::BeamCodeReader::new(beam);
    let mut lines = Vec::new();
    loop {
        let id = reader.next(&mut alloc).expect("a readable instruction");
        let op = alloc.op(id);
        let entry = &erts_tables::GEN_OPC[op.op as usize];
        let mut line = format!("{}/{}", entry.name, op.arity);
        for arg in op.args() {
            let letter = beam_op::TAG_TO_LETTER[usize::from(arg.ty)];
            match arg.ty {
                beam_op::TAG_A => {
                    let name = arinsal_term::global_atoms()
                        .text(arinsal_term::Atom(arg.val as u32))
                        .expect("an interned atom");
                    line.push_str(&format!(" a:{name}"));
                }
                beam_op::TAG_Q if arg.val as usize >= beam.literals.len() => {
                    let big = &reader.bignum_literals[arg.val as usize - beam.literals.len()];
                    line.push_str(&format!(" q:big{big}"));
                }
                _ => line.push_str(&format!(" {letter}:{}", arg.val)),
            }
        }
        let end = entry.name == "int_code_end";
        lines.push(line);
        if end {
            return lines;
        }
    }
}

/// What the transform engine starts from today (the generic nodes after the function boundary
/// passes), in the format of [`reader_dump`]. For tests of the reader.
#[doc(hidden)]
pub fn legacy_generic_ops_dump(beam: &BeamFile) -> Vec<String> {
    let mut arena = TransformArena::new();
    arena.reset();
    let mut head = None;
    let mut tail = None;
    for instruction in &beam.code.instructions {
        let node = Node {
            name: instruction.op.name(),
            args: instruction.args.iter().map(allocation_as_words).collect(),
            offset: instruction.offset,
        };
        let index = arena.allocate(node, None);
        if let Some(previous) = tail {
            arena.set_next(previous, Some(index));
        } else {
            head = Some(index);
        }
        tail = Some(index);
    }
    head = inject_function_starts(&mut arena, head);
    add_function_end_nodes(&mut arena, &mut head);
    let mut lines = Vec::new();
    let mut cursor = head;
    while let Some(index) = cursor {
        let node = arena.node(index);
        let mut flat: Vec<String> = Vec::new();
        for operand in &node.args {
            legacy_operand_text(beam, operand, &mut flat);
        }
        // `synthesize_func_end` tags both labels `TAG_f`; the node of the current engine has `u`.
        if node.name == "int_func_end" {
            for text in &mut flat {
                *text = text.replacen("u:", "f:", 1);
            }
        }
        lines.push(
            format!("{}/{} {}", node.name, flat.len(), flat.join(" "))
                .trim_end()
                .to_owned(),
        );
        cursor = arena.next(index);
    }
    // `beamcodereader_next` puts the last `int_func_end/2` before `int_code_end/0`; the current
    // engine appends it after.
    let count = lines.len();
    if count >= 2
        && lines[count - 2] == "int_code_end/0"
        && lines[count - 1].starts_with("int_func_end/2")
    {
        lines.swap(count - 2, count - 1);
    }
    lines
}

fn legacy_operand_text(beam: &BeamFile, operand: &Operand, out: &mut Vec<String>) {
    match operand {
        Operand::U(value) => out.push(format!("u:{value}")),
        Operand::Int(value) => out.push(format!("i:{}", *value as u64)),
        Operand::BigInt(value) => out.push(format!("q:big{value}")),
        Operand::Atom(0) | Operand::Nil => out.push("n:0".to_owned()),
        Operand::Atom(index) => out.push(format!("a:{}", beam.atoms[*index as usize - 1])),
        Operand::X(register) => out.push(format!("x:{register}")),
        Operand::Y(register) => out.push(format!("y:{register}")),
        Operand::FR(register) => out.push(format!("l:{register}")),
        Operand::Label(0) => out.push("p:0".to_owned()),
        Operand::Label(label) => out.push(format!("f:{label}")),
        Operand::Char(value) => out.push(format!("h:{value}")),
        Operand::Literal(index) => out.push(format!("q:{index}")),
        Operand::List(items) => {
            out.push(format!("u:{}", items.len()));
            for item in items.iter() {
                legacy_operand_text(beam, item, out);
            }
        }
        Operand::Alloc(_) => {
            if let Operand::U(words) = allocation_as_words(operand) {
                out.push(format!("u:{words}"));
            }
        }
        Operand::TypedReg { reg, type_index } => {
            let (letter, register) = match **reg {
                Operand::X(r) => ('x', r),
                Operand::Y(r) => ('y', r),
                _ => ('?', 0),
            };
            let value = if beam.types.is_some() {
                u64::from(register) | (u64::from(*type_index) << 10)
            } else {
                u64::from(register)
            };
            out.push(format!("{letter}:{value}"));
        }
    }
}

/// The opcode tables of the erts build, as text (for comparison with a real erts's tables).
#[doc(hidden)]
pub fn erts_tables_dump() -> String {
    erts_tables::dump()
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
    /// Atom table index.
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
    /// Variable-length operand sequence.
    List(Box<Vec<SpecificOperand>>),
    /// A variable-length operand sequence stored in a transform arena.
    ArenaList(ArenaSlice),
    /// Allocation descriptor list.
    Allocations(Box<Vec<(u8, u64)>>),
    /// Allocation descriptors stored in a transform arena.
    ArenaAllocations(ArenaSlice),
    /// Operand forms without a specific BeamAsm representation yet.
    Other,
    /// A register operand with the compiler's `Type` chunk entry (`{tr, Reg, Type}`); only
    /// produced by the typed transform, for operations that use operand types.
    Typed {
        /// The register operand.
        reg: Box<SpecificOperand>,
        /// Index into the module's `Type` chunk.
        type_index: u32,
    },
}

/// Range into an arena-owned operand slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaSlice {
    /// First item in the owning arena's list storage.
    pub start: u32,
    /// Number of items in this list.
    pub len: u32,
}

impl ArenaSlice {
    fn from_range(start: usize, len: usize) -> Self {
        Self {
            start: u32::try_from(start).expect("BEAM operand arena index exceeds u32"),
            len: u32::try_from(len).expect("BEAM operand list exceeds u32 items"),
        }
    }
}

/// Range of transformed operations belonging to one function or module preamble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionOps {
    /// First operation in the arena's flat operation buffer.
    pub start: usize,
    /// Number of operations in this range.
    pub len: usize,
}

/// Reusable storage for generic ops, transformed operations, and variable operands.
///
/// Keep one arena for a compile stream so released generic nodes can be reused by later
/// rewrites and modules without allocating one object per operation.
#[derive(Default)]
pub struct TransformArena {
    node_blocks: Vec<Box<[NodeSlot; 32]>>,
    node_count: usize,
    free_head: Option<usize>,
    specific_ops: Vec<SpecificOp>,
    lists: Vec<SpecificOperand>,
    allocations: Vec<(u8, u64)>,
    functions: Vec<FunctionOps>,
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

    /// Returns the number of function ranges in the most recently transformed module.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Returns one function's range in the most recently transformed module.
    pub fn function_range(&self, index: usize) -> FunctionOps {
        self.functions[index]
    }

    /// Resolves a list operand stored in this arena.
    pub fn list(&self, slice: ArenaSlice) -> &[SpecificOperand] {
        let start = slice.start as usize;
        &self.lists[start..start + slice.len as usize]
    }

    /// Resolves allocation descriptors stored in this arena.
    pub fn allocation_list(&self, slice: ArenaSlice) -> &[(u8, u64)] {
        let start = slice.start as usize;
        &self.allocations[start..start + slice.len as usize]
    }

    fn reset(&mut self) {
        self.specific_ops.clear();
        self.lists.clear();
        self.allocations.clear();
        self.functions.clear();
        self.free_head = None;
        for index in (0..self.node_count).rev() {
            let next_free = self.free_head;
            let slot = self.slot_mut(index);
            slot.node = None;
            slot.next = next_free;
            self.free_head = Some(index);
        }
    }

    // Port of erts/emulator/beam/beam_file.c:beamopallocator_expand__, OTP-29.1.1.
    fn expand(&mut self) {
        let block_index = self.node_blocks.len();
        let mut block = Box::new(std::array::from_fn(|_| NodeSlot {
            node: None,
            next: None,
        }));
        let first = self.node_count;
        for slot_index in (0..32).rev() {
            let index = first + slot_index;
            block[slot_index].next = if slot_index == 31 {
                self.free_head
            } else {
                Some(index + 1)
            };
        }
        self.free_head = Some(first);
        self.node_count += 32;
        self.node_blocks.push(block);
        debug_assert_eq!(block_index + 1, self.node_blocks.len());
    }

    fn slot(&self, index: usize) -> &NodeSlot {
        &self.node_blocks[index / 32][index % 32]
    }

    fn slot_mut(&mut self, index: usize) -> &mut NodeSlot {
        &mut self.node_blocks[index / 32][index % 32]
    }

    // Port of erts/emulator/beam/beam_file.h:beamopallocator_new_op, OTP-29.1.1.
    fn allocate(&mut self, node: Node, next: Option<usize>) -> usize {
        if self.free_head.is_none() {
            self.expand();
        }
        if let Some(index) = self.free_head {
            self.free_head = self.next(index);
            let slot = self.slot_mut(index);
            slot.node = Some(node);
            slot.next = next;
            index
        } else {
            unreachable!("expansion supplies free GenOp nodes")
        }
    }

    // Port of erts/emulator/beam/beam_file.h:beamopallocator_free_op, OTP-29.1.1.
    fn release(&mut self, index: usize) {
        let next_free = self.free_head;
        let slot = self.slot_mut(index);
        slot.node = None;
        slot.next = next_free;
        self.free_head = Some(index);
    }

    fn node(&self, index: usize) -> &Node {
        self.slot(index).node.as_ref().expect("live GenOp node")
    }

    fn node_mut(&mut self, index: usize) -> &mut Node {
        self.slot_mut(index).node.as_mut().expect("live GenOp node")
    }

    fn next(&self, index: usize) -> Option<usize> {
        self.slot(index).next
    }

    fn set_next(&mut self, index: usize, next: Option<usize>) {
        self.slot_mut(index).next = next;
    }
}

struct NodeSlot {
    node: Option<Node>,
    next: Option<usize>,
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

/// Rewrites one function's generic instruction slice into specific operations.
pub fn transform_function(instructions: &[Instr]) -> Vec<SpecificOp> {
    transform_with_options(instructions, None, false, false)
}

/// Rewrites one function with module metadata needed by OTP predicates.
pub fn transform_function_in_module(instructions: &[Instr], beam: &BeamFile) -> Vec<SpecificOp> {
    transform_with_options(instructions, Some(beam), false, false)
}

/// Splits a module at `func_info` boundaries and rewrites each function.
pub fn transform_module(beam: &BeamFile) -> Vec<Vec<SpecificOp>> {
    transform_module_with_line_breakpoints(beam, false)
}

/// Splits a module and applies rewrites configured for OTP debugger instrumentation.
// Port of erts/emulator/beam/predicates.tab:168, OTP-29.1.1.
pub fn transform_module_with_line_breakpoints(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
) -> Vec<Vec<SpecificOp>> {
    materialize_module(beam, instrument_line_breakpoints, false)
}

/// Like [`transform_module_with_line_breakpoints`], but arithmetic operations keep the
/// `Type` chunk entry of their register operands as [`SpecificOperand::Typed`].
pub fn transform_module_typed(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
) -> Vec<Vec<SpecificOp>> {
    materialize_module(beam, instrument_line_breakpoints, true)
}

/// Rewrites a module into reusable arena storage and returns its flat function ranges.
// Port of erts/emulator/beam/beam_load.c:load_code and utils/beam_makeops:erts_transform_engine,
// OTP-29.1.1.
pub fn transform_module_typed_in_arena(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    arena: &mut TransformArena,
) {
    transform_into_arena(
        &beam.code.instructions,
        Some(beam),
        instrument_line_breakpoints,
        true,
        arena,
    );
}

fn transform_with_options(
    instructions: &[Instr],
    beam: Option<&BeamFile>,
    instrument_line_breakpoints: bool,
    typed: bool,
) -> Vec<SpecificOp> {
    let mut arena = TransformArena::new();
    transform_into_arena(
        instructions,
        beam,
        instrument_line_breakpoints,
        typed,
        &mut arena,
    );
    arena
        .specific_ops
        .iter()
        .map(|op| materialize_op(&arena, op))
        .collect()
}

fn materialize_module(
    beam: &BeamFile,
    instrument_line_breakpoints: bool,
    typed: bool,
) -> Vec<Vec<SpecificOp>> {
    let mut arena = TransformArena::new();
    transform_into_arena(
        &beam.code.instructions,
        Some(beam),
        instrument_line_breakpoints,
        typed,
        &mut arena,
    );
    arena
        .functions
        .iter()
        .map(|range| {
            arena
                .ops(*range)
                .iter()
                .map(|op| materialize_op(&arena, op))
                .collect()
        })
        .collect()
}

fn materialize_op(arena: &TransformArena, op: &SpecificOp) -> SpecificOp {
    let args = op
        .operands()
        .iter()
        .map(|operand| materialize_operand(arena, operand))
        .collect();
    SpecificOp::from_name(op.name(), args)
}

fn materialize_operand(arena: &TransformArena, value: &SpecificOperand) -> SpecificOperand {
    match value {
        SpecificOperand::ArenaList(slice) => SpecificOperand::List(Box::new(
            arena
                .list(*slice)
                .iter()
                .map(|value| materialize_operand(arena, value))
                .collect(),
        )),
        SpecificOperand::ArenaAllocations(slice) => {
            SpecificOperand::Allocations(Box::new(arena.allocation_list(*slice).to_vec()))
        }
        SpecificOperand::Typed { reg, type_index } => SpecificOperand::Typed {
            reg: Box::new(materialize_operand(arena, reg)),
            type_index: *type_index,
        },
        _ => value.clone(),
    }
}

// Port of erts/emulator/beam/beam_load.c:load_code and
// erts/emulator/utils/beam_makeops:erts_transform_engine, OTP-29.1.1.
fn transform_into_arena(
    instructions: &[Instr],
    beam: Option<&BeamFile>,
    instrument_line_breakpoints: bool,
    typed: bool,
    arena: &mut TransformArena,
) {
    arena.reset();
    let mut head = None;
    let mut tail = None;
    for instruction in instructions {
        let node = Node {
            name: instruction.op.name(),
            args: instruction.args.iter().map(allocation_as_words).collect(),
            offset: instruction.offset,
        };
        let index = arena.allocate(node, None);
        if let Some(previous) = tail {
            arena.set_next(previous, Some(index));
        } else {
            head = Some(index);
        }
        tail = Some(index);
    }
    head = inject_function_starts(arena, head);
    add_function_end_nodes(arena, &mut head);
    let mut cursor = head;
    let mut previous = None;
    let rules = rules();
    while let Some(index) = cursor {
        let bucket = rules.get(arena.node(index).name);
        let width = bucket.map_or(1, |bucket| bucket.width);
        let mut ids = SmallVec::<[usize; 8]>::new();
        let mut scan = Some(index);
        while ids.len() < width {
            let Some(id) = scan else { break };
            ids.push(id);
            scan = arena.next(id);
        }
        let window = ids
            .iter()
            .map(|id| arena.node(*id))
            .collect::<SmallVec<[&Node; 8]>>();
        let mut replacement = None;
        for rule in bucket.into_iter().flat_map(|bucket| &bucket.rules) {
            if let Some((consumed, produced)) =
                apply_rule(rule, &window, 0, beam, instrument_line_breakpoints)
            {
                replacement = Some((consumed, produced));
                break;
            }
        }
        let Some((consumed, produced)) = replacement else {
            previous = Some(index);
            cursor = arena.next(index);
            continue;
        };
        let consumed_ids = &ids[..consumed];
        let after = arena.next(*consumed_ids.last().expect("a rule consumes an op"));
        let unchanged = consumed == produced.len()
            && window[..consumed]
                .iter()
                .zip(&produced)
                .all(|(old, new)| node_equal(old, new));
        let same_opcode = consumed == 1
            && produced.len() == 1
            && window[0].name == produced[0].name
            && window[0].args.len() == produced[0].args.len();
        drop(window);
        let stable_first = same_opcode || unchanged;
        let output_len = produced.len();
        let mut output_ids = SmallVec::<[usize; 8]>::new();
        let mut produced = produced.into_iter();
        for id in consumed_ids.iter().take(output_len) {
            let node = produced.next().expect("output count matches iterator");
            arena.slot_mut(*id).node = Some(node);
            output_ids.push(*id);
        }
        for node in produced {
            let id = arena.allocate(node, None);
            output_ids.push(id);
        }
        for id in consumed_ids.iter().skip(output_len) {
            arena.release(*id);
        }
        for pair in output_ids.windows(2) {
            arena.set_next(pair[0], Some(pair[1]));
        }
        if let Some(last) = output_ids.last() {
            arena.set_next(*last, after);
        }
        let replacement_head = output_ids.first().copied().or(after);
        if let Some(previous) = previous {
            arena.set_next(previous, replacement_head);
        } else {
            head = replacement_head;
        }
        if stable_first && !output_ids.is_empty() {
            previous = Some(output_ids[0]);
            cursor = arena.next(output_ids[0]);
        } else {
            cursor = output_ids.first().copied().or(after);
        }
    }
    collect_specific_ops(arena, head, typed);
}

// Port of erts/emulator/beam/generators.tab:230-254, OTP-29.1.1.
fn map_fields_to_elements(instruction: &Node, arena: &mut TransformArena) -> SpecificOp {
    let [fail, source, size, rest @ ..] = instruction.args.as_slice() else {
        return SpecificOp::from_name(
            instruction.name,
            instruction
                .args
                .iter()
                .map(|value| operand_in_arena(arena, value, false))
                .collect(),
        );
    };
    let keys = match rest {
        [Operand::List(keys)] => keys.as_slice(),
        keys => keys,
    };
    let Some(count) = operand_integer(size).and_then(|count| usize::try_from(count).ok()) else {
        return SpecificOp::from_name(
            instruction.name,
            instruction
                .args
                .iter()
                .map(|value| operand_in_arena(arena, value, false))
                .collect(),
        );
    };
    if keys.len() != count {
        return SpecificOp::from_name(
            instruction.name,
            instruction
                .args
                .iter()
                .map(|value| operand_in_arena(arena, value, false))
                .collect(),
        );
    }
    if keys.len() == 1 && matches!(keys[0], Operand::X(_) | Operand::Y(_)) {
        // Port of erts/emulator/beam/jit/arm/ops.tab:1188-1190 and
        // erts/emulator/beam/jit/arm/generators.tab:176-198 (one-key lookup),
        // OTP-29.1.1. The ignored destination makes this the guard `is_map_key/2` path.
        let mut args = SmallVec::<[SpecificOperand; 4]>::new();
        args.push(operand_in_arena(arena, fail, false));
        args.push(operand_in_arena(arena, source, false));
        args.push(operand_in_arena(arena, &keys[0], false));
        args.push(SpecificOperand::X(1023));
        return SpecificOp::from_name("i_get_map_element", args);
    }
    let mut args = SmallVec::<[SpecificOperand; 4]>::new();
    args.reserve(3 + count * 2);
    args.push(operand_in_arena(arena, fail, false));
    args.push(operand_in_arena(arena, source, false));
    args.push(SpecificOperand::Unsigned((count * 2) as u64));
    for key in keys {
        args.push(operand_in_arena(arena, key, false));
        args.push(SpecificOperand::X(1023));
    }
    SpecificOp::from_name("get_map_elements", args)
}

#[derive(Clone, Debug)]
struct Node {
    /// Generic or specific opcode mnemonic. Static, as in the loader's opcode table.
    name: &'static str,
    // Port of BeamOp::def_args[ERTS_BEAM_MAX_OPARGS], beam_file.h:268; generated ops with
    // more than eight operands spill into a growable buffer like BeamOp::a.
    args: SmallVec<[Operand; 8]>,
    offset: usize,
}

fn node_equal(a: &Node, b: &Node) -> bool {
    a.name == b.name
        && a.offset == b.offset
        && a.args.len() == b.args.len()
        && a.args.iter().zip(&b.args).all(|(x, y)| operand_equal(x, y))
}

#[derive(Clone, Debug)]
struct Rule {
    patterns: Vec<Pattern>,
    predicates: Vec<Predicate>,
    outputs: Vec<Output>,
    slot_names: Vec<String>,
    /// The generated match function of the rule (`MATCHERS`).
    matcher: MatchFn,
}

impl Rule {
    /// The runtime form of a parsed rule: the outputs resolved against its variable slots.
    fn from_syntax(syntax: RuleSyntax, matcher: MatchFn) -> Self {
        let outputs = syntax
            .outputs
            .into_iter()
            .map(|output| {
                let resolved = output
                    .args
                    .iter()
                    .map(
                        |token| match syntax.slot_names.iter().position(|name| name == token) {
                            Some(slot) => OutArg::Slot(slot),
                            None if token == "*" => OutArg::Nothing,
                            None => output_constant(token).map_or(OutArg::Invalid, OutArg::Const),
                        },
                    )
                    .collect();
                Output {
                    op: output.op,
                    function: output.function,
                    resolved,
                }
            })
            .collect();
        Rule {
            patterns: syntax.patterns,
            predicates: syntax.predicates,
            outputs,
            slot_names: syntax.slot_names,
            matcher,
        }
    }
}

#[derive(Clone, Debug)]
struct Output {
    op: &'static str,
    function: bool,
    /// `args` resolved against the slots of the rule, once.
    resolved: Vec<OutArg>,
}

/// An argument of a generated instruction (erts `store_var`, `store_val`, `store_rest_args`).
#[derive(Clone, Debug)]
enum OutArg {
    /// The value of a variable of the left-hand side.
    Slot(usize),
    /// A constant of the right-hand side.
    Const(Operand),
    /// `*` with no rest variable bound: the argument list gets nothing.
    Nothing,
    /// A token that is no variable and no constant: the rule cannot produce its output.
    Invalid,
}

/// The rules whose first pattern is one generic opcode (erts `gen_transform` entry of that
/// opcode), and the widest pattern among them.
struct Bucket {
    rules: Vec<Rule>,
    width: usize,
}

/// FNV-1a over the opcode name: the table is read once per instruction, and SipHash costs more
/// than the lookup is worth for a key of a dozen bytes.
#[derive(Default, Clone, Copy)]
struct OpcodeHasher(u64);

impl std::hash::Hasher for OpcodeHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        };
        for byte in bytes {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.0 = hash;
    }
}

type OpcodeMap = HashMap<&'static str, Bucket, std::hash::BuildHasherDefault<OpcodeHasher>>;

fn rules() -> &'static OpcodeMap {
    static RULES: OnceLock<OpcodeMap> = OnceLock::new();
    RULES.get_or_init(|| {
        let syntax = parse_rules(include_str!("../tab/ops.tab"));
        assert_eq!(
            syntax.len(),
            MATCHERS.len(),
            "generated matchers out of step with ops.tab"
        );
        let parsed_rules = syntax
            .into_iter()
            .zip(MATCHERS)
            .map(|(syntax, matcher)| Rule::from_syntax(syntax, matcher))
            .collect::<Vec<_>>();
        let mut buckets: OpcodeMap = HashMap::default();
        for rule in parsed_rules {
            let bucket = buckets.entry(rule.patterns[0].op).or_insert(Bucket {
                rules: Vec::new(),
                width: 1,
            });
            bucket.width = bucket.width.max(rule.patterns.len());
            bucket.rules.push(rule);
        }
        buckets
    })
}

// Port of erts/emulator/beam/beam_file.c:2493-2580 (beamcodereader_next), OTP-29.1.1.
fn inject_function_starts(arena: &mut TransformArena, head: Option<usize>) -> Option<usize> {
    let mut cursor = head;
    while let Some(index) = cursor {
        let line = arena.next(index);
        let function_info = line
            .filter(|id| arena.node(*id).name == "line")
            .map_or(line, |id| arena.next(id));
        let matches = arena.node(index).name == "label"
            && function_info.is_some_and(|id| arena.node(id).name == "func_info")
            && arena.node(index).args.len() == 1
            && line
                .is_none_or(|id| arena.node(id).name != "line" || arena.node(id).args.len() == 1)
            && function_info.is_some_and(|id| arena.node(id).args.len() == 3);
        if matches {
            let info = function_info.expect("matched func_info");
            let has_line = line.is_some_and(|id| arena.node(id).name == "line");
            let next = arena.next(info);
            let offset = arena.node(index).offset;
            let mut args = std::mem::take(&mut arena.node_mut(index).args);
            if has_line {
                args.extend(std::mem::take(&mut arena.node_mut(line.unwrap()).args));
            } else {
                args.push(Operand::Nil);
            }
            args.extend(std::mem::take(&mut arena.node_mut(info).args));
            let node = arena.node_mut(index);
            node.name = "int_func_start";
            node.args = args;
            node.offset = offset;
            arena.set_next(index, next);
            if has_line {
                arena.release(line.unwrap());
            }
            arena.release(info);
            cursor = next;
        } else {
            cursor = arena.next(index);
        }
    }
    head
}

// Port of erts/emulator/beam/beam_load.c:load_code, OTP-29.1.1.
fn add_function_end_nodes(arena: &mut TransformArena, head: &mut Option<usize>) {
    let mut previous = None;
    let mut cursor = *head;
    let mut current_function = None;
    let mut entry_label = None;
    while let Some(index) = cursor {
        let is_start = arena.node(index).name == "int_func_start";
        if is_start {
            if let (Some(function), Some(entry)) = (current_function.take(), entry_label.take()) {
                let offset = arena.node(index).offset;
                let end = arena.allocate(
                    Node {
                        name: "int_func_end",
                        args: smallvec::smallvec![function, entry],
                        offset,
                    },
                    Some(index),
                );
                if let Some(previous) = previous {
                    arena.set_next(previous, Some(end));
                } else {
                    *head = Some(end);
                }
            }
            current_function = arena.node(index).args.first().cloned();
            entry_label = None;
        } else if current_function.is_some()
            && entry_label.is_none()
            && arena.node(index).name == "label"
        {
            entry_label = arena.node(index).args.first().cloned();
        }
        previous = Some(index);
        cursor = arena.next(index);
    }
    if let (Some(function), Some(entry)) = (current_function, entry_label) {
        let offset = previous.map_or(0, |index| arena.node(index).offset);
        let end = arena.allocate(
            Node {
                name: "int_func_end",
                args: smallvec::smallvec![function, entry],
                offset,
            },
            None,
        );
        if let Some(previous) = previous {
            arena.set_next(previous, Some(end));
        } else {
            *head = Some(end);
        }
    }
}

fn import_mfa<'a>(value: &Operand, beam: &'a BeamFile) -> Option<(&'a str, &'a str, u32)> {
    let Operand::U(index) = value else {
        return None;
    };
    let import = beam.imports.get(usize::try_from(*index).ok()?)?;
    let module = beam
        .atoms
        .get(import.module_atom.checked_sub(1)? as usize)?;
    let function = beam
        .atoms
        .get(import.function_atom.checked_sub(1)? as usize)?;
    Some((module, function, import.arity))
}

fn mfa_is_bif(module: &str, function: &str, arity: u32) -> bool {
    arinsal_spec::BIFS
        .iter()
        .any(|bif| bif.module == module && bif.name == function && u32::from(bif.arity) == arity)
}

fn restriction_matches(
    restriction: &Restriction,
    value: &Operand,
    beam: Option<&BeamFile>,
) -> bool {
    let Some(beam) = beam else { return false };
    let Some((module, function, arity)) = import_mfa(value, beam) else {
        return false;
    };
    match restriction {
        Restriction::IsBif => mfa_is_bif(module, function, arity),
        // Port of erts/emulator/utils/beam_makeops:2835-2873 (is_not_bif), OTP-29.1.1:
        // erlang:apply/2,3 are special and never count as plain functions.
        Restriction::IsNotBif => {
            !mfa_is_bif(module, function, arity)
                && !(module == "erlang" && function == "apply" && matches!(arity, 2 | 3))
        }
        Restriction::Mfa {
            module: expected_module,
            function: expected_function,
            arity: expected_arity,
        } => module == expected_module && function == expected_function && arity == *expected_arity,
        Restriction::Bif {
            module: expected_module,
            function: expected_function,
            arity: expected_arity,
        } => {
            if module != expected_module || arity != *expected_arity {
                return false;
            }
            let Some(bif) = arinsal_spec::bif_lookup(module, function, arity as u8) else {
                return false;
            };
            // beam_makeops resolves `$bif:` operands through the C function name from bif.tab
            // (`'div'` is `intdiv_2`, `'/'` is `div_2`); a BIF without one uses its own name.
            match bif.c_name {
                Some(c_name) => c_name
                    .strip_suffix(&format!("_{arity}"))
                    .is_some_and(|name| name == expected_function),
                None => function == expected_function,
            }
        }
    }
}

/// An operand a rule pattern bound: the instruction's own operand when it is borrowed from the
/// code, else a copy (a rest list gathered from several operands).
enum Bound<'a> {
    Ref(&'a Operand),
    Owned(Operand),
}

impl std::ops::Deref for Bound<'_> {
    type Target = Operand;
    fn deref(&self) -> &Operand {
        match self {
            Bound::Ref(operand) => operand,
            Bound::Owned(operand) => operand,
        }
    }
}

type Bindings<'a> = smallvec::SmallVec<[(&'a str, Bound<'a>); 8]>;
type SlotVec<'a> = smallvec::SmallVec<[Option<Bound<'a>>; 8]>;

/// The match function of a rule: the generated straight-line form of its program.
type MatchFn = for<'a> fn(&'a [&'a Node], usize, Option<&BeamFile>, &mut SlotVec<'a>) -> bool;

/// Match state of the generated engine: `instr` and the argument pointer of
/// `erts_transform_engine`, one method per `TOP_*` step.
// Port of the code `beam_makeops` prints for each step (utils/beam_makeops `gen_te_instr`),
// OTP-29.1.1.
struct Frame<'a> {
    code: &'a [&'a Node],
    next: usize,
    expanded: std::borrow::Cow<'a, [Operand]>,
    borrowed: Option<&'a [Operand]>,
    ap: usize,
}

impl<'a> Frame<'a> {
    #[inline(always)]
    fn new(code: &'a [&'a Node], at: usize) -> Self {
        Frame {
            code,
            next: at,
            expanded: std::borrow::Cow::Borrowed(&[]),
            borrowed: None,
            ap: 0,
        }
    }

    /// `next_instr`: advance, the opcode must match, and the operand count fit the pattern.
    #[inline(always)]
    fn next_instr(&mut self, op: &str, fixed: usize, rest: bool) -> bool {
        let instr = &self.code[self.next];
        self.next += 1;
        if op != instr.name {
            return false;
        }
        // Most patterns match the operands as they are; only a rest list without its length
        // operand needs a rewritten copy.
        self.borrowed = Some(instr.args.as_slice());
        self.expanded = std::borrow::Cow::Borrowed(instr.args.as_slice());
        let expected = fixed + usize::from(rest);
        if expected == self.expanded.len() + 1
            && rest
            && let Some(Operand::List(items)) = self.expanded.last()
        {
            let length = Operand::U(items.len() as u64);
            let rest_index = self.expanded.len() - 1;
            self.expanded.to_mut().insert(rest_index, length);
            self.borrowed = None;
        }
        if self.expanded.len() < fixed || (!rest && self.expanded.len() != fixed) {
            return false;
        }
        self.ap = 0;
        true
    }

    /// `is_type`: the operand's type bits meet the mask; `exact_x0` accepts x(0) for `x=0`.
    #[inline(always)]
    fn is_type(&self, mask: Option<u64>, exact_x0: bool) -> bool {
        let value = &self.expanded[self.ap];
        mask.is_none_or(|mask| type_bits(value) & mask != 0)
            || (exact_x0 && register_index(value) == Some(('x', 0)))
    }

    /// `is_eq`.
    #[inline(always)]
    fn is_eq(&self, n: i64) -> bool {
        operand_integer(&self.expanded[self.ap]) == Some(n)
    }

    #[inline(always)]
    fn is_atom(&self, beam: Option<&BeamFile>, atom: &str) -> bool {
        operand_is_atom(&self.expanded[self.ap], atom, beam)
    }

    /// `is_bif`, `is_not_bif`, `is_func`.
    #[inline(always)]
    fn restriction(&self, beam: Option<&BeamFile>, restriction: &Restriction) -> bool {
        restriction_matches(restriction, &self.expanded[self.ap], beam)
    }

    /// `set_var`: bind the operand to a slot, or compare it with the value already there.
    #[inline(always)]
    fn set_var(&self, slots: &mut SlotVec<'a>, slot: usize) -> bool {
        match &slots[slot] {
            Some(previous) => operand_equal(previous, &self.expanded[self.ap]),
            None => {
                slots[slot] = Some(match self.borrowed {
                    Some(args) => Bound::Ref(&args[self.ap]),
                    None => Bound::Owned(self.expanded[self.ap].clone()),
                });
                true
            }
        }
    }

    #[inline(always)]
    fn next_arg(&mut self) {
        self.ap += 1;
    }

    /// `rest_args`: bind the remaining operands as a list.
    fn rest_args(&self, slots: &mut SlotVec<'a>, slot: Option<usize>, fixed: usize) {
        let values = if self.expanded.len() == fixed + 1 {
            match &self.expanded[fixed] {
                Operand::List(values) => (**values).clone(),
                value => vec![value.clone()],
            }
        } else {
            self.expanded[fixed..].to_vec()
        };
        // A rest variable named like an earlier one is shadowed by it, as the first binding
        // of a name wins.
        if let Some(slot) = slot
            && slots[slot].is_none()
        {
            slots[slot] = Some(Bound::Owned(Operand::List(Box::new(values))));
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/matchers.rs"));

/// The instructions one rule application generates: one or two in nearly every rule.
type Produced = smallvec::SmallVec<[Node; 8]>;

#[allow(clippy::chunks_exact_to_as_chunks)]
fn apply_rule(
    rule: &Rule,
    code: &[&Node],
    at: usize,
    beam: Option<&BeamFile>,
    instrument_line_breakpoints: bool,
) -> Option<(usize, Produced)> {
    if at + rule.patterns.len() > code.len() {
        return None;
    }
    let mut slots: SlotVec<'_> = (0..rule.slot_names.len()).map(|_| None).collect();
    if !(rule.matcher)(code, at, beam, &mut slots) {
        return None;
    }
    if !rule.predicates.is_empty() {
        let bindings: Bindings<'_> = rule
            .slot_names
            .iter()
            .zip(&slots)
            .filter_map(|(name, bound)| {
                let bound = match bound.as_ref()? {
                    Bound::Ref(operand) => Bound::Ref(operand),
                    Bound::Owned(operand) => Bound::Owned(operand.clone()),
                };
                Some((name.as_str(), bound))
            })
            .collect();
        for pred in &rule.predicates {
            if !eval_predicate(pred, &bindings, beam, instrument_line_breakpoints) {
                return None;
            }
        }
    }
    let mut produced = Produced::new();
    for output in &rule.outputs {
        let mut args = SmallVec::<[Operand; 8]>::new();
        for arg in &output.resolved {
            match arg {
                OutArg::Slot(slot) => {
                    let value: &Operand = slots[*slot].as_deref()?;
                    if !output.function {
                        if let Operand::List(rest) = value {
                            args.extend(rest.iter().cloned());
                        } else {
                            args.push(value.clone());
                        }
                    } else {
                        args.push(value.clone());
                    }
                }
                OutArg::Const(value) => args.push(value.clone()),
                OutArg::Nothing => {}
                OutArg::Invalid => return None,
            }
        }
        // Ports of OTP-29.1.1 loader generators: beam/generators.tab:87,128,176,202
        // and beam/jit/arm/generators.tab:375. These generate operations using
        // lambda metadata, map-key hashes, and normalized variable operands.
        match output.op {
            "get_utf16" => {
                if args.len() != 4 {
                    return None;
                }
                produced.push(Node {
                    name: "i_bs_get_utf16",
                    args: smallvec::smallvec![
                        args[1].clone(),
                        args[0].clone(),
                        args[2].clone(),
                        args[3].clone(),
                    ],
                    offset: code[at].offset,
                });
            }
            "skip_utf16" => {
                if args.len() != 3 {
                    return None;
                }
                produced.push(Node {
                    name: "i_bs_skip_utf16",
                    args: smallvec::smallvec![args[1].clone(), args[0].clone(), args[2].clone()],
                    offset: code[at].offset,
                });
            }
            "init_yregs_move" => {
                if args.len() != 2 {
                    return None;
                }
                let Operand::List(rest) = &args[1] else {
                    return None;
                };
                let value = rest.first()?;
                produced.push(Node {
                    name: "move",
                    args: smallvec::smallvec![Operand::Nil, value.clone()],
                    offset: code[at].offset,
                });
            }
            "select_val" => {
                if args.len() != 4 {
                    return None;
                }
                let pairs = usize::try_from(operand_integer(&args[2])?).ok()? / 2;
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args =
                    smallvec::smallvec![args[0].clone(), args[1].clone(), args[2].clone(),];
                specific_args.extend(rest.iter().cloned());
                produced.push(Node {
                    name: if pairs <= 10 {
                        "i_select_val_lins"
                    } else {
                        "i_select_val_bins"
                    },
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "select_tuple_arity" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args =
                    smallvec::smallvec![args[0].clone(), args[1].clone(), args[2].clone(),];
                specific_args.extend(rest.iter().cloned());
                produced.push(Node {
                    name: "i_select_tuple_arity",
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "jump_tab" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let min = rest.iter().step_by(2).filter_map(operand_integer).min()?;
                let max = rest.iter().step_by(2).filter_map(operand_integer).max()?;
                let table_size = usize::try_from(max.checked_sub(min)?.checked_add(1)?).ok()?;
                let mut specific_args = smallvec::smallvec![
                    args[0].clone(),
                    args[1].clone(),
                    Operand::U(min as u64),
                    Operand::U(table_size as u64),
                ];
                specific_args.extend(std::iter::repeat_n(args[1].clone(), table_size));
                for pair in rest.chunks_exact(2) {
                    let slot =
                        usize::try_from(operand_integer(&pair[0])?.checked_sub(min)?).ok()?;
                    if slot >= table_size {
                        return None;
                    }
                    specific_args[4 + slot] = pair[1].clone();
                }
                produced.push(Node {
                    name: "i_jump_on_val",
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "select_literals" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                for pair in rest.chunks_exact(2) {
                    produced.push(Node {
                        name: "is_ne_exact",
                        args: smallvec::smallvec![
                            pair[1].clone(),
                            args[0].clone(),
                            pair[0].clone()
                        ],
                        offset: code[at].offset,
                    });
                }
                produced.push(Node {
                    name: "jump",
                    args: smallvec::smallvec![args[1].clone()],
                    offset: code[at].offset,
                });
            }
            "split_values" => {
                // Port of erts/emulator/beam/generators.tab:83-128 (gen.split_values),
                // OTP-29.1.1. The integer table falls through to the literal table.
                if args.len() != 5 {
                    return None;
                }
                let Operand::List(rest) = &args[4] else {
                    return None;
                };
                let size = usize::try_from(operand_integer(&args[3])?).ok()?;
                if size < 2 || size % 2 != 0 || rest.len() != size {
                    return None;
                }
                let mut small_values = SmallVec::<[Operand; 8]>::new();
                let mut literal_values = SmallVec::<[Operand; 8]>::new();
                for pair in rest.chunks_exact(2) {
                    let values = if is_literal_integer(&pair[0]) {
                        &mut literal_values
                    } else {
                        &mut small_values
                    };
                    values.extend(pair.iter().cloned());
                }

                produced.push(Node {
                    name: "is_integer",
                    args: smallvec::smallvec![args[1].clone(), args[0].clone()],
                    offset: code[at].offset,
                });

                let small_size = small_values.len();
                let small_count = small_size / 2;
                let mut small_args = smallvec::smallvec![
                    args[0].clone(),
                    Operand::Nil,
                    Operand::U(small_size as u64),
                ];
                small_args.extend(small_values);
                produced.push(Node {
                    name: if small_count <= 10 {
                        "i_select_val_lins"
                    } else {
                        "i_select_val_bins"
                    },
                    args: small_args,
                    offset: code[at].offset,
                });

                let literal_count = literal_values.len() / 2;
                if literal_count == 0 {
                    produced.push(Node {
                        name: "i_select_val_lins",
                        args: smallvec::smallvec![args[0].clone(), args[2].clone(), Operand::U(0)],
                        offset: code[at].offset,
                    });
                } else {
                    for pair in literal_values.chunks_exact(2) {
                        produced.push(Node {
                            name: "is_ne_exact",
                            args: smallvec::smallvec![
                                pair[1].clone(),
                                args[0].clone(),
                                pair[0].clone()
                            ],
                            offset: code[at].offset,
                        });
                    }
                    produced.push(Node {
                        name: "jump",
                        args: smallvec::smallvec![args[2].clone()],
                        offset: code[at].offset,
                    });
                }
            }
            "bs_match" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args = smallvec::smallvec![args[0].clone(), args[1].clone()];
                specific_args.extend(rest.iter().cloned());
                produced.push(Node {
                    name: "i_bs_match",
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "new_small_map_lit" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args =
                    smallvec::smallvec![args[0].clone(), args[1].clone(), args[2].clone()];
                specific_args.extend(rest.iter().cloned());
                produced.push(Node {
                    name: "i_new_small_map_lit",
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "create_bin" => {
                // Port of erts/emulator/beam/jit/arm/generators.tab:441-530 (gen.create_bin),
                // OTP-29.1.1.
                if args.len() != 7 {
                    return None;
                }
                let Operand::List(segments) = &args[6] else {
                    return None;
                };
                if !segments.len().is_multiple_of(6) {
                    return None;
                }
                let atom_index = |name: &str| {
                    beam.and_then(|beam| beam.atoms.iter().position(|atom| atom == name))
                        .and_then(|position| u32::try_from(position + 1).ok())
                };
                let mut alloc = args[1].clone();
                let mut specific_args = smallvec::smallvec![
                    args[0].clone(),
                    args[1].clone(),
                    args[2].clone(),
                    args[4].clone(),
                ];
                for segment in segments.chunks_exact(6) {
                    let mut segment = segment.iter().cloned().collect::<SmallVec<[Operand; 8]>>();
                    // Translate the flags list to the BSF_* bit mask (ARM is little endian).
                    let mut flags = 0u64;
                    if let Operand::Literal(index) = &segment[3]
                        && let Some(beam) = beam
                        && let Ok(term) = beam.literal(*index)
                    {
                        let mut current = &term;
                        while let OwnedTerm::List { elems, tail } = current {
                            for elem in elems {
                                if let OwnedTerm::Atom(name) = elem
                                    && matches!(name.as_str(), "little" | "native")
                                {
                                    flags |= 2;
                                }
                            }
                            current = tail;
                        }
                    }
                    segment[3] = Operand::U(flags);
                    // Short string segments become integer segments.
                    if operand_is_atom(&segment[0], "string", beam)
                        && let Some(count) = operand_integer(&segment[5])
                        && (0..=4).contains(&count)
                        && let Some(index) = operand_integer(&segment[4])
                        && let Some(beam) = beam
                        && let Some(integer) = atom_index("integer")
                        && let Some(bytes) = usize::try_from(index)
                            .ok()
                            .and_then(|start| beam.strings.get(start..start + count as usize))
                    {
                        let value = bytes
                            .iter()
                            .fold(0i64, |acc, byte| acc << 8 | i64::from(*byte));
                        segment[0] = Operand::Atom(integer);
                        segment[2] = Operand::U(8);
                        segment[4] = Operand::Int(value);
                    }
                    specific_args.extend(segment);
                }
                if operand_is_atom(&segments[0], "private_append", beam)
                    && operand_integer(&alloc).is_some_and(|words| words != 0)
                {
                    produced.push(Node {
                        name: "test_heap",
                        args: smallvec::smallvec![alloc.clone(), args[2].clone()],
                        offset: code[at].offset,
                    });
                    alloc = Operand::U(0);
                    specific_args[1] = alloc;
                }
                produced.push(Node {
                    name: "i_bs_create_bin",
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "get_map_element" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                if rest.len() != 2 {
                    return None;
                }
                let key = rest[0].clone();
                let dst = rest[1].clone();
                if matches!(
                    key,
                    Operand::Atom(_)
                        | Operand::Int(_)
                        | Operand::U(_)
                        | Operand::Nil
                        | Operand::Literal(_)
                ) {
                    produced.push(Node {
                        name: "i_get_map_element_hash",
                        args: smallvec::smallvec![
                            args[0].clone(),
                            args[1].clone(),
                            key,
                            Operand::U(0),
                            dst
                        ],
                        offset: code[at].offset,
                    });
                } else {
                    produced.push(Node {
                        name: "i_get_map_element",
                        args: smallvec::smallvec![args[0].clone(), args[1].clone(), key, dst],
                        offset: code[at].offset,
                    });
                }
            }
            "get_map_elements" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                if matches!(args[2], Operand::U(2))
                    && rest.len() == 2
                    && matches!(rest[0], Operand::X(_) | Operand::Y(_))
                {
                    // Port of erts/emulator/beam/jit/arm/ops.tab:1188-1190 and
                    // erts/emulator/beam/jit/arm/generators.tab:176-198 (one-key lookup),
                    // OTP-29.1.1. Guard `is_map_key/2` uses a scratch destination.
                    produced.push(Node {
                        name: "i_get_map_element",
                        args: smallvec::smallvec![
                            args[0].clone(),
                            args[1].clone(),
                            rest[0].clone(),
                            rest[1].clone(),
                        ],
                        offset: code[at].offset,
                    });
                    continue;
                }
                let mut specific_args = smallvec::smallvec![
                    args[0].clone(),
                    args[1].clone(),
                    // Port of erts/emulator/beam/generators.tab:202-227 (gen.get_map_elements).
                    Operand::U(3 * (rest.len() as u64 / 2)),
                ];
                for pair in rest.chunks_exact(2) {
                    specific_args.push(pair[0].clone());
                    specific_args.push(pair[1].clone());
                    specific_args.push(Operand::U(0));
                }
                produced.push(Node {
                    name: "i_get_map_elements",
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "create_local_record" => {
                // Port of erts/emulator/beam/generators.tab:255-295 (gen.create_local_record),
                // OTP-29.1.1: the record definition literal is appended to the module's literal
                // table after the BEAM literals, one entry per record chunk entry.
                let [Operand::Atom(name), dst, live, _, Operand::List(new)] = args.as_slice()
                else {
                    return None;
                };
                let beam = beam?;
                let name = beam.atom(*name)?;
                let position = beam.records.iter().position(|record| record.name == name)?;
                let literal = u32::try_from(beam.literals.len() + position).ok()?;
                produced.push(Node {
                    name: "create_local_native_record",
                    args: smallvec::smallvec![
                        Operand::Literal(literal),
                        dst.clone(),
                        live.clone(),
                        Operand::List(new.clone()),
                    ],
                    offset: code[at].offset,
                });
            }
            "make_fun3" => {
                if args.len() != 4 {
                    return None;
                }
                let beam = beam?;
                let (Operand::U(index), Operand::U(num_free)) = (&args[0], &args[2]) else {
                    return None;
                };
                let Some(lambda) = beam
                    .lambdas
                    .iter()
                    .find(|lambda| u64::from(lambda.index) == *index)
                else {
                    produced.push(Node {
                        name: "i_lambda_error",
                        args: smallvec::smallvec![Operand::U(0)],
                        offset: code[at].offset,
                    });
                    continue;
                };
                if u64::from(lambda.num_free) != *num_free {
                    produced.push(Node {
                        name: "i_lambda_error",
                        args: smallvec::smallvec![Operand::U(0)],
                        offset: code[at].offset,
                    });
                    continue;
                }
                if lambda.num_free == 0 {
                    produced.push(Node {
                        name: "i_move",
                        // Keep zero-capture fun references distinct from BEAM literal 0.
                        // The high index range is reserved for this internal bridge.
                        args: smallvec::smallvec![
                            Operand::Literal(u32::MAX - lambda.index),
                            args[1].clone(),
                        ],
                        offset: code[at].offset,
                    });
                    continue;
                }
                let Operand::List(env) = &args[3] else {
                    return None;
                };
                let mut specific_args = args[..3]
                    .iter()
                    .cloned()
                    .collect::<SmallVec<[Operand; 8]>>();
                specific_args[2] = Operand::U(u64::from(lambda.arity - lambda.num_free));
                specific_args.push(Operand::U(env.len() as u64));
                specific_args.extend(env.iter().cloned());
                produced.push(Node {
                    name: "i_make_fun3",
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "func_end" => {
                if args.len() != 2 {
                    return None;
                }
                let beam = beam?;
                let entry_label = operand_label(&args[1])?;
                if let Some(lambda) = beam
                    .lambdas
                    .iter()
                    .find(|lambda| lambda.label == entry_label && lambda.num_free > 0)
                {
                    produced.push(Node {
                        name: "i_lambda_trampoline",
                        args: smallvec::smallvec![
                            Operand::U(u64::from(lambda.index)),
                            Operand::U(u64::from(entry_label)),
                            Operand::U(u64::from(lambda.arity)),
                            Operand::U(u64::from(lambda.num_free)),
                        ],
                        offset: code[at].offset,
                    });
                }
            }
            _ => produced.push(Node {
                name: output.op,
                args,
                offset: code[at].offset,
            }),
        }
    }
    Some((rule.patterns.len(), produced))
}

fn output_constant(token: &str) -> Option<Operand> {
    match token {
        "n" => return Some(Operand::Nil),
        "u" | "t" | "I" | "W" | "A" | "P" | "Q" | "b" | "F" | "e" | "L" | "M" | "H" => {
            return Some(Operand::U(0));
        }
        "i" => return Some(Operand::Int(0)),
        "f" | "j" | "p" => return Some(Operand::Label(0)),
        "x" => return Some(Operand::X(1023)),
        "y" => return Some(Operand::Y(0)),
        "l" => return Some(Operand::FR(0)),
        "q" => return Some(Operand::Literal(0)),
        _ => {}
    }
    let (ty, value) = token.split_once('=')?;
    match ty {
        "u" | "t" | "I" | "W" | "A" | "P" | "Q" => Some(Operand::U(value.parse().ok()?)),
        "i" => Some(Operand::Int(value.parse().ok()?)),
        "n" if value == "0" => Some(Operand::Nil),
        _ => None,
    }
}

fn eval_predicate(
    pred: &Predicate,
    bindings: &[(&str, Bound<'_>)],
    beam: Option<&BeamFile>,
    instrument_line_breakpoints: bool,
) -> bool {
    let get = |name: &str| {
        bindings
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| &**value)
    };
    match pred {
        Predicate::Equal(a, b) => get(a).zip(get(b)).is_some_and(|(x, y)| operand_equal(x, y)),
        Predicate::Distinct(a, b) => get(a)
            .zip(get(b))
            .is_some_and(|(x, y)| !operand_equal(x, y)),
        Predicate::Consecutive(a, b, xregs) => get(a).zip(get(b)).is_some_and(|(x, y)| {
            if *xregs && (!matches!(x, Operand::X(_)) || !matches!(y, Operand::X(_))) {
                return false;
            }
            // Port of predicates.tab:86-90; OTP reserves X0..X5 in its ARM64 register cache.
            if *xregs && operand_integer(x).is_none_or(|index| index < 6) {
                return false;
            }
            if std::mem::discriminant(x) != std::mem::discriminant(y) {
                return false;
            }
            operand_integer(y) == operand_integer(x).and_then(|v| v.checked_add(1))
        }),
        Predicate::Never => false,
        Predicate::Call(name, args) => {
            eval_c_predicate(name, args, bindings, beam, instrument_line_breakpoints)
        }
    }
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn eval_c_predicate(
    name: &str,
    args: &[String],
    bindings: &[(&str, Bound<'_>)],
    beam: Option<&BeamFile>,
    instrument_line_breakpoints: bool,
) -> bool {
    // Ports of erts/emulator/beam/predicates.tab:24-166, OTP-29.1.1. These inspect
    // the module's import and atom tables, so rules without module context fail closed.
    let Some(beam) = beam else { return false };
    let get = |arg: &str| {
        bindings
            .iter()
            .find(|(key, _)| *key == arg)
            .map(|(_, value)| &**value)
    };
    let integer = |arg: &str| {
        arg.parse::<i64>()
            .ok()
            .or_else(|| get(arg).and_then(operand_integer))
    };
    let imported = |arg: &str| -> Option<(&str, &str, u32)> {
        let index = match get(arg)? {
            Operand::U(index) => usize::try_from(*index).ok()?,
            _ => return None,
        };
        let import = beam.imports.get(index)?;
        let module = beam
            .atoms
            .get(import.module_atom.checked_sub(1)? as usize)?;
        let function = beam
            .atoms
            .get(import.function_atom.checked_sub(1)? as usize)?;
        Some((module, function, import.arity))
    };
    match name {
        "instrumenting_line_breakpoints" => instrument_line_breakpoints,
        "use_jump_tab" if args.len() == 3 => {
            let size = integer(&args[0]).unwrap_or_default();
            let min_size = integer(&args[2]).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            if size < 2 * min_size
                || size % 2 != 0
                || usize::try_from(size).ok() != Some(rest.len())
            {
                return false;
            }
            let mut keys = Vec::new();
            for pair in rest.chunks_exact(2) {
                let (Operand::Int(key), Operand::Label(_)) = (&pair[0], &pair[1]) else {
                    return false;
                };
                if !is_small_integer(*key) {
                    return false;
                }
                keys.push(*key);
            }
            keys.iter()
                .max()
                .zip(keys.iter().min())
                .is_some_and(|(max, min)| max.saturating_sub(*min) <= size)
        }
        "floats_or_bignums" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            size >= 2
                && size % 2 == 0
                && usize::try_from(size).ok() == Some(rest.len())
                && rest.chunks_exact(2).all(|pair| {
                    is_literal_integer(&pair[0]) && matches!(pair[1], Operand::Label(_))
                })
        }
        "fixed_size_values" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            size >= 2
                && size % 2 == 0
                && usize::try_from(size).ok() == Some(rest.len())
                && rest.chunks_exact(2).all(|pair| {
                    matches!(pair[1], Operand::Label(_))
                        && match pair[0] {
                            Operand::Atom(_) | Operand::U(_) | Operand::Nil => true,
                            Operand::Int(value) => is_small_integer(value),
                            Operand::Literal(index) => beam
                                .literal(index)
                                .is_ok_and(|term| !matches!(term, OwnedTerm::Float(_))),
                            _ => false,
                        }
                })
        }
        "mixed_types" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            // Port of erts/emulator/beam/predicates.tab (mixed_types): the keys are not all of one
            // type; one pass against the first key's type, not every pair of keys.
            size >= 2
                && size % 2 == 0
                && usize::try_from(size).ok() == Some(rest.len())
                && rest.first().is_some_and(|first| {
                    let first = operand_tag(first);
                    rest.chunks_exact(2)
                        .any(|pair| operand_tag(&pair[0]) != first)
                })
        }
        "is_heavy_bif" if args.len() == 1 => {
            imported(&args[0]).is_some_and(|(module, function, arity)| {
                arinsal_spec::bif_lookup(module, function, arity as u8)
                    .is_some_and(|bif| bif.kind == BifKind::Hbif)
            })
        }
        "is_small_map_literal_keys" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            if size < 0 || size % 2 != 0 || usize::try_from(size).ok() != Some(rest.len()) {
                return false;
            }
            let pair_count = size / 2;
            pair_count <= 32
                && (pair_count != 1
                    || matches!(
                        rest.first(),
                        Some(
                            Operand::Atom(_)
                                | Operand::Int(_)
                                | Operand::U(_)
                                | Operand::Nil
                                | Operand::Literal(_)
                        )
                    ))
        }
        "is_empty_map" if args.len() == 1 => {
            let Some(Operand::Literal(index)) = get(&args[0]) else {
                return false;
            };
            matches!(beam.literal(*index), Ok(OwnedTerm::Map(ref entries)) if entries.is_empty())
        }
        "smp_mark_target_label" | "map_key_sort" => true,
        "smp_already_locked" => false,
        "is_mfa_bif" if args.len() == 3 => {
            let atom = |arg: &str| -> Option<&str> {
                let index = match get(arg)? {
                    Operand::Atom(index) => *index,
                    _ => return None,
                };
                beam.atoms
                    .get(index.checked_sub(1)? as usize)
                    .map(String::as_str)
            };
            let arity = get(&args[2])
                .and_then(operand_integer)
                .and_then(|n| u8::try_from(n).ok());
            atom(&args[0]).zip(atom(&args[1])).zip(arity).is_some_and(
                |((module, function), arity)| {
                    arinsal_spec::BIFS.iter().any(|bif| {
                        bif.module == module && bif.name == function && bif.arity == arity
                    })
                },
            )
        }
        "never_fails" | "is_eq_exact_bif" | "is_ne_exact_bif" | "is_ge_bif" | "is_lt_bif"
        | "is_exit_bif"
            if !args.is_empty() =>
        {
            let Some((module, function, arity)) = imported(&args[0]) else {
                return false;
            };
            if module != "erlang" {
                return false;
            }
            match name {
                "is_eq_exact_bif" => function == "=:=" && arity == 2,
                "is_ne_exact_bif" => function == "=/=" && arity == 2,
                "is_ge_bif" => function == ">=" && arity == 2,
                "is_lt_bif" => function == "<" && arity == 2,
                "is_exit_bif" => matches!(
                    (function, arity),
                    ("error", 1..=3) | ("exit", 1) | ("throw", 1) | ("nif_error", 1..=2)
                ),
                "never_fails" => {
                    if function == "is_function" {
                        arity == 1
                    } else {
                        matches!(
                            function,
                            "/=" | "=/="
                                | "=="
                                | "=:="
                                | "<"
                                | "/"
                                | "=<"
                                | ">"
                                | ">="
                                | "is_atom"
                                | "is_boolean"
                                | "is_binary"
                                | "is_bitstring"
                                | "is_float"
                                | "is_integer"
                                | "is_list"
                                | "is_map"
                                | "is_number"
                                | "is_pid"
                                | "is_port"
                                | "is_reference"
                                | "is_tuple"
                        )
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn operand_tag(value: &Operand) -> u8 {
    match value {
        Operand::X(_) => 1,
        Operand::Y(_) => 2,
        Operand::FR(_) => 3,
        Operand::Label(_) => 4,
        Operand::Atom(_) => 5,
        Operand::Literal(_) | Operand::BigInt(_) => 6,
        // Port of erts/emulator/beam/beam_file.c:2132-2212 (marshal_integer), OTP-29.1.1.
        Operand::Int(value) if !is_small_integer(*value) => 6,
        Operand::Int(_) => 7,
        Operand::U(_) => 8,
        Operand::Nil => 9,
        Operand::Char(_) => 10,
        Operand::List(_) => 11,
        Operand::Alloc(_) => 12,
        _ => 13,
    }
}

// OTP converts signed BEAM integers outside SSMALL to literal-table entries while reading code.
fn is_small_integer(value: i64) -> bool {
    (-(1_i64 << 59)..(1_i64 << 59)).contains(&value)
}

fn is_literal_integer(value: &Operand) -> bool {
    matches!(value, Operand::Literal(_) | Operand::BigInt(_))
        || matches!(value, Operand::Int(value) if !is_small_integer(*value))
}

/// Letters `type_matches_one` accepts for every operand (no test is defined for them).
const ANY_OPERAND: u64 = !letters("rxyfjLHanuitIWAPQbFeMdSscqplho") & ((1 << 52) - 1);
const REGISTER_X: u64 = letters("xSds");
const REGISTER_Y: u64 = letters("ySds");
const INTEGER_TYPES: u64 = letters("utIWAPQbFeM");
const CONSTANT: u64 = letters("sc");

/// The type letters `operand` satisfies, all at once: the tag test of erts' `TOP_is_type`
/// (`beam_makeops` `is_type` mask against the operand's tag). Equal to `type_matches_one` per
/// letter, which the unit test checks.
fn type_bits(value: &Operand) -> u64 {
    ANY_OPERAND
        | match value {
            Operand::X(0) => REGISTER_X | letters("r"),
            Operand::X(_) => REGISTER_X,
            Operand::Y(_) => REGISTER_Y,
            Operand::TypedReg { reg, .. } => match register_index(reg) {
                Some(('x', 0)) => REGISTER_X | letters("r"),
                Some(('x', _)) => REGISTER_X,
                Some(_) => REGISTER_Y,
                None => letters("s"),
            },
            Operand::Int(value) => {
                INTEGER_TYPES
                    | CONSTANT
                    | if is_small_integer(*value) {
                        letters("i")
                    } else {
                        0
                    }
            }
            Operand::U(_) => INTEGER_TYPES | CONSTANT | letters("ijLH"),
            Operand::BigInt(_) => CONSTANT,
            Operand::Literal(_) => CONSTANT | letters("q"),
            Operand::Char(_) => CONSTANT | letters("ih"),
            Operand::Atom(_) => CONSTANT | letters("a"),
            Operand::Nil => CONSTANT | letters("n"),
            Operand::Label(0) => letters("jLHp"),
            Operand::Label(_) => letters("fjLH"),
            Operand::FR(_) => letters("l"),
            Operand::List(_) => letters("o"),
            Operand::Alloc(_) => 0,
        }
}

#[cfg(test)]
fn type_matches_one(ty: char, value: &Operand) -> bool {
    match ty {
        'x' => register_index(value).is_some_and(|(kind, _)| kind == 'x'),
        'r' => register_index(value).is_some_and(|(kind, index)| kind == 'x' && index == 0),
        'y' => register_index(value).is_some_and(|(kind, _)| kind == 'y'),
        'f' => matches!(value, Operand::Label(label) if *label != 0),
        'j' | 'L' | 'H' => matches!(value, Operand::Label(_) | Operand::U(_)),
        'a' => matches!(value, Operand::Atom(_)),
        'n' => matches!(value, Operand::Nil),
        // Port of erts/emulator/beam/jit/arm/ops.tab (`i` is a small integer): OTP turns an
        // integer outside SSMALL into a literal while reading the code, so it is no `i`.
        'i' => {
            matches!(value, Operand::Int(value) if is_small_integer(*value))
                || matches!(value, Operand::U(_) | Operand::Char(_))
        }
        'u' | 't' | 'I' | 'W' | 'A' | 'P' | 'Q' | 'b' | 'F' | 'e' | 'M' => {
            matches!(value, Operand::U(_) | Operand::Int(_))
        }
        'd' | 'S' => register_index(value).is_some(),
        's' => {
            matches!(
                value,
                Operand::X(_)
                    | Operand::Y(_)
                    | Operand::Int(_)
                    | Operand::U(_)
                    | Operand::BigInt(_)
                    | Operand::Char(_)
                    | Operand::Atom(_)
                    | Operand::Literal(_)
                    | Operand::Nil
            ) || matches!(value, Operand::TypedReg { .. })
        }
        'c' => matches!(
            value,
            Operand::Int(_)
                | Operand::U(_)
                | Operand::BigInt(_)
                | Operand::Char(_)
                | Operand::Atom(_)
                | Operand::Literal(_)
                | Operand::Nil
        ),
        'q' => matches!(value, Operand::Literal(_)),
        'p' => matches!(value, Operand::Label(0)),
        'l' => matches!(value, Operand::FR(_)),
        'h' => matches!(value, Operand::Char(_)),
        'o' => matches!(value, Operand::List(_)),
        _ => true,
    }
}
fn register_index(value: &Operand) -> Option<(char, u32)> {
    match value {
        Operand::X(index) => Some(('x', *index)),
        Operand::Y(index) => Some(('y', *index)),
        Operand::TypedReg { reg, .. } => register_index(reg),
        _ => None,
    }
}
fn operand_integer(value: &Operand) -> Option<i64> {
    match value {
        Operand::TypedReg { reg, .. } => operand_integer(reg),
        Operand::Int(v) => Some(*v),
        Operand::U(v) => i64::try_from(*v).ok(),
        Operand::X(v)
        | Operand::Y(v)
        | Operand::Label(v)
        | Operand::Atom(v)
        | Operand::Literal(v)
        | Operand::FR(v) => Some(i64::from(*v)),
        Operand::Char(v) => Some(i64::from(*v)),
        _ => None,
    }
}
fn operand_label(value: &Operand) -> Option<u32> {
    match value {
        Operand::Label(value) => Some(*value),
        Operand::U(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}
fn operand_is_atom(value: &Operand, expected: &str, beam: Option<&BeamFile>) -> bool {
    let (Some(beam), Operand::Atom(index)) = (beam, value) else {
        return false;
    };
    let expected = expected.strip_prefix("am_").unwrap_or(expected);
    beam.atoms
        .get(index.saturating_sub(1) as usize)
        .is_some_and(|atom| atom == expected)
}
fn operand_equal(a: &Operand, b: &Operand) -> bool {
    match (a, b) {
        (Operand::TypedReg { reg, .. }, value) | (value, Operand::TypedReg { reg, .. }) => {
            operand_equal(reg, value)
        }
        (Operand::Nil, Operand::Nil) => true,
        (Operand::X(a), Operand::X(b)) | (Operand::Y(a), Operand::Y(b)) => a == b,
        (Operand::U(a), Operand::U(b)) => a == b,
        (Operand::Int(a), Operand::Int(b)) => a == b,
        (Operand::BigInt(a), Operand::BigInt(b)) => a == b,
        (Operand::Atom(a), Operand::Atom(b))
        | (Operand::FR(a), Operand::FR(b))
        | (Operand::Label(a), Operand::Label(b))
        | (Operand::Char(a), Operand::Char(b))
        | (Operand::Literal(a), Operand::Literal(b)) => a == b,
        (Operand::List(a), Operand::List(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| operand_equal(x, y))
        }
        (Operand::Alloc(a), Operand::Alloc(b)) => a
            .iter()
            .map(|allocation| (allocation.kind, allocation.count))
            .eq(b
                .iter()
                .map(|allocation| (allocation.kind, allocation.count))),
        _ => false,
    }
}

/// Sums an allocation list into heap words, as the loader does when it reads the operand.
// Port of erts/emulator/beam/beam_file.c:2234-2280 (marshal_allocation_list), OTP-29.1.1:
// floats take FLOAT_SIZE_OBJECT (2) words each and funs ERL_FUN_SIZE (2) words each.
fn allocation_as_words(value: &Operand) -> Operand {
    let Operand::Alloc(items) = value else {
        return value.clone();
    };
    let words = items.iter().fold(0_u64, |total, item| {
        total.saturating_add(match item.kind {
            arinsal_beam::AllocKind::Words => item.count,
            arinsal_beam::AllocKind::Floats | arinsal_beam::AllocKind::Funs => {
                item.count.saturating_mul(2)
            }
        })
    });
    Operand::U(words)
}

// Port of erts/emulator/beam/beam_load.c:load_code, OTP-29.1.1.
fn collect_specific_ops(arena: &mut TransformArena, mut cursor: Option<usize>, typed: bool) {
    let mut function_start = 0;
    while let Some(index) = cursor {
        let next = arena.next(index);
        let node = arena.slot_mut(index).node.take().expect("live GenOp node");
        if node.name == "i_func_label" && arena.specific_ops.len() != function_start {
            arena.functions.push(FunctionOps {
                start: function_start,
                len: arena.specific_ops.len() - function_start,
            });
            function_start = arena.specific_ops.len();
        }
        let op = if node.name == "has_map_fields" {
            map_fields_to_elements(&node, arena)
        } else {
            let use_types = typed && TYPED_OPS.contains(&node.name);
            let args = node
                .args
                .iter()
                .map(|operand| operand_in_arena(arena, operand, use_types))
                .collect::<SmallVec<[SpecificOperand; 4]>>();
            SpecificOp::from_name(node.name, args)
        };
        arena.specific_ops.push(op);
        arena.release(index);
        cursor = next;
    }
    if arena.specific_ops.len() != function_start {
        arena.functions.push(FunctionOps {
            start: function_start,
            len: arena.specific_ops.len() - function_start,
        });
    }
}

// Port of erts/emulator/beam/jit/asm_load.c:beam_load_emit_op, OTP-29.1.1.
fn operand_in_arena(
    arena: &mut TransformArena,
    value: &Operand,
    keep_type: bool,
) -> SpecificOperand {
    match value {
        Operand::TypedReg { reg, type_index } if keep_type && *type_index != 0 => {
            SpecificOperand::Typed {
                reg: Box::new(operand_in_arena(arena, reg, false)),
                type_index: *type_index,
            }
        }
        Operand::List(values) => {
            let start = arena.lists.len();
            arena
                .lists
                .resize(start + values.len(), SpecificOperand::Other);
            for (index, item) in values.iter().enumerate() {
                let item = operand_in_arena(arena, item, false);
                arena.lists[start + index] = item;
            }
            SpecificOperand::ArenaList(ArenaSlice::from_range(start, values.len()))
        }
        Operand::Alloc(values) => {
            let start = arena.allocations.len();
            arena.allocations.extend(values.iter().map(|allocation| {
                let kind = match allocation.kind {
                    arinsal_beam::AllocKind::Words => 0,
                    arinsal_beam::AllocKind::Floats => 1,
                    arinsal_beam::AllocKind::Funs => 2,
                };
                (kind, allocation.count)
            }));
            SpecificOperand::ArenaAllocations(ArenaSlice::from_range(start, values.len()))
        }
        Operand::X(value) => SpecificOperand::X(*value),
        Operand::Y(value) => SpecificOperand::Y(*value),
        Operand::FR(value) => SpecificOperand::FloatRegister(*value),
        Operand::Label(value) => SpecificOperand::Label(*value),
        Operand::Atom(value) => SpecificOperand::Atom(*value),
        Operand::Literal(value) => SpecificOperand::Literal(*value),
        Operand::Int(value) => SpecificOperand::SmallInt(*value),
        Operand::U(value) => i64::try_from(*value)
            .map_or(SpecificOperand::Unsigned(*value), SpecificOperand::SmallInt),
        Operand::Nil => SpecificOperand::Nil,
        Operand::Char(value) => SpecificOperand::SmallInt(i64::from(*value)),
        Operand::BigInt(value) => SpecificOperand::BigInt(Box::new(value.to_string())),
        Operand::TypedReg { reg, .. } => operand_in_arena(arena, reg, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_spec::Opcode;
    use similar_asserts::assert_eq;

    #[test]
    fn operand_enums_fit_two_machine_words() {
        assert!(std::mem::size_of::<Operand>() <= 16);
        assert!(std::mem::size_of::<SpecificOperand>() <= 16);
    }

    #[test]
    fn function_start_without_line_injects_nil_location() {
        let mut arena = TransformArena::new();
        let first = arena.allocate(
            Node {
                name: "label",
                args: vec![Operand::U(1)].into(),
                offset: 0,
            },
            None,
        );
        let second = arena.allocate(
            Node {
                name: "func_info",
                args: vec![Operand::Atom(1), Operand::Atom(2), Operand::U(0)].into(),
                offset: 2,
            },
            None,
        );
        arena.set_next(first, Some(second));
        let output = inject_function_starts(&mut arena, Some(first)).unwrap();

        assert_eq!(arena.node(output).name, "int_func_start");
        assert!(matches!(
            arena.node(output).args.as_slice(),
            [
                Operand::U(1),
                Operand::Nil,
                Operand::Atom(1),
                Operand::Atom(2),
                Operand::U(0)
            ]
        ));
    }

    #[test]
    fn move_rewrites_to_i_move_without_losing_register_kinds() {
        let input = [Instr {
            op: Opcode::Move,
            args: vec![Operand::Y(3), Operand::X(1)],
            offset: 0,
        }];
        assert!(matches!(
            transform_function(&input).as_slice(),
            [SpecificOp::OpIMove(args)]
                if args.as_slice() == [SpecificOperand::Y(3), SpecificOperand::X(1)]
        ));
    }

    #[test]
    fn has_map_fields_rewrites_to_get_map_elements_with_ignored_destinations() {
        let input = [Instr {
            op: Opcode::HasMapFields,
            args: vec![
                Operand::Label(9),
                Operand::X(0),
                Operand::U(2),
                Operand::List(Box::new(vec![Operand::Atom(4), Operand::Literal(7)])),
            ],
            offset: 0,
        }];
        let output = transform_function(&input);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].name(), "get_map_elements");
        assert_eq!(
            output[0].operands(),
            &[
                SpecificOperand::Label(9),
                SpecificOperand::X(0),
                SpecificOperand::Unsigned(4),
                SpecificOperand::Atom(4),
                SpecificOperand::X(1023),
                SpecificOperand::Literal(7),
                SpecificOperand::X(1023),
            ]
        );
    }

    #[test]
    fn one_key_map_guard_rewrites_to_shared_single_element_lookup() {
        let input = [Instr {
            op: Opcode::HasMapFields,
            args: vec![
                Operand::Label(9),
                Operand::X(0),
                Operand::U(1),
                Operand::List(Box::new(vec![Operand::X(1)])),
            ],
            offset: 0,
        }];
        let output = transform_function(&input);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].name(), "i_get_map_element");
        assert_eq!(
            output[0].operands(),
            &[
                SpecificOperand::Label(9),
                SpecificOperand::X(0),
                SpecificOperand::X(1),
                SpecificOperand::X(1023),
            ]
        );
    }

    #[test]
    fn adjacent_move_trim_uses_a_multi_instruction_rule() {
        let input = [
            Instr {
                op: Opcode::Move,
                args: vec![Operand::X(2), Operand::Y(1)],
                offset: 0,
            },
            Instr {
                op: Opcode::Trim,
                args: vec![Operand::U(3), Operand::U(1)],
                offset: 2,
            },
        ];
        let result = transform_function(&input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name(), "move_trim");
        assert!(
            matches!(&result[0], SpecificOp::OpMoveTrim(args) if args.as_slice() == [
                SpecificOperand::X(2), SpecificOperand::Y(1), SpecificOperand::SmallInt(3),
            ])
        );
    }

    #[test]
    fn three_tuple_element_loads_fetch_the_tuple_pointer_once() {
        let element = |position: u64, destination: Operand| Instr {
            op: Opcode::GetTupleElement,
            args: vec![Operand::X(2), Operand::U(position), destination],
            offset: 0,
        };
        let input = [
            element(0, Operand::X(0)),
            element(1, Operand::X(3)),
            element(2, Operand::Y(0)),
        ];
        let result = transform_function(&input);
        let names = result.iter().map(SpecificOp::name).collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "load_tuple_ptr",
                "get_two_tuple_elements",
                "i_get_tuple_element"
            ]
        );
    }

    #[test]
    fn copied_otp_tables_contain_otp29_specific_operations() {
        assert!(
            DIRECT_RULES
                .iter()
                .any(|rule| rule.input == "move" && rule.output == "i_move")
        );
        assert!(
            SpecificOp::from_name("i_bs_get_utf8", SmallVec::new())
                != SpecificOp::Unknown {
                    name: "i_bs_get_utf8".to_owned(),
                    operands: SmallVec::new()
                }
        );
    }

    /// Port of erts/emulator/beam/jit/arm/ops.tab:687-714, OTP-29.1.1.
    /// A plain `bif` import becomes `call_light_bif`. An `hbif` stays `i_call_ext`.
    /// An exit BIF's tail call is `call_light_bif` with no following return.
    #[test]
    fn plain_bif_call_ext_becomes_call_light_bif() {
        let source = concat!(
            "-module(light_bif_probe).\n",
            "-export([plain/1, heavy/1, tail_plain/0, tail_exit/0, not_bif/0]).\n",
            "plain(X) -> erlang:whereis(X), erlang:monotonic_time(), erlang:registered(), erlang:register(a, self()).\n",
            "heavy(P) -> erlang:process_info(P).\n",
            "tail_plain() -> erlang:whereis(a).\n",
            "tail_exit() -> erlang:error(x).\n",
            "not_bif() -> light_bif_probe_other:go().\n",
        );
        let dir = std::env::temp_dir().join(format!("light_bif_probe_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let erl = dir.join("light_bif_probe.erl");
        std::fs::write(&erl, source).unwrap();
        let compiled = std::process::Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(&erl)
            .output()
            .expect("erlc");
        assert!(
            compiled.status.success(),
            "erlc: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let bytes = std::fs::read(dir.join("light_bif_probe.beam")).unwrap();
        let beam = arinsal_beam::parse(&bytes).unwrap();
        let functions = transform_module(&beam);
        let calls = |module: &str, function: &str, arity: u32| -> Vec<String> {
            let index = beam
                .imports
                .iter()
                .position(|import| {
                    beam.atoms
                        .get(import.module_atom as usize - 1)
                        .is_some_and(|name| name == module)
                        && beam
                            .atoms
                            .get(import.function_atom as usize - 1)
                            .is_some_and(|name| name == function)
                        && import.arity == arity
                })
                .unwrap_or_else(|| panic!("missing import {module}:{function}/{arity}"))
                as u64;
            functions
                .iter()
                .flatten()
                .filter(|op| {
                    op.operands().iter().any(|operand| {
                        matches!(operand, SpecificOperand::SmallInt(value) if *value == index as i64)
                            || matches!(operand, SpecificOperand::Unsigned(value) if *value == index)
                            || matches!(operand, SpecificOperand::Export(value) if u64::from(*value) == index)
                    })
                })
                .map(|op| op.name().to_owned())
                .collect()
        };
        for (module, function, arity) in [
            ("erlang", "whereis", 1),
            ("erlang", "monotonic_time", 0),
            ("erlang", "register", 2),
        ] {
            let names = calls(module, function, arity);
            assert!(
                names.iter().any(|name| name == "call_light_bif"),
                "{module}:{function}/{arity} -> {names:?}"
            );
            assert!(
                !names.iter().any(|name| name.starts_with("i_call_ext")),
                "{module}:{function}/{arity} stayed on the export trampoline: {names:?}"
            );
        }
        let heavy = calls("erlang", "process_info", 1);
        assert!(
            heavy.iter().any(|name| name.starts_with("i_call_ext")),
            "hbif process_info/1 -> {heavy:?}"
        );
        assert!(
            !heavy.iter().any(|name| name == "call_light_bif"),
            "hbif process_info/1 became call_light_bif: {heavy:?}"
        );
        let exit = calls("erlang", "error", 1);
        assert!(
            exit.iter().any(|name| name == "call_light_bif"),
            "exit bif error/1 -> {exit:?}"
        );
        let other = calls("light_bif_probe_other", "go", 0);
        assert!(
            other.iter().any(|name| name.starts_with("i_call_ext")),
            "non-bif -> {other:?}"
        );
        assert!(
            !other.iter().any(|name| name == "call_light_bif"),
            "non-bif became call_light_bif: {other:?}"
        );
    }
}

#[cfg(test)]
mod type_bits_tests {
    use super::*;

    #[test]
    fn type_bits_equal_the_per_letter_tests() {
        let register = |index| Box::new(Operand::X(index));
        let samples = [
            Operand::X(0),
            Operand::X(3),
            Operand::Y(0),
            Operand::Y(7),
            Operand::FR(1),
            Operand::Label(0),
            Operand::Label(9),
            Operand::Char(65),
            Operand::List(Box::new(vec![Operand::Nil])),
            Operand::Alloc(Box::default()),
            Operand::Literal(2),
            Operand::Atom(4),
            Operand::Nil,
            Operand::U(0),
            Operand::U(300),
            Operand::Int(-1),
            Operand::Int(1 << 58),
            Operand::Int(1 << 59),
            Operand::Int(i64::MIN),
            Operand::BigInt(Box::default()),
            Operand::TypedReg {
                reg: register(0),
                type_index: 1,
            },
            Operand::TypedReg {
                reg: register(2),
                type_index: 1,
            },
            Operand::TypedReg {
                reg: Box::new(Operand::Y(1)),
                type_index: 1,
            },
            Operand::TypedReg {
                reg: Box::new(Operand::Nil),
                type_index: 1,
            },
        ];
        for value in &samples {
            let bits = type_bits(value);
            for letter in (b'a'..=b'z').chain(b'A'..=b'Z') {
                assert_eq!(
                    bits & type_bit(letter) != 0,
                    type_matches_one(letter as char, value),
                    "{value:?} / {}",
                    letter as char
                );
            }
        }
    }
}
