//! `BeamOpArg`, `BeamOp` and the `BeamOpAllocator` of erts/emulator/beam/beam_file.h, and the code
//! reader of beam_file.c (`beamcodereader_read_next`, `beamcodereader_next`,
//! `synthesize_func_end`), OTP-29.1.1.
//!
//! The reader differs from erts' in its input only: erts decodes the operand bytes of the Code
//! chunk, while `arinsal_beam::parse` has already decoded the whole chunk into [`Instr`]s for
//! every consumer of the module, so each instruction is converted here from its decoded operands.

use crate::erts_tables::{
    GEN_OPC, GENOP_INT_FUNC_END_2, GENOP_INT_FUNC_START_5, MAX_GENERIC_OPCODE,
};
use crate::erts_tables::{GENOP_FUNC_INFO_3, GENOP_INT_CODE_END_0, GENOP_LABEL_1, GENOP_LINE_1};
use arinsal_beam::{AllocKind, BeamFile, Instr, Operand};
use arinsal_term::Atom;

/// `ERTS_BEAM_MAX_OPARGS`: the arguments `def_args` holds without a separate allocation.
pub(crate) const ERTS_BEAM_MAX_OPARGS: usize = 8;

// The `TAG_*` of beam_opcodes.h: the compiler's operand types, then the loader's.
pub(crate) const TAG_U: u8 = 0;
pub(crate) const TAG_I: u8 = 1;
pub(crate) const TAG_A: u8 = 2;
pub(crate) const TAG_X: u8 = 3;
pub(crate) const TAG_Y: u8 = 4;
pub(crate) const TAG_F: u8 = 5;
pub(crate) const TAG_H: u8 = 6;
pub(crate) const TAG_Z: u8 = 7;
pub(crate) const TAG_N: u8 = 8;
pub(crate) const TAG_P: u8 = 9;
pub(crate) const TAG_R: u8 = 10;
pub(crate) const TAG_V: u8 = 11;
pub(crate) const TAG_L: u8 = 12;
pub(crate) const TAG_Q: u8 = 13;
pub(crate) const TAG_O: u8 = 14;

/// `tag_to_letter[]` of beam_opcodes.c.
pub(crate) const TAG_TO_LETTER: [char; 15] = [
    'u', 'i', 'a', 'x', 'y', 'f', 'h', 'z', 'n', 'p', 'r', 'v', 'l', 'q', 'o',
];

/// `NIL` as an operand value (`TAG_n` carries it).
const NIL: u64 = 0;

/// `MAX_REG`: the number of X and Y registers.
pub(crate) const MAX_REG: u64 = 1024;
/// `REG_MASK` is below `1 << 10`: the type table index of a typed register is stored above it.
pub(crate) const REG_TYPE_SHIFT: u32 = 10;

/// `BeamOpArg`: an operand with its tag. An atom operand holds its global atom index, as erts
/// holds the atom term.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BeamOpArg {
    /// `TAG_xyz`.
    pub ty: u8,
    pub val: u64,
}

impl BeamOpArg {
    pub(crate) const fn new(ty: u8, val: u64) -> Self {
        Self { ty, val }
    }
}

/// An index into the blocks of a [`BeamOpAllocator`]: the `BeamOp *` of erts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpId(u32);

/// `BeamOp`.
#[derive(Clone, Debug)]
pub(crate) struct BeamOp {
    /// Opcode: the number of a generic instruction (`genop_*`).
    pub op: i32,
    /// Number of arguments.
    pub arity: usize,
    /// Default buffer for arguments.
    def_args: [BeamOpArg; ERTS_BEAM_MAX_OPARGS],
    /// The separately allocated arguments when more than `ERTS_BEAM_MAX_OPARGS` (`a` pointing
    /// away from `def_args`).
    spilled: Option<Box<[BeamOpArg]>>,
    pub next: Option<OpId>,
}

impl BeamOp {
    fn empty() -> Self {
        Self {
            op: 0,
            arity: 0,
            def_args: [BeamOpArg::default(); ERTS_BEAM_MAX_OPARGS],
            spilled: None,
            next: None,
        }
    }

    /// `a[0..arity]`.
    pub(crate) fn args(&self) -> &[BeamOpArg] {
        match &self.spilled {
            Some(args) => &args[..self.arity],
            None => &self.def_args[..self.arity],
        }
    }

    /// `a[index]`.
    pub(crate) fn a(&self, index: usize) -> BeamOpArg {
        match &self.spilled {
            Some(args) => args[index],
            None => self.def_args[index],
        }
    }

    /// `a[index] = value`.
    pub(crate) fn set_a(&mut self, index: usize, value: BeamOpArg) {
        match &mut self.spilled {
            Some(args) => args[index] = value,
            None => self.def_args[index] = value,
        }
    }

    /// `op->a == op->def_args`.
    pub(crate) fn uses_def_args(&self) -> bool {
        self.spilled.is_none()
    }

    /// Gives the operation room for `arity` arguments in a separate allocation, keeping the
    /// first `keep` ones (`erts_alloc` + `sys_memcpy` of beamcodereader_read_next and the
    /// `store_rest_args` step of the transform engine).
    pub(crate) fn spill(&mut self, arity: usize, keep: usize) {
        let mut args = vec![BeamOpArg::default(); arity].into_boxed_slice();
        for index in 0..keep {
            args[index] = self.a(index);
        }
        self.spilled = Some(args);
        self.arity = arity;
    }
}

/// `BeamOpAllocator`: blocks of 32 operations and a free list, like `BeamOpBlock`.
#[derive(Default)]
pub(crate) struct BeamOpAllocator {
    blocks: Vec<Box<[BeamOp; 32]>>,
    free: Option<OpId>,
}

impl BeamOpAllocator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `beamopallocator_expand__`.
    fn expand(&mut self) {
        let first = self.blocks.len() * 32;
        let mut block: Box<[BeamOp; 32]> = Box::new(std::array::from_fn(|_| BeamOp::empty()));
        for index in 0..31 {
            block[index].next = Some(OpId((first + index + 1) as u32));
        }
        block[31].next = None;
        self.blocks.push(block);
        self.free = Some(OpId(first as u32));
    }

    /// `beamopallocator_new_op`: the operation's arguments are its `def_args`.
    pub(crate) fn new_op(&mut self) -> OpId {
        if self.free.is_none() {
            self.expand();
        }
        let id = self.free.expect("expansion supplies free operations");
        let op = self.op_mut(id);
        let next = op.next.take();
        op.spilled = None;
        op.op = 0;
        op.arity = 0;
        self.free = next;
        id
    }

    /// `beamopallocator_free_op`.
    pub(crate) fn free_op(&mut self, id: OpId) {
        let free = self.free;
        let op = self.op_mut(id);
        op.spilled = None;
        op.next = free;
        self.free = Some(id);
    }

    pub(crate) fn op(&self, id: OpId) -> &BeamOp {
        &self.blocks[id.0 as usize / 32][id.0 as usize % 32]
    }

    pub(crate) fn op_mut(&mut self, id: OpId) -> &mut BeamOp {
        &mut self.blocks[id.0 as usize / 32][id.0 as usize % 32]
    }
}

/// Why an instruction could not be read: the `LoadAssert` and `LoadError` of beam_file.c.
#[derive(Debug)]
pub(crate) struct ReadError(pub &'static str);

/// `BeamCodeReader`.
pub(crate) struct BeamCodeReader<'a> {
    file: &'a BeamFile,
    instrs: &'a [Instr],
    position: usize,
    /// The global atoms of the module's atom table: `atoms->entries[]`.
    atoms: Vec<Atom>,
    pending: Option<OpId>,
    current_func_label: BeamOpArg,
    current_entry_label: BeamOpArg,
    first: bool,
    /// Integers too large for a word, which `marshal_integer` adds to the literal table
    /// (`beamfile_add_literal`): `TAG_q` with `beam.literals.len() + index`.
    pub(crate) bignum_literals: Vec<String>,
    /// The number of literals before `bignum_literals` (`beam.literals.count`, which grows with
    /// every literal the loader adds).
    pub(crate) literal_base: usize,
}

impl<'a> BeamCodeReader<'a> {
    /// `beamfile_get_code`.
    pub(crate) fn new(file: &'a BeamFile) -> Self {
        let atoms = file
            .atoms
            .iter()
            .map(|name| {
                arinsal_term::global_atoms()
                    .intern(name)
                    .expect("an atom of a module being loaded")
            })
            .collect();
        Self::with_atoms(file, atoms)
    }

    /// `beamfile_get_code` with the module's atoms already in the table.
    pub(crate) fn with_atoms(file: &'a BeamFile, atoms: Vec<Atom>) -> Self {
        Self {
            file,
            instrs: &file.code.instructions,
            position: 0,
            atoms,
            pending: None,
            current_func_label: BeamOpArg::default(),
            current_entry_label: BeamOpArg::default(),
            first: true,
            bignum_literals: Vec::new(),
            literal_base: file.literals.len(),
        }
    }

    /// `beamcodereader_read_next`: the instruction at the reader's position as a `BeamOp`.
    fn read_next(&mut self, alloc: &mut BeamOpAllocator) -> Result<OpId, ReadError> {
        let instr = self
            .instrs
            .get(self.position)
            .ok_or(ReadError("invalid opcode"))?;
        self.position += 1;
        let opcode = instr.op as usize;
        // LoadAssert(opcode > 0 && opcode <= MAX_GENERIC_OPCODE);
        if opcode == 0 || opcode > MAX_GENERIC_OPCODE {
            return Err(ReadError("invalid opcode"));
        }
        let arity = GEN_OPC[opcode].arity;
        debug_assert!(arity <= ERTS_BEAM_MAX_OPARGS);
        let id = alloc.new_op();
        {
            let op = alloc.op_mut(id);
            op.op = opcode as i32;
            op.arity = arity;
        }
        let mut arity = arity;
        let mut i = 0;
        for operand in &instr.args {
            let mut raw = self.read_operand(operand)?;
            if let Operand::List(items) = operand {
                // Lists may only be the last argument.
                if i + 1 != arity {
                    return Err(ReadError("a list that is not the last operand"));
                }
                // The count of the list is the argument; its elements follow.
                arity += items.len();
                let op = alloc.op_mut(id);
                op.arity = arity;
                // Expand the argument array if necessary.
                if arity > ERTS_BEAM_MAX_OPARGS {
                    debug_assert!(op.uses_def_args());
                    op.spill(arity, i);
                }
                raw = BeamOpArg::new(TAG_U, items.len() as u64);
                alloc.op_mut(id).set_a(i, raw);
                i += 1;
                for item in items.iter() {
                    let element = self.read_operand(item)?;
                    alloc.op_mut(id).set_a(i, element);
                    i += 1;
                }
                continue;
            }
            alloc.op_mut(id).set_a(i, raw);
            i += 1;
        }
        if i != arity {
            return Err(ReadError("wrong operand count"));
        }
        Ok(id)
    }

    /// The tagged-number switch of `beamcodereader_read_next` for one operand.
    fn read_operand(&mut self, operand: &Operand) -> Result<BeamOpArg, ReadError> {
        Ok(match operand {
            Operand::U(value) => BeamOpArg::new(TAG_U, *value),
            // `marshal_integer`: a small integer stays `TAG_i`.
            Operand::Int(value) => BeamOpArg::new(TAG_I, *value as u64),
            // `marshal_integer`: a bignum becomes a literal.
            Operand::BigInt(value) => {
                let index = self.literal_base + self.bignum_literals.len();
                self.bignum_literals.push(value.to_string());
                BeamOpArg::new(TAG_Q, index as u64)
            }
            Operand::Atom(0) => BeamOpArg::new(TAG_N, NIL),
            Operand::Atom(index) => {
                let atom = *self
                    .atoms
                    .get(*index as usize - 1)
                    .ok_or(ReadError("atom index out of range"))?;
                BeamOpArg::new(TAG_A, u64::from(atom.0))
            }
            Operand::Nil => BeamOpArg::new(TAG_N, NIL),
            Operand::Label(0) => BeamOpArg::new(TAG_P, 0),
            Operand::Label(label) => BeamOpArg::new(TAG_F, u64::from(*label)),
            Operand::X(register) | Operand::Y(register) => {
                if u64::from(*register) >= MAX_REG {
                    return Err(ReadError("register out of range"));
                }
                let tag = if matches!(operand, Operand::X(_)) {
                    TAG_X
                } else {
                    TAG_Y
                };
                BeamOpArg::new(tag, u64::from(*register))
            }
            // The float register of the extended tag 2.
            Operand::FR(register) => {
                if u64::from(*register) >= MAX_REG {
                    return Err(ReadError("register out of range"));
                }
                BeamOpArg::new(TAG_L, u64::from(*register))
            }
            // The allocation list of the extended tag 3: its size in words.
            Operand::Alloc(items) => {
                let words = items.iter().fold(0_u64, |total, item| {
                    total.saturating_add(match item.kind {
                        AllocKind::Words => item.count,
                        AllocKind::Floats | AllocKind::Funs => item.count.saturating_mul(2),
                    })
                });
                BeamOpArg::new(TAG_U, words)
            }
            Operand::Literal(index) => BeamOpArg::new(TAG_Q, u64::from(*index)),
            // The register with type hint of the extended tag 5.
            Operand::TypedReg { reg, type_index } => {
                let mut register = self.read_operand(reg)?;
                if register.ty != TAG_X && register.ty != TAG_Y {
                    return Err(ReadError("a type hint on a non-register"));
                }
                // A module whose type table was stripped treats these as ordinary registers.
                if self.file.types.is_some() {
                    register.val |= u64::from(*type_index) << REG_TYPE_SHIFT;
                }
                register
            }
            // The compiler never emits a character operand; erts rejects the tag.
            Operand::Char(_) => return Err(ReadError("Unrecognized tag")),
            // The list is handled by the caller.
            Operand::List(_) => BeamOpArg::new(TAG_U, 0),
        })
    }

    /// `synthesize_func_end`.
    fn synthesize_func_end(&mut self, alloc: &mut BeamOpAllocator) {
        let func_end = alloc.new_op();
        let pending = self.pending;
        let (func_label, entry_label) = (self.current_func_label, self.current_entry_label);
        let op = alloc.op_mut(func_end);
        op.op = GENOP_INT_FUNC_END_2;
        op.arity = 2;
        debug_assert_eq!(func_label.ty, TAG_U);
        op.set_a(0, BeamOpArg::new(TAG_F, func_label.val));
        debug_assert_eq!(entry_label.ty, TAG_U);
        op.set_a(1, BeamOpArg::new(TAG_F, entry_label.val));
        op.next = pending;
        self.pending = Some(func_end);
    }

    /// `beamcodereader_next`: the next instruction of the module, with `int_func_start/5` and
    /// `int_func_end/2` synthesized at function boundaries.
    pub(crate) fn next(&mut self, alloc: &mut BeamOpAllocator) -> Result<OpId, ReadError> {
        loop {
            if let Some(id) = self.pending {
                self.pending = alloc.op_mut(id).next;
                return Ok(id);
            }
            let mut op = self.read_next(alloc)?;
            match alloc.op(op).op {
                GENOP_LABEL_1 => {
                    // To simplify the rest of the loading process, attempt to synthesize
                    // int_func_start/5 and int_func_end/2 instructions.
                    //
                    // We look for the following instruction sequence to find function
                    // boundaries: label Lbl | line Loc | func_info M F A. (Where the line
                    // instruction is optional.)
                    //
                    // So far we have seen a label/0 instruction. Put this instruction into the
                    // pending queue and decode the next instruction.
                    self.pending = Some(op);
                    let next = self.read_next(alloc)?;
                    alloc.op_mut(op).next = Some(next);
                    op = next;

                    // If the current instruction is a line instruction, append it to the
                    // pending queue and decode the following instruction.
                    if alloc.op(op).op == GENOP_LINE_1 {
                        let next = self.read_next(alloc)?;
                        alloc.op_mut(op).next = Some(next);
                        op = next;
                    }

                    // The code must not end abruptly after a label.
                    if alloc.op(op).op == GENOP_INT_CODE_END_0 {
                        return Err(ReadError("code ends after a label"));
                    }

                    // If the current instruction is a func_info instruction, we have found a
                    // function boundary.
                    if alloc.op(op).op != GENOP_FUNC_INFO_3 {
                        alloc.op_mut(op).next = None;
                    } else {
                        // The func_info/3 instruction must be followed by its entry label.
                        let entry_op = self.read_next(alloc)?;
                        if alloc.op(entry_op).op != GENOP_LABEL_1 {
                            return Err(ReadError("func_info without an entry label"));
                        }
                        let entry_label = alloc.op(entry_op).a(0);
                        if entry_label.ty != TAG_U {
                            return Err(ReadError("bad entry label"));
                        }
                        alloc.op_mut(entry_op).next = None;

                        // Prepare to walk through the queue of pending instructions.
                        let mut op = self.pending.expect("pending label");

                        // Pick up the label from the first label/1 instruction.
                        let func_label = alloc.op(op).a(0);
                        if func_label.ty != TAG_U {
                            return Err(ReadError("bad function label"));
                        }

                        let next = alloc.op(op).next;
                        alloc.free_op(op);
                        op = next.expect("line or func_info after the label");

                        // Allocate the int_func_start/5 function.
                        let func_start = alloc.new_op();
                        {
                            let start = alloc.op_mut(func_start);
                            start.op = GENOP_INT_FUNC_START_5;
                            start.arity = 5;
                            start.set_a(0, func_label);
                            // If the current instruction is a line/1 instruction, pick up the
                            // location from that instruction. Otherwise use NIL.
                            start.set_a(1, BeamOpArg::new(TAG_N, NIL));
                        }
                        if alloc.op(op).op == GENOP_LINE_1 {
                            let location = alloc.op(op).a(0);
                            alloc.op_mut(func_start).set_a(1, location);
                            let next = alloc.op(op).next;
                            alloc.free_op(op);
                            op = next.expect("func_info after the line");
                        }

                        // Pick up the MFA from the func_info/3 instruction.
                        debug_assert_eq!(alloc.op(op).op, GENOP_FUNC_INFO_3);
                        let (m, f, a) = {
                            let info = alloc.op(op);
                            (info.a(0), info.a(1), info.a(2))
                        };
                        {
                            let start = alloc.op_mut(func_start);
                            start.set_a(2, m);
                            start.set_a(3, f);
                            start.set_a(4, a);
                        }
                        alloc.free_op(op);

                        // Put the int_func_start/5 instruction into the pending queue, and link
                        // the entry label after it.
                        self.pending = Some(func_start);
                        alloc.op_mut(func_start).next = Some(entry_op);

                        // Unless this is the first function in the module, synthesize an
                        // int_func_end/2 instruction and prepend it to the pending queue.
                        if !self.first {
                            self.synthesize_func_end(alloc);
                        }

                        self.current_func_label = func_label;
                        self.current_entry_label = entry_label;
                        self.first = false;
                    }

                    // At this point, there is at least one instruction in the pending queue,
                    // and the op variable points to the last instruction in the queue.
                    continue;
                }
                GENOP_INT_CODE_END_0 => {
                    self.pending = Some(op);
                    if !self.first {
                        self.synthesize_func_end(alloc);
                    }
                    alloc.op_mut(op).next = None;
                    continue;
                }
                _ => return Ok(op),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freed_operations_are_reused_in_free_list_order() {
        let mut alloc = BeamOpAllocator::new();
        let first = alloc.new_op();
        let second = alloc.new_op();
        assert_ne!(first, second);
        alloc.free_op(first);
        assert_eq!(alloc.new_op(), first);
    }

    #[test]
    fn a_block_holds_32_operations() {
        let mut alloc = BeamOpAllocator::new();
        let ids: Vec<OpId> = (0..33).map(|_| alloc.new_op()).collect();
        assert_eq!(ids.len(), 33);
        assert_eq!(alloc.blocks.len(), 2);
    }

    #[test]
    fn arguments_beyond_the_default_buffer_are_kept_apart() {
        let mut alloc = BeamOpAllocator::new();
        let id = alloc.new_op();
        let op = alloc.op_mut(id);
        for index in 0..3 {
            op.set_a(index, BeamOpArg::new(TAG_U, index as u64 + 1));
        }
        assert!(op.uses_def_args());
        op.spill(10, 3);
        assert!(!op.uses_def_args());
        assert_eq!(op.arity, 10);
        assert_eq!(op.a(2), BeamOpArg::new(TAG_U, 3));
        op.set_a(9, BeamOpArg::new(TAG_X, 7));
        assert_eq!(op.args().len(), 10);
        alloc.free_op(id);
        let reused = alloc.new_op();
        assert_eq!(reused, id);
        assert!(alloc.op(reused).uses_def_args());
    }
}
