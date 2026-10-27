//! `BeamOpArg`, `BeamOp` and the `BeamOpAllocator` of erts/emulator/beam/beam_file.h, and the code
//! reader of beam_file.c (`beamcodereader_read_next`, `beamcodereader_next`,
//! `synthesize_func_end`), OTP-29.1.1.
//!
//! The reader works on the bytes of the Code chunk, as erts does (`beamreader_read_tagged`).

use crate::erts_tables::{
    GEN_OPC, GENOP_INT_FUNC_END_2, GENOP_INT_FUNC_START_5, MAX_GENERIC_OPCODE,
};
use crate::erts_tables::{GENOP_FUNC_INFO_3, GENOP_INT_CODE_END_0, GENOP_LABEL_1, GENOP_LINE_1};
use arinsal_beam::BeamFile;
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
#[allow(dead_code)]
pub(crate) const TAG_H: u8 = 6;
#[allow(dead_code)]
pub(crate) const TAG_Z: u8 = 7;
pub(crate) const TAG_N: u8 = 8;
pub(crate) const TAG_P: u8 = 9;
#[allow(dead_code)]
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
    #[cfg(test)]
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
    #[cfg(test)]
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
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadError(pub &'static str);

/// `TaggedNumber` (beam_file.c): a tagged value of the code stream. `big` is the
/// two's complement payload (`ptr_value` with `size`) of an integer that does not fit a word.
struct Tagged<'a> {
    tag: u8,
    value: u64,
    big: Option<&'a [u8]>,
}

/// `BeamCodeReader`.
pub(crate) struct BeamCodeReader<'a> {
    file: &'a BeamFile,
    /// The Code chunk's instruction bytes (`beamreader` head and end).
    data: &'a [u8],
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
    tagged_error: Option<ReadError>,
}

impl<'a> BeamCodeReader<'a> {
    /// `beamfile_get_code`: the reader over a module whose atoms are already in the table.
    pub(crate) fn with_atoms(file: &'a BeamFile, atoms: Vec<Atom>) -> Self {
        Self {
            file,
            data: &file.code.bytes,
            position: 0,
            atoms,
            pending: None,
            current_func_label: BeamOpArg::default(),
            current_entry_label: BeamOpArg::default(),
            first: true,
            bignum_literals: Vec::new(),
            literal_base: file.literals.len(),
            tagged_error: None,
        }
    }

    /// `beamreader_read_u8`.
    fn read_u8(&mut self) -> Result<u8, ReadError> {
        let byte = *self
            .data
            .get(self.position)
            .ok_or(ReadError("truncated code"))?;
        self.position += 1;
        Ok(byte)
    }

    /// `beamreader_read_bytes`.
    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], ReadError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.data.len())
            .ok_or(ReadError("truncated code"))?;
        let bytes = &self.data[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    /// `beamreader_read_tagged`.
    fn read_tagged(&mut self) -> Tagged<'a> {
        match self.read_tagged_inner() {
            Ok(tagged) => tagged,
            Err(error) => self.read_tagged_error(error),
        }
    }

    /// The single cold error path used by `beamreader_read_tagged`'s `LoadError` exits.
    #[cold]
    fn read_tagged_error(&mut self, error: ReadError) -> Tagged<'a> {
        self.tagged_error.get_or_insert(error);
        Tagged {
            tag: TAG_U,
            value: 0,
            big: None,
        }
    }

    fn read_tagged_inner(&mut self) -> Result<Tagged<'a>, ReadError> {
        let mut len_code = self.read_u8()?;
        let mut tag = len_code & 0x07;
        if len_code & 0x08 == 0 {
            return Ok(Tagged {
                tag,
                value: u64::from(len_code >> 4),
                big: None,
            });
        }
        if len_code & 0x10 == 0 {
            let extra = self.read_u8()?;
            return Ok(Tagged {
                tag,
                value: (u64::from(len_code >> 5) << 8) | u64::from(extra),
                big: None,
            });
        }
        len_code >>= 5;
        let count = if len_code < 7 {
            usize::from(len_code) + 2
        } else {
            let prefix = self.read_tagged();
            if let Some(error) = self.tagged_error {
                return Err(error);
            }
            if prefix.tag != TAG_U || prefix.big.is_some() {
                return Err(ReadError("bad size prefix"));
            }
            // LoadAssert(unpacked_size < (ERTS_SINT32_MAX - size_base))
            if prefix.value >= (i32::MAX as u64) - 9 {
                return Err(ReadError("size prefix too large"));
            }
            prefix.value as usize + 9
        };
        let data = self.read_bytes(count)?;
        // Try to unpack the value into a word if possible.
        if count <= 8 {
            let word = data
                .iter()
                .fold(0u64, |word, byte| (word << 8) | u64::from(*byte));
            if tag == TAG_I {
                let shift = 8 * (8 - count as u32);
                let extended = ((word << shift) as i64) >> shift;
                if (-(1_i64 << 59)..(1_i64 << 59)).contains(&extended) {
                    return Ok(Tagged {
                        tag,
                        value: extended as u64,
                        big: None,
                    });
                }
            } else if (word as i64) >= 0 {
                return Ok(Tagged {
                    tag,
                    value: word,
                    big: None,
                });
            }
        }
        // Integers (TAG_i) are the only values allowed to be negative or larger than a word.
        // Indicate overflow by changing the tag to TAG_o.
        if tag != TAG_I {
            tag = TAG_O;
        }
        Ok(Tagged {
            tag,
            value: 0,
            big: Some(data),
        })
    }

    /// `marshal_integer` for the sized form: a bignum literal, or `TAG_o` when it cannot be one.
    fn marshal_big(&mut self, data: &[u8]) -> BeamOpArg {
        // `bytes_to_big` gives up above BIG_ARITY_MAX words.
        const BIG_ARITY_MAX: usize = (1 << 26) - 1;
        if data.len() > BIG_ARITY_MAX * 8 {
            return BeamOpArg::new(TAG_O, 0);
        }
        let value = num_bigint::BigInt::from_signed_bytes_be(data);
        let index = self.literal_base + self.bignum_literals.len();
        self.bignum_literals.push(value.to_string());
        BeamOpArg::new(TAG_Q, index as u64)
    }

    /// `marshal_allocation_list`: the size of the allocation list in words.
    fn marshal_allocation_list(&mut self) -> Result<u64, ReadError> {
        let count = self.read_tagged();
        if let Some(error) = self.tagged_error {
            return Err(error);
        }
        if count.tag != TAG_U || count.big.is_some() || count.value > 3 {
            return Err(ReadError("bad allocation list"));
        }
        let mut sum: u64 = 0;
        for _ in 0..count.value {
            let kind = self.read_tagged();
            if let Some(error) = self.tagged_error {
                return Err(error);
            }
            if kind.tag != TAG_U || kind.big.is_some() || kind.value > i32::MAX as u64 {
                return Err(ReadError("bad allocation list"));
            }
            let number = self.read_tagged();
            if let Some(error) = self.tagged_error {
                return Err(error);
            }
            if number.tag != TAG_U || number.big.is_some() || number.value > (i32::MAX as u64) / 3 {
                return Err(ReadError("bad allocation list"));
            }
            sum += match kind.value {
                0 => number.value,
                1 | 2 => 2 * number.value,
                _ => return Err(ReadError("Invalid allocation tag")),
            };
            if sum > i32::MAX as u64 {
                return Err(ReadError("allocation list too large"));
            }
        }
        Ok(sum)
    }

    /// `beamcodereader_read_next`: the instruction at the reader's position as a `BeamOp`.
    fn read_next(&mut self, alloc: &mut BeamOpAllocator) -> Result<OpId, ReadError> {
        // LoadAssert(opcode > 0 && opcode <= MAX_GENERIC_OPCODE);
        let opcode = usize::from(self.read_u8()?);
        if opcode == 0 || opcode > MAX_GENERIC_OPCODE {
            return Err(ReadError("invalid opcode"));
        }
        let mut arity = GEN_OPC[opcode].arity;
        debug_assert!(arity <= ERTS_BEAM_MAX_OPARGS);
        let id = alloc.new_op();
        let op = alloc.op_mut(id);
        op.op = opcode as i32;
        op.arity = arity;
        let mut i = 0;
        while i < arity {
            let mut raw = self.read_tagged();
            if let Some(error) = self.tagged_error.take() {
                return Err(error);
            }
            let mut arg = BeamOpArg::new(raw.tag, raw.value);
            match raw.tag {
                TAG_U | TAG_Q | TAG_O => {}
                TAG_A => {
                    if raw.value == 0 {
                        arg = BeamOpArg::new(TAG_N, NIL);
                    } else {
                        let atom = self
                            .atoms
                            .get(raw.value as usize - 1)
                            .ok_or(ReadError("atom index out of range"))?;
                        arg = BeamOpArg::new(TAG_A, u64::from(atom.0));
                    }
                }
                TAG_F => {
                    if raw.value == 0 {
                        arg = BeamOpArg::new(TAG_P, 0);
                    } else if raw.value >= u64::from(self.file.code.label_count) {
                        return Err(ReadError("label index out of range"));
                    }
                }
                TAG_I => {
                    if let Some(data) = raw.big {
                        arg = self.marshal_big(data);
                    }
                }
                TAG_X | TAG_Y => {
                    if raw.value >= MAX_REG {
                        return Err(ReadError("register out of range"));
                    }
                }
                // Extended tags.
                TAG_Z => match raw.value {
                    // Floating point number superseded in OTP R16B.
                    0 => return Err(ReadError("Floating point number superseded in OTP R16B")),
                    // Argument list.
                    1 => {
                        // Lists may only be the last argument.
                        if i + 1 != arity {
                            return Err(ReadError("a list that is not the last operand"));
                        }
                        let extra = self.read_tagged();
                        if let Some(error) = self.tagged_error.take() {
                            return Err(error);
                        }
                        if extra.tag != TAG_U || extra.big.is_some() {
                            return Err(ReadError("bad list count"));
                        }
                        // Every element takes at least a byte.
                        if extra.value as usize > self.data.len() - self.position {
                            return Err(ReadError("list count exceeds code"));
                        }
                        arity += extra.value as usize;
                        op.arity = arity;
                        // Expand the argument array if necessary.
                        if arity > ERTS_BEAM_MAX_OPARGS && op.uses_def_args() {
                            op.spill(arity, i);
                        }
                        arg = BeamOpArg::new(TAG_U, extra.value);
                    }
                    // Float register.
                    2 => {
                        let index = self.read_tagged();
                        if let Some(error) = self.tagged_error.take() {
                            return Err(error);
                        }
                        if index.tag != TAG_U || index.big.is_some() || index.value >= MAX_REG {
                            return Err(ReadError("register out of range"));
                        }
                        arg = BeamOpArg::new(TAG_L, index.value);
                    }
                    // Allocation list.
                    3 => arg = BeamOpArg::new(TAG_U, self.marshal_allocation_list()?),
                    // Literal.
                    4 => {
                        let index = self.read_tagged();
                        if let Some(error) = self.tagged_error.take() {
                            return Err(error);
                        }
                        // The referenced literal must be defined in the file, it must not have
                        // been created at runtime.
                        if index.tag != TAG_U
                            || index.big.is_some()
                            || index.value >= self.file.literals.len() as u64
                        {
                            return Err(ReadError("literal index out of range"));
                        }
                        arg = BeamOpArg::new(TAG_Q, index.value);
                    }
                    // Register with type hint.
                    5 => {
                        raw = self.read_tagged();
                        if let Some(error) = self.tagged_error.take() {
                            return Err(error);
                        }
                        if (raw.tag != TAG_X && raw.tag != TAG_Y) || raw.big.is_some() {
                            return Err(ReadError("a type hint on a non-register"));
                        }
                        if raw.value >= MAX_REG {
                            return Err(ReadError("register out of range"));
                        }
                        let index = self.read_tagged();
                        if let Some(error) = self.tagged_error.take() {
                            return Err(error);
                        }
                        if index.tag != TAG_U || index.big.is_some() {
                            return Err(ReadError("bad type index"));
                        }
                        arg = BeamOpArg::new(raw.tag, raw.value);
                        // A module whose type table was stripped treats these as ordinary
                        // registers.
                        if let Some(types) = &self.file.types {
                            if index.value >= types.entries.len() as u64 {
                                return Err(ReadError("type index out of range"));
                            }
                            arg.val |= index.value << REG_TYPE_SHIFT;
                        }
                    }
                    _ => return Err(ReadError("Unrecognized extended tag")),
                },
                _ => return Err(ReadError("Unrecognized tag")),
            }
            // All arguments must be words except for TAG_o, which is valueless.
            if raw.big.is_some() && arg.ty != TAG_O && arg.ty != TAG_Q {
                return Err(ReadError("operand wider than a word"));
            }
            op.set_a(i, arg);
            i += 1;
        }
        if let Some(error) = self.tagged_error.take() {
            return Err(error);
        }
        Ok(id)
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

    use arinsal_beam::{AllocKind, Instr, Operand, parse};

    /// What the operand of a decoded instruction must become: the `beamcodereader_read_next`
    /// switch applied to `arinsal_beam`'s decoding, which is an independent decoder of the same
    /// bytes.
    fn expected(
        file: &BeamFile,
        atoms: &[Atom],
        operand: &Operand,
        bignums: &mut Vec<String>,
    ) -> BeamOpArg {
        let big = |bignums: &mut Vec<String>, text: String| {
            let index = file.literals.len() + bignums.len();
            bignums.push(text);
            BeamOpArg::new(TAG_Q, index as u64)
        };
        match operand {
            Operand::U(value) => BeamOpArg::new(TAG_U, *value),
            Operand::Int(value) if (-(1_i64 << 59)..(1_i64 << 59)).contains(value) => {
                BeamOpArg::new(TAG_I, *value as u64)
            }
            Operand::Int(value) => big(bignums, value.to_string()),
            Operand::BigInt(value) => big(bignums, value.to_string()),
            Operand::Atom(0) | Operand::Nil => BeamOpArg::new(TAG_N, NIL),
            Operand::Atom(index) => BeamOpArg::new(TAG_A, u64::from(atoms[*index as usize - 1].0)),
            Operand::Label(0) => BeamOpArg::new(TAG_P, 0),
            Operand::Label(label) => BeamOpArg::new(TAG_F, u64::from(*label)),
            Operand::X(register) => BeamOpArg::new(TAG_X, u64::from(*register)),
            Operand::Y(register) => BeamOpArg::new(TAG_Y, u64::from(*register)),
            Operand::FR(register) => BeamOpArg::new(TAG_L, u64::from(*register)),
            Operand::Alloc(items) => BeamOpArg::new(
                TAG_U,
                items
                    .iter()
                    .map(|item| match item.kind {
                        AllocKind::Words => item.count,
                        AllocKind::Floats | AllocKind::Funs => 2 * item.count,
                    })
                    .sum(),
            ),
            Operand::Literal(index) => BeamOpArg::new(TAG_Q, u64::from(*index)),
            Operand::TypedReg { reg, type_index } => {
                let mut arg = expected(file, atoms, reg, bignums);
                if file.types.is_some() {
                    arg.val |= u64::from(*type_index) << REG_TYPE_SHIFT;
                }
                arg
            }
            Operand::Char(_) | Operand::List(_) => unreachable!(),
        }
    }

    fn check_module(path: &std::path::Path) {
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let Ok(file) = parse(&bytes) else { return };
        let atoms: Vec<Atom> = file
            .atoms
            .iter()
            .map(|name| arinsal_term::global_atoms().intern(name).unwrap())
            .collect();
        let mut alloc = BeamOpAllocator::new();
        let mut reader = BeamCodeReader::with_atoms(&file, atoms.clone());
        let mut bignums = Vec::new();
        for instr in &file.code.instructions {
            let Instr { op, args, .. } = instr;
            let id = reader.read_next(&mut alloc).unwrap();
            let got = alloc.op(id);
            assert_eq!(got.op, *op as i32, "{}", path.display());
            let mut want: Vec<BeamOpArg> = Vec::new();
            for operand in args {
                if let Operand::List(items) = operand {
                    want.push(BeamOpArg::new(TAG_U, items.len() as u64));
                    for item in items.iter() {
                        want.push(expected(&file, &atoms, item, &mut bignums));
                    }
                } else {
                    want.push(expected(&file, &atoms, operand, &mut bignums));
                }
            }
            assert_eq!(got.args(), want.as_slice(), "{} {:?}", path.display(), op);
        }
        assert_eq!(reader.bignum_literals, bignums, "{}", path.display());
    }

    #[test]
    fn the_byte_reader_equals_the_decoded_instruction_stream() {
        let Ok(output) = std::process::Command::new("erl")
            .args([
                "-noshell",
                "-eval",
                "io:format(\"~s\", [string:join([P || P <- code:get_path(), P =/= \".\"], \"\\n\")]), halt().",
            ])
            .output()
        else {
            eprintln!("erl unavailable; skipping");
            return;
        };
        let dirs = String::from_utf8(output.stdout).unwrap();
        let mut checked = 0;
        for dir in dirs.lines().take(12) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.path().extension().is_some_and(|e| e == "beam") {
                    check_module(&entry.path());
                    checked += 1;
                }
            }
        }
        assert!(checked > 100, "{checked}");
    }
}
