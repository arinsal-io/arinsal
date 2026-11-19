//! Port of erts/emulator/beam/jit/beam_jit_args.hpp (`ArgVal` and its operand kinds),
//! OTP-29.1.1.

/// Typed operand accepted by the first BeamAsm emitter slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgVal {
    /// X register (erts `ArgXRegister`), as erts' `val`: the register number in the low bits
    /// ([`REG_MASK`]) and the operand's index into the module's type table above them
    /// (`ArgRegister::typeIndex`). Whether it lives in a machine register is the target
    /// assembler's choice (`isRegisterBacked` on arm64; none on x86-64), not the operand's.
    X(u32),
    /// Erlang stack Y value, numbered from the current stack pointer; packed with its type
    /// index as [`ArgVal::X`].
    Y(u32),
    /// A tagged immediate term (erts `ArgImmed`: NIL, an atom, a small integer or an arity
    /// value).
    Immediate(u64),
    /// An untagged machine word (erts `ArgWord`, `TAG_u`): the `t`/`I`/`W`/`A`/`P`/`b`
    /// operands of the loader and the untagged elements of variable argument lists.
    Word(u64),
    /// A literal index in the module's static or dynamic literal table.
    Literal(i64),
    /// A module label number.
    Label(u32),
    /// An export table index (external call emission is currently unported).
    Export(u32),
    /// A float register (erts `ArgFRegister`, `l`), as the loader massages it: the register
    /// number times `sizeof(FloatDef)`.
    FReg(u32),
    /// A byte offset into the module's string table (erts `ArgBytePtr`, `M`).
    BytePtr(u64),
    /// An exception handler label (erts `ArgCatch`, `H`).
    Catch(u32),
    /// A lambda table index (erts `ArgLambda`, `F`).
    FunEntry(u32),
}

/// `MAX_REG`: the number of X registers.
// Port of erts/emulator/beam/erl_vm.h:55 (MAX_REG), OTP-29.1.1.
pub const MAX_REG: u32 = 1024;

/// `REG_MASK`: the register number bits of a register operand's `val`; the type index the
/// loader packs above them (beam_file.c, `raw_arg.word_value |= index << 10`) needs
/// `REG_MASK < (1 << 10)`.
// Port of erts/emulator/beam/erl_vm.h:56 (REG_MASK), OTP-29.1.1.
pub const REG_MASK: u32 = MAX_REG - 1;

/// The bit position of the type index in a register operand's `val`.
// Port of erts/emulator/beam/beam_file.c:2435-2436 (read_code, register with type hint),
// OTP-29.1.1.
pub const TYPE_INDEX_SHIFT: u32 = 10;

const TAG_IMMED1_MASK: u64 = 0xf;
const TAG_IMMED1_SMALL: u64 = 0xf;
const TAG_IMMED1_SIZE: u32 = 4;
const TAG_IMMED2_MASK: u64 = 0x3f;
const TAG_IMMED2_ATOM: u64 = 0x0b;
const NIL: u64 = 0x3b;

// Port of erts/emulator/beam/jit/beam_jit_args.hpp:26-420 (ArgVal and the typed views
// ArgRegister, ArgXRegister, ArgYRegister, ArgSmall, ArgWord, ArgLabel, ...), OTP-29.1.1.
// erts' typed views are `ArgVal`s asserted to be of one kind; their `get()` is the accessor
// of that kind here.
impl ArgVal {
    /// An X register operand carrying the type index `type_index` (the loader's
    /// `TAG_x` with `val = reg | type_index << 10`).
    pub const fn typed_x(reg: u32, type_index: u32) -> ArgVal {
        ArgVal::X(reg | (type_index << TYPE_INDEX_SHIFT))
    }

    /// A Y register operand carrying the type index `type_index`.
    pub const fn typed_y(reg: u32, type_index: u32) -> ArgVal {
        ArgVal::Y(reg | (type_index << TYPE_INDEX_SHIFT))
    }

    /// `isAtom`.
    pub const fn is_atom(self) -> bool {
        matches!(self, ArgVal::Immediate(w) if w & TAG_IMMED2_MASK == TAG_IMMED2_ATOM)
    }

    /// `isConstant`.
    pub const fn is_constant(self) -> bool {
        self.is_immed() || self.is_literal()
    }

    /// `isImmed`.
    pub const fn is_immed(self) -> bool {
        matches!(self, ArgVal::Immediate(_))
    }

    /// `isLabel`.
    pub const fn is_label(self) -> bool {
        matches!(self, ArgVal::Label(_))
    }

    /// `isLiteral`.
    pub const fn is_literal(self) -> bool {
        matches!(self, ArgVal::Literal(_))
    }

    /// `isNil`.
    pub const fn is_nil(self) -> bool {
        matches!(self, ArgVal::Immediate(NIL))
    }

    /// `isSmall`.
    pub const fn is_small(self) -> bool {
        matches!(self, ArgVal::Immediate(w) if w & TAG_IMMED1_MASK == TAG_IMMED1_SMALL)
    }

    /// `isSource`.
    pub const fn is_source(self) -> bool {
        self.is_constant() || self.is_register()
    }

    /// `isRegister`.
    pub const fn is_register(self) -> bool {
        matches!(self, ArgVal::X(_) | ArgVal::Y(_) | ArgVal::FReg(_))
    }

    /// `isXRegister`.
    pub const fn is_x_register(self) -> bool {
        matches!(self, ArgVal::X(_))
    }

    /// `isYRegister`.
    pub const fn is_y_register(self) -> bool {
        matches!(self, ArgVal::Y(_))
    }

    /// `isWord`.
    pub const fn is_word(self) -> bool {
        matches!(self, ArgVal::Word(_))
    }

    /// `ArgRegister::typeIndex`: the index into the module's type table (0 for an untyped
    /// register and for anything else, which `getTypeEntry` also reads as entry 0).
    pub const fn type_index(self) -> u32 {
        match self {
            ArgVal::X(val) | ArgVal::Y(val) => val >> TYPE_INDEX_SHIFT,
            _ => 0,
        }
    }

    /// `ArgXRegister::get` / `ArgYRegister::get`: the register number without the type
    /// index; `None` for any other operand.
    pub const fn reg(self) -> Option<u32> {
        match self {
            ArgVal::X(val) | ArgVal::Y(val) => Some(val & REG_MASK),
            _ => None,
        }
    }

    /// `ArgSmall::getSigned`: the untagged value of a small immediate.
    pub const fn small_signed(self) -> Option<i64> {
        match self {
            ArgVal::Immediate(w) if w & TAG_IMMED1_MASK == TAG_IMMED1_SMALL => {
                Some((w as i64) >> TAG_IMMED1_SIZE)
            }
            _ => None,
        }
    }

    /// `ArgLabel::get`.
    pub const fn label(self) -> Option<u32> {
        match self {
            ArgVal::Label(label) => Some(label),
            _ => None,
        }
    }

    /// `ArgWord::get`.
    pub const fn word(self) -> Option<u64> {
        match self {
            ArgVal::Word(word) => Some(word),
            _ => None,
        }
    }

    /// `ArgImmed::get`.
    pub const fn immed(self) -> Option<u64> {
        match self {
            ArgVal::Immediate(term) => Some(term),
            _ => None,
        }
    }

    /// `ArgRegister::trimmed(n)`: the register a destination becomes once `words` have been
    /// trimmed from the frame (a Y register loses its type index, as in erts); `None` for a
    /// Y register trimmed away or a non-register.
    // Port of erts/emulator/beam/jit/beam_jit_args.hpp:257-263 (ArgRegister::trimmed),
    // OTP-29.1.1.
    pub fn trimmed(self, words: u32) -> Option<ArgVal> {
        match self {
            ArgVal::Y(val) => (val & REG_MASK).checked_sub(words).map(ArgVal::Y),
            ArgVal::X(_) => Some(self),
            _ => None,
        }
    }

    /// `ArgRegister::copy<T>(n)`: register `n` of the same kind with this operand's type
    /// index.
    // Port of erts/emulator/beam/jit/beam_jit_args.hpp:265-268 (ArgRegister::copy),
    // OTP-29.1.1.
    pub fn copy(self, n: u32) -> Option<ArgVal> {
        match self {
            ArgVal::X(val) => Some(ArgVal::X(n | (val & !REG_MASK))),
            ArgVal::Y(val) => Some(ArgVal::Y(n | (val & !REG_MASK))),
            _ => None,
        }
    }
}

/// How two register operands lie in memory (`ArgVal::Relation`).
// Port of erts/emulator/beam/jit/beam_jit_args.hpp:142 (ArgVal::Relation), OTP-29.1.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Relation {
    /// Not adjacent.
    None,
    /// `rhs` is the register after `lhs`.
    Consecutive,
    /// `rhs` is the register before `lhs`.
    ReverseConsecutive,
}

/// `ArgVal::memory_relation(lhs, rhs)`.
// Port of erts/emulator/beam/jit/beam_jit_args.hpp:144-154 (memory_relation), OTP-29.1.1.
pub fn memory_relation(lhs: ArgVal, rhs: ArgVal) -> Relation {
    let (l, r) = match (lhs, rhs) {
        (ArgVal::X(l), ArgVal::X(r)) | (ArgVal::Y(l), ArgVal::Y(r)) => (l & REG_MASK, r & REG_MASK),
        _ => return Relation::None,
    };
    if l + 1 == r {
        Relation::Consecutive
    } else if l == r + 1 {
        Relation::ReverseConsecutive
    } else {
        Relation::None
    }
}
