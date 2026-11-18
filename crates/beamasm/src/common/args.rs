//! Port of erts/emulator/beam/jit/beam_jit_args.hpp (`ArgVal` and its operand kinds),
//! OTP-29.1.1.

/// Typed operand accepted by the first BeamAsm emitter slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgVal {
    /// X register (erts `ArgXRegister`). Whether it lives in a machine register is the target
    /// assembler's choice (`isRegisterBacked` on arm64; none on x86-64), not the operand's.
    X(u32),
    /// Erlang stack Y value, numbered from the current stack pointer.
    Y(u32),
    /// A tagged immediate term (erts `ArgImmed`: NIL, an atom, a small integer or an arity
    /// value).
    Immediate(u64),
    /// An untagged machine word (erts `ArgWord`, `TAG_u`): the `t`/`I`/`W`/`A`/`P`/`b`
    /// operands of the loader and the untagged elements of variable argument lists.
    Word(u64),
    /// A literal machine word.
    Literal(u64),
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

impl ArgVal {
    /// `ArgRegister::trimmed(n)`: the register a destination becomes once `words` have been
    /// trimmed from the frame; `None` for a Y register trimmed away or a non-register.
    // Port of erts/emulator/beam/jit/beam_jit_args.hpp:257-263 (ArgRegister::trimmed),
    // OTP-29.1.1.
    pub fn trimmed(self, words: u32) -> Option<ArgVal> {
        match self {
            ArgVal::Y(index) => index.checked_sub(words).map(ArgVal::Y),
            ArgVal::X(_) => Some(self),
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
        (ArgVal::X(l), ArgVal::X(r)) | (ArgVal::Y(l), ArgVal::Y(r)) => (l, r),
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
