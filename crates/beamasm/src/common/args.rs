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
    /// An immediate machine word.
    Immediate(u64),
    /// A literal machine word.
    Literal(u64),
    /// A module label number.
    Label(u32),
    /// An export table index (external call emission is currently unported).
    Export(u32),
}

/// The operand a destination becomes once `words` have been trimmed from the frame.
// Port of erts/emulator/beam/jit/beam_jit_args.hpp (ArgVal::trimmed), OTP-29.1.1.
pub(crate) fn trimmed_arg(dst: ArgVal, words: u32) -> Option<ArgVal> {
    match dst {
        ArgVal::Y(index) => index.checked_sub(words).map(ArgVal::Y),
        ArgVal::X(_) => Some(dst),
        _ => None,
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
