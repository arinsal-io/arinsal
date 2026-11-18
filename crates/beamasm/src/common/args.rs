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
