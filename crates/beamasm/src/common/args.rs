//! Port of erts/emulator/beam/jit/beam_jit_args.hpp (`ArgVal` and its operand kinds),
//! OTP-29.1.1.

/// Typed operand accepted by the first BeamAsm emitter slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgVal {
    /// Register backed X value, numbered X0 through X5.
    X(u8),
    /// X value stored in the scheduler register array beyond the hardware cache.
    XMemory(u32),
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
        ArgVal::X(_) | ArgVal::XMemory(_) => Some(dst),
        _ => None,
    }
}
