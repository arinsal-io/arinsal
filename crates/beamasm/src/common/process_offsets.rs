//! The `Process` fields native code addresses whose offsets depend on the VM's process type
//! (`state`, `sig_qs`) and the message node layout (`ErtsMessage.m[0]`).
//!
//! erts compiles them in with `offsetof(Process, state.counter)`,
//! `offsetof(Process, sig_qs.save)` and `offsetof(ErtsMessage, m[0])` (jit/x86/process_main.cpp,
//! jit/x86/beam_asm_global.cpp, jit/{x86,arm}/instr_msg.cpp, OTP-29.1.1). The fields of the
//! fixed native prefix (`htop` .. `flags`, `mbuf`) are `const` offsets of
//! [`crate::ProcessHeader`]; these three sit in `arinsal_vm::Process`, which this crate cannot
//! name, so the VM hands their `const` offsets (`PROCESS_STATE_OFFSET`,
//! `PROCESS_SIGQ_SAVE_OFFSET`, `ERTS_MESSAGE_TERM_OFFSET`) to the global assembler of either
//! architecture once, when it emits the global fragments that read them.

/// `offsetof` of the process and message fields the global fragments read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessOffsets {
    /// `offsetof(Process, state.counter)`: the `ERTS_PSFLG_*` word.
    pub state: u32,
    /// `offsetof(Process, sig_qs.save)`: the `next` field that points at the message a receive
    /// looks at.
    pub sig_qs_save: u32,
    /// `offsetof(ErtsMessage, m[0])`: the term of a message in its queue node. erts'
    /// `offsetof(ErtsSignal, common.tag)` is the same word (`ERL_MESSAGE_REF_FIELDS__` and
    /// `ERTS_SIGNAL_COMMON_FIELDS__` share their first three words).
    pub message_term: u32,
}

impl ProcessOffsets {
    /// erts 29.1.1's own offsets on x86-64 Linux (`erl +JDdump true`), for byte comparisons
    /// with its dumps.
    #[cfg(all(test, target_arch = "x86_64"))]
    pub(crate) const ERTS_X86_64: Self = Self {
        state: 624,
        sig_qs_save: 328,
        message_term: 16,
    };
}
