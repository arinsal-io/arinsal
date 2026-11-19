//! Safe views of pointer arguments passed to erts-named runtime symbols.
// Port of erts/emulator/beam/erl_bits.h (`ErlSubBits`) and beam_common.h (`GetSource`), OTP-29.1.1.

use arinsal_term::Term;

/// Returns a live mutable match-context term from the `ErlSubBits *` ABI argument.
pub(crate) fn match_context(sub_bits: *mut u64) -> Option<Term> {
    let address = sub_bits as usize;
    if address == 0 || !address.is_multiple_of(core::mem::align_of::<u64>()) {
        return None;
    }
    let context = crate::native_hooks::from_raw((address as u64) | 2);
    arinsal_term::is_match_context(context).then_some(context)
}

/// A caller-owned C operand array whose storage remains live through the runtime call.
#[derive(Clone, Copy)]
pub(crate) struct RuntimeOperandArray {
    words: *const u64,
    len: usize,
}

impl RuntimeOperandArray {
    /// Validates an `Eterm *` and its declared word count before indexed reads.
    pub(crate) fn from_raw(words: *const u64, len: usize) -> Option<Self> {
        if len != 0
            && (words.is_null() || !(words as usize).is_multiple_of(core::mem::align_of::<u64>()))
        {
            return None;
        }
        Some(Self { words, len })
    }

    /// Reads one word from the live operand array.
    pub(crate) fn get(self, index: usize) -> Option<u64> {
        (index < self.len).then(|| crate::raw::beam_common_ffi::read_word(self.words, index))
    }

    /// Number of words in the C operand array.
    pub(crate) fn len(self) -> usize {
        self.len
    }
}

/// Resolves the source descriptors in an embedded C operand array before collector-root staging.
pub(crate) fn resolve_operands(
    operands: RuntimeOperandArray,
    x: &[Term],
    stack: &arinsal_term::ProcessHeap,
) -> Option<Vec<Term>> {
    (0..operands.len())
        .map(|index| get_source(operands.get(index)?, x, stack))
        .collect()
}

/// Uses a mutable Eterm array within this raw module only.
pub(crate) fn with_runtime_terms<R>(
    terms: *mut u64,
    len: usize,
    body: impl FnOnce(&mut [Term]) -> R,
) -> Option<R> {
    crate::raw::beam_common_ffi::with_mut_terms(terms, len, body)
}

/// Resolves one erts `GetSource` descriptor through X registers or the Erlang stack.
pub(crate) fn get_source(
    descriptor: u64,
    x: &[Term],
    stack: &arinsal_term::ProcessHeap,
) -> Option<Term> {
    const LOADER_TAG_MASK: u64 = 0x0f;
    const LOADER_TAG_SIZE: u32 = 4;
    const LOADER_X_REG: u64 = 0x3;
    const LOADER_Y_REG: u64 = 0x7;

    let index = usize::try_from(descriptor >> LOADER_TAG_SIZE).ok()?;
    match descriptor & LOADER_TAG_MASK {
        LOADER_X_REG => x.get(index).copied(),
        LOADER_Y_REG => stack.stack_get(index),
        _ => Some(crate::native_hooks::from_raw(descriptor)),
    }
}

/// Writes one erts `PUT_TERM_REG` destination from the encoded X/Y register descriptor.
pub(crate) fn put_term_reg(
    descriptor: u64,
    value: Term,
    x: &mut [Term],
    stack: &mut arinsal_term::ProcessHeap,
) -> bool {
    const LOADER_TAG_MASK: u64 = 0x0f;
    const LOADER_TAG_SIZE: u32 = 4;
    const LOADER_X_REG: u64 = 0x3;
    const LOADER_Y_REG: u64 = 0x7;

    let Ok(index) = usize::try_from(descriptor >> LOADER_TAG_SIZE) else {
        return false;
    };
    match descriptor & LOADER_TAG_MASK {
        LOADER_X_REG => {
            let Some(slot) = x.get_mut(index) else {
                return false;
            };
            *slot = value;
            true
        }
        LOADER_Y_REG => stack.stack_set(index, value),
        _ => false,
    }
}
