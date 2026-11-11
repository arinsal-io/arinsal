//! Raw access of `bif_table`: the process header the call fragment passes and the function
//! pointer stored as an address.
//!
//! Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`) and
//! erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared: `c_p->current`), OTP-29.1.1.

use super::Bif;
use arinsal_beamasm::ProcessHeader;

/// `c_p->current` of the running process, or 0 for a null header.
pub(super) fn header_current(header: *mut ProcessHeader) -> u64 {
    if header.is_null() {
        return 0;
    }
    // SAFETY: a non-null `header` is the running process's header, passed by the call
    // fragment; only the owning scheduler reads or writes it while the BIF runs.
    unsafe { (*header).current as u64 }
}

/// The [`Bif`] whose address is `address`.
///
/// `address` must be non-zero and come from a `bif!` expression, which type-checks the function
/// against [`Bif`]; every non-zero `bif_table` entry is stored that way by `install`.
pub(super) fn bif_at(address: usize) -> Bif {
    debug_assert_ne!(address, 0);
    // SAFETY: per the contract above, `address` is a `Bif` function pointer cast to usize.
    unsafe { std::mem::transmute::<usize, Bif>(address) }
}
