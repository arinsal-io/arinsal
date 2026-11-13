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

/// The `Export.info` word of the export whose `info.mfa` is at `mfa`.
// Port of erts/emulator/beam/export.h (`ErtsContainerOf(mfa, Export, info.mfa)`), OTP-29.1.1.
///
/// `mfa` must be non-zero and the `mfa` field of a live `ExportEntry`: `c_p->current` while an
/// export's BIF runs.
pub(super) fn export_info_of_mfa(mfa: u64) -> u64 {
    debug_assert_ne!(mfa, 0);
    let entry =
        (mfa - u64::from(arinsal_term::EXPORT_MFA_OFFSET)) as *const arinsal_term::ExportEntry;
    // SAFETY: per the contract above, `entry` is the live entry that owns `mfa`; entries are
    // never freed while a process can hold their `mfa`.
    unsafe { (*entry).info.load(std::sync::atomic::Ordering::Acquire) as u64 }
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
