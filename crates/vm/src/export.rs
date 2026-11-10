//! The export table: one `Export` per MFA, entered in the export table of each code index.
//!
//! Port of erts/emulator/beam/export.c and erl_code_staged.h, OTP-29.1.1. The export table of
//! a code index is [`crate::load::ExportIndex`] inside that index's
//! [`crate::load::CodeTables`]; its entries point at the node's shared `Export` object
//! ([`ExportEntry`], `addresses[ERTS_NUM_CODE_IX]` first), as the per-index entries of one
//! export blob do in erts. A staging area copies the active tables and the active address of
//! every export (`export_stage`); the loader then enters the module's exports and imports in
//! the staging table and writes `addresses[staging_ix]`, and the commit makes both active.

use std::sync::Arc;

use arinsal_beamasm::bif::ExportEntry;
use arinsal_term::Atom;

type Mfa = (Atom, Atom, u8);

/// `erts_export_put` for a batch of exports already allocated for this node: each becomes the
/// entry of its MFA in the staging export table (every table when no staging area is open).
// Port of erts/emulator/beam/export.c:204-226 (erts_export_put), OTP-29.1.1.
pub(crate) fn export_put_all(scope: u64, exports: &[(Mfa, &'static Arc<ExportEntry>)]) {
    if exports.is_empty() {
        return;
    }
    crate::code_ix::for_scope(scope).update_active(|tables| {
        for (mfa, export) in exports {
            tables.exports.put_export(*mfa, export);
        }
    });
}

/// `erts_find_export_entry`: the export of `mfa` in the export table of `code_ix`.
///
/// Runs on a thread covered by the code indexes' thread progress (a scheduler).
// Port of erts/emulator/beam/export.c:154-169 (erts_find_export_entry), OTP-29.1.1.
pub(crate) fn find_export_entry(
    code: &crate::code_ix::CodeIndexes,
    mfa: Mfa,
    code_ix: usize,
) -> Option<&'static ExportEntry> {
    if code_ix >= arinsal_beamasm::bif::ERTS_ADDRESSV_SIZE {
        return None;
    }
    code.with_tables_for_code_ix(code_ix, |tables| tables.exports.dispatch(mfa))
        .flatten()
}

/// `erts_active_export_entry`: the export of `mfa` in the active export table.
// Port of erts/emulator/beam/export.h (erts_active_export_entry), OTP-29.1.1.
pub(crate) fn active_export_entry(scope: u64, mfa: Mfa) -> Option<&'static Arc<ExportEntry>> {
    crate::code_ix::for_scope(scope)
        .active_tables()
        .exports
        .find_arc(mfa)
}

/// `erts_export_get_or_make_stub`: the export of `mfa`, or a new stub entering the export
/// trampoline (whose call runs the error handler) entered in the export table.
// Port of erts/emulator/beam/export.c:228-242 (erts_export_get_or_make_stub), OTP-29.1.1.
pub(crate) fn export_get_or_make_stub(scope: u64, mfa: Mfa) -> Option<Arc<ExportEntry>> {
    if let Some(export) = active_export_entry(scope, mfa) {
        return Some(Arc::clone(export));
    }
    let export = crate::beamasm_integration::make_export(scope, mfa)?;
    export_put_all(scope, &[(mfa, export)]);
    Some(Arc::clone(export))
}
