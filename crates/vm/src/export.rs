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
use arinsal_term::{Atom, TRAMPOLINE_BREAKPOINT, TRAMPOLINE_CALL_ERROR_HANDLER, TRAMPOLINE_NONE};

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

/// The shared `beam_export_trampoline` every export enters while its trampoline is active.
fn export_trampoline() -> usize {
    crate::beamasm_integration::export_trampoline()
}

/// `erts_activate_export_trampoline`: code index `ix` of `ep` enters the export trampoline.
// Port of erts/emulator/beam/export.h:148-160, OTP-29.1.1.
pub(crate) fn activate_export_trampoline(ep: &ExportEntry, ix: usize) {
    ep.set_address(ix, export_trampoline());
}

/// `erts_is_export_trampoline_active`.
// Port of erts/emulator/beam/export.h:162-172, OTP-29.1.1.
pub(crate) fn is_export_trampoline_active(ep: &ExportEntry, ix: usize) -> bool {
    ep.address(ix) == export_trampoline()
}

/// Whether calls through `ep` hit a global call breakpoint (`op_i_generic_breakpoint` in its
/// trampoline).
pub(crate) fn has_export_breakpoint(ep: &ExportEntry) -> bool {
    ep.trampoline_op() == TRAMPOLINE_BREAKPOINT
}

/// `export_start_staging`: the staging code index starts with the active address of every
/// export of the active table.
// Port of erts/emulator/beam/export.c:100-106 (export_stage) and erl_code_staged.h
// (start_staging), OTP-29.1.1.
pub(crate) fn export_start_staging(
    tables: &crate::load::CodeTables,
    active: usize,
    staging: usize,
) {
    for ep in tables.exports.exports() {
        ep.stage(active, staging);
    }
}

/// Clears the global call breakpoint of an export whose trampoline is active in `ix`,
/// restoring the address it saved.
// Port of erts/emulator/beam/beam_load.c:283-296 and beam_bp.c:904-921
// (erts_clear_all_export_break), OTP-29.1.1.
fn clear_export_break(ep: &ExportEntry, ix: usize) {
    if is_export_trampoline_active(ep, ix) && has_export_breakpoint(ep) {
        ep.set_trampoline_op(TRAMPOLINE_NONE);
        ep.set_address(ix, ep.trampoline_address());
        ep.set_trampoline_address(0);
    }
}

/// `delete_code`: every export of `module` in the staging table `ix` enters the error handler.
// Port of erts/emulator/beam/beam_bif_load.c:2407-2445 (delete_code), OTP-29.1.1.
pub(crate) fn delete_code(tables: &crate::load::CodeTables, module: Atom, ix: usize) {
    for ep in tables.exports.exports_of(module) {
        if is_export_trampoline_active(ep, ix) && has_export_breakpoint(ep) {
            ep.set_trampoline_op(TRAMPOLINE_NONE);
        }
        ep.set_bif_traced(false);
        ep.set_trampoline_op(TRAMPOLINE_CALL_ERROR_HANDLER);
        ep.set_trampoline_address(0);
        activate_export_trampoline(ep, ix);
    }
}

/// The export part of `erts_finish_loading` / `beam_load_finalize_code` for one module:
/// the current code of `module`, if any, becomes old (`delete_code`), or with an on_load
/// function its exports only lose their breakpoints; then exports and imports are entered
/// in the staging export table and each exported function's address is written into
/// `addresses[staging_ix]`, or into `trampoline.not_loaded.deferred` for on_load code.
// Port of erts/emulator/beam/beam_load.c:242-330 (erts_finish_loading) and
// jit/asm_load.c:1177-1206 (beam_load_finalize_code), OTP-29.1.1.
pub(crate) fn finish_loading(
    scope: u64,
    module: &arinsal_loader::Module,
    exports: &[(Mfa, &'static Arc<ExportEntry>)],
    imports: &[(Mfa, &'static Arc<ExportEntry>)],
    addresses: &[(Mfa, usize)],
    on_load: bool,
) {
    let code = crate::code_ix::for_scope(scope);
    let staging = code.start_staging();
    let ix = staging.ix();
    staging.with(|tables| {
        if on_load {
            for ep in tables.exports.exports_of(module.name_atom) {
                clear_export_break(ep, ix);
                ep.set_bif_traced(false);
            }
        } else if tables.loaded.get(module.name.as_str()).is_some() {
            // Port of erts/emulator/beam/beam_bif_load.c:2459-2480 (beam_make_current_old).
            delete_code(tables, module.name_atom, ix);
        }
        for (mfa, export) in exports.iter().chain(imports) {
            tables.exports.put_export(*mfa, export);
        }
    });
    for (mfa, address) in addresses {
        let Some((_, ep)) = exports.iter().find(|(key, _)| key == mfa) else {
            continue;
        };
        if on_load {
            ep.set_trampoline_address(*address);
        } else {
            ep.set_address(ix, *address);
        }
    }
}

/// The export fix-up of erlang:finish_after_on_load/2. Kept code (`keep`, inside its staging
/// area `ix`) makes each deferred address callable and sends the module's other non-BIF
/// exports to the error handler; dropped code forgets the deferred addresses.
// Port of erts/emulator/beam/beam_bif_load.c:873-938 (erts_internal_finish_after_on_load_2),
// OTP-29.1.1.
pub(crate) fn finish_after_on_load(
    tables: &crate::load::CodeTables,
    module: Atom,
    keep: bool,
    ix: usize,
) {
    for ep in tables.exports.exports_of(module) {
        let deferred = ep.trampoline_address();
        if keep && deferred != 0 {
            ep.set_address(ix, deferred);
            ep.set_trampoline_address(0);
        } else if ep.bif_number() == -1 {
            if keep {
                ep.set_trampoline_op(TRAMPOLINE_CALL_ERROR_HANDLER);
                activate_export_trampoline(ep, ix);
            } else {
                ep.set_trampoline_address(0);
            }
        }
    }
}

/// Turns the global call breakpoint of `mfa` on or off and publishes `Export.is_bif_traced`,
/// as a staged code change.
// Port of erts/emulator/beam/erl_bif_trace.c:2690-2720 (erts_set_trace_pattern),
// 2942-3005 (install_exp_breakpoints, uninstall_exp_breakpoints, clean_export_entries),
// OTP-29.1.1.
pub(crate) fn set_export_breakpoint(scope: u64, mfa: Mfa, enabled: bool, bif_traced: bool) {
    let code = crate::code_ix::for_scope(scope);
    let Some(ep) = active_export_entry(scope, mfa) else {
        return;
    };
    if has_export_breakpoint(ep) == enabled {
        return;
    }
    let staging = code.start_staging();
    let ix = staging.ix();
    if enabled {
        if !is_export_trampoline_active(ep, ix) {
            ep.set_trampoline_op(TRAMPOLINE_BREAKPOINT);
            ep.set_trampoline_address(ep.address(ix));
        }
        ep.set_bif_traced(bif_traced);
        activate_export_trampoline(ep, ix);
    } else {
        ep.set_bif_traced(bif_traced);
        if is_export_trampoline_active(ep, ix) && has_export_breakpoint(ep) {
            ep.set_address(ix, ep.trampoline_address());
        }
        if !is_export_trampoline_active(ep, ix) && has_export_breakpoint(ep) {
            ep.set_trampoline_op(TRAMPOLINE_NONE);
            ep.set_trampoline_address(0);
        }
    }
    drop(staging);
}
