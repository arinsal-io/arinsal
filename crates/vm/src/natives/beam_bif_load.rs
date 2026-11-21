//! The module-table query BIFs of beam_bif_load.c.
//!
//! Port of erts/emulator/beam/beam_bif_load.c (loaded_0, pre_loaded_0 via erts_preloaded,
//! module_loaded_1, check_old_code_1), OTP-29.1.1.

use crate::code_ix::{code_tables, erts_active_code_ix};
use crate::natives::bif::{badarg, bif_ret};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Term, TermBuilder, atoms, global_atoms};

fn bool_atom(value: bool) -> Term {
    Term::atom(if value { atoms::TRUE } else { atoms::FALSE })
}

fn make_list(
    process: &mut Process,
    values: impl IntoIterator<Item = Term>,
) -> Result<Term, VmError> {
    TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(values)
        .map_err(|_| {
            VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                atoms::SYSTEM_LIMIT,
            )))
        })
}

/// `erlang:loaded/0`: every module with current or old code, consed in `module_code(i)` order.
// Port of erts/emulator/beam/beam_bif_load.c (loaded_0), OTP-29.1.1.
pub(crate) extern "C" fn loaded_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let tables = code_tables(erts_active_code_ix());
    let mut modules = Vec::new();
    for i in 0..tables.loaded.code_size() {
        let Some(entry) = tables.loaded.module_code(i) else {
            continue;
        };
        if entry.curr.is_some() || entry.old.is_some() {
            modules.push(Term::atom(entry.module));
        }
    }
    modules.reverse();
    let list = make_list(process, modules);
    bif_ret(c_p, i, list)
}

/// `erlang:pre_loaded/0`: the names of the preloaded modules (`sys_preloaded()`).
// Port of erts/emulator/beam/erl_init.c (erts_preloaded) called from bif.c (pre_loaded_0),
// OTP-29.1.1.
pub(crate) extern "C" fn pre_loaded_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    const PRELOADED: [&str; 22] = [
        "persistent_term",
        "counters",
        "atomics",
        "erts_dirty_process_signal_handler",
        "erts_trace_cleaner",
        "erts_literal_area_collector",
        "erl_tracer",
        "erts_internal",
        "erlang",
        "erl_prim_loader",
        "prim_zip",
        "prim_net",
        "prim_socket",
        "socket_registry",
        "zlib",
        "prim_file",
        "prim_inet",
        "prim_eval",
        "prim_buffer",
        "init",
        "erl_init",
        "erts_code_purger",
    ];
    let list = make_list(process, PRELOADED.into_iter().map(crate::atom_cache::put));
    bif_ret(c_p, i, list)
}

/// `erlang:module_loaded/1`: the module table of the active code index.
// Port of erts/emulator/beam/beam_bif_load.c (module_loaded_1), OTP-29.1.1.
pub(crate) extern "C" fn module_loaded_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [module] = crate::bif_table::bif_args::<1>(reg);
    let result = (|| -> Result<Term, VmError> {
        let name = global_atoms()
            .text(module.as_atom().ok_or_else(badarg)?)
            .ok_or_else(badarg)?;
        Ok(bool_atom(
            code_tables(erts_active_code_ix()).loaded.contains_key(name),
        ))
    })();
    bif_ret(c_p, i, result)
}

/// `erlang:check_old_code/1`: whether the module has old code.
// Port of erts/emulator/beam/beam_bif_load.c (check_old_code_1), OTP-29.1.1.
pub(crate) extern "C" fn check_old_code_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [module] = crate::bif_table::bif_args::<1>(reg);
    let result = (|| -> Result<Term, VmError> {
        let name = global_atoms()
            .text(module.as_atom().ok_or_else(badarg)?)
            .ok_or_else(badarg)?;
        Ok(bool_atom(
            code_tables(erts_active_code_ix()).loaded.has_old(name),
        ))
    })();
    bif_ret(c_p, i, result)
}
