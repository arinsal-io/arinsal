//! The ETS BIFs of erl_db.c that are `bif_table[].f` bodies: `ets:insert/2`,
//! `ets:insert_new/2` and `ets:lookup/2`.
//!
//! Each is called with `(c_p, reg, I)` by `call_light_bif_shared`. A value returns in x0, a
//! failure is `BIF_ERROR`. A list insert traps to its own BIF with a magic-binary state.

use crate::bif_table::bif_args;
use crate::bif_traps::TrapContext;
use crate::natives::ets;
use crate::proc_create::EtsInsert;
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::{MagicBin, Term, TermBuilder, atoms};

/// `BIF_RET` / `BIF_ERROR` of an ETS body. A failure that is not an exception is an outcome only the
/// scheduler completes (a yield).
#[inline(always)]
fn finish(
    c_p: *mut ProcessHeader,
    i: u64,
    function: &str,
    args: &[arinsal_term::Term],
    result: Result<arinsal_term::Term, VmError>,
) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => finish_error(c_p, i, function, args, error),
    }
}

#[cold]
#[inline(never)]
fn finish_error(
    c_p: *mut ProcessHeader,
    i: u64,
    function: &str,
    args: &[arinsal_term::Term],
    error: VmError,
) -> u64 {
    match ets::bif_failure(function, args, Err(error)) {
        Err(error @ VmError::Trap(_)) => crate::native_helpers::bif_return_current(c_p, i, error),
        Ok(value) => crate::native_hooks::raw(value),
        // BIF_YIELD of a busy table, or an outcome only the scheduler completes.
        Err(error) => crate::native_helpers::bif_return_current(c_p, i, error),
    }
}

fn insert_body<const NEW: bool>(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let x = bif_args::<2>(reg);
    // `is_list(arg2) && CDR(arg2) != NIL || is_internal_magic_ref(arg2)`.
    if x[1].is_magic_ref() || ets::is_list_insert(x[1]) {
        return ets_insert_2_list_driver::<NEW>(c_p, reg, i, process, x);
    }
    let result = ets::ets_insert_2::<NEW>(process, &x);
    finish(
        c_p,
        i,
        if NEW { "insert_new" } else { "insert" },
        &x,
        result,
    )
}

/// `ets_insert_2_list_info` in the magic binary a trapped list insert keeps: the slice state and
/// the list argument the failure names.
struct ListInfo {
    state: EtsInsert,
    list: Term,
}

type ListState = TrapContext<Option<ListInfo>>;

arinsal_term::magic_payload!(ListState => ets_insert_2_list_yield_dtor,);

/// `ets_insert_2_list_driver`: start a list insert, or continue the one its state binary holds,
/// and trap to the BIF itself with `(tid, state_mref)` until it has finished.
// Port of erts/emulator/beam/erl_db.c (ets_insert_2_list_driver), OTP-29.1.1.
fn ets_insert_2_list_driver<const NEW: bool>(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut Process,
    x: [Term; 2],
) -> u64 {
    let [tid, list] = x;
    let mut state_mref = None;
    let (state, objects) = if list.is_magic_ref() {
        // `ERTS_MAGIC_BIN_DESTRUCTOR(state_bin) != ets_insert_2_list_yield_dtor`: BADARG.
        match list.with_magic_payload_mut::<ListState, _>(|holder| holder.0.take()) {
            Some(Some(info)) => {
                // erts_set_gc_state(p, 1)
                process.set_gc_enabled(true);
                state_mref = Some(list);
                (Some(info.state), info.list)
            }
            _ => return crate::natives::bif::bif_badarg(c_p),
        }
    } else {
        (None, list)
    };
    let own_list_insert = matches!(state, Some(EtsInsert::Global(_)));
    if let Err(error) = ets::help_busy_table(process, tid, own_list_insert) {
        return match state {
            Some(state) => trap_list(c_p, reg, i, process, NEW, tid, objects, state, state_mref),
            None => finish_error(c_p, i, function_name::<NEW>(), &x, error),
        };
    }
    let Some(caller) = process.self_pid.and_then(|pid| pid.to_term()) else {
        return crate::natives::bif::bif_badarg(c_p);
    };
    match ets::insert_list(process, caller, NEW, tid, objects, state) {
        Ok(ets::ListInsert::Value(value)) => crate::native_hooks::raw(value),
        Ok(ets::ListInsert::Trap(state)) => {
            trap_list(c_p, reg, i, process, NEW, tid, objects, state, state_mref)
        }
        Err(error) => {
            // `ERTS_BIF_ERROR_TRAPPED2(p, freason, BIF_TRAP_EXPORT(bix), ctx->tid, ctx->list)`.
            crate::bif_table::set_bif_arg(reg, 1, objects);
            finish_error(c_p, i, function_name::<NEW>(), &[tid, objects], error)
        }
    }
}

const fn function_name<const NEW: bool>() -> &'static str {
    if NEW { "insert_new" } else { "insert" }
}

/// `erts_create_magic_binary` and `erts_mk_magic_ref` of the first trap, then
/// `erts_set_gc_state(p, 0)` and `BIF_TRAP2(BIF_TRAP_EXPORT(bix), p, tid, state_mref)`.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn trap_list(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
    process: &mut Process,
    insert_new: bool,
    tid: Term,
    list: Term,
    state: EtsInsert,
    state_mref: Option<Term>,
) -> u64 {
    let info = ListInfo { state, list };
    let state_mref = match state_mref {
        Some(mref) => {
            mref.with_magic_payload_mut::<ListState, _>(|holder| holder.0 = Some(info));
            mref
        }
        None => {
            let owner = MagicBin::with_erts_payload_size_and_refn(
                TrapContext::new(Some(info)),
                ERTS_LIST_STATE_SIZE,
                arinsal_sched::unique::next_ref_words(),
            );
            let mut heap = ProcessHeapHandle(&mut process.heap);
            match TermBuilder::new(&mut heap).magic_ref(owner) {
                Ok(mref) => mref,
                Err(_) => {
                    return crate::native_helpers::bif_return_current(
                        c_p,
                        i,
                        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                            atoms::SYSTEM_LIMIT,
                        ))),
                    );
                }
            }
        }
    };
    process.set_gc_enabled(false);
    // The slice is spent: BUMP_REDS to the end.
    ets::bump_direct(process, isize::MAX);
    let export = if insert_new {
        "ets:insert_new/2"
    } else {
        "ets:insert/2"
    };
    let trap = VmError::TrapExport(crate::ExportTrap::new(
        process,
        export,
        vec![tid, state_mref],
    ));
    crate::native_helpers::bif_return_current(c_p, i, trap)
}

/// `sizeof(ets_insert_2_list_info)`: the payload size the magic binary reports.
const ERTS_LIST_STATE_SIZE: usize = 88;

/// `ets:insert/2`.
// Port of erts/emulator/beam/erl_db.c (ets_insert_2), OTP-29.1.1.
pub(crate) extern "C" fn ets_insert_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    insert_body::<false>(c_p, reg, i)
}

/// `ets:insert_new/2`.
// Port of erts/emulator/beam/erl_db.c (ets_insert_new_2), OTP-29.1.1.
pub(crate) extern "C" fn ets_insert_new_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    insert_body::<true>(c_p, reg, i)
}

/// `ets:lookup/2`.
// Port of erts/emulator/beam/erl_db.c (ets_lookup_2), OTP-29.1.1.
pub(crate) extern "C" fn ets_lookup_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let x = bif_args::<2>(reg);
    let result = ets::ets_lookup_2(process, &x);
    finish(c_p, i, "lookup", &x, result)
}
