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
    match ets::bif_failure("ets", function, args, Err(error)) {
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

/// One ETS BIF body: the table operation on the scheduler's data, `BIF_ERROR` on failure.
macro_rules! ets_bif {
    ($name:ident, $kind:ident, $module:literal, $function:literal, $arity:literal) => {
        pub(crate) extern "C" fn $name(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
            let Some(process) = crate::native_hooks::process_from_header(c_p) else {
                return 0;
            };
            process.heap.note_bif_entry();
            let x = bif_args::<$arity>(reg);
            let result = ets_body(process, ets::EtsBif::$kind, &x);
            finish_in(c_p, i, $module, $function, &x, result)
        }
    };
}

/// The body of an ETS BIF: the ones with a cached-table fast path, else the general operation.
#[inline(always)]
fn ets_body(process: &mut Process, kind: ets::EtsBif, x: &[Term]) -> Result<Term, VmError> {
    use ets::EtsBif;
    match (kind, x.len()) {
        (EtsBif::LookupElement, _) => ets::ets_lookup_element(process, x),
        (EtsBif::UpdateCounter, _) => ets::ets_update_counter(process, x),
        (EtsBif::Delete, 2) => ets::ets_delete_2(process, x),
        (EtsBif::Info, 2) if x[1] == Term::atom(atoms::BINARY) => {
            // Port of erts/emulator/beam/erl_db.c (ets_info_2: BIF_TRAP1 ets_info_binary_trap).
            Err(VmError::TrapExport(crate::ExportTrap::new(
                process,
                "erts_internal:ets_info_binary/1",
                vec![x[0]],
            )))
        }
        _ => ets::ets_call(process, kind, x),
    }
}

#[inline(always)]
fn finish_in(
    c_p: *mut ProcessHeader,
    i: u64,
    module: &str,
    function: &str,
    args: &[Term],
    result: Result<Term, VmError>,
) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => finish_error_in(c_p, i, module, function, args, error),
    }
}

#[cold]
#[inline(never)]
fn finish_error_in(
    c_p: *mut ProcessHeader,
    i: u64,
    module: &str,
    function: &str,
    args: &[Term],
    error: VmError,
) -> u64 {
    match ets::bif_failure(module, function, args, Err(error)) {
        Err(error) => crate::native_helpers::bif_return_current(c_p, i, error),
        Ok(value) => crate::native_hooks::raw(value),
    }
}

pub(crate) extern "C" fn ets_member_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let x = bif_args::<2>(reg);
    let result = ets::ets_member_2(process, &x);
    finish_in(c_p, i, "ets", "member", &x, result)
}

ets_bif!(
    match_spec_test_3,
    MatchSpecTest,
    "erlang",
    "match_spec_test",
    3
);
ets_bif!(
    ets_lookup_binary_info_2,
    LookupBinaryInfo,
    "erts_internal",
    "ets_lookup_binary_info",
    2
);
ets_bif!(
    ets_raw_first_1,
    RawFirst,
    "erts_internal",
    "ets_raw_first",
    1
);
ets_bif!(ets_raw_next_2, RawNext, "erts_internal", "ets_raw_next", 2);
ets_bif!(
    ets_super_user_1,
    SuperUser,
    "erts_internal",
    "ets_super_user",
    1
);
ets_bif!(ets_new_2, New, "ets", "new", 2);
ets_bif!(ets_whereis_1, Whereis, "ets", "whereis", 1);
ets_bif!(ets_rename_2, Rename, "ets", "rename", 2);
ets_bif!(ets_info_1, Info, "ets", "info", 1);
ets_bif!(ets_info_2, Info, "ets", "info", 2);
ets_bif!(ets_delete_1, Delete, "ets", "delete", 1);
ets_bif!(ets_delete_2, Delete, "ets", "delete", 2);
ets_bif!(
    ets_internal_delete_all_2,
    InternalDeleteAll,
    "ets",
    "internal_delete_all",
    2
);
ets_bif!(ets_setopts_2, SetOpts, "ets", "setopts", 2);
ets_bif!(ets_take_2, Take, "ets", "take", 2);
ets_bif!(ets_slot_2, Slot, "ets", "slot", 2);
ets_bif!(ets_first_1, First, "ets", "first", 1);
ets_bif!(ets_first_lookup_1, FirstLookup, "ets", "first_lookup", 1);
ets_bif!(ets_last_1, Last, "ets", "last", 1);
ets_bif!(ets_last_lookup_1, LastLookup, "ets", "last_lookup", 1);
ets_bif!(ets_next_2, Next, "ets", "next", 2);
ets_bif!(ets_next_lookup_2, NextLookup, "ets", "next_lookup", 2);
ets_bif!(ets_prev_2, Prev, "ets", "prev", 2);
ets_bif!(ets_prev_lookup_2, PrevLookup, "ets", "prev_lookup", 2);
ets_bif!(ets_safe_fixtable_2, SafeFixtable, "ets", "safe_fixtable", 2);
ets_bif!(ets_delete_object_2, DeleteObject, "ets", "delete_object", 2);
ets_bif!(ets_give_away_3, GiveAway, "ets", "give_away", 3);
ets_bif!(ets_select_1, Select, "ets", "select", 1);
ets_bif!(ets_select_2, Select, "ets", "select", 2);
ets_bif!(ets_select_3, Select, "ets", "select", 3);
ets_bif!(
    ets_select_reverse_1,
    SelectReverse,
    "ets",
    "select_reverse",
    1
);
ets_bif!(
    ets_select_reverse_2,
    SelectReverse,
    "ets",
    "select_reverse",
    2
);
ets_bif!(
    ets_select_reverse_3,
    SelectReverse,
    "ets",
    "select_reverse",
    3
);
ets_bif!(ets_match_1, Match, "ets", "match", 1);
ets_bif!(ets_match_2, Match, "ets", "match", 2);
ets_bif!(ets_match_3, Match, "ets", "match", 3);
ets_bif!(ets_match_object_1, MatchObject, "ets", "match_object", 1);
ets_bif!(ets_match_object_2, MatchObject, "ets", "match_object", 2);
ets_bif!(ets_match_object_3, MatchObject, "ets", "match_object", 3);
ets_bif!(
    ets_match_spec_compile_1,
    MatchSpecCompile,
    "ets",
    "match_spec_compile",
    1
);
ets_bif!(
    ets_is_compiled_ms_1,
    IsCompiledMs,
    "ets",
    "is_compiled_ms",
    1
);
ets_bif!(
    ets_internal_request_all_0,
    InternalRequestAll,
    "ets",
    "internal_request_all",
    0
);
ets_bif!(
    ets_match_spec_run_r_3,
    MatchSpecRunR,
    "ets",
    "match_spec_run_r",
    3
);
ets_bif!(ets_select_count_2, SelectCount, "ets", "select_count", 2);
ets_bif!(
    ets_internal_select_delete_2,
    InternalSelectDelete,
    "ets",
    "internal_select_delete",
    2
);
ets_bif!(
    ets_select_replace_2,
    SelectReplace,
    "ets",
    "select_replace",
    2
);
ets_bif!(
    ets_lookup_element_3,
    LookupElement,
    "ets",
    "lookup_element",
    3
);
ets_bif!(
    ets_lookup_element_4,
    LookupElement,
    "ets",
    "lookup_element",
    4
);
ets_bif!(
    ets_update_element_3,
    UpdateElement,
    "ets",
    "update_element",
    3
);
ets_bif!(
    ets_update_element_4,
    UpdateElement,
    "ets",
    "update_element",
    4
);
ets_bif!(
    ets_update_counter_3,
    UpdateCounter,
    "ets",
    "update_counter",
    3
);
ets_bif!(
    ets_update_counter_4,
    UpdateCounter,
    "ets",
    "update_counter",
    4
);

type FreeState = TrapContext<Option<arinsal_ets::Garbage>>;

arinsal_term::magic_payload!(FreeState => free_table_continue_destructor,);

/// The state binary of a trapped `ets:delete/1`: the storage still to release.
// Port of erts/emulator/beam/erl_db.c (ets_delete_1: the DbTable pointer packaged for the
// trap), OTP-29.1.1.
pub(crate) fn new_free_state(
    process: &mut Process,
    garbage: arinsal_ets::Garbage,
) -> Result<Term, VmError> {
    let owner = MagicBin::with_erts_payload_size_and_refn(
        TrapContext::new(Some(garbage)),
        ERTS_FREE_STATE_SIZE,
        arinsal_sched::unique::next_ref_words(),
    );
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap).magic_ref(owner).map_err(|_| {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            atoms::SYSTEM_LIMIT,
        )))
    })
}

const ERTS_FREE_STATE_SIZE: usize = 64;

/// `ets:delete_trap/1`, the hidden export `ets:delete/1` traps to.
// Port of erts/emulator/beam/erl_db.c (ets_delete_trap, free_table_continue), OTP-29.1.1.
pub(crate) extern "C" fn ets_delete_trap_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [state] = bif_args::<1>(reg);
    let initial = process.heap.abi.fcalls.max(0) as isize;
    let mut reds = initial;
    let step = state.with_magic_payload_mut::<FreeState, _>(|holder| {
        holder.0.as_mut().map(|garbage| garbage.step(&mut reds))
    });
    match step.flatten() {
        None => crate::natives::bif::bif_badarg(c_p),
        Some(false) => {
            ets::bump_direct(process, isize::MAX);
            let trap = VmError::TrapExport(crate::ExportTrap::new(
                process,
                "ets:delete_trap/1",
                vec![state],
            ));
            crate::native_helpers::bif_return_current(c_p, i, trap)
        }
        Some(true) => {
            state.with_magic_payload_mut::<FreeState, _>(|holder| holder.0 = None);
            ets::bump_direct(process, initial - reds);
            crate::native_hooks::raw(Term::atom(atoms::TRUE))
        }
    }
}
