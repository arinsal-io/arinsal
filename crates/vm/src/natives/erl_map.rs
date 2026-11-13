//! The yielding map BIFs of erl_map.c.
//!
//! Port of erts/emulator/beam/erl_map.c (maps_from_list_1, maps_from_keys_2, maps_keys_1,
//! maps_values_1 and their YCF helpers) and erts/emulator/beam/utils.c (erts_ycf_trap_driver,
//! erts_ycf_trap_driver_trap_helper), OTP-29.1.1. Each BIF is `bif_table[].f` with
//! `(c_p, reg, I)`. A call that runs out of reductions keeps its walk in a magic binary,
//! disables collection, and `BIF_TRAP`s to its own export with the magic reference in X0 and
//! the other arguments unchanged; the export calls the same body, which recognises its state.

use crate::VmError;
use crate::natives::bif::bif_ret;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifCall, BifError, Ctx, MapsBuildWalk, MapsProjectionWalk, ProcessHeapHandle};
use arinsal_maps::{HashmapMergeContext, MAP_MERGE_LOOP_FACTOR};
use arinsal_term::{MagicRef, Term, TermBuilder, atoms};
use std::sync::{Arc, Mutex};

/// `sizeof(erts_ycf_trap_driver_state_holder)` on a 64-bit build: the magic binary's
/// `orig_size`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver_state_holder), OTP-29.1.1.
const ERTS_YCF_TRAP_HOLDER_SIZE: usize = 24;

/// `iterations_per_red` of maps_from_list_1 and maps_from_keys_2.
const FROM_LIST_ITERATIONS_PER_RED: i64 = 40;
/// `iterations_per_red` of maps_keys_1 and maps_values_1.
const PROJECTION_ITERATIONS_PER_RED: i64 = 15;

/// The YCF trap state of `maps:from_list/1` and `maps:from_keys/2`.
type BuildState = Mutex<Option<MapsBuildWalk>>;
/// The YCF trap state of `maps:keys/1` and `maps:values/1`.
type ProjectionState = Mutex<Option<MapsProjectionWalk>>;

/// `maps:from_list/1`.
// Port of erts/emulator/beam/erl_map.c (maps_from_list_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_from_list_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    maps_build(c_p, i, "maps:from_list/1", false)
}

/// `maps:from_keys/2`.
// Port of erts/emulator/beam/erl_map.c (maps_from_keys_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_from_keys_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    maps_build(c_p, i, "maps:from_keys/2", true)
}

/// `maps:keys/1`.
// Port of erts/emulator/beam/erl_map.c (maps_keys_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_keys_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    maps_projection(c_p, i, "maps:keys/1", true)
}

/// `maps:values/1`.
// Port of erts/emulator/beam/erl_map.c (maps_values_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_values_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    maps_projection(c_p, i, "maps:values/1", false)
}

/// `const long reds = iterations_per_red * ERTS_BIF_REDS_LEFT(p)`.
#[inline(always)]
fn ycf_reds(process: &crate::Process, iterations_per_red: i64) -> i64 {
    i64::from(process.heap.abi.fcalls.max(0)) * iterations_per_red
}

/// `BUMP_REDS(p, (init_reds - nr_of_reductions) / iterations_per_red)`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver) and bif.h (BUMP_REDS), OTP-29.1.1.
#[inline(always)]
fn ycf_bump_reds(process: &mut crate::Process, init: i64, left: i64, iterations_per_red: i64) {
    let used = ((init - left) / iterations_per_red).clamp(0, i64::from(i32::MAX));
    let fcalls = i64::from(process.heap.abi.fcalls) - used;
    process.heap.abi.fcalls = fcalls.max(0) as i32;
}

/// `is_boxed(term)`: the primary tag test `is_internal_magic_ref` starts with.
#[inline(always)]
fn is_boxed(term: Term) -> bool {
    term.tagged_word() & 3 == 2
}

/// The arguments of the running BIF: `BIF__ARGS`.
#[inline(always)]
fn bif_args<const N: usize>(process: &crate::Process) -> [Term; N] {
    std::array::from_fn(|index| process.x[index])
}

/// `BIF_ERROR(p, reason)` of a body below.
#[cold]
#[inline(never)]
fn ycf_error(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    error: arinsal_bifs::BifError,
) -> u64 {
    let (module, rest) = export.split_once(':').unwrap_or(("maps", export));
    let function = rest.split_once('/').map_or(rest, |(function, _)| function);
    let args = process.x[..arity].to_vec();
    let error = crate::exceptions::bif_error(process, module, function, &args, error);
    bif_ret(c_p, i, Err(error))
}

/// `erts_ycf_trap_driver_trap_helper`: `reg[0]` is the state, the rest are the BIF's own
/// arguments, and the trap goes to the BIF's export.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver_trap_helper), OTP-29.1.1.
#[cold]
#[inline(never)]
fn ycf_trap(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    state_mref: Term,
) -> u64 {
    let mut args = process.x[..arity].to_vec();
    args[0] = state_mref;
    let trap = VmError::TrapExport(crate::ExportTrap::new(process, export, args));
    bif_ret(c_p, i, Err(trap))
}

/// `erts_create_magic_binary(sizeof(erts_ycf_trap_driver_state_holder), …)` and
/// `erts_mk_magic_ref` of a new trap state.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver: the "We need to trap" arm),
// OTP-29.1.1.
fn create_state_mref<T: std::any::Any + Send + Sync>(
    process: &mut crate::Process,
    state: T,
    c_payload_size: usize,
) -> Result<Term, VmError> {
    let state: Arc<MagicRef> = MagicRef::with_erts_payload_size_and_refn(
        state,
        c_payload_size,
        arinsal_bifs::next_ref_words(),
    );
    let mut heap = ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap).magic_ref(state).map_err(|_| {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            atoms::SYSTEM_LIMIT,
        )))
    })
}

/// `erts_ycf_trap_driver` over `maps_from_list_1_helper` / `maps_from_keys_2_helper`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver) and erl_map.c
// (maps_from_keys_2_helper, maps_from_list_1_helper, hashmap_from_validated_list), OTP-29.1.1.
#[inline(always)]
fn maps_build(c_p: *mut ProcessHeader, i: u64, export: &'static str, from_keys: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let arity = if from_keys { 2 } else { 1 };
    let [list, fill] = bif_args::<2>(process);
    let init = ycf_reds(process, FROM_LIST_ITERATIONS_PER_RED);
    let mut reds = init;
    // Continue a trapped call: the state is ours when its holder is a `BuildState`.
    let resumed = is_boxed(list).then(|| {
        list.with_magic_payload::<BuildState, _>(|state| {
            // erts_set_gc_state(p, 1)
            process.set_gc_enabled(true);
            let mut guard = state.lock().expect("maps build state");
            let walk = guard.as_mut()?;
            let mut heap = ProcessHeapHandle(&mut process.heap);
            let mut call = BifCall::default();
            let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
            let step = walk.step(&mut ctx, &mut reds);
            if !matches!(step, Ok(None)) {
                // The trap state is gone: ycf_continue returned without a new trap state.
                *guard = None;
            }
            Some(step)
        })
    });
    let step = match resumed.flatten() {
        Some(Some(step)) => {
            ycf_bump_reds(process, init, reds, FROM_LIST_ITERATIONS_PER_RED);
            match step {
                Ok(Some(value)) => return crate::native_hooks::raw(value),
                Ok(None) => {
                    process.set_gc_enabled(false);
                    return ycf_trap(c_p, i, process, export, arity, list);
                }
                Err(error) => return ycf_error(c_p, i, process, export, arity, error),
            }
        }
        // A spent state (its holder has no trap state) starts a new call, as erts does.
        _ => {
            let mut walk = if from_keys {
                MapsBuildWalk::from_keys(list, fill)
            } else {
                MapsBuildWalk::from_list(list)
            };
            let step = {
                let mut heap = ProcessHeapHandle(&mut process.heap);
                let mut call = BifCall::default();
                let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
                walk.step(&mut ctx, &mut reds)
            };
            (walk, step)
        }
    };
    let (walk, step) = step;
    ycf_bump_reds(process, init, reds, FROM_LIST_ITERATIONS_PER_RED);
    match step {
        Ok(Some(value)) => crate::native_hooks::raw(value),
        Ok(None) => build_first_trap(c_p, i, process, export, arity, walk),
        Err(error) => ycf_error(c_p, i, process, export, arity, error),
    }
}

/// The first yield of a `maps:from_list/1` / `maps:from_keys/2` call: its state binary, then
/// `erts_set_gc_state(p, 0)` and the trap.
#[cold]
#[inline(never)]
fn build_first_trap(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    walk: MapsBuildWalk,
) -> u64 {
    let state_mref = match create_state_mref::<BuildState>(
        process,
        Mutex::new(Some(walk)),
        ERTS_YCF_TRAP_HOLDER_SIZE,
    ) {
        Ok(state_mref) => state_mref,
        Err(error) => return bif_ret(c_p, i, Err(error)),
    };
    process.set_gc_enabled(false);
    ycf_trap(c_p, i, process, export, arity, state_mref)
}

/// `erts_ycf_trap_driver` over `maps_keys_1_helper` / `maps_values_1_helper`.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver) and erl_map.c (maps_keys_1_helper,
// maps_values_1_helper, hashmap_keys, hashmap_values), OTP-29.1.1.
#[inline(always)]
fn maps_projection(c_p: *mut ProcessHeader, i: u64, export: &'static str, keys: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let map = process.x[0];
    // `is_internal_magic_ref(bif_args[0])` with the driver's destructor: continue a trapped
    // call before looking at the argument as a map.
    if is_boxed(map)
        && map.with_magic_payload::<ProjectionState, _>(|state| {
            state.lock().is_ok_and(|walk| walk.is_some())
        }) == Some(true)
    {
        return projection_resume(c_p, i, process, export, map);
    }
    // The flatmap arm runs without consuming YCF reductions and never yields.
    let flat = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut call = BifCall::default();
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
        MapsProjectionWalk::start_flat(&mut ctx, map, keys)
    };
    match flat {
        Ok(Some(value)) => crate::native_hooks::raw(value),
        Ok(None) => projection_hashmap(c_p, i, process, export, keys, map),
        Err(error) => ycf_error(c_p, i, process, export, 1, error),
    }
}

/// The hashmap arm of a new `maps:keys/1` / `maps:values/1` call.
#[inline(never)]
fn projection_hashmap(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    keys: bool,
    map: Term,
) -> u64 {
    let init = ycf_reds(process, PROJECTION_ITERATIONS_PER_RED);
    let mut reds = init;
    let started = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut call = BifCall::default();
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut call);
        MapsProjectionWalk::start_hashmap(&mut ctx, map, keys)
    };
    let mut walk = match started {
        Ok(walk) => walk,
        Err(error) => return ycf_error(c_p, i, process, export, 1, error),
    };
    let done = walk.step(&mut reds);
    ycf_bump_reds(process, init, reds, PROJECTION_ITERATIONS_PER_RED);
    if done {
        return crate::native_hooks::raw(walk.finish());
    }
    let state_mref = match create_state_mref::<ProjectionState>(
        process,
        Mutex::new(Some(walk)),
        ERTS_YCF_TRAP_HOLDER_SIZE,
    ) {
        Ok(state_mref) => state_mref,
        Err(error) => return bif_ret(c_p, i, Err(error)),
    };
    process.set_gc_enabled(false);
    ycf_trap(c_p, i, process, export, 1, state_mref)
}

/// X0 is the trap state of a yielded call: the next slice of its walk.
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver: "Continue a trapped call"),
// OTP-29.1.1.
#[cold]
#[inline(never)]
fn projection_resume(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    state_mref: Term,
) -> u64 {
    let init = ycf_reds(process, PROJECTION_ITERATIONS_PER_RED);
    let mut reds = init;
    let resumed = state_mref.with_magic_payload::<ProjectionState, _>(|state| {
        let mut guard = state.lock().expect("maps projection state");
        let walk = guard.as_mut()?;
        if !walk.step(&mut reds) {
            return Some(None);
        }
        guard.take().map(|walk| Some(walk.finish()))
    });
    let Some(Some(result)) = resumed else {
        unreachable!("the caller checked the trap state");
    };
    // erts_set_gc_state(p, 1) before ycf_continue; BUMP_REDS after it.
    process.set_gc_enabled(true);
    ycf_bump_reds(process, init, reds, PROJECTION_ITERATIONS_PER_RED);
    match result {
        Some(value) => crate::native_hooks::raw(value),
        None => {
            process.set_gc_enabled(false);
            ycf_trap(c_p, i, process, export, 1, state_mref)
        }
    }
}

/// `sizeof(HashmapMergeContext)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/erl_map.c (HashmapMergeContext), OTP-29.1.1.
const ERTS_HASHMAP_MERGE_CONTEXT_SIZE: usize = 56;

/// The trap state of `hashmap_merge`: the `HashmapMergeContext` of its magic binary.
type MergeState = Mutex<Option<HashmapMergeContext>>;

/// `BIF_P->fvalue = value; BIF_ERROR(BIF_P, BADMAP)` (`tag` is `badmap`) or `BADKEY`: the
/// `{Tag, Value}` reason `expand_error_value` builds, raised with the BIF's frame.
// Port of erts/emulator/beam/beam_common.c (expand_error_value), OTP-29.1.1.
#[cold]
#[inline(never)]
fn bif_error_tagged(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    tag: Term,
    value: Term,
) -> u64 {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let error = match TermBuilder::new(&mut heap).tuple2(tag, value) {
        Ok(reason) => BifError::Error(reason),
        Err(_) => BifError::SystemLimit,
    };
    ycf_error(c_p, i, process, export, arity, error)
}

/// `BIF_ERROR(p, SYSTEM_LIMIT)` of a failed `HAlloc`, which erts cannot hit (the heap grows).
#[cold]
#[inline(never)]
fn system_limit(c_p: *mut ProcessHeader, i: u64) -> u64 {
    bif_ret(
        c_p,
        i,
        Err(VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            atoms::SYSTEM_LIMIT,
        )))),
    )
}

/// `maps:merge/2`.
// Port of erts/emulator/beam/erl_map.c (maps_merge_2, flatmap_merge, map_merge_mixed),
// OTP-29.1.1.
pub(crate) extern "C" fn maps_merge_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (map_a, map_b) = (process.x[0], process.x[1]);
    if map_a == map_b {
        // Merging upon itself always returns itself.
        if map_a.is_flatmap() || map_a.is_hashmap() {
            return crate::native_hooks::raw(map_a);
        }
        return bif_error_tagged(
            c_p,
            i,
            process,
            "maps:merge/2",
            2,
            Term::atom(atoms::BADMAP),
            map_a,
        );
    }
    if map_a.is_flatmap() {
        if map_b.is_flatmap() {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            return match arinsal_maps::flatmap_merge(map_a, map_b, &mut heap) {
                Ok(value) => crate::native_hooks::raw(value),
                Err(_) => system_limit(c_p, i),
            };
        }
        if map_b.is_hashmap() {
            // Will always become a tree.
            return map_merge_mixed(c_p, i, process, map_a, map_b, false);
        }
        return bif_error_tagged(
            c_p,
            i,
            process,
            "maps:merge/2",
            2,
            Term::atom(atoms::BADMAP),
            map_b,
        );
    }
    if map_a.is_hashmap() {
        if map_b.is_hashmap() {
            let merge = HashmapMergeContext::new(map_a, map_b, false);
            return hashmap_merge(c_p, i, process, merge, None);
        }
        if map_b.is_flatmap() {
            return map_merge_mixed(c_p, i, process, map_b, map_a, true);
        }
        return bif_error_tagged(
            c_p,
            i,
            process,
            "maps:merge/2",
            2,
            Term::atom(atoms::BADMAP),
            map_b,
        );
    }
    bif_error_tagged(
        c_p,
        i,
        process,
        "maps:merge/2",
        2,
        Term::atom(atoms::BADMAP),
        map_a,
    )
}

/// Convert the flatmap to a HAMT, then `hashmap_merge`.
// Port of erts/emulator/beam/erl_map.c (map_merge_mixed), OTP-29.1.1.
fn map_merge_mixed(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    flat: Term,
    tree: Term,
    swap_args: bool,
) -> u64 {
    let converted = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::map_merge_mixed_hashmap(flat, &mut heap)
    };
    match converted {
        Ok(None) => crate::native_hooks::raw(tree),
        Ok(Some(res)) => {
            let merge = HashmapMergeContext::new(res, tree, swap_args);
            hashmap_merge(c_p, i, process, merge, None)
        }
        Err(_) => system_limit(c_p, i),
    }
}

/// `maps:merge_trap/1`, `hashmap_merge_trap_export`.
// Port of erts/emulator/beam/erl_map.c (maps_merge_trap_1), OTP-29.1.1.
pub(crate) extern "C" fn maps_merge_trap_1(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let state_mref = process.x[0];
    // `erts_magic_ref2bin(BIF_ARG_1)`: only `hashmap_merge` traps here, with its own state.
    let merge = state_mref
        .with_magic_payload::<MergeState, _>(|state| state.lock().ok()?.take())
        .flatten();
    match merge {
        Some(merge) => hashmap_merge(c_p, i, process, merge, Some(state_mref)),
        None => ycf_error(
            c_p,
            i,
            process,
            "maps:merge_trap/1",
            1,
            arinsal_bifs::BifError::BADARG,
        ),
    }
}

/// `hashmap_merge`: runs the merge for `MAP_MERGE_LOOP_FACTOR * ERTS_BIF_REDS_LEFT(p)` loop
/// steps, then returns the map (re-enabling collection after a trap) or `BIF_TRAP1`s to
/// `hashmap_merge_trap_export` with the context's magic reference.
// Port of erts/emulator/beam/erl_map.c (hashmap_merge: the ctx == NULL / resume_from_trap
// entries, `BUMP_REDS`, and the `trap:` label), OTP-29.1.1.
fn hashmap_merge(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut merge: HashmapMergeContext,
    trap_bin: Option<Term>,
) -> u64 {
    let factor = MAP_MERGE_LOOP_FACTOR;
    let initial_reds = (process.heap.abi.fcalls.max(0) as isize).saturating_mul(factor);
    let mut reds = initial_reds;
    let merged = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::hashmap_merge(&mut merge, &mut reds, &mut heap)
    };
    match merged {
        Ok(Some(value)) => {
            if trap_bin.is_some() {
                // erts_set_gc_state(p, 1)
                process.set_gc_enabled(true);
            }
            ycf_bump_reds(process, initial_reds as i64, reds as i64, factor as i64);
            crate::native_hooks::raw(value)
        }
        Ok(None) => {
            let state_mref = match trap_bin {
                Some(state_mref) => {
                    let _ = state_mref.with_magic_payload::<MergeState, _>(|state| {
                        *state.lock().expect("hashmap merge state") = Some(merge);
                    });
                    state_mref
                }
                None => {
                    let created = create_state_mref::<MergeState>(
                        process,
                        Mutex::new(Some(merge)),
                        ERTS_HASHMAP_MERGE_CONTEXT_SIZE,
                    );
                    match created {
                        Ok(state_mref) => {
                            process.set_gc_enabled(false);
                            state_mref
                        }
                        Err(error) => return bif_ret(c_p, i, Err(error)),
                    }
                }
            };
            // BUMP_ALL_REDS(p); BIF_TRAP1(&hashmap_merge_trap_export, p, ctx->trap_bin)
            crate::natives::erl_bif_chksum::bump_all_reds(process);
            let trap = crate::natives::erl_bif_lists::bif_trap(
                process,
                "maps:merge_trap/1",
                vec![state_mref],
            );
            bif_ret(c_p, i, Err(trap))
        }
        Err(_) => ycf_error(
            c_p,
            i,
            process,
            "maps:merge/2",
            2,
            arinsal_bifs::BifError::SystemLimit,
        ),
    }
}


/// `maps:find/2`.
// Port of erts/emulator/beam/erl_map.c (maps_find_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_find_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, map) = (process.x[0], process.x[1]);
    if !(map.is_flatmap() || map.is_hashmap()) {
        return bif_error_tagged(
            c_p,
            i,
            process,
            "maps:find/2",
            2,
            Term::atom(atoms::BADMAP),
            map,
        );
    }
    match arinsal_maps::get(map, key) {
        Ok(Some(value)) => {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            match TermBuilder::new(&mut heap).tuple2(Term::atom(atoms::OK), value) {
                Ok(res) => crate::native_hooks::raw(res),
                Err(_) => system_limit(c_p, i),
            }
        }
        Ok(None) => crate::native_hooks::raw(Term::atom(atoms::ERROR)),
        Err(_) => bif_error_tagged(
            c_p,
            i,
            process,
            "maps:find/2",
            2,
            Term::atom(atoms::BADMAP),
            map,
        ),
    }
}

/// `maps:get/2`.
// Port of erts/emulator/beam/erl_map.c (maps_get_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_get_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, map) = (process.x[0], process.x[1]);
    if map.is_flatmap() || map.is_hashmap() {
        if let Ok(Some(value)) = arinsal_maps::get(map, key) {
            return crate::native_hooks::raw(value);
        }
        return bif_error_tagged(
            c_p,
            i,
            process,
            "maps:get/2",
            2,
            Term::atom(atoms::BADKEY),
            key,
        );
    }
    bif_error_tagged(
        c_p,
        i,
        process,
        "maps:get/2",
        2,
        Term::atom(atoms::BADMAP),
        map,
    )
}

/// `maps:is_key/2`.
// Port of erts/emulator/beam/erl_map.c (maps_is_key_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_is_key_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, map) = (process.x[0], process.x[1]);
    if map.is_flatmap() || map.is_hashmap() {
        let found = matches!(arinsal_maps::get(map, key), Ok(Some(_)));
        return crate::native_hooks::raw(Term::atom(if found {
            atoms::TRUE
        } else {
            atoms::FALSE
        }));
    }
    bif_error_tagged(
        c_p,
        i,
        process,
        "maps:is_key/2",
        2,
        Term::atom(atoms::BADMAP),
        map,
    )
}

/// The failure of a map operation as `BIF_ERROR` with the BIF's frame: `{badmap, Map}` or
/// `{badkey, Key}`.
// Port of erts/emulator/beam/erl_map.c (BIF_ERROR(BADMAP) / BIF_ERROR(BADKEY) of
// maps_put_3, maps_remove_2, maps_update_3, maps_take_2), OTP-29.1.1.
#[cold]
#[inline(never)]
fn map_failure(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    export: &'static str,
    arity: usize,
    error: arinsal_maps::MapError,
) -> u64 {
    use arinsal_maps::MapError;
    match error {
        MapError::Badmap(map) => bif_error_tagged(
            c_p,
            i,
            process,
            export,
            arity,
            Term::atom(atoms::BADMAP),
            map,
        ),
        MapError::Badkey(key) => bif_error_tagged(
            c_p,
            i,
            process,
            export,
            arity,
            Term::atom(atoms::BADKEY),
            key,
        ),
        MapError::HeapFull { .. } => system_limit(c_p, i),
        _ => ycf_error(c_p, i, process, export, arity, BifError::BADARG),
    }
}

/// `maps:put/3`.
// Port of erts/emulator/beam/erl_map.c (maps_put_3, erts_maps_put), OTP-29.1.1.
pub(crate) extern "C" fn maps_put_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, value, map) = (process.x[0], process.x[1], process.x[2]);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::put(map, key, value, &mut heap)
    };
    match result {
        Ok(res) => crate::native_hooks::raw(res),
        Err(error) => map_failure(c_p, i, process, "maps:put/3", 3, error),
    }
}

/// `maps:update/3`.
// Port of erts/emulator/beam/erl_map.c (maps_update_3, erts_maps_update), OTP-29.1.1.
pub(crate) extern "C" fn maps_update_3(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, value, map) = (process.x[0], process.x[1], process.x[2]);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::update(map, key, value, &mut heap)
    };
    match result {
        Ok(res) => crate::native_hooks::raw(res),
        Err(error) => map_failure(c_p, i, process, "maps:update/3", 3, error),
    }
}

/// `maps:remove/2`.
// Port of erts/emulator/beam/erl_map.c (maps_remove_2, erts_maps_remove), OTP-29.1.1.
pub(crate) extern "C" fn maps_remove_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, map) = (process.x[0], process.x[1]);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        arinsal_maps::remove(map, key, &mut heap)
    };
    match result {
        Ok(res) => crate::native_hooks::raw(res),
        Err(error) => map_failure(c_p, i, process, "maps:remove/2", 2, error),
    }
}

/// `maps:take/2`.
// Port of erts/emulator/beam/erl_map.c (maps_take_2), OTP-29.1.1.
pub(crate) extern "C" fn maps_take_2(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (key, map) = (process.x[0], process.x[1]);
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let result = arinsal_maps::take(map, key, &mut heap).and_then(|taken| match taken {
        Some((value, rest)) => TermBuilder::new(&mut heap)
            .tuple2(value, rest)
            .map(Some)
            .map_err(|_| arinsal_maps::MapError::HeapFull { need_words: 3 }),
        None => Ok(None),
    });
    match result {
        Ok(Some(res)) => crate::native_hooks::raw(res),
        Ok(None) => crate::native_hooks::raw(Term::atom(atoms::ERROR)),
        Err(error) => map_failure(c_p, i, process, "maps:take/2", 2, error),
    }
}
