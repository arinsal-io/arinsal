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
use arinsal_bifs::{BifCall, Ctx, MapsBuildWalk, MapsProjectionWalk, ProcessHeapHandle};
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
) -> Result<Term, VmError> {
    let state: Arc<MagicRef> = MagicRef::with_erts_payload_size_and_refn(
        state,
        ERTS_YCF_TRAP_HOLDER_SIZE,
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
    let state_mref = match create_state_mref::<BuildState>(process, Mutex::new(Some(walk))) {
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
    let state_mref = match create_state_mref::<ProjectionState>(process, Mutex::new(Some(walk))) {
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
