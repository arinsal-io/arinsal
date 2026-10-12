//! Resumable BIF calls and their private continuation exports.

use super::*;
use arinsal_bifs::BifError;
use arinsal_term::{MagicRef, global_atoms};
use smallvec::SmallVec;
use std::sync::{Arc, Mutex};

pub(crate) enum TrapResult {
    Done {
        value: Term,
        reductions: u32,
    },
    Failed {
        error: BifError,
        reductions: u32,
    },
    Yield {
        continuation: &'static str,
        state: Arc<MagicRef>,
        reductions: u32,
    },
}

pub(crate) type Handler = fn(
    &mut Process,
    &[Term],
    Option<&Arc<MagicRef>>,
    Option<arinsal_sched::Pid>,
    bool,
) -> Result<TrapResult, BifError>;

/// A trapping BIF and the continuation export it traps to.
pub(crate) struct Entry {
    module: &'static str,
    function: &'static str,
    arity: u8,
    continuation: &'static str,
    handler: Handler,
}

const CODE_PERMISSION_CONTINUATION: &str = "erts_debug:set_internal_state/2";
const IOLIST_CONTINUATION: &str = "erts_internal:list_to_bitstring_continue/1";
const IOLIST_SIZE_CONTINUATION: &str = "erts_internal:iolist_size_continue/1";
const BINARY_TO_TERM_CONTINUATION: &str = "erts_internal:binary_to_term_trap/1";
const BINARY_COPY_CONTINUATION: &str = "erlang:binary_copy_trap/3";
const TERM_TO_BINARY_CONTINUATION: &str = "erts_internal:term_to_binary_trap/1";
const BINARY_SEARCH_CONTINUATION: &str = "erlang:binary_find_trap/3";
const PTAB_LIST_CONTINUATION: &str = "erlang:ptab_list_continue/2";
const MAPS_MERGE_CONTINUATION: &str = "maps:merge_trap/1";
const MAPS_KEYS_CONTINUATION: &str = "maps:keys/1";
const MAPS_VALUES_CONTINUATION: &str = "maps:values/1";
const MAPS_FROM_LIST_CONTINUATION: &str = "maps:from_list/1";
const MAPS_FROM_KEYS_CONTINUATION: &str = "maps:from_keys/2";
const SUBTRACT_CONTINUATION: &str = "erlang:--/2";
const CONTEXT_REDS: usize = 4000;

/// `beam_bif_export_trap`. `BIF_TRAP` points `c_p->i` here; it is not a BEAM function, so a
/// backtrace names it "unknown function".
// Port of erts/emulator/beam/bif.h:316-326 (ERTS_BIF_PREP_TRAP under BEAMASM) and
// jit/arm/beam_asm_global.cpp:145 (emit_bif_export_trap), OTP-29.1.1.
pub(crate) fn bif_export_trap_pc() -> usize {
    bif_export_trap as *const () as usize
}

fn bif_export_trap() {}

/// A trapped BIF is scheduled out at `beam_bif_export_trap` with the caller's return
/// address on the stack, the way `emit_enter_erlang_frame` leaves it for the export call.
pub(crate) fn note_export_trap(process: &mut Process) {
    let resume = process
        .cold
        .as_ref()
        .and_then(|cold| cold.native_retry_site)
        .map(|(pc, _)| pc)
        .filter(|pc| crate::native_bridge::is_native_function_at(*pc));
    if let Some(resume) = resume {
        let top = process
            .heap
            .stack_get(0)
            .map(|word| word.tagged_word() as usize)
            .unwrap_or(0);
        // The export trampoline and the light-BIF trap path already pushed this CP.
        if top != resume {
            let _ = process.push_native_continuation(resume);
        }
    }
    // `push_native_continuation` republishes the header and clears `i`.
    process.header.i = bif_export_trap as *const u8 as *const _;
}

fn clear_export_trap(process: &mut Process) {
    if process.header.i as usize == bif_export_trap_pc() {
        process.header.i = std::ptr::null();
    }
}

// Port of erts/emulator/beam/erl_bif_lists.c:1246 (lists_reverse_2), OTP-29.1.1.
// The fill lives in `arinsal_bifs::lists_reverse` (on-heap, then alloc). This
// handler only supplies the reduction budget and the trap state.
fn lists_reverse(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    let reds = process.reductions.max(0).min(CONTEXT_REDS as i32) as usize;
    let max_cells = reds
        .saturating_mul(arinsal_bifs::REVERSE_CELLS_PER_RED)
        .max(1);
    let (list, tail) = if let Some(state) = state {
        let saved = state
            .downcast_ref::<Mutex<arinsal_bifs::ReverseCont>>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        (saved.list(), saved.tail())
    } else {
        (args[0], args[1])
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let step = arinsal_bifs::lists_reverse(&mut ctx, list, tail, max_cells)?;
    let reductions = ctx.reductions();
    Ok(match step {
        arinsal_bifs::ReverseStep::Done(value) => TrapResult::Done { value, reductions },
        arinsal_bifs::ReverseStep::Trap(cont) => TrapResult::Yield {
            continuation: "lists:reverse/2",
            state: MagicRef::new(Mutex::new(cont)),
            reductions,
        },
    })
}

fn lists_member_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    let reds = process.reductions.max(0).min(CONTEXT_REDS as i32) as usize;
    let max_iter = reds.saturating_mul(arinsal_bifs::MEMBER_PER_RED);
    let (term, list) = if let Some(state) = state {
        let saved = state
            .downcast_ref::<Mutex<arinsal_bifs::MemberCont>>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        (saved.term(), saved.list())
    } else {
        (args[0], args[1])
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let step = match arinsal_bifs::lists_member(&mut ctx, term, list, max_iter) {
        Ok(step) => step,
        Err(error) => {
            return Ok(TrapResult::Failed {
                error,
                reductions: ctx.reductions(),
            });
        }
    };
    let reductions = ctx.reductions();
    Ok(match step {
        arinsal_bifs::MemberStep::Done(found) => TrapResult::Done {
            value: bool_atom(found),
            reductions,
        },
        arinsal_bifs::MemberStep::More(cont) => TrapResult::Yield {
            continuation: "lists:member/2",
            state: MagicRef::new(Mutex::new(cont)),
            reductions,
        },
    })
}

fn lists_key_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    op: arinsal_bifs::KeyOp,
    continuation: &'static str,
) -> Result<TrapResult, BifError> {
    let (key, pos, list) = if let Some(state) = state {
        let saved = state
            .downcast_ref::<Mutex<arinsal_bifs::KeyfindCont>>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        (saved.key(), saved.pos(), saved.list())
    } else {
        (args[0], args[1], args[2])
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let step =
        match arinsal_bifs::lists_key(&mut ctx, op, key, pos, list, arinsal_bifs::KEYFIND_MAX_ITER)
        {
            Ok(step) => step,
            Err(error) => {
                return Ok(TrapResult::Failed {
                    error,
                    reductions: 0,
                });
            }
        };
    Ok(match step {
        arinsal_bifs::KeyOutcome::Done(value) => TrapResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::KeyOutcome::More(cont) => TrapResult::Yield {
            continuation,
            state: MagicRef::new(Mutex::new(cont)),
            reductions: process.reductions.max(0) as u32,
        },
    })
}

fn lists_keyfind(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    lists_key_trap(
        process,
        args,
        state,
        arinsal_bifs::KeyOp::Find,
        "lists:keyfind/3",
    )
}

fn lists_keymember(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    lists_key_trap(
        process,
        args,
        state,
        arinsal_bifs::KeyOp::Member,
        "lists:keymember/3",
    )
}

fn lists_keysearch(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    lists_key_trap(
        process,
        args,
        state,
        arinsal_bifs::KeyOp::Search,
        "lists:keysearch/3",
    )
}

fn erlang_append(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    continuation: &'static str,
) -> Result<TrapResult, BifError> {
    let reds = process.reductions.max(0).min(CONTEXT_REDS as i32) as usize;
    let cont = if let Some(state) = state {
        let mut saved = state
            .downcast_ref::<Mutex<arinsal_bifs::AppendCont>>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        std::mem::replace(
            &mut *saved,
            arinsal_bifs::AppendCont::start(Term::NIL, Term::NIL),
        )
    } else {
        arinsal_bifs::AppendCont::start(args[0], args[1])
    };
    let (onheap, alloc) = if cont.rhs() == Term::NIL {
        (reds.saturating_mul(arinsal_bifs::APPEND_EMPTY_PER_RED), 0)
    } else {
        (
            reds.saturating_mul(arinsal_bifs::APPEND_ONHEAP_PER_RED),
            reds.saturating_mul(arinsal_bifs::APPEND_ALLOC_PER_RED),
        )
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let step = match arinsal_bifs::lists_append(&mut ctx, cont, onheap, alloc) {
        Ok(step) => step,
        Err(error) => {
            return Ok(TrapResult::Failed {
                error,
                reductions: ctx.reductions(),
            });
        }
    };
    let reductions = ctx.reductions();
    Ok(match step {
        arinsal_bifs::AppendStep::Done(value) => TrapResult::Done { value, reductions },
        arinsal_bifs::AppendStep::More(next) => TrapResult::Yield {
            continuation,
            state: MagicRef::new(Mutex::new(next)),
            reductions,
        },
    })
}

fn erlang_plusplus(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    erlang_append(process, args, state, "erlang:++/2")
}

fn erlang_append_bif(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    erlang_append(process, args, state, "erlang:append/2")
}

fn bool_atom(value: bool) -> Term {
    Term::atom(
        global_atoms()
            .intern(if value { "true" } else { "false" })
            .unwrap(),
    )
}

const ENTRIES: &[Entry] = &[
    Entry {
        module: "lists",
        function: "reverse",
        arity: 2,
        continuation: "lists:reverse/2",
        handler: lists_reverse,
    },
    Entry {
        module: "lists",
        function: "member",
        arity: 2,
        continuation: "lists:member/2",
        handler: lists_member_trap,
    },
    Entry {
        module: "lists",
        function: "keyfind",
        arity: 3,
        continuation: "lists:keyfind/3",
        handler: lists_keyfind,
    },
    Entry {
        module: "lists",
        function: "keymember",
        arity: 3,
        continuation: "lists:keymember/3",
        handler: lists_keymember,
    },
    Entry {
        module: "lists",
        function: "keysearch",
        arity: 3,
        continuation: "lists:keysearch/3",
        handler: lists_keysearch,
    },
    Entry {
        module: "erlang",
        function: "++",
        arity: 2,
        continuation: "erlang:++/2",
        handler: erlang_plusplus,
    },
    Entry {
        module: "erlang",
        function: "append",
        arity: 2,
        continuation: "erlang:append/2",
        handler: erlang_append_bif,
    },
    Entry {
        module: "erlang",
        function: "--",
        arity: 2,
        continuation: SUBTRACT_CONTINUATION,
        handler: subtract,
    },
    Entry {
        module: "erlang",
        function: "subtract",
        arity: 2,
        continuation: "erlang:subtract/2",
        handler: subtract_named,
    },
    Entry {
        module: "maps",
        function: "from_list",
        arity: 1,
        continuation: MAPS_FROM_LIST_CONTINUATION,
        handler: maps_from_list,
    },
    Entry {
        module: "maps",
        function: "from_keys",
        arity: 2,
        continuation: MAPS_FROM_KEYS_CONTINUATION,
        handler: maps_from_keys,
    },
    Entry {
        module: "maps",
        function: "keys",
        arity: 1,
        continuation: MAPS_KEYS_CONTINUATION,
        handler: maps_keys,
    },
    Entry {
        module: "maps",
        function: "values",
        arity: 1,
        continuation: MAPS_VALUES_CONTINUATION,
        handler: maps_values,
    },
    Entry {
        module: "maps",
        function: "merge",
        arity: 2,
        continuation: MAPS_MERGE_CONTINUATION,
        handler: maps_merge,
    },
    Entry {
        module: "erlang",
        function: "processes",
        arity: 0,
        continuation: PTAB_LIST_CONTINUATION,
        handler: processes,
    },
    Entry {
        module: "erts_debug",
        function: "set_internal_state",
        arity: 2,
        continuation: CODE_PERMISSION_CONTINUATION,
        handler: code_permission,
    },
    Entry {
        module: "erlang",
        function: "list_to_binary",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: list_to_binary,
    },
    Entry {
        module: "erlang",
        function: "iolist_to_binary",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: iolist_to_binary,
    },
    Entry {
        module: "binary",
        function: "list_to_bin",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: list_to_binary,
    },
    Entry {
        module: "erlang",
        function: "list_to_bitstring",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: list_to_bitstring,
    },
    Entry {
        module: "erlang",
        function: "iolist_size",
        arity: 1,
        continuation: IOLIST_SIZE_CONTINUATION,
        handler: iolist_size,
    },
    Entry {
        module: "erlang",
        function: "binary_to_term",
        arity: 1,
        continuation: BINARY_TO_TERM_CONTINUATION,
        handler: binary_to_term,
    },
    Entry {
        module: "erlang",
        function: "term_to_binary",
        arity: 1,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_binary,
    },
    Entry {
        module: "erlang",
        function: "term_to_iovec",
        arity: 1,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_iovec,
    },
    Entry {
        module: "erlang",
        function: "term_to_iovec",
        arity: 2,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_iovec,
    },
    Entry {
        module: "erlang",
        function: "term_to_binary",
        arity: 2,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_binary,
    },
    Entry {
        module: "erlang",
        function: "binary_to_term",
        arity: 2,
        continuation: BINARY_TO_TERM_CONTINUATION,
        handler: binary_to_term,
    },
    Entry {
        module: "binary",
        function: "copy",
        arity: 1,
        continuation: BINARY_COPY_CONTINUATION,
        handler: binary_copy,
    },
    Entry {
        module: "binary",
        function: "copy",
        arity: 2,
        continuation: BINARY_COPY_CONTINUATION,
        handler: binary_copy,
    },
    Entry {
        module: "binary",
        function: "match",
        arity: 2,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_match,
    },
    Entry {
        module: "binary",
        function: "match",
        arity: 3,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_match,
    },
    Entry {
        module: "binary",
        function: "matches",
        arity: 2,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_matches,
    },
    Entry {
        module: "binary",
        function: "matches",
        arity: 3,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_matches,
    },
    Entry {
        module: "binary",
        function: "split",
        arity: 2,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_split,
    },
    Entry {
        module: "binary",
        function: "split",
        arity: 3,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_split,
    },
];

struct BinaryCopyState {
    bytes: Vec<u8>,
    copied: usize,
}

enum IolistBinaryPhase {
    Size(arinsal_bifs::IolistSizeWalk),
    Copy {
        output: Term,
        byte_len: usize,
        walk: arinsal_bifs::IolistCopyWalk,
    },
    Done,
}

fn binary_match(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    binary_search(
        process,
        args,
        state,
        restore_gc,
        arinsal_bifs::BinarySearchKind::Match,
    )
}

fn binary_matches(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    binary_search(
        process,
        args,
        state,
        restore_gc,
        arinsal_bifs::BinarySearchKind::Matches,
    )
}

fn binary_split(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    binary_search(
        process,
        args,
        state,
        restore_gc,
        arinsal_bifs::BinarySearchKind::Split,
    )
}

fn binary_search(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    restore_gc: bool,
    kind: arinsal_bifs::BinarySearchKind,
) -> Result<TrapResult, BifError> {
    // Port of erts/emulator/beam/erl_bif_binary.c:1433-1528 (do_binary_find), OTP-29.1.1.
    const SEARCH_LOOP_FACTOR: usize = 10;
    let budget = (process.reductions.max(0) as usize).saturating_mul(SEARCH_LOOP_FACTOR);
    if let Some(state) = state {
        let state = Arc::clone(state);
        let search = state
            .downcast_ref::<Mutex<arinsal_bifs::BinarySearchWalk>>()
            .ok_or(BifError::BADARG)?;
        let mut search = search.lock().map_err(|_| BifError::SystemLimit)?;
        let (done, work) = search.step(budget);
        let reductions = (work / SEARCH_LOOP_FACTOR) as u32;
        if !done {
            drop(search);
            return Ok(TrapResult::Yield {
                continuation: BINARY_SEARCH_CONTINUATION,
                state,
                reductions,
            });
        }
        process.set_gc_enabled(restore_gc);
        return finish_binary_search(process, &search, reductions);
    }

    let mut search = arinsal_bifs::BinarySearchWalk::new(kind, args)?;
    let (done, work) = search.step(budget);
    let reductions = (work / SEARCH_LOOP_FACTOR) as u32;
    if !done {
        return Ok(TrapResult::Yield {
            continuation: BINARY_SEARCH_CONTINUATION,
            state: MagicRef::new(Mutex::new(search)),
            reductions,
        });
    }
    finish_binary_search(process, &search, reductions)
}

fn finish_binary_search(
    process: &mut Process,
    search: &arinsal_bifs::BinarySearchWalk,
    reductions: u32,
) -> Result<TrapResult, BifError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let value = search.finish(&mut ctx)?;
    Ok(TrapResult::Done { value, reductions })
}

type MapsMergeState = Mutex<Option<arinsal_maps::HashmapMergeContext>>;
type MapsProjectionState = Mutex<Option<arinsal_bifs::MapsProjectionWalk>>;
type MapsBuildState = Mutex<Option<arinsal_bifs::MapsBuildWalk>>;

fn maps_from_list(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    maps_build(process, args, state, pid, restore_gc, false)
}

fn maps_from_keys(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    maps_build(process, args, state, pid, restore_gc, true)
}

/// Reductions a YCF-yielded BIF charges: `BUMP_REDS(p, (init_reds - nr_of_reductions) /
/// iterations_per_red)` (erts_ycf_trap_driver, utils.c:3736-3790). The counter may end up
/// negative, so the charge can exceed what was available.
fn ycf_reductions(initial: i64, left: i64, iterations_per_red: i64) -> u32 {
    ((initial - left) / iterations_per_red).clamp(0, i64::from(u32::MAX)) as u32
}

// Port of erts/emulator/beam/erl_map.c:278-366 (from_keys/from_list helpers), :482-591,
// :622-642 (maps_from_list_1, maps_from_keys_2: 40 iterations per reduction) and
// utils.c:3730-3810 (erts_ycf_trap_driver), OTP-29.1.1.
fn maps_build(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
    from_keys: bool,
) -> Result<TrapResult, BifError> {
    const ITERATIONS_PER_RED: i64 = 40;
    let initial = i64::from(process.reductions.max(0)) * ITERATIONS_PER_RED;
    let mut reds = initial;
    let continuation = if from_keys {
        MAPS_FROM_KEYS_CONTINUATION
    } else {
        MAPS_FROM_LIST_CONTINUATION
    };
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let Some(state) = state else {
        // A new call runs on a walk of its own; the magic state is only created when it
        // yields (erts_ycf_trap_driver allocates its state binary after the first yield).
        let mut walk = if from_keys {
            arinsal_bifs::MapsBuildWalk::from_keys(args[0], args[1])
        } else {
            arinsal_bifs::MapsBuildWalk::from_list(args[0])
        };
        let reductions = |reds| ycf_reductions(initial, reds, ITERATIONS_PER_RED);
        return Ok(match walk.step(&mut ctx, &mut reds)? {
            Some(value) => TrapResult::Done {
                value,
                reductions: reductions(reds),
            },
            None => TrapResult::Yield {
                continuation,
                state: MagicRef::new(Mutex::new(Some(walk))),
                reductions: reductions(reds),
            },
        });
    };
    let state = Arc::clone(state);
    let mut guard = state
        .downcast_ref::<MapsBuildState>()
        .ok_or(BifError::BADARG)?
        .lock()
        .map_err(|_| BifError::SystemLimit)?;
    let walk = guard.as_mut().ok_or(BifError::BADARG)?;
    let Some(value) = walk.step(&mut ctx, &mut reds)? else {
        drop(guard);
        return Ok(TrapResult::Yield {
            continuation,
            state,
            reductions: ycf_reductions(initial, reds, ITERATIONS_PER_RED),
        });
    };
    *guard = None;
    drop(guard);
    Ok(TrapResult::Done {
        value,
        reductions: ycf_reductions(initial, reds, ITERATIONS_PER_RED),
    })
}

// Port of erts/emulator/beam/erl_map.c:1206-1252 (maps_keys_1_helper) and
// erts/emulator/beam/erl_map.c:2261-2309 (maps_values_1_helper), OTP-29.1.1.
fn maps_keys(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    maps_projection(process, args, state, pid, restore_gc, true)
}

fn maps_values(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    maps_projection(process, args, state, pid, restore_gc, false)
}

fn maps_projection(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
    keys: bool,
) -> Result<TrapResult, BifError> {
    const ITERATIONS_PER_RED: i64 = 15;
    let initial = i64::from(process.reductions.max(0)) * ITERATIONS_PER_RED;
    let mut reds = initial;
    if let Some(state) = state {
        let state = Arc::clone(state);
        let mut guard = state
            .downcast_ref::<MapsProjectionState>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        let walk = guard.as_mut().ok_or(BifError::BADARG)?;
        let done = walk.step(&mut reds);
        let reductions = ycf_reductions(initial, reds, ITERATIONS_PER_RED);
        if !done {
            drop(guard);
            return Ok(TrapResult::Yield {
                continuation: if keys {
                    MAPS_KEYS_CONTINUATION
                } else {
                    MAPS_VALUES_CONTINUATION
                },
                state,
                reductions,
            });
        }
        let walk = guard.take().ok_or(BifError::BADARG)?;
        drop(guard);
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
        return Ok(TrapResult::Done {
            value: walk.finish(&mut ctx),
            reductions,
        });
    }

    let start = {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
        arinsal_bifs::MapsProjectionWalk::start(&mut ctx, args[0], keys)?
    };
    let mut walk = match start {
        arinsal_bifs::ProjectionStart::Done(value) => {
            return Ok(TrapResult::Done {
                value,
                reductions: 0,
            });
        }
        arinsal_bifs::ProjectionStart::Walk(walk) => walk,
    };
    let done = walk.step(&mut reds);
    let reductions = ycf_reductions(initial, reds, ITERATIONS_PER_RED);
    if !done {
        return Ok(TrapResult::Yield {
            continuation: if keys {
                MAPS_KEYS_CONTINUATION
            } else {
                MAPS_VALUES_CONTINUATION
            },
            state: MagicRef::new(Mutex::new(Some(walk))),
            reductions,
        });
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let value = walk.finish(&mut ctx);
    Ok(TrapResult::Done { value, reductions })
}

// Port of erts/emulator/beam/erl_map.c:1257 (maps_merge_2), 1498 (maps_merge_trap_1) and
// 1558-1861 (hashmap_merge: MAP_MERGE_LOOP_FACTOR budget, BUMP_REDS, trap), OTP-29.1.1.
fn maps_merge(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    use arinsal_maps::{MAP_MERGE_LOOP_FACTOR, MergeStart};
    let initial_reds = (process.reductions.max(0) as isize).saturating_mul(MAP_MERGE_LOOP_FACTOR);
    let mut reds = initial_reds;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    if let Some(state) = state {
        let state = Arc::clone(state);
        let mut guard = state
            .downcast_ref::<MapsMergeState>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        let merge = guard.as_mut().ok_or(BifError::BADARG)?;
        let merged = arinsal_maps::hashmap_merge(merge, &mut reds, &mut heap)
            .map_err(|_| BifError::SystemLimit)?;
        let Some(value) = merged else {
            drop(guard);
            return Ok(TrapResult::Yield {
                continuation: MAPS_MERGE_CONTINUATION,
                state,
                reductions: process.reductions.max(0) as u32,
            });
        };
        *guard = None;
        drop(guard);
        process.set_gc_enabled(restore_gc);
        return Ok(TrapResult::Done {
            value,
            reductions: ((initial_reds - reds) / MAP_MERGE_LOOP_FACTOR) as u32,
        });
    }

    let mut merge = {
        let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
        match arinsal_bifs::maps_merge_start(&mut ctx, args)? {
            MergeStart::Done(value) => {
                return Ok(TrapResult::Done {
                    value,
                    reductions: 0,
                });
            }
            MergeStart::Hashmap(merge) => merge,
        }
    };
    let merged = arinsal_maps::hashmap_merge(&mut merge, &mut reds, &mut heap)
        .map_err(|_| BifError::SystemLimit)?;
    let Some(value) = merged else {
        // BUMP_ALL_REDS before trapping.
        return Ok(TrapResult::Yield {
            continuation: MAPS_MERGE_CONTINUATION,
            state: MagicRef::new(MapsMergeState::new(Some(merge))),
            reductions: process.reductions.max(0) as u32,
        });
    };
    Ok(TrapResult::Done {
        value,
        reductions: ((initial_reds - reds) / MAP_MERGE_LOOP_FACTOR) as u32,
    })
}

/// Key of a trapped call made through `apply` when the caller does not import the BIF.
pub(crate) const APPLY_TRAP_KEY: usize = usize::MAX;

/// Execute or resume one registered trapping BIF before the ordinary BIF path.
pub(crate) fn execute(
    vm: &mut Vm,
    process: &mut Process,
    import: usize,
    arity: usize,
    args: [Term; 3],
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<TrapResult, VmError>> {
    let import_info = vm.code.modules.get(process.module).and_then(|module| {
        module.imports.get(import).map(|import| {
            (
                import.module.as_str(),
                import.function.as_str(),
                usize::from(import.arity),
            )
        })
    });
    let Some((module_name, function_name, import_arity)) = import_info else {
        if let Some(pending) = process.cold_mut().bif_trap.take() {
            process.set_gc_enabled(pending.gc_was_enabled);
        }
        return Some(Err(VmError::Unsupported(format!("import {import}"))));
    };
    if import_arity != arity {
        return None;
    }
    execute_named(
        process,
        module_name,
        function_name,
        import,
        arity,
        args,
        ctx,
    )
}

/// Execute or resume a trapping BIF named by module and function; `key` identifies the call
/// at the current call site (an import index, or [`APPLY_TRAP_KEY`]).
/// Whether `module:function/arity` is a BIF that may trap to a continuation.
pub(crate) fn traps(module: &str, function: &str, arity: u8) -> bool {
    lookup_entry(module, function, usize::from(arity)).is_some()
}

fn lookup_entry(module: &str, function: &str, arity: usize) -> Option<&'static Entry> {
    ENTRIES
        .iter()
        .find(|entry| {
            entry.module == module
                && entry.function == function
                && usize::from(entry.arity) == arity
        })
        .or_else(|| {
            ENTRIES
                .iter()
                .find(|entry| continuation_is(entry.continuation, module, function, arity))
        })
}

fn continuation_is(continuation: &str, module: &str, function: &str, arity: usize) -> bool {
    let Some((mod_name, rest)) = continuation.split_once(':') else {
        return false;
    };
    let Some((fun_name, arity_text)) = rest.rsplit_once('/') else {
        return false;
    };
    mod_name == module && fun_name == function && arity_text.parse::<usize>().ok() == Some(arity)
}

/// Run the trap continuation export. `beam_bif_export_trap` does this on schedule-in:
/// the continuation is an ordinary call, and only that call may trap again.
pub(crate) fn run_trapped_export(
    process: &mut Process,
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<TrapResult, VmError>> {
    let (module, function, arity) = {
        let pending = process.cold.as_ref()?.bif_trap.as_ref()?;
        let (module, function, arity) = continuation_parts(pending.continuation)?;
        (module.to_owned(), function.to_owned(), arity)
    };
    let args = [
        process.x.first().copied().unwrap_or(Term::NIL),
        process.x.get(1).copied().unwrap_or(Term::NIL),
        process.x.get(2).copied().unwrap_or(Term::NIL),
    ];
    execute_named(
        process,
        &module,
        &function,
        bif_export_trap_pc(),
        arity,
        args,
        ctx,
    )
}

fn continuation_parts(continuation: &str) -> Option<(&str, &str, usize)> {
    let (module, rest) = continuation.split_once(':')?;
    let (function, arity_text) = rest.rsplit_once('/')?;
    Some((module, function, arity_text.parse().ok()?))
}

/// The BIF a trap error is blamed on. `ERTS_BIF_ERROR_TRAPPED` names `sp->bif`, the
/// export that first trapped, not the continuation that was running when it failed.
fn original_trap_report(
    process: &Process,
    module_name: &str,
    function_name: &str,
    arity: usize,
    continuation_resume: bool,
) -> (String, String, usize) {
    if continuation_resume
        && let Some(pending) = process
            .cold
            .as_ref()
            .and_then(|cold| cold.bif_trap.as_ref())
    {
        let module = global_atoms()
            .text(pending.callee.0)
            .unwrap_or(module_name)
            .to_owned();
        let function = global_atoms()
            .text(pending.callee.1)
            .unwrap_or(function_name)
            .to_owned();
        return (module, function, pending.arity);
    }
    (module_name.to_owned(), function_name.to_owned(), arity)
}

/// Point `c_p->i` at `beam_bif_export_trap` and record the continuation export's arity.
pub(crate) fn arm_export_trap(process: &mut Process) {
    if let Some(arity) = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .and_then(|pending| continuation_parts(pending.continuation))
        .map(|(_, _, arity)| arity)
    {
        process.header.arity = arity as u8;
    }
    process.header.i = bif_export_trap as *const u8 as *const _;
}

pub(crate) fn execute_named(
    process: &mut Process,
    module_name: &str,
    function_name: &str,
    import: usize,
    arity: usize,
    mut args: [Term; 3],
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<TrapResult, VmError>> {
    let gc_enabled_on_entry = process.heap.gc_enabled;
    let pending_site = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .map(|pending| {
            (
                pending.caller_module == process.module && pending.caller_ip == process.ip,
                pending.import == import,
            )
        });
    // The continuation export is an ordinary call of its own MFA. It is not a retry of
    // the call site that first trapped, so the site check does not name it.
    let continuation_resume = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .is_some_and(|pending| {
            continuation_is(pending.continuation, module_name, function_name, arity)
        });
    let pending_matches = pending_site == Some((true, true)) || continuation_resume;
    if pending_site.is_some_and(|(same_site, _)| !same_site) && !continuation_resume {
        // A trap continuation belongs to exactly one interrupted call. An
        // exception can redirect control without re-entering that call, so
        // discard its state before dispatching a call from another site. The
        // same site may first dispatch `apply` before reaching the trapped BIF.
        if let Some(pending) = process.cold_mut().bif_trap.take() {
            process.set_gc_enabled(pending.gc_was_enabled);
        }
    }
    if module_name == "erts_debug"
        && function_name == "set_internal_state"
        && args[0].as_atom().and_then(|atom| global_atoms().text(atom))
            != Some("code_mod_permission")
    {
        return None;
    }
    let entry = lookup_entry(module_name, function_name, arity);
    let pending = pending_matches
        .then(|| {
            process
                .cold
                .as_ref()
                .and_then(|cold| cold.bif_trap.as_ref())
        })
        .flatten();
    let gc_was_enabled = pending.map_or(gc_enabled_on_entry, |pending| pending.gc_was_enabled);
    let (handler, state) = if let Some(pending) = pending {
        let Some(entry) = entry else {
            if let Some(pending) = process.cold_mut().bif_trap.take() {
                process.set_gc_enabled(pending.gc_was_enabled);
            }
            return Some(Err(VmError::Unsupported(
                "missing BIF continuation entry".into(),
            )));
        };
        if entry.continuation != pending.continuation {
            if let Some(pending) = process.cold_mut().bif_trap.take() {
                process.set_gc_enabled(pending.gc_was_enabled);
            }
            return Some(Err(VmError::Unsupported(
                "BIF continuation export mismatch".into(),
            )));
        }
        // Port of erts/emulator/beam/beam_common.c (BIF_TRAP: the trap export carries its own
        // arguments), OTP-29.1.1: a resumed call takes its arguments from the trap state.
        args = pending.args;
        (entry.handler, Some(Arc::clone(&pending.state)))
    } else {
        (entry?.handler, None)
    };
    if module_name == "erlang"
        && function_name == "binary_to_term"
        && state.is_none()
        && let Some(bits) = arinsal_bifs::bitstring_bit_len(args[0]).ok()
        && bits.is_multiple_of(8)
        && let Some(reserve) = (bits / 8).checked_mul(2).and_then(|n| n.checked_add(64))
    {
        if let Err(error) = process.ensure(reserve, process.gc_live) {
            return Some(Err(error));
        }
        for slot in 0..arity.min(args.len()) {
            args[slot] = process.x.get(slot).copied().unwrap_or(Term::NIL);
        }
    }

    let pid = ctx.as_deref().map(|run| run.pid());
    if module_name == "erlang" && function_name == "binary_to_term" {
        process.set_gc_enabled(false);
    }
    let resumed = state.is_some();
    // The continuation export has its own arity (binary_copy_trap/3, binary_to_term_trap/1).
    // The handler still sees the original BIF's arguments, which the trap state kept.
    let call_arity = if resumed {
        process
            .cold
            .as_ref()
            .and_then(|cold| cold.bif_trap.as_ref())
            .map(|pending| pending.arity)
            .unwrap_or(arity)
    } else {
        arity
    };
    let result = handler(
        process,
        &args[..call_arity.min(args.len())],
        state.as_ref(),
        pid,
        gc_was_enabled,
    );
    // Captured before the match drops the trap state. A continuation failure is still
    // the original BIF's error (erl_iolist.c ERTS_BIF_ERROR_TRAPPED1(c_p, reason, sp->bif, sp->arg)).
    let report = original_trap_report(
        process,
        module_name,
        function_name,
        arity,
        continuation_resume,
    );
    Some(match result {
        Err(error) => {
            process.cold_mut().bif_trap = None;
            clear_export_trap(process);
            process.set_gc_enabled(gc_was_enabled);
            // Re-enabling GC may collect: the X registers, not the copies, hold the live
            // arguments.
            let args = call_args(process, &args, report.2, resumed);
            Err(exceptions::bif_error(
                process, &report.0, &report.1, &args, error,
            ))
        }
        Ok(TrapResult::Done { value, reductions }) => {
            process.cold_mut().bif_trap = None;
            clear_export_trap(process);
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, reductions);
            Ok(TrapResult::Done { value, reductions })
        }
        Ok(TrapResult::Failed { error, reductions }) => {
            process.cold_mut().bif_trap = None;
            clear_export_trap(process);
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, reductions);
            let args = call_args(process, &args, report.2, resumed);
            Err(exceptions::bif_error(
                process, &report.0, &report.1, &args, error,
            ))
        }
        Ok(TrapResult::Yield {
            continuation,
            state,
            reductions,
        }) => {
            // The ptab list state holds no heap terms, so the process stays collectable
            // while trapped (erts keeps it GC-able in ptab_list_continue/2). The same holds
            // for a code-permission waiter: its state is a flag and its arguments are atoms,
            // and erts runs a GC task of the suspended waiter (code_ix.c:323,
            // erts_reject_code_permissions).
            if continuation != PTAB_LIST_CONTINUATION
                && continuation != CODE_PERMISSION_CONTINUATION
            {
                process.set_gc_enabled(false);
            }
            // A later slice of the continuation must keep blaming the BIF that trapped,
            // not the continuation export that is running now.
            let (callee, trap_arity) = if resumed {
                process
                    .cold
                    .as_ref()
                    .and_then(|cold| cold.bif_trap.as_ref())
                    .map(|pending| (pending.callee, pending.arity))
                    .expect("resumed trap")
            } else {
                (
                    (
                        global_atoms().intern(module_name).expect("BIF module atom"),
                        global_atoms()
                            .intern(function_name)
                            .expect("BIF function atom"),
                    ),
                    arity,
                )
            };
            process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.module,
                caller_ip: process.ip,
                schedule_out: false,
                import,
                continuation,
                state,
                gc_was_enabled,
                arity: trap_arity,
                callee,
                args: if resumed {
                    args
                } else {
                    let live = live_args(process, &args, arity);
                    let mut saved = [Term::NIL; 3];
                    saved[..arity].copy_from_slice(&live);
                    saved
                },
            });
            charge(process, ctx, reductions);
            Ok(TrapResult::Yield {
                continuation,
                state: process
                    .cold
                    .as_ref()
                    .and_then(|cold| cold.bif_trap.as_ref())
                    .map(|pending| Arc::clone(&pending.state))
                    .expect("stored continuation"),
                reductions,
            })
        }
    })
}

/// The trapping BIF a light BIF call runs straight from native code.
///
/// `erts_debug:set_internal_state/2` traps only for `code_mod_permission` and needs the
/// scheduler's pid for it, so it keeps the executor path.
pub(crate) fn light_entry(module: &str, function: &str, arity: u8) -> Option<&'static Entry> {
    if module == "erts_debug" {
        return None;
    }
    ENTRIES
        .iter()
        .find(|entry| entry.module == module && entry.function == function && entry.arity == arity)
}

/// Outcome of a trapping BIF run from a light BIF call.
pub(crate) enum LightTrap {
    /// The BIF finished: its value or its error, like any light BIF's result.
    Returned(Result<Term, BifError>),
    /// The BIF trapped to its continuation export (`THE_NON_VALUE` with `freason == TRAP`);
    /// the call site context-switches and the scheduler resumes it through the trap state.
    Trapped,
}

impl Entry {
    /// Whether the BIF decodes onto the heap it reserved before the call.
    pub(crate) fn reserves_heap(&self) -> bool {
        self.continuation == BINARY_TO_TERM_CONTINUATION
    }
}

/// Runs a trapping BIF from a light BIF call, with no trap pending for the process.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-540 (call_light_bif_shared), OTP-29.1.1:
// a trapping BIF is called like any other BIF; one that finishes returns its value at once,
// and one that traps (BIF_TRAP, bif.h) leaves through `context_switch_simplified` to resume
// in its continuation export.
pub(crate) fn call_light(
    process: &mut Process,
    entry: &'static Entry,
    import: usize,
    callee: (arinsal_term::Atom, arinsal_term::Atom),
    args: &[Term],
) -> LightTrap {
    let gc_was_enabled = process.heap.gc_enabled;
    if entry.reserves_heap() {
        process.set_gc_enabled(false);
    }
    let pid = process.self_pid;
    let result = (entry.handler)(process, args, None, pid, gc_was_enabled);
    let (result, reductions) = match result {
        Err(error) => (Err(error), 0),
        Ok(TrapResult::Done { value, reductions }) => (Ok(value), reductions),
        Ok(TrapResult::Failed { error, reductions }) => (Err(error), reductions),
        Ok(TrapResult::Yield {
            continuation,
            state,
            reductions,
        }) => {
            if continuation != PTAB_LIST_CONTINUATION
                && continuation != CODE_PERMISSION_CONTINUATION
            {
                process.set_gc_enabled(false);
            }
            let mut saved = [Term::NIL; 3];
            saved[..args.len()].copy_from_slice(args);
            // The scheduler binds the trap to its call site when it context-switches.
            process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.module,
                caller_ip: process.ip,
                schedule_out: true,
                import,
                continuation,
                state,
                gc_was_enabled,
                arity: args.len(),
                callee,
                args: saved,
            });
            charge_light(process, reductions);
            return LightTrap::Trapped;
        }
    };
    process.set_gc_enabled(gc_was_enabled);
    charge_light(process, reductions);
    LightTrap::Returned(result)
}

/// Install a list-BIF continuation after the plain call's counter ran out.
///
/// The scan itself was the plain BIF. This only does what `BIF_TRAP` does once
/// `max_iter` is exhausted.
pub(crate) fn install_deferred_trap(
    process: &mut Process,
    import: usize,
    callee: (arinsal_term::Atom, arinsal_term::Atom),
    function: &str,
    args: &[Term],
    trap: Box<arinsal_bifs::DeferredTrap>,
    // `(slice, all)`. Keyfind charges every reduction left (`BUMP_ALL_REDS`).
    // The others charge the slice they actually consumed.
    reductions_charged: (u32, u32),
) {
    let (slice_reductions, all_reductions) = reductions_charged;
    let gc_was_enabled = process.heap.gc_enabled;
    let (continuation, state, reductions) = match *trap {
        arinsal_bifs::DeferredTrap::Key(cont) => (
            key_continuation(function),
            MagicRef::new(Mutex::new(cont)),
            all_reductions,
        ),
        arinsal_bifs::DeferredTrap::Member(cont) => (
            "lists:member/2",
            MagicRef::new(Mutex::new(cont)),
            slice_reductions,
        ),
        arinsal_bifs::DeferredTrap::Append(cont) => (
            if function == "append" {
                "erlang:append/2"
            } else {
                "erlang:++/2"
            },
            MagicRef::new(Mutex::new(cont)),
            slice_reductions,
        ),
        arinsal_bifs::DeferredTrap::Subtract(walk) => (
            if function == "subtract" {
                "erlang:subtract/2"
            } else {
                SUBTRACT_CONTINUATION
            },
            MagicRef::new(Mutex::new(walk)),
            slice_reductions,
        ),
    };
    process.set_gc_enabled(false);
    let mut saved = [Term::NIL; 3];
    let arity = args.len().min(3);
    saved[..arity].copy_from_slice(&args[..arity]);
    process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
        caller_module: process.module,
        caller_ip: process.ip,
        schedule_out: true,
        import,
        continuation,
        state,
        gc_was_enabled,
        arity,
        callee,
        args: saved,
    });
    charge_light(process, reductions);
}

fn key_continuation(function: &str) -> &'static str {
    match function {
        "keymember" => "lists:keymember/3",
        "keysearch" => "lists:keysearch/3",
        _ => "lists:keyfind/3",
    }
}

/// Charges a light trapping BIF's reductions against FCALLS (BUMP_REDS, bif.h); the call site
/// has charged the call itself.
fn charge_light(process: &mut Process, reductions: u32) {
    process.reductions = process
        .reductions
        .saturating_sub(reductions.min(i32::MAX as u32) as i32);
}

/// The call's arguments as the X registers hold them now; a collection since the copies
/// were taken has moved boxed arguments.
fn live_args(process: &Process, copies: &[Term; 3], arity: usize) -> Vec<Term> {
    (0..arity)
        .map(|slot| process.x.get(slot).copied().unwrap_or(copies[slot]))
        .collect()
}

/// The arguments for an error report: those held in the trap state on a resumed call, the live
/// X registers on the first call.
fn call_args(process: &Process, saved: &[Term; 3], arity: usize, resumed: bool) -> Vec<Term> {
    if resumed {
        saved[..arity].to_vec()
    } else {
        live_args(process, saved, arity)
    }
}

// Port of erts/emulator/beam/bif.h:71-78 (BUMP_REDS), OTP-29.1.1.
fn charge(
    process: &mut Process,
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    reductions: u32,
) {
    let charge = reductions.max(1);
    process.reductions = process
        .reductions
        .saturating_sub(charge.min(i32::MAX as u32) as i32)
        .max(0);
    if let Some(run) = ctx {
        let _ = run.consume(charge);
    }
}

fn code_permission(
    process: &mut Process,
    args: &[Term],
    _state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    if !crate::natives::internal_state_enabled() {
        return Err(BifError::Error(Term::atom(
            global_atoms().intern("undef").unwrap(),
        )));
    }
    if args[0] != Term::atom(global_atoms().intern("code_mod_permission").unwrap()) {
        return Err(BifError::Unsupported(
            "unhandled set_internal_state selector",
        ));
    }
    let acquire = match global_atoms().text(args[1].as_atom().ok_or(BifError::BADARG)?) {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(BifError::BADARG),
    };
    let pid = pid.ok_or(BifError::Unsupported(
        "code_mod_permission requires a scheduler",
    ))?;
    let Some(runtime) = process.runtime.clone() else {
        return Err(BifError::Unsupported(
            "code_mod_permission requires a runtime",
        ));
    };
    // Port of erts/emulator/beam/erl_bif_info.c:5385-5400, OTP-29.1.1.
    if !acquire {
        crate::natives::code::release_code_mod_permission(&runtime);
    }
    if !acquire || crate::natives::code::try_seize_code_mod_permission(&runtime, pid) {
        return Ok(TrapResult::Done {
            value: Term::atom(global_atoms().intern("true").unwrap()),
            reductions: 1,
        });
    }
    Ok(TrapResult::Yield {
        continuation: CODE_PERMISSION_CONTINUATION,
        state: MagicRef::new(acquire),
        reductions: 1,
    })
}

type SubtractState = Mutex<arinsal_bifs::SubtractWalk>;

// Port of erts/emulator/beam/erl_bif_lists.c:390-1047 (ErtsSubtractContext,
// subtract_continue, and BIF_TRAP2), OTP-29.1.1. Each continuation gets the
// scheduler context budget from erl_vm.h:53 (`CONTEXT_REDS`).
fn subtract(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    subtract_with(process, args, state, pid, gc_changed, SUBTRACT_CONTINUATION)
}

fn subtract_named(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    subtract_with(process, args, state, pid, gc_changed, "erlang:subtract/2")
}

fn subtract_with(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
    continuation: &'static str,
) -> Result<TrapResult, BifError> {
    let reductions_left = process.reductions.max(0).min(CONTEXT_REDS as i32) as usize;
    if let Some(state) = state {
        let state = Arc::clone(state);
        let mut walk = state
            .downcast_ref::<SubtractState>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        let (result, reductions) = subtract_step(process, &mut walk, reductions_left)?;
        return Ok(match result {
            Some(value) => TrapResult::Done { value, reductions },
            None => TrapResult::Yield {
                continuation,
                state: Arc::clone(&state),
                reductions,
            },
        });
    }

    let mut walk = arinsal_bifs::SubtractWalk::new(args[0], args[1])?;
    let (result, reductions) = subtract_step(process, &mut walk, reductions_left)?;
    Ok(match result {
        Some(value) => TrapResult::Done { value, reductions },
        None => TrapResult::Yield {
            continuation,
            state: MagicRef::new(Mutex::new(walk)),
            reductions,
        },
    })
}

fn subtract_step(
    process: &mut Process,
    walk: &mut arinsal_bifs::SubtractWalk,
    reductions_left: usize,
) -> Result<(Option<Term>, u32), BifError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let result = walk.step(&mut ctx, reductions_left)?;
    Ok((result, ctx.reductions()))
}

fn list_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    let root = args[0];
    if !matches!(root.classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(root, 8)? {
        return Ok(TrapResult::Done {
            value,
            reductions: 1,
        });
    }
    iolist_binary_conversion(process, root, state, gc_changed)
}

fn iolist_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    let root = args[0];
    if root.classify() == TermKind::Bitstring {
        if !arinsal_bifs::bitstring_bit_len(root)?.is_multiple_of(8) {
            return Err(BifError::BADARG);
        }
        return Ok(TrapResult::Done {
            value: root,
            reductions: 1,
        });
    }
    iolist_binary_conversion(process, root, state, gc_changed)
}

fn list_to_bitstring(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    if !matches!(args[0].classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(args[0], 1)? {
        return Ok(TrapResult::Done {
            value,
            reductions: 1,
        });
    }
    iolist_conversion(process, args[0], state, true, gc_changed)
}

fn iolist_size(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const CHUNK: usize = 4096;
    let root = args[0];
    if let Some(state) = state {
        let state = Arc::clone(state);
        let walker = state
            .downcast_ref::<Mutex<arinsal_bifs::IolistSizeWalk>>()
            .ok_or(BifError::BADARG)?;
        let mut walker = walker.lock().map_err(|_| BifError::SystemLimit)?;
        let (done, reductions) = match walker.step(CHUNK) {
            Ok(progress) => progress,
            Err((error, reductions)) => {
                return Ok(TrapResult::Failed {
                    error,
                    reductions: reductions as u32,
                });
            }
        };
        if !done {
            drop(walker);
            return Ok(TrapResult::Yield {
                continuation: IOLIST_SIZE_CONTINUATION,
                state,
                reductions: reductions as u32,
            });
        }
        let size = walker.take_size();
        drop(walker);
        process.set_gc_enabled(restore_gc);
        let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .int_from_u64(u64::try_from(size).map_err(|_| BifError::SystemLimit)?)
            .map_err(|_| BifError::SystemLimit)?;
        return Ok(TrapResult::Done {
            value,
            reductions: reductions as u32,
        });
    }

    let mut walker = arinsal_bifs::IolistSizeWalk::new(root);
    let (done, reductions) = match walker.step(CHUNK) {
        Ok(progress) => progress,
        Err((error, reductions)) => {
            return Ok(TrapResult::Failed {
                error,
                reductions: reductions as u32,
            });
        }
    };
    if !done {
        return Ok(TrapResult::Yield {
            continuation: IOLIST_SIZE_CONTINUATION,
            state: MagicRef::new(Mutex::new(walker)),
            reductions: reductions as u32,
        });
    }
    let size = walker.take_size();
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .int_from_u64(u64::try_from(size).map_err(|_| BifError::SystemLimit)?)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done {
        value,
        reductions: reductions as u32,
    })
}

fn iolist_conversion(
    process: &mut Process,
    root: Term,
    state: Option<&Arc<MagicRef>>,
    bitstring: bool,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const CHUNK: usize = 4096;
    if !matches!(root.classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    if let Some(state) = state {
        let state = Arc::clone(state);
        let walker = state
            .downcast_ref::<Mutex<arinsal_bifs::IolistWalk>>()
            .ok_or(BifError::BADARG)?;
        let mut walker = walker.lock().map_err(|_| BifError::SystemLimit)?;
        let (done, reductions) = match walker.step(CHUNK) {
            Ok(progress) => progress,
            Err((error, reductions)) => {
                return Ok(TrapResult::Failed {
                    error,
                    reductions: reductions as u32,
                });
            }
        };
        if !done {
            drop(walker);
            return Ok(TrapResult::Yield {
                continuation: IOLIST_CONTINUATION,
                state,
                reductions: reductions as u32,
            });
        }
        let (bytes, bits) = walker.take_parts();
        drop(walker);
        process.set_gc_enabled(restore_gc);
        let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .bitstring(&bytes, bits)
            .map_err(|_| BifError::SystemLimit)?;
        return Ok(TrapResult::Done {
            value,
            reductions: reductions as u32,
        });
    }

    let mut walker = arinsal_bifs::IolistWalk::new(root, bitstring);
    let (done, reductions) = match walker.step(CHUNK) {
        Ok(progress) => progress,
        Err((error, reductions)) => {
            return Ok(TrapResult::Failed {
                error,
                reductions: reductions as u32,
            });
        }
    };
    if !done {
        return Ok(TrapResult::Yield {
            continuation: IOLIST_CONTINUATION,
            state: MagicRef::new(Mutex::new(walker)),
            reductions: reductions as u32,
        });
    }
    let (bytes, bits) = walker.take_parts();
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .bitstring(&bytes, bits)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done {
        value,
        reductions: reductions as u32,
    })
}

fn iolist_binary_conversion(
    process: &mut Process,
    root: Term,
    state: Option<&Arc<MagicRef>>,
    _restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const SIZE_YIELDS_PER_RED: usize = 8;
    let state = state.map(Arc::clone).unwrap_or_else(|| {
        MagicRef::new(Mutex::new(IolistBinaryPhase::Size(
            arinsal_bifs::IolistSizeWalk::new(root),
        )))
    });
    let phase = state
        .downcast_ref::<Mutex<IolistBinaryPhase>>()
        .ok_or(BifError::BADARG)?;
    let mut phase = phase.lock().map_err(|_| BifError::SystemLimit)?;
    let mut available_reductions = process.reductions.max(0) as usize;
    let mut size_reductions = 0_usize;

    match &mut *phase {
        IolistBinaryPhase::Size(walk) => {
            let initial_yield_count =
                (process.reductions.max(0) as usize).saturating_mul(SIZE_YIELDS_PER_RED);
            let (done, work) = match walk.step(initial_yield_count) {
                Ok(progress) => progress,
                Err((error, work)) => {
                    let reductions = work.div_ceil(SIZE_YIELDS_PER_RED) as u32;
                    return Ok(TrapResult::Failed { error, reductions });
                }
            };
            size_reductions = work.div_ceil(SIZE_YIELDS_PER_RED);
            if !done {
                drop(phase);
                return Ok(TrapResult::Yield {
                    continuation: IOLIST_CONTINUATION,
                    state,
                    reductions: size_reductions as u32,
                });
            }

            let byte_len = walk.take_size();
            let output = arinsal_bifs::allocate_iolist_binary(
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
                byte_len,
            )?;
            if byte_len == 0 {
                *phase = IolistBinaryPhase::Done;
                return Ok(TrapResult::Done {
                    value: output,
                    reductions: size_reductions as u32,
                });
            }
            *phase = IolistBinaryPhase::Copy {
                output,
                byte_len,
                walk: arinsal_bifs::IolistCopyWalk::new(root),
            };
            available_reductions = available_reductions.saturating_sub(size_reductions);
            if available_reductions == 0 {
                drop(phase);
                return Ok(TrapResult::Yield {
                    continuation: IOLIST_CONTINUATION,
                    state,
                    reductions: size_reductions as u32,
                });
            }
        }
        IolistBinaryPhase::Copy { .. } => {}
        IolistBinaryPhase::Done => return Err(BifError::BADARG),
    }

    let IolistBinaryPhase::Copy {
        output,
        byte_len,
        walk,
    } = &mut *phase
    else {
        unreachable!("the size phase transitions to copy or returns above")
    };
    let yield_count = available_reductions.saturating_mul(SIZE_YIELDS_PER_RED);
    let (done, work) = match arinsal_bifs::with_iolist_binary_output(*output, |bytes| {
        Ok(walk.step(bytes, yield_count))
    })? {
        Ok(progress) => progress,
        Err((error, work)) => {
            let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
            arinsal_bifs::finish_iolist_binary_output(*output);
            return Ok(TrapResult::Failed { error, reductions });
        }
    };
    let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
    if !done {
        drop(phase);
        return Ok(TrapResult::Yield {
            continuation: IOLIST_CONTINUATION,
            state,
            reductions,
        });
    }
    if walk.written() != *byte_len {
        arinsal_bifs::finish_iolist_binary_output(*output);
        return Ok(TrapResult::Failed {
            error: BifError::SystemLimit,
            reductions,
        });
    }
    let result = *output;
    arinsal_bifs::finish_iolist_binary_output(result);
    *phase = IolistBinaryPhase::Done;
    Ok(TrapResult::Done {
        value: result,
        reductions,
    })
}

fn binary_to_term(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const BYTES_PER_REDUCTION: usize = 128;
    // Port of erts/emulator/beam/external.c:116 (B2T_BYTES_PER_REDUCTION), OTP-29.1.1.
    let reds = (process.reductions.max(0) as usize).max(1);
    let chunk_bytes = reds.saturating_mul(BYTES_PER_REDUCTION);
    if let Some(state) = state {
        let state = Arc::clone(state);
        let decoder = state
            .downcast_ref::<Mutex<arinsal_bifs::DecodeWalk>>()
            .ok_or(BifError::BADARG)?;
        let mut decoder = decoder.lock().map_err(|_| BifError::SystemLimit)?;
        let step = decode_step(process, &mut decoder, chunk_bytes);
        return match step {
            Ok((None, consumed)) => {
                drop(decoder);
                Ok(TrapResult::Yield {
                    continuation: BINARY_TO_TERM_CONTINUATION,
                    state,
                    reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
                })
            }
            Ok((Some(value), consumed)) => {
                process.set_gc_enabled(restore_gc);
                Ok(TrapResult::Done {
                    value,
                    reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
                })
            }
            Err((error, consumed)) => {
                process.set_gc_enabled(restore_gc);
                Ok(TrapResult::Failed {
                    error: decode_trap_error(error),
                    reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
                })
            }
        };
    }

    let mut decoder = arinsal_bifs::DecodeWalk::new(args)?;
    match decode_step(process, &mut decoder, chunk_bytes) {
        Ok((None, consumed)) => Ok(TrapResult::Yield {
            continuation: BINARY_TO_TERM_CONTINUATION,
            state: MagicRef::new(Mutex::new(decoder)),
            reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
        }),
        Ok((Some(value), consumed)) => {
            process.set_gc_enabled(restore_gc);
            Ok(TrapResult::Done {
                value,
                reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
            })
        }
        Err((error, consumed)) => {
            process.set_gc_enabled(restore_gc);
            Ok(TrapResult::Failed {
                error: decode_trap_error(error),
                reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
            })
        }
    }
}

fn decode_step(
    process: &mut Process,
    decoder: &mut arinsal_bifs::DecodeWalk,
    chunk_bytes: usize,
) -> Result<(Option<Term>, usize), (BifError, usize)> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    decoder.step_into(chunk_bytes, &mut ctx)
}

fn decode_trap_error(error: BifError) -> BifError {
    match error {
        BifError::Unsupported(_) => BifError::BADARG,
        other => other,
    }
}

fn binary_copy(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    // Port of erts/emulator/beam/erl_bif_binary.c:2380-2505, OTP-29.1.1.
    const COPY_BYTES_PER_REDUCTION: usize = 64;
    const CHUNK_BYTES: usize = 4000 * COPY_BYTES_PER_REDUCTION;
    let input = args[0];
    let count = if args.len() == 2 {
        args[1]
            .as_small()
            .filter(|count| *count >= 0)
            .ok_or(BifError::BADARG)? as usize
    } else {
        1
    };
    let input_bits = arinsal_bifs::bitstring_bit_len(input)?;
    if !input_bits.is_multiple_of(8) {
        return Err(BifError::BADARG);
    }
    let input_len = input_bits / 8;
    let len = input_len
        .checked_mul(count)
        .filter(|len| *len <= (1 << 30))
        .ok_or(BifError::SystemLimit)?;
    if len == 0 || input_len == 0 {
        let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .binary(&[])
            .map_err(|_| BifError::SystemLimit)?;
        return Ok(TrapResult::Done {
            value,
            reductions: 1,
        });
    }
    if let Some(state) = state {
        let state = Arc::clone(state);
        let copy = state
            .downcast_ref::<Mutex<BinaryCopyState>>()
            .ok_or(BifError::BADARG)?;
        let mut copy = copy.lock().map_err(|_| BifError::SystemLimit)?;
        let (done, reductions) = copy_binary_chunk(
            &mut copy,
            input,
            input_len,
            len,
            CHUNK_BYTES,
            COPY_BYTES_PER_REDUCTION,
        )?;
        if !done {
            drop(copy);
            return Ok(TrapResult::Yield {
                continuation: BINARY_COPY_CONTINUATION,
                state,
                reductions,
            });
        }
        process.set_gc_enabled(restore_gc);
        return finish_binary_copy(process, &copy.bytes, reductions);
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| BifError::SystemLimit)?;
    bytes.resize(len, 0);
    let mut copy = BinaryCopyState { bytes, copied: 0 };
    let (done, reductions) = copy_binary_chunk(
        &mut copy,
        input,
        input_len,
        len,
        CHUNK_BYTES,
        COPY_BYTES_PER_REDUCTION,
    )?;
    if !done {
        return Ok(TrapResult::Yield {
            continuation: BINARY_COPY_CONTINUATION,
            state: MagicRef::new(Mutex::new(copy)),
            reductions,
        });
    }
    finish_binary_copy(process, &copy.bytes, reductions)
}

fn copy_binary_chunk(
    copy: &mut BinaryCopyState,
    input: Term,
    input_len: usize,
    len: usize,
    chunk_bytes: usize,
    bytes_per_reduction: usize,
) -> Result<(bool, u32), BifError> {
    let end = copy.copied.saturating_add(chunk_bytes).min(len);
    let mut offset = copy.copied;
    while offset < end {
        let source_offset = offset % input_len;
        let amount = (end - offset).min(input_len - source_offset);
        arinsal_bifs::copy_binary_range(
            input,
            source_offset,
            &mut copy.bytes[offset..offset + amount],
        )?;
        offset += amount;
    }
    let reductions = ((end - copy.copied) / bytes_per_reduction) as u32;
    copy.copied = end;
    Ok((end == len, reductions))
}

fn finish_binary_copy(
    process: &mut Process,
    bytes: &[u8],
    reductions: u32,
) -> Result<TrapResult, BifError> {
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .binary(bytes)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done { value, reductions })
}

fn term_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    term_encode(process, args, state, restore_gc, false)
}

fn term_to_iovec(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    term_encode(process, args, state, restore_gc, true)
}

fn term_encode(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    restore_gc: bool,
    iovec: bool,
) -> Result<TrapResult, BifError> {
    // Port of erts/emulator/beam/external.c:2449-2590, OTP-29.1.1.
    const TERM_TO_BINARY_LOOP_FACTOR: usize = 32;
    let chunk_work =
        (process.reductions.max(0) as usize).saturating_mul(TERM_TO_BINARY_LOOP_FACTOR);
    if let Some(state) = state {
        let state = Arc::clone(state);
        let encoder = state
            .downcast_ref::<Mutex<arinsal_bifs::EncodeWalk>>()
            .ok_or(BifError::BADARG)?;
        let mut encoder_guard = encoder.lock().map_err(|_| BifError::SystemLimit)?;
        let (done, work) = encoder_guard.step(chunk_work)?;
        let reductions = work.div_ceil(TERM_TO_BINARY_LOOP_FACTOR) as u32;
        if !done {
            drop(encoder_guard);
            return Ok(TrapResult::Yield {
                continuation: TERM_TO_BINARY_CONTINUATION,
                state,
                reductions,
            });
        }
        process.set_gc_enabled(restore_gc);
        let encoder = std::mem::replace(&mut *encoder_guard, arinsal_bifs::EncodeWalk::completed());
        drop(encoder_guard);
        return finish_term_encode(process, encoder, reductions, iovec);
    }

    let mut encoder = arinsal_bifs::EncodeWalk::new(args)?;
    let (done, work) = encoder.step(chunk_work)?;
    let reductions = work.div_ceil(TERM_TO_BINARY_LOOP_FACTOR) as u32;
    if !done {
        return Ok(TrapResult::Yield {
            continuation: TERM_TO_BINARY_CONTINUATION,
            state: MagicRef::new(Mutex::new(encoder)),
            reductions,
        });
    }
    finish_term_encode(process, encoder, reductions, iovec)
}

fn finish_term_encode(
    process: &mut Process,
    encoder: arinsal_bifs::EncodeWalk,
    reductions: u32,
    iovec: bool,
) -> Result<TrapResult, BifError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let value = if iovec {
        let (parts, compressed) = encoder.finish_iovec()?;
        let terms = parts
            .iter()
            .map(|bytes| builder.binary(bytes).map_err(|_| BifError::SystemLimit))
            .collect::<Result<Vec<_>, _>>()?;
        if compressed {
            terms[0]
        } else {
            builder
                .list_from_iter(terms)
                .map_err(|_| BifError::SystemLimit)?
        }
    } else {
        let bytes = encoder.finish_binary_buffer()?;
        builder.binary(&bytes).map_err(|_| BifError::SystemLimit)?
    };
    Ok(TrapResult::Done { value, reductions })
}

/// Progress of one `erlang:processes/0` call.
struct PtabListState {
    /// Consistent snapshot of the table taken when the BIF started.
    pids: SmallVec<[arinsal_sched::Pid; 16]>,
    /// Next table index to inspect.
    next_index: u32,
}

// Port of erts/emulator/beam/erl_ptab.c:746 (erts_ptab_list) and :1281 (ptab_list_continue),
// OTP-29.1.1. Costs follow the engine's constants (erl_ptab.c:42-57): 25 table indices per
// reduction scanned in chunks of 1000, 75 result conses per reduction.
fn processes(
    process: &mut Process,
    _args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const INDICES_PER_RED: u32 = 25;
    const CHUNK_SIZE: u32 = 1000;
    const MIN_START_REDS: u32 = CHUNK_SIZE / INDICES_PER_RED;
    let table_max = arinsal_term::ptab::process_table_layout().max();
    let reds_left = process.reductions.max(0) as u32;
    if let Some(state) = state {
        let state = Arc::clone(state);
        let list = state
            .downcast_ref::<Mutex<PtabListState>>()
            .ok_or(BifError::BADARG)?;
        let mut list = list.lock().map_err(|_| BifError::SystemLimit)?;
        let (done, spent) = scan_process_table(&mut list, table_max, reds_left);
        if !done {
            drop(list);
            return Ok(TrapResult::Yield {
                continuation: PTAB_LIST_CONTINUATION,
                state,
                reductions: spent,
            });
        }
        let pid_terms = list
            .pids
            .iter()
            .filter_map(|pid| pid.to_term())
            .collect::<Vec<_>>();
        drop(list);
        return finish_processes(process, pid_terms, spent);
    }

    let mut list = {
        let runtime = process.runtime.as_ref().ok_or(BifError::BADARG)?;
        let mut pids = SmallVec::<[arinsal_sched::Pid; 16]>::from(runtime.process_pids());
        pids.sort_by_key(|pid| crate::process::pid_table_index(*pid));
        PtabListState {
            pids,
            next_index: 0,
        }
    };
    if reds_left < MIN_START_REDS {
        return Ok(TrapResult::Yield {
            continuation: PTAB_LIST_CONTINUATION,
            state: MagicRef::new(Mutex::new(list)),
            reductions: 1,
        });
    }
    let (done, spent) = scan_process_table(&mut list, table_max, reds_left);
    if !done {
        return Ok(TrapResult::Yield {
            continuation: PTAB_LIST_CONTINUATION,
            state: MagicRef::new(Mutex::new(list)),
            reductions: spent,
        });
    }
    let pid_terms = list
        .pids
        .iter()
        .filter_map(|pid| pid.to_term())
        .collect::<Vec<_>>();
    finish_processes(process, pid_terms, spent)
}

fn scan_process_table(list: &mut PtabListState, table_max: u32, reds_left: u32) -> (bool, u32) {
    const CHUNK_SIZE: u32 = 1000;
    const MIN_START_REDS: u32 = CHUNK_SIZE / 25;
    const CONSES_PER_RED: usize = 75;
    let mut spent = 0_u32;
    while list.next_index < table_max && spent < reds_left {
        list.next_index = (list.next_index + CHUNK_SIZE).min(table_max);
        spent += MIN_START_REDS;
    }
    if list.next_index >= table_max {
        spent = spent.max(list.pids.len().div_ceil(CONSES_PER_RED) as u32);
        (true, spent)
    } else {
        (false, spent)
    }
}

fn finish_processes(
    process: &mut Process,
    pid_terms: Vec<Term>,
    spent: u32,
) -> Result<TrapResult, BifError> {
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .list_from_iter(pid_terms)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done {
        value,
        reductions: spent,
    })
}
