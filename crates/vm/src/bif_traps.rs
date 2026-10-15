//! Resumable BIF calls and their private continuation exports.

use super::*;
use arinsal_bifs::BifError;
use arinsal_term::{MagicRef, global_atoms};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

pub(crate) enum HandlerResult {
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

impl HandlerResult {
    /// The charge the handler reported for its run.
    pub(crate) fn reductions(&self) -> u32 {
        match self {
            Self::Done { reductions, .. }
            | Self::Failed { reductions, .. }
            | Self::Yield { reductions, .. } => *reductions,
        }
    }
}

/// What resuming a trapped call produces: a handler's result, or the Erlang export the trap
/// calls (erts BIF_TRAP*: `c_p->i` is the export, the arguments are its X registers).
pub(crate) enum ResumeResult {
    Handler(HandlerResult),
    Export(crate::ExportTrap),
}

pub(crate) type Handler = fn(
    &mut Process,
    &[Term],
    Option<&Arc<MagicRef>>,
    Option<arinsal_sched::Pid>,
    bool,
) -> Result<HandlerResult, BifError>;

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
const IOLIST_TO_IOVEC_CONTINUATION: &str = "erts_internal:iolist_to_iovec_continue/1";
const BINARY_TO_TERM_CONTINUATION: &str = "erts_internal:binary_to_term_trap/1";
const BINARY_COPY_CONTINUATION: &str = "erlang:binary_copy_trap/3";
const BINARY_TO_LIST_CONTINUATION: &str = "erlang:binary_to_list/1";
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
const RE_RUN_CONTINUATION: &str = "erlang:re_run_trap/3";

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
    let frame = if resume.is_none() && process.native_pc.is_none() {
        let released_by_call = process
            .cold
            .as_ref()
            .and_then(|cold| cold.ext_last_released.as_ref())
            .is_some_and(|released| {
                !released.kept && released.module == process.module && released.ip == process.ip
            });
        (!released_by_call).then(|| crate::proc_create::TrapReturn {
            module: process.module,
            ip: process.ip + 1,
        })
    } else {
        None
    };
    if frame.is_some() || process.cold.is_some() {
        process.cold_mut().trap_return = frame;
    }
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
) -> Result<HandlerResult, BifError> {
    let reds = process.reductions.max(0).min(CONTEXT_REDS as i32) as usize;
    let max_cells = reds
        .saturating_mul(arinsal_bifs::REVERSE_ONHEAP_CELLS_PER_RED)
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
    let step = arinsal_bifs::lists_reverse(&mut ctx, list, tail, max_cells);
    drop(ctx);
    let step = step?;
    Ok(match step {
        arinsal_bifs::ReverseStep::Done(value) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::ReverseStep::Trap(cont) => HandlerResult::Yield {
            continuation: "lists:reverse/2",
            state: MagicRef::new(Mutex::new(cont)),
            reductions: 0,
        },
    })
}

fn lists_member_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
    let step = match arinsal_bifs::lists_member(&mut ctx, term, list, max_iter) {
        Ok(step) => step,
        Err(error) => {
            drop(ctx);
            return Ok(HandlerResult::Failed {
                error,
                reductions: 0,
            });
        }
    };
    drop(ctx);
    Ok(match step {
        arinsal_bifs::MemberStep::Done(found) => HandlerResult::Done {
            value: bool_atom(found),
            reductions: 0,
        },
        arinsal_bifs::MemberStep::More(cont) => HandlerResult::Yield {
            continuation: "lists:member/2",
            state: MagicRef::new(Mutex::new(cont)),
            reductions: 0,
        },
    })
}

fn lists_key_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    op: arinsal_bifs::KeyOp,
    continuation: &'static str,
) -> Result<HandlerResult, BifError> {
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
    let step =
        match arinsal_bifs::lists_key(&mut ctx, op, key, pos, list, arinsal_bifs::KEYFIND_MAX_ITER)
        {
            Ok(step) => step,
            Err(error) => {
                process.reductions_used = process
                    .reductions_used
                    .saturating_add(u64::from(ctx.reductions()));
                return Ok(HandlerResult::Failed {
                    error,
                    reductions: 0,
                });
            }
        };
    process.reductions_used = process
        .reductions_used
        .saturating_add(u64::from(ctx.reductions()));
    Ok(match step {
        arinsal_bifs::KeyOutcome::Done(value) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::KeyOutcome::More(cont) => HandlerResult::Yield {
            continuation,
            state: MagicRef::new(Mutex::new(cont)),
            reductions: 0,
        },
    })
}

fn lists_keyfind(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
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
) -> Result<HandlerResult, BifError> {
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
) -> Result<HandlerResult, BifError> {
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
) -> Result<HandlerResult, BifError> {
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
    let step = match arinsal_bifs::lists_append(&mut ctx, cont, onheap, alloc) {
        Ok(step) => step,
        Err(error) => {
            process.reductions_used = process
                .reductions_used
                .saturating_add(u64::from(ctx.reductions()));
            return Ok(HandlerResult::Failed {
                error,
                reductions: 0,
            });
        }
    };
    process.reductions_used = process
        .reductions_used
        .saturating_add(u64::from(ctx.reductions()));
    Ok(match step {
        arinsal_bifs::AppendStep::Done(value) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::AppendStep::More(next) => HandlerResult::Yield {
            continuation,
            state: MagicRef::new(Mutex::new(next)),
            reductions: 0,
        },
    })
}

fn erlang_plusplus(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    erlang_append(process, args, state, "erlang:++/2")
}

fn erlang_append_bif(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
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
    // erl_bif_re.c: re_run_2/3 and re_internal_run_4 all trap to `re_match_trap_export`
    // (erlang:re_run_trap/3) with the restart state in a magic reference.
    Entry {
        module: "re",
        function: "run",
        arity: 2,
        continuation: RE_RUN_CONTINUATION,
        handler: re_run_trap,
    },
    Entry {
        module: "re",
        function: "run",
        arity: 3,
        continuation: RE_RUN_CONTINUATION,
        handler: re_run_trap,
    },
    Entry {
        module: "re",
        function: "internal_run",
        arity: 4,
        continuation: RE_RUN_CONTINUATION,
        handler: re_run_trap,
    },
    Entry {
        module: "re",
        function: "run",
        arity: 2,
        continuation: "re:run/2",
        handler: re_run_trap,
    },
    Entry {
        module: "re",
        function: "run",
        arity: 3,
        continuation: "re:run/3",
        handler: re_run_trap,
    },
    Entry {
        module: "erlang",
        function: "binary_to_list",
        arity: 1,
        continuation: BINARY_TO_LIST_CONTINUATION,
        handler: binary_to_list_trap,
    },
    Entry {
        module: "erlang",
        function: "binary_to_list",
        arity: 3,
        continuation: BINARY_TO_LIST_CONTINUATION,
        handler: binary_to_list_trap,
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
        function: "iolist_to_iovec",
        arity: 1,
        continuation: IOLIST_TO_IOVEC_CONTINUATION,
        handler: iolist_to_iovec,
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
        output: IolistOutput,
        byte_len: usize,
        walk: arinsal_bifs::IolistCopyWalk,
    },
    Done,
}

/// Output staging for `erts_new_bitstring`: up to 64 bytes stay on heap after the walk completes.
// Port of erts/emulator/beam/erl_bits.c:2841-2858 (erts_new_bitstring_refc), OTP-29.1.1.
enum IolistOutput {
    Small(Vec<u8>),
    Writable(Term),
}

impl IolistOutput {
    fn finish_writer(&self) {
        if let Self::Writable(term) = self {
            arinsal_bifs::finish_iolist_binary_output(*term);
        }
    }
}

fn binary_match(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
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
) -> Result<HandlerResult, BifError> {
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
) -> Result<HandlerResult, BifError> {
    binary_search(
        process,
        args,
        state,
        restore_gc,
        arinsal_bifs::BinarySearchKind::Split,
    )
}

/// `re:run/2,3`: PCRE2 runs for the loops the slice's reductions allow, then the match state
/// goes into a magic reference and the call traps to itself.
// Port of erts/emulator/beam/erl_bif_re.c:1495-1795 (re_run) and :1841-1900 (re_exec_trap),
// OTP-29.1.1.
fn re_run_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    type Resume = Mutex<Option<Box<arinsal_re::RunState>>>;
    let prior = match state {
        Some(state) => state
            .downcast_ref::<Resume>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?
            .take(),
        None => None,
    };
    // loop_limit = MIN(reds_initial * LOOP_FACTOR, max_loop_limit), max = CONTEXT_REDS * LOOP_FACTOR
    let reds_left = process.reductions.clamp(1, CONTEXT_REDS as i32);
    let budget = reds_left * arinsal_re::LOOP_FACTOR;
    let (progress, loops) = {
        let mut heap = crate::ProcessHeapHandle(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
        arinsal_re::run_slice(
            &mut ctx,
            if args.len() == 4 {
                "internal_run"
            } else {
                "run"
            },
            args,
            prior,
            budget,
        )?
    };
    let reductions = (loops / arinsal_re::LOOP_FACTOR as u64).min(u64::from(u32::MAX)) as u32;
    Ok(match progress {
        arinsal_re::Progress::Done(value) => HandlerResult::Done { value, reductions },
        arinsal_re::Progress::Yield(run) => HandlerResult::Yield {
            continuation: RE_RUN_CONTINUATION,
            state: MagicRef::new(Mutex::new(Some(run))),
            reductions,
        },
    })
}

// Port of erts/emulator/beam/binary.c:213-239 (binary_to_list_chunk), OTP-29.1.1.
fn binary_to_list_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    if state.is_none() {
        let bif = arinsal_bifs::lookup("erlang", "binary_to_list", args.len() as u8)
            .ok_or(BifError::BADARG)?;
        return binary_to_list_start(process, args, bif, _pid, restore_gc);
    }
    let state = Arc::clone(state.ok_or(BifError::BADARG)?);
    let walk = state
        .downcast_ref::<Mutex<arinsal_bifs::BinaryToListWalk>>()
        .ok_or(BifError::BADARG)?;
    let mut walk = walk.lock().map_err(|_| BifError::SystemLimit)?;
    let reds_left = process.reductions.max(0) as usize;
    let chunk = reds_left.saturating_add(1).saturating_mul(256);
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let (value, used) = walk.step(&mut heap, chunk)?;
    let reductions = used.div_ceil(256).min(u32::MAX as usize) as u32;
    if let Some(value) = value {
        process.set_gc_enabled(restore_gc);
        Ok(HandlerResult::Done { value, reductions })
    } else {
        drop(walk);
        Ok(HandlerResult::Yield {
            continuation: BINARY_TO_LIST_CONTINUATION,
            state,
            reductions,
        })
    }
}

fn binary_to_list_start(
    process: &mut Process,
    args: &[Term],
    bif: arinsal_bifs::BifFn,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    ctx.set_reduction_budget(process.reductions.max(0) as usize);
    let value = bif(&mut ctx, args)?;
    let reductions = ctx.reductions();
    match ctx.take_deferred().map(|trap| *trap) {
        Some(arinsal_bifs::DeferredTrap::BinaryToList(walk)) => Ok(HandlerResult::Yield {
            continuation: BINARY_TO_LIST_CONTINUATION,
            state: MagicRef::new(Mutex::new(walk)),
            reductions,
        }),
        Some(_) => Err(BifError::BADARG),
        None => Ok(HandlerResult::Done { value, reductions }),
    }
}

fn binary_search(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    restore_gc: bool,
    kind: arinsal_bifs::BinarySearchKind,
) -> Result<HandlerResult, BifError> {
    // Port of erts/emulator/beam/erl_bif_binary.c:1433-1528 (do_binary_find), OTP-29.1.1.
    // Port of erts/emulator/beam/erl_bif_binary.c:110 (get_reds), OTP-29.1.1.
    const SEARCH_LOOP_FACTOR: usize = 10;
    let budget = (process.reductions.max(0) as usize)
        .saturating_mul(SEARCH_LOOP_FACTOR)
        .max(1);
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
            return Ok(HandlerResult::Yield {
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
        return Ok(HandlerResult::Yield {
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
) -> Result<HandlerResult, BifError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
    let value = search.finish(&mut ctx)?;
    Ok(HandlerResult::Done { value, reductions })
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
) -> Result<HandlerResult, BifError> {
    maps_build(process, args, state, pid, restore_gc, false)
}

fn maps_from_keys(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
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
) -> Result<HandlerResult, BifError> {
    const ITERATIONS_PER_RED: i64 = 40;
    let initial = i64::from(process.reductions.max(0)) * ITERATIONS_PER_RED;
    let mut reds = initial;
    let continuation = if from_keys {
        MAPS_FROM_KEYS_CONTINUATION
    } else {
        MAPS_FROM_LIST_CONTINUATION
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
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
            Some(value) => HandlerResult::Done {
                value,
                reductions: reductions(reds),
            },
            None => HandlerResult::Yield {
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
        return Ok(HandlerResult::Yield {
            continuation,
            state,
            reductions: ycf_reductions(initial, reds, ITERATIONS_PER_RED),
        });
    };
    *guard = None;
    drop(guard);
    Ok(HandlerResult::Done {
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
) -> Result<HandlerResult, BifError> {
    maps_projection(process, args, state, pid, restore_gc, true)
}

fn maps_values(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    maps_projection(process, args, state, pid, restore_gc, false)
}

fn maps_projection(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
    keys: bool,
) -> Result<HandlerResult, BifError> {
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
            return Ok(HandlerResult::Yield {
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
        return Ok(HandlerResult::Done {
            value: walk.finish(),
            reductions,
        });
    }

    let start = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
        arinsal_bifs::MapsProjectionWalk::start(&mut ctx, args[0], keys)?
    };
    let mut walk = match start {
        arinsal_bifs::ProjectionStart::Done(value) => {
            return Ok(HandlerResult::Done {
                value,
                reductions: 0,
            });
        }
        arinsal_bifs::ProjectionStart::Walk(walk) => walk,
    };
    let done = walk.step(&mut reds);
    let reductions = ycf_reductions(initial, reds, ITERATIONS_PER_RED);
    if !done {
        return Ok(HandlerResult::Yield {
            continuation: if keys {
                MAPS_KEYS_CONTINUATION
            } else {
                MAPS_VALUES_CONTINUATION
            },
            state: MagicRef::new(Mutex::new(Some(walk))),
            reductions,
        });
    }
    let value = walk.finish();
    Ok(HandlerResult::Done { value, reductions })
}

// Port of erts/emulator/beam/erl_map.c:1257 (maps_merge_2), 1498 (maps_merge_trap_1) and
// 1558-1861 (hashmap_merge: MAP_MERGE_LOOP_FACTOR budget, BUMP_REDS, trap), OTP-29.1.1.
fn maps_merge(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    use arinsal_maps::{MAP_MERGE_LOOP_FACTOR, MergeStart};
    let initial_reds = (process.reductions.max(0) as isize).saturating_mul(MAP_MERGE_LOOP_FACTOR);
    let mut reds = initial_reds;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
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
            return Ok(HandlerResult::Yield {
                continuation: MAPS_MERGE_CONTINUATION,
                state,
                reductions: process.reductions.max(0) as u32,
            });
        };
        *guard = None;
        drop(guard);
        process.set_gc_enabled(restore_gc);
        return Ok(HandlerResult::Done {
            value,
            reductions: ((initial_reds - reds) / MAP_MERGE_LOOP_FACTOR) as u32,
        });
    }

    let mut merge =
        match arinsal_bifs::maps_merge_start_on_process_heap(&mut heap, args[0], args[1])? {
            MergeStart::Done(value) => {
                return Ok(HandlerResult::Done {
                    value,
                    reductions: 0,
                });
            }
            MergeStart::Hashmap(merge) => merge,
        };
    let merged = arinsal_maps::hashmap_merge(&mut merge, &mut reds, &mut heap)
        .map_err(|_| BifError::SystemLimit)?;
    let Some(value) = merged else {
        // BUMP_ALL_REDS before trapping.
        return Ok(HandlerResult::Yield {
            continuation: MAPS_MERGE_CONTINUATION,
            state: MagicRef::new(MapsMergeState::new(Some(merge))),
            reductions: process.reductions.max(0) as u32,
        });
    };
    Ok(HandlerResult::Done {
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
    args: [Term; 4],
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<HandlerResult, VmError>> {
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

/// Index of [`ENTRIES`] by export name, the way erts finds an export by `{M, F, A}`: the
/// first entry with that name, else the first whose continuation export has it.
struct EntryIndex {
    direct: HashMap<(&'static str, &'static str, usize), usize>,
    continuation: HashMap<(&'static str, &'static str, usize), usize>,
}

fn entry_index() -> &'static EntryIndex {
    static INDEX: OnceLock<EntryIndex> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = EntryIndex {
            direct: HashMap::new(),
            continuation: HashMap::new(),
        };
        for (position, entry) in ENTRIES.iter().enumerate() {
            index
                .direct
                .entry((entry.module, entry.function, usize::from(entry.arity)))
                .or_insert(position);
            if let Some((module, function, arity)) = continuation_parts(entry.continuation) {
                index
                    .continuation
                    .entry((module, function, arity))
                    .or_insert(position);
            }
        }
        index
    })
}

fn lookup_entry(module: &str, function: &str, arity: usize) -> Option<&'static Entry> {
    let index = entry_index();
    index
        .direct
        .get(&(module, function, arity))
        .or_else(|| index.continuation.get(&(module, function, arity)))
        .map(|&position| &ENTRIES[position])
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
) -> Option<Result<ResumeResult, VmError>> {
    let (module, function, arity) = {
        let pending = process.cold.as_ref()?.bif_trap.as_ref()?;
        let (module, function, arity) = continuation_parts(pending.continuation)?;
        (module.to_owned(), function.to_owned(), arity)
    };
    // An Erlang export has no Rust handler: the trap calls it with the saved arguments.
    // Port of erts/emulator/beam/beam_common.c (BIF_TRAP: the trap export carries its own
    // arguments), OTP-29.1.1.
    if lookup_entry(&module, &function, arity).is_none() {
        let pending = process.cold_mut().bif_trap.take()?;
        clear_export_trap(process);
        // The arguments are the live X registers the trap left (erts BIF_TRAPn, reg[0..n]).
        let args = process.x[..pending.arity].to_vec();
        return Some(Ok(ResumeResult::Export(crate::ExportTrap {
            continuation: pending.continuation,
            args,
        })));
    }
    let args = [
        process.x.first().copied().unwrap_or(Term::NIL),
        process.x.get(1).copied().unwrap_or(Term::NIL),
        process.x.get(2).copied().unwrap_or(Term::NIL),
        Term::NIL,
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
    .map(|result| result.map(ResumeResult::Handler))
}

/// Install the trap state of a BIF that traps to an Erlang export. The scheduler then runs
/// the export at `beam_bif_export_trap`, the way an export trap of a Rust continuation runs.
// Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*: at most three arguments in X0-X2),
// OTP-29.1.1.
pub(crate) fn install_export_trap(
    process: &mut Process,
    import: usize,
    callee: (arinsal_term::Atom, arinsal_term::Atom),
    trap: &crate::ExportTrap,
) {
    let arity = trap.args.len();
    assert!(arity <= 3, "BIF traps pass at most three arguments");
    // erts BIF_TRAPn writes the arguments to reg[0..n] and sets c_p->arity: they are the live
    // X registers of the export call, rooted like any other. GC stays enabled while trapped.
    if process.x.len() < arity {
        let mut registers = process.x.to_vec();
        registers.resize(arity, Term::NIL);
        process.x = registers.into();
    }
    process.x[..arity].copy_from_slice(&trap.args);
    process.gc_live = arity;
    let gc_was_enabled = process.heap.gc_enabled;
    process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
        caller_module: process.module,
        caller_ip: process.ip,
        schedule_out: true,
        import,
        continuation: trap.continuation,
        state: MagicRef::new(Mutex::new(())),
        gc_was_enabled,
        arity,
        callee,
        // Export traps keep their arguments in X; this field is for BIF continuations only.
        args: [Term::NIL; 3],
    });
}

pub(crate) fn continuation_parts(continuation: &str) -> Option<(&str, &str, usize)> {
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
    mut args: [Term; 4],
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<HandlerResult, VmError>> {
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
        args = [pending.args[0], pending.args[1], pending.args[2], Term::NIL];
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
    let fcalls_in = process.reductions;
    let result = handler(
        process,
        &args[..call_arity.min(args.len())],
        state.as_ref(),
        pid,
        gc_was_enabled,
    );
    process.trap_work = fcalls_in.saturating_sub(process.reductions).max(0);
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
        Ok(HandlerResult::Done { value, reductions }) => {
            process.cold_mut().bif_trap = None;
            clear_export_trap(process);
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, reductions);
            Ok(HandlerResult::Done { value, reductions })
        }
        Ok(HandlerResult::Failed { error, reductions }) => {
            process.cold_mut().bif_trap = None;
            clear_export_trap(process);
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, reductions);
            let args = call_args(process, &args, report.2, resumed);
            Err(exceptions::bif_error(
                process, &report.0, &report.1, &args, error,
            ))
        }
        Ok(HandlerResult::Yield {
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
                    // BIF_TRAP keeps at most three arguments (bif.h:316-326); a four-argument
                    // BIF such as re:internal_run/4 traps to a three-argument export.
                    arity.min(3),
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
                    [args[0], args[1], args[2]]
                } else {
                    let live = live_args(process, &args, arity.min(3));
                    let mut saved = [Term::NIL; 3];
                    saved[..live.len()].copy_from_slice(&live);
                    saved
                },
            });
            charge(process, ctx, reductions);
            Ok(HandlerResult::Yield {
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

/// The body of one trapping BIF, compiled into its own light entry (`native_helpers::
/// trap_bif_entry`). The common run is a direct call; the trap state is built only when
/// the run yields.
pub(crate) trait TrapBody {
    /// The first run of the BIF. `restore_gc` is the process's collection state on entry.
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError>;
}

/// `maps:keys/1`.
pub(crate) struct MapsKeys;
/// `maps:values/1`.
pub(crate) struct MapsValues;
/// `maps:merge/2`.
pub(crate) struct MapsMerge;
/// `maps:from_list/1`.
pub(crate) struct MapsFromList;
/// `binary_to_list/1,3`.
pub(crate) struct BinaryToList<B>(std::marker::PhantomData<fn() -> B>);
/// `list_to_binary/1` and `binary:list_to_bin/1`.
pub(crate) struct ListToBinary;
/// `iolist_to_binary/1`.
pub(crate) struct IolistToBinary;
/// `iolist_size/1`.
pub(crate) struct IolistSize;
/// `iolist_to_iovec/1`.
pub(crate) struct IolistToIovec;

impl TrapBody for MapsKeys {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        maps_keys(process, args, None, pid, restore_gc)
    }
}

impl TrapBody for MapsValues {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        maps_values(process, args, None, pid, restore_gc)
    }
}

impl TrapBody for MapsMerge {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        maps_merge(process, args, None, pid, restore_gc)
    }
}

impl TrapBody for MapsFromList {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        maps_from_list(process, args, None, pid, restore_gc)
    }
}

impl<B: arinsal_bifs::BifBody> TrapBody for BinaryToList<B> {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        // Port of erts/emulator/beam/binary.c:202-239 (`binary_to_list_1/3`), OTP-29.1.1.
        binary_to_list_start(process, args, B::call, pid, restore_gc)
    }
}

impl TrapBody for ListToBinary {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        // Port of erts/emulator/beam/erl_iolist.c:857-935 (`list_to_bitstring_bif`), OTP-29.1.1.
        list_to_binary(process, args, None, pid, restore_gc)
    }
}

impl TrapBody for IolistToBinary {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        // Port of erts/emulator/beam/erl_iolist.c:916-927 (iolist_to_binary_1), OTP-29.1.1.
        iolist_to_binary(process, args, None, pid, restore_gc)
    }
}

impl TrapBody for IolistToIovec {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        iolist_to_iovec(process, args, None, pid, restore_gc)
    }
}

impl TrapBody for IolistSize {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        // Port of erts/emulator/beam/erl_iolist.c:938-1093 (`iolist_size_1`), OTP-29.1.1.
        iolist_size(process, args, None, pid, restore_gc)
    }
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
    finish_light(process, import, callee, args, gc_was_enabled, result)
}

/// The result of a trapping BIF's first run, as a light BIF call sees it: a value, an error,
/// or the trap it installs (`BIF_TRAP`).
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-540 (call_light_bif_shared), OTP-29.1.1.
pub(crate) fn finish_light(
    process: &mut Process,
    import: usize,
    callee: (arinsal_term::Atom, arinsal_term::Atom),
    args: &[Term],
    gc_was_enabled: bool,
    result: Result<HandlerResult, BifError>,
) -> LightTrap {
    let (result, reductions) = match result {
        Err(error) => (Err(error), 0),
        Ok(HandlerResult::Done { value, reductions }) => (Ok(value), reductions),
        Ok(HandlerResult::Failed { error, reductions }) => (Err(error), reductions),
        Ok(HandlerResult::Yield {
            continuation,
            state,
            reductions,
        }) => {
            let binary_to_list_retry = continuation == BINARY_TO_LIST_CONTINUATION
                && state
                    .downcast_ref::<Mutex<arinsal_bifs::BinaryToListWalk>>()
                    .and_then(|walk| walk.lock().ok())
                    .is_some_and(|walk| walk.needs_initial_allocation());
            if continuation != PTAB_LIST_CONTINUATION
                && continuation != CODE_PERMISSION_CONTINUATION
                && !binary_to_list_retry
            {
                process.set_gc_enabled(false);
            }
            let mut saved = [Term::NIL; 3];
            let kept = args.len().min(3);
            saved[..kept].copy_from_slice(&args[..kept]);
            // The scheduler binds the trap to its call site when it context-switches.
            process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.module,
                caller_ip: process.ip,
                schedule_out: true,
                import,
                continuation,
                state,
                gc_was_enabled,
                arity: kept,
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
) {
    let gc_was_enabled = process.heap.gc_enabled;
    let mut disable_gc = true;
    let (continuation, state) = match *trap {
        arinsal_bifs::DeferredTrap::BinaryToList(walk) => {
            disable_gc = !walk.needs_initial_allocation();
            (BINARY_TO_LIST_CONTINUATION, MagicRef::new(Mutex::new(walk)))
        }
        arinsal_bifs::DeferredTrap::Key(cont) => {
            (key_continuation(function), MagicRef::new(Mutex::new(cont)))
        }
        arinsal_bifs::DeferredTrap::Member(cont) => {
            ("lists:member/2", MagicRef::new(Mutex::new(cont)))
        }
        arinsal_bifs::DeferredTrap::Reverse(cont) => {
            ("lists:reverse/2", MagicRef::new(Mutex::new(cont)))
        }
        arinsal_bifs::DeferredTrap::Append(cont) => (
            if function == "append" {
                "erlang:append/2"
            } else {
                "erlang:++/2"
            },
            MagicRef::new(Mutex::new(cont)),
        ),
        arinsal_bifs::DeferredTrap::Subtract(walk) => (
            if function == "subtract" {
                "erlang:subtract/2"
            } else {
                SUBTRACT_CONTINUATION
            },
            MagicRef::new(Mutex::new(walk)),
        ),
    };
    if disable_gc {
        process.set_gc_enabled(false);
    }
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
pub(crate) fn charge_light(process: &mut Process, reductions: u32) {
    process.reductions = process
        .reductions
        .saturating_sub(reductions.min(i32::MAX as u32) as i32)
        .max(0);
}

/// The call's arguments as the X registers hold them now; a collection since the copies
/// were taken has moved boxed arguments.
fn live_args(process: &Process, copies: &[Term; 4], arity: usize) -> Vec<Term> {
    (0..arity)
        .map(|slot| process.x.get(slot).copied().unwrap_or(copies[slot]))
        .collect()
}

/// The arguments for an error report: those held in the trap state on a resumed call, the live
/// X registers on the first call.
fn call_args(process: &Process, saved: &[Term; 4], arity: usize, resumed: bool) -> Vec<Term> {
    if resumed {
        saved[..arity.min(4)].to_vec()
    } else {
        live_args(process, saved, arity)
    }
}

/// What one call of a trapping BIF costs the process and its scheduler slice.
///
/// A handler decrements the process counter itself while it works (`BUMP_REDS` through its
/// `Ctx`), and some also return that work as the charge for `charge` to take again. The call
/// is billed for the work once, as erts bills `REDS_IN - FCALLS`. A call is billed no more
/// than the counter held, since `BUMP_REDS` stops at zero, and what the handler gave up
/// through `ERTS_VBUMP_ALL_REDS` ends the slice without being the process's own work.
pub(crate) struct TrapMeter {
    fcalls: i32,
    used: u64,
    consumed: u32,
    call_counted: bool,
}

impl TrapMeter {
    /// The call is an instruction that already counted its own reduction.
    pub(crate) fn start(
        process: &Process,
        ctx: Option<&arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Self {
        Self {
            fcalls: process.reductions,
            used: process.reductions_used,
            consumed: ctx.map_or(0, |run| run.consumed()),
            call_counted: true,
        }
    }

    /// The call is the continuation export, run by the scheduler on schedule-in: its call
    /// costs one reduction of its own.
    pub(crate) fn start_continuation(
        process: &Process,
        ctx: Option<&arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Self {
        Self {
            call_counted: false,
            ..Self::start(process, ctx)
        }
    }

    /// Settle the call's cost. `returned` is the charge the handler reported.
    pub(crate) fn finish(
        self,
        process: &mut Process,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
        returned: u32,
    ) {
        let inside = u32::try_from(process.trap_work).unwrap_or(0);
        let held = u32::try_from(self.fcalls.max(1)).unwrap_or(1);
        let work = inside.max(returned.max(1)).min(held);
        let virtual_reds = std::mem::take(&mut process.virtual_reds);
        process.reductions = self
            .fcalls
            .saturating_sub(i32::try_from(work).unwrap_or(i32::MAX))
            .max(0);
        let counted_call = u32::from(self.call_counted);
        let used = process.reductions_used.saturating_sub(self.used);
        process.reductions_used = process.reductions_used.saturating_add(
            u64::from(work.saturating_sub(counted_call))
                .saturating_sub(used)
                .saturating_sub(u64::from(virtual_reds)),
        );
        if let Some(run) = ctx {
            let counted = run.consumed().saturating_sub(self.consumed);
            run.consume(work.saturating_sub(counted));
        }
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
) -> Result<HandlerResult, BifError> {
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
    if !acquire || crate::natives::code::try_seize_code_mod_permission(&runtime, process, pid) {
        return Ok(HandlerResult::Done {
            value: Term::atom(global_atoms().intern("true").unwrap()),
            reductions: 1,
        });
    }
    Ok(HandlerResult::Yield {
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
) -> Result<HandlerResult, BifError> {
    subtract_with(process, args, state, pid, gc_changed, SUBTRACT_CONTINUATION)
}

fn subtract_named(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    subtract_with(process, args, state, pid, gc_changed, "erlang:subtract/2")
}

fn subtract_with(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
    continuation: &'static str,
) -> Result<HandlerResult, BifError> {
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
            Some(value) => HandlerResult::Done { value, reductions },
            None => HandlerResult::Yield {
                continuation,
                state: Arc::clone(&state),
                reductions,
            },
        });
    }

    let mut walk = arinsal_bifs::SubtractWalk::new(args[0], args[1])?;
    let (result, reductions) = subtract_step(process, &mut walk, reductions_left)?;
    Ok(match result {
        Some(value) => HandlerResult::Done { value, reductions },
        None => HandlerResult::Yield {
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
    let result = walk.step(&mut ctx, reductions_left)?;
    Ok((result, ctx.reductions()))
}

fn list_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    let root = args[0];
    if !matches!(root.classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(root, 8)? {
        return Ok(HandlerResult::Done {
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
) -> Result<HandlerResult, BifError> {
    let root = args[0];
    if root.classify() == TermKind::Bitstring {
        if !arinsal_bifs::bitstring_bit_len(root)?.is_multiple_of(8) {
            return Err(BifError::BADARG);
        }
        return Ok(HandlerResult::Done {
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
) -> Result<HandlerResult, BifError> {
    if !matches!(args[0].classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(args[0], 1)? {
        return Ok(HandlerResult::Done {
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
) -> Result<HandlerResult, BifError> {
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
                return Ok(HandlerResult::Failed {
                    error,
                    reductions: reductions as u32,
                });
            }
        };
        if !done {
            drop(walker);
            return Ok(HandlerResult::Yield {
                continuation: IOLIST_SIZE_CONTINUATION,
                state,
                reductions: reductions as u32,
            });
        }
        let size = walker.take_size();
        drop(walker);
        process.set_gc_enabled(restore_gc);
        let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
            .int_from_u64(u64::try_from(size).map_err(|_| BifError::SystemLimit)?)
            .map_err(|_| BifError::SystemLimit)?;
        return Ok(HandlerResult::Done {
            value,
            reductions: reductions as u32,
        });
    }

    let mut walker = arinsal_bifs::IolistSizeWalk::new(root);
    let (done, reductions) = match walker.step(CHUNK) {
        Ok(progress) => progress,
        Err((error, reductions)) => {
            return Ok(HandlerResult::Failed {
                error,
                reductions: reductions as u32,
            });
        }
    };
    if !done {
        return Ok(HandlerResult::Yield {
            continuation: IOLIST_SIZE_CONTINUATION,
            state: MagicRef::new(Mutex::new(walker)),
            reductions: reductions as u32,
        });
    }
    let size = walker.take_size();
    let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .int_from_u64(u64::try_from(size).map_err(|_| BifError::SystemLimit)?)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(HandlerResult::Done {
        value,
        reductions: reductions as u32,
    })
}

const SIZE_YIELDS_PER_RED: usize = 8;

fn iolist_to_iovec(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    let state = match state {
        Some(state) => Arc::clone(state),
        None => {
            if let Some(value) = arinsal_bifs::iolist_to_iovec_shortcut(
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
                args[0],
            )? {
                return Ok(HandlerResult::Done {
                    value,
                    reductions: 0,
                });
            }
            MagicRef::new(Mutex::new(arinsal_bifs::IolistVecWalk::new(args[0])))
        }
    };
    let walk = state
        .downcast_ref::<Mutex<arinsal_bifs::IolistVecWalk>>()
        .ok_or(BifError::BADARG)?;
    let mut walk = walk.lock().map_err(|_| BifError::SystemLimit)?;
    let entry_reds = process.reductions.max(0) as usize;
    let mut spent = 0_usize;
    let mut reds_left = entry_reds;
    let yielded = |state: Arc<MagicRef>, reductions: usize| {
        Ok(HandlerResult::Yield {
            continuation: IOLIST_TO_IOVEC_CONTINUATION,
            state,
            reductions: reductions as u32,
        })
    };
    if !walk.sized() {
        if reds_left == 0 {
            drop(walk);
            return yielded(state, 0);
        }
        match walk.size_step(reds_left.saturating_mul(SIZE_YIELDS_PER_RED)) {
            Err((error, used)) => {
                return Ok(HandlerResult::Failed {
                    error,
                    reductions: arinsal_bifs::iolist_yield_reductions(used) as u32,
                });
            }
            Ok((false, _)) => {
                drop(walk);
                return yielded(state, entry_reds);
            }
            Ok((true, used)) => {
                let reds = arinsal_bifs::iolist_yield_reductions(used);
                spent += reds;
                reds_left = reds_left.saturating_sub(reds);
            }
        }
        if reds_left == 0 {
            drop(walk);
            return yielded(state, entry_reds);
        }
    }
    if reds_left == 0 {
        drop(walk);
        return yielded(state, 0);
    }
    match walk.copy_step(reds_left.saturating_mul(SIZE_YIELDS_PER_RED)) {
        Err((error, used)) => Ok(HandlerResult::Failed {
            error,
            reductions: (spent + arinsal_bifs::iolist_yield_reductions(used)) as u32,
        }),
        Ok((false, _)) => {
            drop(walk);
            yielded(state, entry_reds)
        }
        Ok((true, used)) => {
            let reductions = (spent + arinsal_bifs::iolist_yield_reductions(used)) as u32;
            let value = walk.finish(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))?;
            Ok(HandlerResult::Done { value, reductions })
        }
    }
}

fn iolist_conversion(
    process: &mut Process,
    root: Term,
    state: Option<&Arc<MagicRef>>,
    bitstring: bool,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
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
                return Ok(HandlerResult::Failed {
                    error,
                    reductions: reductions as u32,
                });
            }
        };
        if !done {
            drop(walker);
            return Ok(HandlerResult::Yield {
                continuation: IOLIST_CONTINUATION,
                state,
                reductions: reductions as u32,
            });
        }
        let (bytes, bits) = walker.take_parts();
        drop(walker);
        process.set_gc_enabled(restore_gc);
        let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
            .bitstring(&bytes, bits)
            .map_err(|_| BifError::SystemLimit)?;
        return Ok(HandlerResult::Done {
            value,
            reductions: reductions as u32,
        });
    }

    let mut walker = arinsal_bifs::IolistWalk::new(root, bitstring);
    let (done, reductions) = match walker.step(CHUNK) {
        Ok(progress) => progress,
        Err((error, reductions)) => {
            return Ok(HandlerResult::Failed {
                error,
                reductions: reductions as u32,
            });
        }
    };
    if !done {
        return Ok(HandlerResult::Yield {
            continuation: IOLIST_CONTINUATION,
            state: MagicRef::new(Mutex::new(walker)),
            reductions: reductions as u32,
        });
    }
    let (bytes, bits) = walker.take_parts();
    let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .bitstring(&bytes, bits)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(HandlerResult::Done {
        value,
        reductions: reductions as u32,
    })
}

fn iolist_binary_conversion(
    process: &mut Process,
    root: Term,
    state: Option<&Arc<MagicRef>>,
    _restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    const SIZE_YIELDS_PER_RED: usize = 8;
    if state.is_none() {
        let mut walk = arinsal_bifs::IolistSizeWalk::new(root);
        let initial_yield_count =
            (process.reductions.max(0) as usize).saturating_mul(SIZE_YIELDS_PER_RED);
        let (done, work) = match walk.step(initial_yield_count) {
            Ok(progress) => progress,
            Err((error, work)) => {
                return Ok(HandlerResult::Failed {
                    error,
                    reductions: work.div_ceil(SIZE_YIELDS_PER_RED) as u32,
                });
            }
        };
        let size_reductions = work.div_ceil(SIZE_YIELDS_PER_RED);
        if !done {
            return Ok(HandlerResult::Yield {
                continuation: IOLIST_CONTINUATION,
                state: MagicRef::new(Mutex::new(IolistBinaryPhase::Size(walk))),
                reductions: size_reductions as u32,
            });
        }
        let byte_len = walk.take_size();
        if byte_len == 0 {
            let value = arinsal_bifs::allocate_iolist_binary(
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
                0,
            )?;
            return Ok(HandlerResult::Done {
                value,
                reductions: size_reductions as u32,
            });
        }
        let mut output = if byte_len <= 64 {
            IolistOutput::Small(vec![0; byte_len])
        } else {
            IolistOutput::Writable(arinsal_bifs::allocate_iolist_binary(
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
                byte_len,
            )?)
        };
        let mut copy = arinsal_bifs::IolistCopyWalk::new(root);
        let available_reductions =
            (process.reductions.max(0) as usize).saturating_sub(size_reductions);
        if available_reductions == 0 {
            return Ok(HandlerResult::Yield {
                continuation: IOLIST_CONTINUATION,
                state: MagicRef::new(Mutex::new(IolistBinaryPhase::Copy {
                    output,
                    byte_len,
                    walk: copy,
                })),
                reductions: size_reductions as u32,
            });
        }
        let yield_count = available_reductions.saturating_mul(SIZE_YIELDS_PER_RED);
        let stepped = match &mut output {
            IolistOutput::Small(bytes) => copy.step(bytes, yield_count),
            IolistOutput::Writable(term) => {
                arinsal_bifs::with_iolist_binary_output(*term, |bytes| {
                    Ok(copy.step(bytes, yield_count))
                })?
            }
        };
        let (done, work) = match stepped {
            Ok(progress) => progress,
            Err((error, work)) => {
                output.finish_writer();
                return Ok(HandlerResult::Failed {
                    error,
                    reductions: (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32,
                });
            }
        };
        let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
        if !done {
            return Ok(HandlerResult::Yield {
                continuation: IOLIST_CONTINUATION,
                state: MagicRef::new(Mutex::new(IolistBinaryPhase::Copy {
                    output,
                    byte_len,
                    walk: copy,
                })),
                reductions,
            });
        }
        if copy.written() != byte_len {
            output.finish_writer();
            return Ok(HandlerResult::Failed {
                error: BifError::SystemLimit,
                reductions,
            });
        }
        let value = match output {
            IolistOutput::Small(bytes) => {
                TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                    .binary(&bytes)
                    .map_err(|_| BifError::SystemLimit)?
            }
            IolistOutput::Writable(term) => {
                arinsal_bifs::finish_iolist_binary_output(term);
                term
            }
        };
        return Ok(HandlerResult::Done { value, reductions });
    }
    // list_to_bitstring traps to the same continuation export as list_to_binary
    // (erl_iolist.c list_to_bitstring_continue), so the state decides which walk resumes.
    if state.is_some_and(|state| {
        state
            .downcast_ref::<Mutex<arinsal_bifs::IolistWalk>>()
            .is_some()
    }) {
        return iolist_conversion(process, root, state, true, _restore_gc);
    }
    let state = Arc::clone(state.expect("resumed iolist conversion has state"));
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
                    return Ok(HandlerResult::Failed { error, reductions });
                }
            };
            size_reductions = work.div_ceil(SIZE_YIELDS_PER_RED);
            if !done {
                drop(phase);
                return Ok(HandlerResult::Yield {
                    continuation: IOLIST_CONTINUATION,
                    state,
                    reductions: size_reductions as u32,
                });
            }

            let byte_len = walk.take_size();
            if byte_len == 0 {
                let value = arinsal_bifs::allocate_iolist_binary(
                    &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
                    0,
                )?;
                *phase = IolistBinaryPhase::Done;
                return Ok(HandlerResult::Done {
                    value,
                    reductions: size_reductions as u32,
                });
            }
            let output = if byte_len <= 64 {
                IolistOutput::Small(vec![0; byte_len])
            } else {
                IolistOutput::Writable(arinsal_bifs::allocate_iolist_binary(
                    &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
                    byte_len,
                )?)
            };
            *phase = IolistBinaryPhase::Copy {
                output,
                byte_len,
                walk: arinsal_bifs::IolistCopyWalk::new(root),
            };
            available_reductions = available_reductions.saturating_sub(size_reductions);
            if available_reductions == 0 {
                drop(phase);
                return Ok(HandlerResult::Yield {
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
    let stepped = match output {
        IolistOutput::Small(bytes) => walk.step(bytes, yield_count),
        IolistOutput::Writable(term) => arinsal_bifs::with_iolist_binary_output(*term, |bytes| {
            Ok(walk.step(bytes, yield_count))
        })?,
    };
    let (done, work) = match stepped {
        Ok(progress) => progress,
        Err((error, work)) => {
            let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
            output.finish_writer();
            return Ok(HandlerResult::Failed { error, reductions });
        }
    };
    let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
    if !done {
        drop(phase);
        return Ok(HandlerResult::Yield {
            continuation: IOLIST_CONTINUATION,
            state,
            reductions,
        });
    }
    if walk.written() != *byte_len {
        output.finish_writer();
        return Ok(HandlerResult::Failed {
            error: BifError::SystemLimit,
            reductions,
        });
    }
    let result = match output {
        IolistOutput::Small(bytes) => {
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .binary(bytes)
                .map_err(|_| BifError::SystemLimit)?
        }
        IolistOutput::Writable(term) => {
            arinsal_bifs::finish_iolist_binary_output(*term);
            *term
        }
    };
    *phase = IolistBinaryPhase::Done;
    Ok(HandlerResult::Done {
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
) -> Result<HandlerResult, BifError> {
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
                Ok(HandlerResult::Yield {
                    continuation: BINARY_TO_TERM_CONTINUATION,
                    state,
                    reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
                })
            }
            Ok((Some(value), consumed)) => {
                process.set_gc_enabled(restore_gc);
                Ok(HandlerResult::Done {
                    value,
                    reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
                })
            }
            Err((error, consumed)) => {
                process.set_gc_enabled(restore_gc);
                Ok(HandlerResult::Failed {
                    error: decode_trap_error(error),
                    reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
                })
            }
        };
    }

    let mut decoder = arinsal_bifs::DecodeWalk::new(args)?;
    match decode_step(process, &mut decoder, chunk_bytes) {
        Ok((None, consumed)) => Ok(HandlerResult::Yield {
            continuation: BINARY_TO_TERM_CONTINUATION,
            state: MagicRef::new(Mutex::new(decoder)),
            reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
        }),
        Ok((Some(value), consumed)) => {
            process.set_gc_enabled(restore_gc);
            Ok(HandlerResult::Done {
                value,
                reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
            })
        }
        Err((error, consumed)) => {
            process.set_gc_enabled(restore_gc);
            Ok(HandlerResult::Failed {
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
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.reductions);
    decoder.step_into(chunk_bytes, &mut ctx)
}

fn decode_trap_error(error: BifError) -> BifError {
    match error {
        BifError::Unsupported(_) => BifError::BADARG,
        other => other,
    }
}

/// Bits copied per reduction: a cache line (`ERTS_CACHE_LINE_SIZE * 8`, 64-byte lines).
const BITSTRING_COPY_LOOP_FACTOR: u64 = 64 * 8;

/// `ERTS_VBUMP_ALL_REDS`: the rest of the slice is given up without being the process's own
/// work. The scheduler leaves the process at the next reduction check, and `virtual_reds`
/// keeps the given-up amount out of the process's reduction count.
fn vbump_all_reds(process: &mut Process) {
    if process.reductions > 0 {
        process.virtual_reds = process
            .virtual_reds
            .saturating_add(process.reductions as u32);
    }
    process.reductions = 0;
}

/// `get_reds`: the loop budget of one slice, `ERTS_BIF_REDS_LEFT * loop_factor`, capped by
/// the `binary_loop_limit` debug state and never zero.
fn binary_loop_budget(process: &Process, loop_factor: u64) -> u64 {
    let reds = u64::try_from(process.reductions.max(0))
        .unwrap_or(0)
        .saturating_mul(loop_factor);
    let limit = crate::natives::erts_debug::binary_loop_limit();
    if limit != 0 && limit < reds {
        return limit;
    }
    reds.max(1)
}

fn binary_copy(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
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
        let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
            .binary(&[])
            .map_err(|_| BifError::SystemLimit)?;
        return Ok(HandlerResult::Done {
            value,
            reductions: 1,
        });
    }
    let target_bits = (len as u64).saturating_mul(8);
    let max_copy_bits = binary_loop_budget(process, BITSTRING_COPY_LOOP_FACTOR);
    if let Some(state) = state {
        let state = Arc::clone(state);
        let copy = state
            .downcast_ref::<Mutex<BinaryCopyState>>()
            .ok_or(BifError::BADARG)?;
        let mut copy = copy.lock().map_err(|_| BifError::SystemLimit)?;
        let initial_target_offset = (copy.copied as u64).saturating_mul(8);
        let mut trap_offset = target_bits;
        if (u64::MAX - max_copy_bits) < initial_target_offset
            && initial_target_offset.saturating_add(max_copy_bits) < trap_offset
        {
            trap_offset = initial_target_offset + max_copy_bits;
        }
        copy_binary_to(&mut copy, input, input_len, len, trap_offset)?;
        if copy.copied == len {
            let bits_copied = target_bits - initial_target_offset;
            process.set_gc_enabled(restore_gc);
            let value = finish_binary_copy(process, &copy.bytes)?;
            return Ok(HandlerResult::Done {
                value,
                reductions: reductions_from(bits_copied / BITSTRING_COPY_LOOP_FACTOR),
            });
        }
        drop(copy);
        vbump_all_reds(process);
        return Ok(HandlerResult::Yield {
            continuation: BINARY_COPY_CONTINUATION,
            state,
            reductions: 0,
        });
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| BifError::SystemLimit)?;
    bytes.resize(len, 0);
    let mut copy = BinaryCopyState { bytes, copied: 0 };
    copy_binary_to(
        &mut copy,
        input,
        input_len,
        len,
        max_copy_bits.min(target_bits),
    )?;
    if copy.copied < len {
        vbump_all_reds(process);
        return Ok(HandlerResult::Yield {
            continuation: BINARY_COPY_CONTINUATION,
            state: MagicRef::new(Mutex::new(copy)),
            reductions: 0,
        });
    }
    let value = finish_binary_copy(process, &copy.bytes)?;
    Ok(HandlerResult::Done {
        value,
        reductions: reductions_from(target_bits / BITSTRING_COPY_LOOP_FACTOR),
    })
}

fn reductions_from(reductions: u64) -> u32 {
    u32::try_from(reductions).unwrap_or(u32::MAX)
}

/// `binary_copy_loop`: copy the source repeatedly up to `trap_offset` bits of the target.
fn copy_binary_to(
    copy: &mut BinaryCopyState,
    input: Term,
    input_len: usize,
    len: usize,
    trap_offset: u64,
) -> Result<(), BifError> {
    let end = usize::try_from(trap_offset / 8).map_or(len, |end| end.min(len));
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
    copy.copied = end.max(copy.copied);
    Ok(())
}

fn finish_binary_copy(process: &mut Process, bytes: &[u8]) -> Result<Term, BifError> {
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .binary(bytes)
        .map_err(|_| BifError::SystemLimit)
}

fn term_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    term_encode(process, args, state, restore_gc, false)
}

fn term_to_iovec(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    term_encode(process, args, state, restore_gc, true)
}

fn term_encode(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    restore_gc: bool,
    iovec: bool,
) -> Result<HandlerResult, BifError> {
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
            return Ok(HandlerResult::Yield {
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
        return Ok(HandlerResult::Yield {
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
) -> Result<HandlerResult, BifError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
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
    Ok(HandlerResult::Done { value, reductions })
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
) -> Result<HandlerResult, BifError> {
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
            return Ok(HandlerResult::Yield {
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
        return Ok(HandlerResult::Yield {
            continuation: PTAB_LIST_CONTINUATION,
            state: MagicRef::new(Mutex::new(list)),
            reductions: 1,
        });
    }
    let (done, spent) = scan_process_table(&mut list, table_max, reds_left);
    if !done {
        return Ok(HandlerResult::Yield {
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
) -> Result<HandlerResult, BifError> {
    let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(pid_terms)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(HandlerResult::Done {
        value,
        reductions: spent,
    })
}

#[cfg(test)]
mod export_trap_tests {
    use super::*;
    use arinsal_etf::OwnedTerm;

    /// A collection between the trap and its resume must keep the trapped arguments: they are
    /// live X registers now, not state that is only valid while GC is disabled.
    #[test]
    fn export_trap_arguments_survive_a_collection_while_trapped() {
        let mut process = Process::new();
        let tuple = TermBuilder::new(&mut process.heap)
            .tuple(&[Term::small(7).unwrap(), Term::small(8).unwrap()])
            .unwrap();
        let false_atom = Term::atom(global_atoms().intern("false").unwrap());
        let true_atom = Term::atom(global_atoms().intern("true").unwrap());
        let trap = crate::ExportTrap {
            continuation: "erts_internal:flush_monitor_messages/3",
            args: vec![tuple, false_atom, true_atom],
        };
        let callee = (
            global_atoms().intern("erlang").unwrap(),
            global_atoms().intern("demonitor").unwrap(),
        );
        install_export_trap(&mut process, 0, callee, &trap);
        assert!(process.heap.gc_enabled, "export traps keep GC enabled");

        // A collection while the process is scheduled out: the live X registers are the roots.
        process
            .collect_heap_roots(process.gc_live, &mut [], 0)
            .unwrap();

        let Some(Ok(ResumeResult::Export(resumed))) = run_trapped_export(&mut process, None) else {
            panic!("the export trap resumes as an export call");
        };
        assert_eq!(
            resumed.continuation,
            "erts_internal:flush_monitor_messages/3"
        );
        assert_eq!(
            arinsal_term::to_owned(resumed.args[0]).unwrap(),
            OwnedTerm::Tuple(vec![OwnedTerm::Int(7), OwnedTerm::Int(8)])
        );
        assert_eq!(resumed.args[1], false_atom);
        assert_eq!(resumed.args[2], true_atom);
        assert!(process.cold.as_ref().is_none_or(|c| c.bif_trap.is_none()));
    }
}
