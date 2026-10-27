//! Resumable BIF calls and their private continuation exports.

use super::*;
use arinsal_bifs::BifError;
use arinsal_term::{MagicRef, global_atoms};
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
    /// Transfer directly to the BIF's export continuation without scheduling out.
    Export(crate::ExportTrap),
}

impl HandlerResult {
    /// The charge the handler reported for its run.
    pub(crate) fn reductions(&self) -> u32 {
        match self {
            Self::Done { reductions, .. }
            | Self::Failed { reductions, .. }
            | Self::Yield { reductions, .. } => *reductions,
            Self::Export(_) => 0,
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
/// The continuation of `lists:reverse/2`: the BIF traps to its own export with the cells
/// still to walk and the reversed prefix as arguments.
pub(crate) const REVERSE_CONTINUATION: &str = "lists:reverse/2";
const IOLIST_CONTINUATION: &str = "erts_internal:list_to_bitstring_continue/1";
const IOLIST_SIZE_CONTINUATION: &str = "erts_internal:iolist_size_continue/1";
const IOLIST_TO_IOVEC_CONTINUATION: &str = "erts_internal:iolist_to_iovec_continue/1";
const BINARY_TO_TERM_CONTINUATION: &str = "erts_internal:binary_to_term_trap/1";
const BINARY_COPY_CONTINUATION: &str = "erlang:binary_copy_trap/3";
const BINARY_TO_LIST_CONTINUATION: &str = "erlang:binary_to_list/1";
const TERM_TO_BINARY_CONTINUATION: &str = "erts_internal:term_to_binary_trap/1";
const BINARY_SEARCH_CONTINUATION: &str = "erlang:binary_find_trap/3";
pub(crate) const PTAB_LIST_CONTINUATION: &str = "erlang:ptab_list_continue/2";
const MAPS_MERGE_CONTINUATION: &str = "maps:merge_trap/1";
const MAPS_KEYS_CONTINUATION: &str = "maps:keys/1";
const MAPS_VALUES_CONTINUATION: &str = "maps:values/1";
const MAPS_FROM_LIST_CONTINUATION: &str = "maps:from_list/1";
const MAPS_FROM_KEYS_CONTINUATION: &str = "maps:from_keys/2";
const SUBTRACT_CONTINUATION: &str = "erlang:--/2";
const CONTEXT_REDS: usize = 4000;
const RE_RUN_CONTINUATION: &str = "erlang:re_run_trap/3";
const RE_GRUN_CONTINUATION: &str = "re:grun/3";
const RE_URUN_CONTINUATION: &str = "re:urun/3";

// C payload sizes passed to erts_create_magic_binary on macOS arm64. The separate magic binary
// data offset is added by MagicRef::with_erts_payload_size.
// Port of erts/emulator/beam/erl_bif_lists.c (ErtsAppendContext, ErtsSubtractContext).
const ERTS_APPEND_CONTEXT_SIZE: usize = 40;
const ERTS_SUBTRACT_CONTEXT_SIZE: usize = 192;
// Port of erts/emulator/beam/erl_term_hashing.c (ErtsMakeHash2Context).
const ERTS_HASH2_CONTEXT_SIZE: usize = 136;
// Port of erts/emulator/beam/erl_unicode.c (RestartContext).
const ERTS_UNICODE_RESTART_CONTEXT_SIZE: usize = 40;
// Port of erts/emulator/beam/erl_bif_re.c (RestartContext).
const ERTS_REGEX_RESTART_CONTEXT_SIZE: usize = 64;
// Port of erts/emulator/beam/binary.c (ErtsB2LState) and erl_bif_binary.c
// (BinaryFindContext).
const ERTS_BINARY_TO_LIST_STATE_SIZE: usize = 40;
const ERTS_BINARY_FIND_CONTEXT_SIZE: usize = 312;
// Port of erts/emulator/beam/utils.c (erts_ycf_trap_driver_state_holder) and erl_map.c
// (HashmapMergeContext).
const ERTS_YCF_TRAP_HOLDER_SIZE: usize = 24;
const ERTS_HASHMAP_MERGE_CONTEXT_SIZE: usize = 56;
// Port of erts/emulator/beam/erl_iolist.c (ErtsL2BState, IOListSizeState,
// ErtsIOList2VecState).
const ERTS_L2B_STATE_SIZE: usize = 176;
const ERTS_IOLIST_SIZE_STATE_SIZE: usize = 88;
const ERTS_IOLIST_TO_IOVEC_STATE_SIZE: usize = 152;
// Port of erts/emulator/beam/external.c (B2TContext), including its decode union.
const ERTS_BINARY_TO_TERM_CONTEXT_SIZE: usize = 296;
// Port of erts/emulator/beam/dist.h (TTBContext), whose encode union is larger than B2TContext.
const ERTS_TERM_TO_BINARY_CONTEXT_SIZE: usize = 296;
// Port of erts/emulator/beam/erl_ptab.c (ErtsPTabListBifData).
const ERTS_PTAB_LIST_STATE_SIZE: usize = 64;

fn magic_binary_state<T: std::any::Any + Send + Sync>(
    payload: T,
    c_payload_size: usize,
) -> Arc<MagicRef> {
    MagicRef::with_erts_payload_size(payload, c_payload_size)
}

/// OTP keeps these continuations in BIF arguments/registers and allocates no magic binary.
fn argument_trap_state<T: std::any::Any + Send + Sync>(payload: T) -> Arc<MagicRef> {
    MagicRef::with_orig_size(payload, 0)
}

/// Build the continuation argument that owns an erts magic binary.
fn trap_state_term(
    process: &mut Process,
    state: &Arc<MagicRef>,
) -> Result<Option<Term>, arinsal_term::TermError> {
    if state.orig_size() == 0 {
        return Ok(None);
    }
    // Port of erts/emulator/beam/erl_bif_lists.c (append_create_trap_state): the magic reference
    // thing is a live continuation argument, so its off-heap owner charges orig_size to vheap.
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let term = arinsal_term::TermBuilder::new(&mut heap).magic_ref(Arc::clone(state))?;
    Ok(Some(term))
}

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
                !released.kept && released.module == process.module && released.ip == process.ip()
            });
        (!released_by_call).then(|| crate::proc_create::TrapReturn {
            module: process.module,
            ip: process.ip() + 1,
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
// handler only supplies the reduction budget; the trap's arguments are the cells still
// to walk and the reversed prefix, which a resumed call reads like a first call does.
fn lists_reverse(
    process: &mut Process,
    args: &[Term],
    _state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    let reds = process.reductions.max(0).min(CONTEXT_REDS as i32) as usize;
    let max_cells = reds
        .saturating_mul(arinsal_bifs::REVERSE_ONHEAP_CELLS_PER_RED)
        .max(1);
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let step = arinsal_bifs::lists_reverse(&mut ctx, args[0], args[1], max_cells);
    drop(bif_state);
    let step = step?;
    Ok(match step {
        arinsal_bifs::ReverseStep::Done(value) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::ReverseStep::Trap(cont) => HandlerResult::Yield {
            continuation: REVERSE_CONTINUATION,
            state: argument_trap_state(Mutex::new(cont)),
            reductions: 0,
        },
    })
}

/// The arguments `BIF_TRAP2(lists:reverse/2, list, tail)` leaves for the next slice.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_reverse_alloc and lists_reverse_onheap: BIF_TRAP2 with the remaining
// list and the reversed prefix), OTP-29.1.1.
fn reverse_trap_args(state: &Arc<MagicRef>) -> Option<[Term; 2]> {
    let cont = state
        .downcast_ref::<Mutex<arinsal_bifs::ReverseCont>>()?
        .lock()
        .ok()?;
    Some([cont.list(), cont.tail()])
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
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let step = match arinsal_bifs::lists_member(&mut ctx, term, list, max_iter) {
        Ok(step) => step,
        Err(error) => {
            drop(bif_state);
            return Ok(HandlerResult::Failed {
                error,
                reductions: 0,
            });
        }
    };
    drop(bif_state);
    Ok(match step {
        arinsal_bifs::MemberStep::Done(found) => HandlerResult::Done {
            value: bool_atom(found),
            reductions: 0,
        },
        arinsal_bifs::MemberStep::More(cont) => HandlerResult::Yield {
            continuation: "lists:member/2",
            state: argument_trap_state(Mutex::new(cont)),
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
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let step =
        match arinsal_bifs::lists_key(&mut ctx, op, key, pos, list, arinsal_bifs::KEYFIND_MAX_ITER)
        {
            Ok(step) => step,
            Err(error) => {
                let reductions = ctx.reductions();
                drop(bif_state);
                process.reductions_used = process
                    .reductions_used
                    .saturating_add(u64::from(reductions));
                return Ok(HandlerResult::Failed {
                    error,
                    reductions: 0,
                });
            }
        };
    let reductions = ctx.reductions();
    drop(bif_state);
    process.reductions_used = process
        .reductions_used
        .saturating_add(u64::from(reductions));
    Ok(match step {
        arinsal_bifs::KeyOutcome::Done(value) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::KeyOutcome::More(cont) => HandlerResult::Yield {
            continuation,
            state: argument_trap_state(Mutex::new(cont)),
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
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let step = match arinsal_bifs::lists_append(&mut ctx, cont, onheap, alloc) {
        Ok(step) => step,
        Err(error) => {
            let reductions = ctx.reductions();
            drop(bif_state);
            process.reductions_used = process
                .reductions_used
                .saturating_add(u64::from(reductions));
            return Ok(HandlerResult::Failed {
                error,
                reductions: 0,
            });
        }
    };
    let reductions = ctx.reductions();
    drop(bif_state);
    process.reductions_used = process
        .reductions_used
        .saturating_add(u64::from(reductions));
    Ok(match step {
        arinsal_bifs::AppendStep::Done(value) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::AppendStep::More(next) => {
            let state = if let Some(state) = state {
                let saved = state
                    .downcast_ref::<Mutex<arinsal_bifs::AppendCont>>()
                    .ok_or(BifError::BADARG)?;
                *saved.lock().map_err(|_| BifError::SystemLimit)? = next;
                Arc::clone(state)
            } else {
                magic_binary_state(Mutex::new(next), ERTS_APPEND_CONTEXT_SIZE)
            };
            HandlerResult::Yield {
                continuation,
                state,
                reductions: 0,
            }
        }
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

fn chksum_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    kind: arinsal_bifs::ChksumKind,
    md5_update: bool,
) -> Result<HandlerResult, BifError> {
    let resumed = match state {
        Some(state) => Some(
            state
                .downcast_ref::<Mutex<arinsal_bifs::ChksumCont>>()
                .ok_or(BifError::BADARG)?
                .lock()
                .map_err(|_| BifError::SystemLimit)?
                .clone(),
        ),
        None => None,
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let step = match &resumed {
        Some(cont) => arinsal_bifs::chksum_resume(&mut ctx, cont),
        None if md5_update => {
            arinsal_bifs::chksum_start(&mut ctx, arinsal_bifs::ChksumKind::Md5Update, args)
        }
        None => arinsal_bifs::chksum_start(&mut ctx, kind, args),
    };
    drop(bif_state);
    Ok(match step {
        Ok(arinsal_bifs::ChksumStep::Done(value)) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        Ok(arinsal_bifs::ChksumStep::More(cont)) => HandlerResult::Yield {
            continuation: cont.continuation(),
            state: argument_trap_state(Mutex::new(cont)),
            reductions: 0,
        },
        Err(error) => HandlerResult::Failed {
            error,
            reductions: 0,
        },
    })
}

fn erlang_crc32(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    chksum_trap(process, args, state, arinsal_bifs::ChksumKind::Crc32, false)
}

fn erlang_adler32(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    chksum_trap(
        process,
        args,
        state,
        arinsal_bifs::ChksumKind::Adler32,
        false,
    )
}

fn erlang_md5_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    chksum_trap(process, args, state, arinsal_bifs::ChksumKind::Md5, false)
}

// Port of erts/emulator/beam/erl_bif_chksum.c:551-585 (md5_update_2), OTP-29.1.1.
fn erlang_md5_update_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    chksum_trap(process, args, state, arinsal_bifs::ChksumKind::Md5, true)
}

fn phash2_trap(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
) -> Result<HandlerResult, BifError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let Some(state) = state else {
        let step = arinsal_bifs::phash2_start(&mut ctx, args);
        drop(bif_state);
        return Ok(match step {
            Ok(arinsal_bifs::Phash2Step::Done(value)) => HandlerResult::Done {
                value,
                reductions: 0,
            },
            Ok(arinsal_bifs::Phash2Step::More(cont)) => HandlerResult::Yield {
                continuation: cont.continuation(),
                state: magic_binary_state(Mutex::new(*cont), ERTS_HASH2_CONTEXT_SIZE),
                reductions: 0,
            },
            Err(error) => HandlerResult::Failed {
                error,
                reductions: 0,
            },
        });
    };
    let saved = state
        .downcast_ref::<Mutex<arinsal_bifs::Phash2Cont>>()
        .ok_or(BifError::BADARG)?;
    let mut cont = saved.lock().map_err(|_| BifError::SystemLimit)?;
    let step = arinsal_bifs::phash2_slice(&mut ctx, &mut cont);
    let continuation = cont.continuation();
    drop(cont);
    drop(bif_state);
    Ok(match step {
        Ok(Some(value)) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        Ok(None) => HandlerResult::Yield {
            continuation,
            state: Arc::clone(state),
            reductions: 0,
        },
        Err(error) => HandlerResult::Failed {
            error,
            reductions: 0,
        },
    })
}

fn erlang_phash2_trap_1(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    phash2_trap(process, args, state)
}

fn erlang_length_trap(
    process: &mut Process,
    _args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    let state = state.ok_or(BifError::BADARG)?;
    let (list, acc) = {
        let saved = state
            .downcast_ref::<Mutex<arinsal_bifs::LengthCont>>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        (saved.list(), saved.acc())
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let step = arinsal_bifs::length_slice(&mut ctx, list, acc);
    drop(bif_state);
    Ok(match step {
        Ok(arinsal_bifs::LengthStep::Done(value)) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        Ok(arinsal_bifs::LengthStep::More(cont)) => HandlerResult::Yield {
            continuation: "erlang:length/3",
            state: argument_trap_state(Mutex::new(cont)),
            reductions: 0,
        },
        Err(error) => HandlerResult::Failed {
            error,
            reductions: 0,
        },
    })
}

fn unicode_trap(
    process: &mut Process,
    state: Option<&Arc<MagicRef>>,
) -> Result<HandlerResult, BifError> {
    let cont = state
        .ok_or(BifError::BADARG)?
        .downcast_ref::<Mutex<arinsal_bifs::UnicodeCont>>()
        .ok_or(BifError::BADARG)?
        .lock()
        .map_err(|_| BifError::SystemLimit)?
        .clone();
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    let step = arinsal_bifs::unicode_resume(&mut ctx, &cont);
    drop(bif_state);
    Ok(match step {
        arinsal_bifs::UnicodeStep::Done(value) => HandlerResult::Done {
            value,
            reductions: 0,
        },
        arinsal_bifs::UnicodeStep::More(cont) => HandlerResult::Yield {
            continuation: cont.continuation(),
            state: magic_binary_state(Mutex::new(cont), ERTS_UNICODE_RESTART_CONTEXT_SIZE),
            reductions: 0,
        },
    })
}

fn unicode_convert_start(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    function: &'static str,
) -> Result<HandlerResult, BifError> {
    if state.is_some() {
        return unicode_trap(process, state);
    }
    let bif =
        arinsal_bifs::lookup("unicode", function, args.len() as u8).ok_or(BifError::BADARG)?;
    let (result, deferred) = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        // Port of erts/emulator/beam/erl_unicode.c:166 (allowed_iterations), OTP-29.1.1:
        // the loop budget rereads FCALLS after cost_to_proc charges it.
        let mut state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut state);
        let result = bif(&mut ctx, args)?;
        let deferred = ctx.take_deferred();
        (result, deferred)
    };
    match deferred.map(|trap| *trap) {
        Some(arinsal_bifs::DeferredTrap::Unicode(cont)) => Ok(HandlerResult::Yield {
            continuation: cont.continuation(),
            state: magic_binary_state(Mutex::new(cont), ERTS_UNICODE_RESTART_CONTEXT_SIZE),
            reductions: 0,
        }),
        Some(_) => Err(BifError::BADARG),
        None => Ok(HandlerResult::Done {
            value: result,
            reductions: 0,
        }),
    }
}

// Port of erts/emulator/beam/erl_unicode.c:931 (unicode_characters_to_binary_2), OTP-29.1.1.
fn unicode_characters_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    if state.is_none()
        && let Some(value) = arinsal_bifs::unicode_utf8_binary_fast_path(args)?
    {
        return Ok(HandlerResult::Done {
            value,
            reductions: 0,
        });
    }
    unicode_convert_start(process, args, state, "characters_to_binary")
}

// Port of erts/emulator/beam/erl_unicode.c:1122 (unicode_characters_to_list_2), OTP-29.1.1.
fn unicode_characters_to_list(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    unicode_convert_start(process, args, state, "characters_to_list")
}

macro_rules! unicode_trap_entry {
    ($name:ident) => {
        fn $name(
            process: &mut Process,
            _args: &[Term],
            state: Option<&Arc<MagicRef>>,
            _pid: Option<arinsal_sched::Pid>,
            _gc_changed: bool,
        ) -> Result<HandlerResult, BifError> {
            unicode_trap(process, state)
        }
    };
}

unicode_trap_entry!(erlang_characters_to_utf8_trap);
unicode_trap_entry!(erlang_characters_to_list_trap_1);
unicode_trap_entry!(erlang_characters_to_list_trap_2);
unicode_trap_entry!(erlang_characters_to_list_trap_3);
unicode_trap_entry!(erlang_characters_to_list_trap_4);

fn bool_atom(value: bool) -> Term {
    Term::atom(
        global_atoms()
            .intern(if value { "true" } else { "false" })
            .unwrap(),
    )
}

const ENTRIES: &[Entry] = &[
    Entry {
        module: "unicode",
        function: "characters_to_binary",
        arity: 2,
        continuation: "erlang:characters_to_utf8_trap/4",
        handler: unicode_characters_to_binary,
    },
    Entry {
        module: "unicode",
        function: "characters_to_list",
        arity: 2,
        continuation: "erlang:characters_to_list_trap_1/3",
        handler: unicode_characters_to_list,
    },
    Entry {
        module: "erlang",
        function: "characters_to_utf8_trap",
        arity: 4,
        continuation: "erlang:characters_to_utf8_trap/4",
        handler: erlang_characters_to_utf8_trap,
    },
    Entry {
        module: "erlang",
        function: "characters_to_list_trap_1",
        arity: 3,
        continuation: "erlang:characters_to_list_trap_1/3",
        handler: erlang_characters_to_list_trap_1,
    },
    Entry {
        module: "erlang",
        function: "characters_to_list_trap_2",
        arity: 3,
        continuation: "erlang:characters_to_list_trap_2/3",
        handler: erlang_characters_to_list_trap_2,
    },
    Entry {
        module: "erlang",
        function: "characters_to_list_trap_3",
        arity: 3,
        continuation: "erlang:characters_to_list_trap_3/3",
        handler: erlang_characters_to_list_trap_3,
    },
    Entry {
        module: "erlang",
        function: "characters_to_list_trap_4",
        arity: 1,
        continuation: "erlang:characters_to_list_trap_4/1",
        handler: erlang_characters_to_list_trap_4,
    },
    Entry {
        module: "erlang",
        function: "length",
        arity: 3,
        continuation: "erlang:length/3",
        handler: erlang_length_trap,
    },
    Entry {
        module: "erlang",
        function: "phash2_trap",
        arity: 1,
        continuation: "erlang:phash2_trap/1",
        handler: erlang_phash2_trap_1,
    },
    Entry {
        module: "erlang",
        function: "phash2_trap",
        arity: 2,
        continuation: "erlang:phash2_trap/2",
        handler: erlang_phash2_trap_1,
    },
    // Port of erts/emulator/beam/bif.c:5350 (phash2_1), OTP-29.1.1.
    Entry {
        module: "erlang",
        function: "phash2",
        arity: 1,
        continuation: "erlang:phash2_trap/1",
        handler: erlang_phash2_trap_1,
    },
    // Port of erts/emulator/beam/bif.c:5362 (phash2_2), OTP-29.1.1.
    Entry {
        module: "erlang",
        function: "phash2",
        arity: 2,
        continuation: "erlang:phash2_trap/2",
        handler: erlang_phash2_trap_1,
    },
    // Port of erts/emulator/beam/erl_bif_chksum.c:290 (crc32_1), OTP-29.1.1.
    Entry {
        module: "erlang",
        function: "crc32",
        arity: 1,
        continuation: "erlang:crc32/2",
        handler: erlang_crc32,
    },
    Entry {
        module: "erlang",
        function: "crc32",
        arity: 2,
        continuation: "erlang:crc32/2",
        handler: erlang_crc32,
    },
    Entry {
        module: "erlang",
        function: "adler32",
        arity: 2,
        continuation: "erlang:adler32/2",
        handler: erlang_adler32,
    },
    // Port of erts/emulator/beam/erl_bif_chksum.c:370 (adler32_1), OTP-29.1.1.
    Entry {
        module: "erlang",
        function: "adler32",
        arity: 1,
        continuation: "erlang:adler32/2",
        handler: erlang_adler32,
    },
    // Port of erts/emulator/beam/erl_bif_chksum.c:455 (md5_1), OTP-29.1.1.
    Entry {
        module: "erlang",
        function: "md5",
        arity: 1,
        continuation: "erlang:md5_trap/2",
        handler: erlang_md5_trap,
    },
    Entry {
        module: "erlang",
        function: "md5_trap",
        arity: 2,
        continuation: "erlang:md5_trap/2",
        handler: erlang_md5_trap,
    },
    Entry {
        module: "erlang",
        function: "md5_update",
        arity: 2,
        continuation: "erlang:md5_update/2",
        handler: erlang_md5_update_trap,
    },
    Entry {
        module: "lists",
        function: "reverse",
        arity: 2,
        continuation: REVERSE_CONTINUATION,
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
        module: "erlang",
        function: "ports",
        arity: 0,
        continuation: PTAB_LIST_CONTINUATION,
        handler: ports,
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
        function: "external_size",
        arity: 1,
        continuation: "erlang:external_size/1",
        handler: external_size,
    },
    Entry {
        module: "erlang",
        function: "external_size",
        arity: 2,
        continuation: "erlang:external_size/2",
        handler: external_size,
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

// Port of erts/emulator/beam/erl_bif_binary.c:2365-2374 (CopyBinState), OTP-29.1.1.
struct BinaryCopyState {
    result: Term,
    copied_bits: usize,
}

enum IolistBinaryPhase {
    Size(arinsal_bifs::IolistSizeWalk),
    Copy {
        output: IolistOutput,
        bit_len: usize,
        bitstring: bool,
        walk: arinsal_bifs::IolistCopyWalk,
        restore_gc: bool,
    },
    Done,
}

/// Output staging for `erts_new_bitstring`: up to 64 bytes stay on heap after the walk completes.
// Port of erts/emulator/beam/erl_bits.c:2841-2858 (erts_new_bitstring_refc), OTP-29.1.1.
enum IolistOutput {
    Small(arinsal_term::HeapBinaryWriter),
    Bitstring(Vec<u8>),
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
    let dispatch = {
        let mut heap = crate::ProcessHeapHandle(&mut process.heap);
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = arinsal_bifs::Ctx::new(&mut heap, &mut state);
        arinsal_re::run_slice_or_global(
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
    Ok(match dispatch {
        arinsal_re::RunDispatch::Run { progress, loops } => {
            let reductions =
                (loops / arinsal_re::LOOP_FACTOR as u64).min(u64::from(u32::MAX)) as u32;
            match progress {
                arinsal_re::Progress::Done(value) => HandlerResult::Done { value, reductions },
                arinsal_re::Progress::Yield(run) => HandlerResult::Yield {
                    continuation: RE_RUN_CONTINUATION,
                    state: magic_binary_state(
                        Mutex::new(Some(run)),
                        ERTS_REGEX_RESTART_CONTEXT_SIZE,
                    ),
                    reductions,
                },
            }
        }
        arinsal_re::RunDispatch::Global(arinsal_re::GlobalRun::Return(value)) => {
            HandlerResult::Done {
                value,
                reductions: 0,
            }
        }
        arinsal_re::RunDispatch::Global(arinsal_re::GlobalRun::UnicodeTrap) => {
            // Port of erts/emulator/beam/erl_bif_re.c:1530-1533 and :1590-1597 (urun_trap_exportp),
            // OTP-29.1.1.
            process.x.ensure_x(3);
            process.x[..3].copy_from_slice(&[
                args[0],
                args[1],
                args.get(2).copied().unwrap_or(Term::NIL),
            ]);
            process.gc_live = 3;
            HandlerResult::Export(crate::ExportTrap {
                continuation: RE_URUN_CONTINUATION,
                args: vec![args[0], args[1], args.get(2).copied().unwrap_or(Term::NIL)],
            })
        }
        arinsal_re::RunDispatch::Global(arinsal_re::GlobalRun::Trap { pattern, options }) => {
            // Port of erts/emulator/beam/erl_bif_re.c:1557-1603 (grun_trap_exportp), OTP-29.1.1.
            process.x.ensure_x(3);
            process.x[..3].copy_from_slice(&[args[0], pattern, options]);
            process.gc_live = 3;
            HandlerResult::Export(crate::ExportTrap {
                continuation: RE_GRUN_CONTINUATION,
                args: vec![args[0], pattern, options],
            })
        }
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
    let mut state = arinsal_bifs::BifState::default();
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap, &mut state);
    ctx.set_reduction_budget(process.reductions.max(0) as usize);
    let value = bif(&mut ctx, args)?;
    let reductions = ctx.reductions();
    match ctx.take_deferred().map(|trap| *trap) {
        Some(arinsal_bifs::DeferredTrap::BinaryToList(walk)) => Ok(HandlerResult::Yield {
            continuation: BINARY_TO_LIST_CONTINUATION,
            state: magic_binary_state(Mutex::new(walk), ERTS_BINARY_TO_LIST_STATE_SIZE),
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
            // Port of erts/emulator/beam/erl_bif_binary.c (binary_find_trap),
            // OTP-29.1.1: only the first call bumps all reductions before trapping.
            return Ok(HandlerResult::Yield {
                continuation: BINARY_SEARCH_CONTINUATION,
                state,
                reductions: 0,
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
            state: magic_binary_state(Mutex::new(search), ERTS_BINARY_FIND_CONTEXT_SIZE),
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
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
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
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
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
                state: magic_binary_state(Mutex::new(Some(walk)), ERTS_YCF_TRAP_HOLDER_SIZE),
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

    // erts maps_keys_1 handles a flatmap before any yielding state exists.
    let mut walk = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
        if let Some(value) = arinsal_bifs::MapsProjectionWalk::start_flat(&mut ctx, args[0], keys)?
        {
            return Ok(HandlerResult::Done {
                value,
                reductions: 0,
            });
        }
        arinsal_bifs::MapsProjectionWalk::start_hashmap(&mut ctx, args[0], keys)?
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
            state: magic_binary_state(Mutex::new(Some(walk)), ERTS_YCF_TRAP_HOLDER_SIZE),
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
            state: magic_binary_state(
                MapsMergeState::new(Some(merge)),
                ERTS_HASHMAP_MERGE_CONTEXT_SIZE,
            ),
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
    let resumes_here = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .is_some_and(|pending| {
            (pending.caller_module, pending.caller_ip) == process.trap_site()
                && pending.import == import
        });
    if resumes_here
        && process
            .cold
            .as_ref()
            .and_then(|cold| cold.bif_trap.as_ref())
            .is_some_and(|pending| pending.target.entry.is_some())
    {
        let result = run_trapped_export(process, ctx)?;
        let trap_site = process.trap_site();
        if matches!(
            &result,
            Ok(ResumeResult::Handler(HandlerResult::Yield { .. }))
        ) && let Some(pending) = process
            .cold
            .as_mut()
            .and_then(|cold| cold.bif_trap.as_mut())
        {
            // Port of erts/emulator/beam/beam_common.c (BIF_TRAP), OTP-29.1.1: a continuation
            // that traps again returns to this gc_bif instruction before its result is stored.
            // The continuation ran inside the interpreter at the original gc_bif site.
            // Keep that site as the resume key across another continuation slice.
            pending.import = import;
            (pending.caller_module, pending.caller_ip) = trap_site;
        }
        return Some(result.and_then(|result| match result {
            ResumeResult::Handler(result) => Ok(result),
            ResumeResult::Export(trap) => Err(VmError::TrapExport(trap)),
        }));
    }
    let import_info = vm.code.modules.get(process.module).and_then(|module| {
        module
            .imports
            .get(import)
            .map(|import| (import.module, import.function, usize::from(import.arity)))
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

/// The export a trap continues in. erts `BIF_TRAP` names the trap `Export*` directly; here the
/// name-keyed lookup is done once, when the trap is installed, and a resume reads the result.
pub(crate) struct ContinuationTarget {
    pub(crate) module: &'static str,
    pub(crate) function: &'static str,
    pub(crate) arity: usize,
    /// The Rust handler of the continuation, absent when it is an Erlang export.
    pub(crate) entry: Option<&'static Entry>,
}

impl ContinuationTarget {
    fn is(&self, module: &str, function: &str, arity: usize) -> bool {
        self.arity == arity && self.function == function && self.module == module
    }
}

/// The target of a continuation string, cached per string address so a trap pays no hashing.
pub(crate) fn continuation_target(continuation: &'static str) -> &'static ContinuationTarget {
    use std::cell::Cell;
    const SLOTS: usize = 64;
    type Slot = Option<(usize, usize, &'static ContinuationTarget)>;
    thread_local! {
        static RECENT: Cell<[Slot; SLOTS]> = const { Cell::new([None; SLOTS]) };
    }
    let key = (continuation.as_ptr() as usize, continuation.len());
    let slot = (key.0 >> 3) % SLOTS;
    if let Some(target) = RECENT.with(|recent| {
        recent.get()[slot].and_then(|(ptr, len, target)| ((ptr, len) == key).then_some(target))
    }) {
        return target;
    }
    static ALL: OnceLock<Mutex<HashMap<&'static str, &'static ContinuationTarget>>> =
        OnceLock::new();
    let target = *ALL
        .get_or_init(Default::default)
        .lock()
        .expect("continuation targets")
        .entry(continuation)
        .or_insert_with(|| {
            let (module, function, arity) = continuation_parts(continuation)
                .expect("a continuation is `module:function/arity`");
            Box::leak(Box::new(ContinuationTarget {
                module,
                function,
                arity,
                entry: lookup_entry(module, function, arity),
            }))
        });
    RECENT.with(|recent| {
        let mut slots = recent.get();
        slots[slot] = Some((key.0, key.1, target));
        recent.set(slots);
    });
    target
}

/// Run the trap continuation export. `beam_bif_export_trap` does this on schedule-in:
/// the continuation is an ordinary call, and only that call may trap again.
pub(crate) fn run_trapped_export(
    process: &mut Process,
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<ResumeResult, VmError>> {
    let target = process.cold.as_ref()?.bif_trap.as_ref()?.target;
    let (module, function, arity) = (target.module, target.function, target.arity);
    // An Erlang export has no Rust handler: the trap calls it with the saved arguments.
    // Port of erts/emulator/beam/beam_common.c (BIF_TRAP: the trap export carries its own
    // arguments), OTP-29.1.1.
    if target.entry.is_none() {
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
        module,
        function,
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
    process.x.ensure_x(arity);
    process.x[..arity].copy_from_slice(&trap.args);
    process.gc_live = arity;
    let gc_was_enabled = process.heap.gc_enabled;
    process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
        caller_module: process.trap_site().0,
        caller_ip: process.trap_site().1,
        schedule_out: true,
        import,
        continuation: trap.continuation,
        target: continuation_target(trap.continuation),
        state: argument_trap_state(Mutex::new(())),
        state_term: None,
        gc_was_enabled,
        arity,
        callee,
        // Export traps keep their arguments in X; this field is for BIF continuations only.
        args: [Term::NIL; 3],
    });
}

pub(crate) fn continuation_parts(
    continuation: &'static str,
) -> Option<(&'static str, &'static str, usize)> {
    let (module, rest) = continuation.split_once(':')?;
    let (function, arity_text) = rest.rsplit_once('/')?;
    Some((module, function, arity_text.parse().ok()?))
}

/// The BIF a trap error is blamed on. `ERTS_BIF_ERROR_TRAPPED` names `sp->bif`, the
/// export that first trapped, not the continuation that was running when it failed.
fn original_trap_report<'a>(
    process: &Process,
    module_name: &'a str,
    function_name: &'a str,
    arity: usize,
    continuation_resume: bool,
) -> (&'a str, &'a str, usize) {
    if continuation_resume
        && let Some(pending) = process
            .cold
            .as_ref()
            .and_then(|cold| cold.bif_trap.as_ref())
    {
        let module = global_atoms().text(pending.callee.0).unwrap_or(module_name);
        let function = global_atoms()
            .text(pending.callee.1)
            .unwrap_or(function_name);
        return (module, function, pending.arity);
    }
    (module_name, function_name, arity)
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
    mut ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<HandlerResult, VmError>> {
    let gc_enabled_on_entry = process.heap.gc_enabled;
    let pending_site = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .map(|pending| {
            (
                (pending.caller_module, pending.caller_ip) == process.trap_site(),
                pending.import == import,
            )
        });
    // The continuation export is an ordinary call of its own MFA. It is not a retry of
    // the call site that first trapped, so the site check does not name it.
    let continuation_resume = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .is_some_and(|pending| pending.target.is(module_name, function_name, arity));
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
    // A resume names its handler through the trap, the way BIF_TRAP names the `Export*`.
    let entry = if continuation_resume {
        process
            .cold
            .as_ref()
            .and_then(|cold| cold.bif_trap.as_ref())
            .and_then(|pending| pending.target.entry)
    } else {
        lookup_entry(module_name, function_name, arity)
    };
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
            if pending_site == Some((true, true))
                && !continuation_resume
                && pending.target.entry.is_none()
                && let Some(Ok(ResumeResult::Export(trap))) =
                    run_trapped_export(process, ctx.as_deref_mut())
            {
                return Some(Err(VmError::TrapExport(trap)));
            }
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
                process, report.0, report.1, &args, error,
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
                process, report.0, report.1, &args, error,
            ))
        }
        Ok(HandlerResult::Yield {
            continuation,
            state,
            reductions,
        }) => {
            let carried_state_term = resumed
                .then(|| {
                    process
                        .cold
                        .as_ref()
                        .and_then(|cold| cold.bif_trap.as_ref())
                        .filter(|pending| Arc::ptr_eq(&pending.state, &state))
                        .map(|pending| pending.state_term)
                })
                .flatten();
            let state_term = if let Some(state_term) = carried_state_term {
                state_term
            } else {
                match trap_state_term(process, &state) {
                    Ok(state_term) => state_term,
                    Err(_) => {
                        process.cold_mut().bif_trap = None;
                        clear_export_trap(process);
                        process.set_gc_enabled(gc_was_enabled);
                        let args = call_args(process, &args, report.2, resumed);
                        return Some(Err(exceptions::bif_error(
                            process,
                            report.0,
                            report.1,
                            &args,
                            BifError::SystemLimit,
                        )));
                    }
                }
            };
            // The ptab list state holds no heap terms, so the process stays collectable
            // while trapped (erts keeps it GC-able in ptab_list_continue/2). The same holds
            // for a code-permission waiter: its state is a flag and its arguments are atoms,
            // and erts runs a GC task of the suspended waiter (code_ix.c:323,
            // erts_reject_code_permissions).
            if continuation != PTAB_LIST_CONTINUATION
                && continuation != CODE_PERMISSION_CONTINUATION
                && continuation != REVERSE_CONTINUATION
                && continuation != RE_GRUN_CONTINUATION
                && continuation != RE_URUN_CONTINUATION
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
            let reverse_args = (continuation == REVERSE_CONTINUATION)
                .then(|| reverse_trap_args(&state))
                .flatten();
            process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.trap_site().0,
                caller_ip: process.trap_site().1,
                schedule_out: false,
                import,
                continuation,
                target: continuation_target(continuation),
                state,
                state_term,
                gc_was_enabled,
                arity: trap_arity,
                callee,
                args: if let Some(trap_args) = reverse_args {
                    [trap_args[0], trap_args[1], Term::NIL]
                } else if continuation == PTAB_LIST_CONTINUATION {
                    [process.x[0], Term::NIL, Term::NIL]
                } else if resumed {
                    [args[0], args[1], args[2]]
                } else {
                    let live = live_args(process, &args, arity.min(3));
                    let mut saved = [Term::NIL; 3];
                    saved[..live.len()].copy_from_slice(&live);
                    saved
                },
            });
            charge(process, ctx, reductions);
            // Port of erts/emulator/beam/erl_gc.c (erts_gc_after_bif_call_lhf with a
            // TRAP result collects with the trap's arguments as roots), OTP-29.1.1.
            if continuation == REVERSE_CONTINUATION
                && let Err(error) = process.collect_bin_vheap_if_due(0)
            {
                return Some(Err(error));
            }
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
        Ok(HandlerResult::Export(trap)) => {
            process.cold_mut().bif_trap = None;
            clear_export_trap(process);
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, 0);
            return Some(Err(VmError::TrapExport(trap)));
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
    /// Fixed arity of a direct entry, if shared by the body type.
    const ARITY: Option<usize> = None;

    /// The value of a call that needs no trap state, no reduction charge and no collection
    /// change, or `None` to take [`TrapBody::run`]. Nothing may be allocated before `None`.
    #[inline(always)]
    fn direct(_process: &mut Process, _args: &[Term]) -> Option<Term> {
        None
    }

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
    const ARITY: Option<usize> = Some(1);

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
    const ARITY: Option<usize> = Some(1);

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
    const ARITY: Option<usize> = Some(2);

    #[inline(always)]
    fn direct(process: &mut Process, args: &[Term]) -> Option<Term> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        arinsal_maps::merge_flatmaps(args[0], args[1], &mut heap)
    }

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
    const ARITY: Option<usize> = Some(1);

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
    const ARITY: Option<usize> = Some(1);

    fn direct(process: &mut Process, args: &[Term]) -> Option<Term> {
        iolist_binary_direct(process, args[0], false)
    }

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
    const ARITY: Option<usize> = Some(1);

    fn direct(process: &mut Process, args: &[Term]) -> Option<Term> {
        iolist_binary_direct(process, args[0], true)
    }

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
    const ARITY: Option<usize> = Some(1);

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
    const ARITY: Option<usize> = Some(1);

    fn direct(process: &mut Process, args: &[Term]) -> Option<Term> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
        arinsal_bifs::iolist_size_direct(&mut ctx, args[0])
    }

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

/// `erlang:phash2/N` as its own light entry.
// Port of erts/emulator/beam/bif.c (phash2_1, phash2_2), OTP-29.1.1: the BIF hashes on the C
// stack and traps only when `trapping_make_hash2` runs out of reductions.
pub(crate) struct Phash2<const N: usize>;

impl<const N: usize> TrapBody for Phash2<N> {
    const ARITY: Option<usize> = Some(N);

    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        _pid: Option<arinsal_sched::Pid>,
        _restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        Ok(match arinsal_bifs::phash2_run(args, process.reductions)? {
            arinsal_bifs::Phash2Run::Done { value, reductions } => {
                HandlerResult::Done { value, reductions }
            }
            arinsal_bifs::Phash2Run::More(cont) => {
                // BUMP_ALL_REDS before BIF_TRAP.
                process.reductions = 0;
                HandlerResult::Yield {
                    continuation: cont.continuation(),
                    state: magic_binary_state(Mutex::new(*cont), ERTS_HASH2_CONTEXT_SIZE),
                    reductions: 0,
                }
            }
        })
    }
}

/// `term_to_binary/1,2` entered directly from the light-BIF fragment.
pub(crate) struct TermToBinary;

impl TrapBody for TermToBinary {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        // Port of erts/emulator/beam/external.c:2450-2567 (`erts_term_to_binary_int`), OTP-29.1.1.
        term_to_binary(process, args, None, pid, restore_gc)
    }
}

/// `binary_to_term/1,2` entered directly from the light-BIF fragment.
pub(crate) struct BinaryToTerm;

impl TrapBody for BinaryToTerm {
    fn run(
        process: &mut Process,
        args: &[Term],
        _instruction: usize,
        pid: Option<arinsal_sched::Pid>,
        restore_gc: bool,
    ) -> Result<HandlerResult, BifError> {
        // Port of erts/emulator/beam/external.c:1948-2156 (`binary_to_term_int`), OTP-29.1.1.
        binary_to_term(process, args, None, pid, restore_gc)
    }
}

type NativeBifEntry =
    extern "C" fn(*mut arinsal_beamasm::ProcessHeader, *mut u64, u64, u64, u64) -> u64;

/// Calls an arity-one external-term BIF without constructing the generic trap-body adapter.
// Port of erts/emulator/beam/external.c (term_to_binary_1, external_size_1,
// binary_to_term_1), OTP-29.1.1: a completed BIF returns directly; only an error or trap
// takes the cold continuation path.
#[inline(always)]
fn direct_external_term_entry<F>(
    header: *mut arinsal_beamasm::ProcessHeader,
    regs: *mut u64,
    instruction: u64,
    descriptor: u64,
    identity: u64,
    fallback: NativeBifEntry,
    run: F,
) -> u64
where
    F: FnOnce(&mut Process, &[Term], bool) -> Result<HandlerResult, BifError>,
{
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    if registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64 {
        return fallback(header, regs, instruction, descriptor, identity);
    }
    let entry_top = process.heap.heap_top_index();
    let gc_was_enabled = process.heap.gc_enabled;
    let result = run(process, &registers.x_reg_array[..1], gc_was_enabled);
    match result {
        Ok(HandlerResult::Done { value, reductions }) => {
            process.set_gc_enabled(gc_was_enabled);
            charge_light(process, reductions);
            crate::native_helpers::light_value_return(process, entry_top, value)
        }
        other => crate::native_helpers::trap_body_finish(
            process,
            registers,
            identity as usize,
            descriptor,
            1,
            entry_top,
            gc_was_enabled,
            other,
        )
        .unwrap_or(0),
    }
}

/// Direct `erlang:term_to_binary/1` entry for its completed first call.
// Port of erts/emulator/beam/external.c:1442 (`term_to_binary_1`), OTP-29.1.1.
pub(crate) extern "C" fn term_to_binary_1_light(
    header: *mut arinsal_beamasm::ProcessHeader,
    regs: *mut u64,
    instruction: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
    direct_external_term_entry(
        header,
        regs,
        instruction,
        descriptor,
        identity,
        crate::native_helpers::trap_bif_entry::<TermToBinary>,
        |process, args, restore_gc| {
            let chunk_work =
                (process.reductions.max(0) as usize).saturating_mul(TERM_TO_BINARY_LOOP_FACTOR);
            term_encode_first(process, args, restore_gc, chunk_work)
        },
    )
}

/// Direct `erlang:external_size/1` entry.
// Port of erts/emulator/beam/external.c:2197 (`external_size_1`), OTP-29.1.1.
pub(crate) extern "C" fn external_size_1_light(
    header: *mut arinsal_beamasm::ProcessHeader,
    regs: *mut u64,
    instruction: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
    direct_external_term_entry(
        header,
        regs,
        instruction,
        descriptor,
        identity,
        crate::native_helpers::trap_bif_light,
        |process, args, restore_gc| external_size(process, args, None, None, restore_gc),
    )
}

/// Direct `erlang:binary_to_term/1` entry for its first decode slice.
// Port of erts/emulator/beam/external.c:2146 (`binary_to_term_1`), OTP-29.1.1.
pub(crate) extern "C" fn binary_to_term_1_light(
    header: *mut arinsal_beamasm::ProcessHeader,
    regs: *mut u64,
    instruction: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
    direct_external_term_entry(
        header,
        regs,
        instruction,
        descriptor,
        identity,
        crate::native_helpers::trap_bif_entry::<BinaryToTerm>,
        |process, args, restore_gc| {
            let pid = process.self_pid;
            binary_to_term(process, args, None, pid, restore_gc)
        },
    )
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
                && continuation != REVERSE_CONTINUATION
                && continuation != RE_GRUN_CONTINUATION
                && continuation != RE_URUN_CONTINUATION
                && !binary_to_list_retry
            {
                process.set_gc_enabled(false);
            }
            let mut saved = [Term::NIL; 3];
            let kept = args.len().min(3);
            saved[..kept].copy_from_slice(&args[..kept]);
            if continuation == PTAB_LIST_CONTINUATION {
                // BIF_TRAP1 carries the accumulator in X0; it does not change the trapped
                // processes/0 or ports/0 call's arity.
                saved[0] = process.x[0];
            }
            if continuation == REVERSE_CONTINUATION
                && let Some(trap_args) = reverse_trap_args(&state)
            {
                saved[..2].copy_from_slice(&trap_args);
            }
            let Ok(state_term) = trap_state_term(process, &state) else {
                return LightTrap::Returned(Err(BifError::SystemLimit));
            };
            // The scheduler binds the trap to its call site when it context-switches.
            process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.trap_site().0,
                caller_ip: process.trap_site().1,
                schedule_out: true,
                import,
                continuation,
                target: continuation_target(continuation),
                state,
                state_term,
                gc_was_enabled,
                arity: kept,
                callee,
                args: saved,
            });
            charge_light(process, reductions);
            return LightTrap::Trapped;
        }
        Ok(HandlerResult::Export(trap)) => {
            let state = argument_trap_state(Mutex::new(()));
            let Ok(state_term) = trap_state_term(process, &state) else {
                return LightTrap::Returned(Err(BifError::SystemLimit));
            };
            let mut saved = [Term::NIL; 3];
            let kept = trap.args.len().min(saved.len());
            saved[..kept].copy_from_slice(&trap.args[..kept]);
            process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.trap_site().0,
                caller_ip: process.trap_site().1,
                schedule_out: false,
                import,
                continuation: trap.continuation,
                target: continuation_target(trap.continuation),
                state,
                state_term,
                gc_was_enabled,
                arity: kept,
                callee,
                args: saved,
            });
            charge_light(process, 0);
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
) -> Result<(), arinsal_term::TermError> {
    let gc_was_enabled = process.heap.gc_enabled;
    let mut disable_gc = true;
    let (continuation, state) = match *trap {
        arinsal_bifs::DeferredTrap::BinaryToList(walk) => {
            disable_gc = !walk.needs_initial_allocation();
            (
                BINARY_TO_LIST_CONTINUATION,
                magic_binary_state(Mutex::new(walk), ERTS_BINARY_TO_LIST_STATE_SIZE),
            )
        }
        arinsal_bifs::DeferredTrap::Key(cont) => (
            key_continuation(function),
            argument_trap_state(Mutex::new(cont)),
        ),
        arinsal_bifs::DeferredTrap::Member(cont) => {
            ("lists:member/2", argument_trap_state(Mutex::new(cont)))
        }
        arinsal_bifs::DeferredTrap::Reverse(cont) => {
            (REVERSE_CONTINUATION, argument_trap_state(Mutex::new(cont)))
        }
        arinsal_bifs::DeferredTrap::Append(cont) => (
            if function == "append" {
                "erlang:append/2"
            } else {
                "erlang:++/2"
            },
            magic_binary_state(Mutex::new(cont), ERTS_APPEND_CONTEXT_SIZE),
        ),
        arinsal_bifs::DeferredTrap::Length(cont) => {
            ("erlang:length/3", argument_trap_state(Mutex::new(cont)))
        }
        arinsal_bifs::DeferredTrap::Phash2(cont) => (
            cont.continuation(),
            magic_binary_state(Mutex::new(*cont), ERTS_HASH2_CONTEXT_SIZE),
        ),
        arinsal_bifs::DeferredTrap::Chksum(cont) => {
            (cont.continuation(), argument_trap_state(Mutex::new(cont)))
        }
        arinsal_bifs::DeferredTrap::Unicode(cont) => (
            cont.continuation(),
            magic_binary_state(Mutex::new(cont), ERTS_UNICODE_RESTART_CONTEXT_SIZE),
        ),
        arinsal_bifs::DeferredTrap::Subtract(walk) => (
            if function == "subtract" {
                "erlang:subtract/2"
            } else {
                SUBTRACT_CONTINUATION
            },
            magic_binary_state(Mutex::new(walk), ERTS_SUBTRACT_CONTEXT_SIZE),
        ),
    };
    let state_term = trap_state_term(process, &state)?;
    if disable_gc && continuation != REVERSE_CONTINUATION {
        process.set_gc_enabled(false);
    }
    let mut saved = [Term::NIL; 3];
    let arity = args.len().min(3);
    saved[..arity].copy_from_slice(&args[..arity]);
    if continuation == REVERSE_CONTINUATION
        && let Some(trap_args) = reverse_trap_args(&state)
    {
        saved[..2].copy_from_slice(&trap_args);
    }
    process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
        caller_module: process.trap_site().0,
        caller_ip: process.trap_site().1,
        schedule_out: true,
        import,
        continuation,
        target: continuation_target(continuation),
        state,
        state_term,
        gc_was_enabled,
        arity,
        callee,
        args: saved,
    });
    Ok(())
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
    let Some(runtime) = process.runtime else {
        return Err(BifError::Unsupported(
            "code_mod_permission requires a runtime",
        ));
    };
    // Port of erts/emulator/beam/erl_bif_info.c:5385-5400, OTP-29.1.1.
    if !acquire {
        crate::natives::code::release_code_mod_permission(runtime);
    }
    if !acquire || crate::natives::code::try_seize_code_mod_permission(runtime, process, pid) {
        return Ok(HandlerResult::Done {
            value: Term::atom(global_atoms().intern("true").unwrap()),
            reductions: 1,
        });
    }
    Ok(HandlerResult::Yield {
        continuation: CODE_PERMISSION_CONTINUATION,
        state: argument_trap_state(acquire),
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
            state: magic_binary_state(Mutex::new(walk), ERTS_SUBTRACT_CONTEXT_SIZE),
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
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
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
            reductions: 0,
        });
    }
    iolist_binary_conversion(process, root, state, false, gc_changed)
}

// Port of erts/emulator/beam/erl_iolist.c:718-762,857-927
// (list_to_bitstring_engine, list_to_bitstring_bif, iolist_to_binary_1), OTP-29.1.1.
// The size and copy passes run on the stack; only a yielding call needs saved state.
fn iolist_binary_direct(process: &mut Process, root: Term, allow_binary: bool) -> Option<Term> {
    if allow_binary && root.classify() == TermKind::Bitstring {
        arinsal_bifs::bitstring_bit_len(root)
            .ok()?
            .is_multiple_of(8)
            .then_some(())?;
        return Some(root);
    }
    if !matches!(root.classify(), TermKind::List | TermKind::Nil) {
        return None;
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(root, 8).ok()? {
        return Some(value);
    }
    if root == Term::NIL {
        return Some(
            TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .binary(&[])
                .expect("process HAlloc supplies the empty binary"),
        );
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    arinsal_bifs::iolist_to_binary_direct(&mut ctx, root)
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
            reductions: 0,
        });
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(root, 8)? {
        return Ok(HandlerResult::Done {
            value,
            reductions: 0,
        });
    }
    iolist_binary_conversion(process, root, state, false, gc_changed)
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
    iolist_binary_conversion(process, args[0], state, true, gc_changed)
}

fn iolist_size(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    // Port of erts/emulator/beam/erl_iolist.c (`iolist_size_dispatch`, `iolist_size_1`,
    // `iolist_size_continue`), OTP-29.1.1: the walk gets `reds_left * 8` yield counts and
    // charges one reduction per eight of them.
    let root = args[0];
    let reds_left = process.reductions.max(0) as usize;
    // erts walks on the C stack and allocates trap state only when it yields, so the common
    // call that finishes in one go allocates nothing.
    let (progress, size, parked) = match state {
        Some(state) => {
            let mut walker = state
                .downcast_ref::<Mutex<arinsal_bifs::IolistSizeWalk>>()
                .ok_or(BifError::BADARG)?
                .lock()
                .map_err(|_| BifError::SystemLimit)?;
            if reds_left == 0 {
                drop(walker);
                return Ok(HandlerResult::Yield {
                    continuation: IOLIST_SIZE_CONTINUATION,
                    state: Arc::clone(state),
                    reductions: 0,
                });
            }
            let progress = walker.step(reds_left.saturating_mul(SIZE_YIELDS_PER_RED));
            let size = if matches!(progress, Ok((true, _))) {
                walker.take_size()
            } else {
                0
            };
            (progress, size, Some(Arc::clone(state)))
        }
        None => {
            let mut walker = arinsal_bifs::IolistSizeWalk::new(root);
            if reds_left == 0 {
                return Ok(HandlerResult::Yield {
                    continuation: IOLIST_SIZE_CONTINUATION,
                    state: magic_binary_state(Mutex::new(walker), ERTS_IOLIST_SIZE_STATE_SIZE),
                    reductions: 0,
                });
            }
            let progress = walker.step(reds_left.saturating_mul(SIZE_YIELDS_PER_RED));
            match progress {
                Ok((true, _)) => (progress, walker.take_size(), None),
                _ => (
                    progress,
                    0,
                    Some(magic_binary_state(
                        Mutex::new(walker),
                        ERTS_IOLIST_SIZE_STATE_SIZE,
                    )),
                ),
            }
        }
    };
    let (done, work) = match progress {
        Ok(progress) => progress,
        Err((error, work)) => {
            return Ok(HandlerResult::Failed {
                error,
                reductions: arinsal_bifs::iolist_yield_reductions(work) as u32,
            });
        }
    };
    let reductions = arinsal_bifs::iolist_yield_reductions(work) as u32;
    if !done {
        let Some(state) = parked else {
            return Err(BifError::SystemLimit);
        };
        return Ok(HandlerResult::Yield {
            continuation: IOLIST_SIZE_CONTINUATION,
            state,
            reductions,
        });
    }
    process.set_gc_enabled(restore_gc);
    let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .int_from_u64(u64::try_from(size).map_err(|_| BifError::SystemLimit)?)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(HandlerResult::Done { value, reductions })
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
            magic_binary_state(
                Mutex::new(arinsal_bifs::IolistVecWalk::new(args[0])),
                ERTS_IOLIST_TO_IOVEC_STATE_SIZE,
            )
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

struct IolistCopySetup {
    empty: Option<Term>,
    ready: Option<(IolistOutput, usize, arinsal_bifs::IolistCopyWalk, bool)>,
}

/// Allocate the result after the size pass of `list_to_binary/1` and friends (`bitstring` false)
/// or `list_to_bitstring/1`.
// Port of erts/emulator/beam/erl_iolist.c (`list_to_bitstring_dispatch`), OTP-29.1.1.
fn iolist_copy_setup(
    process: &mut Process,
    size: &mut arinsal_bifs::IolistSizeWalk,
    root: Term,
) -> Result<IolistCopySetup, BifError> {
    if size.is_bits() {
        let bit_len = size.take_bits();
        if bit_len == 0 {
            let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                .bitstring(&[], 0)
                .map_err(|_| BifError::SystemLimit)?;
            return Ok(IolistCopySetup {
                empty: Some(value),
                ready: None,
            });
        }
        return Ok(IolistCopySetup {
            empty: None,
            ready: Some((
                IolistOutput::Bitstring(vec![0; bit_len.div_ceil(8)]),
                bit_len,
                arinsal_bifs::IolistCopyWalk::new_bits(root),
                process.heap.gc_enabled,
            )),
        });
    }
    let byte_len = size.take_size();
    if byte_len == 0 {
        let value = arinsal_bifs::allocate_iolist_binary(
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            0,
        )?;
        return Ok(IolistCopySetup {
            empty: Some(value),
            ready: None,
        });
    }
    if byte_len <= 64 {
        let restore_gc = process.heap.gc_enabled;
        let output = match arinsal_term::HeapBinaryWriter::new(&mut process.heap, byte_len) {
            Ok(output) => output,
            Err(_) => return Err(BifError::SystemLimit),
        };
        return Ok(IolistCopySetup {
            empty: None,
            ready: Some((
                IolistOutput::Small(output),
                byte_len * 8,
                arinsal_bifs::IolistCopyWalk::new(root),
                restore_gc,
            )),
        });
    }
    let output = IolistOutput::Writable(arinsal_bifs::allocate_iolist_binary(
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        byte_len,
    )?);
    Ok(IolistCopySetup {
        empty: None,
        ready: Some((
            output,
            byte_len * 8,
            arinsal_bifs::IolistCopyWalk::new(root),
            process.heap.gc_enabled,
        )),
    })
}

fn iolist_binary_conversion(
    process: &mut Process,
    root: Term,
    state: Option<&Arc<MagicRef>>,
    bitstring: bool,
    _restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    if root == Term::NIL && state.is_none() {
        let value = arinsal_bifs::allocate_iolist_binary(
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            0,
        )?;
        return Ok(HandlerResult::Done {
            value,
            reductions: 0,
        });
    }
    let Some(state) = state else {
        let mut phase = IolistBinaryPhase::Size(if bitstring {
            arinsal_bifs::IolistSizeWalk::new_bits(root)
        } else {
            arinsal_bifs::IolistSizeWalk::new(root)
        });
        return Ok(match iolist_binary_step(process, root, &mut phase)? {
            IolistStep::Finished(result) => result,
            IolistStep::Yield(reductions) => HandlerResult::Yield {
                continuation: IOLIST_CONTINUATION,
                state: magic_binary_state(Mutex::new(Box::new(phase)), ERTS_L2B_STATE_SIZE),
                reductions,
            },
        });
    };
    let state = Arc::clone(state);
    let phase = state
        .downcast_ref::<Mutex<Box<IolistBinaryPhase>>>()
        .ok_or(BifError::BADARG)?;
    let mut phase = phase.lock().map_err(|_| BifError::SystemLimit)?;
    let step = iolist_binary_step(process, root, &mut phase)?;
    drop(phase);
    Ok(match step {
        IolistStep::Finished(result) => result,
        IolistStep::Yield(reductions) => HandlerResult::Yield {
            continuation: IOLIST_CONTINUATION,
            state,
            reductions,
        },
    })
}

enum IolistStep {
    Finished(HandlerResult),
    Yield(u32),
}

fn iolist_binary_step(
    process: &mut Process,
    root: Term,
    phase: &mut IolistBinaryPhase,
) -> Result<IolistStep, BifError> {
    const SIZE_YIELDS_PER_RED: usize = 8;
    let finished = |result| Ok(IolistStep::Finished(result));
    let mut available_reductions = process.reductions.max(0) as usize;
    let mut size_reductions = 0_usize;

    match phase {
        IolistBinaryPhase::Size(walk) => {
            let initial_yield_count = available_reductions.saturating_mul(SIZE_YIELDS_PER_RED);
            let (done, work) = match walk.step(initial_yield_count) {
                Ok(progress) => progress,
                Err((error, work)) => {
                    let reductions = work.div_ceil(SIZE_YIELDS_PER_RED) as u32;
                    return finished(HandlerResult::Failed { error, reductions });
                }
            };
            size_reductions = work.div_ceil(SIZE_YIELDS_PER_RED);
            if !done {
                return Ok(IolistStep::Yield(size_reductions as u32));
            }
            let bitstring = walk.is_bits();
            let setup = iolist_copy_setup(process, walk, root)?;
            if let Some(value) = setup.empty {
                *phase = IolistBinaryPhase::Done;
                return finished(HandlerResult::Done {
                    value,
                    reductions: size_reductions as u32,
                });
            }
            let (output, bit_len, walk, restore_gc) = setup
                .ready
                .expect("nonempty iolist output has a copy state");
            *phase = IolistBinaryPhase::Copy {
                output,
                bit_len,
                bitstring,
                walk,
                restore_gc,
            };
            available_reductions = available_reductions.saturating_sub(size_reductions);
            if available_reductions == 0 {
                return Ok(IolistStep::Yield(size_reductions as u32));
            }
        }
        IolistBinaryPhase::Copy { .. } => {}
        IolistBinaryPhase::Done => return Err(BifError::BADARG),
    }

    let IolistBinaryPhase::Copy {
        output,
        bit_len,
        bitstring,
        walk,
        restore_gc,
    } = &mut *phase
    else {
        unreachable!("the size phase transitions to copy or returns above")
    };
    let yield_count = available_reductions.saturating_mul(SIZE_YIELDS_PER_RED);
    let stepped = match output {
        IolistOutput::Small(writer) => {
            walk.step_to_heap_binary(&mut process.heap, writer, yield_count)
        }
        IolistOutput::Bitstring(bytes) => walk.step(bytes, yield_count),
        IolistOutput::Writable(term) => arinsal_bifs::with_iolist_binary_output(*term, |bytes| {
            Ok(walk.step(bytes, yield_count))
        })?,
    };
    let (done, work) = match stepped {
        Ok(progress) => progress,
        Err((error, work)) => {
            let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
            if let IolistOutput::Small(writer) = output {
                writer.cancel(&mut process.heap);
            } else {
                output.finish_writer();
            }
            process.set_gc_enabled(*restore_gc);
            return finished(HandlerResult::Failed { error, reductions });
        }
    };
    let reductions = (size_reductions + work.div_ceil(SIZE_YIELDS_PER_RED)) as u32;
    if !done {
        return Ok(IolistStep::Yield(reductions));
    }
    if walk.written_bits() != *bit_len {
        if let IolistOutput::Small(writer) = output {
            writer.cancel(&mut process.heap);
        } else {
            output.finish_writer();
        }
        process.set_gc_enabled(*restore_gc);
        return finished(HandlerResult::Failed {
            error: BifError::SystemLimit,
            reductions,
        });
    }
    let (bit_len, bitstring) = (*bit_len, *bitstring);
    let value = match output {
        IolistOutput::Small(writer) => writer
            .finish(&mut process.heap)
            .map_err(|_| BifError::SystemLimit)?,
        IolistOutput::Bitstring(bytes) => {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let mut builder = TermBuilder::new(&mut heap);
            if bitstring {
                builder.bitstring(bytes, bit_len)
            } else {
                builder.binary(bytes)
            }
            .map_err(|_| BifError::SystemLimit)?
        }
        IolistOutput::Writable(term) => {
            arinsal_bifs::finish_iolist_binary_output(*term);
            *term
        }
    };
    process.set_gc_enabled(*restore_gc);
    *phase = IolistBinaryPhase::Done;
    finished(HandlerResult::Done { value, reductions })
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
            .downcast_ref::<Mutex<arinsal_bifs::DecodeWalk<'static>>>()
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
    let (node_name, creation) = {
        let tables = crate::node_tables::lock();
        (tables.local_name.clone(), tables.local_creation)
    };
    let node = global_atoms()
        .intern(&node_name)
        .map_err(|_| BifError::SystemLimit)?;
    decoder.set_local_node(node, creation);
    match decode_step(process, &mut decoder, chunk_bytes) {
        Ok((None, consumed)) => {
            let decoder = decoder.into_owned()?;
            Ok(HandlerResult::Yield {
                continuation: BINARY_TO_TERM_CONTINUATION,
                state: magic_binary_state(Mutex::new(decoder), ERTS_BINARY_TO_TERM_CONTEXT_SIZE),
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
    }
}

fn decode_step(
    process: &mut Process,
    decoder: &mut arinsal_bifs::DecodeWalk<'_>,
    chunk_bytes: usize,
) -> Result<(Option<Term>, usize), (BifError, usize)> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
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

// Port of erts/emulator/beam/erl_bif_binary.c:2400-2495
// (do_binary_copy, binary_copy_trap), OTP-29.1.1.
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
    let target_bits = len.checked_mul(8).ok_or(BifError::SystemLimit)?;
    let max_copy_bits = usize::try_from(binary_loop_budget(process, BITSTRING_COPY_LOOP_FACTOR))
        .unwrap_or(usize::MAX);
    if let Some(state) = state {
        let state = Arc::clone(state);
        let copy = state
            .downcast_ref::<Mutex<BinaryCopyState>>()
            .ok_or(BifError::BADARG)?;
        let mut copy = copy.lock().map_err(|_| BifError::SystemLimit)?;
        let initial_target_offset = copy.copied_bits;
        let mut trap_offset = target_bits;
        if (usize::MAX - max_copy_bits) < initial_target_offset
            && initial_target_offset.saturating_add(max_copy_bits) < trap_offset
        {
            trap_offset = initial_target_offset + max_copy_bits;
        }
        let copied_bits = copy_binary_to(input, copy.result, initial_target_offset, trap_offset)?;
        copy.copied_bits = copied_bits;
        if copied_bits == target_bits {
            let bits_copied = copied_bits - initial_target_offset;
            let result = copy.result;
            drop(copy);
            arinsal_bifs::finish_iolist_binary_output(result);
            process.set_gc_enabled(restore_gc);
            return Ok(HandlerResult::Done {
                value: result,
                reductions: reductions_from(
                    (bits_copied / BITSTRING_COPY_LOOP_FACTOR as usize) as u64,
                ),
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

    if max_copy_bits >= target_bits {
        let mut copy_error = None;
        let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
            .binary_from_fn(len, |destination| {
                if let Err(error) =
                    arinsal_bifs::copy_binary_pattern(input, destination, 0, target_bits)
                {
                    copy_error = Some(error);
                }
            })
            .map_err(|_| BifError::SystemLimit)?;
        if let Some(error) = copy_error {
            return Err(error);
        }
        return Ok(HandlerResult::Done {
            value,
            reductions: reductions_from((target_bits / BITSTRING_COPY_LOOP_FACTOR as usize) as u64),
        });
    }

    let result = arinsal_bifs::allocate_iolist_binary(
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        len,
    )?;
    let copied_bits = copy_binary_to(input, result, 0, max_copy_bits.min(target_bits))?;
    debug_assert!(copied_bits < target_bits);
    vbump_all_reds(process);
    Ok(HandlerResult::Yield {
        continuation: BINARY_COPY_CONTINUATION,
        state: argument_trap_state(Mutex::new(BinaryCopyState {
            result,
            copied_bits,
        })),
        reductions: 0,
    })
}

// Port of erts/emulator/beam/bif.h:71-78 (BUMP_REDS), OTP-29.1.1.
fn reductions_from(reductions: u64) -> u32 {
    u32::try_from(reductions).unwrap_or(u32::MAX)
}

/// Continue `binary_copy_loop` in the final binary allocated by `do_binary_copy`.
// Port of erts/emulator/beam/erl_bif_binary.c:2379-2398 (binary_copy_loop), OTP-29.1.1.
fn copy_binary_to(
    input: Term,
    result: Term,
    copied_bits: usize,
    trap_offset: usize,
) -> Result<usize, BifError> {
    let mut copied = copied_bits;
    arinsal_bifs::with_iolist_binary_output(result, |destination| {
        copied = arinsal_bifs::copy_binary_pattern(input, destination, copied_bits, trap_offset)?;
        Ok(())
    })?;
    Ok(copied)
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

fn external_size(
    process: &mut Process,
    args: &[Term],
    _state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    // Port of erts/emulator/beam/external.c (erts_encode_ext_size), OTP-29.1.1.
    let mut encoder = arinsal_bifs::EncodeWalk::new_external_size(args)?;
    encoder.set_local_node_source(local_node_source);
    encoder.step_size(usize::MAX)?;
    let size = encoder.encoded_size().ok_or(BifError::SystemLimit)?;
    let value = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .int_from_u64(u64::try_from(size).map_err(|_| BifError::SystemLimit)?)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(HandlerResult::Done {
        value,
        reductions: 0,
    })
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

/// Node name and creation for locally tagged pids, ports and references; read only when the
/// term being encoded holds one (erts reads `erts_this_node` in `enc_internal_pid`).
fn local_node_source() -> (arinsal_term::Atom, u32) {
    // `erts_this_node` is read without any lock.
    arinsal_term::this_node()
}

#[inline(always)]
fn new_term_encoder(args: &[Term]) -> Result<arinsal_bifs::EncodeWalk, BifError> {
    let mut encoder = arinsal_bifs::EncodeWalk::new(args)?;
    encoder.set_local_node_source(local_node_source);
    Ok(encoder)
}

/// Saved state for `erts_term_to_binary_int`, including the result binary once allocated.
// Port of erts/emulator/beam/external.c:2450-2567, OTP-29.1.1.
struct TermEncodeState {
    encoder: arinsal_bifs::EncodeWalk,
    pending_work: usize,
    output: Option<Term>,
    /// The refc Binary being filled when the pass yielded without compression.
    raw: Option<arinsal_term::RefcBinary>,
    source: Option<Term>,
    compressing: bool,
    iovec: bool,
}

impl TermEncodeState {
    fn completed() -> Self {
        Self {
            encoder: arinsal_bifs::EncodeWalk::completed(),
            pending_work: 0,
            output: None,
            raw: None,
            source: None,
            compressing: false,
            iovec: false,
        }
    }
}

const TERM_TO_BINARY_LOOP_FACTOR: usize = 32;

/// The reductions `term_to_binary` charges for `work` units: one for an encoding that fits an
/// on-heap binary, `work / TERM_TO_BINARY_LOOP_FACTOR` otherwise.
fn term_encode_charge(encoder: &arinsal_bifs::EncodeWalk, work: usize) -> u32 {
    if encoder.finishes_simple() {
        1
    } else {
        (work / TERM_TO_BINARY_LOOP_FACTOR) as u32
    }
}

/// Save the context of a first call that ran out of reductions, with the refc Binary being
/// filled if the encode pass had started.
// Port of erts/emulator/beam/external.c:2488-2518 and :2552-2567, OTP-29.1.1: the TTB context
// stays on the stack until a pass actually yields.
#[cold]
#[inline(never)]
fn term_encode_yield(
    encoder: arinsal_bifs::EncodeWalk,
    raw: Option<arinsal_term::RefcBinary>,
    work: usize,
) -> HandlerResult {
    let state = magic_binary_state(
        Mutex::new(TermEncodeState {
            encoder,
            pending_work: 0,
            output: None,
            raw,
            source: None,
            compressing: false,
            iovec: false,
        }),
        ERTS_TERM_TO_BINARY_CONTEXT_SIZE,
    );
    HandlerResult::Yield {
        continuation: TERM_TO_BINARY_CONTINUATION,
        state,
        reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
    }
}

/// First call of `term_to_binary/1,2`, before any context was saved.
// Port of erts/emulator/beam/external.c:2450-2567 (erts_term_to_binary_int), OTP-29.1.1.
fn term_encode_first(
    process: &mut Process,
    args: &[Term],
    restore_gc: bool,
    chunk_work: usize,
) -> Result<HandlerResult, BifError> {
    let charge = term_encode_charge;
    let mut encoder = new_term_encoder(args)?;
    let (sized, size_work) = encoder.step_size(chunk_work)?;
    if !sized {
        return Ok(term_encode_yield(encoder, None, size_work));
    }
    if encoder.finishes_simple() {
        let value = encoder
            .encode_simple_binary(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))?;
        process.set_gc_enabled(restore_gc);
        return Ok(HandlerResult::Done {
            value,
            reductions: 1,
        });
    }

    // Port of erts/emulator/beam/external.c:2519-2582, OTP-29.1.1:
    // encode with the local context and export it only if this pass yields.
    let size = encoder.encoded_size().ok_or(BifError::SystemLimit)?;
    let encode_budget = chunk_work.saturating_sub(size_work);
    // erts_bin_nrml_alloc(size) filled in place; the context keeps the Binary if the pass
    // yields (`ctx->result_bin`).
    if !encoder.uses_compression() {
        let encoded = encoder.encode_into_refc(
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            encode_budget,
        );
        let (encoded, encode_work) = match encoded {
            Ok(progress) => progress,
            Err(error) => {
                process.set_gc_enabled(restore_gc);
                return Err(error);
            }
        };
        match encoded {
            arinsal_bifs::RefcEncoded::Done(value) => {
                let reductions = charge(&encoder, size_work + encode_work);
                process.set_gc_enabled(restore_gc);
                return Ok(HandlerResult::Done { value, reductions });
            }
            arinsal_bifs::RefcEncoded::Partial(binary) => {
                return Ok(term_encode_yield(
                    encoder,
                    Some(binary),
                    size_work + encode_work,
                ));
            }
        }
    }
    term_encode_writable_first(
        process,
        encoder,
        restore_gc,
        chunk_work,
        size_work,
        size,
        encode_budget,
    )
}

/// The first call of a compressed `term_to_binary`, which fills a writable binary and then
/// compresses it.
#[inline(never)]
fn term_encode_writable_first(
    process: &mut Process,
    mut encoder: arinsal_bifs::EncodeWalk,
    restore_gc: bool,
    chunk_work: usize,
    size_work: usize,
    size: usize,
    encode_budget: usize,
) -> Result<HandlerResult, BifError> {
    let charge = term_encode_charge;
    let output = arinsal_bifs::allocate_iolist_binary(
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        size,
    )?;
    let encoded = arinsal_bifs::with_iolist_binary_output(output, |bytes| {
        encoder.step_into(bytes, encode_budget)
    });
    let (done, encode_work) = match encoded {
        Ok(progress) => progress,
        Err(error) => {
            arinsal_bifs::finish_iolist_binary_output(output);
            process.set_gc_enabled(restore_gc);
            return Err(error);
        }
    };
    let mut work = size_work + encode_work;
    if !done {
        let state = magic_binary_state(
            Mutex::new(TermEncodeState {
                encoder,
                pending_work: 0,
                output: Some(output),
                raw: None,
                source: None,
                compressing: false,
                iovec: false,
            }),
            ERTS_TERM_TO_BINARY_CONTEXT_SIZE,
        );
        return Ok(HandlerResult::Yield {
            continuation: TERM_TO_BINARY_CONTINUATION,
            state,
            reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
        });
    }
    arinsal_bifs::finish_iolist_binary_output(output);
    if !encoder.uses_compression() {
        let reductions = charge(&encoder, work);
        process.set_gc_enabled(restore_gc);
        return Ok(HandlerResult::Done {
            value: output,
            reductions,
        });
    }

    let compressed = arinsal_bifs::allocate_iolist_binary(
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        size,
    )?;
    arinsal_bifs::with_iolist_binary_output(compressed, |bytes| {
        bytes[..6].copy_from_slice(&[131, 80, 0, 0, 0, 0]);
        bytes[2..6].copy_from_slice(&((size - 1) as u32).to_be_bytes());
        Ok(())
    })?;
    let output_budget = chunk_work.saturating_sub(work).max(1);
    let progress = arinsal_bifs::with_binary_bytes(output, |view| {
        arinsal_bifs::with_iolist_binary_output(compressed, |bytes| {
            encoder.compress_into(&view.bytes()[1..], &mut bytes[6..], output_budget)
        })
    })??;
    work += progress.1;
    if progress.0 || encoder.compression_output_full() {
        let value = if encoder.compression_is_useful() {
            let final_size = 6usize
                .checked_add(
                    encoder
                        .compressed_payload_len()
                        .ok_or(BifError::SystemLimit)?,
                )
                .ok_or(BifError::SystemLimit)?;
            arinsal_term::writable_resize_private(
                compressed,
                final_size.checked_mul(8).ok_or(BifError::SystemLimit)?,
            )
            .map_err(|_| BifError::SystemLimit)?;
            arinsal_bifs::finish_iolist_binary_output(compressed);
            compressed
        } else {
            arinsal_bifs::finish_iolist_binary_output(compressed);
            output
        };
        let reductions = charge(&encoder, work);
        process.set_gc_enabled(restore_gc);
        return Ok(HandlerResult::Done { value, reductions });
    }

    let state = magic_binary_state(
        Mutex::new(TermEncodeState {
            encoder,
            pending_work: 0,
            output: Some(compressed),
            raw: None,
            source: Some(output),
            compressing: true,
            iovec: false,
        }),
        ERTS_TERM_TO_BINARY_CONTEXT_SIZE,
    );
    Ok(HandlerResult::Yield {
        continuation: TERM_TO_BINARY_CONTINUATION,
        state,
        reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
    })
}

fn term_encode(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    restore_gc: bool,
    iovec: bool,
) -> Result<HandlerResult, BifError> {
    // Port of erts/emulator/beam/external.c:2450-2567 (erts_term_to_binary_int), OTP-29.1.1.
    let chunk_work =
        (process.reductions.max(0) as usize).saturating_mul(TERM_TO_BINARY_LOOP_FACTOR);
    let charge = term_encode_charge;
    if state.is_none() && !iovec {
        return term_encode_first(process, args, restore_gc, chunk_work);
    }
    let state = match state {
        Some(state) => Arc::clone(state),
        None => {
            let mut encoder = new_term_encoder(args)?;
            encoder.set_iovec(iovec);
            magic_binary_state(
                Mutex::new(TermEncodeState {
                    encoder,
                    pending_work: 0,
                    output: None,
                    raw: None,
                    source: None,
                    compressing: false,
                    iovec,
                }),
                ERTS_TERM_TO_BINARY_CONTEXT_SIZE,
            )
        }
    };
    let saved = state
        .downcast_ref::<Mutex<TermEncodeState>>()
        .ok_or(BifError::BADARG)?;
    let mut saved = saved.lock().map_err(|_| BifError::SystemLimit)?;

    if saved.iovec {
        let (done, work) = saved.encoder.step(chunk_work)?;
        if !done {
            drop(saved);
            return Ok(HandlerResult::Yield {
                continuation: TERM_TO_BINARY_CONTINUATION,
                state,
                reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
            });
        }
        process.set_gc_enabled(restore_gc);
        let reductions = charge(&saved.encoder, work);
        let encoder = std::mem::replace(&mut saved.encoder, arinsal_bifs::EncodeWalk::completed());
        drop(saved);
        return finish_term_encode(process, encoder, reductions, iovec);
    }

    let mut work = std::mem::take(&mut saved.pending_work);
    if !saved.compressing && saved.output.is_none() && saved.raw.is_none() {
        let size_budget = chunk_work.saturating_sub(work);
        let (sized, size_work) = saved.encoder.step_size(size_budget)?;
        work += size_work;
        if !sized {
            drop(saved);
            return Ok(HandlerResult::Yield {
                continuation: TERM_TO_BINARY_CONTINUATION,
                state,
                reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
            });
        }
        let size = saved.encoder.encoded_size().ok_or(BifError::SystemLimit)?;
        if saved.encoder.finishes_simple() {
            let value = saved
                .encoder
                .encode_simple_binary(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))?;
            let reductions = 1;
            *saved = TermEncodeState::completed();
            drop(saved);
            process.set_gc_enabled(restore_gc);
            return Ok(HandlerResult::Done { value, reductions });
        }
        let output = arinsal_bifs::allocate_iolist_binary(
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            size,
        )?;
        saved.output = Some(output);
    }

    if saved.raw.is_some() {
        let encode_budget = chunk_work.saturating_sub(work);
        let size = saved.encoder.encoded_size().ok_or(BifError::SystemLimit)?;
        let TermEncodeState { encoder, raw, .. } = &mut *saved;
        let bytes = raw
            .as_mut()
            .and_then(arinsal_term::RefcBinary::bytes_mut_unique)
            .ok_or(BifError::SystemLimit)?;
        let (done, encode_work) = match encoder.step_into(bytes, encode_budget) {
            Ok(progress) => progress,
            Err(error) => {
                process.set_gc_enabled(restore_gc);
                return Err(error);
            }
        };
        work += encode_work;
        if !done {
            drop(saved);
            return Ok(HandlerResult::Yield {
                continuation: TERM_TO_BINARY_CONTINUATION,
                state,
                reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
            });
        }
        let binary = saved.raw.take().ok_or(BifError::BADARG)?;
        let reductions = charge(&saved.encoder, work);
        *saved = TermEncodeState::completed();
        drop(saved);
        process.set_gc_enabled(restore_gc);
        let value = arinsal_bifs::install_refc_binary(
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            binary,
            size,
        )?;
        return Ok(HandlerResult::Done { value, reductions });
    }

    if !saved.compressing {
        let raw = saved.output.ok_or(BifError::BADARG)?;
        let encode_budget = chunk_work.saturating_sub(work);
        let encoded = arinsal_bifs::with_iolist_binary_output(raw, |bytes| {
            saved.encoder.step_into(bytes, encode_budget)
        });
        let (done, encode_work) = match encoded {
            Ok(progress) => progress,
            Err(error) => {
                arinsal_bifs::finish_iolist_binary_output(raw);
                process.set_gc_enabled(restore_gc);
                return Err(error);
            }
        };
        work += encode_work;
        if !done {
            drop(saved);
            return Ok(HandlerResult::Yield {
                continuation: TERM_TO_BINARY_CONTINUATION,
                state,
                reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
            });
        }
        arinsal_bifs::finish_iolist_binary_output(raw);
        if saved.encoder.uses_compression() {
            let size = saved.encoder.encoded_size().ok_or(BifError::SystemLimit)?;
            let compressed = arinsal_bifs::allocate_iolist_binary(
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
                size,
            )?;
            arinsal_bifs::with_iolist_binary_output(compressed, |bytes| {
                bytes[..6].copy_from_slice(&[131, 80, 0, 0, 0, 0]);
                bytes[2..6].copy_from_slice(&((size - 1) as u32).to_be_bytes());
                Ok(())
            })?;
            saved.source = Some(raw);
            saved.output = Some(compressed);
            saved.compressing = true;
        } else {
            let reductions = charge(&saved.encoder, work);
            *saved = TermEncodeState::completed();
            drop(saved);
            process.set_gc_enabled(restore_gc);
            return Ok(HandlerResult::Done {
                value: raw,
                reductions,
            });
        }
    }

    let source = saved.source.ok_or(BifError::BADARG)?;
    let output = saved.output.ok_or(BifError::BADARG)?;
    if !saved.encoder.compression_output_full() {
        let output_budget = chunk_work.saturating_sub(work).max(1);
        let progress = arinsal_bifs::with_binary_bytes(source, |view| {
            arinsal_bifs::with_iolist_binary_output(output, |bytes| {
                saved
                    .encoder
                    .compress_into(&view.bytes()[1..], &mut bytes[6..], output_budget)
            })
        })??;
        work += progress.1;
        if !progress.0 && !saved.encoder.compression_output_full() {
            drop(saved);
            return Ok(HandlerResult::Yield {
                continuation: TERM_TO_BINARY_CONTINUATION,
                state,
                reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
            });
        }
    }
    if saved.encoder.compression_is_useful() {
        let final_size = 6usize
            .checked_add(
                saved
                    .encoder
                    .compressed_payload_len()
                    .ok_or(BifError::SystemLimit)?,
            )
            .ok_or(BifError::SystemLimit)?;
        arinsal_term::writable_resize_private(
            output,
            final_size.checked_mul(8).ok_or(BifError::SystemLimit)?,
        )
        .map_err(|_| BifError::SystemLimit)?;
        arinsal_bifs::finish_iolist_binary_output(output);
        let reductions = charge(&saved.encoder, work);
        *saved = TermEncodeState::completed();
        drop(saved);
        process.set_gc_enabled(restore_gc);
        return Ok(HandlerResult::Done {
            value: output,
            reductions,
        });
    }
    if saved.encoder.compression_output_full() || saved.encoder.compression_finished() {
        arinsal_bifs::finish_iolist_binary_output(output);
        let reductions = charge(&saved.encoder, work);
        *saved = TermEncodeState::completed();
        drop(saved);
        process.set_gc_enabled(restore_gc);
        return Ok(HandlerResult::Done {
            value: source,
            reductions,
        });
    }
    drop(saved);
    Ok(HandlerResult::Yield {
        continuation: TERM_TO_BINARY_CONTINUATION,
        state,
        reductions: (work / TERM_TO_BINARY_LOOP_FACTOR) as u32,
    })
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
    /// Process-table listing and its invocation marker in the shared deletion list.
    snapshot: Option<arinsal_sched::PtabListSnapshot<Process>>,
    scheduler: Arc<arinsal_sched::Scheduler<Process>>,
    /// Process identifiers to cons onto the caller heap after the scan.
    pids: Vec<Term>,
    /// Per-chunk table intervals used to reconcile deleted records.
    chunk_intervals: Vec<u64>,
    /// Next table index to inspect.
    next_index: u32,
    deleted_done: bool,
}

// Port of erts/emulator/beam/erl_ptab.c:746 (erts_ptab_list) and :1281 (ptab_list_continue),
// OTP-29.1.1. Costs follow the engine's constants (erl_ptab.c:42-57): 25 table indices per
// reduction scanned in chunks of 1000, 75 result conses per reduction.
fn processes(
    process: &mut Process,
    args: &[Term],
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
            .downcast_ref::<Mutex<PtabListContinuation>>()
            .ok_or(BifError::BADARG)?;
        let mut list = list.lock().map_err(|_| BifError::SystemLimit)?;
        let accumulator = args.first().copied().unwrap_or(Term::NIL);
        set_ptab_accumulator(process, accumulator)?;
        return match &mut *list {
            PtabListContinuation::Processes(list) => resume_processes(
                process,
                list,
                table_max,
                reds_left,
                Arc::clone(&state),
                accumulator,
            ),
            PtabListContinuation::Ports(list) => resume_ports(
                process,
                list,
                table_max,
                reds_left,
                Arc::clone(&state),
                accumulator,
            ),
        };
    }

    let runtime = process.runtime.as_ref().ok_or(BifError::BADARG)?;
    let scheduler = runtime.scheduler_arc().map_err(|_| BifError::SystemLimit)?;
    let list = PtabListState {
        snapshot: None,
        scheduler,
        pids: Vec::new(),
        chunk_intervals: Vec::new(),
        next_index: 0,
        deleted_done: false,
    };
    set_ptab_accumulator(process, Term::NIL)?;
    let state = magic_binary_state(
        Mutex::new(PtabListContinuation::Processes(list)),
        ERTS_PTAB_LIST_STATE_SIZE,
    );
    let list_cell = state
        .downcast_ref::<Mutex<PtabListContinuation>>()
        .ok_or(BifError::BADARG)?;
    let mut list = list_cell.lock().map_err(|_| BifError::SystemLimit)?;
    if reds_left < MIN_START_REDS {
        return Ok(HandlerResult::Yield {
            continuation: PTAB_LIST_CONTINUATION,
            state: Arc::clone(&state),
            reductions: 1,
        });
    }
    match &mut *list {
        PtabListContinuation::Processes(list) => run_process_list(
            process,
            list,
            table_max,
            reds_left,
            Arc::clone(&state),
            Term::NIL,
        ),
        PtabListContinuation::Ports(_) => unreachable!(),
    }
}

// Port of erts/emulator/beam/erl_ptab.c:888 (ptab_list_bif_engine), OTP-29.1.1.
fn scan_process_table(list: &mut PtabListState, table_max: u32, reds_left: u32) -> (bool, u32) {
    const CHUNK_SIZE: u32 = 1000;
    if list.snapshot.is_none() {
        list.snapshot = Some(list.scheduler.begin_ptab_list());
    }
    let mut spent = 0_u32;
    let mut first_chunk = true;
    while list.next_index < table_max {
        let first = list.next_index;
        let end = (first + CHUNK_SIZE).min(table_max);
        let chunk_reds = (end - first) / 25;
        if !first_chunk && (spent >= reds_left || chunk_reds > reds_left - spent) {
            break;
        }
        let (pids, interval) = list.snapshot.as_ref().unwrap().scan_chunk(first, end);
        list.pids
            .extend(pids.into_iter().filter_map(|pid| pid.to_term()));
        list.chunk_intervals.push(interval);
        let indices = end - first;
        list.next_index = end;
        spent += indices / 25;
        first_chunk = false;
    }
    (list.next_index >= table_max, spent)
}

// Port of erts/emulator/beam/erl_ptab.c:1281 (ptab_list_continue), OTP-29.1.1.
fn run_process_list(
    process: &mut Process,
    list: &mut PtabListState,
    table_max: u32,
    reds_left: u32,
    state: Arc<MagicRef>,
    accumulator: Term,
) -> Result<HandlerResult, BifError> {
    let (table_done, mut spent) = scan_process_table(list, table_max, reds_left);
    if !table_done {
        return ptab_yield(process, state, accumulator, spent);
    }
    if !list.deleted_done {
        let max_deleted_reds = reds_left.saturating_sub(spent).min(40);
        let (deleted, deleted_reds, done) = list
            .snapshot
            .as_mut()
            .expect("table scan initialized its snapshot")
            .inspect_deleted(&list.chunk_intervals, max_deleted_reds);
        list.pids
            .extend(deleted.into_iter().filter_map(|pid| pid.to_term()));
        list.deleted_done = done;
        spent += deleted_reds;
        if !done {
            return ptab_yield(process, state, accumulator, spent);
        }
    }
    build_ptab_result(
        process,
        &mut list.pids,
        accumulator,
        reds_left.saturating_sub(spent),
        spent,
        state,
    )
}

fn resume_processes(
    process: &mut Process,
    list: &mut PtabListState,
    table_max: u32,
    reds_left: u32,
    state: Arc<MagicRef>,
    accumulator: Term,
) -> Result<HandlerResult, BifError> {
    run_process_list(process, list, table_max, reds_left, state, accumulator)
}

// Port of erts/emulator/beam/erl_ptab.c:1210 (BUILDING_RESULT), OTP-29.1.1.
fn build_ptab_result(
    process: &mut Process,
    terms: &mut Vec<Term>,
    accumulator: Term,
    reds_left: u32,
    spent: u32,
    state: Arc<MagicRef>,
) -> Result<HandlerResult, BifError> {
    const CONSES_PER_RED: usize = 75;
    let conses = terms
        .len()
        .min((reds_left as usize).saturating_mul(CONSES_PER_RED));
    if conses == 0 {
        if terms.is_empty() {
            return Ok(HandlerResult::Done {
                value: accumulator,
                reductions: spent,
            });
        }
        return ptab_yield(process, state, accumulator, spent);
    }
    set_ptab_accumulator(process, accumulator)?;
    process
        .ensure(conses.saturating_mul(2), 1)
        .map_err(|_| BifError::SystemLimit)?;
    let accumulator = process.x[0];
    let start = terms.len() - conses;
    let built = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .reserve_cons_list(conses)
        .and_then(|builder| {
            builder.prepend_exact_with_tail(terms[start..].iter().rev().copied(), accumulator)
        })
        .map_err(|_| BifError::SystemLimit)?;
    terms.truncate(start);
    set_ptab_accumulator(process, built)?;
    let spent = spent + (conses / CONSES_PER_RED) as u32;
    if terms.is_empty() {
        Ok(HandlerResult::Done {
            value: built,
            reductions: spent,
        })
    } else {
        ptab_yield(process, state, built, spent)
    }
}

fn set_ptab_accumulator(process: &mut Process, accumulator: Term) -> Result<(), BifError> {
    let slot = process.x.get_mut(0).ok_or(BifError::SystemLimit)?;
    *slot = accumulator;
    Ok(())
}

fn ptab_yield(
    process: &mut Process,
    state: Arc<MagicRef>,
    accumulator: Term,
    reductions: u32,
) -> Result<HandlerResult, BifError> {
    set_ptab_accumulator(process, accumulator)?;
    Ok(HandlerResult::Yield {
        continuation: PTAB_LIST_CONTINUATION,
        state,
        reductions,
    })
}

struct PortPtabListState {
    snapshot: Option<crate::port::PortPtabListSnapshot>,
    runtime: &'static crate::process::Runtime,
    ids: Vec<Term>,
    chunk_intervals: Vec<u64>,
    next_index: u32,
    deleted_done: bool,
}

enum PtabListContinuation {
    Processes(PtabListState),
    Ports(PortPtabListState),
}

// Port of erts/emulator/beam/erl_ptab.c (erts_ptab_list, ptab_list_bif_engine,
// ptab_list_continue), OTP-29.1.1. The standard I/O port is the first table element.
fn ports(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
) -> Result<HandlerResult, BifError> {
    const CHUNK_SIZE: u32 = 1000;
    const INDICES_PER_RED: u32 = 25;
    const MIN_START_REDS: u32 = CHUNK_SIZE / INDICES_PER_RED;
    let table_max = arinsal_term::ptab::port_table_layout().max();
    let reds_left = process.reductions.max(0) as u32;
    let Some(state) = state else {
        if process.runtime.is_none() {
            let port = Term::port(0).ok_or(BifError::SystemLimit)?;
            return Ok(HandlerResult::Done {
                value: TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
                    .list_from_iter([port])
                    .map_err(|_| BifError::SystemLimit)?,
                reductions: 1,
            });
        }
        let runtime = process.runtime.as_ref().ok_or(BifError::BADARG)?;
        let list = PortPtabListState {
            snapshot: None,
            runtime,
            ids: vec![Term::port(0).ok_or(BifError::SystemLimit)?],
            chunk_intervals: Vec::new(),
            next_index: 0,
            deleted_done: false,
        };
        set_ptab_accumulator(process, Term::NIL)?;
        let state = magic_binary_state(
            Mutex::new(PtabListContinuation::Ports(list)),
            ERTS_PTAB_LIST_STATE_SIZE,
        );
        let list_cell = state
            .downcast_ref::<Mutex<PtabListContinuation>>()
            .ok_or(BifError::BADARG)?;
        let mut list = list_cell.lock().map_err(|_| BifError::SystemLimit)?;
        if reds_left < MIN_START_REDS {
            return Ok(HandlerResult::Yield {
                continuation: PTAB_LIST_CONTINUATION,
                state: Arc::clone(&state),
                reductions: 1,
            });
        }
        return match &mut *list {
            PtabListContinuation::Ports(list) => run_port_list(
                process,
                list,
                table_max,
                reds_left,
                Arc::clone(&state),
                Term::NIL,
            ),
            PtabListContinuation::Processes(_) => unreachable!(),
        };
    };
    let state = Arc::clone(state);
    let list = state
        .downcast_ref::<Mutex<PtabListContinuation>>()
        .ok_or(BifError::BADARG)?;
    let mut list = list.lock().map_err(|_| BifError::SystemLimit)?;
    let accumulator = args.first().copied().unwrap_or(Term::NIL);
    set_ptab_accumulator(process, accumulator)?;
    match &mut *list {
        PtabListContinuation::Ports(list) => resume_ports(
            process,
            list,
            table_max,
            reds_left,
            Arc::clone(&state),
            accumulator,
        ),
        PtabListContinuation::Processes(list) => resume_processes(
            process,
            list,
            table_max,
            reds_left,
            Arc::clone(&state),
            accumulator,
        ),
    }
}

// Port of erts/emulator/beam/erl_ptab.c:1281 (ptab_list_continue), OTP-29.1.1.
fn resume_ports(
    process: &mut Process,
    list: &mut PortPtabListState,
    table_max: u32,
    reds_left: u32,
    state: Arc<MagicRef>,
    accumulator: Term,
) -> Result<HandlerResult, BifError> {
    run_port_list(process, list, table_max, reds_left, state, accumulator)
}

// Port of erts/emulator/beam/erl_ptab.c:888 (ptab_list_bif_engine), OTP-29.1.1.
fn run_port_list(
    process: &mut Process,
    list: &mut PortPtabListState,
    table_max: u32,
    reds_left: u32,
    state: Arc<MagicRef>,
    accumulator: Term,
) -> Result<HandlerResult, BifError> {
    let (table_done, mut spent) = scan_port_table(list, table_max, reds_left);
    if !table_done {
        return ptab_yield(process, state, accumulator, spent);
    }
    if !list.deleted_done {
        let max_deleted_reds = reds_left.saturating_sub(spent).min(40);
        let (deleted, deleted_reds, done) = list
            .snapshot
            .as_mut()
            .expect("table scan initialized its snapshot")
            .inspect_deleted(&list.chunk_intervals, max_deleted_reds);
        list.ids.extend(
            deleted
                .into_iter()
                .filter(|id| *id != 0)
                .filter_map(Term::port),
        );
        list.deleted_done = done;
        spent += deleted_reds;
        if !done {
            return ptab_yield(process, state, accumulator, spent);
        }
    }
    build_ptab_result(
        process,
        &mut list.ids,
        accumulator,
        reds_left.saturating_sub(spent),
        spent,
        state,
    )
}

// Port of erts/emulator/beam/erl_ptab.c:888 (ptab_list_bif_engine), OTP-29.1.1.
fn scan_port_table(list: &mut PortPtabListState, table_max: u32, reds_left: u32) -> (bool, u32) {
    const CHUNK_SIZE: u32 = 1000;
    if list.snapshot.is_none() {
        list.snapshot = Some(list.runtime.ports.begin_ptab_list());
    }
    let mut spent = 0_u32;
    let mut first_chunk = true;
    while list.next_index < table_max {
        let first = list.next_index;
        let end = (first + CHUNK_SIZE).min(table_max);
        let chunk_reds = (end - first) / 25;
        if !first_chunk && (spent >= reds_left || chunk_reds > reds_left - spent) {
            break;
        }
        let (ids, interval) = list.snapshot.as_ref().unwrap().scan_chunk(first, end);
        list.ids
            .extend(ids.into_iter().filter(|id| *id != 0).filter_map(Term::port));
        list.chunk_intervals.push(interval);
        list.next_index = end;
        spent += (end - first) / 25;
        first_chunk = false;
    }
    (list.next_index >= table_max, spent)
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
