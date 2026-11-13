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
            Self::Done { reductions, .. } | Self::Yield { reductions, .. } => *reductions,
            Self::Export(_) => 0,
        }
    }
}

/// How a trapped BIF keeps its heap terms across a collection that runs while it is parked.
// Port of erts/emulator/beam/bif.h (ERTS_BIF_PREP_TRAPn) and erl_gc.c (F_DISABLE_GC,
// erts_set_gc_state), OTP-29.1.1: a BIF continuation either keeps every heap term in the
// arguments of its trap (the X registers, `c_p->arity`), which the collector updates, or it
// keeps process-heap pointers in its off-heap state and disables collection while it is parked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TrapGc {
    /// The state may hold heap terms; the process is not collected while the trap is parked.
    Disabled,
    /// The first `n` of the trap's saved arguments are the live registers and the only heap
    /// terms the trap keeps: collection roots.
    RootedArgs(usize),
    /// The arguments are the live X registers of the continuation export (`gc_live`).
    LiveRegisters,
    /// The state holds no heap term and the arguments are immediates.
    NoTerms,
}

/// The one table of continuations that stay collectable while parked. Every other
/// continuation disables collection, like erts' `erts_set_gc_state(c_p, 0)` before a
/// state-carrying BIF_TRAP.
pub(crate) fn trap_gc_policy(continuation: &str) -> TrapGc {
    if continuation == PTAB_LIST_CONTINUATION {
        // BIF_TRAP1 carries the accumulator in X0.
        TrapGc::RootedArgs(1)
    } else if continuation == CODE_PERMISSION_CONTINUATION {
        TrapGc::NoTerms
    } else if continuation == RE_GRUN_CONTINUATION
        || continuation == RE_URUN_CONTINUATION
        || continuation == "erlang:characters_to_utf8_trap/4"
    {
        TrapGc::LiveRegisters
    } else {
        TrapGc::Disabled
    }
}

/// Whether the trap state of a parked BIF holds process-heap terms of its own.
pub(crate) fn state_holds_heap_terms(state: &Arc<MagicRef>) -> bool {
    macro_rules! any {
        ($($t:ty),* $(,)?) => { false $(|| state.downcast_ref::<Mutex<$t>>().is_some())* };
    }
    any!(
        arinsal_bifs::BinaryToListWalk,
        arinsal_bifs::UnicodeCont,
        arinsal_bifs::IolistVecWalk,
        arinsal_bifs::IolistSizeWalk,
        arinsal_bifs::DecodeWalk<'static>,
        arinsal_bifs::BinarySearchWalk,
        BinaryCopyState,
    )
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
const BINARY_COPY_CONTINUATION: &str = "erlang:binary_copy_trap/3";
const BINARY_SEARCH_CONTINUATION: &str = "erlang:binary_find_trap/3";
pub(crate) const PTAB_LIST_CONTINUATION: &str = "erlang:ptab_list_continue/2";
/// `dsend_continue_trap_export`.
pub(crate) const DSEND_CONTINUE_CONTINUATION: &str = "erts_internal:dsend_continue_trap/1";
// sizeof(ErtsDSigSendContext) (dist.h), measured with a C probe against the configured OTP-29.1.1
// aarch64-apple-darwin tree: the magic binary payload of a parked send.
const ERTS_DSIG_SEND_CONTEXT_SIZE: usize = 536;
const CONTEXT_REDS: usize = 4000;
const RE_RUN_CONTINUATION: &str = "erlang:re_run_trap/3";
const RE_GRUN_CONTINUATION: &str = "re:grun/3";
const RE_URUN_CONTINUATION: &str = "re:urun/3";

// C payload sizes passed to erts_create_magic_binary on macOS arm64. The separate magic binary
// data offset is added by MagicRef::with_erts_payload_size.
// Port of erts/emulator/beam/erl_unicode.c (RestartContext).
const ERTS_UNICODE_RESTART_CONTEXT_SIZE: usize = 40;
// Port of erts/emulator/beam/erl_bif_re.c (RestartContext).
const ERTS_REGEX_RESTART_CONTEXT_SIZE: usize = 64;
const ERTS_BINARY_FIND_CONTEXT_SIZE: usize = 312;
// Port of erts/emulator/beam/erl_iolist.c (ErtsL2BState, IOListSizeState,
// ErtsIOList2VecState).
// Port of erts/emulator/beam/erl_ptab.c (ErtsPTabListBifData).
const ERTS_PTAB_LIST_STATE_SIZE: usize = 64;

fn magic_binary_state<T: std::any::Any + Send + Sync>(
    payload: T,
    c_payload_size: usize,
) -> Arc<MagicRef> {
    MagicRef::with_erts_payload_size_and_refn(
        payload,
        c_payload_size,
        arinsal_bifs::next_ref_words(),
    )
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
        .native_retry_site()
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
    process.heap.abi.i = bif_export_trap as *const u8 as *const _;
}

fn clear_export_trap(process: &mut Process) {
    if process.heap.abi.i as usize == bif_export_trap_pc() {
        process.heap.abi.i = std::ptr::null();
    }
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
    let mut bif_state = arinsal_bifs::BifState::default();
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

// Port of erts/emulator/beam/erl_unicode.c:851 (characters_to_utf8_trap), OTP-29.1.1.
fn unicode_binary_trap(
    process: &mut Process,
    state: Option<&Arc<MagicRef>>,
) -> Result<HandlerResult, BifError> {
    // BIF_TRAP4 restores the continuation arguments in the live X registers.
    let cont = arinsal_bifs::UnicodeCont::from_binary_trap_arguments(&process.x[..4])
        .ok_or(BifError::BADARG)?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut bif_state = arinsal_bifs::BifState::default();
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut bif_state);
    match arinsal_bifs::unicode_resume(&mut ctx, &cont) {
        arinsal_bifs::UnicodeStep::Done(value) => Ok(HandlerResult::Done {
            value,
            reductions: 0,
        }),
        arinsal_bifs::UnicodeStep::More(cont) => {
            let trap_args = cont.binary_trap_arguments().ok_or(BifError::BADARG)?;
            process.x.ensure_x(trap_args.len());
            process.x[..trap_args.len()].copy_from_slice(&trap_args);
            process.gc_live = trap_args.len();
            Ok(HandlerResult::Yield {
                continuation: cont.continuation(),
                state: state.cloned().unwrap_or_else(|| argument_trap_state(())),
                reductions: 0,
            })
        }
    }
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
    // erts binds this continuation BIF when its export is loaded. Resolve the
    // Rust function pointer once, then keep the call path to the body itself.
    static CHARACTERS_TO_BINARY: std::sync::OnceLock<arinsal_bifs::BifFn> =
        std::sync::OnceLock::new();
    static CHARACTERS_TO_LIST: std::sync::OnceLock<arinsal_bifs::BifFn> =
        std::sync::OnceLock::new();
    let bif = match function {
        "characters_to_binary" => CHARACTERS_TO_BINARY.get_or_init(|| {
            arinsal_bifs::lookup("unicode", function, args.len() as u8)
                .expect("registered Unicode BIF")
        }),
        "characters_to_list" => CHARACTERS_TO_LIST.get_or_init(|| {
            arinsal_bifs::lookup("unicode", function, args.len() as u8)
                .expect("registered Unicode BIF")
        }),
        _ => return Err(BifError::BADARG),
    };
    let (result, deferred) = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        // Port of erts/emulator/beam/erl_unicode.c:166 (allowed_iterations), OTP-29.1.1:
        // the loop budget rereads FCALLS after cost_to_proc charges it.
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut state);
        let result = bif(&mut ctx, args)?;
        let deferred = ctx.take_deferred();
        (result, deferred)
    };
    match deferred.map(|trap| *trap) {
        Some(arinsal_bifs::DeferredTrap::Unicode(cont))
            if cont.continuation() == "erlang:characters_to_utf8_trap/4" =>
        {
            let trap_args = cont.binary_trap_arguments().ok_or(BifError::BADARG)?;
            process.x.ensure_x(trap_args.len());
            process.x[..trap_args.len()].copy_from_slice(&trap_args);
            process.gc_live = trap_args.len();
            Ok(HandlerResult::Yield {
                continuation: cont.continuation(),
                state: argument_trap_state(()),
                reductions: 0,
            })
        }
        Some(arinsal_bifs::DeferredTrap::Unicode(cont)) => Ok(HandlerResult::Yield {
            continuation: cont.continuation(),
            state: magic_binary_state(Mutex::new(cont), ERTS_UNICODE_RESTART_CONTEXT_SIZE),
            reductions: 0,
        }),
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

fn erlang_characters_to_utf8_trap(
    process: &mut Process,
    _args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<HandlerResult, BifError> {
    unicode_binary_trap(process, state)
}
unicode_trap_entry!(erlang_characters_to_list_trap_1);
unicode_trap_entry!(erlang_characters_to_list_trap_2);
unicode_trap_entry!(erlang_characters_to_list_trap_3);
unicode_trap_entry!(erlang_characters_to_list_trap_4);

const ENTRIES: &[Entry] = &[
    Entry {
        module: "erts_internal",
        function: "dsend_continue_trap",
        arity: 1,
        continuation: DSEND_CONTINUE_CONTINUATION,
        handler: dsend_continue_trap_1,
    },
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
    let reds_left = process.heap.abi.fcalls.clamp(1, CONTEXT_REDS as i32);
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
            HandlerResult::Export(crate::ExportTrap::new(
                process,
                RE_URUN_CONTINUATION,
                vec![args[0], args[1], args.get(2).copied().unwrap_or(Term::NIL)],
            ))
        }
        arinsal_re::RunDispatch::Global(arinsal_re::GlobalRun::Trap { pattern, options }) => {
            // Port of erts/emulator/beam/erl_bif_re.c:1557-1603 (grun_trap_exportp), OTP-29.1.1.
            process.x.ensure_x(3);
            process.x[..3].copy_from_slice(&[args[0], pattern, options]);
            process.gc_live = 3;
            HandlerResult::Export(crate::ExportTrap::new(
                process,
                RE_GRUN_CONTINUATION,
                vec![args[0], pattern, options],
            ))
        }
    })
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
    let budget = (process.heap.abi.fcalls.max(0) as usize)
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
    // Port of erts/emulator/beam/erl_bif_binary.c result callbacks, OTP-29.1.1:
    // allocate directly on the process heap after the search loop completes.
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let value = search.finish(&mut heap)?;
    Ok(HandlerResult::Done { value, reductions })
}

/// Key of a trapped call made through `apply` when the caller does not import the BIF.
pub(crate) const APPLY_TRAP_KEY: usize = usize::MAX;

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
    pub(crate) continuation: &'static str,
    pub(crate) trap_export_id: usize,
    pub(crate) module: &'static str,
    pub(crate) function: &'static str,
    pub(crate) arity: usize,
    pub(crate) module_atom: arinsal_term::Atom,
    pub(crate) function_atom: arinsal_term::Atom,
    /// The Rust handler of the continuation, absent when it is an Erlang export.
    pub(crate) entry: Option<&'static Entry>,
    /// `trampoline.bif.address` of a hidden trap export (`erts_init_trap_export`).
    pub(crate) trap_function: Option<usize>,
}

impl std::fmt::Debug for ContinuationTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContinuationTarget")
            .field("continuation", &self.continuation)
            .field("arity", &self.arity)
            .finish()
    }
}

impl ContinuationTarget {
    fn is(&self, module: &str, function: &str, arity: usize) -> bool {
        self.arity == arity && self.function == function && self.module == module
    }
}

/// The target of a continuation string, cached per string address so a trap pays no hashing.
/// Its stable id indexes each runtime's `ExportEntry` table.
pub(crate) const TRAP_EXPORT_CAPACITY: usize = 128;

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
    let mut all = ALL
        .get_or_init(Default::default)
        .lock()
        .expect("continuation targets");
    let target = if let Some(target) = all.get(continuation) {
        *target
    } else {
        assert!(
            all.len() < TRAP_EXPORT_CAPACITY,
            "trap export table capacity"
        );
        let (module, function, arity) =
            continuation_parts(continuation).expect("a continuation is `module:function/arity`");
        let target: &'static ContinuationTarget = Box::leak(Box::new(ContinuationTarget {
            continuation,
            trap_export_id: all.len(),
            module,
            function,
            arity,
            module_atom: global_atoms()
                .intern(module)
                .expect("continuation module atom"),
            function_atom: global_atoms()
                .intern(function)
                .expect("continuation function atom"),
            entry: lookup_entry(module, function, arity),
            trap_function: u8::try_from(arity)
                .ok()
                .and_then(|arity| crate::bif_table::trap_function(module, function, arity)),
        }));
        let _ = all.insert(continuation, target);
        target
    };
    drop(all);
    RECENT.with(|recent| {
        let mut slots = recent.get();
        slots[slot] = Some((key.0, key.1, target));
        recent.set(slots);
    });
    target
}

/// The pending `BIF_TRAP*` to an export as the call the scheduler makes next: the export and
/// the arguments the trap left in the X registers (erts BIF_TRAPn, reg[0..n]).
// Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*) and beam_common.c, OTP-29.1.1.
pub(crate) fn take_export_trap(process: &mut Process) -> Option<crate::ExportTrap> {
    let pending = process.take_work(|w| w.bif_trap.take())?;
    clear_export_trap(process);
    let args = process.x[..pending.arity].to_vec();
    Some(crate::ExportTrap::new(process, pending.continuation, args))
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
        return take_export_trap(process).map(|trap| Ok(ResumeResult::Export(trap)));
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
    .map(|result| {
        result.map(|handler| match handler {
            HandlerResult::Export(trap) => ResumeResult::Export(trap),
            handler => ResumeResult::Handler(handler),
        })
    })
}

/// Install the trap state of a BIF that traps to an Erlang export. The scheduler then runs
/// the export at `beam_bif_export_trap`, the way an export trap of a Rust continuation runs.
// Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*: up to four arguments in X0-X3),
// OTP-29.1.1.
/// `schedule_out` is whether the context switch of the trap (`context_switch_simplified`) is
/// still ahead: true when native code returns THE_NON_VALUE and branches to
/// `beam_bif_export_trap`, false when the executor yields the slice for the trap itself.
pub(crate) fn install_export_trap(
    process: &mut Process,
    import: usize,
    callee: (arinsal_term::Atom, arinsal_term::Atom),
    trap: &crate::ExportTrap,
    schedule_out: bool,
) {
    let arity = trap.args.len();
    assert!(arity <= 4, "BIF traps pass at most four arguments");
    // erts BIF_TRAPn writes the arguments to reg[0..n] and sets c_p->arity: they are the live
    // X registers of the export call, rooted like any other. GC stays enabled while trapped.
    process.x.ensure_x(arity);
    process.x[..arity].copy_from_slice(&trap.args);
    process.gc_live = arity;
    let gc_was_enabled = process.heap.gc_enabled;
    if trap.gc_disabled {
        process.set_gc_enabled(false);
    }
    process.slice_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
        caller_module: process.trap_site().0,
        caller_ip: process.trap_site().1,
        schedule_out,
        import,
        continuation: trap.target.continuation,
        target: trap.target,
        state: argument_trap_state(()),
        state_term: None,
        gc_was_enabled,
        arity,
        callee,
        root_args: 0,
        args: {
            let mut saved = [Term::NIL; 4];
            saved[..arity].copy_from_slice(&trap.args);
            saved
        },
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
// Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*), OTP-29.1.1.
pub(crate) fn arm_export_trap(process: &mut Process) {
    if let Some(arity) = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .map(|pending| pending.target.arity)
    {
        process.heap.abi.arity = arity as u8;
    }
    process.heap.abi.i = bif_export_trap as *const u8 as *const _;
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
        if let Some(pending) = process.take_work(|w| w.bif_trap.take()) {
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
            if let Some(pending) = process.take_work(|w| w.bif_trap.take()) {
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
            if let Some(pending) = process.take_work(|w| w.bif_trap.take()) {
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
    let pid = ctx.as_deref().map(|run| run.pid());
    let resumed = state.is_some();
    // The continuation export has its own arity (binary_copy_trap/3).
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
    let fcalls_in = process.heap.abi.fcalls;
    let result = handler(
        process,
        &args[..call_arity.min(args.len())],
        state.as_ref(),
        pid,
        gc_was_enabled,
    );
    process.trap_work = fcalls_in.saturating_sub(process.heap.abi.fcalls).max(0);
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
            process.slice_mut().bif_trap = None;
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
            process.slice_mut().bif_trap = None;
            clear_export_trap(process);
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, reductions);
            Ok(HandlerResult::Done { value, reductions })
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
                        process.slice_mut().bif_trap = None;
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
            // Which continuations stay collectable while parked is decided in one place,
            // `trap_gc_policy`; every other one disables collection as erts does before a
            // state-carrying BIF_TRAP (a ptab list or code-permission waiter keeps no heap
            // term of its own, erts runs GC tasks of such a suspended process).
            let gc_policy = trap_gc_policy(continuation);
            if gc_policy == TrapGc::Disabled {
                process.set_gc_enabled(false);
            }
            let root_args = match gc_policy {
                TrapGc::RootedArgs(n) => n,
                _ => 0,
            };
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
            process.slice_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
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
                root_args,
                args: if continuation == PTAB_LIST_CONTINUATION {
                    [process.x[0], Term::NIL, Term::NIL, Term::NIL]
                } else if resumed {
                    args
                } else {
                    let live = live_args(process, &args, arity.min(4));
                    let mut saved = [Term::NIL; 4];
                    saved[..live.len()].copy_from_slice(&live);
                    saved
                },
            });
            charge(process, ctx, reductions);
            // Port of erts/emulator/beam/erl_gc.c (erts_gc_after_bif_call_lhf with a
            // TRAP result collects with the trap's arguments as roots), OTP-29.1.1.
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
            process.slice_mut().bif_trap = None;
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

/// Outcome of a trapping BIF run from a light BIF call.
pub(crate) enum LightTrap {
    /// The BIF finished: its value or its error, like any light BIF's result.
    Returned(Result<Term, BifError>),
    /// The BIF trapped to its continuation export (`THE_NON_VALUE` with `freason == TRAP`);
    /// the call site context-switches and the scheduler resumes it through the trap state.
    Trapped,
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
        Ok(HandlerResult::Yield {
            continuation,
            state,
            reductions,
        }) => {
            let gc_policy = trap_gc_policy(continuation);
            if gc_policy == TrapGc::Disabled {
                process.set_gc_enabled(false);
            }
            let root_args = match gc_policy {
                TrapGc::RootedArgs(n) => n,
                _ => 0,
            };
            let mut saved = [Term::NIL; 4];
            let kept = args.len().min(4);
            saved[..kept].copy_from_slice(&args[..kept]);
            if continuation == PTAB_LIST_CONTINUATION {
                // BIF_TRAP1 carries the accumulator in X0; it does not change the trapped
                // processes/0 or ports/0 call's arity.
                saved[0] = process.x[0];
            }
            let Ok(state_term) = trap_state_term(process, &state) else {
                return LightTrap::Returned(Err(BifError::SystemLimit));
            };
            // The scheduler binds the trap to its call site when it context-switches.
            process.slice_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
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
                root_args,
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
            let mut saved = [Term::NIL; 4];
            let kept = trap.args.len().min(saved.len());
            saved[..kept].copy_from_slice(&trap.args[..kept]);
            process.slice_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.trap_site().0,
                caller_ip: process.trap_site().1,
                // BIF_TRAP to an export is a context switch like any other trap
                // (instr_bif.cpp, call_light_bif_shared: context_switch_simplified);
                // `beam_bif_export_trap` calls the export on schedule-in.
                schedule_out: true,
                import,
                continuation: trap.target.continuation,
                target: trap.target,
                state,
                state_term,
                gc_was_enabled,
                arity: kept,
                callee,
                root_args: 0,
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
    args: &[Term],
    trap: arinsal_bifs::DeferredTrap,
) -> Result<(), arinsal_term::TermError> {
    let gc_was_enabled = process.heap.gc_enabled;
    let (continuation, state) = match trap {
        arinsal_bifs::DeferredTrap::Unicode(cont) => (
            cont.continuation(),
            magic_binary_state(Mutex::new(cont), ERTS_UNICODE_RESTART_CONTEXT_SIZE),
        ),
    };
    let state_term = trap_state_term(process, &state)?;
    let gc_policy = trap_gc_policy(continuation);
    if gc_policy == TrapGc::Disabled {
        process.set_gc_enabled(false);
    }
    let root_args = match gc_policy {
        TrapGc::RootedArgs(n) => n,
        _ => 0,
    };
    let mut saved = [Term::NIL; 4];
    let arity = args.len().min(4);
    saved[..arity].copy_from_slice(&args[..arity]);
    process.slice_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
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
        root_args,
        args: saved,
    });
    Ok(())
}

/// Charges a light trapping BIF's reductions against FCALLS (BUMP_REDS, bif.h); the call site
/// has charged the call itself.
pub(crate) fn charge_light(process: &mut Process, reductions: u32) {
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
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
/// is billed for the work once, on FCALLS, which the context switch reads as `REDS_IN -
/// FCALLS`. A call is billed no more than the counter held, since `BUMP_REDS` stops at zero.
pub(crate) struct TrapMeter {
    fcalls: i32,
    call_counted: bool,
}

impl TrapMeter {
    /// The call is an instruction that already counted its own reduction.
    pub(crate) fn start(
        process: &Process,
        _ctx: Option<&arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Self {
        Self {
            fcalls: process.heap.abi.fcalls,
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
        _ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
        returned: u32,
    ) {
        let inside = u32::try_from(process.trap_work).unwrap_or(0);
        let held = u32::try_from(self.fcalls.max(1)).unwrap_or(1);
        // The instruction already took the call's own reduction from FCALLS.
        let work = inside
            .max(returned.max(1))
            .min(held)
            .saturating_sub(u32::from(self.call_counted));
        process.heap.abi.fcalls = self
            .fcalls
            .saturating_sub(i32::try_from(work).unwrap_or(i32::MAX))
            .max(0);
    }
}

// Port of erts/emulator/beam/bif.h:71-78 (BUMP_REDS), OTP-29.1.1: the call's own reduction is
// taken by the instruction that called the BIF (`subs FCALLS`), never added here: a traced BIF
// call takes none, so a floor of one reduction overcharged it.
fn charge(
    process: &mut Process,
    _ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    reductions: u32,
) {
    let charge = reductions;
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(charge.min(i32::MAX as u32) as i32)
        .max(0);
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

/// Bits copied per reduction: a cache line (`ERTS_CACHE_LINE_SIZE * 8`, 64-byte lines).
const BITSTRING_COPY_LOOP_FACTOR: u64 = 64 * 8;

/// `ERTS_VBUMP_ALL_REDS`: the rest of the slice is given up without being the process's own
/// work. The scheduler leaves the process at the next reduction check, and `virtual_reds`
/// keeps the given-up amount out of the process's reduction count.
pub(crate) fn vbump_all_reds(process: &mut Process) {
    if process.heap.abi.fcalls > 0 {
        process.virtual_reds = process
            .virtual_reds
            .saturating_add(process.heap.abi.fcalls as u32);
    }
    process.heap.abi.fcalls = 0;
}

/// `get_reds`: the loop budget of one slice, `ERTS_BIF_REDS_LEFT * loop_factor`, capped by
/// the `binary_loop_limit` debug state and never zero.
fn binary_loop_budget(process: &Process, loop_factor: u64) -> u64 {
    let reds = u64::try_from(process.heap.abi.fcalls.max(0))
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
    let reds_left = process.heap.abi.fcalls.max(0) as u32;
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
        chunk_intervals: Vec::with_capacity(table_max.div_ceil(1000) as usize),
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
        let count = list.snapshot.as_ref().unwrap().count();
        list.pids
            .reserve_exact(count.saturating_sub(list.pids.capacity()));
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
        let interval = list
            .snapshot
            .as_ref()
            .unwrap()
            .scan_chunk_with(first, end, |pid| {
                if let Some(pid) = pid.to_term() {
                    list.pids.push(pid);
                }
            });
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
        let (deleted_reds, done) = list
            .snapshot
            .as_mut()
            .expect("table scan initialized its snapshot")
            .inspect_deleted_with(&list.chunk_intervals, max_deleted_reds, |pid| {
                if let Some(pid) = pid.to_term() {
                    list.pids.push(pid);
                }
            });
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
    let reds_left = process.heap.abi.fcalls.max(0) as u32;
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
        let ids = vec![Term::port(0).ok_or(BifError::SystemLimit)?];
        let list = PortPtabListState {
            snapshot: None,
            runtime,
            ids,
            chunk_intervals: Vec::with_capacity(table_max.div_ceil(1000) as usize),
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
        let (deleted_reds, done) = list
            .snapshot
            .as_mut()
            .expect("table scan initialized its snapshot")
            .inspect_deleted_with(&list.chunk_intervals, max_deleted_reds, |id| {
                if id != 0
                    && let Some(id) = Term::port(id)
                {
                    list.ids.push(id);
                }
            });
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
        let count = list.snapshot.as_ref().unwrap().count();
        list.ids
            .reserve_exact(count.saturating_sub(list.ids.capacity()));
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
        let interval = list
            .snapshot
            .as_ref()
            .unwrap()
            .scan_chunk_with(first, end, |id| {
                if id != 0
                    && let Some(id) = Term::port(id)
                {
                    list.ids.push(id);
                }
            });
        list.chunk_intervals.push(interval);
        list.next_index = end;
        spent += (end - first) / 25;
        first_chunk = false;
    }
    (list.next_index >= table_max, spent)
}

/// `erts_dsend_export_trap_context`: the magic binary of a parked distributed send, as the
/// `BIF_TRAP1` argument of `dsend_continue_trap/1`. The context keeps the return term, so
/// garbage collection is disabled while the send is parked (`erts_set_gc_state(c_p, 0)`).
// Port of erts/emulator/beam/bif.c (erts_dsend_export_trap_context, ERTS_BIF_PREP_TRAP1 of
// dsend_continue_trap_export), OTP-29.1.1.
pub(crate) fn dsend_export_trap(
    process: &mut Process,
    mut ctx: crate::dist::DsigSendContext,
    return_term: Term,
) -> Result<crate::ExportTrap, BifError> {
    ctx.set_return_term(return_term);
    let state = magic_binary_state(Mutex::new(ctx), ERTS_DSIG_SEND_CONTEXT_SIZE);
    let state_term = trap_state_term(process, &state)
        .map_err(|_| BifError::SystemLimit)?
        .ok_or(BifError::SystemLimit)?;
    let mut trap = crate::ExportTrap::new(process, DSEND_CONTINUE_CONTINUATION, vec![state_term]);
    trap.gc_disabled = true;
    Ok(trap)
}

/// `dsend_continue_trap_1`: restore the reductions and resume `erts_dsig_send` on the context,
/// trapping again while fragments remain.
// Port of erts/emulator/beam/bif.c:2806-2840 (dsend_continue_trap_1), OTP-29.1.1.
fn dsend_continue_trap_1(
    process: &mut Process,
    args: &[Term],
    _state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    _gc_was_enabled: bool,
) -> Result<HandlerResult, BifError> {
    let (Some(sender), [context]) = (pid, args) else {
        return Err(BifError::BADARG);
    };
    let context = *context;
    let (result, return_term) = context
        .with_magic_payload::<Mutex<crate::dist::DsigSendContext>, _>(|ctx| {
            let mut ctx = ctx.lock().map_err(|_| BifError::SystemLimit)?;
            let result = crate::dist::dsend_continue(process, &mut ctx, sender)
                .map_err(|_| BifError::BADARG)?;
            Ok::<_, BifError>((result, ctx.return_term()))
        })
        .ok_or(BifError::BADARG)??;
    Ok(match result {
        // erts_set_gc_state(BIF_P, 1) is the restore of the trap's GC state on completion.
        crate::dist::DsendContinue::Done => HandlerResult::Done {
            value: return_term,
            reductions: 0,
        },
        crate::dist::DsendContinue::Yield { no_suspend: true } => HandlerResult::Done {
            value: Term::atom(arinsal_term::atoms::NOSUSPEND),
            reductions: 0,
        },
        crate::dist::DsendContinue::Yield { no_suspend: false } => {
            // ERTS_BIF_YIELD_RETURN(BIF_P, ctx->return_term).
            vbump_all_reds(process);
            HandlerResult::Export(crate::ExportTrap::new(
                process,
                crate::natives::sys::BIF_RETURN_TRAP,
                vec![return_term, Term::atom(arinsal_term::atoms::UNDEFINED)],
            ))
        }
        crate::dist::DsendContinue::Continue => {
            // BUMP_ALL_REDS(BIF_P); BIF_TRAP1(&dsend_continue_trap_export, BIF_P, BIF_ARG_1).
            process.heap.abi.fcalls = 0;
            let mut trap =
                crate::ExportTrap::new(process, DSEND_CONTINUE_CONTINUATION, vec![context]);
            trap.gc_disabled = true;
            HandlerResult::Export(trap)
        }
    })
}

/// A process that exits while parked in `dsend_continue_trap/1` finishes its fragmented send
/// first (`F_FRAGMENTED_SEND`: `pectxt.dist_state = p->arg_reg[0]`).
// Port of erts/emulator/beam/erl_process.c:14525-14532 (erts_continue_exit_process), OTP-29.1.1.
pub(crate) fn finish_parked_dsend(process: &mut Process, sender: arinsal_sched::Pid) {
    let Some(context) = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .filter(|pending| pending.continuation == DSEND_CONTINUE_CONTINUATION)
        .map(|pending| pending.args[0])
    else {
        return;
    };
    let _ = context.with_magic_payload::<Mutex<crate::dist::DsigSendContext>, _>(|ctx| {
        if let Ok(mut ctx) = ctx.lock() {
            crate::dist::dsend_exit(process, &mut ctx, sender);
        }
    });
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
        let trap = crate::ExportTrap::new(
            &process,
            "erts_internal:flush_monitor_messages/3",
            vec![tuple, false_atom, true_atom],
        );
        let callee = (
            global_atoms().intern("erlang").unwrap(),
            global_atoms().intern("demonitor").unwrap(),
        );
        install_export_trap(&mut process, 0, callee, &trap, true);
        assert!(process.heap.gc_enabled, "export traps keep GC enabled");

        // A collection while the process is scheduled out: the live X registers are the roots.
        process
            .collect_heap_roots(process.gc_live, &mut [], 0)
            .unwrap();

        let Some(Ok(ResumeResult::Export(resumed))) = run_trapped_export(&mut process, None) else {
            panic!("the export trap resumes as an export call");
        };
        assert_eq!(
            resumed.target.continuation,
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
