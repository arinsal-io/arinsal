//! Resumable BIF calls and their private continuation exports.

use super::*;
use arinsal_bifs::BifError;
use arinsal_term::{MagicBin, global_atoms};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The data of a trap context's magic binary: the C context struct (`ErtsAppendContext`,
/// `TTBContext`, ...) behind the lock the resuming BIF takes. A local type so that every
/// context gets its own named destructor.
pub(crate) struct TrapContext<T>(Mutex<T>);

impl<T> TrapContext<T> {
    pub(crate) fn new(context: T) -> Self {
        Self(Mutex::new(context))
    }
}

impl<T> std::ops::Deref for TrapContext<T> {
    type Target = Mutex<T>;
    fn deref(&self) -> &Mutex<T> {
        &self.0
    }
}

/// A continuation that carries everything in its arguments: OTP allocates no context.
pub(crate) struct NoContext;

// One named destructor per trap context, as each erts trap passes its own to
// erts_create_magic_binary (bif.c, erl_bif_binary.c, external.c, erl_map.c, ...).
arinsal_term::magic_payload!(
    NoContext => no_context_destructor,
    TrapContext<arinsal_bifs::Phash2Cont> => make_hash2_destructor,
    TrapContext<BinaryCopyState> => binary_copy_destructor,
    TrapContext<crate::dist::DsigSendContext> => dsig_send_context_destructor,

);

pub(crate) enum HandlerResult {
    Done {
        value: Term,
        reductions: u32,
    },
    Yield {
        continuation: &'static str,
        state: MagicBin,
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
    /// The arguments are the live X registers of the continuation export (`gc_live`).
    LiveRegisters,
}

/// The one table of continuations that stay collectable while parked. Every other
/// continuation disables collection, like erts' `erts_set_gc_state(c_p, 0)` before a
/// state-carrying BIF_TRAP.
pub(crate) fn trap_gc_policy(continuation: &str) -> TrapGc {
    if continuation == "erlang:characters_to_utf8_trap/4" {
        TrapGc::LiveRegisters
    } else {
        TrapGc::Disabled
    }
}

/// Whether the trap state of a parked BIF holds process-heap terms of its own.
pub(crate) fn state_holds_heap_terms(state: &MagicBin) -> bool {
    macro_rules! any {
        ($($t:ty),* $(,)?) => { false $(|| state.downcast_ref::<TrapContext<$t>>().is_some())* };
    }
    any!(BinaryCopyState,)
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
    Option<&MagicBin>,
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

const BINARY_COPY_CONTINUATION: &str = "erlang:binary_copy_trap/3";
/// `dsend_continue_trap_export`.
pub(crate) const DSEND_CONTINUE_CONTINUATION: &str = "erts_internal:dsend_continue_trap/1";
// sizeof(ErtsDSigSendContext) (dist.h), measured with a C probe against the configured OTP-29.1.1
// aarch64-apple-darwin tree: the magic binary payload of a parked send.
const ERTS_DSIG_SEND_CONTEXT_SIZE: usize = 536;

// Port of erts/emulator/beam/erl_iolist.c (ErtsL2BState, IOListSizeState,
// ErtsIOList2VecState).

fn magic_binary_state<T: arinsal_term::MagicPayload>(
    payload: T,
    c_payload_size: usize,
) -> MagicBin {
    MagicBin::with_erts_payload_size_and_refn(
        payload,
        c_payload_size,
        arinsal_bifs::next_ref_words(),
    )
}

/// OTP keeps these continuations in BIF arguments/registers and allocates no magic binary.
fn argument_trap_state<T: arinsal_term::MagicPayload>(payload: T) -> MagicBin {
    MagicBin::with_orig_size(payload, 0)
}

/// Build the continuation argument that owns an erts magic binary.
fn trap_state_term(
    process: &mut Process,
    state: &MagicBin,
) -> Result<Option<Term>, arinsal_term::TermError> {
    if state.orig_size() == 0 {
        return Ok(None);
    }
    // Port of erts/emulator/beam/erl_bif_lists.c (append_create_trap_state): the magic reference
    // thing is a live continuation argument, so its off-heap owner charges orig_size to vheap.
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let term = arinsal_term::TermBuilder::new(&mut heap).magic_ref(MagicBin::clone(state))?;
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

const ENTRIES: &[Entry] = &[
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
];

// Port of erts/emulator/beam/erl_bif_binary.c:2365-2374 (CopyBinState), OTP-29.1.1.
struct BinaryCopyState {
    result: Term,
    copied_bits: usize,
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
        state: argument_trap_state(NoContext),
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
        (entry.handler, Some(MagicBin::clone(&pending.state)))
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
                        .filter(|pending| MagicBin::ptr_eq(&pending.state, &state))
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
                root_args: 0,
                args: if resumed {
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
                    .map(|pending| MagicBin::clone(&pending.state))
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
            let mut saved = [Term::NIL; 4];
            let kept = args.len().min(4);
            saved[..kept].copy_from_slice(&args[..kept]);
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
                root_args: 0,
                args: saved,
            });
            charge_light(process, reductions);
            return LightTrap::Trapped;
        }
        Ok(HandlerResult::Export(trap)) => {
            let state = argument_trap_state(NoContext);
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
    state: Option<&MagicBin>,
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
        let state = MagicBin::clone(state);
        let copy = state
            .downcast_ref::<TrapContext<BinaryCopyState>>()
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
        state: argument_trap_state(TrapContext::new(BinaryCopyState {
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
    let state = magic_binary_state(TrapContext::new(ctx), ERTS_DSIG_SEND_CONTEXT_SIZE);
    let state_term = trap_state_term(process, &state)
        .map_err(|_| BifError::SystemLimit)?
        .ok_or(BifError::SystemLimit)?;
    let mut trap = crate::ExportTrap::new(process, DSEND_CONTINUE_CONTINUATION, vec![state_term]);
    trap.gc_disabled = true;
    Ok(trap)
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
    let _ = context.with_magic_payload::<TrapContext<crate::dist::DsigSendContext>, _>(|ctx| {
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
            .collect_arg_reg(process.gc_live, &mut [], 0)
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
