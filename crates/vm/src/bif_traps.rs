//! Resumable BIF calls and their private continuation exports.

use super::*;
use arinsal_bifs::BifError;
use arinsal_term::{MagicBin, global_atoms};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The data of a trap context's magic binary: the C context struct (`ErtsAppendContext`,
/// `TTBContext`, ...) inline in the magic binary, mutated in place by the owning process as
/// erts does through ERTS_MAGIC_BIN_DATA. A local type so that every context gets its own named
/// destructor.
#[repr(transparent)]
pub(crate) struct TrapContext<T>(pub(crate) T);

impl<T> TrapContext<T> {
    pub(crate) fn new(context: T) -> Self {
        Self(context)
    }
}

impl<T> std::ops::Deref for TrapContext<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

// SAFETY: a trap context is created by the BIF that traps and reachable only through the trap
// term in that process's own registers (erts ERTS_MAGIC_BIN_DATA of a trap export's state); the
// process runs on one scheduler thread at a time, so no two accesses to the payload overlap.
unsafe impl<T> arinsal_term::ExclusiveMagicPayload for TrapContext<T> where
    TrapContext<T>: arinsal_term::MagicPayload
{
}

impl<T> std::ops::DerefMut for TrapContext<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// One named destructor per trap context, as each erts trap passes its own to
// erts_create_magic_binary (bif.c, erl_bif_binary.c, external.c, erl_map.c, ...).
arinsal_term::magic_payload!(
    TrapContext<arinsal_bifs::Phash2Cont> => make_hash2_destructor,
    TrapContext<crate::dist::DsigSendContext> => dsig_send_context_destructor,

);

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
        arinsal_sched::unique::next_ref_words(),
    )
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

/// Install the trap state of a BIF that traps to an Erlang export. The scheduler then runs
/// the export at `beam_bif_export_trap` on schedule-in.
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
    let gc_was_enabled = process.heap.gc_enabled();
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
        gc_was_enabled,
        arity,
        callee,
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
    let _ = context.with_magic_payload_mut::<TrapContext<crate::dist::DsigSendContext>, _>(|ctx| {
        let ctx = &mut ctx.0;
        crate::dist::dsend_exit(process, ctx, sender);
    });
}

#[cfg(test)]
mod export_trap_tests {
    use super::*;
    use arinsal_etf::OwnedTerm;
    use arinsal_term::TermBuilder;

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
        assert!(process.heap.gc_enabled(), "export traps keep GC enabled");

        // A collection while the process is scheduled out: the live X registers are the roots.
        process.collect_arg_reg(process.gc_live, &mut [], 0);

        let Some(resumed) = take_export_trap(&mut process) else {
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
