//! VM-facing system native bindings: statistics and literal retirement.
//!
//! Return shapes follow OTP-29.1.1's `statistics_1` and `system_info_1`.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_bifs::Ctx;
use arinsal_pterm::RetiredArea;
use arinsal_sched::RunCtx;
use arinsal_term::{
    FragmentIndex, SharedCopyCache, Term, TermBuilder, TermKind, copy_term,
    copy_term_preserving_sharing_with_cache, global_atoms,
};
use std::cell::Cell;
use std::collections::HashSet;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[path = "alloc_atoms.rs"]
mod alloc_atoms;
#[path = "alloc_info.rs"]
mod alloc_info;

const QUANTUM: u32 = 4_000;
// Header subtags from arinsal-term/src/lib.rs. They are crate-private there.
const ARITY: u64 = 0x00;
const FUN: u64 = 0x14;
const RECORD: u64 = 0x1c;
const SUB_BITS: u64 = 0x24;
const MAP: u64 = 0x2c;

type MicrostateBaseline = (Instant, Vec<[u64; 7]>, [u64; 3]);

#[derive(Clone)]
struct SchedBase {
    started: Instant,
    active_ns: Vec<u64>,
}
/// Clock origins captured when the VM boots and copied into its runtime.
#[derive(Clone, Copy)]
pub(crate) struct StatisticsOrigins {
    cpu_ns: u64,
    wall: Instant,
}

impl StatisticsOrigins {
    pub(crate) fn now() -> Self {
        Self {
            cpu_ns: cpu_ns(),
            wall: Instant::now(),
        }
    }
}

/// Initialize clock origins before a VM can execute code.
pub(crate) fn initialize_statistics_origins() -> StatisticsOrigins {
    arinsal_bifs::initialize_time_origin();
    StatisticsOrigins::now()
}

/// Record a collection and acknowledge persistent-term literals this process may hold.
pub(crate) fn after_collection(
    process: &mut Process,
    live_x: usize,
    collections: u64,
    words_reclaimed: u64,
) {
    let flags = runtime_state(process);
    flags.gc_count.fetch_add(collections, Ordering::Relaxed);
    flags.gc_words.fetch_add(words_reclaimed, Ordering::Relaxed);
    snapshot_process(process, live_x);
}

/// Handle one phase of a literal-copy request after earlier signals have drained.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:8128 (`handle_cla`), OTP-29.1.1.
pub(crate) fn copy_literal_area(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    area_id: u64,
    request: Message,
    how: arinsal_sched::LiteralCopyHow,
    requester: arinsal_sched::Pid,
) -> Result<(), VmError> {
    let store = process._persistent_terms.store();
    let area = store.retired_area(&process._persistent_terms, area_id);
    let Some(area) = area else {
        reply_literal_area_copy(ctx, request, requester, atom("ok"))?;
        return Ok(());
    };

    if how == arinsal_sched::LiteralCopyHow::Init {
        // Port of erl_proc_sig_queue.c:8167-8278: earlier queued messages are
        // made self-contained before process-heap references are considered.
        process
            .inbox
            .copy_literal_area_references(&mut process.heap, &area)?;
        // Port of beam_bif_load.c:1012 (erts_check_copy_literals_gc_need), OTP-29.1.1:
        // the heap may be inconsistent while GC is disabled, so do not scan it;
        // the collection is requested and delayed until GC is enabled.
        if !process.heap.gc_enabled {
            reply_literal_area_copy(ctx, request, requester, atom("need_gc"))?;
            return Ok(());
        }
        if literal_scan_words(process) > ctx.remaining() as usize * 512 {
            reply_literal_area_copy(ctx, request, requester, atom("check_gc"))?;
            return Ok(());
        }
        let has_roots = has_literal_area_roots(process, &area);
        if has_roots {
            reply_literal_area_copy(ctx, request, requester, atom("need_gc"))?;
            return Ok(());
        }
        store.acknowledge_copied(&process._persistent_terms, area_id, 0);
    } else {
        // `check_gc` repeats the root scan after signal-queue work; `need_gc`
        // performs the collection requested by the initial signal phase.
        let has_roots =
            how == arinsal_sched::LiteralCopyHow::NeedGc || has_literal_area_roots(process, &area);
        if has_roots {
            // erts_garbage_collect_literals roots `c_p->arg_reg` up to `c_p->arity`, the live
            // X registers of the point where the process switched out (erl_gc.c:1243).
            let live_x = crate::process::switched_out_live(process);
            let hibernated = process.hibernated;
            let copied = rewrite_roots(process, live_x, std::slice::from_ref(&area))?;
            process.heap.request_full_sweep();
            process.force_gc_live(live_x)?;
            if hibernated {
                // Port of erts/emulator/beam/erl_gc.c:1387 (erts_garbage_collect_literals
                // restores the hibernated heap), OTP-29.1.1.
                process.garbage_collect_hibernate(live_x)?;
            }
            store.acknowledge_copied(&process._persistent_terms, area_id, u64::from(copied));
        } else {
            store.acknowledge_copied(&process._persistent_terms, area_id, 0);
        }
    }
    reply_literal_area_copy(ctx, request, requester, atom("ok"))?;
    Ok(())
}

fn has_literal_area_roots(process: &Process, area: &RetiredArea) -> bool {
    let heap = process.heap.has_heap_reference(|term| area.contains(term));
    // Only the live X registers are roots; dead ones may hold stale pointers.
    // Port of erts/emulator/beam/beam_bif_load.c:1100-1106 (`c_p->arg_reg` up to
    // `c_p->arity`), OTP-29.1.1.
    let live = crate::process::switched_out_live(process);
    let roots = process.x[..live]
        .iter()
        .copied()
        .chain((0..process.heap.stack_words()).filter_map(|index| process.heap.stack_get(index)))
        // A finished dirty job's result also waits in those registers in erts.
        .chain(process.dirty_result_roots());
    let mut frag_index = FragmentIndex::default();
    let x_and_stack =
        references_retired_from_roots(process, roots, std::slice::from_ref(area), &mut frag_index);
    let inbox = process.inbox.has_literal_area_reference(area);
    let dictionary = process.dictionary.as_ref().is_some_and(|dictionary| {
        dictionary
            .entries()
            .any(|(key, value)| area.contains(key) || area.contains(value))
    });
    let continuation = process
        .cold
        .as_ref()
        .and_then(|cold| cold.persistent_get_all.as_ref())
        .is_some_and(|state| {
            references_retired(
                process,
                state.result,
                std::slice::from_ref(area),
                &mut frag_index,
            )
        });
    heap || x_and_stack || inbox || dictionary || continuation
}

fn literal_scan_words(process: &Process) -> usize {
    process
        .heap
        .literal_scan_words()
        .saturating_add(process.inbox.literal_scan_words())
        .saturating_add(process.x.len())
        .saturating_add(usize::from(
            process
                .cold
                .as_ref()
                .is_some_and(|cold| cold.persistent_get_all.is_some()),
        ))
        .saturating_add(process.dirty_result_roots().len())
        .saturating_add(
            process
                .dictionary
                .as_ref()
                .map_or(0, |dictionary| dictionary.len() * 2),
        )
}

/// Complete a collector request for a process that has already started exiting.
pub(crate) fn reply_exiting_literal_area(
    _process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    request: Message,
    requester: arinsal_sched::Pid,
) -> Result<(), VmError> {
    reply_literal_area_copy(ctx, request, requester, atom("ok"))
}

/// Complete a request when the target exited before the scheduler accepted its signal.
pub(crate) fn reply_failed_literal_area_request(
    _process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    area: Term,
    how: arinsal_sched::LiteralCopyHow,
    target: arinsal_sched::Pid,
) -> Result<(), VmError> {
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3480-3482
    // (erts_proc_sig_send_cla_request), OTP-29.1.1: the reply goes back to the requester.
    let request = Message::literal_copy_request(area, how, target)?;
    let requester = ctx.pid();
    reply_literal_area_copy(ctx, request, requester, atom("ok"))
}

fn reply_literal_area_copy(
    ctx: &mut RunCtx<'_, Message>,
    request: Message,
    requester: arinsal_sched::Pid,
    result: Term,
) -> Result<(), VmError> {
    // A reply to an exited requester is dropped, like any message to a dead process.
    match ctx.send(requester, request.literal_copy_reply(result)?) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(()),
        Err(error) => Err(VmError::Unsupported(format!(
            "literal-copy response: {error}"
        ))),
    }
}

/// System and persistent-term BIFs this family dispatches.
///
/// `system_info/1` and the `nodes/2` visible-map fast path stay outside the
/// table: those arms return `None` for selectors they do not handle.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("persistent_term", "put", 2),
    ("persistent_term", "put_new", 2),
    ("persistent_term", "get", 0),
    ("persistent_term", "get", 1),
    ("persistent_term", "get", 2),
    ("persistent_term", "erase", 1),
    ("persistent_term", "info", 0),
    ("erts_internal", "erase_persistent_terms", 0),
    ("erts_internal", "no_aux_work_threads", 0),
    ("erlang", "nodes", 0),
    ("erlang", "display", 1),
    ("erlang", "display_string", 2),
    ("erts_internal", "term_to_string", 2),
    // `term_to_string/1` is `term_to_string(T, undefined)` in erts_internal.erl.
    ("erlang", "statistics", 1),
    ("erlang", "bump_reductions", 1),
    ("erts_internal", "garbage_collect", 1),
    ("erlang", "system_flag", 2),
    ("erts_internal", "scheduler_wall_time", 1),
    ("erlang", "dt_spread_tag", 1),
    ("erlang", "dt_restore_tag", 1),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

type Handler =
    fn(&mut Vm, &mut Process, &mut RunCtx<'_, Message>, &[Term]) -> Result<Term, VmError>;

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<Handler> {
    match (module, function, arity) {
        ("erlang", "nodes", 0) => Some(call_nodes0),
        ("erlang", "display", 1) => Some(call_display),
        ("erlang", "display_string", 2) => Some(call_display_string),
        ("erts_internal", "term_to_string", 2) => Some(call_term_to_string),
        ("erlang", "statistics", 1) => Some(call_statistics),
        ("erlang", "bump_reductions", 1) => Some(call_bump_reductions),
        ("erts_internal", "garbage_collect", 1) => Some(call_garbage_collect),
        ("erts_internal", "no_aux_work_threads", 0) => Some(call_no_aux_work_threads),
        ("erlang", "system_flag", 2) => Some(call_system_flag),
        ("erts_internal", "scheduler_wall_time", 1) => Some(call_scheduler_wall_time),
        ("erlang", "dt_spread_tag", 1) => Some(call_dt_spread_tag),
        ("erlang", "dt_restore_tag", 1) => Some(call_dt_restore_tag),
        _ => None,
    }
}

/// Port of erts/emulator/beam/erl_process.c:9234 (no_aux_work_threads/0), OTP-29.1.1.
fn call_no_aux_work_threads(
    _vm: &mut Vm,
    _process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    non_neg(_process, ctx.scheduler_count().saturating_add(1) as u64)
}

fn call_nodes0(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    Ok(Term::NIL)
}

fn call_display(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    display(args[0])
}

fn call_display_string(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    display_string(args).map_err(|error| {
        crate::exceptions::bif_error(process, "erlang", "display_string", args, error)
    })
}

fn call_term_to_string(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    term_to_string(process, args)
}

/// `erlang:statistics/1` for the items that need no scheduler context, called from native code.
/// The others (reductions, run queues, scheduler wall time, microstate accounting) read the
/// scheduler's counters through the executor.
// Port of erts/emulator/beam/erl_bif_info.c (statistics_1, `runtime`, `wall_clock`,
// `garbage_collection`, `io`), OTP-29.1.1.
pub(crate) fn statistics_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [key] = args else {
        return None;
    };
    if !matches!(
        atom_name(*key)?,
        "runtime" | "wall_clock" | "garbage_collection" | "io"
    ) {
        return None;
    }
    statistics(process, None, *key).ok().map(Ok)
}

fn call_statistics(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    statistics(process, Some(ctx), args[0])
}

fn call_bump_reductions(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:5403 (bump_reductions_1), OTP-29.1.1.
    // The BIF consumes at most one scheduler quantum and returns `true`.
    let reductions = args[0]
        .as_small()
        .filter(|value| *value >= 0)
        .ok_or_else(badarg)?;
    let charged = reductions.min(QUANTUM as i64) as u32;
    process.reductions -= charged as i32;
    process.reductions_used = process.reductions_used.saturating_add(u64::from(charged));
    ctx.consume(charged);
    Ok(atom("true"))
}

fn call_garbage_collect(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4077 (erts_internal_garbage_collect_1), OTP-29.1.1:
    // no signal is handled here. The collection itself fetches the outer queue
    // (erl_gc.c:987-990), and literals of an area being released stay referenced until
    // the process handles its copy-literals request (erts_garbage_collect_literals).
    garbage_collect(process, args[0])
}

fn call_system_flag(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    system_flag(vm, process, ctx, args)
}

fn call_scheduler_wall_time(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:5306 (erts_internal_scheduler_wall_time_1), OTP-29.1.1.
    // Any term other than `true` disables accounting. The previous flag is returned.
    set_scheduler_wall_enabled(process, ctx, atom_name(args[0]) == Some("true"))
}

fn call_dt_spread_tag(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:6032 (dt_spread_tag_1), OTP-29.1.1.
    // Without DTrace the BIF checks the boolean and returns `true`.
    if args[0] != atom("true") && args[0] != atom("false") {
        return Err(badarg());
    }
    Ok(atom("true"))
}

fn call_dt_restore_tag(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:6066 (dt_restore_tag_1), OTP-29.1.1.
    // Without DTrace only `true` is accepted, and the BIF returns `true`.
    if args[0] != atom("true") {
        return Err(badarg());
    }
    Ok(atom("true"))
}

pub(super) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        call_values(vm, process, ctx, module, function, values)
    })
}

fn call_values(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let arity = args.len() as u8;
    if module == "persistent_term" && function == "get" && arity == 0 {
        return Some(get_all_step(process, ctx));
    }
    if let Some(bif) = arinsal_pterm::lookup_in(module, function, arity) {
        debug_assert!(
            recognizes(module, function, arity),
            "persistent_term {module}:{function}/{arity} is dispatched but not listed"
        );
        let updating = matches!(
            (module, function, arity),
            ("persistent_term", "put" | "put_new", 2)
                | ("persistent_term", "erase", 1)
                | ("erts_internal", "erase_persistent_terms", 0)
        );
        let store = process._persistent_terms.store();
        if updating {
            // Port of erts/emulator/beam/erl_bif_persistent.c:533-539 (an updater resumes
            // after table_updater ran and returns the result it yielded with), OTP-29.1.1.
            if let Some(result) = process
                .cold
                .as_mut()
                .and_then(|cold| cold.persistent_update_result.take())
            {
                store.release_update_permission(&process._persistent_terms);
                return Some(Ok(result));
            }
            // Port of erts/emulator/beam/erl_bif_persistent.c:692-694 (ERTS_BIF_YIELD when
            // another process holds the update permission), OTP-29.1.1.
            if !store.try_seize_update_permission(&process._persistent_terms) {
                return Some(Err(VmError::Yield));
            }
        }
        let before = PersistentTermUpdate::snapshot(store);
        let result = {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let mut bif_ctx = Ctx::with_fcalls(&mut heap, &mut process.reductions);
            bif(store, &mut bif_ctx, args)
        };
        let published = result.is_ok() && before.published();
        if result.is_ok() {
            before.finish(process, ctx);
        }
        if updating {
            if let (true, Ok(value)) = (published, &result) {
                // Port of erts/emulator/beam/erl_bif_persistent.c:537-539 (suspend_updater
                // and ERTS_BIF_YIELD_RETURN): the updater keeps the permission until it is
                // scheduled again after thread progress.
                process.cold_mut().persistent_update_result = Some(*value);
                return Some(Err(VmError::Yield));
            }
            store.release_update_permission(&process._persistent_terms);
        }
        return Some(result.map_err(|error| {
            crate::exceptions::bif_error(process, module, function, args, error)
        }));
    }
    if let Some(handle) = handler(module, function, arity) {
        return Some(handle(vm, process, ctx, args));
    }
    match (module, function, args.len()) {
        // boot_loop1: rpc and global query peer nodes while this VM is non-distributed.
        // `node::call` handles the general case first; this arm remains for a direct call.
        ("erlang", "nodes", 2)
            if args[0].as_atom().and_then(|atom| global_atoms().text(atom)) == Some("visible")
                && args[1].classify() == TermKind::Map =>
        {
            Some(Ok(Term::NIL))
        }
        // Port of erts/emulator/beam/bif.c:5929-6119 (DTrace BIFs without
        // USE_VM_PROBES), OTP-29.1.1.
        ("erlang", "dt_get_tag" | "dt_get_tag_data", 0) => Some(Ok(atom("undefined"))),
        ("erlang", "dt_put_tag", 1) => Some(Ok(atom("undefined"))),
        ("erlang", "dt_spread_tag", 1) => {
            Some(if args[0] == atom("true") || args[0] == atom("false") {
                Ok(atom("true"))
            } else {
                Err(badarg())
            })
        }
        ("erlang", "dt_restore_tag", 1) => Some(if args[0] == atom("true") {
            Ok(atom("true"))
        } else {
            Err(badarg())
        }),
        ("erlang", "dt_prepend_vm_tag_data" | "dt_append_vm_tag_data", 1) => Some(Ok(args[0])),
        // Port of erts/emulator/beam/dist.c:6670, OTP-29.1.1. Local peers
        // always advertise the Unicode I/O distribution flag.
        ("net_kernel", "dflag_unicode_io", 1) => Some(match args[0].classify() {
            TermKind::Pid if args[0].as_pid().is_some() => Ok(atom("true")),
            TermKind::Pid => Ok(atom("false")),
            _ => Err(badarg()),
        }),
        ("erlang", "system_info", 1) => alloc_info::system_info(vm, process, ctx, args[0])
            .or_else(|| system_info(vm, process, Some(ctx), args[0])),
        _ => None,
    }
}

/// Persistent-term table counters taken before an updating BIF runs.
pub(crate) struct PersistentTermUpdate {
    store: &'static arinsal_pterm::Store,
    updates: u64,
    retired: u64,
}

impl PersistentTermUpdate {
    pub(crate) fn snapshot(store: &'static arinsal_pterm::Store) -> Self {
        Self {
            store,
            updates: store.table_updates(),
            retired: store.retired_generation(),
        }
    }

    /// Whether a table update was published since the snapshot.
    pub(crate) fn published(&self) -> bool {
        self.store.table_updates() != self.updates
    }

    /// Complete an update the way erts' updater does once the new table is published.
    pub(crate) fn finish(self, process: &Process, ctx: &mut RunCtx<'_, Message>) {
        let store = self.store;
        if store.table_updates() != self.updates {
            // Port of erts/emulator/beam/erl_bif_persistent.c:490,535,737 (table updates go
            // through erts_schedule_thr_prgr_later_op(table_updater) and the updater stays
            // suspended until thread progress), OTP-29.1.1. This bounds the update rate the
            // same way and keeps the collector queue as short as in erts.
            ctx.block_thread_progress(std::time::Duration::ZERO);
            // The old table is unreachable once every scheduler has passed a
            // progress point (`get` does not yield). Port of
            // erl_bif_persistent.c:1175 (`table_updater`), OTP-29.1.1.
            store.reclaim_old_tables();
        }
        if store.retired_generation() != self.retired {
            // Port of erts/emulator/beam/beam_bif_load.c:2341 (erts_queue_release_literals),
            // OTP-29.1.1: every queued area sends `copy_literals` to the collector.
            wake_literal_collector(process, ctx);
        }
    }
}

// Port of erts/emulator/beam/beam_bif_load.c:1916 (wake area-switch wait), OTP-29.1.1.
pub(crate) fn wake_literal_collector(process: &Process, ctx: &mut RunCtx<'_, Message>) {
    let store = process._persistent_terms.store();
    if !store.has_retired() {
        return;
    }
    let Some(pid) = process
        .runtime
        .as_ref()
        .and_then(|runtime| *runtime.literal_collector.lock().unwrap())
    else {
        return;
    };
    if let Ok(message) = Message::copy_from(atom("copy_literals")) {
        let _ = ctx.send(pid, message);
    }
}

// Port of erts/emulator/beam/erl_bif_persistent.c:324 (persistent_term_get_0)
// and :831 (do_get_all), OTP-29.1.1.
fn get_all_step(process: &mut Process, ctx: &mut RunCtx<'_, Message>) -> Result<Term, VmError> {
    if process
        .cold
        .as_ref()
        .is_none_or(|cold| cold.persistent_get_all.is_none())
    {
        let snapshot = process._persistent_terms.store().snapshot();
        let remaining = snapshot.len();
        process.cold_mut().persistent_get_all = Some(crate::proc_create::PersistentGetAll {
            snapshot,
            cursor: 0,
            remaining,
            result: Term::NIL,
        });
    }

    // OTP's BIF chunk size is `ERTS_BIF_REDS_LEFT(c_p)`, which is also how
    // `erts_debug:set_internal_state(reds_left, ...)` steers this operation.
    // Keep the scheduler quantum as an upper bound for this Rust call.
    let budget = (process.reductions.max(1) as u32).min(ctx.remaining().max(1)) as usize;
    let mut copied = 0_usize;
    loop {
        let (remaining, next_entry, tail) = process
            .cold
            .as_ref()
            .and_then(|cold| cold.persistent_get_all.as_ref())
            .map(|state| {
                (
                    state.remaining,
                    state.snapshot.entry_from(state.cursor),
                    state.result,
                )
            })
            .ok_or_else(|| VmError::Unsupported("persistent get/0 continuation".into()))?;
        if remaining == 0 || copied >= budget {
            break;
        }
        let (next_cursor, (key, value)) = next_entry
            .ok_or_else(|| VmError::Unsupported("persistent get/0 snapshot entry".into()))?;
        let result = (|| {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let key = copy_term(key, &mut heap).map_err(|_| {
                VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                    "system_limit",
                )))
            })?;
            let pair = TermBuilder::new(&mut heap)
                .tuple(&[key, value])
                .map_err(|_| {
                    VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                        "system_limit",
                    )))
                })?;
            TermBuilder::new(&mut heap).cons(pair, tail).map_err(|_| {
                VmError::Trap(crate::exceptions::Trap::error(crate::signals::atom(
                    "system_limit",
                )))
            })
        })();
        match result {
            Ok(list) => {
                process
                    .cold_mut()
                    .persistent_get_all
                    .as_mut()
                    .expect("persistent get/0 continuation remains live")
                    .result = list;
            }
            Err(error) => {
                process.cold_mut().persistent_get_all = None;
                return Err(error);
            }
        }
        process
            .cold_mut()
            .persistent_get_all
            .as_mut()
            .expect("persistent get/0 continuation remains live")
            .cursor = next_cursor;
        process
            .cold_mut()
            .persistent_get_all
            .as_mut()
            .expect("persistent get/0 continuation remains live")
            .remaining -= 1;
        copied += 1;
    }

    let done = process
        .cold
        .as_ref()
        .and_then(|cold| cold.persistent_get_all.as_ref())
        .is_some_and(|state| state.remaining == 0);
    if done {
        let state = process
            .cold_mut()
            .persistent_get_all
            .take()
            .expect("persistent get/0 continuation remains live");
        Ok(state.result)
    } else {
        ctx.consume(copied as u32);
        Err(VmError::Yield)
    }
}

// Port of erts/emulator/beam/bif.c:4144 (display_1) and :4156
// (erts_internal_term_to_string_2), OTP-29.1.1.
// boot_loop2: init formats fatal boot errors before io_lib is available.
fn display(term: Term) -> Result<Term, VmError> {
    display_match_spec(term)?;
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

pub(crate) fn display_match_spec(term: Term) -> Result<(), VmError> {
    let owned = arinsal_term::to_owned(term).map_err(|_| badarg())?;
    let rendered = print_otp_term(&owned, i32::MAX as usize);
    write!(std::io::stdout().lock(), "{rendered}\r\n")
        .map_err(|error| VmError::Unsupported(format!("display write: {error}")))
}

fn term_to_string(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let limit = if atom_name(args[1]) == Some("undefined") {
        i32::MAX as usize
    } else {
        usize::try_from(args[1].as_small().ok_or_else(badarg)?)
            .ok()
            .filter(|limit| *limit > 1 && *limit < i32::MAX as usize)
            .ok_or_else(badarg)?
    };
    let owned = arinsal_term::to_owned(args[0]).map_err(|_| badarg())?;
    let rendered = print_otp_term(&owned, limit);
    let bytes = rendered
        .bytes()
        .map(|byte| Term::small(i64::from(byte)).unwrap());
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(bytes)
        .map_err(|error| VmError::Unsupported(format!("term_to_string allocation: {error:?}")))
}

pub(crate) fn print_otp_term(term: &arinsal_etf::OwnedTerm, limit: usize) -> String {
    use arinsal_etf::OwnedTerm;

    fn printable_string(items: &[OwnedTerm]) -> Option<String> {
        if items.is_empty() {
            return None;
        }
        let mut text = String::with_capacity(items.len());
        for item in items {
            let OwnedTerm::Int(code) = item else {
                return None;
            };
            let Ok(byte) = u8::try_from(*code) else {
                return None;
            };
            if byte < b' ' && !matches!(byte, b'\n' | b'\r' | b'\t') || byte == 127 {
                return None;
            }
            text.push(char::from(byte));
        }
        Some(text)
    }

    fn render(term: &OwnedTerm, remaining: &mut usize, out: &mut String) -> bool {
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        match term {
            OwnedTerm::Tuple(items) => {
                out.push('{');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    if !render(item, remaining, out) {
                        return false;
                    }
                }
                out.push('}');
            }
            OwnedTerm::List { elems, tail } => {
                if matches!(tail.as_ref(), OwnedTerm::Nil)
                    && let Some(text) = printable_string(elems)
                {
                    out.push('"');
                    for byte in text.bytes() {
                        if *remaining == 0 {
                            return false;
                        }
                        *remaining -= 1;
                        match byte {
                            b'\n' => out.push_str("\\n"),
                            b'"' => out.push_str("\\\""),
                            _ => out.push(char::from(byte)),
                        }
                    }
                    out.push('"');
                } else {
                    out.push('[');
                    for (index, item) in elems.iter().enumerate() {
                        if index > 0 {
                            out.push(',');
                        }
                        if !render(item, remaining, out) {
                            return false;
                        }
                    }
                    if !matches!(tail.as_ref(), OwnedTerm::Nil) {
                        out.push('|');
                        if !render(tail, remaining, out) {
                            return false;
                        }
                    }
                    out.push(']');
                }
            }
            OwnedTerm::Map(pairs) => {
                out.push_str("#{");
                for (index, (key, value)) in pairs.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    if !render(key, remaining, out) {
                        return false;
                    }
                    out.push_str("=>");
                    if !render(value, remaining, out) {
                        return false;
                    }
                }
                out.push('}');
            }
            OwnedTerm::Binary(bytes)
                if !bytes.is_empty() && bytes.iter().all(|byte| (32..127).contains(byte)) =>
            {
                out.push_str("<<\"");
                for byte in bytes {
                    if *remaining == 0 {
                        return false;
                    }
                    *remaining -= 1;
                    if *byte == b'"' {
                        out.push('\\');
                    }
                    out.push(char::from(*byte));
                }
                out.push_str("\">>");
            }
            OwnedTerm::Binary(bytes) => {
                out.push_str("<<");
                for (index, byte) in bytes.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    if *remaining == 0 {
                        return false;
                    }
                    *remaining -= 1;
                    out.push_str(&byte.to_string());
                }
                out.push_str(">>");
            }
            OwnedTerm::Float(value) => {
                let formatted = format!("{value:.6e}");
                let (mantissa, exponent) = formatted.split_once('e').unwrap();
                let exponent = exponent.parse::<i32>().unwrap_or(0);
                out.push_str(&format!("{mantissa}e{exponent:+03}"));
            }
            // Port of erts/emulator/beam/erl_printf_term.c:508-524 (PID_DEF/PORT_DEF), OTP-29.1.1.
            OwnedTerm::Pid {
                node, id, serial, ..
            } => {
                let node = if node == "nonode@nohost" { "0" } else { node };
                out.push_str(&format!("<{node}.{id}.{serial}>"));
            }
            OwnedTerm::Port { node, id, .. } => {
                let node = if node == "nonode@nohost" { "0" } else { node };
                out.push_str(&format!("#Port<{node}.{id}>"));
            }
            OwnedTerm::Atom(name) => {
                out.push_str(&term.to_string());
                *remaining = remaining.saturating_sub(name.len());
                if *remaining == 0 {
                    return false;
                }
            }
            _ => out.push_str(&term.to_string()),
        }
        true
    }

    let mut out = String::new();
    let mut remaining = limit;
    if !render(term, &mut remaining, &mut out) || remaining == 0 {
        out.push_str("... ");
    }
    out
}

// Port of erts/emulator/beam/bif.c:4192 (display_string_2), OTP-29.1.1.
// boot_loop1: logger_simple_h writes directly to stdout after a boot failure.
fn display_string(args: &[Term]) -> Result<Term, arinsal_bifs::BifError> {
    use arinsal_etf::OwnedTerm;

    fn append_string(value: &OwnedTerm, bytes: &mut Vec<u8>) -> Result<(), arinsal_bifs::BifError> {
        match value {
            OwnedTerm::Nil => Ok(()),
            OwnedTerm::List { elems, tail } => {
                for element in elems {
                    append_string(element, bytes)?;
                }
                append_string(tail, bytes)
            }
            OwnedTerm::Int(codepoint) => {
                let c = u32::try_from(*codepoint)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or(arinsal_bifs::BifError::BADARG)?;
                let mut buffer = [0; 4];
                bytes.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                Ok(())
            }
            OwnedTerm::Binary(binary) => {
                bytes.extend_from_slice(binary);
                Ok(())
            }
            _ => Err(arinsal_bifs::BifError::BADARG),
        }
    }

    let destination = args[0]
        .as_atom()
        .and_then(|atom| global_atoms().text(atom))
        .ok_or(arinsal_bifs::BifError::BADARG)?;
    let value = arinsal_term::to_owned(args[1]).map_err(|_| arinsal_bifs::BifError::BADARG)?;
    let mut bytes = Vec::new();
    append_string(&value, &mut bytes)?;
    match destination {
        "stdout" => std::io::stdout().lock().write_all(&bytes),
        "stderr" => std::io::stderr().lock().write_all(&bytes),
        _ => return Err(arinsal_bifs::BifError::BADARG),
    }
    .map_err(|_| arinsal_bifs::BifError::BADARG)?;
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

// boot_loop1: init:has_small_memory/0 probes this before loading kernel modules.
fn system_info(
    vm: &Vm,
    process: &mut Process,
    ctx: Option<&RunCtx<'_, Message>>,
    selector: Term,
) -> Option<Result<Term, VmError>> {
    let owned_selector = arinsal_term::to_owned(selector).ok();
    if let Some(arinsal_etf::OwnedTerm::Tuple(parts)) = owned_selector.as_ref()
        && let [
            arinsal_etf::OwnedTerm::Atom(name),
            arinsal_etf::OwnedTerm::Atom(kind),
        ] = parts.as_slice()
    {
        match (name.as_str(), kind.as_str()) {
            ("wordsize", "internal" | "external") => return Some(Ok(Term::small(8).unwrap())),
            ("wordsize", _) => return Some(Err(badarg())),
            ("cpu_topology", "detected") => return Some(Ok(atom("undefined"))),
            ("cpu_topology", "defined" | "used") => return Some(cpu_topology_info(process)),
            ("cpu_topology", _) => return Some(Err(badarg())),
            // Other two-atom selectors ({allocator, A}, ...) are handled below.
            _ => {}
        }
    }
    if let Some(arinsal_etf::OwnedTerm::Tuple(parts)) = owned_selector.as_ref()
        && let [
            arinsal_etf::OwnedTerm::Atom(operation),
            arinsal_etf::OwnedTerm::Atom(name),
        ] = parts.as_slice()
        && operation == "allocator"
    {
        return Some(allocator_system_info(process, name));
    }
    let name = selector
        .as_atom()
        .and_then(|atom| global_atoms().text(atom));
    match name {
        Some("alloc_util_allocators") => Some(allocator_names(process)),
        Some("allocator") => Some(all_allocator_options(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:2942, OTP-29.1.1.
        Some("process_count") => Some(non_neg(process, process_count(process) as u64)),
        // Port of erts/emulator/beam/erl_bif_info.c:3521, OTP-29.1.1.
        Some("atom_count") => Some(non_neg(process, global_atoms().len() as u64)),
        // Port of erts/emulator/beam/erl_bif_info.c:3518 (atom_limit), OTP-29.1.1.
        Some("atom_limit") => Some(non_neg(process, global_atoms().limit() as u64)),
        // Port of erts/emulator/beam/erl_bif_info.c:3524-3529, OTP-29.1.1.
        Some("tolerant_timeofday") => Some(Ok(atom("disabled"))),
        // Port of erts/emulator/beam/erl_bif_info.c:3515, OTP-29.1.1.
        Some("ets_count") => Some(non_neg(
            process,
            process
                .runtime
                .as_ref()
                .map(|runtime| runtime.ets.read().unwrap().table_count())
                .unwrap_or(0) as u64,
        )),
        // Port of erts/emulator/beam/erl_bif_info.c:2949-2954, OTP-29.1.1.
        Some("info" | "procs" | "loaded" | "dist") => {
            Some(system_info_dump(vm, process, name.unwrap()))
        }
        // Port of erts/emulator/beam/erl_bif_info.c:3547-3548, OTP-29.1.1.
        Some("system_logger") => Some(Ok(system_logger(process))),
        Some("debug_compiled") => Some(Ok(Term::atom(arinsal_term::atoms::FALSE))),
        // Port of erts/emulator/beam/erl_bif_info.c:3448-3449, OTP-29.1.1.
        // Arinsal's loaded BEAM select instructions use the jump-table dispatch path.
        Some("beam_jump_table") => Some(Ok(Term::atom(arinsal_term::atoms::TRUE))),
        // Port of erts/emulator/beam/erl_bif_info.c:3370-3376, OTP-29.1.1.
        Some("lock_checking") => Some(Ok(Term::atom(arinsal_term::atoms::FALSE))),
        // Port of erts/emulator/beam/erl_bif_info.c:2888-2889, OTP-29.1.1.
        Some("ets_always_compress") => Some(Ok(Term::atom(arinsal_term::atoms::FALSE))),
        // Port of erts/emulator/beam/erl_bif_info.c:3412 (taints), OTP-29.1.1.
        Some("taints") => Some(crate::ddll::taint_term(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:3235-3248 (driver_version, nif_version), OTP-29.1.1.
        Some("driver_version") => Some(crate::ddll::text_term(
            process,
            &format!(
                "{}.{}",
                arinsal_drv::layout::ERL_DRV_EXTENDED_MAJOR_VERSION,
                arinsal_drv::layout::ERL_DRV_EXTENDED_MINOR_VERSION
            ),
        )),
        Some("nif_version") => Some(crate::ddll::text_term(process, "2.18")),
        Some("threads") => Some(Ok(Term::atom(arinsal_term::atoms::TRUE))),
        Some("check_io") => Some(check_io_info(process)),
        Some("ethread_info") => Some(ethread_info(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:3549 (max_integer), OTP-29.1.1.
        Some("max_integer") => Some(max_integer(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:3179 (system_info_1), OTP-29.1.1.
        Some("creation") => Some(non_neg(
            process,
            u64::from(crate::node_tables::lock().local_creation),
        )),
        // Port of erts/emulator/beam/erl_bif_info.c:2773 (system_info_1), OTP-29.1.1.
        Some("schedulers_online") => Some(read_flags(process, |process, flags| {
            non_neg(process, flags.schedulers_online as u64)
        })),
        Some("schedulers") => Some(read_flags(process, |process, flags| {
            non_neg(process, flags.schedulers_total as u64)
        })),
        // Port of erts/emulator/beam/erl_bif_info.c:3258-3335 (schedulers_state, schedulers_active),
        // OTP-29.1.1.
        Some("schedulers_active") => {
            Some(non_neg(process, normal_schedulers_active(process) as u64))
        }
        Some("schedulers_state") => {
            let (total, online) = with_flags(process, |flags| {
                (
                    flags.schedulers_total as i64,
                    flags.schedulers_online as i64,
                )
            });
            let active = normal_schedulers_active(process) as i64;
            Some(owned_system_info(
                process,
                arinsal_etf::OwnedTerm::Tuple(vec![
                    arinsal_etf::OwnedTerm::Int(total),
                    arinsal_etf::OwnedTerm::Int(online),
                    arinsal_etf::OwnedTerm::Int(active),
                ]),
            ))
        }
        // Port of erts/emulator/beam/erl_bif_info.c:3338 (run_queues = erts_no_run_queues), OTP-29.1.1:
        // one run queue per scheduler.
        Some("run_queues") => Some(read_flags(process, |process, flags| {
            non_neg(process, flags.schedulers_total as u64)
        })),
        // Port of erts/emulator/beam/erl_bif_info.c:3283-3324 (`all_schedulers_state`), OTP-29.1.1.
        Some("all_schedulers_state") => Some(all_schedulers_state(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:2784 (system_info scheduler_id), OTP-29.1.1.
        Some("scheduler_id") => Some(
            ctx.and_then(RunCtx::scheduler_id)
                .and_then(|id| Term::small(id as i64))
                .ok_or_else(badarg),
        ),
        Some("dirty_cpu_schedulers") => Some(read_flags(process, |process, flags| {
            non_neg(process, flags.dirty_cpu_total as u64)
        })),
        Some("dirty_cpu_schedulers_online") => Some(read_flags(process, |process, flags| {
            non_neg(process, flags.dirty_cpu_online as u64)
        })),
        Some("dirty_io_schedulers") => Some(read_flags(process, |process, flags| {
            non_neg(process, flags.dirty_io_total as u64)
        })),
        // Port of erts/emulator/beam/erl_bif_info.c:3032-3037 (thread_pool_size), OTP-29.1.1.
        Some("thread_pool_size") => Some(read_flags(process, |process, flags| {
            non_neg(process, flags.thread_pool_size as u64)
        })),
        Some("fullsweep_after") => Some(read_flags(process, |process, flags| {
            tagged(process, "fullsweep_after", u64::from(flags.fullsweep_after))
        })),
        // Port of erts/emulator/beam/erl_bif_info.c:2884-2885, OTP-29.1.1.
        Some("trace_control_word") => {
            Some(Term::small(trace_control_word_value(process)).ok_or_else(badarg))
        }
        Some("min_heap_size") => Some(read_flags(process, |process, flags| {
            tagged(process, "min_heap_size", flags.min_heap_size as u64)
        })),
        Some("min_bin_vheap_size") => Some(read_flags(process, |process, flags| {
            tagged(
                process,
                "min_bin_vheap_size",
                flags.min_bin_vheap_size as u64,
            )
        })),
        Some("max_heap_size") => Some(read_flags(process, |process, flags| {
            max_heap_map(process, flags.max_heap)
        })),
        Some("multi_scheduling") => Some(Ok(atom(multi_scheduling_state(process, |state| {
            state.state()
        })))),
        // Port of erts/emulator/beam/erl_bif_info.c:3390 (multi_scheduling_blockers), OTP-29.1.1.
        Some(name @ ("multi_scheduling_blockers" | "normal_multi_scheduling_blockers")) => {
            let normal = name.starts_with("normal");
            let single = with_flags(process, |flags| flags.schedulers_total == 1);
            let blockers = if single {
                Vec::new()
            } else {
                multi_scheduling_state(process, |state| state.blockers(normal))
            };
            let terms = blockers
                .into_iter()
                .filter_map(arinsal_sched::Pid::to_term)
                .collect::<Vec<_>>();
            Some(cons_list(process, &terms))
        }
        Some("cpu_topology") => Some(cpu_topology_info(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:3251 and
        // erts/emulator/beam/erl_cpu_topology.c:662-692, OTP-29.1.1.
        Some("scheduler_bind_type") => {
            let bind_type = arinsal_args::active_scheduler_options()
                .0
                .bind_type
                .unwrap_or_else(|| "u".to_owned());
            let atom_name = match bind_type.as_str() {
                "s" => "spread",
                "ps" => "processor_spread",
                "ts" => "thread_spread",
                "tnnps" => "thread_no_node_processor_spread",
                "nnps" => "no_node_processor_spread",
                "nnts" => "no_node_thread_spread",
                "ns" => "no_spread",
                _ => "unbound",
            };
            Some(Ok(atom(atom_name)))
        }
        Some("scheduler_bindings") => Some(read_flags(process, |process, flags| {
            tuple(process, &vec![atom("unbound"); flags.schedulers_total])
        })),
        // Port of erts/emulator/beam/erl_bif_info.c:3352-3353, OTP-29.1.1.
        Some("port_parallelism") => Some(Ok(atom(
            if arinsal_args::active_scheduler_options()
                .0
                .port_parallelism
                .unwrap_or(false)
            {
                "true"
            } else {
                "false"
            },
        ))),
        Some("sequential_tracer") => Some(crate::seq_trace::system_tracer_info(process)),
        Some("allocated_areas") => Some(memory_areas(vm, process)),
        _ if selector.classify() == TermKind::Tuple => Some(Err(badarg())),
        _ => None,
    }
}

fn allocator_names(process: &mut Process) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;
    // Port of erl_alloc.c:2805. Names are interned from the highest allocator down.
    alloc_atoms::note_alloc_util_allocator_names();
    let names = [
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
    ];
    owned_system_info(
        process,
        O::List {
            elems: names.into_iter().map(|name| O::Atom(name.into())).collect(),
            tail: Box::new(O::Nil),
        },
    )
}

// Port of erts/emulator/beam/erl_bif_info.c:2943 (system_info process_count), OTP-29.1.1.
fn process_count(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
        .map_or(1, |scheduler| scheduler.process_count())
}

fn system_info_dump(vm: &Vm, process: &mut Process, selector: &str) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;

    let dump = match selector {
        "info" => format!("Arinsal emulator\nProcesses: {}\n", process_count(process)),
        "procs" => {
            let Some(runtime) = process.runtime.as_ref() else {
                return owned_system_info(process, O::Binary(Vec::new()));
            };
            let pids = runtime.process_pids();
            let mut dump = String::new();
            for pid in pids {
                use std::fmt::Write as _;
                let _ = writeln!(dump, "{pid:?}");
            }
            dump
        }
        "loaded" => {
            let mut dump = String::new();
            for module in vm.code.modules.iter() {
                use std::fmt::Write as _;
                let _ = writeln!(dump, "{}", module.name);
            }
            dump
        }
        "dist" => {
            let tables = crate::node_tables::lock();
            let mut dump = String::new();
            for entry in tables.entries.values().filter(|entry| entry.connected) {
                use std::fmt::Write as _;
                let _ = writeln!(dump, "{} ({})", entry.name, entry.connection_id);
            }
            dump
        }
        _ => unreachable!("system_info_dump only handles info and procs"),
    };
    owned_system_info(process, O::Binary(dump.into_bytes()))
}

pub(crate) fn system_logger(process: &Process) -> Term {
    let mut current = runtime_state(process)
        .system_logger
        .lock()
        .expect("system logger");
    if let Some(pid) = arinsal_sched::Pid::from_term(*current)
        && process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.scheduler().ok())
            .is_some_and(|scheduler| !scheduler.lookup(pid))
    {
        *current = atom("logger");
    }
    *current
}

// Port of erts/emulator/beam/erl_alloc.c:1708-1840 (handle_args), OTP-29.1.1.
fn allocator_global_settings(
    flags: &[arinsal_args::IgnoredFlag],
) -> (i64, i64, i64, i64, &'static str, i64, u64, bool) {
    let (mut amcbf, mut rmcbf, mut mcs, mut mmap_scs) = (4 * 1024 * 1024, 20, 10, 0);
    let (mut lock_memory, mut ycs, mut mmc, mut sac) = ("no", 1024 * 1024, u64::MAX, true);
    for flag in flags {
        let Some(value) = flag.value.as_deref() else {
            continue;
        };
        let Some(amount) = parse_flag_integer(value) else {
            match flag.name.as_str() {
                "+Mlpm" => lock_memory = if value == "all" { "all" } else { "no" },
                "+Musac" => sac = value == "true",
                _ => {}
            }
            continue;
        };
        match flag.name.as_str() {
            "+MMamcbf" => amcbf = amount.saturating_mul(1024).min(i64::MAX as u64) as i64,
            "+MMrmcbf" => rmcbf = amount.min(i64::MAX as u64) as i64,
            "+MMmcs" => mcs = amount.min(i64::MAX as u64) as i64,
            "+MMscs" => mmap_scs = amount.saturating_mul(1024 * 1024).min(i64::MAX as u64) as i64,
            "+Muycs" => ycs = amount.saturating_mul(1024).min(i64::MAX as u64) as i64,
            "+Mummc" => mmc = amount,
            _ => {}
        }
    }
    (amcbf, rmcbf, mcs, mmap_scs, lock_memory, ycs, mmc, sac)
}

fn allocator_system_info(process: &mut Process, name: &str) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;
    let configured = arinsal_args::active_allocator_options();
    if name == "sys_alloc" {
        alloc_atoms::note_sys_alloc_options();
        return owned_system_info(
            process,
            O::List {
                elems: vec![O::Tuple(vec![
                    O::Atom("instance".into()),
                    O::Int(0),
                    O::List {
                        elems: vec![O::Tuple(vec![
                            O::Atom("options".into()),
                            O::List {
                                elems: vec![
                                    option("e", O::Atom("true".into())),
                                    option("m", O::Atom("libc".into())),
                                ],
                                tail: Box::new(O::Nil),
                            },
                        ])],
                        tail: Box::new(O::Nil),
                    },
                ])],
                tail: Box::new(O::Nil),
            },
        );
    }
    if name == "mseg_alloc" {
        alloc_atoms::note_mseg();
        let schedulers = configured
            .schedulers
            .and_then(|count| usize::try_from(count).ok())
            .filter(|count| *count > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
        let (amcbf, rmcbf, mcs, _, _, _, _, _) = allocator_global_settings(&configured.flags);
        let count = schedulers + 1;
        let instances = (0..count)
            .map(|index| {
                O::Tuple(vec![
                    O::Atom("instance".into()),
                    O::Int(index as i64),
                    O::List {
                        elems: vec![
                            O::Tuple(vec![
                                O::Atom("version".into()),
                                O::List {
                                    elems: "0.9"
                                        .bytes()
                                        .map(|byte| O::Int(i64::from(byte)))
                                        .collect(),
                                    tail: Box::new(O::Nil),
                                },
                            ]),
                            option(
                                "options",
                                O::List {
                                    elems: vec![
                                        option("amcbf", O::Int(amcbf)),
                                        option("rmcbf", O::Int(rmcbf)),
                                        option("mcs", O::Int(mcs)),
                                    ],
                                    tail: Box::new(O::Nil),
                                },
                            ),
                        ],
                        tail: Box::new(O::Nil),
                    },
                ])
            })
            .collect();
        return owned_system_info(
            process,
            O::List {
                elems: instances,
                tail: Box::new(O::Nil),
            },
        );
    }

    let schedulers = configured
        .schedulers
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    let dirty = configured.dirty_instances.unwrap_or(0);
    let Some(mut spec) = default_allocator(name, schedulers) else {
        return Err(badarg());
    };
    apply_allocator_overrides(&mut spec, name, &configured.flags, schedulers);
    if let Some(sbct) = DYN_SBCT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(name)
    {
        spec.sbct = *sbct;
    }
    if !spec.enabled {
        alloc_atoms::note_disabled_allocator(name);
        return owned_system_info(process, O::Atom("false".into()));
    }
    alloc_atoms::note_one_allocator(name);
    let count = if spec.thread_specific {
        schedulers + dirty + 1
    } else {
        1
    };
    let instances = (0..count)
        .map(|index| {
            let global = index == 0;
            let mut entries = Vec::new();
            entries.push(O::Tuple(vec![
                O::Atom("versions".into()),
                O::List {
                    elems: (if (name == "temp_alloc" && global) || spec.shared_profile {
                        "2.1"
                    } else {
                        "0.9"
                    })
                    .bytes()
                    .map(|byte| O::Int(i64::from(byte)))
                    .collect(),
                    tail: Box::new(O::Nil),
                },
                O::List {
                    elems: "3.0".bytes().map(|byte| O::Int(i64::from(byte))).collect(),
                    tail: Box::new(O::Nil),
                },
            ]));
            entries.push(option("options", allocator_options(&spec, global)));
            O::Tuple(vec![
                O::Atom("instance".into()),
                O::Int(index as i64),
                O::List {
                    elems: entries,
                    tail: Box::new(O::Nil),
                },
            ])
        })
        .collect();
    owned_system_info(
        process,
        O::List {
            elems: instances,
            tail: Box::new(O::Nil),
        },
    )
}

fn all_allocator_options(process: &mut Process) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;
    // Port of erl_alloc.c:2902 (erts_allocator_options).
    alloc_atoms::note_allocator_catalog();
    let active = arinsal_args::active_allocator_options();
    let (amcbf, rmcbf, mcs, mmap_scs, lock_memory, ycs, mmc, sac) =
        allocator_global_settings(&active.flags);
    let schedulers = active
        .schedulers
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    let names = [
        "sys_alloc",
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
        "mseg_alloc",
        "sys_aligned_alloc",
        "literal_mmap",
    ];
    let allocators = O::List {
        elems: names.into_iter().map(|name| O::Atom(name.into())).collect(),
        tail: Box::new(O::Nil),
    };
    let mut configured = vec![O::Tuple(vec![
        O::Atom("sys_alloc".into()),
        O::List {
            elems: vec![
                option("e", O::Atom("true".into())),
                option("m", O::Atom("libc".into())),
            ],
            tail: Box::new(O::Nil),
        },
    ])];
    for name in [
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
    ] {
        let Some(mut spec) = default_allocator(name, schedulers) else {
            continue;
        };
        apply_allocator_overrides(&mut spec, name, &active.flags, schedulers);
        configured.push(O::Tuple(vec![
            O::Atom(name.into()),
            allocator_options(&spec, true),
        ]));
    }
    let mut test = default_allocator("test_alloc", schedulers).unwrap();
    apply_allocator_overrides(&mut test, "test_alloc", &active.flags, schedulers);
    configured.push(O::Tuple(vec![
        O::Atom("test_alloc".into()),
        if test.enabled {
            allocator_options(&test, true)
        } else {
            O::List {
                elems: vec![option("e", O::Atom("false".into()))],
                tail: Box::new(O::Nil),
            }
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("mseg_alloc".into()),
        O::List {
            elems: vec![
                option("amcbf", O::Int(amcbf)),
                option("rmcbf", O::Int(rmcbf)),
                option("mcs", O::Int(mcs)),
            ],
            tail: Box::new(O::Nil),
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("alloc_util".into()),
        O::List {
            elems: vec![
                option(
                    "mmc",
                    if mmc <= i64::MAX as u64 {
                        O::Int(mmc as i64)
                    } else {
                        O::BigInt(num_bigint::BigInt::from(mmc))
                    },
                ),
                option("ycs", O::Int(ycs)),
                option("sac", O::Atom(if sac { "true" } else { "false" }.into())),
            ],
            tail: Box::new(O::Nil),
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("erts_mmap".into()),
        O::List {
            elems: vec![option("scs", O::Int(mmap_scs))],
            tail: Box::new(O::Nil),
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("lock_physical_memory".into()),
        O::Atom(lock_memory.into()),
    ]));
    owned_system_info(
        process,
        O::Tuple(vec![
            O::Atom("undefined".into()),
            O::Nil,
            allocators,
            O::List {
                elems: configured,
                tail: Box::new(O::Nil),
            },
        ]),
    )
}

#[derive(Clone, Copy)]
struct AllocatorSystemInfo {
    enabled: bool,
    thread_specific: bool,
    scheduler_divisor: u64,
    shared_profile: bool,
    base_mmbcs: u64,
    base_lmbcs: u64,
    base_smbcs: u64,
    mmbcs_explicit: bool,
    lmbcs_explicit: bool,
    smbcs_explicit: bool,
    atags: u64,
    ramv: bool,
    strategy: &'static str,
    global_strategy: &'static str,
    sbct: u64,
    asbcst: u64,
    rsbcst: u64,
    rsbcmt: u64,
    rmbcmt: u64,
    mmbcs: u64,
    mmmbc: u64,
    mmsbc: u64,
    lmbcs: u64,
    smbcs: u64,
    acul: u64,
    acful: u64,
    acnl: u64,
    acfml: u64,
    mbcgs: u64,
    mbsd: Option<u64>,
    cp: &'static str,
}

// Port of erts/emulator/beam/erl_alloc.c:221-425 (default allocator initializers), OTP-29.1.1.
fn default_allocator(name: &str, schedulers: usize) -> Option<AllocatorSystemInfo> {
    let mbc = (128 * 1024 / schedulers.clamp(1, 4)) as u64;
    let lbc = 5 * 1024 * 1024;
    let sbc = (1024 * 1024 / schedulers.clamp(1, 4)) as u64;
    let mut value = AllocatorSystemInfo {
        enabled: true,
        thread_specific: true,
        scheduler_divisor: schedulers.clamp(1, 4) as u64,
        shared_profile: false,
        base_mmbcs: 0,
        base_lmbcs: 0,
        base_smbcs: 0,
        mmbcs_explicit: false,
        lmbcs_explicit: false,
        smbcs_explicit: false,
        atags: 0,
        ramv: false,
        strategy: "aoffcbf",
        global_strategy: "aoffcbf",
        sbct: 512 * 1024,
        asbcst: 4_145_152,
        rsbcst: 20,
        rsbcmt: 80,
        rmbcmt: 50,
        mmbcs: mbc,
        mmmbc: u64::MAX,
        mmsbc: 256,
        lmbcs: lbc,
        smbcs: sbc,
        acul: 60,
        acful: 0,
        acnl: 1000,
        acfml: 0,
        mbcgs: 10,
        mbsd: None,
        cp: "undefined",
    };
    match name {
        "temp_alloc" => {
            value.strategy = "af";
            value.global_strategy = "gf";
            value.rsbcst = 90;
            value.rmbcmt = 100;
            value.mmbcs = 128 * 1024;
            value.lmbcs = 10 * 1024 * 1024;
            value.smbcs = 1024 * 1024;
            value.acul = 0;
            value.acnl = 0;
            value.mbsd = Some(3);
        }
        "sl_alloc" => {
            value.rsbcst = 80;
            value.rmbcmt = 50;
            value.cp = "S";
        }
        "std_alloc" => {
            value.rsbcst = 20;
            value.cp = "D";
        }
        "ets_alloc" => {
            value.rsbcst = 20;
            value.cp = "E";
        }
        "fix_alloc" => {
            value.rsbcst = 20;
            value.cp = "F";
        }
        "ll_alloc" => {
            value.sbct = u64::MAX;
            value.asbcst = 0;
            value.rsbcst = 0;
            value.rsbcmt = 0;
            value.rmbcmt = 0;
            value.mmbcs = 2 * 1024 * 1024 / schedulers.clamp(1, 4) as u64;
            value.mmsbc = 0;
            value.acul = 85;
            value.cp = "L";
        }
        "eheap_alloc" => {
            value.rsbcst = 50;
            value.mmbcs = 512 * 1024 / schedulers.clamp(1, 4) as u64;
            value.acul = 45;
            value.cp = "H";
        }
        "literal_alloc" => {
            value.thread_specific = false;
            value.strategy = "aobf";
            value.global_strategy = "aobf";
            value.sbct = u64::MAX;
            value.asbcst = 0;
            value.rsbcst = 0;
            value.rsbcmt = 0;
            value.rmbcmt = 0;
            value.mmbcs = 1024 * 1024;
            value.mmsbc = 0;
            value.lmbcs = 10 * 1024 * 1024;
            value.smbcs = 1024 * 1024;
            value.acul = 0;
            value.acnl = 0;
        }
        "binary_alloc" | "driver_alloc" => {
            value.atags = 1;
            value.rsbcst = 20;
            value.rmbcmt = 50;
            value.cp = if name == "binary_alloc" { "B" } else { "R" };
        }
        "test_alloc" => {
            value.enabled = false;
            value.atags = 1;
            value.strategy = "aoffcbf";
            value.global_strategy = "aoffcbf";
            value.sbct = 16 * 1024;
            value.mmbcs = 0;
            value.lmbcs = 8 * 1024;
            value.smbcs = 4 * 1024;
            value.rsbcst = 20;
            value.rsbcmt = 80;
            value.rmbcmt = 50;
            value.acul = 60;
            value.acnl = 1000;
            value.cp = "Z";
        }
        _ => return None,
    }
    value.base_mmbcs = value.mmbcs;
    value.base_lmbcs = value.lmbcs;
    value.base_smbcs = value.smbcs;
    Some(value)
}

// Port of erts/emulator/beam/erl_alloc.c:1283-1554 (handle_au_arg), OTP-29.1.1.
fn apply_allocator_overrides(
    spec: &mut AllocatorSystemInfo,
    name: &str,
    flags: &[arinsal_args::IgnoredFlag],
    schedulers: usize,
) {
    for flag in flags {
        let Some(value) = flag.value.as_deref() else {
            continue;
        };
        let Some(rest) = flag.name.strip_prefix("+M") else {
            continue;
        };
        if rest == "ea" {
            match value {
                "min" | "max" => {
                    if matches!(
                        name,
                        "binary_alloc"
                            | "std_alloc"
                            | "ets_alloc"
                            | "eheap_alloc"
                            | "ll_alloc"
                            | "driver_alloc"
                            | "fix_alloc"
                            | "sl_alloc"
                    ) {
                        spec.enabled = value == "max";
                    }
                }
                "r9c" | "r10b" | "r11b" => apply_allocator_preset(spec, name, value, schedulers),
                _ => {}
            }
            continue;
        }
        let applies = if rest.starts_with('u') {
            matches!(
                name,
                "binary_alloc"
                    | "std_alloc"
                    | "ets_alloc"
                    | "eheap_alloc"
                    | "ll_alloc"
                    | "driver_alloc"
                    | "fix_alloc"
                    | "sl_alloc"
            )
        } else {
            rest.chars().next().is_some_and(|prefix| match prefix {
                'T' => name == "temp_alloc",
                'S' => name == "sl_alloc",
                'D' => name == "std_alloc",
                'L' => name == "ll_alloc",
                'H' => name == "eheap_alloc",
                'E' => name == "ets_alloc",
                'F' => name == "fix_alloc",
                'I' => name == "literal_alloc",
                'B' => name == "binary_alloc",
                'R' => name == "driver_alloc",
                'Z' => name == "test_alloc",
                _ => false,
            })
        };
        if !applies {
            continue;
        }
        let switch = &rest[1..];
        match switch {
            "e" => spec.enabled = value == "true",
            "t" => {
                let was_thread_specific = spec.thread_specific;
                spec.thread_specific = value == "true";
                if value == "false" && was_thread_specific {
                    spec.acul = 0;
                    spec.acful = 0;
                    spec.acnl = 0;
                    if matches!(
                        name,
                        "sl_alloc"
                            | "std_alloc"
                            | "ll_alloc"
                            | "eheap_alloc"
                            | "ets_alloc"
                            | "fix_alloc"
                            | "binary_alloc"
                            | "driver_alloc"
                    ) {
                        if !spec.mmbcs_explicit {
                            spec.mmbcs = spec.mmbcs.saturating_mul(spec.scheduler_divisor);
                        }
                        if !spec.lmbcs_explicit {
                            spec.lmbcs = 10 * 1024 * 1024;
                        }
                        if !spec.smbcs_explicit {
                            spec.smbcs = 1024 * 1024;
                        }
                        spec.global_strategy = "gf";
                        spec.mbsd = Some(3);
                        spec.shared_profile = true;
                    }
                } else if value == "true" && !was_thread_specific && spec.shared_profile {
                    if !spec.mmbcs_explicit {
                        spec.mmbcs = spec.base_mmbcs;
                    }
                    if !spec.lmbcs_explicit {
                        spec.lmbcs = spec.base_lmbcs;
                    }
                    if !spec.smbcs_explicit {
                        spec.smbcs = spec.base_smbcs;
                    }
                }
            }
            "ramv" => spec.ramv = value == "true",
            "atags" => {
                spec.atags = match value {
                    "true" => 1,
                    "code" => 2,
                    _ => 0,
                }
            }
            "sbct" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.sbct = number.saturating_mul(1024)
                }
            }
            "asbcst" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.asbcst = number.saturating_mul(1024)
                }
            }
            "rsbcst" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.rsbcst = number.min(100)
                }
            }
            "rsbcmt" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.rsbcmt = number.min(100)
                }
            }
            "rmbcmt" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.rmbcmt = number.min(100)
                }
            }
            "mmbcs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mmbcs = number.saturating_mul(1024);
                    spec.mmbcs_explicit = true;
                }
            }
            "mmmbc" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mmmbc = number
                }
            }
            "mmsbc" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mmsbc = number
                }
            }
            "lmbcs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.lmbcs = number.saturating_mul(1024);
                    spec.lmbcs_explicit = true;
                }
            }
            "smbcs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.smbcs = number.saturating_mul(1024);
                    spec.smbcs_explicit = true;
                }
            }
            "acul" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acul = number.min(100)
                } else if value == "de" {
                    spec.acul = match name {
                        "ll_alloc" => 85,
                        "eheap_alloc" => 45,
                        _ => 60,
                    }
                }
            }
            "acful" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acful = number.min(100)
                }
            }
            "acnl" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acnl = number
                }
            }
            "acfml" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acfml = number
                }
            }
            "mbcgs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mbcgs = number
                }
            }
            "mbsd" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mbsd = Some(number.max(1))
                }
            }
            "cp" => {
                spec.cp = match value {
                    "B" => "B",
                    "D" => "D",
                    "E" => "E",
                    "F" => "F",
                    "H" => "H",
                    "L" => "L",
                    "R" => "R",
                    "S" => "S",
                    "@" => "@",
                    ":" => ":",
                    _ => spec.cp,
                }
            }
            "as" => {
                let strategy = match value {
                    "bf" => "bf",
                    "aobf" => "aobf",
                    "gf" => "gf",
                    "af" => "af",
                    "aoff" => "aoff",
                    "aoffcbf" => "aoffcbf",
                    "aoffcaobf" => "aoffcaobf",
                    "ageffcaoff" => "ageffcaoff",
                    "ageffcbf" => "ageffcbf",
                    "ageffcaobf" => "ageffcaobf",
                    "chaosff" if name == "test_alloc" => "chaosff",
                    _ => spec.strategy,
                };
                spec.strategy = strategy;
                spec.global_strategy = strategy;
            }
            _ => {}
        }
    }
}

// Port of erts/emulator/beam/erl_alloc.c:1749-1772 (handle_args +Mea), OTP-29.1.1.
fn apply_allocator_preset(
    spec: &mut AllocatorSystemInfo,
    name: &str,
    preset: &str,
    schedulers: usize,
) {
    if !matches!(
        name,
        "binary_alloc"
            | "std_alloc"
            | "ets_alloc"
            | "eheap_alloc"
            | "ll_alloc"
            | "driver_alloc"
            | "fix_alloc"
            | "sl_alloc"
            | "temp_alloc"
    ) {
        return;
    }
    let default_name = if name == "fix_alloc" {
        "driver_alloc"
    } else {
        name
    };
    if let Some(defaults) = default_allocator(default_name, schedulers) {
        *spec = defaults;
    }
    if name != "temp_alloc" {
        spec.thread_specific = false;
        spec.acul = 0;
        spec.acful = 0;
        spec.ramv = false;
        spec.mmbcs = spec.mmbcs.saturating_mul(spec.scheduler_divisor);
        spec.lmbcs = 5 * 1024 * 1024;
        spec.shared_profile = true;
    }
    if name == "driver_alloc"
        || preset == "r9c"
            && matches!(
                name,
                "sl_alloc" | "std_alloc" | "binary_alloc" | "ets_alloc"
            )
    {
        spec.enabled = false;
    }
}

fn parse_flag_integer(value: &str) -> Option<u64> {
    let value = value.trim_start();
    let value = value.strip_prefix('+').unwrap_or(value);
    let digits = value
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0_u64, |number, digit| {
        number.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

fn allocator_options(spec: &AllocatorSystemInfo, global: bool) -> arinsal_etf::OwnedTerm {
    use arinsal_etf::OwnedTerm as O;
    let number = |value: u64| {
        if value <= i64::MAX as u64 {
            O::Int(value as i64)
        } else {
            O::BigInt(num_bigint::BigInt::from(value))
        }
    };
    let bool_atom = |value| O::Atom(if value { "true" } else { "false" }.into());
    let cp = if global || !spec.thread_specific || spec.shared_profile || spec.cp == "undefined" {
        "undefined"
    } else {
        spec.cp
    };
    let mut values = vec![
        option("e", bool_atom(spec.enabled)),
        option("t", bool_atom(spec.thread_specific)),
        option(
            "atags",
            if spec.atags > 1 {
                O::Int(spec.atags as i64)
            } else {
                bool_atom(spec.atags == 1)
            },
        ),
        option("ramv", bool_atom(false)),
        option("sbct", number(spec.sbct)),
        option("asbcst", number(spec.asbcst)),
        option("rsbcst", number(spec.rsbcst)),
        option("rsbcmt", number(spec.rsbcmt)),
        option("rmbcmt", number(spec.rmbcmt)),
        option("mmbcs", number(spec.mmbcs)),
        option("mmmbc", number(spec.mmmbc)),
        option("mmsbc", number(spec.mmsbc)),
        option("lmbcs", number(spec.lmbcs)),
        option("smbcs", number(spec.smbcs)),
        option("mbcgs", O::Int(10)),
        option("acful", O::Int(0)),
        option("acul", number(if global { 0 } else { spec.acul })),
        option("acnl", number(if global { 0 } else { spec.acnl })),
        option("acfml", O::Int(0)),
        option("cp", O::Atom(cp.into())),
    ];
    if let Some(mbsd) = spec.mbsd
        && (global || spec.shared_profile)
    {
        values.push(option("mbsd", number(mbsd)));
    }
    values.push(option(
        "as",
        O::Atom(
            if global || spec.shared_profile {
                spec.global_strategy
            } else {
                spec.strategy
            }
            .into(),
        ),
    ));
    O::List {
        elems: values,
        tail: Box::new(O::Nil),
    }
}

fn option(name: &str, value: arinsal_etf::OwnedTerm) -> arinsal_etf::OwnedTerm {
    arinsal_etf::OwnedTerm::Tuple(vec![arinsal_etf::OwnedTerm::Atom(name.into()), value])
}

fn owned_system_info(
    process: &mut Process,
    value: arinsal_etf::OwnedTerm,
) -> Result<Term, VmError> {
    arinsal_term::from_owned(
        &value,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|_| badarg())
}

fn max_integer(process: &mut Process) -> Result<Term, VmError> {
    const MAX_BIG_BITS: usize = 65_535 * 64;
    let value = (num_bigint::BigInt::from(1_u8) << MAX_BIG_BITS) - 1;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .int_from_bigint(&value)
        .map_err(|_| badarg())
}

// Port of erts/emulator/beam/erl_bif_info.c:5487 (erts_get_ethread_info), OTP-29.1.1.
fn ethread_info(process: &mut Process) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;

    fn list(items: Vec<O>) -> O {
        O::List {
            elems: items,
            tail: Box::new(O::Nil),
        }
    }
    fn string(value: &str) -> O {
        list(value.bytes().map(|byte| O::Int(i64::from(byte))).collect())
    }
    fn atomic_entry(label: &str, width: &str, name: &str, operations: &[&str]) -> O {
        O::Tuple(vec![
            string(label),
            string(name),
            list(
                operations
                    .iter()
                    .map(|operation| string(&format!("ethr_native_atomic{width}_{operation}()")))
                    .collect(),
            ),
        ])
    }

    let bit_ops = [
        "or_retold_relb",
        "or_retold_acqb",
        "or_retold",
        "and_retold_relb",
        "and_retold_acqb",
        "and_retold",
        "read_acqb",
        "read",
        "add_return_relb",
        "add_return_acqb",
        "add_return",
        "set_relb",
        "set",
        "cmpxchg_acqb",
        "cmpxchg",
    ];
    let double_word_ops = [
        "read_acqb",
        "read",
        "set_relb",
        "set",
        "cmpxchg_acqb",
        "cmpxchg",
    ];
    let entries = vec![
        atomic_entry(
            "32-bit native atomics",
            "32",
            "gcc_atomic_and_sync_builtins",
            &bit_ops,
        ),
        atomic_entry(
            "64-bit native atomics",
            "64",
            "gcc_atomic_and_sync_builtins",
            &bit_ops,
        ),
        O::Tuple(vec![
            string("Double word native atomics"),
            string("gcc_atomic_and_sync_builtins"),
            list(
                double_word_ops
                    .iter()
                    .map(|operation| string(&format!("ethr_native_su_dw_atomic_{operation}()")))
                    .collect(),
            ),
        ]),
        O::Tuple(vec![string("Native spinlocks"), string("native-atomics")]),
        O::Tuple(vec![
            string("Native rw-spinlocks"),
            string("native-atomics"),
        ]),
    ];
    arinsal_term::from_owned(
        &list(entries),
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .map_err(|error| VmError::Unsupported(format!("ethread_info result: {error:?}")))
}

fn memory_areas(vm: &Vm, process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_info.c:2773 (allocated_areas selector), OTP-29.1.1.
    alloc_atoms::note_allocated_areas();
    // `erlang:memory/0` already sampled process and atom bytes into the allocator
    // reply (`std_alloc`). A second sample sees the heap grow while those replies
    // are built, and `system = total - processes` then drops below atom+code.
    let sampled = take_memory_sample();
    if sampled.is_none() {
        snapshot_process(process, process.gc_live);
    }
    let values = memory_values(vm, process);
    let value = |name: &str| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    };
    let (_, persistent) = process._persistent_terms.store().info();
    let external_bytes = persistent as u64;
    let external_size = non_neg(process, external_bytes)?;
    let external = tuple(process, &[atom("external_alloc"), external_size])?;
    let (atom_bytes, atom_used_bytes, process_bytes) =
        sampled.unwrap_or((value("atom"), value("atom_used"), value("processes")));
    let allocated_atoms = non_neg(process, atom_bytes)?;
    let used_atoms = non_neg(process, atom_used_bytes)?;
    let atoms = tuple(process, &[atom("atom_space"), allocated_atoms, used_atoms])?;
    let processes = non_neg(process, process_bytes)?;
    let processes = tuple(process, &[atom("process_table"), processes])?;
    let ets_size = non_neg(process, value("ets"))?;
    let ets = tuple(process, &[atom("ets_misc"), ets_size])?;
    let code_size = non_neg(process, value("code"))?;
    let code = tuple(process, &[atom("loaded_code"), code_size])?;
    let areas = [external, atoms, processes, ets, code];
    cons_list(process, &areas)
}

pub(crate) fn memory_values(vm: &Vm, process: &Process) -> [(&'static str, u64); 9] {
    let store = process._persistent_terms.store();
    let (processes, processes_used, _) = store.process_memory_totals();
    // Port of erts/emulator/beam/erl_bif_info.c:4459 (erts_memory) and erl_alloc.c:2495,
    // OTP-29.1.1: binary memory is global allocator usage, independent of process ownership.
    let binary = arinsal_term::binary_memory_bytes();
    let (atom, atom_used) = atom_bytes();
    let code = code_bytes(vm);
    let ets = ets_bytes(process);
    let (_, persistent) = store.info();
    let system = atom
        .saturating_add(binary)
        .saturating_add(code)
        .saturating_add(ets)
        .saturating_add(persistent as u64);
    let total = processes.saturating_add(system);
    [
        ("total", total),
        ("processes", processes),
        ("processes_used", processes_used),
        ("system", system),
        ("atom", atom),
        ("atom_used", atom_used),
        ("binary", binary),
        ("code", code),
        ("ets", ets),
    ]
}

thread_local! {
    /// `(atom, atom_used, processes)` from the `memory_internal` half of `erlang:memory/0`.
    static MEMORY_SAMPLE: Cell<Option<(u64, u64, u64)>> = const { Cell::new(None) };
}

/// Keep the `memory_internal` sizes for the following `allocated_areas` call.
pub(super) fn freeze_memory_sample(atom: u64, atom_used: u64, processes: u64) {
    MEMORY_SAMPLE.set(Some((atom, atom_used, processes)));
}

/// Take the sample captured by [`freeze_memory_sample`], if this thread has one.
pub(super) fn take_memory_sample() -> Option<(u64, u64, u64)> {
    MEMORY_SAMPLE.replace(None)
}

pub(crate) fn snapshot_process(process: &mut Process, _live_x: usize) {
    let word = std::mem::size_of::<usize>();
    let extra = std::mem::size_of::<Process>() + process.x.len() * word + process.fr.len() * word;
    let capacity = process
        .heap
        .total_heap_size_words()
        .saturating_mul(word)
        .saturating_add(extra) as u64;
    // Port of erts/emulator/beam/erl_alloc.c:2190-2303 (memory category reporting), OTP-29.1.1:
    // ERTS accounts process heap blocks, including each block's unused tail.
    let used = capacity;
    process._persistent_terms.store().set_process_memory(
        &process._persistent_terms,
        capacity,
        used,
        process.heap.off_heap_binary_bytes(),
    );
}

fn code_bytes(vm: &Vm) -> u64 {
    vm.code
        .modules
        .iter()
        .map(|module| {
            let code = std::mem::size_of_val(module.code.as_ref());
            let generic = std::mem::size_of_val(module.generic.as_slice());
            let names: usize = module.functions.iter().map(|(_, name, _)| name.len()).sum();
            (code + generic + module.strings.len() + names + module.name.len()) as u64
        })
        .sum()
}

fn ets_bytes(process: &Process) -> u64 {
    let Some(runtime) = &process.runtime else {
        return 0;
    };
    let registry = runtime.ets.read().expect("ets registry");
    let words: usize = registry
        .all()
        .into_iter()
        .map(|id| {
            registry
                .get(id)
                .map(|table| table.memory_words())
                .unwrap_or(0)
        })
        .sum();
    words as u64 * std::mem::size_of::<usize>() as u64
}

fn atom_bytes() -> (u64, u64) {
    let count = global_atoms().len();
    let predefined = arinsal_term::atoms::PREDEFINED;
    let text: usize = predefined.iter().map(|name| name.len()).sum();
    let extra = count.saturating_sub(predefined.len()).saturating_mul(8);
    let entries = count.saturating_mul(std::mem::size_of::<usize>() * 6);
    let used = (text + extra + entries) as u64;
    let allocated = used.saturating_add((count as u64).saturating_mul(16));
    (allocated, used.min(allocated))
}

fn statistics(
    process: &mut Process,
    ctx: Option<&mut RunCtx<'_, Message>>,
    key: Term,
) -> Result<Term, VmError> {
    let Some(name) = atom_name(key) else {
        return Err(badarg());
    };
    match name {
        "runtime" => {
            let flags = runtime_state(process);
            let (total, delta) = since(runtime_ms(flags), &flags.last_runtime_ms);
            pair(process, total, delta)
        }
        "wall_clock" => {
            let flags = runtime_state(process);
            let (total, delta) = since(wall_ms(flags), &flags.last_wall_ms);
            pair(process, total, delta)
        }
        "reductions" => {
            let flags = runtime_state(process);
            let (total, delta) = since(reduction_total(ctx.as_deref()), &flags.last_reductions);
            pair(process, total, delta)
        }
        "exact_reductions" => {
            let flags = runtime_state(process);
            let (total, delta) = since(
                reduction_total(ctx.as_deref()),
                &flags.last_exact_reductions,
            );
            pair(process, total, delta)
        }
        "context_switches" => {
            let total =
                scheduler_stats(process, ctx.as_deref()).map_or(0, |stats| stats.context_switches);
            let flags = runtime_state(process);
            let (_, delta) = since(total, &flags.last_context_switches);
            pair(process, total, delta)
        }
        "garbage_collection" => triple(
            process,
            runtime_state(process).gc_count.load(Ordering::Relaxed),
            runtime_state(process).gc_words.load(Ordering::Relaxed),
            0,
        ),
        "io" => io_counters(process),
        "run_queue" => non_neg(
            process,
            queue_counts(process, ctx.as_deref(), false, false)
                .iter()
                .sum(),
        ),
        "total_run_queue_lengths" | "total_run_queue_lengths_all" => {
            let all = name == "total_run_queue_lengths_all";
            non_neg(
                process,
                queue_counts(process, ctx.as_deref(), false, all)
                    .iter()
                    .sum(),
            )
        }
        "run_queue_lengths" | "run_queue_lengths_all" => {
            let all = name == "run_queue_lengths_all";
            int_list(process, &queue_counts(process, ctx.as_deref(), false, all))
        }
        "active_tasks" | "active_tasks_all" => {
            let all = name == "active_tasks_all";
            int_list(process, &queue_counts(process, ctx.as_deref(), true, all))
        }
        "total_active_tasks" | "total_active_tasks_all" => {
            let all = name == "total_active_tasks_all";
            non_neg(
                process,
                queue_counts(process, ctx.as_deref(), true, all)
                    .iter()
                    .sum(),
            )
        }
        "run_queues" => int_tuple(process, &queue_counts(process, ctx.as_deref(), false, true)),
        "scheduler_wall_time" => scheduler_wall(process, ctx.as_deref(), false),
        "scheduler_wall_time_all" => scheduler_wall(process, ctx.as_deref(), true),
        "microstate_accounting" => microstate(process, ctx),
        _ => Err(badarg()),
    }
}

fn system_flag(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4972 (system_flag_2), OTP-29.1.1.
    let Some(name) = atom_name(args[0]) else {
        return Err(badarg());
    };
    match name {
        "multi_scheduling" => multi_scheduling(process, ctx, args[1]),
        "schedulers_online" => schedulers_online(process, ctx, args[1], false),
        "dirty_cpu_schedulers_online" => schedulers_online(process, ctx, args[1], true),
        "fullsweep_after" => fullsweep_after(process, args[1]),
        "min_heap_size" => heap_minimum(process, args[1], true),
        "min_bin_vheap_size" => heap_minimum(process, args[1], false),
        "max_heap_size" => max_heap_flag(process, args[1]),
        "debug_flags" => Ok(atom("true")),
        "backtrace_depth" => backtrace_depth(vm, process, args[1]),
        "trace_control_word" => trace_control_word(process, args[1]),
        "sequential_tracer" => crate::seq_trace::set_system_tracer(vm, process, args[1]),
        "reset_seq_trace" => {
            crate::seq_trace::clear_all();
            Ok(atom("true"))
        }
        "scheduler_wall_time" => set_scheduler_wall(process, ctx, args[1]),
        "microstate_accounting" => set_microstate(process, ctx, args[1]),
        "outstanding_system_requests_limit" => outstanding_limit(process, args[1]),
        "scheduling_statistics" => scheduling_statistics(args[1]),
        "time_offset" if atom_name(args[1]) == Some("finalize") => Ok(atom("final")),
        "scheduler_bind_type" => {
            // Port of erts/emulator/beam/bif.c:5284 and
            // erts/emulator/beam/erl_cpu_topology.c:714, OTP-29.1.1.
            warn_deprecated_scheduler_bind(process, ctx);
            if args[1] == atom("unbound") {
                Ok(atom("unbound"))
            } else {
                Err(bif_error(process, "system_flag", args, "notsup"))
            }
        }
        "cpu_topology" => {
            // Port of erts/emulator/beam/bif.c:5276 and
            // erts/emulator/beam/erl_cpu_topology.c:1348, OTP-29.1.1.
            warn_deprecated_cpu_topology(process, ctx);
            set_cpu_topology(process, args[1], "set_cpu_topology")
        }
        "internal_cpu_topology" => {
            // Port of erts/emulator/beam/bif.c:5272 and
            // erts/emulator/beam/erl_cpu_topology.c:1348, OTP-29.1.1.
            set_cpu_topology(process, args[1], "system_flag")
        }
        "erts_alloc" => erts_alloc_flag(process, args[1]),
        "system_logger" => set_system_logger(process, args[1]),
        _ => Err(badarg()),
    }
}

// Port of erts/emulator/beam/erl_cpu_topology.c:1348 (`erts_set_cpu_topology`), OTP-29.1.1.
fn cpu_topology_info(process: &mut Process) -> Result<Term, VmError> {
    let current = runtime_state(process)
        .cpu_topology
        .lock()
        .expect("CPU topology state")
        .clone();
    match current {
        Some(topology) => arinsal_term::from_owned(
            &topology,
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        )
        .map_err(|_| badarg()),
        None => Ok(atom("undefined")),
    }
}

fn set_cpu_topology(
    process: &mut Process,
    value: Term,
    error_function: &str,
) -> Result<Term, VmError> {
    let new = if value == atom("undefined") {
        None
    } else {
        let owned = arinsal_term::to_owned(value)
            .map_err(|_| bif_error_for(process, error_function, &[value], "badarg"))?;
        if !valid_cpu_topology(&owned) {
            return Err(bif_error_for(process, error_function, &[value], "badarg"));
        }
        Some(canonical_cpu_topology(owned))
    };
    let mut current = runtime_state(process)
        .cpu_topology
        .lock()
        .expect("CPU topology state");
    let previous = current.clone();
    *current = new;
    drop(current);
    match previous {
        Some(topology) => {
            let term = arinsal_term::from_owned(
                &topology,
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .map_err(|_| badarg())?;
            Ok(term)
        }
        None => Ok(atom("undefined")),
    }
}

// The Erlang wrapper accepts the historical {Tag, [], Children} spelling and
// formats singleton core/thread levels away after assigning their implicit id 0.
fn canonical_cpu_topology(topology: arinsal_etf::OwnedTerm) -> arinsal_etf::OwnedTerm {
    use arinsal_etf::OwnedTerm as O;

    fn node(term: &O) -> O {
        let O::Tuple(fields) = term else {
            return term.clone();
        };
        let (tag, child) = match fields.as_slice() {
            [O::Atom(tag), child] => (tag.as_str(), child),
            [O::Atom(tag), O::Nil, child] => (tag.as_str(), child),
            _ => return term.clone(),
        };
        let children = match child {
            O::List { elems, tail } if matches!(tail.as_ref(), O::Nil) => O::List {
                elems: elems.iter().map(node).collect(),
                tail: Box::new(O::Nil),
            },
            child => node(child),
        };
        let children = match &children {
            O::Tuple(fields) if matches!(fields.first(), Some(O::Atom(name)) if name == "core" || name == "thread") => {
                fields.get(1).cloned().unwrap_or(O::Nil)
            }
            O::List { elems, tail } if elems.len() == 1 && matches!(tail.as_ref(), O::Nil) => {
                match &elems[0] {
                    O::Tuple(fields) if matches!(fields.first(), Some(O::Atom(name)) if name == "core" || name == "thread") => {
                        fields.get(1).cloned().unwrap_or(O::Nil)
                    }
                    _ => O::List {
                        elems: elems.clone(),
                        tail: tail.clone(),
                    },
                }
            }
            _ => children,
        };
        O::Tuple(vec![O::Atom(tag.into()), children])
    }

    match &topology {
        O::List { elems, tail } => O::List {
            elems: elems.iter().map(node).collect(),
            tail: tail.clone(),
        },
        _ => topology,
    }
}

fn valid_cpu_topology(topology: &arinsal_etf::OwnedTerm) -> bool {
    use arinsal_etf::OwnedTerm;

    let OwnedTerm::List { elems, tail } = topology else {
        return false;
    };
    if !matches!(tail.as_ref(), OwnedTerm::Nil) || elems.is_empty() {
        return false;
    }
    fn visit(node: &OwnedTerm, parent: &str, logical_ids: &mut HashSet<i64>) -> bool {
        let OwnedTerm::Tuple(fields) = node else {
            return false;
        };
        let (tag, child) = match fields.as_slice() {
            [OwnedTerm::Atom(tag), child] => (tag.as_str(), child),
            [OwnedTerm::Atom(tag), OwnedTerm::Nil, child] => (tag.as_str(), child),
            _ => return false,
        };
        let allowed = matches!(
            (parent, tag),
            ("root", "node" | "processor" | "core" | "thread")
                | ("node", "processor" | "core" | "thread" | "logical")
                | ("processor", "node" | "core" | "thread" | "logical")
                | ("core", "thread" | "logical")
                | ("thread", "logical")
        );
        if !allowed {
            return false;
        }
        if tag == "logical" {
            let OwnedTerm::Int(id) = child else {
                return false;
            };
            return (0..65_536).contains(id) && logical_ids.insert(*id);
        }
        let mut children = Vec::new();
        match child {
            OwnedTerm::List { elems, tail } if matches!(tail.as_ref(), OwnedTerm::Nil) => {
                children.extend(elems);
            }
            _ => children.push(child),
        }
        let sibling_tag = children.first().and_then(|child| match child {
            OwnedTerm::Tuple(fields) => fields.first().and_then(|tag| match tag {
                OwnedTerm::Atom(tag) => Some(tag.as_str()),
                _ => None,
            }),
            _ => None,
        });
        !children.is_empty()
            && sibling_tag.is_some()
            && children
                .into_iter()
                .all(|child| {
                    let same_tag = match &child {
                        OwnedTerm::Tuple(fields) => matches!(fields.first(), Some(OwnedTerm::Atom(child_tag)) if Some(child_tag.as_str()) == sibling_tag),
                        _ => false,
                    };
                    same_tag && visit(child, tag, logical_ids)
                })
    }
    let mut logical_ids = HashSet::new();
    elems
        .iter()
        .all(|node| visit(node, "root", &mut logical_ids))
        && !logical_ids.is_empty()
}

/// Build OTP's test reader-group assignment for the currently defined topology.
// Port of erts/emulator/beam/erl_cpu_topology.c:1834-1848 and :1918-2256, OTP-29.1.1.
pub(crate) fn reader_groups_map(process: &mut Process, groups: i64) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;

    if groups <= 0 {
        return Err(badarg());
    }
    let topology = runtime_state(process)
        .cpu_topology
        .lock()
        .expect("CPU topology state")
        .clone();
    let Some(O::List { elems, tail }) = topology.as_ref() else {
        return Ok(Term::NIL);
    };
    if !matches!(tail.as_ref(), O::Nil) {
        return Ok(Term::NIL);
    }

    // The group builder only needs the ordered hierarchy levels associated with
    // each logical processor. The synthetic ids preserve sibling boundaries.
    #[derive(Clone, Copy)]
    struct Cpu {
        level: [i32; 6],
    }
    fn visit(term: &O, parent: [i32; 6], parent_tag: &str, rows: &mut Vec<Cpu>) -> bool {
        let O::Tuple(fields) = term else { return false };
        let (tag, child) = match fields.as_slice() {
            [O::Atom(tag), child] => (tag.as_str(), child),
            [O::Atom(tag), O::Nil, child] => (tag.as_str(), child),
            _ => return false,
        };
        let rank = match tag {
            "node" => 0,
            "processor" => 1,
            "core" => 3,
            "thread" => 4,
            "logical" => 5,
            _ => return false,
        };
        let allowed = matches!(
            (parent_tag, tag),
            ("root", "node" | "processor" | "core" | "thread")
                | ("node", "processor" | "core" | "thread" | "logical")
                | ("processor", "node" | "core" | "thread" | "logical")
                | ("core", "thread" | "logical")
                | ("thread", "logical")
        );
        if !allowed {
            return false;
        }
        if rank == 5 {
            let O::Int(id) = child else { return false };
            let Ok(id) = i32::try_from(*id) else {
                return false;
            };
            let mut level = parent;
            level[5] = id;
            if level[1] < 0 {
                level[1] = 0;
            }
            if level[3] < 0 {
                level[3] = 0;
            }
            if level[4] < 0 {
                level[4] = 0;
            }
            rows.push(Cpu { level });
            return true;
        }
        let mut level = parent;
        let field = if rank == 0 && parent_tag == "processor" {
            2
        } else {
            rank as usize
        };
        level[field] = parent[field].max(0);
        if field == 2 {
            level[0] = parent[0];
        }
        let children = match child {
            O::List { elems, tail } if matches!(tail.as_ref(), O::Nil) => elems.clone(),
            other => vec![other.clone()],
        };
        if children.is_empty() {
            return false;
        }
        let sibling_tag = children.first().and_then(|child| match child {
            O::Tuple(fields) => fields.first().and_then(|tag| match tag {
                O::Atom(tag) => Some(tag.clone()),
                _ => None,
            }),
            _ => None,
        });
        if sibling_tag.is_none() {
            return false;
        }
        for (next, child) in children.into_iter().enumerate() {
            let O::Tuple(fields) = &child else {
                return false;
            };
            let child_tag = match fields.first() {
                Some(O::Atom(tag)) => tag.as_str(),
                _ => return false,
            };
            if sibling_tag.as_deref() != Some(child_tag) {
                return false;
            }
            let child_rank = match child_tag {
                "node" => 0,
                "processor" => 1,
                "core" => 3,
                "thread" => 4,
                "logical" => 5,
                _ => return false,
            };
            let target_field = if child_rank == 0 && rank == 1 {
                2
            } else {
                child_rank as usize
            };
            let mut child_parent = level;
            child_parent[target_field] = i32::try_from(next).unwrap_or(i32::MAX);
            if !visit(&child, child_parent, tag, rows) {
                return false;
            }
        }
        true
    }

    let mut rows = Vec::new();
    let root = [-1; 6];
    let mut root_ids = [0_i32; 6];
    for term in elems {
        let O::Tuple(fields) = term else {
            return Err(badarg());
        };
        let tag = match fields.first() {
            Some(O::Atom(tag)) => tag.as_str(),
            _ => return Err(badarg()),
        };
        let field = match tag {
            "node" => 0,
            "processor" => 1,
            "core" => 3,
            "thread" => 4,
            _ => return Err(badarg()),
        };
        let mut parent = root;
        parent[field] = root_ids[field];
        root_ids[field] += 1;
        if !visit(term, parent, "root", &mut rows) {
            return Err(badarg());
        }
    }
    if rows.is_empty() {
        return Ok(Term::NIL);
    }

    // Port of make_available_cpu_topology: count changes at each level.
    let mut counts = [-1_i32; 6];
    let mut previous = [-2_i32; 6];
    for row in &mut rows {
        let raw_levels = row.level;
        let mut changed_at = 5;
        for level in 0..5 {
            if previous[level] != raw_levels[level] {
                changed_at = level;
                break;
            }
        }
        for count in counts.iter_mut().skip(changed_at) {
            *count += 1;
        }
        row.level[..5].copy_from_slice(&counts[..5]);
        previous = raw_levels;
    }
    let mut no = counts;
    for count in &mut no {
        *count += 1;
    }

    // Port of erts/emulator/beam/erl_cpu_topology.c:2087-2256 (make_cpu_groups_map,
    // sub_levels, write_cpu_groups), OTP-29.1.1.
    let groups = groups as usize;
    let spread = (0..4)
        .find(|&level| no[level] as usize > groups)
        .unwrap_or(3);
    let mut assigned = vec![0_i32; rows.len()];
    if no[spread] as usize <= groups {
        let mut cg = -1;
        let mut last = -1;
        for (ix, row) in rows.iter().enumerate() {
            if last != row.level[spread] {
                cg += 1;
                last = row.level[spread];
            }
            assigned[ix] = cg;
        }
    } else {
        // (id, sub_levels, cpu_groups); `tl` is the level above the spread level, -1 for none.
        let tl = spread as isize - 1;
        let toplevels = if spread == 0 {
            1
        } else {
            no[spread - 1] as usize
        };
        let mut counts: Vec<(i32, usize, usize)> = Vec::with_capacity(toplevels);
        if toplevels == 1 {
            counts.push((0, no[spread] as usize, groups));
        } else {
            let tl = tl as usize;
            let mut cgs = groups;
            let cgs_per_tl = cgs / toplevels;
            let mut a = 0;
            for _ in 0..toplevels {
                let id = rows[a].level[tl];
                let mut last = -1;
                let mut sub = 0;
                loop {
                    if last != rows[a].level[spread] {
                        sub += 1;
                        last = rows[a].level[spread];
                    }
                    a += 1;
                    if !(a < rows.len() && id == rows[a].level[tl]) {
                        break;
                    }
                }
                counts.push((id, sub, 0));
            }
            counts.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
            for entry in &mut counts {
                if entry.1 < cgs_per_tl {
                    entry.2 = entry.1;
                    cgs -= entry.1;
                } else {
                    entry.2 = cgs_per_tl;
                    cgs -= cgs_per_tl;
                }
            }
            while cgs > 0 {
                let mut progressed = false;
                for entry in &mut counts {
                    if entry.1 == entry.2 {
                        break;
                    }
                    entry.2 += 1;
                    progressed = true;
                    cgs -= 1;
                    if cgs == 0 {
                        break;
                    }
                }
                // The C loop spins forever here; no group can be placed, so it is badarg.
                if !progressed {
                    return Err(badarg());
                }
            }
            counts.sort_by_key(|entry| entry.0);
        }
        let mut a = 0;
        let mut cg = -1_i32;
        let mut ix = 0;
        while a < rows.len() {
            let (id, sub_levels, cpu_groups) = counts[ix];
            // The C code divides by zero when fewer groups than top levels were requested.
            let (Some(per_group), Some(xsl)) = (
                sub_levels.checked_div(cpu_groups),
                sub_levels.checked_rem(cpu_groups),
            ) else {
                return Err(badarg());
            };
            let xsl_cg_lim = (cpu_groups - xsl) as i32 + cg + 1;
            let mut sls = 0;
            let mut last = -1;
            loop {
                if last != rows[a].level[spread] {
                    if sls == 0 {
                        sls = per_group;
                        cg += 1;
                        if cg >= xsl_cg_lim {
                            sls += 1;
                        }
                    }
                    last = rows[a].level[spread];
                    sls -= 1;
                }
                assigned[a] = cg;
                a += 1;
                if !(a < rows.len() && (tl < 0 || rows[a].level[tl as usize] == id)) {
                    break;
                }
            }
            ix += 1;
        }
    }
    let mut pairs = rows
        .iter()
        .zip(assigned)
        .map(|(row, group)| (row.level[5], group))
        .collect::<Vec<_>>();
    pairs.sort_unstable_by_key(|(logical, _)| *logical);
    owned_system_info(
        process,
        O::List {
            elems: pairs
                .into_iter()
                .map(|(logical, group)| {
                    O::Tuple(vec![O::Int(logical.into()), O::Int(i64::from(group + 1))])
                })
                .collect(),
            tail: Box::new(O::Nil),
        },
    )
}

// Port of erts/emulator/beam/utils.c:919 (`send_warning_to_logger`) and :802
// (`do_send_logger_message`), OTP-29.1.1.
fn send_deprecation_warning(process: &mut Process, ctx: &mut RunCtx<'_, Message>, text: &str) {
    let logger = process.runtime.as_ref().and_then(|runtime| {
        runtime
            .reg
            .whereis_proc_str("logger")
            .or_else(|| runtime.reg.whereis_proc_str("error_logger"))
    });
    let Some(logger) = logger else {
        eprintln!("{text}");
        return;
    };
    let pid = ctx.pid().to_term().unwrap_or(Term::NIL);
    let group_leader = process
        .group_leader
        .and_then(|leader| leader.to_term())
        .unwrap_or(Term::NIL);
    let timestamp = runtime_state(process)
        .wall_origin
        .elapsed()
        .as_micros()
        .try_into()
        .unwrap_or(i64::MAX);
    let event = (|| -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let warning = builder.string_to_list(text).map_err(|_| badarg())?;
        let format = builder.string_to_list("~s~n").map_err(|_| badarg())?;
        let args = builder.list_from_iter([warning]).map_err(|_| badarg())?;
        let error_logger = builder
            .flatmap_from_pairs(&[
                (atom("emulator"), atom("true")),
                (atom("tag"), atom("warning_msg")),
            ])
            .map_err(|_| badarg())?;
        let metadata = builder
            .flatmap_from_pairs(&[
                (atom("error_logger"), error_logger),
                (atom("gl"), group_leader),
                (atom("pid"), pid),
                (atom("time"), Term::small(timestamp).ok_or_else(badarg)?),
            ])
            .map_err(|_| badarg())?;
        builder
            .tuple(&[atom("log"), atom("warning"), format, args, metadata])
            .map_err(|_| badarg())
    })();
    if let Ok(event) = event
        && let Ok(message) = Message::copy_from(event)
    {
        let _ = ctx.send(logger, message);
    }
}

fn warn_deprecated_scheduler_bind(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    send_deprecation_warning(
        process,
        ctx,
        "A call to erlang:system_flag(scheduler_bind_type, _) was\nmade. The scheduler_bind_type argument is deprecated and\nscheduled for removal in Erlang/OTP 18. For more\ninformation see the erlang:system_flag/2 documentation.\n",
    );
}

fn warn_deprecated_cpu_topology(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    send_deprecation_warning(
        process,
        ctx,
        "A call to erlang:system_flag(cpu_topology, _) was made.\nThe cpu_topology argument is deprecated and scheduled\nfor removal in Erlang/OTP 18. For more information\nsee the erlang:system_flag/2 documentation.\n",
    );
}

fn bif_error_for(_process: &mut Process, function: &str, args: &[Term], reason: &str) -> VmError {
    let mut trap = crate::exceptions::Trap::error(atom(reason));
    trap.top = Some(crate::stacktrace::TopFrame::Bif {
        module: global_atoms().intern("erlang").expect("built-in atom"),
        function: global_atoms().intern(function).expect("system BIF atom"),
        args: match crate::stacktrace::BifArgs::from_terms(args) {
            Ok(args) => args,
            Err(error) => return error,
        },
        info: crate::stacktrace::BifErrorInfo::Plain,
    });
    VmError::Trap(trap)
}

fn bif_error(process: &mut Process, function: &str, args: &[Term], reason: &str) -> VmError {
    bif_error_for(process, function, args, reason)
}

// Port of erts/emulator/beam/erl_alloc.c:3445 (`erts_alloc_set_dyn_param`), OTP-29.1.1.
fn erts_alloc_flag(process: &mut Process, value: Term) -> Result<Term, VmError> {
    let owned = arinsal_term::to_owned(value).map_err(|_| {
        bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        )
    })?;
    let arinsal_etf::OwnedTerm::Tuple(ref items) = owned else {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    };
    let [
        arinsal_etf::OwnedTerm::Atom(allocator),
        arinsal_etf::OwnedTerm::Atom(parameter),
        integer,
    ] = items.as_slice()
    else {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    };
    let amount = match integer {
        arinsal_etf::OwnedTerm::Int(amount) => u64::try_from(*amount).ok(),
        arinsal_etf::OwnedTerm::BigInt(amount) => num_traits::ToPrimitive::to_u64(amount),
        _ => None,
    };
    let Some(amount) = amount else {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    };
    const ALLOCATORS: &[&str] = &[
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
        "sys_alloc",
        "test_alloc",
    ];
    if !ALLOCATORS.contains(&allocator.as_str()) {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    }
    // Only alloc_util allocators accept dynamic parameters, and only `sbct`.
    // Port of erts/emulator/beam/erl_alloc.c:3445 (`erts_alloc_set_dyn_param`), OTP-29.1.1.
    let schedulers = std::thread::available_parallelism().map_or(1, usize::from);
    let configured = arinsal_args::active_allocator_options();
    let enabled = default_allocator(allocator, schedulers).is_some_and(|mut spec| {
        apply_allocator_overrides(&mut spec, allocator, &configured.flags, schedulers);
        spec.enabled
    });
    if !enabled || parameter != "sbct" {
        return Ok(atom("notsup"));
    }
    let accepted = usize::try_from(amount)
        .ok()
        .and_then(|amount| arinsal_alloc::typed::try_set_dyn_sbct(allocator, amount));
    if accepted != Some(true) {
        return Ok(atom("notsup"));
    }
    DYN_SBCT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(allocator.clone(), amount);
    Ok(atom("ok"))
}

/// Dynamic `sbct` values set through `system_flag(erts_alloc, ...)`, by allocator name.
static DYN_SBCT: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
    std::sync::LazyLock::new(Default::default);

pub(crate) fn set_system_logger(process: &Process, value: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_trace.c:2486, OTP-29.1.1.
    if value != atom("logger") && value != atom("undefined") && value.as_pid().is_none() {
        return Err(badarg());
    }
    let mut current = runtime_state(process)
        .system_logger
        .lock()
        .expect("system logger");
    Ok(std::mem::replace(&mut *current, value))
}

fn set_scheduler_wall(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    value: Term,
) -> Result<Term, VmError> {
    let enable = match atom_name(value) {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(badarg()),
    };
    set_scheduler_wall_enabled(process, ctx, enable)
}

fn set_scheduler_wall_enabled(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    enable: bool,
) -> Result<Term, VmError> {
    let mut state = runtime_state(process)
        .sched_wall
        .lock()
        .expect("scheduler wall time");
    let previous = state.is_some();
    if enable && state.is_none() {
        *state = Some(SchedBase {
            started: Instant::now(),
            active_ns: Vec::new(),
        });
    } else if !enable {
        *state = None;
    }
    drop(state);
    set_runtime_accounting(process, ctx);
    if enable && !previous {
        let active_ns = scheduler_stats(process, Some(ctx))
            .map_or_else(Vec::new, |stats| all_active_ns(&stats));
        runtime_state(process)
            .sched_wall
            .lock()
            .expect("scheduler wall time")
            .as_mut()
            .unwrap()
            .active_ns = active_ns;
    }
    Ok(atom(if previous { "true" } else { "false" }))
}

fn set_runtime_accounting(process: &Process, ctx: &mut RunCtx<'_, Message>) {
    let enabled = runtime_state(process)
        .sched_wall
        .lock()
        .expect("scheduler wall time")
        .is_some();
    if let Some(scheduler) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
    {
        scheduler.set_accounting_enabled(enabled);
    }
    ctx.set_wall_accounting_enabled(enabled);
}

/// Statistics counters and bookkeeping of one runtime; erts keeps them in emulator globals.
pub(crate) struct StatisticsState {
    pub(crate) last_reductions: AtomicU64,
    pub(crate) last_exact_reductions: AtomicU64,
    pub(crate) last_context_switches: AtomicU64,
    pub(crate) gc_count: AtomicU64,
    pub(crate) gc_words: AtomicU64,
    last_runtime_ms: AtomicU64,
    last_wall_ms: AtomicU64,
    cpu_origin_ns: u64,
    wall_origin: Instant,
    microstate: AtomicBool,
    cpu_topology: Mutex<Option<arinsal_etf::OwnedTerm>>,
    sched_wall: Mutex<Option<SchedBase>>,
    microstate_base: Mutex<Option<MicrostateBaseline>>,
    system_logger: Mutex<Term>,
}

/// `erlang:system_flag/2` state of one runtime.
#[derive(Clone)]
pub(crate) struct SystemFlags {
    fullsweep_after: u16,
    min_heap_size: i64,
    min_bin_vheap_size: i64,
    thread_pool_size: usize,
    max_heap: crate::process::MaxHeap,
    schedulers_online: usize,
    schedulers_total: usize,
    dirty_cpu_online: usize,
    dirty_cpu_total: usize,
    dirty_io_total: usize,
    trace_word: i64,
    outstanding: u64,
}

impl StatisticsState {
    pub(crate) fn new(origins: StatisticsOrigins) -> Self {
        Self {
            last_reductions: AtomicU64::new(0),
            last_exact_reductions: AtomicU64::new(0),
            last_context_switches: AtomicU64::new(0),
            gc_count: AtomicU64::new(0),
            gc_words: AtomicU64::new(0),
            last_runtime_ms: AtomicU64::new(0),
            last_wall_ms: AtomicU64::new(0),
            cpu_origin_ns: origins.cpu_ns,
            wall_origin: origins.wall,
            microstate: AtomicBool::new(false),
            cpu_topology: Mutex::new(None),
            sched_wall: Mutex::new(None),
            microstate_base: Mutex::new(None),
            system_logger: Mutex::new(atom("logger")),
        }
    }
}

fn runtime_state(process: &Process) -> &StatisticsState {
    static UNATTACHED: OnceLock<StatisticsState> = OnceLock::new();
    process
        .runtime
        .as_ref()
        .map(|runtime| &runtime.statistics)
        .unwrap_or_else(|| {
            UNATTACHED.get_or_init(|| StatisticsState::new(StatisticsOrigins::now()))
        })
}

pub(crate) struct GcSpawnDefaults {
    pub(crate) fullsweep_after: u16,
    pub(crate) max_heap_size: crate::process::MaxHeap,
    pub(crate) min_bin_vheap_size: i64,
}

pub(crate) fn gc_spawn_defaults(runtime: Option<&crate::process::Runtime>) -> GcSpawnDefaults {
    with_runtime_flags(runtime, |flags| GcSpawnDefaults {
        fullsweep_after: flags.fullsweep_after,
        max_heap_size: flags.max_heap,
        min_bin_vheap_size: flags.min_bin_vheap_size,
    })
}

pub(crate) fn multi_scheduling_blocked(process: &Process) -> bool {
    multi_scheduling_state(process, crate::process::MultiScheduling::any_blocked)
}

fn multi_scheduling_state<T>(
    process: &Process,
    body: impl FnOnce(&crate::process::MultiScheduling) -> T,
) -> T {
    match process.runtime.as_ref() {
        Some(runtime) => body(&runtime.multi_scheduling.lock().unwrap()),
        None => body(&crate::process::MultiScheduling::default()),
    }
}

pub(crate) fn normalize_spawn_heap_minimum(
    runtime: Option<&crate::process::Runtime>,
    requested: Option<usize>,
    binary: bool,
) -> usize {
    with_runtime_flags(runtime, |flags| {
        let minimum = if binary {
            flags.min_bin_vheap_size
        } else {
            flags.min_heap_size
        } as usize;
        match requested {
            Some(size) if size > minimum => {
                next_heap_size(i64::try_from(size).unwrap_or(i64::MAX)) as usize
            }
            _ => minimum,
        }
    })
}

/// `erlang:system_info(schedulers)` at boot: the scheduler count `driver_system_info` reports.
pub(crate) fn schedulers_total() -> usize {
    SystemFlags::boot().schedulers_total
}

impl SystemFlags {
    /// Values a runtime boots with, from the command line and the environment.
    pub(crate) fn boot() -> Self {
        static BOOT: OnceLock<SystemFlags> = OnceLock::new();
        BOOT.get_or_init(|| {
            let cpus = logical_processors();
            let emulator = arinsal_args::active_emulator_flags();
            let (
                schedulers_total,
                schedulers_online,
                dirty_cpu_total,
                dirty_cpu_online,
                dirty_io_total,
            ) = boot_scheduler_counts_from(cpus, &emulator);
            SystemFlags {
                // Port of erl_init.c:1328-1332 (`ERL_FULLSWEEP_AFTER`), OTP-29.1.1.
                fullsweep_after: std::env::var("ERL_FULLSWEEP_AFTER")
                    .ok()
                    .map(|value| value.trim().parse::<i64>().unwrap_or(0) as u16)
                    .unwrap_or(u16::MAX),
                // Port of erts/emulator/beam/erl_init.c:1556-1562 (+hms), OTP-29.1.1.
                min_heap_size: emulator
                    .min_heap_size
                    .map(|words| next_heap_size(i64::try_from(words).unwrap_or(i64::MAX)))
                    .unwrap_or(233),
                min_bin_vheap_size: 46_422,
                // Port of erts/emulator/beam/erl_init.c:1162-1163 (+A zero clamp), OTP-29.1.1.
                thread_pool_size: emulator.async_threads.unwrap_or(1).max(1) as usize,
                max_heap: crate::process::MaxHeap::default(),
                schedulers_online,
                schedulers_total,
                dirty_cpu_online,
                dirty_cpu_total,
                dirty_io_total,
                trace_word: 0,
                outstanding: (cpus as u64).saturating_mul(2),
            }
        })
        .clone()
    }
}

/// erts keeps these flags in the emulator's globals; every runtime is a separate emulator
/// here, and several runtimes can share one OS process.
fn with_flags<T>(process: &Process, body: impl FnOnce(&mut SystemFlags) -> T) -> T {
    with_runtime_flags(process.runtime.as_deref(), body)
}

/// A snapshot of the flags for code that allocates on `process` while reading them.
fn read_flags<T>(process: &mut Process, body: impl FnOnce(&mut Process, &SystemFlags) -> T) -> T {
    let flags = with_flags(process, |flags| flags.clone());
    body(process, &flags)
}

/// Flags of `runtime`; an unscheduled evaluation without a runtime sees the boot values
/// and its changes are dropped.
pub(crate) fn with_runtime_flags<T>(
    runtime: Option<&crate::process::Runtime>,
    body: impl FnOnce(&mut SystemFlags) -> T,
) -> T {
    match runtime {
        Some(runtime) => body(&mut runtime.system_flags.lock().expect("system flags")),
        None => body(&mut SystemFlags::boot()),
    }
}

/// Dirty CPU total and online, and dirty I/O scheduler counts chosen at boot.
pub(crate) fn dirty_scheduler_defaults(runtime: &crate::process::Runtime) -> (usize, usize, usize) {
    with_runtime_flags(Some(runtime), |flags| {
        (
            flags.dirty_cpu_total,
            flags.dirty_cpu_online,
            flags.dirty_io_total,
        )
    })
}

pub(crate) fn scheduler_online_default(runtime: &crate::process::Runtime) -> usize {
    with_runtime_flags(Some(runtime), |flags| flags.schedulers_online)
}

#[cfg(test)]
fn boot_scheduler_counts(cpus: usize) -> (usize, usize, usize, usize, usize) {
    boot_scheduler_counts_from(cpus, &arinsal_args::EmulatorFlags::default())
}

// Port of erts/emulator/beam/erl_init.c:851-867, 951-1140, 1193-1210, OTP-29.1.1.
fn boot_scheduler_counts_from(
    cpus: usize,
    emulator: &arinsal_args::EmulatorFlags,
) -> (usize, usize, usize, usize, usize) {
    let schedulers =
        arinsal_args::resolve_scheduler_count(emulator.schedulers, cpus).unwrap_or((cpus, cpus));
    let dirty_cpu = arinsal_args::resolve_scheduler_count(emulator.dirty_cpu_schedulers, cpus)
        .unwrap_or((cpus, cpus));
    // Port of erts/emulator/beam/erl_init.c:867 (dirty_io_scheds = 10), OTP-29.1.1.
    let dirty_io = emulator
        .dirty_io_schedulers
        .map_or(10, |count| count as usize);
    let schedulers = (
        schedulers.0.max(1),
        schedulers.1.clamp(1, schedulers.0.max(1)),
    );
    // Port of erts/emulator/beam/erl_init.c:1193-1200, OTP-29.1.1: dirty CPU schedulers
    // never outnumber the normal schedulers.
    let dirty_total = dirty_cpu.0.clamp(1, schedulers.0);
    let dirty_cpu = (
        dirty_total,
        dirty_cpu.1.clamp(1, dirty_total).min(schedulers.1),
    );
    (
        schedulers.0,
        schedulers.1,
        dirty_cpu.0,
        dirty_cpu.1,
        dirty_io.max(1),
    )
}

#[cfg(test)]
fn parse_scheduler_pair(value: &str, cpus: usize) -> Option<(usize, usize)> {
    let (total, online) = value
        .split_once(':')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    arinsal_args::resolve_scheduler_count(
        Some(arinsal_args::SchedulerCount {
            total: total.parse().ok()?,
            online: online.map(str::parse).transpose().ok()?,
        }),
        cpus,
    )
}

// Port of erts/emulator/beam/erl_gc.c:265 (heap size table) and :311
// (erts_next_heap_size), OTP-29.1.1.
fn next_heap_size(size: i64) -> i64 {
    static SIZES: OnceLock<Vec<i64>> = OnceLock::new();
    let sizes = SIZES.get_or_init(|| {
        let mut sizes = Vec::with_capacity(154);
        sizes.push(12);
        sizes.push(38);
        for index in 2..23 {
            let next = sizes[index - 1] + sizes[index - 2] + 1;
            sizes.push(next);
        }
        let max = (1i64 << 53) / 8;
        while sizes.len() < 154 {
            let prev = *sizes.last().unwrap();
            let next = prev + prev / 5;
            if next <= prev || next > max {
                break;
            }
            sizes.push(next);
        }
        sizes
    });
    if size < sizes[0] {
        return sizes[0];
    }
    match sizes.binary_search(&size) {
        Ok(index) => sizes[index],
        Err(index) => sizes.get(index).copied().unwrap_or(*sizes.last().unwrap()),
    }
}

fn multi_scheduling(
    process: &mut Process,
    ctx: &RunCtx<'_, Message>,
    value: Term,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_process.c:8484 (erts_block_multi_scheduling), OTP-29.1.1.
    let action = match atom_name(value) {
        Some("block") => crate::process::MsbChange::Block { normal: false },
        Some("unblock") => crate::process::MsbChange::Unblock { normal: false },
        Some("block_normal") => crate::process::MsbChange::Block { normal: true },
        Some("unblock_normal") => crate::process::MsbChange::Unblock { normal: true },
        _ => return Err(badarg()),
    };
    let pid = ctx.pid();
    // An unscheduled evaluation has no runtime and no other scheduler to block.
    let Some(runtime) = process.runtime.clone() else {
        let mut state = crate::process::MultiScheduling::default();
        state.change(pid, action);
        return Ok(atom(state.state()));
    };
    let mut state = runtime.multi_scheduling.lock().unwrap();
    if state.change(pid, action) {
        // erts F_HAVE_BLCKD_MSCHED / F_HAVE_BLCKD_NMSCHED: released when this process exits.
        process.cold_mut().have_blocked_multi_scheduling = true;
    }
    if let Ok(scheduler) = runtime.scheduler() {
        scheduler.set_scheduling_blocked(state.any_blocked(), ctx.worker_id());
    }
    Ok(atom(state.state()))
}

/// Release every multi-scheduling block `process` still holds.
///
/// Port of erts/emulator/beam/erl_process.c:14318-14353 (erts_continue_exit_process,
/// ERTS_CONTINUE_EXIT_BLCKD_MSHED / _NMSHED), OTP-29.1.1.
pub(crate) fn release_multi_scheduling_blocks(process: &mut Process, pid: arinsal_sched::Pid) {
    let Some(cold) = process.cold.as_mut() else {
        return;
    };
    if !std::mem::take(&mut cold.have_blocked_multi_scheduling) {
        return;
    }
    let Some(runtime) = process.runtime.as_ref() else {
        return;
    };
    let mut state = runtime.multi_scheduling.lock().unwrap();
    state.release(pid);
    if !state.any_blocked()
        && let Ok(scheduler) = runtime.scheduler()
    {
        scheduler.set_scheduling_blocked(false, None);
    }
}

fn schedulers_online(
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    value: Term,
    dirty: bool,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_process.c:8228 (erts_set_schedulers_online), OTP-29.1.1.
    let requested = value.as_small().ok_or_else(badarg)?;
    with_flags(process, |flags| {
        // Port of erts/emulator/beam/bif.c:5015 and :5178
        // (system_flag_2 scheduler controls), OTP-29.1.1.
        // Normal schedulers bound the number of dirty CPU schedulers online.
        let previous = if dirty {
            if requested < 1
                || requested as usize > flags.dirty_cpu_total
                || requested as usize > flags.schedulers_online
            {
                return Err(badarg());
            }
            let previous = flags.dirty_cpu_online;
            flags.dirty_cpu_online = requested as usize;
            previous
        } else {
            if requested < 1 || requested as usize > flags.schedulers_total {
                return Err(badarg());
            }
            let previous = flags.schedulers_online;
            // A full stats snapshot rendezvouses with every worker. Calling it
            // from a running worker waits on that same worker forever; the
            // scheduler setter validates its configured capacity directly.
            if requested as usize != previous
                && let Some(scheduler) = process
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.scheduler().ok())
                && !scheduler
                    .set_online_schedulers((requested as usize).min(scheduler.worker_count()))
            {
                return Err(badarg());
            }
            // Port of erts/emulator/beam/erl_process.c:8316-8321
            // (erts_set_schedulers_online), OTP-29.1.1: dirty CPU schedulers
            // online follow the normal-scheduler change proportionally.
            let total_pct = flags.dirty_cpu_total * 100 / flags.schedulers_total;
            let onln_pct = requested as usize * total_pct / previous;
            flags.dirty_cpu_online = (flags.dirty_cpu_online * onln_pct / 100).max(1);
            flags.schedulers_online = requested as usize;
            previous
        };
        // Port of erts/emulator/beam/erl_process.c:7266 (dirty CPU schedulers online), OTP-29.1.1.
        if let Some(scheduler) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.scheduler().ok())
        {
            scheduler.set_dirty_cpu_online(flags.dirty_cpu_online);
            if !dirty && multi_scheduling_state(process, |state| state.any_blocked()) {
                // Port of erts/emulator/beam/erl_process.c:8316-8321
                // (`erts_set_schedulers_online`), OTP-29.1.1: keep the blocking
                // scheduler online so the suspended caller can be resumed.
                let caller = ctx
                    .worker_id()
                    .filter(|worker| *worker < flags.schedulers_online)
                    .unwrap_or(0);
                scheduler.set_scheduling_blocked(true, Some(caller));
            }
        }
        Term::small(previous as i64).ok_or_else(badarg)
    })
}

fn fullsweep_after(process: &Process, value: Term) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n >= 0).ok_or_else(badarg)?;
    let stored = u16::try_from(requested).unwrap_or(u16::MAX);
    with_flags(process, |flags| {
        let previous = flags.fullsweep_after;
        flags.fullsweep_after = stored;
        Ok(Term::small(i64::from(previous)).unwrap())
    })
}

fn heap_minimum(process: &Process, value: Term, heap: bool) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n >= 0).ok_or_else(badarg)?;
    let rounded = next_heap_size(requested);
    with_flags(process, |flags| {
        let slot = if heap {
            &mut flags.min_heap_size
        } else {
            &mut flags.min_bin_vheap_size
        };
        let previous = *slot;
        *slot = rounded;
        Term::small(previous).ok_or_else(badarg)
    })
}

fn backtrace_depth(vm: &mut Vm, process: &Process, value: Term) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n >= 0).ok_or_else(badarg)?;
    let requested = (requested as usize).min(64);
    let previous = process
        .runtime
        .as_ref()
        .map_or(vm.backtrace_depth, |runtime| {
            runtime.backtrace_depth.swap(requested, Ordering::AcqRel)
        });
    vm.backtrace_depth = requested;
    Term::small(previous as i64).ok_or_else(badarg)
}

fn trace_control_word(process: &Process, value: Term) -> Result<Term, VmError> {
    let requested = value
        .as_small()
        .filter(|value| (0..=i64::from(u32::MAX)).contains(value))
        .ok_or_else(badarg)?;
    with_flags(process, |flags| {
        let previous = flags.trace_word;
        flags.trace_word = requested;
        Term::small(previous).ok_or_else(badarg)
    })
}

pub(crate) fn trace_control_word_value(process: &Process) -> i64 {
    with_flags(process, |flags| flags.trace_word)
}

pub(crate) fn set_trace_control_word_value(process: &Process, value: i64) {
    with_flags(process, |flags| flags.trace_word = value);
}

fn outstanding_limit(process: &Process, value: Term) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n > 0).ok_or_else(badarg)?;
    with_flags(process, |flags| {
        let previous = flags.outstanding;
        flags.outstanding = requested as u64;
        Term::small(i64::try_from(previous).unwrap_or(i64::MAX)).ok_or_else(badarg)
    })
}

fn scheduling_statistics(value: Term) -> Result<Term, VmError> {
    match atom_name(value) {
        Some("enable" | "disable" | "clear") => Ok(atom("true")),
        _ => Err(badarg()),
    }
}

fn max_heap_flag(process: &mut Process, value: Term) -> Result<Term, VmError> {
    let parsed = parse_system_max_heap(process, value)?;
    let previous = with_flags(process, |flags| {
        let old = flags.max_heap;
        if parsed.size < flags.min_heap_size as u64 && parsed.size != 0 {
            return Err(badarg());
        }
        flags.max_heap = parsed;
        Ok(old)
    })?;
    max_heap_map(process, previous)
}

/// The current system-wide max_heap_size flags: erts parses every max_heap_size value starting from them
/// (erts/emulator/beam/erl_process.c erts_max_heap_size: `*max_heap_flags = H_MAX_FLAGS`), OTP-29.1.1.
pub(crate) fn system_max_heap(
    runtime: Option<&crate::process::Runtime>,
) -> crate::process::MaxHeap {
    crate::process::MaxHeap {
        reported: false,
        ..with_runtime_flags(runtime, |flags| flags.max_heap)
    }
}

fn parse_system_max_heap(
    process: &Process,
    value: Term,
) -> Result<crate::process::MaxHeap, VmError> {
    let mut limit = crate::process::MaxHeap {
        size: 0,
        ..system_max_heap(process.runtime.as_deref())
    };
    if let Some(size) = value.as_small() {
        if size < 0 {
            return Err(badarg());
        }
        limit.size = size as u64;
        return Ok(limit);
    }
    if value.classify() != TermKind::Map {
        return Err(badarg());
    }
    // SAFETY: The flag map stays rooted in the caller's registers.
    let map = unsafe { value.flatmap_ref() }.ok_or_else(badarg)?;
    let size = map
        .get(atom("size"))
        .and_then(|term| term.as_small())
        .filter(|size| *size >= 0)
        .ok_or_else(badarg)?;
    limit.size = size as u64;
    let boolean = |key: &str| -> Result<Option<bool>, VmError> {
        match map.get(atom(key)) {
            None => Ok(None),
            Some(term) if term == atom("true") => Ok(Some(true)),
            Some(term) if term == atom("false") => Ok(Some(false)),
            Some(_) => Err(badarg()),
        }
    };
    if let Some(kill) = boolean("kill")? {
        limit.kill = kill;
    }
    if let Some(log) = boolean("error_logger")? {
        limit.log = log;
    }
    if let Some(include) = boolean("include_shared_binaries")? {
        limit.include_shared_binaries = include;
    }
    Ok(limit)
}

fn max_heap_map(process: &mut Process, limit: crate::process::MaxHeap) -> Result<Term, VmError> {
    let size = Term::small(i64::try_from(limit.size).map_err(|_| badarg())?).ok_or_else(badarg)?;
    let pairs = [
        (
            atom("error_logger"),
            atom(if limit.log { "true" } else { "false" }),
        ),
        (
            atom("include_shared_binaries"),
            atom(if limit.include_shared_binaries {
                "true"
            } else {
                "false"
            }),
        ),
        (
            atom("kill"),
            atom(if limit.kill { "true" } else { "false" }),
        ),
        (atom("size"), size),
    ];
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&pairs)
        .map_err(|error| VmError::Unsupported(format!("max_heap_size map: {error:?}")))
}

// Port of erts/emulator/beam/erl_msacc.c:329 (microstate accounting actions), OTP-29.1.1.
fn set_microstate(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    value: Term,
) -> Result<Term, VmError> {
    let previous = runtime_state(process).microstate.load(Ordering::Relaxed);
    match atom_name(value) {
        Some("true") => {
            runtime_state(process)
                .microstate
                .store(true, Ordering::Relaxed);
            set_microstate_workers(process, true);
            ctx.set_msacc_accounting_enabled(true);
            ctx.set_msacc_state(arinsal_sched::MsaccState::Emulator);
            if !previous {
                ctx.set_gc_accounting_baseline(process.stats.gc.nanoseconds);
                if runtime_state(process)
                    .microstate_base
                    .lock()
                    .expect("microstate baseline")
                    .is_none()
                {
                    reset_microstate_baseline(process, ctx);
                }
            }
        }
        Some("false") => {
            runtime_state(process)
                .microstate
                .store(false, Ordering::Relaxed);
            ctx.account_gc_total(process.stats.gc.nanoseconds);
            ctx.set_msacc_accounting_enabled(false);
            set_microstate_workers(process, false);
        }
        Some("reset") => {
            set_microstate_workers(process, previous);
            if previous {
                ctx.account_gc_total(process.stats.gc.nanoseconds);
            }
            ctx.set_gc_accounting_baseline(process.stats.gc.nanoseconds);
            reset_microstate_baseline(process, ctx);
        }
        _ => return Err(badarg()),
    }
    set_runtime_accounting(process, ctx);
    Ok(atom(if previous { "true" } else { "false" }))
}

// Port of erts/emulator/beam/erl_msacc.c:367 (managed scheduler requests), OTP-29.1.1.
fn set_microstate_workers(process: &Process, enabled: bool) {
    crate::check_io::set_msacc_enabled(enabled);
    if let Some(scheduler) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
    {
        scheduler.set_microstate_enabled(enabled);
    }
}

// Port of erts/emulator/beam/erl_msacc.c:425 (counter reset), OTP-29.1.1.
fn reset_microstate_baseline(process: &Process, ctx: &RunCtx<'_, Message>) {
    let stats = scheduler_stats(process, Some(ctx));
    let counters = stats.as_ref().map_or_else(Vec::new, all_msacc_ns);
    let poll_baseline = crate::check_io::msacc_snapshot();
    *runtime_state(process)
        .microstate_base
        .lock()
        .expect("microstate baseline") = Some((Instant::now(), counters, poll_baseline));
}

/// `erts_internal:garbage_collect/1` from native code, on the light BIF path.
// Port of erts/emulator/beam/bif.c:4077 (`erts_internal_garbage_collect_1`) and
// jit/arm/instr_bif.cpp:378 (`call_light_bif_shared`), OTP-29.1.1.
pub(crate) fn garbage_collect_bif(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    if let Some(slot) = process.x.first_mut() {
        *slot = args[0];
    }
    Some(match garbage_collect(process, args[0]) {
        Ok(term) => Ok(term),
        Err(VmError::Trap(trap)) => Err(trap),
        Err(_) => Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        ))),
    })
}

fn garbage_collect(process: &mut Process, arg: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4079-4089, OTP-29.1.1: the argument is
    // compared to the predefined atoms, and the result is `am_true`.
    let major = if arg == Term::atom(arinsal_term::atoms::MAJOR) {
        true
    } else if arg == Term::atom(arinsal_term::atoms::MINOR) {
        false
    } else {
        return Err(badarg());
    };
    let fullsweep_after = process.heap.fullsweep_after();
    if major {
        process.heap.set_fullsweep_after(0);
    }
    // Port of bif.c:4084 (`erts_garbage_collect(BIF_P, 0, NULL, 0)`), OTP-29.1.1:
    // the caller spilled live X registers, so this BIF passes no register roots.
    let live = 0;
    let collected = process.collect_heap_roots(live, &mut [], 0);
    process.heap.set_fullsweep_after(fullsweep_after);
    let gc = collected.map_err(|error| VmError::Unsupported(format!("GC {error:?}")))?;
    after_collection(process, live, gc.collections, gc.words_reclaimed);
    // Port of erts/emulator/beam/erl_gc.c (`erts_garbage_collect`: BUMP_REDS(p, reds) with the
    // cost `garbage_collect` returns), OTP-29.1.1.
    process.bump_gc_reds(gc.reductions);
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

fn rewrite_roots(
    process: &mut Process,
    live_x: usize,
    areas: &[RetiredArea],
) -> Result<u32, VmError> {
    let mut copied = 0_u32;
    let mut shared_copy = SharedCopyCache::default();
    let mut frag_index = FragmentIndex::default();
    let live = live_x.min(process.x.len());
    for index in 0..live {
        let term = process.x[index];
        let (term, did) = rewrite_root(process, term, areas, &mut shared_copy, &mut frag_index)?;
        process.x[index] = term;
        copied += u32::from(did);
    }
    let depth = process.heap.stack_words();
    for index in 0..depth {
        let Some(term) = process.heap.stack_get(index) else {
            continue;
        };
        let (term, did) = rewrite_root(process, term, areas, &mut shared_copy, &mut frag_index)?;
        process.heap.stack_set(index, term);
        copied += u32::from(did);
    }
    if let Some(dictionary) = process.dictionary.as_ref() {
        let entries = dictionary.entries().collect::<Vec<_>>();
        let mut rewritten = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let (key, key_copied) =
                rewrite_root(process, key, areas, &mut shared_copy, &mut frag_index)?;
            let (value, value_copied) =
                rewrite_root(process, value, areas, &mut shared_copy, &mut frag_index)?;
            rewritten.push((key, value));
            copied += u32::from(key_copied) + u32::from(value_copied);
        }
        if let Some(dictionary) = process.dictionary.as_mut() {
            dictionary.assign_entries(&rewritten);
        }
    }
    if let Some(result) = process
        .cold
        .as_ref()
        .and_then(|cold| cold.persistent_get_all.as_ref())
        .map(|state| state.result)
    {
        let (updated, did) =
            rewrite_root(process, result, areas, &mut shared_copy, &mut frag_index)?;
        process
            .cold_mut()
            .persistent_get_all
            .as_mut()
            .expect("persistent get/0 continuation remains live")
            .result = updated;
        copied += u32::from(did);
    }
    // A finished dirty job's result is in erts' argument registers, which
    // erts_garbage_collect_literals copies out of the area like the other roots.
    // Port of erts/emulator/beam/erl_gc.c:1243 (`p->arg_reg, p->arity`), OTP-29.1.1.
    let dirty_results = process.dirty_result_roots();
    let mut rewritten = Vec::with_capacity(dirty_results.len());
    for term in dirty_results {
        let (updated, did) = rewrite_root(process, term, areas, &mut shared_copy, &mut frag_index)?;
        rewritten.push(updated);
        copied += u32::from(did);
    }
    for (slot, term) in process.dirty_result_roots_mut().into_iter().zip(rewritten) {
        *slot = term;
    }
    // Off-heap message fragments remain owned by the queue and are not roots.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8460 (off-heap queue GC handling), OTP-29.1.1.
    let (indices, mut inbox) = process.inbox.gc_root_snapshot();
    for term in &mut inbox {
        let (updated, did) =
            rewrite_root(process, *term, areas, &mut shared_copy, &mut frag_index)?;
        *term = updated;
        copied += u32::from(did);
    }
    process.inbox.update_gc_roots(&indices, &inbox);
    Ok(copied)
}

fn rewrite_root(
    process: &mut Process,
    term: Term,
    areas: &[RetiredArea],
    shared_copy: &mut SharedCopyCache,
    index: &mut FragmentIndex,
) -> Result<(Term, bool), VmError> {
    if !references_retired(process, term, areas, index) {
        return Ok((term, false));
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let copied = copy_term_preserving_sharing_with_cache(term, &mut heap, shared_copy)
        .map_err(|error| VmError::Unsupported(format!("literal copy {error:?}")))?;
    Ok((copied, true))
}

fn references_retired(
    process: &Process,
    term: Term,
    areas: &[RetiredArea],
    index: &mut FragmentIndex,
) -> bool {
    references_retired_from_roots(process, std::iter::once(term), areas, index)
}

fn references_retired_from_roots(
    process: &Process,
    roots: impl IntoIterator<Item = Term>,
    areas: &[RetiredArea],
    index: &mut FragmentIndex,
) -> bool {
    let mut stack = roots.into_iter().collect::<Vec<_>>();
    let mut seen = HashSet::new();
    while let Some(term) = stack.pop() {
        if !term.is_pointer() {
            continue;
        }
        // SAFETY: a pointer term addresses an aligned heap word while the process is stopped.
        let addr = unsafe { term.raw_ptr() as usize };
        if !seen.insert(addr) {
            continue;
        }
        if areas.iter().any(|area| area.contains(term)) {
            return true;
        }
        if !process.heap.owns_term_indexed(term, index) {
            continue;
        }
        push_children(term, &mut stack);
    }
    false
}

/// Rebuild a tagged word stored inside a live boxed object.
fn term_word(word: u64) -> Term {
    // SAFETY: `Term` is a single-field tuple struct over the heap word.
    unsafe { std::mem::transmute(word) }
}

fn push_children(term: Term, out: &mut Vec<Term>) {
    if term.classify() == TermKind::List {
        // SAFETY: list classification means a live cons cell on a stable heap.
        if let Some((head, tail)) = unsafe { term.cons_ref() } {
            out.push(head);
            out.push(tail);
        }
        return;
    }
    let Some(header) = term.header() else {
        return;
    };
    let tag = header & 63;
    // SAFETY: header() only succeeds for a live boxed term.
    let ptr = unsafe { term.raw_ptr() };
    match tag {
        ARITY => {
            // SAFETY: the arity header describes this live tuple.
            if let Some(tuple) = unsafe { term.tuple_ref() } {
                out.extend(tuple.iter());
            }
        }
        MAP => {
            // SAFETY: boxed_object_words requires this live map header.
            let words = unsafe { arinsal_term::boxed_object_words(header, ptr) };
            let start = if (header >> 6) & 3 == 1 { 1 } else { 2 };
            for index in start..words {
                // SAFETY: the child range is inside this initialized map.
                let child = term_word(unsafe { *ptr.add(index) });
                if child.is_pointer() {
                    out.push(child);
                }
            }
        }
        SUB_BITS => {
            // SAFETY: SUB_BITS word four is its original term.
            out.push(term_word(unsafe { *ptr.add(4) }));
        }
        FUN => {
            // SAFETY: the fun view is valid while the process heap is stable.
            if let Some(fun) = unsafe { term.fun_ref() } {
                let mut index = 0;
                while let Some(value) = fun.free(index) {
                    out.push(value);
                    index += 1;
                }
            }
        }
        RECORD => {
            // SAFETY: the record view is valid while the process heap is stable.
            if let Some(record) = unsafe { term.record_ref() } {
                for index in 0..record.len() {
                    if let Some(value) = record.value(index) {
                        out.push(value);
                    }
                }
            }
        }
        _ => {}
    }
}

fn reduction_total(ctx: Option<&RunCtx<'_, Message>>) -> u64 {
    ctx.map_or(0, |ctx| ctx.total_reductions() + u64::from(ctx.consumed()))
}

fn since(total: u64, last: &AtomicU64) -> (u64, u64) {
    let previous = last.swap(total, Ordering::Relaxed);
    (total, total.saturating_sub(previous))
}

fn cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the timespec we own and does not retain it.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + ts.tv_nsec as u64
}

fn runtime_ms(flags: &StatisticsState) -> u64 {
    let now = cpu_ns();
    now.saturating_sub(flags.cpu_origin_ns) / 1_000_000
}

fn wall_ms(flags: &StatisticsState) -> u64 {
    u64::try_from(flags.wall_origin.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn logical_processors() -> usize {
    std::thread::available_parallelism().map_or(1, |count| count.get())
}

fn scheduler_stats(
    process: &Process,
    ctx: Option<&RunCtx<'_, Message>>,
) -> Option<arinsal_sched::SchedulerStats> {
    if let Some(ctx) = ctx {
        return Some(ctx.scheduler_stats());
    }
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
        .map(|scheduler| scheduler.stats())
}

/// Active normal schedulers: all online ones unless multi scheduling is blocked.
// Port of erts/emulator/beam/erl_process.c:8130-8152 (erts_schedulers_state), OTP-29.1.1.
pub(crate) fn normal_schedulers_active(process: &Process) -> usize {
    let online = with_flags(process, |flags| flags.schedulers_online);
    if multi_scheduling_state(process, |state| state.any_blocked()) {
        1
    } else {
        online
    }
}

fn all_schedulers_state(process: &mut Process) -> Result<Term, VmError> {
    let (normal, online, dirty_cpu, dirty_online, dirty_io) = with_flags(process, |flags| {
        (
            flags.schedulers_total,
            flags.schedulers_online,
            flags.dirty_cpu_total,
            flags.dirty_cpu_online,
            flags.dirty_io_total,
        )
    });
    // Port of erts/emulator/beam/erl_process.c:8130-8152 (`erts_schedulers_state`), OTP-29.1.1.
    // These are scheduler suspend counts, not workers currently executing tasks.
    let (any_blocked, blocked) = multi_scheduling_state(process, |state| {
        (state.any_blocked(), state.state() == "blocked")
    });
    let active = if any_blocked { 1 } else { online };
    let dirty_cpu_active = if blocked { 0 } else { dirty_online };
    let dirty_io_active = if blocked { 0 } else { dirty_io };
    let mut states = Vec::with_capacity(3);
    states.push(scheduler_state_owned(
        "normal",
        [normal as u64, online as u64, active as u64],
    ));
    if dirty_cpu > 0 {
        states.push(scheduler_state_owned(
            "dirty_cpu",
            [
                dirty_cpu as u64,
                dirty_online as u64,
                dirty_cpu_active as u64,
            ],
        ));
    }
    if dirty_io > 0 {
        states.push(scheduler_state_owned(
            "dirty_io",
            [dirty_io as u64, dirty_io as u64, dirty_io_active as u64],
        ));
    }
    owned_system_info(
        process,
        arinsal_etf::OwnedTerm::List {
            elems: states,
            tail: Box::new(arinsal_etf::OwnedTerm::Nil),
        },
    )
}

fn scheduler_state_owned(kind: &str, [total, online, active]: [u64; 3]) -> arinsal_etf::OwnedTerm {
    use arinsal_etf::OwnedTerm as O;
    O::Tuple(vec![
        O::Atom(kind.to_owned()),
        O::Int(total as i64),
        O::Int(online as i64),
        O::Int(active as i64),
    ])
}

fn queue_counts(
    process: &Process,
    ctx: Option<&RunCtx<'_, Message>>,
    active: bool,
    include_dirty_io: bool,
) -> Vec<u64> {
    // Port of erts/emulator/beam/erl_process.c:9281 (erts_run_queues_len), OTP-29.1.1.
    let schedulers = with_flags(process, |flags| flags.schedulers_total);
    // erts exposes one aggregated run queue for each dirty scheduler class.
    let slots = schedulers + 1 + usize::from(include_dirty_io);
    let mut values = vec![0; slots];
    if let Some(stats) = scheduler_stats(process, ctx) {
        let source = if active {
            &stats.active_tasks
        } else {
            &stats.run_queue_lengths
        };
        for (target, value) in values.iter_mut().take(schedulers).zip(source) {
            *target = *value;
        }
    }
    values
}

/// Active nanoseconds of the normal, then dirty CPU, then dirty I/O scheduler threads.
fn all_active_ns(stats: &arinsal_sched::SchedulerStats) -> Vec<u64> {
    let mut all = stats.active_ns.clone();
    all.extend_from_slice(&stats.dirty_active_ns[0]);
    all.extend_from_slice(&stats.dirty_active_ns[1]);
    all
}

/// Microstate counters of the normal, then dirty CPU, then dirty I/O scheduler threads.
fn all_msacc_ns(stats: &arinsal_sched::SchedulerStats) -> Vec<[u64; 7]> {
    let mut all = stats.msacc_ns.clone();
    all.extend_from_slice(&stats.dirty_msacc_ns[0]);
    all.extend_from_slice(&stats.dirty_msacc_ns[1]);
    all
}

fn scheduler_wall(
    process: &mut Process,
    ctx: Option<&RunCtx<'_, Message>>,
    include_dirty_io: bool,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_process.c scheduler active/total time accounting, OTP-29.1.1.
    let base = runtime_state(process)
        .sched_wall
        .lock()
        .expect("scheduler wall time")
        .clone();
    let Some(base) = base else {
        return Ok(atom("undefined"));
    };
    let total_us = u64::try_from(base.started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let stats = scheduler_stats(process, ctx);
    let (schedulers, dirty_cpu, dirty_io) = with_flags(process, |flags| {
        (
            flags.schedulers_total,
            flags.dirty_cpu_total,
            flags.dirty_io_total,
        )
    });
    let now = stats.as_ref().map_or_else(Vec::new, all_active_ns);
    let normal_len = stats.as_ref().map_or(0, |stats| stats.active_ns.len());
    // Port of erts/emulator/beam/erl_process.c:3044 (erts_sched_wall_time_request): one entry
    // per normal scheduler, then per dirty CPU and, for `_all`, dirty I/O scheduler.
    let active_us = |index: usize| {
        now.get(index)
            .copied()
            .unwrap_or(0)
            .saturating_sub(base.active_ns.get(index).copied().unwrap_or(0))
            / 1_000
    };
    let mut entries = Vec::new();
    for id in 0..schedulers {
        entries.push(triple(process, (id + 1) as u64, active_us(id), total_us)?);
    }
    for id in 0..dirty_cpu {
        let active = active_us(normal_len + id);
        entries.push(triple(
            process,
            (schedulers + id + 1) as u64,
            active,
            total_us,
        )?);
    }
    if include_dirty_io {
        for id in 0..dirty_io {
            let active = active_us(normal_len + dirty_cpu + id);
            entries.push(triple(
                process,
                (schedulers + dirty_cpu + id + 1) as u64,
                active,
                total_us,
            )?);
        }
    }
    cons_list(process, &entries)
}

fn microstate(
    process: &mut Process,
    mut ctx: Option<&mut RunCtx<'_, Message>>,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_msacc.c result layout, OTP-29.1.1.
    // erts keeps msacc counters from boot, so the list exists even if accounting was never on.
    if runtime_state(process)
        .microstate_base
        .lock()
        .expect("microstate baseline")
        .is_none()
        && let Some(ctx) = ctx.as_deref()
    {
        reset_microstate_baseline(process, ctx);
    }
    let baseline = runtime_state(process)
        .microstate_base
        .lock()
        .expect("microstate baseline")
        .clone();
    let Some((_, baseline, poll_baseline)) = baseline else {
        return Ok(atom("undefined"));
    };
    if let Some(ctx) = ctx.as_deref_mut() {
        ctx.account_gc_total(process.stats.gc.nanoseconds);
    }
    let stats = scheduler_stats(process, ctx.as_deref());
    let (online, dirty_cpu, dirty_io) = with_flags(process, |flags| {
        (
            flags.schedulers_online,
            flags.dirty_cpu_total,
            flags.dirty_io_total,
        )
    });
    let mut entries = Vec::new();
    for id in 0..online {
        let mut counters = stats
            .as_ref()
            .and_then(|stats| stats.msacc_ns.get(id))
            .copied()
            .unwrap_or([0; 7]);
        for (state, counter) in counters.iter_mut().enumerate() {
            *counter = counter.saturating_sub(baseline.get(id).map_or(0, |prior| prior[state]));
        }
        entries.push(msacc_entry(
            process,
            (id + 1) as i64,
            "scheduler",
            counters,
        )?);
    }
    // Port of erts/emulator/beam/erl_msacc.c:211 (dirty scheduler thread counters), OTP-29.1.1.
    let all = stats.as_ref().map_or_else(Vec::new, all_msacc_ns);
    let normal_len = stats.as_ref().map_or(0, |stats| stats.msacc_ns.len());
    let counters_of = |index: usize| {
        let mut counters = all.get(index).copied().unwrap_or([0; 7]);
        for (state, counter) in counters.iter_mut().enumerate() {
            *counter = counter.saturating_sub(baseline.get(index).map_or(0, |prior| prior[state]));
        }
        counters
    };
    for id in 0..dirty_cpu {
        let counters = counters_of(normal_len + id);
        entries.push(msacc_entry(
            process,
            (id + 1) as i64,
            "dirty_cpu_scheduler",
            counters,
        )?);
    }
    for id in 0..dirty_io {
        let counters = counters_of(normal_len + dirty_cpu + id);
        entries.push(msacc_entry(
            process,
            (id + 1) as i64,
            "dirty_io_scheduler",
            counters,
        )?);
    }
    let poll_ns = crate::check_io::msacc_snapshot();
    // The aux and async threads only sleep here: they accrue the time accounting was on.
    let elapsed = poll_ns[2].saturating_sub(poll_baseline[2]);
    entries.push(msacc_entry(process, 1, "aux", [0, 0, 0, 0, 0, 0, elapsed])?);
    let poll_check_io_ns = poll_ns[0].saturating_sub(poll_baseline[0]);
    let poll_sleep_ns = poll_ns[1].saturating_sub(poll_baseline[1]);
    entries.push(msacc_entry(
        process,
        0,
        "poll",
        [0, poll_check_io_ns, 0, 0, 0, 0, poll_sleep_ns],
    )?);
    entries.push(msacc_entry(
        process,
        0,
        "async",
        [0, 0, 0, 0, 0, 0, elapsed],
    )?);
    cons_list(process, &entries)
}

fn msacc_entry(
    process: &mut Process,
    id: i64,
    kind: &str,
    values: [u64; 7],
) -> Result<Term, VmError> {
    // Perf-counter ticks on this host are nanoseconds; msacc:stats/0 performs
    // the same perf_counter-to-microsecond conversion as OTP.
    let counters = map(
        process,
        &[
            ("aux", small(values[0].min(i64::MAX as u64) as i64)),
            ("check_io", small(values[1].min(i64::MAX as u64) as i64)),
            ("emulator", small(values[2].min(i64::MAX as u64) as i64)),
            ("gc", small(values[3].min(i64::MAX as u64) as i64)),
            ("other", small(values[4].min(i64::MAX as u64) as i64)),
            ("port", small(values[5].min(i64::MAX as u64) as i64)),
            ("sleep", small(values[6].min(i64::MAX as u64) as i64)),
        ],
    )?;
    map(
        process,
        &[
            ("counters", counters),
            ("id", small(id)),
            ("type", atom(kind)),
        ],
    )
}

fn io_counters(process: &mut Process) -> Result<Term, VmError> {
    // Port byte totals stay zero until port read/write paths publish counters.
    let input = tagged(process, "input", 0)?;
    let output = tagged(process, "output", 0)?;
    tuple(process, &[input, output])
}

fn small(value: i64) -> Term {
    Term::small(value).unwrap_or(Term::NIL)
}

fn check_io_info(process: &mut Process) -> Result<Term, VmError> {
    // Port of erts_check_io_info in erts/emulator/sys/common/erl_check_io.c:2675,
    // OTP-29.1.1. The fallback and scheduler sets are part of OTP's Mac layout.
    let entries = [
        (
            "select", "false", 13_536, "true", "false", "false", "true", 0, 2,
        ),
        (
            "kqueue", "kqueue", 56, "false", "false", "true", "false", 0, 1,
        ),
        (
            "kqueue", "kqueue", 65_592, "false", "false", "true", "false", 1, 1,
        ),
    ];
    let mut sets = Vec::with_capacity(entries.len());
    for (primary, kernel_poll, memory, lazy, batch, concurrent, fallback, poll_threads, set_size) in
        entries
    {
        let properties = [
            ("name", atom("erts_poll")),
            ("primary", atom(primary)),
            ("kernel_poll", atom(kernel_poll)),
            ("memory_size", non_neg(process, memory)?),
            ("total_poll_set_size", small(set_size)),
            ("lazy_updates", atom(lazy)),
            ("pending_updates", small(0)),
            ("batch_updates", atom(batch)),
            ("concurrent_updates", atom(concurrent)),
            ("fallback", atom(fallback)),
            ("max_fds", non_neg(process, 1_048_576)?),
            ("active_fds", small(0)),
            ("poll_threads", small(poll_threads)),
        ];
        let properties = properties
            .iter()
            .map(|(key, value)| tuple(process, &[atom(key), *value]))
            .collect::<Result<Vec<_>, _>>()?;
        sets.push(cons_list(process, &properties)?);
    }
    cons_list(process, &sets)
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("runtime atom"))
}

fn atom_name(term: Term) -> Option<&'static str> {
    global_atoms().text(term.as_atom()?)
}

pub(crate) fn non_neg(process: &mut Process, value: u64) -> Result<Term, VmError> {
    if let Ok(value) = i64::try_from(value)
        && let Some(term) = Term::small(value)
    {
        return Ok(term);
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .int_from_bigint(&num_bigint::BigInt::from(value))
        .map_err(|_| badarg())
}

fn pair(process: &mut Process, a: u64, b: u64) -> Result<Term, VmError> {
    let a = non_neg(process, a)?;
    let b = non_neg(process, b)?;
    tuple(process, &[a, b])
}

fn triple(process: &mut Process, a: u64, b: u64, c: u64) -> Result<Term, VmError> {
    let a = non_neg(process, a)?;
    let b = non_neg(process, b)?;
    let c = non_neg(process, c)?;
    tuple(process, &[a, b, c])
}

fn tagged(process: &mut Process, name: &str, value: u64) -> Result<Term, VmError> {
    let value = non_neg(process, value)?;
    tuple(process, &[atom(name), value])
}

fn tuple(process: &mut Process, terms: &[Term]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(terms)
        .map_err(|_| badarg())
}

fn cons_list(process: &mut Process, terms: &[Term]) -> Result<Term, VmError> {
    let mut list = Term::NIL;
    for term in terms.iter().rev() {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        list = TermBuilder::new(&mut heap)
            .cons(*term, list)
            .map_err(|_| badarg())?;
    }
    Ok(list)
}

fn int_list(process: &mut Process, values: &[u64]) -> Result<Term, VmError> {
    let mut terms = Vec::with_capacity(values.len());
    for value in values {
        terms.push(non_neg(process, *value)?);
    }
    cons_list(process, &terms)
}

fn int_tuple(process: &mut Process, values: &[u64]) -> Result<Term, VmError> {
    let mut terms = Vec::with_capacity(values.len());
    for value in values {
        terms.push(non_neg(process, *value)?);
    }
    tuple(process, &terms)
}

fn map(process: &mut Process, pairs: &[(&str, Term)]) -> Result<Term, VmError> {
    let pairs: Vec<(Term, Term)> = pairs
        .iter()
        .map(|(key, value)| (atom(key), *value))
        .collect();
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    arinsal_maps::from_list(&pairs, &mut heap).map_err(|_| badarg())
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_difftest::{CallResult, RefErl};
    use arinsal_sched::{Config, RunCtx, RunOutcome, Scheduler, Task};

    /// Tests that change or read the process-global scheduler flags run one
    /// at a time; the flags are shared by every test in this binary.
    static SCHEDULER_FLAGS: Mutex<()> = Mutex::new(());

    #[test]
    fn scheduler_startup_system_info_matches_otp_on_scheduler_path() {
        let _flags = SCHEDULER_FLAGS.lock().unwrap_or_else(|e| e.into_inner());
        arinsal_args::configure_scheduler_options(arinsal_args::ActiveSchedulerOptions::default());
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping scheduler startup system_info differential test");
            return;
        };
        let beam = reference
            .compile_named(
                "scheduler_startup_info_probe",
                "-module(scheduler_startup_info_probe). -export([run/0]). run() -> {erlang:system_info(scheduler_bind_type), erlang:system_info(port_parallelism)}.",
                &[],
            )
            .unwrap();
        reference
            .load("scheduler_startup_info_probe", &beam)
            .unwrap();
        let expected = reference.call("scheduler_startup_info_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("scheduler_startup_info_probe", "run", &[], 1, None)
            .unwrap_or_else(|error| panic!("scheduler startup system_info VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn beam_jump_table_system_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping BEAM jump-table differential test");
            return;
        };
        let beam = reference
            .compile_named(
                "beam_jump_table_probe",
                "-module(beam_jump_table_probe). -export([run/0]). run() -> erlang:system_info(beam_jump_table).",
                &[],
            )
            .unwrap();
        reference.load("beam_jump_table_probe", &beam).unwrap();
        let expected = reference.call("beam_jump_table_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("beam_jump_table_probe", "run", &[], 1, None)
            .unwrap_or_else(|error| panic!("BEAM jump-table VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn all_scheduler_state_matches_otp() {
        let _flags = SCHEDULER_FLAGS.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping all scheduler state differential test");
            return;
        };
        let beam = reference
            .compile_named(
                "all_scheduler_state_probe",
                "-module(all_scheduler_state_probe). -export([run/0]). run() -> erlang:system_info(all_schedulers_state).",
                &[],
            )
            .unwrap();
        reference.load("all_scheduler_state_probe", &beam).unwrap();
        let expected = reference.call("all_scheduler_state_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("all_scheduler_state_probe", "run", &[], 10, None)
            .unwrap_or_else(|error| panic!("all scheduler state VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn system_logger_is_isolated_between_vm_runtimes() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping per-runtime system logger test");
            return;
        };
        let first_beam = reference
            .compile_named(
                "runtime_logger_first",
                "-module(runtime_logger_first). -export([run/0]). run() -> erlang:system_flag(system_logger, undefined).",
                &[],
            )
            .unwrap();
        let second_beam = reference
            .compile_named(
                "runtime_logger_second",
                "-module(runtime_logger_second). -export([run/0]). run() -> erlang:system_flag(system_logger, undefined).",
                &[],
            )
            .unwrap();
        let mut first = Vm::new([]);
        first.load_bytes(&first_beam).unwrap();
        assert_eq!(
            first
                .eval_scheduled("runtime_logger_first", "run", &[], 1, None)
                .unwrap()
                .term,
            OwnedTerm::atom("logger")
        );
        let mut second = Vm::new([]);
        second.load_bytes(&second_beam).unwrap();
        assert_eq!(
            second
                .eval_scheduled("runtime_logger_second", "run", &[], 1, None)
                .unwrap()
                .term,
            OwnedTerm::atom("logger")
        );
    }

    #[test]
    fn statistics_reduction_delta_is_isolated_between_vm_runtimes() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping per-runtime statistics test");
            return;
        };
        let beam = reference
            .compile_named(
                "runtime_reductions_probe",
                "-module(runtime_reductions_probe). -export([run/0]). run() -> First=erlang:statistics(reductions), Second=erlang:statistics(reductions), {First,Second}.",
                &[],
            )
            .unwrap();
        let mut first = Vm::new([]);
        first.load_bytes(&beam).unwrap();
        first
            .eval_scheduled("runtime_reductions_probe", "run", &[], 1, None)
            .unwrap();

        let mut second = Vm::new([]);
        second.load_bytes(&beam).unwrap();
        let result = second
            .eval_scheduled("runtime_reductions_probe", "run", &[], 1, None)
            .unwrap_or_else(|error| panic!("statistics VM error: {error:?}"));
        let OwnedTerm::Tuple(values) = &result.term else {
            panic!(
                "statistics(reductions) returned a non-tuple: {:?}",
                result.term
            );
        };
        let Some(OwnedTerm::Tuple(first_read)) = values.first() else {
            panic!("first statistics result was not a tuple: {values:?}");
        };
        assert_eq!(first_read.len(), 2);
        assert_eq!(
            first_read[0], first_read[1],
            "a fresh runtime must start with no previous reductions delta"
        );
    }

    #[test]
    fn changing_online_scheduler_count_matches_otp() {
        let _flags = SCHEDULER_FLAGS.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping scheduler-count differential test");
            return;
        };
        let source = concat!(
            "-module(scheduler_count_probe). -export([run/0]).\n",
            "run() -> Previous=erlang:system_flag(schedulers_online,1), ",
            "Current=erlang:system_info(schedulers_online), ",
            "erlang:system_flag(schedulers_online,Previous), {Previous,Current}."
        );
        let beam = reference
            .compile_named("scheduler_count_probe", source, &[])
            .unwrap();
        reference.load("scheduler_count_probe", &beam).unwrap();
        let expected = reference.call("scheduler_count_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("scheduler_count_probe", "run", &[], 10, None)
            .unwrap_or_else(|error| panic!("scheduler-count VM error: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }

    #[test]
    fn garbage_collect_result_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping garbage_collect differential test");
            return;
        };
        for mode in ["major", "minor"] {
            let expected =
                reference.call("erts_internal", "garbage_collect", &[OwnedTerm::atom(mode)]);
            let term = Term::atom(global_atoms().intern(mode).unwrap());
            let actual = garbage_collect(&mut Process::new(), term)
                .and_then(|term| to_owned(term).map_err(|_| badarg()));
            assert_eq!(expected, CallResult::Ok(actual.unwrap()));
        }
    }

    #[test]
    fn debug_compiled_system_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping system_info differential test");
            return;
        };
        let expected = reference.call(
            "erlang",
            "system_info",
            &[OwnedTerm::atom("debug_compiled")],
        );
        let selector = Term::atom(global_atoms().intern("debug_compiled").unwrap());
        let actual = system_info(&Vm::new([]), &mut Process::new(), None, selector)
            .unwrap()
            .unwrap();
        assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
    }

    #[test]
    fn ets_always_compress_system_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping ETS compression system_info differential test");
            return;
        };
        let expected = reference.call(
            "erlang",
            "system_info",
            &[OwnedTerm::atom("ets_always_compress")],
        );
        let selector = Term::atom(global_atoms().intern("ets_always_compress").unwrap());
        let actual = system_info(&Vm::new([]), &mut Process::new(), None, selector)
            .unwrap()
            .unwrap();
        assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
    }

    #[test]
    fn max_integer_system_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping max_integer differential test");
            return;
        };
        let expected = reference.call("erlang", "system_info", &[OwnedTerm::atom("max_integer")]);
        let selector = Term::atom(global_atoms().intern("max_integer").unwrap());
        let actual = system_info(&Vm::new([]), &mut Process::new(), None, selector)
            .unwrap()
            .unwrap();
        assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
    }

    #[test]
    fn check_io_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping check_io info differential test");
            return;
        };
        let expected = reference.call("erlang", "system_info", &[OwnedTerm::atom("check_io")]);
        let selector = Term::atom(global_atoms().intern("check_io").unwrap());
        let mut process = Process::new();
        let actual = system_info(&Vm::new([]), &mut process, None, selector)
            .unwrap()
            .unwrap();
        let CallResult::Ok(expected) = expected else {
            panic!("OTP check_io system_info failed: {expected:?}");
        };
        let mut expected = expected;
        let mut actual = to_owned(actual).unwrap();
        normalize_check_io_counters(&mut expected);
        normalize_check_io_counters(&mut actual);
        assert_eq!(expected, actual);
    }

    fn normalize_check_io_counters(term: &mut OwnedTerm) {
        match term {
            OwnedTerm::List { elems, tail } => {
                for elem in elems {
                    normalize_check_io_counters(elem);
                }
                normalize_check_io_counters(tail);
            }
            OwnedTerm::Tuple(elems) => {
                if elems.len() == 2
                    && matches!(
                        &elems[0],
                        OwnedTerm::Atom(key)
                            if matches!(
                                key.as_str(),
                                "total_poll_set_size"
                                    | "pending_updates"
                                    | "active_fds"
                                    | "poll_threads"
                            )
                    )
                {
                    elems[1] = OwnedTerm::Atom("volatile_counter".into());
                }
                for elem in elems {
                    normalize_check_io_counters(elem);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn wordsize_and_ethread_info_system_selectors_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping system_info selector differential test");
            return;
        };
        for selector in [
            OwnedTerm::Tuple(vec![
                OwnedTerm::atom("wordsize"),
                OwnedTerm::atom("internal"),
            ]),
            OwnedTerm::Tuple(vec![
                OwnedTerm::atom("wordsize"),
                OwnedTerm::atom("external"),
            ]),
            OwnedTerm::atom("ethread_info"),
        ] {
            let expected = reference.call("erlang", "system_info", std::slice::from_ref(&selector));
            let mut heap = VecHeap::new();
            let selector_term = from_owned(&selector, &mut heap).unwrap();
            let mut process = Process::new();
            let actual = system_info(&Vm::new([]), &mut process, None, selector_term)
                .unwrap()
                .unwrap();
            assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
        }
    }

    #[test]
    fn display_string_empty_matches_otp() {
        let Ok(reference) = std::process::Command::new("erl")
            .args([
                "-noshell",
                "-eval",
                "io:format(\"~p~n\", [erlang:display_string(stderr, [])]), halt().",
            ])
            .output()
        else {
            eprintln!("erl unavailable; skipping display_string differential test");
            return;
        };
        assert!(reference.status.success());
        let actual = display_string(&[
            Term::atom(global_atoms().intern("stderr").unwrap()),
            Term::NIL,
        ])
        .unwrap();
        assert_eq!(reference.stdout, b"true\n");
        assert_eq!(to_owned(actual).unwrap(), OwnedTerm::atom("true"));
    }
    use arinsal_etf::OwnedTerm;
    use arinsal_term::{VecHeap, from_owned, to_owned};

    struct CountedYield;
    impl Task for CountedYield {
        type Message = ();
        type SchedulerData = ();
        fn run(&mut self, ctx: &mut RunCtx<'_, ()>, _: &mut (), _budget: u32) -> RunOutcome {
            assert!(ctx.consume(3));
            RunOutcome::Yield
        }
    }

    #[test]
    fn sched_acct_scheduler_dispatch_and_reductions_are_exact() {
        let scheduler = Scheduler::simulation(Config::default(), 9);
        scheduler.spawn(CountedYield).unwrap();
        assert!(scheduler.step());
        let stats = scheduler.stats();
        assert_eq!(stats.context_switches, 1);
        assert_eq!(stats.reductions, 3);
        assert_eq!(stats.run_queue_lengths.iter().sum::<u64>(), 1);
        assert_eq!(stats.active_tasks.iter().sum::<u64>(), 1);
    }

    #[test]
    fn sched_acct_scheduler_flag_parser_matches_otp_count_forms() {
        assert_eq!(parse_scheduler_pair("8:3", 10), Some((8, 3)));
        assert_eq!(parse_scheduler_pair("8", 10), Some((8, 8)));
        assert_eq!(parse_scheduler_pair("-1:-2", 10), Some((9, 8)));
        assert_eq!(parse_scheduler_pair("0:3", 10), Some((10, 3)));
        assert_eq!(boot_scheduler_counts(10), (10, 10, 10, 10, 10));
    }

    #[test]
    fn sched_acct_system_scheduler_facts_match_otp() {
        let _flags = SCHEDULER_FLAGS.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping scheduler facts differential test");
            return;
        };
        for selector in [
            "schedulers",
            "schedulers_online",
            "dirty_cpu_schedulers",
            "dirty_cpu_schedulers_online",
            "dirty_io_schedulers",
        ] {
            let expected = reference.call("erlang", "system_info", &[OwnedTerm::atom(selector)]);
            let input = Term::atom(global_atoms().intern(selector).unwrap());
            let actual = system_info(&Vm::new([]), &mut Process::new(), None, input)
                .unwrap()
                .unwrap();
            assert_eq!(
                CallResult::Ok(to_owned(actual).unwrap()),
                expected,
                "{selector}"
            );
        }
    }

    #[test]
    fn alloc_a4_allocator_options_match_otp() {
        use OwnedTerm as O;

        fn reference_term(arguments: &[&str], eval: &str) -> O {
            let output = std::process::Command::new("erl")
                .args(arguments)
                .args([
                    "-noshell",
                    "-eval",
                    &format!(
                        "io:put_chars(standard_io,binary:encode_hex(term_to_binary({eval}))),halt()."
                    ),
                ])
                .output()
                .expect("reference erl process");
            assert!(
                output.status.success(),
                "reference erl failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let encoded = std::str::from_utf8(&output.stdout).unwrap();
            let bytes = encoded
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            arinsal_etf::decode(&bytes).unwrap()
        }

        let default_output = reference_term(
            &[],
            "{[erlang:system_info({allocator,A}) || A <- [temp_alloc,sl_alloc,std_alloc,ll_alloc,eheap_alloc,ets_alloc,fix_alloc,literal_alloc,binary_alloc,driver_alloc]],erlang:system_info(allocator),erlang:system_info(alloc_util_allocators)}",
        );
        let O::Tuple(default_values) = &default_output else {
            panic!("OTP default allocator query was not a tuple");
        };
        let O::List {
            elems: default_infos,
            ..
        } = &default_values[0]
        else {
            panic!("OTP default allocator options were not a list");
        };
        arinsal_args::configure_allocator_options(arinsal_args::ActiveAllocatorOptions::default());

        fn project(value: &O) -> O {
            let O::List { elems, .. } = value else {
                return value.clone();
            };
            O::List {
                elems: elems
                    .iter()
                    .filter_map(|entry| {
                        let O::Tuple(fields) = entry else {
                            return None;
                        };
                        if fields.len() != 3 {
                            return None;
                        }
                        let O::List { elems, .. } = &fields[2] else {
                            return None;
                        };
                        let selected = elems
                            .iter()
                            .filter(|item| matches!(item, O::Tuple(parts) if parts.first().is_some_and(|key| matches!(key, O::Atom(name) if name == "options" || name == "versions"))))
                            .cloned()
                            .collect();
                        Some(O::Tuple(vec![fields[1].clone(), O::List { elems: selected, tail: Box::new(O::Nil) }]))
                    })
                    .collect(),
                tail: Box::new(O::Nil),
            }
        }

        for (index, name) in [
            "temp_alloc",
            "sl_alloc",
            "std_alloc",
            "ll_alloc",
            "eheap_alloc",
            "ets_alloc",
            "fix_alloc",
            "literal_alloc",
            "binary_alloc",
            "driver_alloc",
        ]
        .into_iter()
        .enumerate()
        {
            let mut process = Process::new();
            let input = from_owned(
                &O::Tuple(vec![O::Atom("allocator".into()), O::Atom(name.into())]),
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .unwrap();
            let actual = system_info(&Vm::new([]), &mut process, None, input)
                .unwrap()
                .unwrap();
            assert_eq!(
                project(&to_owned(actual).unwrap()),
                project(&default_infos[index]),
                "{name}"
            );
        }

        for (selector, expected) in [
            (O::Atom("allocator".into()), &default_values[1]),
            (O::Atom("alloc_util_allocators".into()), &default_values[2]),
        ] {
            let mut process = Process::new();
            let input = from_owned(
                &selector,
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .unwrap();
            let actual = system_info(&Vm::new([]), &mut process, None, input)
                .unwrap()
                .unwrap();
            assert_eq!(to_owned(actual).unwrap(), *expected, "{selector}");
        }

        let names = ["eheap_alloc", "sl_alloc", "ets_alloc", "binary_alloc"];
        let expected = reference_term(
            &[
                "+S", "2:2", "+MHsbct", "100", "+MSas", "ageffcbf", "+MEacul", "75", "+MBatags",
                "true", "+MHt", "false", "+MHt", "true", "+MMmcs", "5",
            ],
            "{[erlang:system_info({allocator,A}) || A <- [eheap_alloc,sl_alloc,ets_alloc,binary_alloc]],erlang:system_info({allocator,mseg_alloc}),erlang:system_info(allocator)}",
        );
        let mut actual_infos = Vec::new();
        let active = arinsal_args::ActiveAllocatorOptions {
            schedulers: Some(2),
            flags: vec![
                arinsal_args::IgnoredFlag {
                    name: "+MHsbct".into(),
                    value: Some("100".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MHt".into(),
                    value: Some("false".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MHt".into(),
                    value: Some("true".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MSas".into(),
                    value: Some("ageffcbf".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MEacul".into(),
                    value: Some("75".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MBatags".into(),
                    value: Some("true".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MMmcs".into(),
                    value: Some("5".into()),
                },
            ],
            ..Default::default()
        };
        arinsal_args::configure_allocator_options(active);
        for name in names {
            let mut process = Process::new();
            let input = from_owned(
                &O::Tuple(vec![O::Atom("allocator".into()), O::Atom(name.into())]),
                &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
            )
            .unwrap();
            actual_infos.push(
                to_owned(
                    system_info(&Vm::new([]), &mut process, None, input)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap(),
            );
        }
        let O::Tuple(flagged_expected) = &expected else {
            panic!("OTP flagged allocator result was not a tuple");
        };
        let O::List {
            elems: expected_infos,
            ..
        } = &flagged_expected[0]
        else {
            panic!("OTP flagged allocator options were not a list");
        };
        assert_eq!(actual_infos.len(), expected_infos.len());
        for (actual, expected) in actual_infos.iter().zip(expected_infos) {
            assert_eq!(
                project(actual),
                project(expected),
                "allocator options with +M switches"
            );
        }
        let mut process = Process::new();
        let input = Term::atom(global_atoms().intern("allocator").unwrap());
        let actual = system_info(&Vm::new([]), &mut process, None, input)
            .unwrap()
            .unwrap();
        assert_eq!(
            to_owned(actual).unwrap(),
            flagged_expected[2],
            "global allocator configuration with +M switches"
        );
        let mut process = Process::new();
        let input = from_owned(
            &O::Tuple(vec![
                O::Atom("allocator".into()),
                O::Atom("mseg_alloc".into()),
            ]),
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        )
        .unwrap();
        let actual = system_info(&Vm::new([]), &mut process, None, input)
            .unwrap()
            .unwrap();
        assert_eq!(
            project(&to_owned(actual).unwrap()),
            project(&flagged_expected[1]),
            "mseg allocator options with +MM switches"
        );

        let test_expected = reference_term(
            &["+MZe", "true"],
            "erlang:system_info({allocator,test_alloc})",
        );
        arinsal_args::configure_allocator_options(arinsal_args::ActiveAllocatorOptions {
            flags: vec![arinsal_args::IgnoredFlag {
                name: "+MZe".into(),
                value: Some("true".into()),
            }],
            ..Default::default()
        });
        let mut process = Process::new();
        let input = from_owned(
            &O::Tuple(vec![
                O::Atom("allocator".into()),
                O::Atom("test_alloc".into()),
            ]),
            &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
        )
        .unwrap();
        let actual = system_info(&Vm::new([]), &mut process, None, input)
            .unwrap()
            .unwrap();
        assert_eq!(
            project(&to_owned(actual).unwrap()),
            project(&test_expected),
            "enabled test allocator options"
        );
        arinsal_args::configure_allocator_options(arinsal_args::ActiveAllocatorOptions::default());
    }

    #[test]
    fn sched_acct_queue_statistics_shapes_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping queue shape differential test");
            return;
        };
        for selector in [
            "run_queue_lengths",
            "run_queue_lengths_all",
            "active_tasks",
            "active_tasks_all",
        ] {
            let expected = reference.call("erlang", "statistics", &[OwnedTerm::atom(selector)]);
            let mut heap = VecHeap::new();
            let input = from_owned(&OwnedTerm::atom(selector), &mut heap).unwrap();
            let actual = statistics(&mut Process::new(), None, input)
                .and_then(|term| to_owned(term).map_err(|_| badarg()))
                .unwrap();
            match (&actual, &expected) {
                (
                    OwnedTerm::List { elems: actual, .. },
                    CallResult::Ok(OwnedTerm::List {
                        elems: expected, ..
                    }),
                ) => assert_eq!(actual.len(), expected.len(), "{selector}"),
                _ => panic!("queue statistics should be lists"),
            }
        }
    }

    #[test]
    fn sched_acct_run_queue_totals_equal_scheduler_slots() {
        let process = Process::new();
        let lengths = queue_counts(&process, None, false, false);
        let all = queue_counts(&process, None, false, true);
        assert_eq!(lengths.iter().sum::<u64>(), 0);
        assert_eq!(all.iter().sum::<u64>(), 0);
        assert!(all.len() > lengths.len());
    }

    #[test]
    fn statistics_shapes_and_badarg_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping statistics differential test");
            return;
        };
        for key in [
            "runtime",
            "wall_clock",
            "reductions",
            "exact_reductions",
            "run_queue",
            "run_queue_lengths",
            "total_run_queue_lengths",
            "context_switches",
            "garbage_collection",
            "io",
            "scheduler_wall_time",
            "total_active_tasks",
            "active_tasks",
        ] {
            let expected = reference.call("erlang", "statistics", &[OwnedTerm::atom(key)]);
            let mut input_heap = VecHeap::new();
            let input = from_owned(&OwnedTerm::atom(key), &mut input_heap).unwrap();
            let mut process = Process::new();
            let actual = statistics(&mut process, None, input)
                .and_then(|term| to_owned(term).map_err(|_| badarg()));
            match (actual, expected) {
                (Ok(OwnedTerm::Int(_)), CallResult::Ok(OwnedTerm::Int(_)))
                | (Ok(OwnedTerm::Tuple(_)), CallResult::Ok(OwnedTerm::Tuple(_)))
                | (Ok(OwnedTerm::List { .. }), CallResult::Ok(OwnedTerm::List { .. }))
                | (Ok(OwnedTerm::Atom(_)), CallResult::Ok(OwnedTerm::Atom(_))) => {}
                (actual, expected) => {
                    panic!("statistics({key}) shape mismatch: {actual:?} / {expected:?}")
                }
            }
        }
        let mut heap = VecHeap::new();
        let micro = from_owned(&OwnedTerm::atom("microstate_accounting"), &mut heap).unwrap();
        let actual = statistics(&mut Process::new(), None, micro)
            .and_then(|term| to_owned(term).map_err(|_| badarg()))
            .expect("microstate");
        assert_eq!(actual, OwnedTerm::atom("undefined"));
        let invalid = from_owned(&OwnedTerm::atom("invalid"), &mut heap).unwrap();
        assert!(statistics(&mut Process::new(), None, invalid).is_err());
    }
}
