//! Process creation of erl_process.c.
//!
//! Port of erts/emulator/beam/erl_process.c (erts_parse_spawn_opts, erl_create_process,
//! erts_send_local_spawn_reply) and erl_process.h (ErlSpawnOpts, ERTS_SET_DEFAULT_SPAWN_OPTS),
//! OTP-29.1.1. Creation works from the parent (`c_p`) alone: the child is allocated, its heap
//! sized and filled, its links and monitors installed, and it is queued on the calling
//! scheduler's run queue. Only tracing and seq_trace reach the scheduler's data, through
//! `with_sched`, as the trace calls of `erl_create_process` take the tracer through the
//! scheduler.

use crate::natives::bif::{badarg, with_sched};
use crate::proc_create::AliasMode;
use crate::process::{MaxHeap, Message, Runtime};
use crate::{Process, VmError};
use arinsal_sched::{Pid, Priority};
use arinsal_term::{Atom, Term, TermBuilder, TermKind, atoms};

/// `ErlSpawnOpts`: the options `erl_create_process` takes.
// Port of erts/emulator/beam/erl_process.h (ErlSpawnOpts, SPO_* flags), OTP-29.1.1.
pub(crate) struct ErlSpawnOpts {
    /// `SPO_LINK`, with `link_oflags & ERTS_ML_FLG_PRIO_ML` as `link_priority`.
    pub link: bool,
    pub link_priority: bool,
    /// `SPO_MONITOR` with `monitor_tag` and `monitor_oflags`.
    pub monitor: Option<SpawnMonitor>,
    /// `flags & SPO_USE_ARGS`: one of min_heap_size, priority, fullsweep_after,
    /// max_heap_size or scheduler was given, so the fields below are used.
    pub use_args: bool,
    pub min_heap_size: usize,
    pub min_vheap_size: usize,
    pub max_gen_gcs: u16,
    pub max_heap: MaxHeap,
    pub priority: Priority,
    /// `scheduler`: 0 is unbound.
    pub scheduler: usize,
    /// `SPO_OFF_HEAP_MSGQ` / `SPO_ON_HEAP_MSGQ` when given; `None` keeps the system default.
    pub off_heap_msgq: Option<bool>,
    /// `SPO_ASYNC_DIST`.
    pub async_dist: bool,
    /// `SPO_ASYNC`: a `spawn_request`, which replies and records `mfa` as the initial call.
    pub r#async: bool,
    /// `SPO_NO_SMSG` / `SPO_NO_EMSG`.
    pub no_smsg: bool,
    pub no_emsg: bool,
    /// `so->tag`, `so->opts` and `so->mfa`.
    pub tag: Term,
    pub opts: Term,
    pub mfa: Option<(Atom, Atom, usize)>,
    /// `so->mref`: the monitor (or spawn_request) reference `erl_create_process` made.
    pub mref: Term,
}

/// `monitor_tag` and `monitor_oflags` of `SPO_MONITOR`.
pub(crate) struct SpawnMonitor {
    pub tag: Option<arinsal_etf::OwnedTerm>,
    pub alias: Option<AliasMode>,
    pub priority: bool,
}

/// `so->error_code` of a failed `erl_create_process`.
pub(crate) enum CreateError {
    Badarg,
    SystemLimit,
    Vm(VmError),
}

impl CreateError {
    /// `BIF_ERROR(c_p, so.error_code)`.
    pub(crate) fn into_bif_error(self) -> VmError {
        match self {
            CreateError::Badarg => badarg(),
            CreateError::SystemLimit => system_limit(),
            CreateError::Vm(error) => error,
        }
    }
}

impl From<VmError> for CreateError {
    fn from(error: VmError) -> Self {
        CreateError::Vm(error)
    }
}

pub(crate) fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

impl ErlSpawnOpts {
    /// `ERTS_SET_DEFAULT_SPAWN_OPTS(&so)`: `erts_default_spo_flags`, no options, `spawn_reply`.
    // Port of erts/emulator/beam/erl_process.h (ERTS_SET_DEFAULT_SPAWN_OPTS), OTP-29.1.1.
    pub(crate) fn new(runtime: Option<&Runtime>) -> Self {
        let defaults = crate::natives::sys::gc_defaults(runtime);
        Self {
            link: false,
            link_priority: false,
            monitor: None,
            use_args: false,
            min_heap_size: defaults.min_heap_size() as usize,
            min_vheap_size: defaults.min_bin_vheap_size() as usize,
            max_gen_gcs: defaults.max_gen_gcs(),
            max_heap: defaults.max_heap(),
            priority: Priority::Normal,
            scheduler: 0,
            off_heap_msgq: None,
            async_dist: defaults.async_dist(),
            r#async: false,
            no_smsg: false,
            no_emsg: false,
            tag: Term::atom(atoms::SPAWN_REPLY),
            opts: Term::NIL,
            mfa: None,
            mref: Term::NIL,
        }
    }
}

/// Outcome of `erts_parse_spawn_opts`: 0, `<0` (badopt) or `>0` (not a proper list).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseResult {
    Ok,
    BadOpt,
    NotList,
}

/// `erts_parse_spawn_opts(sop, opts_list, tag, message_opt)`. `tag` is `Some` where
/// `reply_tag` is allowed; `message_opt` allows `reply`.
// Port of erts/emulator/beam/erl_process.c:12222 (erts_parse_spawn_opts), OTP-29.1.1.
pub(crate) fn erts_parse_spawn_opts(
    sop: &mut ErlSpawnOpts,
    runtime: Option<&Runtime>,
    opts_list: Term,
    mut tag: Option<&mut Term>,
    message_opt: bool,
) -> ParseResult {
    *sop = ErlSpawnOpts::new(runtime);
    if let Some(tag) = tag.as_deref_mut() {
        *tag = sop.tag;
    }
    let mut bad = false;
    let mut ap = opts_list;
    while ap.classify() == TermKind::List {
        // SAFETY: the option list is a BIF argument, rooted for the call.
        let Some((arg, tail)) = (unsafe { ap.cons_ref() }) else {
            break;
        };
        ap = tail;
        if arg == Term::atom(atoms::LINK) {
            sop.link = true;
        } else if arg == Term::atom(atoms::MONITOR) {
            sop.monitor = Some(SpawnMonitor {
                tag: None,
                alias: None,
                priority: false,
            });
        } else if let Some((key, val)) = crate::natives::proc::tuple2(arg) {
            if !parse_tuple_option(sop, runtime, key, val, tag.as_deref_mut(), message_opt) {
                bad = true;
            }
        } else {
            bad = true;
        }
    }
    if ap != Term::NIL {
        return ParseResult::NotList;
    }
    if sop.max_heap.size != 0 && sop.max_heap.size < sop.min_heap_size as u64 {
        bad = true;
    }
    if bad {
        ParseResult::BadOpt
    } else {
        ParseResult::Ok
    }
}

/// One `{Key, Value}` option of `erts_parse_spawn_opts`; `false` is `result = -1`.
fn parse_tuple_option(
    sop: &mut ErlSpawnOpts,
    runtime: Option<&Runtime>,
    arg: Term,
    val: Term,
    tag: Option<&mut Term>,
    message_opt: bool,
) -> bool {
    let atom = |a| Term::atom(a);
    if arg == atom(atoms::PRIORITY) {
        sop.use_args = true;
        sop.priority = match val {
            v if v == atom(atoms::MAX) => Priority::Max,
            v if v == atom(atoms::HIGH) => Priority::High,
            v if v == atom(atoms::NORMAL) => Priority::Normal,
            v if v == atom(atoms::LOW) => Priority::Low,
            _ => return false,
        };
    } else if arg == atom(atoms::ASYNC_DIST) {
        if val == atom(atoms::TRUE) {
            sop.async_dist = true;
        } else if val == atom(atoms::FALSE) {
            sop.async_dist = false;
        } else {
            return false;
        }
    } else if arg == atom(atoms::MESSAGE_QUEUE_DATA) {
        if val == atom(atoms::ON_HEAP) {
            sop.off_heap_msgq = Some(false);
        } else if val == atom(atoms::OFF_HEAP) {
            sop.off_heap_msgq = Some(true);
        } else {
            return false;
        }
    } else if arg == atom(atoms::MIN_HEAP_SIZE) && val.as_small().is_some() {
        sop.use_args = true;
        let size = val.as_small().unwrap_or(-1);
        if size < 0 {
            return false;
        }
        sop.min_heap_size =
            crate::natives::sys::normalize_spawn_heap_minimum(runtime, Some(size as usize), false);
    } else if arg == atom(atoms::MAX_HEAP_SIZE) {
        sop.use_args = true;
        match crate::natives::proc::parse_max_heap_from(val, sop.max_heap) {
            Ok(limit) => sop.max_heap = limit,
            Err(()) => return false,
        }
    } else if arg == atom(atoms::MIN_BIN_VHEAP_SIZE) && val.as_small().is_some() {
        let size = val.as_small().unwrap_or(-1);
        if size < 0 {
            return false;
        }
        sop.min_vheap_size =
            crate::natives::sys::normalize_spawn_heap_minimum(runtime, Some(size as usize), true);
    } else if arg == atom(atoms::FULLSWEEP_AFTER) && val.as_small().is_some() {
        sop.use_args = true;
        let gcs = val.as_small().unwrap_or(-1);
        if gcs < 0 {
            return false;
        }
        sop.max_gen_gcs = gcs.min(i64::from(u16::MAX)) as u16;
    } else if arg == atom(atoms::SCHEDULER) && val.as_small().is_some() {
        sop.use_args = true;
        let scheduler = val.as_small().unwrap_or(-1);
        let schedulers = runtime
            .and_then(|runtime| runtime.scheduler().ok())
            .map_or(0, |scheduler| scheduler.scheduler_count());
        if scheduler < 0 || schedulers < scheduler as usize {
            return false;
        }
        sop.scheduler = scheduler as usize;
    } else if arg == atom(atoms::REPLY) {
        if !message_opt {
            return false;
        }
        let (no_smsg, no_emsg) = match val {
            v if v == atom(atoms::ERROR_ONLY) => (true, false),
            v if v == atom(atoms::SUCCESS_ONLY) => (false, true),
            v if v == atom(atoms::NO) => (true, true),
            v if v == atom(atoms::YES) => (false, false),
            _ => return false,
        };
        sop.no_smsg = no_smsg;
        sop.no_emsg = no_emsg;
    } else if arg == atom(atoms::REPLY_TAG) {
        let Some(tag) = tag else {
            return false;
        };
        *tag = val;
    } else if arg == atom(atoms::LINK) {
        let Some(priority) = crate::natives::bif::erts_link_opts(val) else {
            return false;
        };
        sop.link_priority = priority;
        sop.link = true;
    } else if arg == atom(atoms::MONITOR) {
        let Some((tag, alias, priority)) = crate::signals::spawn_monitor_options(val) else {
            return false;
        };
        sop.monitor = Some(SpawnMonitor {
            tag,
            alias,
            priority,
        });
    } else {
        return false;
    }
    true
}

/// The child `create_child` has built and inserted but not yet queued.
struct UnscheduledChild {
    spawned: arinsal_sched::SpawnedProcess<Message>,
    seq_spawn: Option<crate::seq_trace::Token>,
}

/// `erl_create_process(parent, mod, func, args, so)`: the child's pid, with `so.mref` set
/// to the monitor or spawn_request reference.
// Port of erts/emulator/beam/erl_process.c:12437 (erl_create_process), OTP-29.1.1. The child
// starts at erlang:apply/3 with `mod`, `func` and `args` in X0..X2, its links and monitors
// exist before it is inserted, the spawn_request reply is queued before it can run, and it is
// added to the parent's run queue last.
pub(crate) fn erl_create_process(
    parent: &mut Process,
    module: Term,
    function: Term,
    args: Term,
    so: &mut ErlSpawnOpts,
) -> Result<Term, CreateError> {
    let parent_pid = parent.self_pid.ok_or(CreateError::SystemLimit)?;
    let alias = so.monitor.as_ref().and_then(|monitor| monitor.alias);
    // The reference is made before the arguments are checked, as erts does.
    let mut monitor_id = None;
    let spawn_ref = if alias.is_some() {
        let id = parent.next_ref();
        monitor_id = Some(id);
        crate::signals::pid_reference(parent, id, parent_pid)?
    } else if so.monitor.is_some() || so.r#async {
        let id = parent.next_ref();
        monitor_id = Some(id);
        crate::signals::reference(parent, id)?
    } else if crate::seq_trace::has_token(parent) {
        crate::signals::reference(parent, parent.next_ref())?
    } else {
        Term::NIL
    };
    if so.monitor.is_some() || so.r#async {
        so.mref = spawn_ref;
    }
    let (Some(m), Some(f), Some(arity)) = (
        module.as_atom(),
        function.as_atom(),
        crate::signals::list_length(args),
    ) else {
        return Err(CreateError::Badarg);
    };
    // `p->u.initial.arity` is a byte here (`Process::initial_mfa`).
    if arity > usize::from(u8::MAX) {
        return Err(CreateError::SystemLimit);
    }
    let monitor_id = so.monitor.as_ref().and(monitor_id);
    let UnscheduledChild { spawned, seq_spawn } = create_child(
        parent,
        parent_pid,
        (module, function, args),
        (m, f, arity),
        so,
        monitor_id,
    )?;
    let pid = spawned.pid();
    let pid_term = pid.to_term().ok_or(CreateError::SystemLimit)?;
    if crate::trace::spawn_interested(parent, parent_pid) {
        trace_spawn(parent, pid, (module, function, args), so.link)?;
    }
    let mut seq_reply_token = None;
    if let Some(request) = seq_spawn.as_ref() {
        seq_reply_token = seq_spawn_events(
            parent,
            parent_pid,
            request,
            pid,
            (module, function, args, arity),
            so,
            spawn_ref,
        )?;
    }
    if so.r#async && !so.no_smsg {
        erts_send_local_spawn_reply(parent, parent_pid, pid, so.tag, spawn_ref, seq_reply_token)?;
    }
    // add2runq on the parent's run queue: the calling scheduler's.
    let esdp = parent
        .native_handle()
        .ok_or_else(|| VmError::Unsupported("spawn outside a normal scheduler".into()))?;
    esdp.schedule_spawned(spawned)
        .map_err(|_| VmError::Unsupported("spawn outside a normal scheduler".into()))?
        .map_err(|error| VmError::Unsupported(format!("schedule spawn: {error}")))?;
    Ok(pid_term)
}

/// `trace_proc_spawn(parent, am_spawn, ...)` and, for a link, `trace_proc(..., am_link, ...)`.
// Port of erts/emulator/beam/erl_process.c (erl_create_process: F_TRACE_PROCS), OTP-29.1.1.
#[cold]
#[inline(never)]
fn trace_spawn(
    parent: &mut Process,
    child: Pid,
    mfa: (Term, Term, Term),
    linked: bool,
) -> Result<(), VmError> {
    let (module, function, args) = mfa;
    let mfa = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut parent.heap);
        let arg_list = TermBuilder::new(&mut heap)
            .list_from_iter(crate::signals::list(args).unwrap_or_default())
            .map_err(|error| VmError::Unsupported(format!("spawn trace args: {error:?}")))?;
        TermBuilder::new(&mut heap)
            .tuple(&[module, function, arg_list])
            .map_err(|error| VmError::Unsupported(format!("spawn trace MFA: {error:?}")))?
    };
    with_sched(parent, |vm, parent, ctx| {
        crate::trace::spawned(vm, parent, ctx, child, mfa, linked);
    })
}

/// The seq_trace events of a spawn: the spawn_request message sent and received and, for a
/// synchronous spawn, the simulated reply. Returns the reply's token.
// Port of erts/emulator/beam/erl_process.c:12818-12832 and 12980-13003 (erl_create_process:
// have_seqtrace), OTP-29.1.1.
#[cold]
#[inline(never)]
fn seq_spawn_events(
    parent: &mut Process,
    parent_pid: Pid,
    request: &crate::seq_trace::Token,
    child: Pid,
    call: (Term, Term, Term, usize),
    so: &ErlSpawnOpts,
    spawn_ref: Term,
) -> Result<Option<crate::seq_trace::Token>, VmError> {
    let (module, function, args, arity) = call;
    let (Some(child_term), Some(parent_term)) = (child.to_term(), parent_pid.to_term()) else {
        return Ok(None);
    };
    let owned = |term: Term| {
        arinsal_term::to_owned(term).unwrap_or_else(|_| arinsal_etf::OwnedTerm::atom("undefined"))
    };
    let group_leader = parent
        .group_leader_pid(parent_pid)
        .to_term()
        .unwrap_or(Term::NIL);
    let arity = Term::small(arity as i64).unwrap_or(Term::NIL);
    let request_message = arinsal_etf::OwnedTerm::tuple(vec![
        arinsal_etf::OwnedTerm::atom("spawn_request"),
        owned(spawn_ref),
        owned(parent_term),
        owned(group_leader),
        arinsal_etf::OwnedTerm::tuple(vec![owned(module), owned(function), owned(arity)]),
        owned(so.opts),
        owned(so.tag),
        owned(args),
    ]);
    let reply_message = arinsal_etf::OwnedTerm::tuple(vec![
        owned(so.tag),
        owned(spawn_ref),
        arinsal_etf::OwnedTerm::atom("ok"),
        owned(child_term),
    ]);
    let synchronous = !so.r#async;
    with_sched(parent, |vm, parent, ctx| {
        Some(crate::seq_trace::spawn_events(
            vm,
            parent,
            ctx,
            request,
            child,
            (request_message, reply_message),
            synchronous,
        ))
    })
}

/// `erts_send_local_spawn_reply(parent, ..., child, tag, ref, result, token)`: `{Tag, Ref, ok,
/// Pid}` queued from the child to the parent before the child can run, so the parent sees it
/// ahead of anything the child sends.
// Port of erts/emulator/beam/erl_process.c:13146 (erts_send_local_spawn_reply), OTP-29.1.1.
fn erts_send_local_spawn_reply(
    parent: &mut Process,
    parent_pid: Pid,
    child: Pid,
    tag: Term,
    reference: Term,
    token: Option<crate::seq_trace::Token>,
) -> Result<(), VmError> {
    let pid_term = child
        .to_term()
        .ok_or_else(|| VmError::Unsupported("pid limit".into()))?;
    let message = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut parent.heap);
        TermBuilder::new(&mut heap)
            .tuple(&[tag, reference, Term::atom(atoms::OK), pid_term])
            .map_err(|error| VmError::Unsupported(format!("spawn reply: {error:?}")))?
    };
    let mut envelope = Message::copy_from(message)?;
    if let Some(token) = token {
        envelope.attach_seq_token(Box::new(token));
    }
    let scheduler = parent
        .runtime
        .ok_or_else(|| VmError::Unsupported("spawn requires a scheduler".into()))?
        .scheduler()?;
    scheduler
        .send(child, parent_pid, envelope)
        .map_err(|error| VmError::Unsupported(format!("spawn_reply: {error}")))
}

/// `erl_create_process` up to the point where the child is linked and ready to be queued: the
/// part that needs only the parent (`c_p`).
// Port of erts/emulator/beam/erl_process.c:12437 (erl_create_process), OTP-29.1.1.
fn create_child(
    parent: &mut Process,
    parent_pid: Pid,
    call: (Term, Term, Term),
    mfa: (Atom, Atom, usize),
    so: &ErlSpawnOpts,
    monitor_id: Option<u64>,
) -> Result<UnscheduledChild, CreateError> {
    let (module, function, args) = call;
    // `p->u.initial`: the spawned MFA, or `so->mfa` of a spawn_request.
    let (m, f, arity) = so.mfa.unwrap_or(mfa);
    // Port of erts/emulator/beam/erl_process.c (erl_create_process: erts_get_runq), OTP-29.1.1:
    // resolve the parent's run queue once and keep its non-owning runtime borrow through enqueue.
    let runtime = parent
        .runtime
        .ok_or_else(|| VmError::Unsupported("spawn requires a scheduler".into()))?;
    let scheduler = runtime.scheduler()?;
    let defaults = crate::natives::sys::gc_spawn_defaults(Some(runtime));
    // `SPO_USE_ARGS`: the parsed values; otherwise H_MIN_SIZE, BIN_VH_MIN_SIZE, H_MAX_SIZE and
    // erts_max_gen_gcs.
    let (min_heap, min_bin_vheap, fullsweep_after, max_heap, priority, bound) = if so.use_args {
        (
            so.min_heap_size,
            so.min_vheap_size,
            so.max_gen_gcs,
            so.max_heap,
            so.priority,
            (so.scheduler != 0).then_some(so.scheduler),
        )
    } else {
        (
            crate::natives::sys::normalize_spawn_heap_minimum(Some(runtime), None, false),
            defaults.min_bin_vheap_size as usize,
            defaults.fullsweep_after,
            defaults.max_heap_size,
            Priority::Normal,
            None,
        )
    };
    let literals = arinsal_term::LiteralAreas::current();
    let arg_size = std::cell::Cell::new(0);
    let parent_alloc_ix = parent.heap.alloc_ix();
    let group_leader = parent.group_leader_pid(parent_pid);
    // Port of erts/emulator/beam/erl_process.c (erl_create_process), OTP-29.1.1: alloc_process
    // takes the process struct and its table entry first, and the fields are then initialized
    // in place.
    let init_child = |child_pid: Pid, child: &mut Process| -> Result<(), VmError> {
        child.set_runtime_with_min_bin_vheap_size(Some(runtime), min_bin_vheap as u64);
        // Both active and user priority come from so->priority; a normal priority is the
        // absent flag (process_info reports `normal` for it).
        if priority != Priority::Normal {
            crate::natives::proc::set_flag(
                child,
                "priority",
                Term::atom(match priority {
                    Priority::Max => atoms::MAX,
                    Priority::High => atoms::HIGH,
                    Priority::Normal => atoms::NORMAL,
                    Priority::Low => atoms::LOW,
                }),
            );
        }
        child.heap.set_fullsweep_after(fullsweep_after);
        // SPO_ASYNC_DIST sets F_ASYNC_DIST; an unset field already reads as false.
        if so.async_dist {
            child.cold_mut().flags.async_dist = Some(Term::atom(atoms::TRUE));
        }
        if !crate::natives::proc::is_default_max_heap(max_heap) {
            child.cold_mut().max_heap = max_heap;
        }
        if let Some(off_heap) = so.off_heap_msgq {
            child.cold_mut().off_heap_msgq = off_heap;
        }
        // `p->i = beam_run_process`: the child's first run installs it (Executor::run) and
        // applies X0..X2.
        child.initial_mfa = Some((m, f, arity as u8));
        child.group_leader = Some(group_leader);
        child.parent = Some(parent_pid);
        // `args` is copied with copy_struct_litopt and the three arg registers take mod, func
        // and the copy.
        let copied_args = {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut child.heap);
            arinsal_term::copy_struct_litopt(args, &mut heap, arg_size.get(), &literals)
                .map_err(|error| VmError::Unsupported(format!("spawn arguments: {error:?}")))?
        };
        child.x[0] = module;
        child.x[1] = function;
        child.x[2] = copied_args;
        // The link must be on the child before it becomes schedulable.
        if so.link {
            child
                .links
                .insert(crate::proc_create::process_link(parent_pid, false));
        }
        if let (Some(id), Some(monitor)) = (monitor_id, so.monitor.as_ref()) {
            // Port of erts/emulator/beam/erl_process.c:12932-12942 (erl_create_process):
            // the child has a pid and remains locked while both monitor halves are installed.
            let (origin, target) = crate::proc_create::create_monitor_with_reference_at(
                parent.heap.alloc_ix(),
                crate::proc_create::monitor_reference(id, monitor.alias, monitor.priority),
                parent_pid.data(),
                child_pid.data(),
                crate::proc_create::MonitorInfo::new(monitor.tag.clone(), None),
                crate::proc_create::OriginMonitor::Process(crate::proc_create::OriginHalf),
            );
            parent.monitors.insert(origin);
            child.lt_monitors.insert(target);
            if monitor.priority {
                parent.cold_mut().prio_monitors.insert(id);
            }
        }
        Ok(())
    };
    let spawned = scheduler.spawn_unscheduled_try_prepare_init(
        || {
            // erts allocates the Process before sizing the copied argument graph and
            // allocating its initial heap.
            let size = arinsal_term::size_object_litopt(args, &literals);
            arg_size.set(size);
            let heap_need = size.saturating_add(arinsal_term::S_RESERVED);
            arinsal_term::spawned_heap_words(heap_need, min_heap)
                .map_err(|error| VmError::Unsupported(format!("spawn heap: {error:?}")))
        },
        |heap_words, slot| {
            crate::proc_create::raw::initialize_spawned(
                slot,
                3,
                heap_words,
                parent_alloc_ix,
                min_heap,
            )
        },
        init_child,
        priority,
        bound,
        parent_alloc_ix,
    );
    let spawned = match spawned {
        Ok(spawned) => spawned,
        Err(arinsal_sched::SpawnInitError::Init(error)) => return Err(CreateError::Vm(error)),
        // Port of erts/emulator/beam/erl_process.c (erl_create_process), OTP-29.1.1:
        // alloc_process logs this before setting SYSTEM_LIMIT when the process table is full.
        Err(arinsal_sched::SpawnInitError::Table(_)) => {
            crate::utils::send_error_to_logger_str(
                runtime,
                parent_pid,
                parent
                    .group_leader_pid(parent_pid)
                    .to_term()
                    .unwrap_or(Term::NIL),
                "Too many processes\n",
            );
            return Err(CreateError::SystemLimit);
        }
    };
    let seq_spawn = if crate::seq_trace::has_token(parent) {
        spawned
            .with_task(|child: &mut Process| {
                crate::seq_trace::spawn_prepare(parent, parent_pid, child)
            })
            .flatten()
    } else {
        None
    };
    if so.link {
        // `erts_link_tree_lookup_insert(&ERTS_P_LINKS(parent), lnk)` with `so->link_oflags`.
        parent.links.insert(crate::proc_create::process_link(
            spawned.pid(),
            so.link_priority,
        ));
    }
    Ok(UnscheduledChild { spawned, seq_spawn })
}
