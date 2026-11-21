use super::*;
use std::sync::OnceLock;

/// `+S` for the in-process test node, recorded before `erl_start`.
static EVAL_PLUS_S: OnceLock<usize> = OnceLock::new();

impl Runtime {
    /// Create a distributed child with its remote monitor (and optional link) installed before
    /// it can run.
    // Port of erts/emulator/beam/erl_process.c:12940-13152 (erl_create_process, so->mref
    // monitor insertion), OTP-29.1.1: a spawn_request monitor lives in the child from creation,
    // so a child that exits at once still sends its own exit reason in the DOWN.
    pub(crate) fn spawn_mfa_unscheduled_watched(
        &'static self,
        module: &str,
        function: &str,
        args: &[arinsal_etf::OwnedTerm],
        linker: Option<Pid>,
        monitor: Option<crate::proc_create::DistOrigin>,
        parent: &arinsal_etf::OwnedTerm,
    ) -> Result<Pid, VmError> {
        self.spawn_mfa_scheduled(module, function, args, linker, monitor, Some(parent))
    }

    fn spawn_mfa_scheduled(
        &'static self,
        module: &str,
        function: &str,
        args: &[arinsal_etf::OwnedTerm],
        linker: Option<Pid>,
        monitor: Option<crate::proc_create::DistOrigin>,
        parent: Option<&arinsal_etf::OwnedTerm>,
    ) -> Result<Pid, VmError> {
        let arity = u8::try_from(args.len())
            .map_err(|_| VmError::Unsupported("spawn: too many arguments".into()))?;
        let (module_atom, function_atom, _) = mfa_atoms(module, function, arity)
            .ok_or_else(|| VmError::Unsupported("spawn: bad module or function name".into()))?;
        // Port of erts/emulator/beam/erl_process.c (erl_create_process: `arg_size =
        // size_object_litopt(args)`, `heap_need = arg_size + S_RESERVED`, the initial heap
        // allocated once at `erts_next_heap_size(heap_need)` and `copy_struct_litopt` of the
        // whole argument list into it), OTP-29.1.1. The decoded request arguments first sit
        // apart from the child, as the dist message's heap fragment does in dist.c
        // (DOP_SPAWN_REQUEST), so the child's heap is sized by the copied list.
        let literals = arinsal_term::LiteralAreas::current();
        let mut decoded = arinsal_term::ProcessHeap::with_words(0);
        let owned_args = arinsal_etf::OwnedTerm::List {
            elems: args.to_vec(),
            tail: Box::new(arinsal_etf::OwnedTerm::Nil),
        };
        let decoded_args = if args.is_empty() {
            Term::NIL
        } else {
            arinsal_term::from_owned(
                &owned_args,
                &mut arinsal_bifs::ProcessHeapHandle(&mut decoded),
            )
            .map_err(|_| VmError::Unsupported("spawn argument decode failed".into()))?
        };
        let arg_size = arinsal_term::size_object_litopt(decoded_args, &literals);
        let min_heap = crate::natives::sys::normalize_spawn_heap_minimum(Some(self), None, false);
        let heap_words = arinsal_term::spawned_heap_words(
            arg_size.saturating_add(arinsal_term::S_RESERVED),
            min_heap,
        );
        let mut child =
            Process::with_spawn_registers_sized(args.len().max(3), heap_words, min_heap);
        child.set_runtime(Some(self));
        child.cold_mut().group_leader = None;
        // Port of erts/emulator/beam/erl_process.c:12756-12767 (erl_create_process p->parent),
        // OTP-29.1.1: a remote parent is kept as its external pid.
        if let Some(parent) = parent {
            child.cold_mut().parent_external = Some(Box::new(parent.clone()));
        }
        if let Some(linker) = linker {
            child
                .links
                .insert(crate::proc_create::process_link(linker, false));
        }
        let copied_args = arinsal_term::copy_struct_litopt(
            decoded_args,
            &mut arinsal_bifs::ProcessHeapHandle(&mut child.heap),
            arg_size,
            &literals,
        )
        .map_err(|error| VmError::Unsupported(format!("spawn arguments: {error:?}")))?;
        drop(decoded);
        // erl_create_process: every MFA, a BIF's too, starts at beam_run_process, which
        // applies X0..X2 through the export.
        child.start_at_run_process(module_atom, function_atom, copied_args, arity)?;
        let scheduler = self.scheduler()?;
        let Some(monitor) = monitor else {
            return scheduler
                .spawn_unscheduled(child)
                .map_err(|error| VmError::Unsupported(format!("spawn: {error}")));
        };
        // Port of erts/emulator/beam/erl_process.c (erl_create_process, SPO_MONITOR with a
        // remote parent), OTP-29.1.1: the origin half goes into the connection and the target
        // half into the child's monitor tree, or both are released when the connection is
        // gone.
        let spawned = scheduler
            .spawn_unscheduled_init(
                || child,
                |pid, child: &mut Process| {
                    crate::dist::insert_spawn_child_monitor(child, pid, monitor);
                    Ok::<(), std::convert::Infallible>(())
                },
                arinsal_sched::Priority::Normal,
                None,
            )
            .map_err(|error| match error {
                arinsal_sched::SpawnInitError::Table(error) => {
                    VmError::Unsupported(format!("spawn: {error}"))
                }
                arinsal_sched::SpawnInitError::Init(never) => match never {},
            })?;
        Ok(spawned.pid())
    }

    /// Schedule a distributed child after its spawn reply was queued.
    pub(crate) fn schedule_spawn(&self, pid: Pid) -> Result<(), VmError> {
        self.scheduler()?
            .schedule_unscheduled(pid)
            .map_err(|error| VmError::Unsupported(format!("spawn schedule: {error}")))
    }
}

impl Vm {
    /// Spawns `module:function(args)` as a system process on the boot scheduler before any
    /// scheduler thread runs: `SPO_SYSTEM_PROC` sets `ERTS_STC_FLG_SYSTEM_PROC`, so its
    /// termination brings the node down.
    // Port of erts/emulator/beam/erl_init.c:335 (erl_spawn_system_process) through
    // erl_process.c (erl_create_process, `so->flags & SPO_SYSTEM_PROC`), OTP-29.1.1.
    fn erl_spawn_system_process(
        &mut self,
        runtime: &'static Runtime,
        module: &str,
        function: &str,
        args: &[Term],
        priority: arinsal_sched::Priority,
    ) -> Result<Pid, VmError> {
        let mut process = Process::with_spawn_registers(args.len().max(3));
        // erl_create_process: copy_struct of the arguments into the new heap.
        let literals = arinsal_term::LiteralAreas::current();
        let mut copied = Vec::with_capacity(args.len());
        for &arg in args {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            copied.push(
                arinsal_term::copy_term_litopt(arg, &mut heap, &literals).map_err(|error| {
                    VmError::Load(format!("system process {module} arguments: {error:?}"))
                })?,
            );
        }
        let arity = u8::try_from(args.len())
            .map_err(|_| VmError::Load(format!("system process {module} arguments")))?;
        let (module_atom, function_atom, _) = mfa_atoms(module, function, arity)
            .ok_or_else(|| VmError::Load(format!("{module}:{function}/{arity} name")))?;
        let args = arinsal_term::TermBuilder::new(&mut process.heap)
            .list_from_slice(&copied)
            .map_err(|error| VmError::Load(format!("system process {module}: {error:?}")))?;
        process.set_runtime(Some(runtime));
        // erl_create_process starts every MFA at beam_run_process.
        process.start_at_run_process(module_atom, function_atom, args, arity)?;
        if priority != arinsal_sched::Priority::Normal {
            let name = match priority {
                arinsal_sched::Priority::Max => "max",
                arinsal_sched::Priority::High => "high",
                arinsal_sched::Priority::Normal => "normal",
                arinsal_sched::Priority::Low => "low",
            };
            crate::natives::proc::set_flag(&mut process, "priority", crate::atom_cache::put(name));
        }
        // erl_system_process_otp: `so.scheduler = 0`; erl_create_process enqueues on the
        // creating (boot) scheduler's run queue, before the other schedulers exist.
        let pid = runtime
            .scheduler()?
            .spawn_priority_on(
                process,
                priority,
                0,
                // erl_system_process_otp: `so.flags |= SPO_SYSTEM_PROC`.
                crate::proc_create::ERTS_STC_FLG_SYSTEM_PROC,
            )
            .map_err(|error| VmError::Unsupported(format!("system process {module}: {error}")))?;
        Ok(pid)
    }

    /// Record `+S N:N` for the in-process test node. erts sizes schedulers in
    /// `erl_start` from `+S`; this must run before [`crate::boot::erl_start`].
    pub fn request_eval_plus_s(workers: usize) {
        if workers > 0 {
            let _ = EVAL_PLUS_S.get_or_init(|| workers);
        }
    }

    /// `+S` recorded by [`Self::request_eval_plus_s`] or [`Self::eval_scheduled`].
    pub fn requested_eval_plus_s() -> Option<usize> {
        EVAL_PLUS_S.get().copied()
    }

    /// Run an exported function with schedulable BEAM processes.
    pub fn eval_scheduled(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
        workers: usize,
    ) -> Result<ScheduledResult, VmError> {
        self.eval_scheduled_reductions(module, function, args, workers, 4_000)
    }

    /// Executes one exported function in a fresh process: BIFs and the `erlang` fun builtins
    /// in place ([`Vm::eval`]), Erlang code natively under the scheduler. The result term
    /// lives in a process heap the result retains.
    pub fn eval_exported(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
    ) -> Result<crate::EvalResult, VmError> {
        let direct = arinsal_bifs::lookup(module, function, args.len() as u8).is_some()
            || crate::natives::static_nif_lookup(module, function, args.len() as u8).is_some()
            || module == "erlang"
                && matches!(
                    (function, args.len()),
                    ("apply", 2 | 3) | ("make_fun", 3) | ("fun_info", 1 | 2)
                );
        if direct {
            return self.eval(module, function, args);
        }
        self.eval_in_scheduled_process(module, function, args)
    }

    /// Runs `module:function(args)` in a scheduled process and copies the result into a
    /// fresh process heap: Erlang code runs only natively, in a process of its own.
    pub(crate) fn eval_in_scheduled_process(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
    ) -> Result<crate::EvalResult, VmError> {
        let scheduled = self.eval_scheduled(module, function, args, 1)?;
        let mut process = Process::new();
        let term = {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            arinsal_term::from_owned(&scheduled.term, &mut heap)
                .map_err(|error| VmError::Unsupported(format!("eval result: {error:?}")))?
        };
        Ok(crate::EvalResult {
            term,
            stats: scheduled.stats,
            _process: process,
        })
    }

    /// [`Vm::eval_scheduled`] with an explicit reduction quantum.
    ///
    /// A quantum of 1 yields on `wait` after `loop_rec` has observed an empty
    /// mailbox. The next slice drains the ingress before that `wait` runs.
    pub fn eval_scheduled_reductions(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
        workers: usize,
        _reductions: u32,
    ) -> Result<ScheduledResult, VmError> {
        // Port of erlexec `+S` for the node: honour the workers argument as
        // `+S N:N` when the node has not started yet (nextest: one node per OS process).
        Self::request_eval_plus_s(workers);
        self.spawn_entry(module, function, args)?.wait()
    }

    /// Spawns `module:function(args)` as an entry process in the running node and returns
    /// without waiting for it: [`EntryProcess::wait`] receives its result. The node must have
    /// been started by [`crate::boot::erl_start`].
    pub(crate) fn spawn_entry(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
    ) -> Result<EntryProcess, VmError> {
        let runtime = crate::erl_init::erts_runtime().ok_or_else(|| {
            VmError::Unsupported("the node is not started (boot::erl_start)".into())
        })?;
        // The evaluated call runs in an ordinary process the carrier spawns on the node.
        let _ = runtime;
        eval_carrier_request(module, function, args)
    }

    /// Spawns `erl_init:start(Modname, Argv)` as the node's first process, before any
    /// scheduler thread runs; it gets the first pid (`erts_init_process_id`). It is a system
    /// process: when it terminates the node ends (erl_process.c:14186).
    // Port of erts/emulator/beam/erl_init.c:356 (erl_first_process_otp), OTP-29.1.1.
    pub(crate) fn erl_first_process_otp(
        &mut self,
        runtime: &'static Runtime,
        modname: Term,
        argv: Term,
    ) -> Result<Pid, VmError> {
        let pid = self.erl_spawn_system_process(
            runtime,
            "erl_init",
            "start",
            &[modname, argv],
            arinsal_sched::Priority::Normal,
        )?;
        runtime
            .init_process_id
            .set(pid)
            .map_err(|_| VmError::Unsupported("erts_init_process_id already set".into()))?;
        Ok(pid)
    }

    /// The system processes that are always alive, spawned after the first process and before
    /// the scheduler threads start.
    // Port of erts/emulator/beam/erl_init.c:2544-2606 (erl_start: erl_system_process_otp for
    // erts_code_purger, erts_literal_area_collector, three erts_dirty_process_signal_handler
    // and erts_trace_cleaner), OTP-29.1.1.
    pub(crate) fn erl_system_processes_otp(
        &mut self,
        runtime: &'static Runtime,
    ) -> Result<(), VmError> {
        use arinsal_sched::Priority;
        // erl_system_process_otp(erts_init_process_id, name, off_heap_msgq, prio).
        self.erl_spawn_system_process(runtime, "erts_code_purger", "start", &[], Priority::High)?;
        let literal_collector = self.erl_spawn_system_process(
            runtime,
            "erts_literal_area_collector",
            "start",
            &[],
            Priority::High,
        )?;
        *runtime.literal_collector.lock().unwrap() = Some(literal_collector);
        let mut handlers = Vec::with_capacity(3);
        for priority in [Priority::Normal, Priority::High, Priority::Max] {
            let pid = self.erl_spawn_system_process(
                runtime,
                "erts_dirty_process_signal_handler",
                "start",
                &[],
                priority,
            )?;
            runtime.dirty_signal_handlers.lock().unwrap().insert(pid);
            handlers.push(pid);
        }
        runtime.scheduler()?.set_dirty_signal_handlers(
            handlers[0],
            handlers[1],
            handlers[2],
            |pid| pid.to_term().and_then(|term| Message::copy_from(term).ok()),
        );
        self.erl_spawn_system_process(
            runtime,
            "erts_trace_cleaner",
            "start",
            &[],
            Priority::Normal,
        )?;
        Ok(())
    }
}

impl Runtime {
    /// The node's runtime-system tables, built once by `erl_init` before the preloaded
    /// modules load: the process and port tables, the registered-name table, ETS, the trap
    /// exports and the statistics state. The scheduler is installed by
    /// [`Runtime::erts_init_scheduling`].
    // Port of erts/emulator/beam/erl_init.c:248 (erl_init: erts_init_process, erts_ptab_init,
    // init_register_table, init_db, erts_init_io, erts_init_bif), OTP-29.1.1.
    pub(crate) fn erl_init_tables() -> &'static Runtime {
        let code = Arc::clone(crate::code_ix::global());
        let port_layout = arinsal_term::ptab::port_table_layout();
        let port_ids = PtabIdRing::new(port_layout.max());
        let named_ets = Arc::new(arinsal_ets::NamedTableIndex::new());
        Box::leak(Box::new(Runtime {
            statistics: crate::natives::sys::StatisticsState::new(
                crate::natives::sys::erts_statistics_origins(),
            ),
            code,
            trap_exports: std::array::from_fn(|_| OnceLock::new()),
            dirty_signal_handlers: Mutex::new(std::collections::HashSet::new()),
            literal_collector: Mutex::new(None),
            init_process_id: OnceLock::new(),
            scheduler: OnceLock::new(),
            reg: crate::register::RegisterTable::new(),
            next_trace_weak_id: AtomicU64::new(0),
            ports: crate::port::PortTable::new(port_layout),
            forker_port: OnceLock::new(),
            system_monitor: Mutex::new(None),
            session_monitors: Mutex::new(Vec::new()),
            system_monitor_flags: AtomicU8::new(0),
            long_message_queues: Mutex::new(Vec::new()),
            port_ids,
            named_ets: Arc::clone(&named_ets),
            ets: std::sync::RwLock::new(arinsal_ets::Registry::new_with_named_index(named_ets)),
            code_mod_permission: Mutex::new(crate::natives::code::CodeModPermission::default()),
            breakpoints: Arc::new(crate::trace_bp::BpNode::new()),
            debug_wait_active: AtomicBool::new(false),
            system_flags: Mutex::new(crate::natives::sys::SystemFlags::boot()),
            gc_defaults: crate::natives::sys::GcDefaults::boot(),
            persistent_terms: arinsal_pterm::global_store(),
            persistent_term_later_op: arinsal_sched::ErtsThrPrgrLaterOp::new(),
            persistent_term_resume_pid: AtomicU64::new(0),
            persistent_term_resume_owner: AtomicU64::new(0),
            multi_scheduling: Mutex::new(MultiScheduling::default()),
        }))
    }

    /// Builds the run queues and scheduler data for `workers` normal schedulers without
    /// starting a thread, and attaches the tables that free through thread progress.
    // Port of erts/emulator/beam/erl_process.c:6090 (erts_init_scheduling), called from
    // erl_init.c:248 (erl_init), OTP-29.1.1.
    pub(crate) fn erts_init_scheduling(&'static self, workers: usize) -> Result<(), VmError> {
        let (dirty_cpu_schedulers, dirty_cpu_online, dirty_io_schedulers) =
            crate::natives::sys::dirty_scheduler_defaults(self);
        let scheduler_options = arinsal_args::active_scheduler_options().0;
        let config = Config {
            workers,
            // CONTEXT_REDS (erl_vm.h).
            reductions: 4_000,
            dirty_cpu_schedulers,
            dirty_io_schedulers,
            compact_load: scheduler_options.compact_load.unwrap_or(true),
            utilization_balancing: scheduler_options.utilization_balancing.unwrap_or(false),
            busy_wait_thresholds: scheduler_options.busy_wait,
            wakeup_thresholds: scheduler_options.wakeup,
            forced_wakeup_interval: scheduler_options.forced_wakeup_interval,
            port_parallelism: scheduler_options.port_parallelism,
            scheduler_bind_type: scheduler_options.bind_type,
            sched_thread_stack_sizes: std::array::from_fn(|index| {
                scheduler_options.stack_sizes[index]
                    .unwrap_or(arinsal_sched::ERTS_DEFAULT_SCHED_STACK_SIZES[index])
            }),
            max_processes: arinsal_term::ptab::process_table_layout().max(),
        };
        // `erts_no_schedulers` is what `system_info(schedulers)` reports; a run with fewer
        // worker threads than that keeps the layout of the reported scheduler count.
        arinsal_sched::unique::init_unique_scheduler_count(
            config.workers.max(crate::natives::sys::schedulers_total()) as u32,
            config.dirty_cpu_schedulers as u32,
            config.dirty_io_schedulers as u32,
        );
        // Port of erts/emulator/beam/erl_cpu_topology.c:1705-1708 (max_main_threads) and
        // ethr_mutex.c:151-166 (ethr_mutex_lib_late_init): the table locks' spin count grows
        // with the number of main threads, the schedulers on configured CPUs.
        arinsal_ets::rwmtx::set_main_threads(
            config
                .workers
                .min(arinsal_alloc::cpuinfo::cpu_info().configured.max(1)),
        );
        let scheduler = Arc::new(Scheduler::erts_init_scheduling(config, dirty_cpu_online));
        let online = crate::natives::sys::scheduler_online_default(self);
        let _ = scheduler.set_online_schedulers(online.min(workers.max(1)));
        self.ports.attach(scheduler.progress());
        self.scheduler
            .set(scheduler)
            .map_err(|_| VmError::Unsupported("runtime scheduler already set".into()))?;
        // Port of code_ix.c:142-171 and beam_common.c (erts_schedule_code_barrier),
        // OTP-29.1.1: code-table owners retire through this scheduler's progress queue.
        let scheduler = Arc::downgrade(self.scheduler()?);
        self.code.set_retire_hook(move |retired| {
            if let Some(scheduler) = scheduler.upgrade() {
                retired.schedule(&scheduler);
            } else {
                // The scheduler is gone only after shutdown joined its workers.
                retired.release();
            }
        });
        Ok(())
    }

    /// Starts the scheduler threads once the first process and the system processes exist.
    // Port of erts/emulator/beam/erl_process.c:8909 (erts_start_schedulers), OTP-29.1.1.
    pub(crate) fn erts_start_schedulers(&self) -> Result<(), VmError> {
        self.scheduler()?.erts_start_schedulers();
        Ok(())
    }
}

/// An evaluation sent to the eval carrier: [`EntryProcess::wait`] receives its result.
pub struct EntryProcess(u64);

impl EntryProcess {
    /// Blocks until the carrier reports the evaluation's result or exception.
    pub fn wait(self) -> Result<ScheduledResult, VmError> {
        let carrier = EVAL_CARRIER
            .get()
            .ok_or_else(|| VmError::Unsupported("no eval carrier on this node".into()))?;
        decode_carrier_reply(carrier.wait(self.0)?)
    }
}

/// The host ends of the eval carrier's pipes: requests go to the node's `{fd,R,W}` port and
/// replies come back from it, `{packet, 4}` framed external term format.
///
/// Test harness of [`Vm::eval_scheduled`], not an erts structure: erts evaluates code only in
/// processes, and a host talks to a node through a port, as `arinsal_difftest::RefErl` does
/// with a real erl. The carrier (`eval_carrier/arinsal_eval_carrier.erl`) is started by
/// init's `-run`.
struct EvalCarrier {
    requests: Mutex<std::io::PipeWriter>,
    replies: Mutex<CarrierReplies>,
    arrived: std::sync::Condvar,
    next_id: AtomicU64,
}

struct CarrierReplies {
    /// `None` while one waiter reads a frame outside the lock.
    reader: Option<std::io::PipeReader>,
    done: std::collections::HashMap<u64, arinsal_etf::OwnedTerm>,
}

static EVAL_CARRIER: OnceLock<EvalCarrier> = OnceLock::new();

/// Creates the carrier's pipes and returns the boot arguments that start it:
/// `-pa <code_dir> -run arinsal_eval_carrier start R W`, `R`/`W` being the node's pipe ends and
/// `code_dir` the directory holding `arinsal_eval_carrier.beam`.
pub(crate) fn eval_carrier_args(code_dir: &std::path::Path) -> Result<Vec<String>, VmError> {
    use std::os::fd::IntoRawFd;
    let pipe_error =
        |error: std::io::Error| VmError::Unsupported(format!("eval carrier pipe: {error}"));
    let (node_reader, host_writer) = std::io::pipe().map_err(pipe_error)?;
    let (host_reader, node_writer) = std::io::pipe().map_err(pipe_error)?;
    EVAL_CARRIER
        .set(EvalCarrier {
            requests: Mutex::new(host_writer),
            replies: Mutex::new(CarrierReplies {
                reader: Some(host_reader),
                done: std::collections::HashMap::new(),
            }),
            arrived: std::sync::Condvar::new(),
            next_id: AtomicU64::new(0),
        })
        .map_err(|_| VmError::Unsupported("eval carrier already started".into()))?;
    // The node's fd port owns these ends from now on.
    let read_fd = node_reader.into_raw_fd();
    let write_fd = node_writer.into_raw_fd();
    Ok(vec![
        "-pa".into(),
        code_dir.display().to_string(),
        "-run".into(),
        "arinsal_eval_carrier".into(),
        "start".into(),
        read_fd.to_string(),
        write_fd.to_string(),
    ])
}

/// Sends `{Id, Module, Function, Args}` to the carrier.
fn eval_carrier_request(
    module: &str,
    function: &str,
    args: &[Term],
) -> Result<EntryProcess, VmError> {
    use std::io::Write;
    let carrier = EVAL_CARRIER
        .get()
        .ok_or_else(|| VmError::Unsupported("no eval carrier on this node".into()))?;
    let mut owned_args = Vec::with_capacity(args.len());
    for &arg in args {
        owned_args.push(
            arinsal_term::to_owned(arg)
                .map_err(|error| VmError::Unsupported(format!("eval argument: {error:?}")))?,
        );
    }
    let id = carrier.next_id.fetch_add(1, Ordering::Relaxed);
    // The arguments travel as their own external term, decoded apart by the carrier.
    let args_ext = arinsal_etf::encode(
        &arinsal_etf::OwnedTerm::List {
            elems: owned_args,
            tail: Box::new(arinsal_etf::OwnedTerm::Nil),
        },
        arinsal_etf::EncodeOptions::default(),
    );
    let request = arinsal_etf::OwnedTerm::Tuple(vec![
        arinsal_etf::OwnedTerm::Int(id as i64),
        arinsal_etf::OwnedTerm::Atom(module.into()),
        arinsal_etf::OwnedTerm::Atom(function.into()),
        arinsal_etf::OwnedTerm::Binary(args_ext),
    ]);
    let bytes = arinsal_etf::encode(&request, arinsal_etf::EncodeOptions::default());
    let length = u32::try_from(bytes.len())
        .map_err(|_| VmError::Unsupported("eval request too large".into()))?;
    let mut writer = carrier.requests.lock().unwrap();
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(&bytes))
        .map_err(|error| VmError::Unsupported(format!("eval carrier write: {error}")))?;
    Ok(EntryProcess(id))
}

impl EvalCarrier {
    /// The reply to request `id`. One waiter at a time reads frames; replies to other requests
    /// are kept for their waiters.
    fn wait(&self, id: u64) -> Result<arinsal_etf::OwnedTerm, VmError> {
        use std::io::Read;
        let mut replies = self.replies.lock().unwrap();
        loop {
            if let Some(reply) = replies.done.remove(&id) {
                return Ok(reply);
            }
            let Some(mut reader) = replies.reader.take() else {
                replies = self.arrived.wait(replies).unwrap();
                continue;
            };
            drop(replies);
            let mut frame = || -> Result<arinsal_etf::OwnedTerm, VmError> {
                let read_error = |error: std::io::Error| {
                    VmError::Unsupported(format!("eval carrier read: {error}"))
                };
                let mut length = [0u8; 4];
                reader.read_exact(&mut length).map_err(read_error)?;
                let mut bytes = vec![0u8; u32::from_be_bytes(length) as usize];
                reader.read_exact(&mut bytes).map_err(read_error)?;
                arinsal_etf::decode(&bytes)
                    .map_err(|error| VmError::Unsupported(format!("eval carrier reply: {error}")))
            };
            let result = frame();
            replies = self.replies.lock().unwrap();
            replies.reader = Some(reader);
            self.arrived.notify_all();
            let reply = result?;
            let arinsal_etf::OwnedTerm::Tuple(parts) = &reply else {
                return Err(VmError::Unsupported("eval carrier reply shape".into()));
            };
            let [arinsal_etf::OwnedTerm::Int(reply_id), body] = parts.as_slice() else {
                return Err(VmError::Unsupported("eval carrier reply shape".into()));
            };
            replies.done.insert(*reply_id as u64, body.clone());
        }
    }
}

/// `{ok, Value, TotalHeapSize, MinorGcs}` or `{Class, Reason, Stack}`.
fn decode_carrier_reply(reply: arinsal_etf::OwnedTerm) -> Result<ScheduledResult, VmError> {
    use arinsal_etf::OwnedTerm;
    let shape = || VmError::Unsupported("eval carrier result shape".into());
    let OwnedTerm::Tuple(parts) = &reply else {
        return Err(shape());
    };
    let (tag, first, rest) = match parts.as_slice() {
        [OwnedTerm::Atom(tag), first, rest @ ..] => (tag.as_str(), first.clone(), rest),
        _ => return Err(shape()),
    };
    let class = match tag {
        "ok" => {
            let [OwnedTerm::Int(heap), OwnedTerm::Int(gcs)] = rest else {
                return Err(shape());
            };
            let mut stats = crate::Stats {
                heap_words: *heap as usize,
                ..crate::Stats::default()
            };
            stats.gc.collections = *gcs as u64;
            stats.gc.minor_collections = *gcs as u64;
            return Ok(ScheduledResult {
                text: format!("{first}"),
                term: first,
                stats,
            });
        }
        "error" => arinsal_bifs::Class::Error,
        "exit" => arinsal_bifs::Class::Exit,
        "throw" => arinsal_bifs::Class::Throw,
        _ => return Err(shape()),
    };
    let [stack] = rest else {
        return Err(shape());
    };
    let stack = stack.clone();
    Err(VmError::Raised(Box::new(crate::exceptions::Raised {
        class,
        reason: first,
        stack,
    })))
}

/// Scheduler class of a scheduler type, for matching rescheduled NIF calls.
pub(super) fn scheduler_class(kind: arinsal_sched::SchedulerType) -> arinsal_bifs::SchedulerClass {
    match kind {
        arinsal_sched::SchedulerType::Normal => arinsal_bifs::SchedulerClass::Normal,
        arinsal_sched::SchedulerType::DirtyCpu => arinsal_bifs::SchedulerClass::DirtyCpu,
        arinsal_sched::SchedulerType::DirtyIo => arinsal_bifs::SchedulerClass::DirtyIo,
    }
}

/// `p->u.initial` for a system or spawned MFA given by name (atoms, as erts keeps them).
fn mfa_atoms(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<(arinsal_term::Atom, arinsal_term::Atom, u8)> {
    let module = crate::atom_cache::put(module).as_atom()?;
    let function = crate::atom_cache::put(function).as_atom()?;
    Some((module, function, arity))
}
