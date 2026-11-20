use super::*;
use crate::code_ix::{code_tables, erts_active_code_ix};

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
        )
        .map_err(|error| VmError::Unsupported(format!("spawn heap: {error:?}")))?;
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
        // erl_spawn_system_process: `erts_find_function(mod, func, arity)` must succeed; the
        // module is preloaded.
        self.load_named(module)?;
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
        process.static_flags |= crate::proc_create::ERTS_STC_FLG_SYSTEM_PROC;
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
            .spawn_priority_on(process, priority, 0)
            .map_err(|error| VmError::Unsupported(format!("system process {module}: {error}")))?;
        runtime.system_processes.lock().unwrap().insert(pid);
        Ok(pid)
    }

    /// Finishes a module whose `-on_load` is pending the way `code_server` does it: the
    /// on_load function runs in its own process, and only after `finish_after_on_load/2`
    /// the caller's call runs.
    // Port of lib/kernel/src/code_server.erl (handle_on_load, finish_on_load_1) and
    // erts/emulator/beam/beam_bif_load.c (call_on_load_function_1,
    // erts_internal_finish_after_on_load_2), OTP-29.1.1.
    fn run_pending_on_load(
        &mut self,
        module: &str,
        workers: usize,
        reductions: u32,
    ) -> Result<(), VmError> {
        let name = Term::atom(
            arinsal_term::global_atoms()
                .intern(module)
                .map_err(|error| VmError::Load(format!("on_load module name: {error:?}")))?,
        );
        let result = self.eval_scheduled_reductions(
            "erlang",
            "call_on_load_function",
            &[name],
            workers,
            reductions,
        );
        let keep = matches!(&result, Ok(done) if done.text == "ok");
        crate::natives::code::finish_after_on_load(module, keep)
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
        reductions: u32,
    ) -> Result<ScheduledResult, VmError> {
        self.spawn_entry(module, function, args, workers, reductions)?
            .wait()
    }

    /// Spawns `module:function(args)` as an entry process in the running node and returns
    /// without waiting for it: [`EntryProcess::wait`] receives its result. The node must have
    /// been started by [`crate::boot::erl_start`].
    pub(crate) fn spawn_entry(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
        workers: usize,
        reductions: u32,
    ) -> Result<EntryProcess, VmError> {
        let runtime = crate::erl_init::erts_runtime().ok_or_else(|| {
            VmError::Unsupported("the node is not started (boot::erl_start)".into())
        })?;
        if !code_tables(erts_active_code_ix())
            .loaded
            .contains_key(module)
            && !code_tables(erts_active_code_ix())
                .pending_on_load
                .contains_key(module)
            && let Err(error) = self.load_named(module)
            && !code_tables(erts_active_code_ix())
                .pending_on_load
                .contains_key(module)
        {
            return Err(error);
        }
        if code_tables(erts_active_code_ix())
            .pending_on_load
            .contains_key(module)
        {
            self.run_pending_on_load(module, workers, reductions)?;
        }
        let module_id = self.load_named(module)?;
        if code_tables(erts_active_code_ix()).modules[module_id]
            .export(function, args.len() as u32)
            .is_none()
        {
            return Err(VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::UNDEF,
            ))));
        }
        let (process, receiver) = entry_process(runtime, module, function, args)?;
        let scheduler = runtime.scheduler()?;
        let pid = scheduler
            .spawn_unscheduled(process)
            .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        scheduler
            .schedule_unscheduled(pid)
            .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
        Ok(EntryProcess(receiver))
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

/// An entry process applying `module:function(args)`: its arguments copied into its own heap
/// and its result sent to the returned receiver when it exits.
fn entry_process(
    runtime: &'static Runtime,
    module: &str,
    function: &str,
    args: &[Term],
) -> Result<(Process, mpsc::Receiver<Result<ScheduledResult, VmError>>), VmError> {
    let mut process = Process::with_spawn_registers(3);
    // Port of erts/emulator/beam/erl_process.c (erl_create_process: copy_struct of the
    // arguments into the new heap), OTP-29.1.1: the process owns its arguments, so a
    // collection never meets a term outside its heap and the literal areas.
    let literals = arinsal_term::LiteralAreas::current();
    let mut copied = Vec::with_capacity(args.len());
    for &arg in args {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        copied.push(
            arinsal_term::copy_term_litopt(arg, &mut heap, &literals)
                .map_err(|error| VmError::Load(format!("entry process arguments: {error:?}")))?,
        );
    }
    let arity =
        u8::try_from(args.len()).map_err(|_| VmError::Load("entry process arguments".into()))?;
    let (module_atom, function_atom, _) = mfa_atoms(module, function, arity)
        .ok_or_else(|| VmError::Load(format!("{module}:{function} name")))?;
    let args = arinsal_term::TermBuilder::new(&mut process.heap)
        .list_from_slice(&copied)
        .map_err(|error| VmError::Load(format!("entry process arguments: {error:?}")))?;
    process.set_runtime(Some(runtime));
    process.start_at_run_process(module_atom, function_atom, args, arity)?;
    process.entry = true;
    let (sender, receiver) = mpsc::channel();
    *runtime.result.lock().unwrap() = sender;
    Ok((process, receiver))
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
        // No entry process yet: the first one installs its own result channel.
        let (result, _) = mpsc::channel();
        Box::leak(Box::new(Runtime {
            statistics: crate::natives::sys::StatisticsState::new(
                crate::natives::sys::erts_statistics_origins(),
            ),
            code,
            trap_exports: std::array::from_fn(|_| OnceLock::new()),
            system_processes: Mutex::new(std::collections::HashSet::new()),
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
            result: Mutex::new(result),
            code_mod_permission: Mutex::new(crate::natives::code::CodeModPermission::default()),
            breakpoints: Arc::new(crate::trace_bp::BpNode::new()),
            debug_wait_active: AtomicBool::new(false),
            system_flags: Mutex::new(crate::natives::sys::SystemFlags::boot()),
            gc_defaults: crate::natives::sys::GcDefaults::boot(),
            persistent_terms: arinsal_pterm::global_store(),
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
                scheduler.thread_progress_later(move || retired.release());
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

/// A running evaluation of [`Vm::eval_scheduled`] in a started node.
pub struct EntryProcess(mpsc::Receiver<Result<ScheduledResult, VmError>>);

impl EntryProcess {
    /// Blocks until the entry process exits and returns its result.
    pub fn wait(self) -> Result<ScheduledResult, VmError> {
        let result = self
            .0
            .recv()
            .map_err(|_| VmError::Unsupported("entry process disappeared".into()))?;
        while arinsal_pterm::global_store().has_retired() {
            std::thread::park_timeout(std::time::Duration::from_millis(1));
        }
        result
    }
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
