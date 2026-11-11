use super::*;

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
    fn spawn_system_process(
        &mut self,
        scheduler: &Scheduler<Process>,
        runtime: &'static Runtime,
        module: &str,
        function: &str,
    ) -> Result<Pid, VmError> {
        self.spawn_system_process_priority(
            scheduler,
            runtime,
            module,
            function,
            arinsal_sched::Priority::Normal,
        )
    }

    // Port of erts/emulator/beam/erl_init.c:402 (erl_system_process_otp), OTP-29.1.1.
    fn spawn_system_process_priority(
        &mut self,
        scheduler: &Scheduler<Process>,
        runtime: &'static Runtime,
        module: &str,
        function: &str,
        priority: arinsal_sched::Priority,
    ) -> Result<Pid, VmError> {
        // The module is preloaded before the process applies it, as erts preloads system modules.
        self.load_named(module)?;
        let (module_atom, function_atom, _) = mfa_atoms(module, function, 0)
            .ok_or_else(|| VmError::Load(format!("{module}:{function}/0 name")))?;
        let mut process = Process::with_spawn_registers(3);
        process.set_runtime(Some(runtime));
        // Port of erts/emulator/beam/erl_init.c:402 (erl_system_process_otp): spawned with `NIL`
        // arguments through erl_create_process, which starts at beam_run_process.
        process.start_at_run_process(module_atom, function_atom, Term::NIL, 0)?;
        if priority != arinsal_sched::Priority::Normal {
            let name = match priority {
                arinsal_sched::Priority::Max => "max",
                arinsal_sched::Priority::High => "high",
                arinsal_sched::Priority::Normal => "normal",
                arinsal_sched::Priority::Low => "low",
            };
            crate::natives::proc::set_flag(&mut process, "priority", crate::atom_cache::put(name));
        }
        // erl_init creates system processes on the boot scheduler, before other
        // schedulers have left scheduler_wait. Spreading them wakes those
        // schedulers and they steal the first user processes.
        let pid = scheduler
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
        simulation_seed: Option<u64>,
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
            simulation_seed,
            reductions,
        );
        let keep = matches!(&result, Ok(done) if done.text == "ok");
        crate::natives::code::finish_after_on_load(self, module, keep)
    }

    /// Run an exported function with schedulable BEAM processes.
    pub fn eval_scheduled(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
        workers: usize,
        simulation_seed: Option<u64>,
    ) -> Result<ScheduledResult, VmError> {
        self.eval_scheduled_reductions(module, function, args, workers, simulation_seed, 4_000)
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
        let scheduled = self.eval_scheduled(module, function, args, 1, None)?;
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
        simulation_seed: Option<u64>,
        reductions: u32,
    ) -> Result<ScheduledResult, VmError> {
        // A booted node gets these from erl_features:init_features/0 during the
        // boot, exactly like erts; seeding them earlier would also give the
        // feature atoms indices erts does not give them.
        if module != "erl_init" {
            initialize_feature_defaults(arinsal_pterm::store_for(self.code_scope))?;
        }
        if self.child_setup.is_none() {
            self.child_setup = Some(crate::child_setup::start().map_err(|error| {
                VmError::Load(format!("cannot start erl_child_setup: {error}"))
            })?);
        }
        self.refresh_code();
        if !self.code.loaded.contains_key(module)
            && !self.code.pending_on_load.contains_key(module)
            && let Err(error) = self.load_named(module)
            && !self.code.pending_on_load.contains_key(module)
        {
            return Err(error);
        }
        if self.code.pending_on_load.contains_key(module) {
            self.run_pending_on_load(module, workers, simulation_seed, reductions)?;
        }
        let module_id = self.load_named(module)?;
        // Port of erts/emulator/beam/erl_init.c:508 (load_preloaded), OTP-29.1.1:
        // erts_internal is preloaded, so the `erts_internal:await_result/1` trap of every
        // request BIF finds it loaded. A bare VM loads modules on first call; that load needs
        // the staging permission a running purge holds, and the trapping caller would wait for it.
        if module != "erl_init" {
            let _ = self.load_named("erts_internal");
        }
        if self.code.modules[module_id]
            .export(function, args.len() as u8)
            .is_none()
        {
            return Err(VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::UNDEF,
            ))));
        }
        let (sender, receiver) = mpsc::channel();
        if let Some(runtime) = self.runtime
            && runtime.simulated != simulation_seed.is_some()
        {
            return Err(VmError::Unsupported(
                "a VM cannot change between real and simulated scheduling".into(),
            ));
        }
        let runtime: &'static Runtime = if let Some(runtime) = self.runtime
            && simulation_seed.is_none()
        {
            runtime
        } else {
            // A seeded scheduler run is an isolated simulation invocation: its seed and virtual
            // process table belong to that run, as in the prior per-invocation scheduler scope.
            if let Some(runtime) = self.runtime
                && let Ok(scheduler) = runtime.scheduler()
            {
                scheduler.release();
            }
            let code = Arc::clone(&self.code_ix);
            let port_layout = arinsal_term::ptab::port_table_layout();
            let port_ids = PtabIdRing::new(port_layout.max());
            // erts creates its forker port first and keeps port id zero occupied.
            assert_eq!(port_ids.reserve(), Some(0));
            let named_ets = Arc::new(arinsal_ets::NamedTableIndex::new());
            let runtime: &'static Runtime = Box::leak(Box::new(Runtime {
                statistics: crate::natives::sys::StatisticsState::new(self.statistics_origins),
                backtrace_depth: AtomicUsize::new(8),
                code: Arc::clone(&code),
                code_scope: self.code_scope,
                trap_exports: std::array::from_fn(|_| OnceLock::new()),
                system_processes: Mutex::new(std::collections::HashSet::new()),
                otp_root: self.otp_root.clone(),
                dirty_signal_handlers: Mutex::new(std::collections::HashSet::new()),
                literal_collector: Mutex::new(None),
                paths: self.paths.clone(),
                scheduler: OnceLock::new(),
                reg: crate::register::RegisterTable::new(),
                next_trace_weak_id: AtomicU64::new(0),
                ports: crate::port::PortTable::new(port_layout),
                child_setup: Arc::clone(self.child_setup.as_ref().expect("child setup started")),
                system_monitor: Mutex::new(None),
                session_monitors: Mutex::new(Vec::new()),
                system_monitor_flags: AtomicU8::new(0),
                long_message_queues: Mutex::new(Vec::new()),
                port_ids,
                simulated: simulation_seed.is_some(),
                virtual_ms: AtomicU64::new(0),
                named_ets: Arc::clone(&named_ets),
                ets: std::sync::RwLock::new(arinsal_ets::Registry::new_with_named_index(named_ets)),
                result: Mutex::new(sender.clone()),
                code_mod_permission: Mutex::new(crate::natives::code::CodeModPermission::default()),
                breakpoints: Arc::new(crate::trace_bp::BpNode::new(self.code_scope)),
                debug_wait_active: AtomicBool::new(false),
                system_flags: Mutex::new(crate::natives::sys::SystemFlags::boot()),
                gc_defaults: crate::natives::sys::GcDefaults::boot(),
                persistent_terms: arinsal_pterm::store_for(self.code_scope),
                multi_scheduling: Mutex::new(MultiScheduling::default()),
            }));
            self.runtime = Some(runtime);
            runtime
        };
        *runtime.result.lock().unwrap() = sender;
        if runtime.simulated != simulation_seed.is_some() {
            return Err(VmError::Unsupported(
                "a VM cannot change between real and simulated scheduling".into(),
            ));
        }
        let first_runtime = runtime.scheduler.get().is_none();
        (|| -> Result<ScheduledResult, VmError> {
            if first_runtime {
                let (dirty_cpu_schedulers, dirty_cpu_online, dirty_io_schedulers) =
                    crate::natives::sys::dirty_scheduler_defaults(runtime);
                let scheduler_options = arinsal_args::active_scheduler_options().0;
                let config = Config {
                    workers,
                    reductions: reductions.max(1),
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
                arinsal_bifs::init_unique_scheduler_count(
                    config.workers.max(crate::natives::sys::schedulers_total()) as u32,
                    config.dirty_cpu_schedulers as u32,
                    config.dirty_io_schedulers as u32,
                );
                // Port of erts/emulator/beam/erl_cpu_topology.c:1705-1708 (max_main_threads) and
                // ethr_mutex.c:151-166 (ethr_mutex_lib_late_init): the table locks' spin count grows with
                // the number of main threads, the schedulers on configured CPUs.
                arinsal_ets::rwmtx::set_main_threads(
                    config
                        .workers
                        .min(arinsal_alloc::cpuinfo::cpu_info().configured.max(1)),
                );
                let scheduler = Arc::new(match simulation_seed {
                    Some(seed) => Scheduler::simulation(config, seed),
                    None => Scheduler::new(config),
                });
                let online = crate::natives::sys::scheduler_online_default(runtime);
                let _ = scheduler.set_online_schedulers(online.min(workers.max(1)));
                let _ = scheduler.set_dirty_cpu_online(dirty_cpu_online);
                runtime.ports.attach(scheduler.progress());
                runtime
                    .scheduler
                    .set(scheduler)
                    .map_err(|_| VmError::Unsupported("runtime scheduler already set".into()))?;
                // Port of code_ix.c:142-171 and beam_common.c (erts_schedule_code_barrier),
                // OTP-29.1.1: code-table owners retire through this scheduler's progress queue.
                let scheduler = Arc::downgrade(runtime.scheduler()?);
                runtime.code.set_retire_hook(move |retired| {
                    if let Some(scheduler) = scheduler.upgrade() {
                        scheduler.thread_progress_later(move || retired.release());
                    } else {
                        // The scheduler is gone only after shutdown joined its workers.
                        retired.release();
                    }
                });
                if module == "erl_init" && function == "start" && simulation_seed.is_none() {
                    crate::natives::env::install_boot_signals(runtime)?;
                }
            }
            let scheduler = runtime.scheduler()?;
            let mut process = Process::with_spawn_registers(3);
            // Port of erts/emulator/beam/erl_process.c (erl_create_process: copy_struct of the
            // arguments into the new heap), OTP-29.1.1: the first process owns its arguments, so
            // a collection never meets a term outside its heap and the literal areas.
            let literals = arinsal_term::LiteralAreas::current();
            let mut copied = Vec::with_capacity(args.len());
            for &arg in args {
                let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                copied.push(
                    arinsal_term::copy_term_litopt(arg, &mut heap, &literals).map_err(|error| {
                        VmError::Load(format!("first process arguments: {error:?}"))
                    })?,
                );
            }
            let arity = u8::try_from(args.len())
                .map_err(|_| VmError::Load("first process arguments".into()))?;
            let (module_atom, function_atom, _) = mfa_atoms(module, function, arity)
                .ok_or_else(|| VmError::Load(format!("{module}:{function} name")))?;
            let args = arinsal_term::TermBuilder::new(&mut process.heap)
                .list_from_slice(&copied)
                .map_err(|error| VmError::Load(format!("first process arguments: {error:?}")))?;
            process.set_runtime(Some(runtime));
            // Port of erts/emulator/beam/erl_init.c:356 (erl_first_process_otp): the first
            // process is spawned through erl_create_process, which starts at beam_run_process.
            process.start_at_run_process(module_atom, function_atom, args, arity)?;
            process.entry = true;
            // Port of erts/emulator/beam/erl_init.c:2540 (erl_first_process_otp), OTP-29.1.1:
            // the first process gets the first pid; it runs once the system processes
            // exist, as erts starts its schedulers only after spawning them.
            let entry_pid: Pid = scheduler
                .spawn_unscheduled(process)
                .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
            // Port of erts/emulator/beam/erl_init.c system-process startup: every
            // VM needs the preloaded owner of the literal-area release protocol.
            if first_runtime {
                if module == "erl_init" && function == "start" {
                    // Port of erts/emulator/beam/erl_process.c:12525-12531 (erl_create_process), OTP-29.1.1.
                    self.spawn_system_process_priority(
                        scheduler,
                        runtime,
                        "erts_code_purger",
                        "start",
                        arinsal_sched::Priority::High,
                    )?;
                }
                let literal_collector = self.spawn_system_process_priority(
                    scheduler,
                    runtime,
                    "erts_literal_area_collector",
                    "start",
                    arinsal_sched::Priority::High,
                )?;
                *runtime.literal_collector.lock().unwrap() = Some(literal_collector);
                let mut handlers = Vec::with_capacity(3);
                for priority in [
                    arinsal_sched::Priority::Normal,
                    arinsal_sched::Priority::High,
                    arinsal_sched::Priority::Max,
                ] {
                    let pid = self.spawn_system_process_priority(
                        scheduler,
                        runtime,
                        "erts_dirty_process_signal_handler",
                        "start",
                        priority,
                    )?;
                    runtime.dirty_signal_handlers.lock().unwrap().insert(pid);
                    handlers.push(pid);
                }
                scheduler.set_dirty_signal_handlers(handlers[0], handlers[1], handlers[2], |pid| {
                    pid.to_term().and_then(|term| Message::copy_from(term).ok())
                });
                self.spawn_system_process(scheduler, runtime, "erts_trace_cleaner", "start")?;
            }
            scheduler
                .schedule_unscheduled(entry_pid)
                .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
            if simulation_seed.is_some() {
                loop {
                    if let Ok(result) = receiver.try_recv() {
                        while arinsal_pterm::store_for(self.code_scope).has_retired() {
                            if !scheduler.step() {
                                let now = runtime.virtual_ms.fetch_add(1, Ordering::Relaxed) + 1;
                                scheduler.advance_ms(1).map_err(|error| {
                                    VmError::Unsupported(format!("simulation clock: {error}"))
                                })?;
                                if now > 60_000 {
                                    return Err(VmError::Unsupported(
                                    "literal collector did not finish before simulation timeout"
                                        .into(),
                                ));
                                }
                            }
                        }
                        return result;
                    }
                    if !scheduler.step() {
                        let now = runtime.virtual_ms.fetch_add(1, Ordering::Relaxed) + 1;
                        scheduler.advance_ms(1).map_err(|error| {
                            VmError::Unsupported(format!("simulation clock: {error}"))
                        })?;
                        if now > 60_000 {
                            return Err(VmError::Unsupported(
                                "simulation has no runnable process or timer".into(),
                            ));
                        }
                    }
                }
            }
            let result = receiver
                .recv()
                .map_err(|_| VmError::Unsupported("entry process disappeared".into()))?;
            while arinsal_pterm::store_for(self.code_scope).has_retired() {
                std::thread::park_timeout(std::time::Duration::from_millis(1));
            }
            self.refresh_code();
            result
        })()
    }
}

fn initialize_feature_defaults(store: &arinsal_pterm::Store) -> Result<(), VmError> {
    let mut heap = arinsal_term::VecHeap::new();
    let module = Term::atom(
        arinsal_term::global_atoms()
            .intern("erl_features")
            .map_err(|error| VmError::Load(format!("feature atom: {error:?}")))?,
    );
    for name in ["enabled_features", "keywords"] {
        let key = TermBuilder::new(&mut heap)
            .tuple(&[
                module,
                Term::atom(
                    arinsal_term::global_atoms()
                        .intern(name)
                        .map_err(|error| VmError::Load(format!("feature atom: {error:?}")))?,
                ),
            ])
            .map_err(|error| VmError::Load(format!("feature key: {error:?}")))?;
        store
            .put_new(key, Term::NIL)
            .map_err(|error| VmError::Load(format!("feature default: {error:?}")))?;
    }
    let key = TermBuilder::new(&mut heap)
        .tuple(&[
            module,
            Term::atom(
                arinsal_term::global_atoms()
                    .intern("init_done")
                    .map_err(|error| VmError::Load(format!("feature atom: {error:?}")))?,
            ),
        ])
        .map_err(|error| VmError::Load(format!("feature key: {error:?}")))?;
    store
        .put_new(key, Term::atom(arinsal_term::atoms::TRUE))
        .map(|_| ())
        .map_err(|error| VmError::Load(format!("feature default: {error:?}")))
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
