use super::*;

pub(super) fn exit_reason_from(process: &mut Process, error: &VmError) -> Term {
    if let Some(reason) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.exit_reason.take())
    {
        return reason;
    }
    // An exit signal that reached a running process (kill becomes killed) ends it with its
    // reason (erts/emulator/beam/erl_proc_sig_queue.c, handle_exit_signal), OTP-29.1.1.
    if let VmError::Trap(trap) = error
        && trap.class == arinsal_bifs::Class::Exit
    {
        return trap.reason;
    }
    let VmError::Raised(raised) = error else {
        return crate::signals::atom("error");
    };
    let owned = if raised.class == arinsal_bifs::Class::Error {
        arinsal_etf::OwnedTerm::Tuple(vec![raised.reason.clone(), raised.stack.clone()])
    } else {
        raised.reason.clone()
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    match arinsal_term::from_owned(&owned, &mut heap) {
        Ok(reason) => reason,
        Err(conversion_error) => {
            eprintln!("arinsal: exit reason conversion failed: {conversion_error:?}");
            crate::signals::atom("system_limit")
        }
    }
}

impl Process {
    pub(crate) fn tuple(&mut self, elements: &[Term]) -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut self.heap);
        TermBuilder::new(&mut heap)
            .tuple(elements)
            .map_err(|error| VmError::Unsupported(format!("signal tuple: {error:?}")))
    }

    pub(super) fn notify_exit(&mut self, vm: &mut Vm, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        self.exit_stage1(vm, ctx, reason);
        self.set_exit_cont(Some(
            arinsal_alloc::typed::FixAllocBox::new(crate::proc_create::ExitCont {
                reason,
                garbage: None,
                entry_result: None,
                code: 0,
            })
            .expect("exit continuation allocation"),
        ));
        let mut reds = isize::MAX;
        let mut garbage = None;
        self.exit_ets(ctx, &mut reds, &mut garbage);
        self.exit_stage3(ctx, reason);
    }

    /// Process exit up to the release of owned ETS tables.
    ///
    /// Port of erts/emulator/beam/erl_process.c:14290-14430 (`erts_continue_exit_process`),
    /// OTP-29.1.1: each global table is touched only when the process-local word says this
    /// process has that resource.
    fn exit_stage1(&mut self, vm: &mut Vm, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        self.final_exit_reason = Some(reason);
        let resources = proc_flags::resources_to_clean(ctx.exit_flags());
        if resources & proc_flags::CODE_PERM != 0 {
            crate::natives::code::code_mod_permission_process_exit(self, ctx.pid());
        }
        // Port of erts/emulator/beam/beam_bif_load.c:301-320 (commit_code_ix), OTP-29.1.1:
        // the code barrier of a loader commits and releases the code modification permission
        // even when the suspended loader exits.
        if let Some(staged) = self
            .cold
            .as_mut()
            .and_then(|cold| cold.finish_loading_commit.take().map(|boxed| *boxed))
        {
            let barrier_callback = staged.barrier_passed.is_some();
            let barrier_passed = staged
                .barrier_passed
                .as_ref()
                .is_none_or(|passed| passed.load(std::sync::atomic::Ordering::Acquire));
            if barrier_passed {
                vm.commit_staged(staged);
            }
            if !barrier_callback && let Some(runtime) = &self.runtime {
                crate::natives::code::release_code_mod_permission(runtime);
            }
        }
        crate::natives::proc::trace_finish_process_exit(vm, self, ctx);
        // erl_process.c:14221: the exit trace is emitted only when F_TRACE_PROCS is set.
        if resources & proc_flags::TRACE != 0 {
            crate::trace::emit(
                Some(vm),
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "exit",
                &[reason],
            );
        }
        // Port of erts/emulator/beam/erl_process.c:14421-14464, OTP-29.1.1: releasing the
        // registered name is traced after the exit event, and only when p->reg != NULL.
        // The name lives on the process (`p->common.u.alive.reg`), so exit does not scan
        // the table. The table entry itself is released in `exit_stage3`.
        if resources & proc_flags::REG != 0
            && let Some(index) = self
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.scheduler().ok())
                .and_then(|scheduler| scheduler.registered_atom_index(ctx.pid()))
        {
            crate::trace::emit(
                Some(vm),
                self,
                ctx,
                ctx.pid(),
                crate::trace::PROCS,
                "unregister",
                &[Term::atom(Atom(index))],
            );
        }
        // erl_process.c:14200 (erts_trace_check_exiting) matches the system-monitor receiver.
        if resources & proc_flags::SYS_MON != 0 {
            crate::natives::erts_debug::monitor_process_exited(self, ctx.pid());
        }
        // delete_all_trace_refs walks p->common.tracee.first_ref, which is NULL when untraced.
        if resources & proc_flags::TRACE != 0 {
            crate::trace::retain_exiting(self, ctx.pid());
        }
        if resources & proc_flags::TRACER != 0 {
            crate::trace::tracer_exited(self, ctx.pid());
        }
        // Port of erts/emulator/beam/erl_process.c:11039 (cleanup_sys_tasks), OTP-29.1.1:
        // delayed literal-copy requests of an exiting process are answered with `ok`.
        {
            for task in self.take_delayed_gc() {
                if let crate::proc_create::DelayedGc::Literal {
                    request, requester, ..
                } = task
                {
                    let _ = crate::natives::sys::reply_exiting_literal_area(
                        self, ctx, request, requester,
                    );
                }
            }
        }
        // Port of erts/emulator/beam/erl_process.c:14300-14304, OTP-29.1.1.
        // Timers aimed at this process are canceled only when p->bif_timers != NULL.
        if resources & proc_flags::BIF_TIMERS != 0 {
            ctx.cancel_target_timers(ctx.pid());
        }
        // g_proc_sched: a terminating suspender releases every suspend it acquired.
        // g_port_fix: close owned ports synchronously on the termination path.
        // Node monitors live in the process monitor tree; the global table is
        // consulted only when this process registered one (dist.c:6732).
        if resources & proc_flags::NODE_MON != 0 {
            crate::node_tables::lock().forget_node_monitors(ctx.pid());
        }
    }

    /// Release the tables this exiting process owns, `reds` reductions at a time. Returns
    /// whether all of them are released; otherwise the process yields and calls again.
    ///
    /// Port of erts/emulator/beam/erl_db.c:5031 (erts_db_process_exiting), OTP-29.1.1.
    fn exit_ets(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        reds: &mut isize,
        interrupted: &mut Option<arinsal_ets::Garbage>,
    ) -> bool {
        // erl_process.c:14362: erts_db_process_exiting runs only when F_USING_DB is set.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::USING_DB == 0 {
            return true;
        }
        let (Some(runtime), Some(owner)) = (self.runtime, ctx.pid().to_term()) else {
            return true;
        };
        // FREE_OWNED_TABLE: finish the table whose release was interrupted.
        if let Some(mut garbage) = interrupted.take()
            && !garbage.step(reds)
        {
            *interrupted = Some(garbage);
            return false;
        }
        // GET_OWNED_TABLE
        loop {
            if *reds <= 0 {
                return false;
            }
            let Some(tid) = runtime.ets.read().unwrap().first_owned(owner) else {
                break;
            };
            let info = {
                let registry = runtime.ets.read().unwrap();
                registry.get(tid).ok().map(|table| {
                    (
                        table.options.named_table.then_some(table.options.name),
                        table.options.heir,
                    )
                })
            };
            let Some((name, heir)) = info else {
                runtime.ets.write().unwrap().forget_owned(owner, tid);
                continue;
            };
            {
                // Port of erts/emulator/beam/erl_db.c:4898-4900 (give_table_to_heir),
                // OTP-29.1.1: an owner that is its own heir keeps, and so deletes, the table.
                let heir = heir.filter(|heir| heir.pid != owner);
                if let Some(heir) = heir
                    && let Some(pid) = Pid::from_term(heir.pid)
                    && !heir.transfer
                {
                    // Port of erts/emulator/beam/erl_db.c:4910-4930 (give_table_to_heir),
                    // OTP-29.1.1: `{heir, Pid}` hands the table over without a message.
                    let alive = runtime.scheduler().is_ok_and(|scheduler| {
                        scheduler.started_interval(pid) == Some(heir.started_interval)
                    });
                    if alive
                        && runtime.publish_proc_flag(pid, proc_flags::USING_DB)
                        && runtime
                            .ets
                            .write()
                            .unwrap()
                            .give_away(tid, heir.pid)
                            .is_ok()
                    {
                        continue;
                    }
                } else if let Some(heir) = heir
                && let Some(pid) = Pid::from_term(heir.pid)
                // erl_db.c:4908: a heir that died and whose pid was reused keeps nothing.
                && runtime.scheduler().is_ok_and(|scheduler| {
                    scheduler.started_interval(pid) == Some(heir.started_interval)
                }) {
                    let mut heap = arinsal_term::VecHeap::new();
                    // Port of erts/emulator/beam/erl_db.c:4959-4962
                    // (send_ets_transfer_message), OTP-29.1.1.
                    let tab = match name {
                        Some(name) => Ok(Term::atom(name)),
                        None => runtime
                            .ets
                            .read()
                            .unwrap()
                            .tid_term(tid, &mut heap)
                            .map_err(|_| arinsal_term::TermError::BadArg),
                    };
                    let message_term = tab.and_then(|tab| {
                        let from = ctx.pid().to_term().ok_or(arinsal_term::TermError::BadArg)?;
                        arinsal_term::TermBuilder::new(&mut heap).tuple(&[
                            crate::signals::atom("ETS-TRANSFER"),
                            tab,
                            from,
                            heir.data,
                        ])
                    });
                    if let Ok(message_term) = message_term
                        && let Ok(message) = Message::copy_from(message_term)
                    {
                        let mut registry = runtime.ets.write().unwrap();
                        // erl_db.c:4914: the heir's F_USING_DB bit, so its exit releases the table.
                        if runtime.publish_proc_flag(pid, proc_flags::USING_DB)
                            && registry.give_away(tid, heir.pid).is_ok()
                        {
                            drop(registry);
                            if ctx.send(pid, message).is_ok() {
                                continue;
                            }
                        }
                    }
                }
            }
            let detached = runtime.ets.write().unwrap().detach(tid);
            let Ok((mut garbage, fixations)) = detached else {
                runtime.ets.write().unwrap().forget_owned(owner, tid);
                continue;
            };
            // FREE_OWNED_TABLE
            *reds -= fixations as isize;
            if !garbage.step(reds) {
                *interrupted = Some(garbage);
                return false;
            }
        }
        // UNFIX_TABLES
        if runtime.ets.read().unwrap().has_fixations(owner) {
            runtime.ets.write().unwrap().release_fixations(owner);
        }
        true
    }

    /// Process exit after its tables are released: pending signals, names, links and monitors.
    fn exit_stage3(&mut self, ctx: &mut RunCtx<'_, Message>, reason: Term) {
        // Port of erts/emulator/beam/erl_process.c:14374-14392
        // (ERTS_CONTINUE_EXIT_CLEAN_SYS_TASKS), OTP-29.1.1. Keep the literal area alive
        // through system task replies while the reason or a dirty-running process can access it.
        if (!reason.is_immed() || ctx.dirty_running())
            && self.slice().is_none_or(|work| work.rla_block.is_none())
        {
            let block = self.persistent_terms.block_release();
            self.slice_mut().rla_block = Some(block);
        }
        // delete_all_trace_refs (erl_trace.c:3774) is a no-op when first_ref is NULL.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE != 0 {
            crate::trace::clear(self, ctx.pid());
        }
        let resources = proc_flags::resources_to_clean(ctx.exit_flags());
        if resources & proc_flags::DDLL != 0
            && let Some(runtime) = self.runtime
            && let Ok(scheduler) = runtime.scheduler()
        {
            // Port of erts/emulator/beam/erl_process.c:14415-14417
            // (ERTS_CONTINUE_EXIT_FREE), OTP-29.1.1.
            crate::ddll::proc_dead(scheduler, ctx.pid());
        }
        // ERTS_CONTINUE_EXIT_FREE releases the registered name before removing the pid from
        // the process table. The name index is stored on the process-table entry.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::REG != 0
            && let Some(runtime) = &self.runtime
            && let Ok(scheduler) = runtime.scheduler()
            && let Some(index) = scheduler.registered_atom_index(ctx.pid())
        {
            // Port of erts/emulator/beam/erl_process.c:14424-14426
            // (`erts_unregister_name` with `THE_NON_VALUE`), OTP-29.1.1.
            // The registered name is the last Erlang resource released, and only when
            // p->common.u.alive.reg != NULL.
            let name = Atom(index);
            let mut table = runtime.reg.write();
            if matches!(table.fetch(name), Some(crate::register::RegId::Proc(pid)) if pid == ctx.pid())
            {
                table.erase(name);
                scheduler.clear_registered_atom_index(ctx.pid(), index);
            }
        }
        // Port of erts/emulator/beam/erl_process.c:14438-14456
        // (ERTS_CONTINUE_EXIT_FREE), OTP-29.1.1: unregister the name, then mark the pid
        // dead in the process table. Later exit phases process links, monitors and signals.
        ctx.begin_exit();
        // Further publishes fail with `NoProcess` and the watcher synthesizes DOWN.
        // Signals already queued are installed before we notify.
        self.absorb_exit_signals(ctx);
        let links = self.links.drain();
        for node in links {
            if node.view().unlinking() != 0 {
                continue;
            }
            if node.view().kind() == crate::monitor_link::node_type::LINK_PORT {
                if let Some(runtime) = self.runtime
                    && let Ok(scheduler) = runtime.scheduler()
                {
                    crate::port::owner_exit(
                        runtime,
                        scheduler,
                        ctx.pid(),
                        reason,
                        &[crate::proc_create::port_of_link_key(node.view().other())],
                    );
                }
                continue;
            }
            let pid = Pid::from_data(node.view().other());
            if self.runtime.as_ref().is_some_and(|runtime| {
                crate::dist::forward_link_exit_if_proxy(runtime, pid, ctx.pid(), reason)
            }) {
                continue;
            }
            if let Ok(mut message) = Message::copy_from(reason) {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:1700-1703 and :1827
                // (send_gen_exit_signal), OTP-29.1.1: the exit signal carries the exiting
                // process's token and counts as a send.
                if crate::seq_trace::has_token(self)
                    && let Some(token) = crate::seq_trace::on_exit_signal(self, ctx, pid, reason)
                {
                    message.attach_seq_token(token);
                }
                let _ = ctx.signal(pid, arinsal_sched::Signal::ExitLinked(Box::new(message)));
            }
        }
        // Suspend monitors are handled with the process monitor phase, after links.
        crate::suspend::release_on_exit(self, ctx);
        crate::suspend::down_on_exit(self, ctx);
        // Port of erts/emulator/beam/erl_process.c:13829 (erts_proc_exit_handle_monitor,
        // ERTS_MON_TYPE_RESOURCE): erts_fire_nif_monitor.
        if let Some(exiting) = ctx.pid().to_term()
            && let Some(cold) = self.cold.as_ref()
            && !cold.resource_monitors.is_empty()
        {
            for monitor in cold.resource_monitors.values() {
                monitor.fire(exiting);
            }
        }
        // Port of erts/emulator/beam/erl_process.c (erts_proc_exit_handle_monitor): the target
        // halves, of remote origins in the monitor tree and of local ones in the list.
        let monitors = self.monitors.drain();
        for monitor in monitors {
            if monitor.view().is_target() {
                let half = monitor.view();
                let reference = half.reference();
                if half.kind() == crate::monitor_link::node_type::MONITOR_PORT {
                    if let Some(runtime) = self.runtime.as_ref() {
                        crate::port::fire_port_monitor(runtime, half.other(), reference);
                    }
                    continue;
                }
                let pid = Pid::from_data(half.other());
                if let Some(runtime) = self.runtime.as_ref()
                    && crate::dist::forward_monitor_down_if_proxy(
                        runtime,
                        pid,
                        ctx.pid(),
                        reference,
                        reason,
                    )
                {
                    continue;
                }
                if reason.is_pointer() {
                    if let Ok(message) = down_message_on_sender(
                        self,
                        reference,
                        half.reference_creator(),
                        half.info(),
                        ctx.pid(),
                        reason,
                    ) {
                        let _ = ctx.signal(
                            pid,
                            arinsal_sched::Signal::MonitorDownMsg {
                                reference,
                                message: Box::new(message),
                            },
                        );
                    }
                } else {
                    let _ = ctx.signal(
                        pid,
                        arinsal_sched::Signal::MonitorDownImmediate {
                            reference,
                            reason: reason.word(),
                        },
                    );
                }
                continue;
            }
            match monitor.state() {
                Some(crate::proc_create::OriginMonitor::Process(_)) => {
                    let target = Pid::from_data(monitor.view().other());
                    let shared = monitor.into_shared();
                    let _ = ctx.signal(target, arinsal_sched::Signal::DemonitorOrigin(shared));
                }
                Some(crate::proc_create::OriginMonitor::Port {
                    port_id: Some(port_id),
                    ..
                }) => {
                    crate::port::demonitor_port(
                        self,
                        ctx.pid(),
                        *port_id,
                        monitor.view().reference(),
                    );
                }
                _ => {}
            }
        }
        let lt_monitors = self.lt_monitors.drain();
        for target in lt_monitors {
            let half = target.view();
            let reference = half.reference();
            if half.kind() == crate::monitor_link::node_type::MONITOR_PORT {
                if let Some(runtime) = self.runtime.as_ref() {
                    crate::port::fire_port_monitor(runtime, half.other(), reference);
                }
                continue;
            }
            let pid = Pid::from_data(half.other());
            if let Some(runtime) = self.runtime.as_ref()
                && crate::dist::forward_monitor_down_if_proxy(
                    runtime,
                    pid,
                    ctx.pid(),
                    reference,
                    reason,
                )
            {
                continue;
            }
            if reason.is_pointer() {
                if let Ok(message) = down_message_on_sender(
                    self,
                    reference,
                    half.reference_creator(),
                    half.info(),
                    ctx.pid(),
                    reason,
                ) {
                    let _ = ctx.signal(
                        pid,
                        arinsal_sched::Signal::MonitorDownMsg {
                            reference,
                            message: Box::new(message),
                        },
                    );
                }
            } else {
                let _ = ctx.signal(
                    pid,
                    arinsal_sched::Signal::MonitorDownImmediate {
                        reference,
                        reason: reason.word(),
                    },
                );
            }
        }
    }
}

pub(super) fn report_process_error(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    reason: Term,
) {
    let Some(runtime) = process.runtime else {
        return;
    };
    let destination = crate::natives::sys::system_logger(process);
    let logger = if destination == crate::signals::atom("undefined") {
        None
    } else if let Some(pid) = Pid::from_term(destination) {
        Some(pid)
    } else {
        runtime
            .reg
            .whereis_proc_str("logger")
            .or_else(|| runtime.reg.whereis_proc_str("error_logger"))
    };
    let Some(logger) = logger else {
        return;
    };
    let Some(pid) = ctx.pid().to_term() else {
        return;
    };
    let node_name = {
        let nodes = crate::node_tables::lock();
        nodes.alive.then(|| nodes.local_identity().0.to_owned())
    };
    let built = (|| -> Result<Term, VmError> {
        let format = if node_name.is_some() {
            "Error in process ~p on node ~p with exit value:~n~p~n"
        } else {
            "Error in process ~p with exit value:~n~p~n"
        };
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let format = builder
            .list_from_iter(
                format
                    .bytes()
                    .map(|byte| Term::small(i64::from(byte)).unwrap()),
            )
            .map_err(|error| VmError::Unsupported(format!("process error format: {error:?}")))?;
        let mut values = vec![pid];
        if let Some(node_name) = node_name {
            values.push(Term::atom(
                arinsal_term::global_atoms()
                    .intern(&node_name)
                    .map_err(|error| VmError::Unsupported(format!("node atom: {error:?}")))?,
            ));
        }
        values.push(reason);
        let args = builder
            .list_from_iter(values)
            .map_err(|error| VmError::Unsupported(format!("process error args: {error:?}")))?;
        let logger_metadata = builder
            .flatmap_from_pairs(&[
                (
                    crate::signals::atom("emulator"),
                    crate::signals::atom("true"),
                ),
                (crate::signals::atom("tag"), crate::signals::atom("error")),
            ])
            .map_err(|error| VmError::Unsupported(format!("logger metadata: {error:?}")))?;
        let group_leader = process
            .group_leader
            .and_then(Pid::to_term)
            .unwrap_or(Term::NIL);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_micros() as i64)
            .ok()
            .and_then(Term::small)
            .unwrap_or(Term::NIL);
        let metadata = builder
            .flatmap_from_pairs(&[
                (crate::signals::atom("error_logger"), logger_metadata),
                (crate::signals::atom("gl"), group_leader),
                (crate::signals::atom("pid"), pid),
                (crate::signals::atom("time"), time),
            ])
            .map_err(|error| VmError::Unsupported(format!("logger event metadata: {error:?}")))?;
        builder
            .tuple(&[
                crate::signals::atom("log"),
                crate::signals::atom("error"),
                format,
                args,
                metadata,
            ])
            .map_err(|error| VmError::Unsupported(format!("logger event: {error:?}")))
    })();
    if let Ok(term) = built
        && let Ok(message) = Message::copy_from(term)
    {
        let _ = ctx.send(logger, message);
    }
}

impl Process {
    /// Terminate the process: everything up to the owned ETS tables now, the tables a slice of
    /// reductions at a time, and the rest once they are released.
    ///
    /// Port of erts/emulator/beam/erl_process.c:14160 (erts_continue_exit_process), OTP-29.1.1.
    pub(super) fn exit_with(
        &mut self,
        runtime: &'static Runtime,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        reason: Term,
        entry_result: Option<Result<ScheduledResult, VmError>>,
        code: u64,
    ) -> RunOutcome {
        with_executor(data, runtime, |executor| {
            self.exit_stage1(&mut executor.vm, ctx, reason)
        });
        // Port of erts/emulator/beam/erl_process.c (erts_continue_exit_process), OTP-29.1.1:
        // the continuation state lives on the stack and is allocated only when the exit yields.
        let state = crate::proc_create::ExitCont {
            reason,
            garbage: None,
            entry_result,
            code,
        };
        // Port of erts/emulator/beam/erl_process.c:14229 (erts_do_exit_process:
        // `BUMP_REDS(p, 100)`), OTP-29.1.1: the rest of the exit runs on what is left, and the
        // schedulers' wakeup_other, check_balance and check_time counters see this cost.
        ctx.consume(100);
        self.continue_exit(runtime, ctx, data, false, state)
    }

    /// Run the interruptible part of process exit; yields with `out_exiting` when the
    /// reductions run out and finishes with `out_exited`.
    pub(super) fn continue_exit(
        &mut self,
        runtime: &'static Runtime,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        resumed: bool,
        mut state: crate::proc_create::ExitCont,
    ) -> RunOutcome {
        let zero = [Term::small(0).expect("small zero")];
        if resumed {
            with_executor(data, runtime, |executor| {
                crate::trace::emit(
                    Some(&mut executor.vm),
                    self,
                    ctx,
                    ctx.pid(),
                    crate::trace::EXITING,
                    "in_exiting",
                    &zero,
                );
            });
        }
        let initial = ctx.remaining() as isize;
        let mut reds = initial;
        let done = self.exit_ets(ctx, &mut reds, &mut state.garbage);
        ctx.consume((initial - reds).clamp(0, initial) as u32);
        if !done {
            with_executor(data, runtime, |executor| {
                crate::trace::emit(
                    Some(&mut executor.vm),
                    self,
                    ctx,
                    ctx.pid(),
                    crate::trace::EXITING,
                    "out_exiting",
                    &zero,
                );
            });
            self.set_exit_cont(Some(
                arinsal_alloc::typed::FixAllocBox::new(state)
                    .expect("exit continuation allocation"),
            ));
            return RunOutcome::Yield;
        }
        let cont = state;
        with_executor(data, runtime, |executor| {
            crate::trace::emit(
                Some(&mut executor.vm),
                self,
                ctx,
                ctx.pid(),
                crate::trace::EXITING,
                "out_exited",
                &zero,
            );
        });
        self.exit_stage3(ctx, cont.reason);
        if self.entry
            && let Some(result) = cont.entry_result
        {
            let _ = runtime.result.lock().unwrap().send(result);
        }
        RunOutcome::Exit(cont.code)
    }
}
