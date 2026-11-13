use super::*;

/// A suspended process that would run on is parked instead. Its queued signals are handled
/// first: a suspended process only handles signals (erts schedules it for them as system
/// tasks), and one parked with unhandled signals in its middle queue would never run again.
/// Returns `Yield` when the drain resumed the process, so it keeps running.
// Port of erts/emulator/beam/erl_process.c:9742 (ERTS_PSFLG_SUSPENDED processes are scheduled for
// ERTS_PSFLG_ACTIVE_SYS signal handling only), OTP-29.1.1.
pub(super) fn park_suspended(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<RunState, VmError> {
    let pid = ctx.pid();
    process.cold_mut().sys_task_point = true;
    let drained = process.drain(ctx);
    let executed = drained.and_then(|()| crate::signals::execute_sys_tasks(process, ctx));
    process.cold_mut().sys_task_point = false;
    executed?;
    // The resumer's wake-up signal may have been consumed by the drain above: re-check so a
    // resume racing with this suspension is not lost.
    if process
        .runtime
        .as_ref()
        .is_none_or(|runtime| runtime.suspend_total_of(pid) == 0)
    {
        return Ok(RunState::Yield);
    }
    process.slice_mut().suspend_parked = true;
    Ok(RunState::Wait { timeout_pos: None })
}

impl Task for Process {
    type Message = Message;
    type SchedulerData = SchedulerData;

    // Port of erts/emulator/beam/erl_process.c:12723-12727 (erl_create_process), OTP-29.1.1.
    fn init_in_place(&mut self) {
        self.inbox.init_in_place();
    }

    fn gc_nanoseconds(&self) -> u64 {
        self.stats.gc.nanoseconds
    }

    // Inlined into the worker loop: see `Executor::run`. The dirty and simulated scheduler
    // path (`run_slice`) gets its own copy, which the normal schedulers never execute.
    #[inline(always)]
    fn run(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        budget: u32,
    ) -> RunOutcome {
        // Port of erts/emulator/beam/erl_trace.c:704-716 (trace_sched), OTP-29.1.1.
        let trace_scheduling = crate::trace::running_procs_enabled();
        if trace_scheduling {
            crate::trace::emit_process(
                None,
                self,
                ctx.pid(),
                crate::trace::RUNNING_PROCS,
                "in",
                &[],
            );
        }
        // The buffer mode depends on the process alone; the key carries it with the scheduler,
        // so a slice on the same scheduler with the same mode has nothing to redo.
        let offheap = self.message_queue_data() == MessageQueueData::OffHeap;
        let key = ctx.scheduler_key();
        let run_key = if key == 0 {
            0
        } else {
            key | (u64::from(offheap) << 63)
        };
        if run_key == 0 || self.run_key != run_key {
            ctx.set_parallel_signal_buffers(offheap);
            self.run_key = run_key;
        }
        // The light BIF path has no scheduler context. A probe is the process-side
        // `sig_inq` flag (`ERTS_PSFLG_MSG_SIG_IN_Q`) it checks before collecting.
        if self.signal_probe().is_none()
            && let Some(probe) = ctx.signal_probe()
        {
            self.set_signal_probe(Some(probe));
        }
        // Records built or decoded on this thread use its node's canonical definitions, and
        // export funs built here its export entries. A scheduler thread serves one runtime, so
        // the scopes are selected once; a simulated scheduler shares its thread with others.
        if !data.scopes_selected || ctx.simulated() {
            let scope = self
                .runtime
                .as_ref()
                .map_or(0, |runtime| runtime.code_scope);
            arinsal_term::set_record_scope(scope);
            crate::fun_dispatch::set_thread_code_scope(scope);
            data.scopes_selected = scope != 0;
        }
        // Port of erts/emulator/beam/erl_alloc.c (erts_alloc passes `esdp->no` to the
        // thread-specific allocators), OTP-29.1.1: the process heap allocates on this scheduler's
        // instance without looking the thread up, for the span of this run.
        let alloc_ix = *data
            .alloc_ix
            .get_or_insert_with(arinsal_alloc::thread_alloc_ix);
        self.heap.set_alloc_ix(Some(alloc_ix));
        self.on_managed = !ctx.scheduler_type().is_dirty() && !ctx.simulated();
        if self.receive_timeout_pos.is_some() {
            self.receive_timeout_schedule_in();
        }
        // Port of erts/emulator/beam/erl_process.c:10435 (`p->fcalls = reds`) and
        // jit/arm/process_main.cpp (`def_arg_reg[5] = REDS_IN = FCALLS`), OTP-29.1.1: the
        // slice's one counter starts at the budget.
        let reds_in = budget.min(i32::MAX as u32) as i32;
        self.heap.abi.fcalls = reds_in;
        self.reds_in = reds_in;
        // Port of erts/emulator/beam/beam_common.c (erts_dirty_process_main: `start_time`),
        // OTP-29.1.1: a dirty CPU scheduler charges the time from picking the process up.
        let dirty_start =
            (ctx.scheduler_type() == arinsal_sched::SchedulerType::DirtyCpu).then(|| {
                self.take_work(|w| w.dirty_pickup.take())
                    .unwrap_or_else(std::time::Instant::now)
            });
        let outcome = abort_on_worker_panic(|| self.run_task(ctx, data));
        self.context_switch(ctx, dirty_start);
        self.heap.set_alloc_ix(None);
        self.native = None;
        if matches!(outcome, RunOutcome::Exit(_)) {
            // erts finishes a suspended updater's table_updater even when the process is
            // killed, which releases the permission; the update is already published here.
            self.persistent_terms
                .release_update_permission(crate::natives::sys::persistent_owner(ctx.pid()));
        }
        if trace_scheduling {
            crate::trace::emit_process(
                None,
                self,
                ctx.pid(),
                crate::trace::RUNNING_PROCS,
                "out",
                &[],
            );
        }
        outcome
    }

    fn scheduler_shutdown(&mut self) {
        // The probe holds a reference to this process's own struct.
        self.set_signal_probe(None);
        if let Some(pid) = self.self_pid {
            self.persistent_terms
                .release_update_permission(crate::natives::sys::persistent_owner(pid));
        }
    }

    fn scheduler_profile_event(
        scheduler_id: u32,
        active: bool,
        active_schedulers: u32,
    ) -> Option<(Pid, Message)> {
        crate::natives::misc::profile_scheduler_event(scheduler_id, active, active_schedulers)
    }

    fn take_dirty_job(
        &mut self,
        kind: arinsal_sched::DirtyKind,
    ) -> Option<arinsal_sched::DirtyJob> {
        if kind == arinsal_sched::DirtyKind::Cpu {
            self.slice_mut().dirty_pickup = Some(std::time::Instant::now());
        }
        Process::take_dirty_job(self, kind)
    }

    fn finish_dirty_job(&mut self, result: Box<dyn std::any::Any>) {
        Process::finish_dirty_job(self, result);
    }

    // Port of erts/emulator/beam/erl_process.c (delete_process), OTP-29.1.1: the heap,
    // off-heap list, message queue, dictionary and the link and monitor state are freed by
    // the exiting scheduler, not when the last reference to the struct goes.
    fn delete_process(&mut self) {
        // Before the cold state, which holds the hold, is released (erts keeps it in `p->u.terminate`).
        self.unblock_literal_release();
        crate::trace::clear_save_calls(self);
        self.heap.clear_for_exit();
        // The queues go before the cold state: receive markers linked in them are nodes of
        // the marker block it holds (erts_proc_sig_cleanup_queues skips them).
        self.inbox = MessageQueue::default();
        *self.sig_cont_mut() = Default::default();
        self.cold = None;
        // The probe keeps a reference to this process; holding it past exit leaks the struct.
        self.set_signal_probe(None);
        self.dictionary = None;
        self.set_exit_cont(None);
        self.seq_trace_token = None;
        self.final_exit_reason = None;
    }

    fn reap_signals(&mut self, pid: Pid, events: Vec<Event<Message>>) {
        let mut monitors = Vec::new();
        let mut links = Vec::new();
        let mut unlink_acks = Vec::new();
        let mut literal_replies = Vec::new();
        for event in events {
            match event.payload {
                Payload::Signal(Signal::Monitor { reference, .. }) => {
                    monitors.push((reference, event.from));
                }
                Payload::Signal(Signal::MonitorOpaque { reference, shared }) => {
                    if shared
                        .0
                        .downcast_ref::<arinsal_nif::ResourceMonitor>()
                        .is_none()
                    {
                        monitors.push((reference, event.from));
                    }
                }
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
                // OTP-29.1.1: a link that reaches a process after its exit handling gets `noproc`.
                Payload::Signal(Signal::Link { .. }) => links.push(event.from),
                Payload::Signal(Signal::DistLink(shared)) => {
                    if let Some(link) = crate::dist::DistLinkHalf::take(&shared) {
                        crate::dist::proc_exit_handle_link(
                            self.runtime,
                            pid,
                            link,
                            Term::atom(arinsal_term::atoms::NOPROC),
                        );
                    }
                }
                Payload::Signal(Signal::DistUnlink(op)) => {
                    if let Some(runtime) = self.runtime {
                        crate::dist::reply_dist_unlink_ack(runtime, &op);
                    }
                }
                // A spawn reply that reached the queue after exit handling: answered as when
                // erts_proc_sig_send_dist_spawn_reply fails (dist.c:3090-3121).
                Payload::Signal(Signal::DistSpawnReply(shared)) => {
                    if let (Some(runtime), Some(data)) = (
                        self.runtime,
                        shared.0.downcast_ref::<crate::dist::DistSpawnReplyData>(),
                    ) {
                        crate::dist::spawn_reply_send_failed(runtime, data);
                    }
                }
                Payload::Signal(Signal::Unlink(id)) => {
                    links.retain(|from| *from != event.from);
                    unlink_acks.push((event.from, id));
                }
                Payload::Signal(
                    Signal::Demonitor(reference) | Signal::DistDemonitor(reference),
                ) => {
                    monitors.retain(|(id, _)| *id != reference);
                }
                Payload::Signal(Signal::DemonitorOrigin(shared)) => {
                    let reference = shared.reference();
                    monitors.retain(|(id, _)| *id != reference);
                }
                // Port of erts/emulator/beam/erl_proc_sig_queue.c:7426 (erts_proc_exit_handle_signal),
                // OTP-29.1.1: an exiting process still answers a queued literal-copy request.
                Payload::Signal(Signal::LiteralAreaCopy(copy)) => {
                    let arinsal_sched::LiteralAreaCopyRequest {
                        request, requester, ..
                    } = *copy;
                    if let Ok(reply) =
                        request.literal_copy_reply(Term::atom(arinsal_term::atoms::OK))
                    {
                        literal_replies.push((requester, reply));
                    }
                }
                _ => {}
            }
        }
        if monitors.is_empty()
            && literal_replies.is_empty()
            && links.is_empty()
            && unlink_acks.is_empty()
        {
            return;
        }
        let Ok(scheduler) = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.scheduler())
            .transpose()
        else {
            return;
        };
        let Some(scheduler) = scheduler else {
            return;
        };
        for (requester, reply) in literal_replies {
            let _ = scheduler.send(pid, requester, reply);
        }
        for (requester, id) in unlink_acks {
            let _ = scheduler.signal(pid, requester, Signal::UnlinkAckSignal(id));
        }
        for linker in links {
            if let Ok(reason) = Message::copy_from(Term::atom(arinsal_term::atoms::NOPROC)) {
                // A link exit (erts_proc_exit_handle_link), so the linker drops its half.
                let _ = scheduler.signal(pid, linker, Signal::ExitLinked(Box::new(reason)));
            }
        }
        for (reference, watcher) in monitors {
            let reason = self
                .final_exit_reason
                .unwrap_or_else(|| Term::atom(arinsal_term::atoms::NOPROC));
            let Ok(reason) = Message::copy_from(reason) else {
                continue;
            };
            let _ = scheduler.signal(
                pid,
                watcher,
                Signal::MonitorDown {
                    reference,
                    reason: Box::new(reason),
                },
            );
        }
    }
}

#[inline(always)]
pub(super) fn abort_on_worker_panic(run: impl FnOnce() -> RunOutcome) -> RunOutcome {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(outcome) => outcome,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            eprintln!("arinsal: VM panic in scheduler worker: {message}");
            std::process::abort();
        }
    }
}

impl Process {
    /// The context switch's reduction count, taken once per slice: `reds_used` is what the
    /// slice took from FCALLS, `p->reds` gains it less what `ERTS_VBUMP_REDS` gave up, and
    /// the scheduler counts it. A dirty scheduler charges by its own rule instead.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp (context_switch: `reds_used =
    // REDS_IN - FCALLS`), beam_common.c (erts_dirty_process_main: `reds_used`) and
    // erl_process.c:9678-9700 (erts_schedule: `actual_reds = calls - esdp->virtual_reds`,
    // `p->reds += actual_reds`), OTP-29.1.1.
    #[inline(always)]
    fn context_switch(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        dirty_start: Option<std::time::Instant>,
    ) {
        let virtual_reds = std::mem::take(&mut self.virtual_reds);
        let reds_used = match ctx.scheduler_type() {
            arinsal_sched::SchedulerType::Normal => {
                u32::try_from(self.reds_in.saturating_sub(self.heap.abi.fcalls)).unwrap_or(0)
            }
            arinsal_sched::SchedulerType::DirtyIo => virtual_reds.saturating_add(1),
            arinsal_sched::SchedulerType::DirtyCpu => {
                let treds = dirty_start.map_or(0, |start| erts_time2reds(start.elapsed()));
                u32::try_from(treds.saturating_add(u64::from(virtual_reds)))
                    .unwrap_or(i32::MAX as u32)
                    .min(i32::MAX as u32)
            }
        };
        ctx.add_virtual_reds(virtual_reds);
        let _ = ctx.consume(reds_used);
        self.reductions_used = self
            .reductions_used
            .saturating_add(u64::from(reds_used.saturating_sub(virtual_reds)));
    }

    #[inline(always)]
    fn run_task(&mut self, ctx: &mut RunCtx<'_, Message>, data: &mut SchedulerData) -> RunOutcome {
        if self.runtime.is_none() {
            return RunOutcome::Exit(1);
        }
        // erts stores the scheduler id on the process. Profiling allocates no side
        // record unless runnable-proc profiling is actually on.
        self.scheduler_id = ctx.scheduler_id().map_or(0, |id| id as u32);
        // Port of erts/emulator/beam/erl_process.c:6978-6992 (schedule_process_sys_task and
        // the enqueue paths test erts_system_profile_flags.runnable_procs before
        // profile_runnable_proc), OTP-29.1.1: without profiling this is one flag test.
        if crate::natives::misc::profile_runnable_procs()
            && !self.slice().is_some_and(|work| work.profile_active)
        {
            crate::natives::misc::profile_process_event(self, ctx, true);
            self.cold_mut().scheduler_id = self.scheduler_id as usize;
            self.slice_mut().profile_active = true;
        }
        if self.dirty_exiting() {
            // Exited by a dirty signal handler while queued for a dirty scheduler.
            return RunOutcome::Exit(1);
        }
        if let Some(state) = self.take_exit_cont() {
            // Port of erts/emulator/beam/erl_process.c:10528 (in_exiting), OTP-29.1.1: an
            // exiting process only continues its exit when scheduled in.
            let runtime = self.runtime_handle();
            return self.continue_exit(runtime, ctx, data, true, state.into_inner());
        }
        let result = self.run_executor(ctx, data);
        if self.dirty_exiting() {
            // Port of erts/emulator/beam/erl_process.c:10096 (need_forced_exit), OTP-29.1.1:
            // the process already terminated while the job ran; whatever the job returned,
            // only the process structure remains to be released.
            return RunOutcome::Exit(1);
        }
        self.finish_run(ctx, data, result)
    }

    /// The node runtime this process belongs to. A slice only needs a counted reference on
    /// the exit paths, so the scheduler takes it there, not on every turn.
    fn runtime_handle(&self) -> &'static Runtime {
        self.runtime.expect("a scheduled process has a runtime")
    }

    #[inline(always)]
    fn run_executor(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
    ) -> Result<RunState, VmError> {
        let executor = match data.executor {
            Some(ref mut executor) => executor,
            None => {
                let runtime = self.runtime_handle();
                data.executor.insert(new_executor(runtime))
            }
        };
        let mut result = executor.run(self, ctx);
        // BIF_TRAP context-switches to beam_bif_export_trap. The continuation is an export
        // call, so the caller's CP stays on the stack and the backtrace PC is that trap.
        if matches!(result, Ok(RunState::Yield))
            && self.slice().is_some_and(|work| work.bif_trap.is_some())
        {
            crate::bif_traps::note_export_trap(self);
        }
        // A native BIF yield returns before the interpreter's suspend check. erts leaves
        // a suspended process out of the run queue (ERTS_PSFLG_SUSPENDED): the code-permission
        // seize failure is `erts_suspend` plus `ERTS_BIF_YIELD`.
        if matches!(result, Ok(RunState::Yield)) && crate::suspend::ctx_suspended(ctx) {
            result = park_suspended(self, ctx);
        }
        if matches!(result, Ok(RunState::Yield | RunState::Wait { .. }))
            && let Err(error) = crate::signals::reschedule_deferred_sys_tasks(self, ctx)
        {
            result = Err(error);
        }
        if self
            .cold
            .as_ref()
            .and_then(|cold| cold.debug_wait_completion.as_ref())
            .is_some_and(|completed| !completed.load(Ordering::Acquire))
        {
            Ok(RunState::Wait { timeout_pos: None })
        } else {
            result
        }
    }

    fn finish_run(
        &mut self,
        ctx: &mut RunCtx<'_, Message>,
        data: &mut SchedulerData,
        result: Result<RunState, VmError>,
    ) -> RunOutcome {
        if matches!(&result, Ok(RunState::Wait { .. } | RunState::Done(_)))
            && self.slice().is_some_and(|work| work.profile_active)
        {
            crate::natives::misc::profile_process_event(self, ctx, false);
            self.slice_mut().profile_active = false;
        }
        // g_proc_sched. Port of erts/emulator/beam/erl_gc.c:1197 (max_heap_size kill), OTP-29.1.1.
        if heap_limit_kills(self, ctx) {
            let entry_result = self
                .entry
                .then(|| Box::new(Err(VmError::Unsupported("max_heap_size".into()))));
            let runtime = self.runtime_handle();
            return self.exit_with(
                runtime,
                ctx,
                data,
                Term::atom(arinsal_term::atoms::KILLED),
                entry_result,
                1,
            );
        }
        // Port of erts/emulator/beam/erl_process.c:6747-6763 (schedule_out_process), OTP-29.1.1:
        // with GC disabled the dirty collection is dropped; the next collection does it.
        if !ctx.scheduler_type().is_dirty()
            && !self.heap.gc_enabled
            && self
                .cold
                .as_mut()
                .is_some_and(|cold| cold.dirty_gc.take().is_some() && cold.delayed_gc.is_empty())
        {
            self.update_work(|work| work.dirty_sys_gc = false);
        }
        match result {
            // Port of erts/emulator/beam/erl_process.c:6695-6840 (schedule_out_process),
            // OTP-29.1.1: a process with ERTS_PSFLG_DIRTY_ACTIVE_SYS is enqueued on the dirty
            // CPU run queue.
            // The schedule-out sets the ACTIVE bit others read (remote_status) instead of
            // publishing a status under the runtime lock.
            Ok(RunState::Yield)
                if !ctx.scheduler_type().is_dirty()
                    && self.slice().is_some_and(|work| work.dirty_sys_gc) =>
            {
                ctx.set_active(true);
                RunOutcome::Dirty(arinsal_sched::DirtyKind::Cpu)
            }
            Ok(RunState::Yield) => {
                ctx.set_active(true);
                RunOutcome::Yield
            }
            Ok(RunState::Wait { timeout_pos }) => {
                // Port of erts/emulator/beam/erl_process.c:9304 (erts_process_state2status),
                // OTP-29.1.1: suspension keeps ERTS_PSFLG_ACTIVE, so a process resumed while
                // this slice ended is runnable, not waiting.
                let parked = self
                    .take_work(|work| std::mem::take(&mut work.suspend_parked).then_some(()))
                    .is_some();
                ctx.set_active(parked);
                match timeout_pos {
                    Some(timeout_pos) => RunOutcome::WaitTimer { timeout_pos },
                    None => RunOutcome::Wait { timeout_ms: None },
                }
            }
            Ok(RunState::Done(term)) => {
                if trace_boot_enabled() {
                    eprintln!(
                        "arinsal boot: process {:?} done pc={:?} value={term:?} {:?}",
                        ctx.pid(),
                        self.native_pc(),
                        arinsal_term::to_owned(term).ok()
                    );
                }
                #[cfg(feature = "pf-mem-counters")]
                if self.entry {
                    eprintln!(
                        "PF_MEM entry_done markers={} monitors={} spawn_constructs={} spawn_construct_ns={} spawn_fun_load_ns={} spawn_fun_setup_ns={} spawn_fun_sched_ns={}",
                        self.cold
                            .as_ref()
                            .and_then(|cold| cold.receive_markers.as_ref())
                            .map_or(0, |markers| markers.len()),
                        self.monitors.iter().count(),
                        crate::PF_SPAWN_CONSTRUCTS.load(Ordering::Relaxed),
                        crate::PF_SPAWN_CONSTRUCT_NS.load(Ordering::Relaxed),
                        crate::signals::PF_SPAWN_FUN_LOAD_NS.load(Ordering::Relaxed),
                        crate::signals::PF_SPAWN_FUN_SETUP_NS.load(Ordering::Relaxed),
                        crate::signals::PF_SPAWN_FUN_SCHED_NS.load(Ordering::Relaxed)
                    );
                }
                crate::signals::process_exiting(self, ctx);
                let entry_result = self.entry.then(|| {
                    self.stats.heap_words = self.heap.capacity_words();
                    let owned = arinsal_term::to_owned(term).map_err(|error| {
                        VmError::Unsupported(format!("result conversion: {error:?}"))
                    });
                    Box::new(owned.map(|term_owned| ScheduledResult {
                        text: format!("{term_owned}"),
                        term: term_owned,
                        stats: self.stats.snapshot(),
                    }))
                });
                let runtime = self.runtime_handle();
                self.exit_with(
                    runtime,
                    ctx,
                    data,
                    // erts passes `am_normal` (beam_common.c, `erts_do_exit_process(c_p, am_normal)`).
                    Term::atom(arinsal_term::atoms::NORMAL),
                    entry_result,
                    0,
                )
            }
            Err(error) => {
                if matches!(error, VmError::Yield) {
                    return RunOutcome::Yield;
                }
                if let VmError::Dirty(kind) = error {
                    return RunOutcome::Dirty(kind);
                }
                let reason = exit_reason_from(self, &error);
                if matches!(&error, VmError::Raised(raised) if raised.class == arinsal_bifs::Class::Error)
                {
                    report_process_error(self, ctx, reason);
                }
                crate::signals::process_exiting(self, ctx);
                if trace_boot_enabled() {
                    eprintln!("arinsal boot: process {:?} exited: {error}", ctx.pid());
                }
                let entry_result = self.entry.then(|| Box::new(Err(error)));
                let runtime = self.runtime_handle();
                self.exit_with(runtime, ctx, data, reason, entry_result, 1)
            }
        }
    }
}
