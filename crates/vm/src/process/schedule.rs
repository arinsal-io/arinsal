use super::executor_run::process_main;
use super::*;

/// A suspended process that would run on is parked instead. Its queued signals are handled
/// first: a suspended process only handles signals (erts schedules it for them as system
/// tasks), and one parked with unhandled signals in its middle queue would never run again.
/// Returns `Yield` when the drain resumed the process, so it keeps running.
// Port of erts/emulator/beam/erl_process.c:9742 (ERTS_PSFLG_SUSPENDED processes are scheduled for
// ERTS_PSFLG_ACTIVE_SYS signal handling only), OTP-29.1.1.
pub(super) fn park_suspended(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
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
    Ok(RunState::Wait)
}

impl Task for Process {
    type Message = Message;
    type SchedulerData = SchedulerData;
    // Port of erts/emulator/beam/erl_process.c (schedule: process scheduling statistics), OTP-29.1.1.

    fn scheduler_data(&self) -> Option<&arinsal_sched::ProcSchedData<Self>> {
        Some(&self.scheduler_data)
    }

    // Port of erts/emulator/beam/erl_process.c:12723-12727 (erl_create_process), OTP-29.1.1.
    // Port of erts/emulator/beam/erl_ptab.c (erts_ptab_new_element: `p->common.id`), OTP-29.1.1:
    // the process knows its own identifier from its creation on.
    fn init_in_place(&mut self, pid: Pid) {
        self.heap.abi.self_pid = pid.to_term().expect("valid pid").tagged_word();
        self.inbox.init_in_place();
    }

    // A process without a runtime exits at once in `run_task` and never reaches Erlang code.
    fn copy_in_registers(c_p: &mut CP<'_>, reg: &SchedulerData) {
        let process = c_p.task();
        if process.runtime.is_some() {
            reg.registers
                .with(|reg| crate::beam_common::copy_in_registers(process, reg));
        }
    }

    fn copy_out_registers(c_p: &mut CP<'_>, reg: &SchedulerData) {
        let process = c_p.task();
        if process.runtime.is_some() {
            reg.registers
                .with(|reg| crate::beam_common::copy_out_registers(process, &reg.x_reg_array));
        }
    }

    // Port of erts/emulator/beam/erl_process.c:10508-10546 (trace_schedule_in), OTP-29.1.1: an
    // exiting process that resumes its exit (`p->u.terminate` set) reports `in_exiting`,
    // any other `in`; a call-time traced process starts its schedule-in time break.
    fn trace_schedule_in(c_p: &mut CP<'_>, esdp: &ErtsSchedulerData) {
        esdp.with_ctx(c_p, |process, ctx| {
            // `p->scheduler_data = esdp` precedes the trace (erl_process.c:10232).
            crate::proc_create::raw::erts_psd_set_word(
                &mut process.psd,
                crate::proc_create::raw::ERTS_PSD_SCHED_ID,
                ctx.scheduler_id().unwrap_or(0),
            );
            let exiting = process.has_exit_cont();
            if process.runtime.is_none() {
                return;
            }
            if process.dirty_exiting()
                || (!exiting && ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE == 0)
            {
                return;
            }
            {
                let pid = ctx.pid();
                if exiting {
                    let zero = [Term::small(0).expect("small zero")];
                    crate::trace::emit(
                        Some(&mut Vm {}),
                        process,
                        ctx,
                        pid,
                        crate::trace::EXITING,
                        "in_exiting",
                        &zero,
                    );
                } else {
                    // The MFA tuple is built on the process heap, where erts' HAlloc never fails.
                    let running = crate::trace::running_mfa(process, pid).unwrap_or(None);
                    let running_fields = [running.unwrap_or(Term::small(0).expect("small zero"))];
                    crate::trace::emit(
                        Some(&mut Vm {}),
                        process,
                        ctx,
                        pid,
                        crate::trace::RUNNING,
                        "in",
                        &running_fields,
                    );
                }
                if crate::trace::flags(process, pid) & crate::trace::CALL != 0 {
                    crate::trace_bp::schedule_time_break(process, pid, false);
                }
            }
        })
    }

    // Port of erts/emulator/beam/erl_process.c:10548-10570 (trace_schedule_out), OTP-29.1.1: a
    // process that yields in its exit reports `out_exiting`, any other `out`. A process that
    // finished its exit is freed (ERTS_PSFLG_FREE in `p->state`) and has reported `out_exited`
    // itself.
    fn trace_schedule_out(c_p: &mut CP<'_>, esdp: &ErtsSchedulerData) {
        esdp.with_ctx(c_p, |process, ctx| {
            if ctx.proc_state().load(Ordering::Acquire) & arinsal_sched::psflg::FREE != 0 {
                return;
            }
            let exiting = process.has_exit_cont();
            if process.runtime.is_none() {
                return;
            }
            if !exiting && ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE == 0 {
                return;
            }
            {
                let pid = ctx.pid();
                if crate::trace::flags(process, pid) & crate::trace::CALL != 0 {
                    crate::trace_bp::schedule_time_break(process, pid, true);
                }
                if exiting {
                    let zero = [Term::small(0).expect("small zero")];
                    crate::trace::emit(
                        Some(&mut Vm {}),
                        process,
                        ctx,
                        pid,
                        crate::trace::EXITING,
                        "out_exiting",
                        &zero,
                    );
                } else {
                    // erl_trace.c:752-760 (trace_sched_session): no current function is reported
                    // as 0.
                    let running = crate::trace::running_mfa(process, pid).unwrap_or(None);
                    let running_fields = [running.unwrap_or(Term::small(0).expect("small zero"))];
                    crate::trace::emit(
                        Some(&mut Vm {}),
                        process,
                        ctx,
                        pid,
                        crate::trace::RUNNING,
                        "out",
                        &running_fields,
                    );
                }
            }
        })
    }

    fn gc_nanoseconds(&self) -> u64 {
        self.stats.gc.nanoseconds
    }

    // Port of erts/emulator/beam/erl_process.c:10232-10440 (erts_schedule, schedule-in of the
    // selected process after `p->scheduler_data = esdp` and trace_schedule_in: `p->fcalls =
    // reds`), OTP-29.1.1.
    fn schedule_in(c_p: &mut CP<'_>, esdp: &ErtsSchedulerData, reds: u32, calls: &mut u32) -> bool {
        esdp.with_ctx(c_p, |process, ctx| {
            // `c_p` (the native prefix at the start of this task) and the process state word are in
            // one process struct, the state word at `offsetof(Process, state)` from `c_p`.
            debug_assert_eq!(
                std::ptr::from_ref(ctx.proc_state()).addr()
                    - std::ptr::from_mut(process.native_header()).addr(),
                crate::process::PROCESS_STATE_OFFSET
            );
            // The NIF hub of this scheduler reads `esdp->current_process`, which erts_schedule
            // set (erl_process.c:10180, OTP-29.1.1).
            crate::natives::nif::bind_scheduler_hub(process);
            // Port of erts/emulator/beam/erl_process.c:10232 (`p->scheduler_data = esdp`; the
            // scheduler number process_info reports is `esdp->no`), OTP-29.1.1.
            crate::proc_create::raw::erts_psd_set_word(
                &mut process.psd,
                crate::proc_create::raw::ERTS_PSD_SCHED_ID,
                ctx.scheduler_id().unwrap_or(0),
            );
            // Port of erts/emulator/beam/erl_trace.c:704-716 (trace_sched), OTP-29.1.1.
            if crate::trace::running_procs_enabled() {
                crate::trace::emit_process(
                    process,
                    ctx.pid(),
                    crate::trace::RUNNING_PROCS,
                    "in",
                    &[],
                );
            }
            // The light BIF path has no scheduler context. A probe is the process-side
            // `sig_inq` flag (`ERTS_PSFLG_MSG_SIG_IN_Q`) it checks before collecting.
            if process.signal_probe().is_none()
                && let Some(probe) = ctx.signal_probe()
            {
                process.set_signal_probe(Some(probe));
            }
            // Port of erts/emulator/beam/erl_alloc.c (erts_alloc passes `esdp->no` to the
            // thread-specific allocators), OTP-29.1.1: the process heap allocates on this scheduler's
            // instance without looking the thread up, while it is scheduled in.
            let data = arinsal_sched::erts_sched_registers(esdp);
            let alloc_ix = data.alloc_ix.get().unwrap_or_else(|| {
                let ix = arinsal_alloc::thread_alloc_ix();
                data.alloc_ix.set(Some(ix));
                ix
            });
            process.heap.set_alloc_ix(Some(alloc_ix));
            if process.receive_timeout_pos.is_some() {
                process.receive_timeout_schedule_in();
            }
            // Port of erts/emulator/beam/erl_process.c:10435 (`p->fcalls = reds`), OTP-29.1.1:
            // the RUNNING_SYS work below charges `reds` (`reds -= sig_reds`, `reds -= cost`)
            // through `c_p->fcalls`.
            let reds = reds.min(i32::MAX as u32) as i32;
            process.heap.abi.fcalls = reds;
            // Port of erts/emulator/beam/erl_process.c:10232-10318 (erts_schedule: the
            // RUNNING_SYS work is the normal-scheduler branch; erts_dirty_process_main runs
            // a dirty scheduler's job), OTP-29.1.1. A process that is exiting resumes its
            // exit (`p->i = beam_continue_exit`) without it.
            if ctx.scheduler_type().is_dirty()
                || process.runtime.is_none()
                || process.dirty_exiting()
                || process.has_exit_cont()
            {
                // An exiting process claimed for system work (ERTS_PSFLG_RUNNING_SYS) goes to
                // ERTS_PSFLG_RUNNING: the cmpxchg of erl_process.c:10377-10404 never refuses an
                // exiting process.
                if !ctx.scheduler_type().is_dirty()
                    && ctx.proc_state().load(Ordering::Acquire) & arinsal_sched::psflg::RUNNING_SYS
                        != 0
                {
                    let _ = ctx.running_sys_to_running();
                }
                return true;
            }
            let result = super::executor_run::schedule_in_running_sys(process, ctx);
            let used = u32::try_from(reds.saturating_sub(process.heap.abi.fcalls)).unwrap_or(0);
            *calls = used;
            let outcome = match result {
                Ok(true) => {
                    // Port of erts/emulator/beam/erl_process.c:10440-10447 (`if (reds !=
                    // context_reds) { ... p->reds += actual_reds; }`), OTP-29.1.1.
                    process.reductions_used =
                        process.reductions_used.saturating_add(u64::from(used));
                    return true;
                }
                Ok(false) => crate::signals::reschedule_deferred_sys_tasks(process, ctx)
                    .map(|()| RunState::Yield),
                Err(error) => Err(error),
            };
            // `goto sched_out_proc`: the schedule-in work is the slice's outcome.
            process.finish_run(ctx, outcome);
            false
        })
    }

    // Inlined into the worker loop: the slice between erts_schedule's schedule-in and
    // schedule-out, as process_main runs it.
    #[inline(always)]
    fn run(c_p: &mut CP<'_>, esdp: &ErtsSchedulerData, _budget: u32, calls: &mut u32) {
        esdp.with_ctx(c_p, |process, ctx| {
            // Port of jit/arm/process_main.cpp and jit/x86/process_main.cpp (`REDS_IN =
            // FCALLS` after erts_schedule returns), OTP-29.1.1.
            process.x.set_reds_in(process.heap.abi.fcalls);
            // Port of erts/emulator/beam/beam_common.c (erts_dirty_process_main: `start_time`),
            // OTP-29.1.1: a dirty CPU scheduler charges the time from picking the process up.
            let dirty_start = (ctx.scheduler_type() == arinsal_sched::SchedulerType::DirtyCpu)
                .then(|| {
                    process
                        .take_work(|w| w.dirty_pickup.take())
                        .unwrap_or_else(std::time::Instant::now)
                });
            process.run_task(ctx);
            *calls = process.reds_used(ctx, dirty_start);
        })
    }

    // Port of erts/emulator/beam/erl_process.c:9660-9700 (erts_schedule, schedule-out of the
    // process that ran: `actual_reds = calls - esdp->virtual_reds`, `p->reds += actual_reds`,
    // then trace_schedule_out), OTP-29.1.1.
    fn schedule_out(c_p: &mut CP<'_>, esdp: &ErtsSchedulerData, calls: u32) {
        esdp.with_ctx(c_p, |process, ctx| {
            let virtual_reds = std::mem::take(&mut process.virtual_reds);
            ctx.add_virtual_reds(virtual_reds);
            process.reductions_used = process
                .reductions_used
                .saturating_add(u64::from(calls.saturating_sub(virtual_reds)));
            process.heap.set_alloc_ix(None);
            process.native = None;
            if crate::trace::running_procs_enabled() {
                crate::trace::emit_process(
                    process,
                    ctx.pid(),
                    crate::trace::RUNNING_PROCS,
                    "out",
                    &[],
                );
            }
        })
    }

    fn scheduler_shutdown(&mut self) {
        // The probe holds a reference to this process's own struct.
        self.set_signal_probe(None);
        if let Some(pid) = self.self_pid() {
            self.persistent_terms
                .release_update_permission(crate::natives::sys::persistent_owner(pid));
        }
    }

    fn scheduler_profile_event(scheduler_id: u32, active: bool, active_schedulers: u32) {
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
        crate::erl_nfunc_sched::erts_destroy_nfunc(self);
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
                Payload::Signal(Signal::Link) => links.push(event.from),
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

impl Process {
    /// The reductions the slice used, the `calls` the scheduler passes to `erts_schedule`:
    /// what it took from FCALLS on a normal scheduler, a dirty scheduler's own rule otherwise.
    /// `p->virtual_reds` stays for erts_schedule's schedule-out to subtract.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp (context_switch: `reds_used =
    // REDS_IN - FCALLS`) and beam_common.c (erts_dirty_process_main: `reds_used`), OTP-29.1.1.
    #[inline(always)]
    fn reds_used(
        &self,
        ctx: &mut RunCtx<'_, crate::Process>,
        dirty_start: Option<std::time::Instant>,
    ) -> u32 {
        let virtual_reds = self.virtual_reds;
        match ctx.scheduler_type() {
            arinsal_sched::SchedulerType::Normal => {
                u32::try_from(self.x.reds_in().saturating_sub(self.heap.abi.fcalls)).unwrap_or(0)
            }
            arinsal_sched::SchedulerType::DirtyIo => virtual_reds.saturating_add(1),
            arinsal_sched::SchedulerType::DirtyCpu => {
                let treds = dirty_start.map_or(0, |start| erts_time2reds(start.elapsed()));
                u32::try_from(treds.saturating_add(u64::from(virtual_reds)))
                    .unwrap_or(i32::MAX as u32)
                    .min(i32::MAX as u32)
            }
        }
    }

    #[inline(always)]
    fn run_task(&mut self, ctx: &mut RunCtx<'_, crate::Process>) {
        if self.runtime.is_none() {
            // A process with no node runtime (the in-process test harness) has no code to
            // run; it ends at once.
            ctx.erts_proc_exit_free(self);
            return;
        }
        // Profiling allocates no side record unless runnable-proc profiling is actually on.
        // Port of erts/emulator/beam/erl_process.c:6978-6992 (schedule_process_sys_task and
        // the enqueue paths test erts_system_profile_flags.runnable_procs before
        // profile_runnable_proc), OTP-29.1.1: without profiling this is one flag test.
        if crate::natives::misc::profile_runnable_procs()
            && !self.slice().is_some_and(|work| work.profile_active)
        {
            crate::natives::misc::profile_process_event(self, ctx, true);
            self.slice_mut().profile_active = true;
        }
        if self.dirty_exiting() {
            // Exited by a dirty signal handler while queued for a dirty scheduler: the exit
            // ran there, only the process structure remains to be released.
            ctx.erts_proc_exit_free(self);
            return;
        }
        if self.has_exit_cont() {
            // Port of erts/emulator/beam/erl_process.c:14819 (erts_continue_exit_process
            // yield: `p->i = beam_continue_exit`) and beam_emu.c / jit/x86/instr_common.cpp:295
            // (continue_exit: `erts_continue_exit_process(c_p); goto do_schedule`),
            // OTP-29.1.1: an exiting process resumes at its exit continuation.
            self.erts_continue_exit_process(&mut Vm {}, ctx);
            return self.exit_outcome(ctx);
        }
        let result = self.run_executor(ctx);
        if self.has_exit_cont()
            || ctx.proc_state().load(Ordering::Acquire) & arinsal_sched::psflg::FREE != 0
        {
            // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:304-385 (process_exit /
            // raise_exception_shared: `handle_error` returned NULL, `jmp do_schedule`),
            // OTP-29.1.1: the slice terminated the process in place (terminate_proc ->
            // erts_do_exit_process); erts_schedule reads FREE or the exit continuation.
            return self.exit_outcome(ctx);
        }
        if self.dirty_exiting() {
            // Port of erts/emulator/beam/erl_process.c:10096 (need_forced_exit), OTP-29.1.1:
            // the process already terminated while the job ran; whatever the job returned,
            // only the process structure remains to be released.
            ctx.erts_proc_exit_free(self);
            return;
        }
        self.finish_run(ctx, result)
    }

    /// How the slice that ran `erts_do_exit_process` / `erts_continue_exit_process` ends:
    /// both `goto do_schedule`, and erts_schedule reads FREE from `p->state`; an exit that
    /// suspended at ERTS_CONTINUE_EXIT_DIST_PEND_SPAWN_MONITORS waits (ACTIVE cleared), any
    /// other stays active.
    // Port of erts/emulator/beam/beam_emu.c (normal_exit / continue_exit: `goto do_schedule`),
    // OTP-29.1.1.
    fn exit_outcome(&self, ctx: &RunCtx<'_, crate::Process>) {
        if self.exit_waits() {
            self.wait_locked(ctx);
        }
    }

    /// A slice that ends waiting outside a receive (hibernate, suspend, an exit pending on
    /// spawn monitors, a debugger wait) clears `ERTS_PSFLG_ACTIVE` in `p->state` for
    /// schedule_out_process, as the receive's own wait does in beam_jit_wait_locked. Receive
    /// timers are set in the slice (beam_jit_wait_timeout) and cancelled where the receive
    /// ends (remove_message / timeout / exit), never here.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1192-1196 (beam_jit_wait_locked:
    // `erts_atomic32_read_band_relb(&c_p->state, ~ERTS_PSFLG_ACTIVE)`), OTP-29.1.1.
    //
    // A message that reached the outer queue since the process last looked
    // (`ERTS_PSFLG_MSG_SIG_IN_Q`) keeps it active: erts clears the bit under the msgq lock, which
    // a sender takes before it reads the state, so the sender sees the process inactive and
    // schedules it; the lock-free queue has the same order in the one state word.
    fn wait_locked(&self, ctx: &RunCtx<'_, crate::Process>) {
        let _ = arinsal_sched::erts_wait_clear_active(ctx.proc_state());
    }

    /// The slice ends with dirty work: `ERTS_PSFLG_DIRTY_CPU_PROC` / `ERTS_PSFLG_DIRTY_IO_PROC`
    /// in `p->state`, which schedule_out_process reads to pick the dirty run queue.
    // Port of erts/emulator/beam/bif.c:5683-5703 (erts_schedule_bif:
    // `erts_atomic32_read_bset_nob(&c_p->state, mask, set)`) and erl_nif.c:3466
    // (schedule_dirty_nif), OTP-29.1.1.
    fn schedule_dirty(ctx: &RunCtx<'_, crate::Process>, kind: arinsal_sched::DirtyKind) {
        let set = match kind {
            arinsal_sched::DirtyKind::Cpu => arinsal_sched::psflg::DIRTY_CPU_PROC,
            arinsal_sched::DirtyKind::Io => arinsal_sched::psflg::DIRTY_IO_PROC,
        };
        ctx.proc_state().fetch_or(set, Ordering::AcqRel);
    }

    /// The process ends with `reason`: `erts_do_exit_process` runs on this scheduler's VM view.
    fn exit_with(&mut self, ctx: &mut RunCtx<'_, crate::Process>, reason: Term) {
        self.erts_do_exit_process(&mut Vm {}, ctx, reason);
        self.exit_outcome(ctx)
    }

    #[inline(always)]
    fn run_executor(&mut self, ctx: &mut RunCtx<'_, crate::Process>) -> Result<RunState, VmError> {
        let esdp = ctx.esdp();
        let data = arinsal_sched::erts_sched_registers(esdp);
        let mut result = data.registers.with(|reg| process_main(self, ctx, reg));
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
        if matches!(result, Ok(RunState::Yield | RunState::Wait))
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
            Ok(RunState::Wait)
        } else {
            result
        }
    }

    fn finish_run(
        &mut self,
        ctx: &mut RunCtx<'_, crate::Process>,
        result: Result<RunState, VmError>,
    ) {
        if matches!(&result, Ok(RunState::Wait | RunState::Done(_)))
            && self.slice().is_some_and(|work| work.profile_active)
        {
            crate::natives::misc::profile_process_event(self, ctx, false);
            self.slice_mut().profile_active = false;
        }
        // Port of erts/emulator/beam/erl_process.c:6747-6763 (schedule_out_process), OTP-29.1.1:
        // with GC disabled the dirty collection is dropped; the next collection does it.
        if !ctx.scheduler_type().is_dirty()
            && !self.heap.gc_enabled()
            && self.cold.as_mut().is_some_and(|cold| {
                cold.dirty_gc.take().is_some() && cold.dirty_sys_tasks.is_empty()
            })
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
                // ERTS_PSFLG_DIRTY_ACTIVE_SYS sends it to the dirty CPU run queue.
                ctx.set_dirty_active_sys();
            }
            Ok(RunState::Yield) => {}
            Ok(RunState::Wait) => {
                let _ =
                    self.take_work(|work| std::mem::take(&mut work.suspend_parked).then_some(()));
                self.wait_locked(ctx);
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
                {
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
                self.exit_with(
                    ctx,
                    // erts passes `am_normal` (beam_common.c, `erts_do_exit_process(c_p, am_normal)`).
                    Term::atom(arinsal_term::atoms::NORMAL),
                )
            }
            Err(error) => {
                if matches!(error, VmError::Yield) {
                    return;
                }
                if let VmError::Dirty(kind) = error {
                    if self.slice().is_some_and(|work| work.dirty_sys_gc) {
                        ctx.set_dirty_active_sys();
                    }
                    Self::schedule_dirty(ctx, kind);
                    return;
                }
                self.terminate_proc(ctx, error);
                self.exit_outcome(ctx)
            }
        }
    }

    /// Terminates the process with the exception `error` found no catch for: `{Value,
    /// Stacktrace}` for an error (add_stacktrace), the EXF_LOG message, then
    /// `erts_do_exit_process`.
    // Port of erts/emulator/beam/beam_common.c:685-725 (terminate_proc), OTP-29.1.1.
    pub(crate) fn terminate_proc(&mut self, ctx: &mut RunCtx<'_, crate::Process>, error: VmError) {
        let reason = exit_reason_from(self, &error);
        if matches!(&error, VmError::Raised(raised) if raised.class == arinsal_bifs::Class::Error) {
            report_process_error(self, ctx, reason);
        }
        crate::signals::process_exiting(self, ctx);
        if trace_boot_enabled() {
            eprintln!("arinsal boot: process {:?} exited: {error}", ctx.pid());
        }
        // erl_process.c:14173 (erts_do_exit_process: `p->arity = 0`) runs inside.
        self.erts_do_exit_process(&mut Vm {}, ctx, reason);
    }
}
