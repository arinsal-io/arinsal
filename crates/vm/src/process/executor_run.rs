use super::*;

impl Executor {
    /// One process slice on this scheduler: schedule-in, native entry, schedule-out.
    // Inlined into `Task::run` (its only caller), and `run_native_resume` into this: erts
    // switches out through one C frame (the JIT `bl erts_schedule`), and every Rust frame
    // between the worker loop and the native entry is a return the predictor misses after a
    // switch-out, because Erlang code returning into earlier slices' frames drained the
    // return-address stack.
    #[inline(always)]
    pub(super) fn run(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        budget: u32,
    ) -> Result<RunState, VmError> {
        let exec_key = ctx.scheduler_key();
        let cached = exec_key != 0 && process.exec_key == exec_key && process.self_pid.is_some();
        if !cached {
            process.heap.abi.self_pid = ctx.pid().to_term().expect("valid pid").tagged_word();
            process.self_pid = Some(ctx.pid());
        }
        // Port of erts/emulator/beam/erl_process.c:10180 (erts_schedule: esdp->current_process
        // = p), OTP-29.1.1. A simulated scheduler shares its thread with other runtimes, so
        // it binds the thread's hub on every turn.
        if self.hub_bound && !ctx.simulated() {
            self.current_process
                .store(ctx.pid().data(), Ordering::Relaxed);
        } else {
            self.hub_bound =
                crate::natives::nif::bind_scheduler_hub(process, &self.current_process);
        }
        if !cached {
            process.scheduler_id = ctx.scheduler_id().map_or(0, |id| id as u32);
            // Port of erts/emulator/beam/erl_process.h:2595 (erts_proc_sched_data): the process
            // turn uses the scheduler thread's reference and unique-integer counters.
            let thr = arinsal_bifs::scheduler_thr_id(
                ctx.scheduler_id().map(|id| id as u32),
                ctx.scheduler_count() as u32,
            );
            if process
                .scheduler_ref_state
                .as_ref()
                .is_none_or(|state| state.thr_id() != thr)
            {
                let state = match self.ref_state {
                    Some(state) if state.thr_id() == thr => state,
                    _ => {
                        let state = arinsal_bifs::bind_scheduler_ref_state(thr);
                        self.ref_state = Some(state);
                        state
                    }
                };
                process.scheduler_ref_state = Some(state);
            }
            process.exec_key = exec_key;
        }
        let schedule_started = crate::natives::erts_debug::long_schedule_monitored(process)
            .then(std::time::Instant::now);
        // A process runs with the code index active when it is scheduled in. The `in` trace
        // event resolves the current function against it, so this replica must be current
        // first (erts_find_function_from_pc reads the active code index).
        // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-247, OTP-29.1.1.
        self.vm.refresh_code();
        // Port of erts/emulator/beam/erl_process.c:10539-10543 (schedule-in tests
        // ERTS_TRACE_FLAGS(p) before any trace work), OTP-29.1.1: the process flag word has
        // `proc_flags::TRACE` while the trace table holds an entry for this process.
        if ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE != 0 {
            let running = crate::trace::running_mfa(process, ctx.pid())?;
            let running_fields = [running.unwrap_or(Term::small(0).expect("small zero"))];
            crate::trace::emit(
                Some(&mut self.vm),
                process,
                ctx,
                ctx.pid(),
                crate::trace::RUNNING,
                "in",
                &running_fields,
            );
            // Port of erts/emulator/beam/erl_process.c:10541-10543 (trace_schedule_in),
            // OTP-29.1.1.
            if crate::trace::flags(process, ctx.pid()) & crate::trace::CALL != 0 {
                crate::trace_bp::schedule_time_break(process, ctx.pid(), false);
            }
        }
        // Port of erts/emulator/beam/erl_process.c:10435 (`p->fcalls = reds`), OTP-29.1.1.
        // A normal slice replaces leftover FCALLS so the send after a code-permission
        // release is not skipped by a reduction check that still sees only a few: that
        // yield lets the waiter run and send `{Pid, locked}` first.
        // A 1-reduction quantum is the scheduler budget that splits `loop_rec` from
        // `wait`. Light BIFs do `subs FCALLS, #1; b.le yield` and resume at the same
        // entry (instr_bif.cpp:399-400, OTP-29.1.1), so installing FCALLS=1 never
        // enters the BIF. Leave a positive count alone in that case.
        let reds = budget.min(i32::MAX as u32) as i32;
        if process.native_pc().is_some() {
            if reds > 1 || process.heap.abi.fcalls <= 0 {
                process.heap.abi.fcalls = reds;
            }
        } else if process.heap.abi.fcalls <= 0 && reds > 0 {
            // Interpreted schedule-in. A trapping BIF charges FCALLS to 0 when it
            // yields; the continuation (lists:member/2) reads that counter as its
            // scan budget. Leaving it at 0 makes every resume yield without
            // scanning, and the process never reaches halt.
            process.heap.abi.fcalls = reds;
        }
        // Port of erts/emulator/beam/erl_process.c:12616 (erl_create_process: `p->i =
        // beam_run_process`), OTP-29.1.1: a spawned process (`p->u.initial` set) enters at the
        // stub on its first run. It is installed here, not at spawn, because process_info and
        // trace read `p->current = &p->u.initial` through the absence of a code address.
        if !process.entry_started() && process.initial_mfa.is_some() {
            process.set_run_process_entry()?;
        }
        process.replace_entry_started(true);
        // Port of erts/emulator/beam/jit/arm/process_main.cpp (copy_in_registers) and
        // erl_process.c (erts_schedule), OTP-29.1.1: the scheduler's one X register array is
        // the process's file for the slice, loaded with the `c_p->arity` saved registers.
        let saved_len = process.x.saved_arity();
        // SAFETY: `self.native_registers` lives in this boxed `Executor`, which is not moved
        // or dropped during the call, and the epilogue below detaches before `run` returns.
        unsafe { process.x.attach(&mut self.native_registers) };
        if crate::xreg_poison_enabled() {
            process.x[saved_len..].fill(crate::XREG_POISON);
        }
        let mut fast_ran = false;
        // Port of erts/emulator/beam/erl_process.c:10318-10351 (erts_schedule), OTP-29.1.1:
        // a process scheduled with non-message signals queued (a monitor, an alias message)
        // handles them in the scheduler and then enters its code like any other; the signals
        // are not a reason for a different entry path.
        let mut signals_handled = false;
        let mut signal_error = None;
        if ctx.has_pending_nmsg() && Self::fast_entry_ok_before_signals(process, ctx) {
            signals_handled = true;
            signal_error = schedule_in_signals(process, ctx).err();
        }
        let fast_result = if let Some(error) = signal_error {
            Some(Err(error))
        } else if Self::fast_entry_ok(process, ctx) {
            self.fast_resume(process, ctx, &mut fast_ran)
        } else {
            None
        };
        let result = if let Some(result) = fast_result {
            result
        } else {
            (|| -> Result<RunState, VmError> {
                'execution: {
                    // Port of erts/emulator/beam/erl_process.c:12940-13152 (erl_create_process), OTP-29.1.1.
                    // A spawned MFA may name a BIF directly; execute it as the process entry so
                    // exceptions such as exit/1 retain their BIF class and reason.
                    let initial_bif = process.take_work(|work| work.initial_bif.take());
                    let dirty_sys_gc = process.slice().is_some_and(|work| work.dirty_sys_gc);
                    if let Some((module, function, arity)) = initial_bif {
                        // Both spawn paths (erl_create_process and the distributed spawn) place the
                        // BIF's arguments in X0..X(arity-1); the entry runs the BIF on them.
                        let mut args = process.x[..usize::from(arity)].to_vec();
                        let Some(bif) = arinsal_bifs::lookup(&module, &function, arity) else {
                            // A BIF implemented by a VM native (process-aware BIFs such as
                            // erlang:node/1 or register/2) runs through the native table.
                            let resolved =
                                crate::natives::classify(&module, &function, arity, true);
                            match self.vm.dispatch_native(
                                process,
                                ctx,
                                &module,
                                &function,
                                usize::from(arity),
                                resolved,
                            ) {
                                Some(Ok(value)) => break 'execution Ok(RunState::Done(value)),
                                Some(Err(error)) => break 'execution Err(error),
                                None => {
                                    break 'execution Err(VmError::Unsupported(format!(
                                        "spawned BIF entry {module}:{function}/{arity} has no native"
                                    )));
                                }
                            }
                        };
                        let mut result = crate::calls::call_bif(&mut process.heap, bif, &args);
                        crate::calls::gc_after_bif(process, &mut args, &mut result)?;
                        match result {
                            Ok(value) => break 'execution Ok(RunState::Done(value)),
                            Err(error) => {
                                break 'execution Err(crate::exceptions::direct_bif_error(
                                    process, &module, &function, &args, error,
                                ));
                            }
                        }
                    }
                    // Port of erts/emulator/beam/erl_process.c:10318-10372 (ERTS_PSFLG_RUNNING_SYS:
                    // handle signals and execute system tasks before Erlang code), OTP-29.1.1.
                    // Port of erts/emulator/beam/erl_process.c:10363-10372 and 11018-11040
                    // (a dirty scheduler executes the dirty GC system task, then the process
                    // returns to a normal scheduler), OTP-29.1.1.
                    if dirty_sys_gc {
                        if !ctx.scheduler_type().is_dirty() {
                            // ERTS_PSFLG_DIRTY_ACTIVE_SYS: the dirty work runs before Erlang code.
                            break 'execution Err(VmError::Dirty(arinsal_sched::DirtyKind::Cpu));
                        }
                        process.slice_mut().dirty_sys_gc = false;
                        process.run_dirty_gc()?;
                        // The signals are handled on the normal scheduler the process returns to.
                        break 'execution Ok(RunState::Yield);
                    }
                    // Port of erts/emulator/beam/erl_process.c:10318-10351 (schedule: a process
                    // with signals queued handles them before Erlang code; with Erlang work to do
                    // and no dirty work, at most ERTS_SIG_HANDLE_REDS_MAX_PREFERED), OTP-29.1.1.
                    // A process parked on a request reply reads it from its message queue like
                    // erts_internal:await_result's receive, so the reply message is fetched here.
                    // Signals already handled at this schedule-in (before the fast entry) are
                    // not handled again: erts_schedule handles them once per schedule-in.
                    if !signals_handled
                        && (ctx.sys_task_run()
                            || !process.sig_cont_empty()
                            || process.delayed_gc_due()
                            || ctx.has_pending_nmsg())
                    {
                        schedule_in_signals(process, ctx)?;
                    }

                    // erts collects a process that is being scheduled in once signals have
                    // been fetched (erl_process.c:10415). One check per slice: later
                    // iterations have already executed and their live X count is gc_live,
                    // not the switch-out arity.
                    let mut schedule_in_gc = !fast_ran;
                    // Native code that exited only for a fetch reenters without a scheduling point.
                    let mut reenter = false;
                    loop {
                        // Port of erts/emulator/beam/erl_process.c (schedule: the scheduler-type
                        // switch; check_dirty_enqueue_in_prio_queue), OTP-29.1.1: a process whose dirty NIF has not run yet carries its
                        // ERTS_PSFLG_DIRTY_*_PROC flag, so it executes only on that dirty scheduler
                        // class and every other scheduler sends it back to the dirty run queue.
                        // Yielding or running here would resume the dirty-NIF dispatch stub as if
                        // it were an unresolved export.
                        let pending_dirty = process
                            .cold
                            .as_ref()
                            .and_then(|cold| cold.native_dirty_nif)
                            .map(|(_, _, class)| class);
                        let dirty_here = pending_dirty
                            .is_some_and(|class| class == scheduler_class(ctx.scheduler_type()));
                        match pending_dirty {
                            Some(arinsal_bifs::SchedulerClass::DirtyCpu) if !dirty_here => {
                                break Err(VmError::Dirty(arinsal_sched::DirtyKind::Cpu));
                            }
                            Some(arinsal_bifs::SchedulerClass::DirtyIo) if !dirty_here => {
                                break Err(VmError::Dirty(arinsal_sched::DirtyKind::Io));
                            }
                            _ => {}
                        }
                        let reentered = std::mem::take(&mut reenter);
                        if !dirty_here && !reentered {
                            // A caught exception re-enters this loop without replenishing its process slice.
                            if ctx.remaining() == 0 {
                                break Ok(RunState::Yield);
                            }
                            if process.force_yield() {
                                process.set_force_yield(false);
                                break Ok(RunState::Yield);
                            }
                            // g_proc_sched: a suspended process is not scheduled; a hibernating
                            // one stays waiting until a message arrives, then continues at apply/3.
                            if let Some(wait) = self.sched_preempt(process, ctx)? {
                                break Ok(wait);
                            }
                        }
                        // Port of erts/emulator/beam/erl_process.c:10190 (a finished dirty
                        // job returns the process to a normal scheduler before its continuation).
                        if ctx.scheduler_type().is_dirty() && process.dirty_bif_completed() {
                            break Ok(RunState::Yield);
                        }
                        // Port of erts/emulator/beam/bif.c:5814-5835
                        // (erts_call_dirty_bif): a completed dirty BIF resumes by calling its
                        // internal result/exception export with the scheduled argument registers.
                        if let Some(((module, function, arity), args)) =
                            process.take_dirty_bif_continuation()
                        {
                            let arity = usize::from(arity);
                            process.x.ensure_x(arity + 2);
                            process.x[arity] = Term::atom(
                                arinsal_term::global_atoms().intern(module).map_err(|_| {
                                    VmError::Unsupported("dirty continuation module atom".into())
                                })?,
                            );
                            process.x[arity + 1] = Term::atom(
                                arinsal_term::global_atoms().intern(function).map_err(|_| {
                                    VmError::Unsupported("dirty continuation function atom".into())
                                })?,
                            );
                            process.x[..arity].copy_from_slice(&args);
                            process.heap.abi.arity = arity as u8;
                            process.gc_live = arity;
                            let continuation = self.vm.apply_fixed(process, arity, Some(ctx));
                            let continuation = match continuation {
                                Ok(outcome) => outcome,
                                Err(VmError::Trap(trap)) => {
                                    if let Some(error) = crate::exceptions::resume(
                                        &mut self.vm,
                                        process,
                                        Some(ctx),
                                        trap,
                                    )? {
                                        process.heap.abi.exc.freason = 0;
                                        process.heap.abi.exc.fvalue = 0;
                                        break Err(error);
                                    }
                                    process.heap.abi.exc.freason = 0;
                                    process.heap.abi.exc.fvalue = 0;
                                    continue;
                                }
                                Err(error) => break Err(error),
                            };
                            match continuation {
                                crate::ImportOutcome::Dispatch => continue,
                                crate::ImportOutcome::Yield => break Ok(RunState::Yield),
                                crate::ImportOutcome::Returned(value) => {
                                    if process.native_pc().is_none() {
                                        break Ok(RunState::Done(value));
                                    }
                                    continue;
                                }
                            }
                        }
                        process.native_transfer = false;
                        crate::dist::continue_fragmented_send(process, ctx)?;
                        // Port of erts/emulator/beam/erl_nif.c (erts_call_dirty_nif), OTP-29.1.1:
                        // the dirty scheduler runs the NIF, then the process returns to a normal
                        // scheduler to continue after the call.
                        if let Some((identity, resume_pc, class)) =
                            process.cold.as_ref().and_then(|cold| cold.native_dirty_nif)
                            && scheduler_class(ctx.scheduler_type()) == class
                        {
                            process.slice_mut().native_dirty_nif = None;
                            match crate::native_helpers::run_static_nif(process, identity) {
                                Ok(value) => {
                                    process.x[0] = value;
                                    process.native_continuation_resume = true;
                                    process.set_native_resume_arity(1);
                                    process.set_native_pc(Some(resume_pc));
                                    if ctx.scheduler_type().is_dirty() {
                                        break Ok(RunState::Yield);
                                    }
                                    continue;
                                }
                                Err(error @ (VmError::Dirty(_) | VmError::Yield)) => {
                                    // A continuation scheduled for another scheduler class.
                                    let class = match error {
                                        VmError::Dirty(arinsal_sched::DirtyKind::Cpu) => {
                                            arinsal_bifs::SchedulerClass::DirtyCpu
                                        }
                                        VmError::Dirty(arinsal_sched::DirtyKind::Io) => {
                                            arinsal_bifs::SchedulerClass::DirtyIo
                                        }
                                        _ => arinsal_bifs::SchedulerClass::Normal,
                                    };
                                    process.slice_mut().native_dirty_nif =
                                        Some((identity, resume_pc, class));
                                    break Err(error);
                                }
                                Err(VmError::Trap(trap)) => {
                                    if let Some(error) = crate::exceptions::resume(
                                        &mut self.vm,
                                        process,
                                        Some(ctx),
                                        trap,
                                    )? {
                                        break Err(error);
                                    }
                                    process.heap.abi.exc.freason = 0;
                                    process.heap.abi.exc.fvalue = 0;
                                    process.heap.abi.exc.ftrace = 0;
                                    continue;
                                }
                                Err(error) => break Err(error),
                            }
                        }
                        if process.force_yield() {
                            process.set_force_yield(false);
                            break Ok(RunState::Yield);
                        }
                        if let Some(kind) = process
                            .native_pc()
                            .and_then(crate::trace::TraceFrameKind::of)
                        {
                            // The scheduler resumes at a trace frame's return address: return
                            // through the frame here, as its stub does for native returns.
                            // Port of erts/emulator/beam/jit/arm/instr_trace.cpp
                            // (emit_return_trace, emit_i_return_to_trace,
                            // emit_i_call_trace_return), OTP-29.1.1.
                            process.set_native_pc(None);
                            let returned = crate::trace::return_through_trace_frame(
                                process,
                                kind,
                                |p, words| {
                                    p.heap.release_stack(words);
                                },
                            );
                            let Some((event, caller)) = returned else {
                                break Err(VmError::Unsupported("native trace frame".into()));
                            };
                            if let Some(event) = event {
                                self.emit_native_return_event(process, ctx, event)?;
                            }
                            let resume_pc = caller.tagged_word() as usize;
                            let bridge = arinsal_beamasm::rt::arinsal_enter_native_return
                                as *const () as usize;
                            if resume_pc == bridge {
                                if !resume_after_native_return(process) {
                                    break Ok(RunState::Done(process.x[0]));
                                }
                            } else {
                                process.native_continuation_resume = true;
                                process.set_native_resume_arity(1);
                                process.set_native_pc(Some(resume_pc));
                            }
                            continue;
                        }

                        if let Some(code_ptr) = process.native_pc() {
                            crate::beamasm_integration::count_native_call();
                            if schedule_in_gc {
                                schedule_in_gc = false;
                                collect_on_schedule_in(process)?;
                            }
                            process.set_native_pc(None);

                            let trace_boot = trace_boot_enabled();
                            let function = trace_boot
                                .then(|| crate::native_function_at(code_ptr))
                                .flatten();
                            if trace_boot {
                                eprintln!(
                                    "arinsal boot: enter native {:?} pc={code_ptr:#x}",
                                    function
                                );
                                if function.as_ref().is_some_and(|f| {
                                    f.module == "prim_file" && f.function == "decode_path"
                                }) {
                                    eprintln!(
                                        "arinsal boot: decode_path input={:?}",
                                        process.x.first()
                                    );
                                }
                            }
                            // A native call to a BIF that parked the process (cross-process signal
                            // reply) is redone once the process wakes, like the interpreter re-executes
                            // the call instruction.
                            let retry = process.take_native_retry();
                            let outcome = if let Some(target_pc) = retry {
                                if let Some(call_arity) =
                                    retry_call_arity(target_pc, process.x.saved_arity())
                                {
                                    process.heap.abi.arity = call_arity;
                                }
                                if process
                                    .cold
                                    .as_ref()
                                    .and_then(|cold| cold.bif_trap.as_ref())
                                    .is_some_and(|pending| {
                                        !pending.schedule_out && pending.import == target_pc
                                    })
                                {
                                    crate::native_helpers::debug_assert_native_heap(process);
                                }
                                // The redone call keeps its return address and call site, so a BIF
                                // that fails after trapping raises at the original call.
                                let (resume_pc, call_site_pc) =
                                    process.take_native_retry_site().unwrap_or((0, 0));
                                crate::beamasm_integration::note_call_retry();
                                if call_site_pc != 0 {
                                    process.native_error_pc = call_site_pc;
                                }
                                arinsal_beamasm::ExitReason::CallUnported {
                                    target_pc,
                                    resume_pc,
                                }
                            } else {
                                // Port of erts/emulator/beam/erl_process.c (schedule: reductions
                                // used = CONTEXT_REDS - FCALLS), OTP-29.1.1: native code counts down
                                // FCALLS; the scheduler charges what it used.
                                // FCALLS and the scheduler budget are one counter in erts. A BIF
                                // charge can zero the process counter while the slice still
                                // has reductions; refilling avoids yielding before the next
                                // instruction (the send after a code-permission release).
                                let native = {
                                    if process.heap.abi.fcalls <= 0
                                        && let Ok(remaining) = i32::try_from(ctx.remaining())
                                        && remaining > 0
                                    {
                                        process.heap.abi.fcalls = remaining;
                                    }
                                    let fcalls_before = process.heap.abi.fcalls;
                                    // A code change this scheduler committed waits for thread
                                    // progress first: every other scheduler then finishes the slice it
                                    // runs with the previous code index (erts' code barrier).
                                    if crate::code_ix::take_code_barrier() {
                                        ctx.block_thread_progress(std::time::Duration::ZERO);
                                    }
                                    self.native_registers.active_code_ix = self
                                        .vm
                                        .code_ix
                                        .process_code_ix(crate::trace::saves_calls(process))
                                        as u64;
                                    let native = crate::native_bridge::run_native_resume(
                                        process,
                                        &mut self.native_registers,
                                        code_ptr,
                                    );
                                    let consumed =
                                        fcalls_before.saturating_sub(process.heap.abi.fcalls);
                                    ctx.consume(u32::try_from(consumed).unwrap_or(0));
                                    // Native `timeout` has no scheduler context to send its trace event.
                                    if process.native_exit_kind
                                        != crate::proc_create::NativeExit::None
                                        && process.take_native_timeout_trace()
                                    {
                                        crate::trace::timeout_event(
                                            Some(&mut self.vm),
                                            process,
                                            ctx,
                                        );
                                    }
                                    // Port of erts/emulator/beam/erl_process.c (erts_current_reductions),
                                    // OTP-29.1.1: the process's reduction count includes what its
                                    // native code consumed from FCALLS.
                                    // Reductions the slice gave up with `ERTS_VBUMP_ALL_REDS` ended
                                    // the slice but are not the process's own.
                                    let virtual_reds = std::mem::take(&mut process.virtual_reds);
                                    ctx.add_virtual_reds(virtual_reds);
                                    process.reductions_used =
                                        process.reductions_used.saturating_add(
                                            u64::try_from(consumed)
                                                .unwrap_or(0)
                                                .saturating_sub(u64::from(virtual_reds)),
                                        );
                                    native
                                };
                                match native {
                                    Ok(outcome) => outcome,
                                    Err(VmError::Trap(trap)) => {
                                        if let Some(error) = crate::exceptions::resume(
                                            &mut self.vm,
                                            process,
                                            Some(ctx),
                                            trap,
                                        )? {
                                            break Err(error);
                                        }
                                        process.heap.abi.exc.freason = 0;
                                        process.heap.abi.exc.fvalue = 0;
                                        process.heap.abi.exc.ftrace = 0;
                                        continue;
                                    }
                                    Err(error) => return Err(error),
                                }
                            };
                            if trace_boot
                                && function.as_ref().is_some_and(|f| {
                                    f.module == "prim_file" && f.function == "decode_path"
                                })
                            {
                                eprintln!(
                                    "arinsal boot: decode_path exit={outcome:?} output={:?}",
                                    process.x.first()
                                );
                            }
                            match self.after_native(process, ctx, outcome, code_ptr, &mut reenter) {
                                Ok(Flow::Continue) => continue,
                                Ok(Flow::Break(result)) => break result,
                                Err(error) => return Err(error),
                            }
                        }
                        let result = process.drain(ctx).and_then(|()| {
                            if schedule_in_gc {
                                schedule_in_gc = false;
                                collect_on_schedule_in(process)?;
                            }
                            // Only a BIF run for a native exit keeps a redzone.
                            process.heap.clear_native_redzone();
                            self.vm.enter_native_position(process)
                        });
                        // erts schedules out only when FCALLS runs out; entering the native code
                        // of the process's position continues the slice.
                        if matches!(&result, Ok(RunState::Yield))
                            && process.native_pc().is_some()
                            && !process.force_yield()
                            && native_transfer_continues(process, ctx)
                        {
                            continue;
                        }
                        if hibernate_stopped(process) {
                            if hibernate_fetch_collect(process, ctx)? {
                                if let Some(runtime) = process.runtime {
                                    runtime.mark_hibernating(ctx.pid(), true);
                                    // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                                    process.slice_mut().hibernate_sched = true;
                                }
                                break Ok(RunState::Wait { timeout_pos: None });
                            }
                            self.install_apply(process, ctx)?;
                            continue;
                        }
                        if matches!(&result, Ok(RunState::Yield))
                            && process.runtime.is_some()
                            && crate::suspend::ctx_suspended(ctx)
                        {
                            break park_suspended(process, ctx);
                        }
                        let trap = match result {
                            Err(VmError::Trap(trap)) => {
                                // g_port_fix: busy port_command suspends the sender and retries the call.
                                if crate::port::take_busy_suspend() {
                                    break Ok(RunState::Wait { timeout_pos: None });
                                }
                                trap
                            }
                            Err(VmError::Exception { reason, frame }) => {
                                if trace_boot_enabled() {
                                    eprintln!("arinsal boot: exception {reason} at {frame}");
                                }
                                let mut trap = crate::exceptions::from_legacy(&reason)?;
                                if reason == "undef"
                                    && let Some((mfa, arity)) = frame.rsplit_once('/')
                                    && let Some((module, function)) = mfa.split_once(':')
                                    && let Ok(arity) = arity.parse::<usize>()
                                    && arity <= process.x.len()
                                {
                                    trap.top = Some(crate::stacktrace::TopFrame::Bif {
                                        module: arinsal_term::global_atoms()
                                            .intern(module)
                                            .map_err(|_| {
                                                VmError::Unsupported("undef module atom".into())
                                            })?,
                                        function: arinsal_term::global_atoms()
                                            .intern(function)
                                            .map_err(|_| {
                                                VmError::Unsupported("undef function atom".into())
                                            })?,
                                        args: crate::stacktrace::BifArgs::from_terms(
                                            &process.x[..arity],
                                        )?,
                                        info: crate::stacktrace::BifErrorInfo::None,
                                    });
                                }
                                trap
                            }
                            Err(VmError::ExceptionInfo {
                                reason,
                                frame,
                                info,
                            }) => {
                                if trace_boot_enabled() {
                                    eprintln!("arinsal boot: exception {reason} at {frame}");
                                }
                                let mut trap = crate::exceptions::from_legacy(&reason)?;
                                // The arity of the current function (`c_p->i`).
                                let arity = process
                                    .native_pc()
                                    .and_then(crate::native_bridge::native_function_at)
                                    .map_or(0, |function| function.arity);
                                trap.top = Some(crate::stacktrace::TopFrame::CurrentArgsWithInfo(
                                    Some(Term::small(i64::from(arity)).expect("arity is small")),
                                    info,
                                ));
                                trap
                            }
                            other => break other,
                        };
                        if trace_boot_enabled() {
                            eprintln!(
                                "arinsal boot: process {:?} trap in {} at pc {:?}: {:?} reason {:?}",
                                ctx.pid(),
                                self.vm.frame_name(process),
                                process.native_pc(),
                                trap.class,
                                arinsal_term::to_owned(trap.reason)
                            );
                        }
                        let resumed =
                            crate::exceptions::resume(&mut self.vm, process, Some(ctx), trap)?;
                        if let Some(error) = resumed {
                            break Err(error);
                        }
                        process.heap.abi.exc.freason = 0;
                        process.heap.abi.exc.fvalue = 0;
                        process.heap.abi.exc.ftrace = 0;
                    }
                }
            })()
        };
        // erts keeps a process whose middle queue holds unhandled signals (ERTS_PSFLG_SIG_Q)
        // scheduled for signal handling even when it waits (erl_process.c:10318-10351, with
        // all reductions since it has no Erlang work); this scheduler only wakes a process for
        // new input, so the rest is handled before it sleeps. Messages it produces end the
        // wait like a new message would.
        let result = match result {
            Ok(RunState::Wait { timeout_pos })
                if !process.sig_cont_empty() || process.delayed_gc_due() =>
            {
                let queued = process.inbox.len();
                match process.handle_local_signals(ctx) {
                    Ok(()) if process.inbox.len() == queued => Ok(RunState::Wait { timeout_pos }),
                    Ok(()) => Ok(RunState::Yield),
                    Err(error) => Err(error),
                }
            }
            other => other,
        };
        if matches!(
            result,
            Ok(RunState::Yield | RunState::Wait { .. }) | Err(VmError::Yield | VmError::Dirty(_))
        ) {
            // Port of erts/emulator/beam/erl_process.c:10550 and beam_common.c (the yield or
            // wait site stores its live X register count in `c_p->arity`, and only those are
            // saved in `c_p->arg_reg`), OTP-29.1.1: a native continuation already holds it in
            // `header.arity`; an interpreted switch-out has it in `gc_live`, the count of its
            // last live operand or call arity (4 from exception handler entry until it runs).
            // A native call the scheduler redoes (BIF trap, traced apply) carries the larger of
            // the two, whichever side stated it. From here on `header.arity` is the one count
            // every reader of the saved file takes.
            let arity_set = process.native_pc().is_some() && process.native_arity_set;
            let call_arity = usize::from(process.heap.abi.arity);
            let mut live_x = if arity_set {
                call_arity
            } else if process.native_pc().is_some() {
                process.gc_live.max(call_arity)
            } else {
                process.gc_live
            };
            // A fun call or apply the scheduler redoes reads its operands from the saved file:
            // the arguments and the fun or module and function above them, and nothing else is
            // live. The saved count is that operand count; the retry takes the call's own arity
            // back from it (`retry_call_arity`).
            if !arity_set
                && process.native_pc().is_some()
                && let Some(operands) = process
                    .native_retry()
                    .and_then(|target| retry_operand_count(target, call_arity))
            {
                live_x = operands;
            }
            process.heap.abi.arity = live_x.min(usize::from(u8::MAX)) as u8;
            process.gc_live = live_x;
            let save_x = live_x;
            if crate::native_bridge::return_trace_enabled() && process.native_pc().is_some() {
                eprintln!(
                    "[sched-save-native] live_x={live_x} x0={:#x} native_pc={:?}",
                    process.x[0].tagged_word(),
                    process.native_pc()
                );
            }
            // Port of erts/emulator/beam/jit/arm/process_main.cpp (copy_out_registers),
            // OTP-29.1.1: the `c_p->arity` registers go from the scheduler array into the
            // process, six of them inline (`def_arg_reg`) so switching out allocates nothing.
            process.x.detach_save(save_x);
        } else {
            process.x.detach_save(0);
            process.x = crate::proc_create::ArgRegs::empty();
        }
        // A waiting process is not collected when it switches out: erts only runs
        // `scheduler_gc_proc` for a process being scheduled in (a yielded process is still
        // active) or handling signals/sys tasks, so a sleeping receiver with on-heap message
        // fragments keeps them until it next runs.
        if matches!(result, Ok(RunState::Yield)) {
            // erts collects a switched-out process rooting only its `c_p->arity` live X
            // registers; the saved register file above that holds dead registers whose
            // pointers may refer to a heap an earlier collection already freed.
            // Port of erts/emulator/beam/erl_process.c:10415 (ERTS_IS_GC_DESIRED ->
            // scheduler_gc_proc, garbage_collect with p->arity), OTP-29.1.1.
            let live = switched_out_live(process);
            process.collect_bin_vheap_if_due(live)?;
        }
        // OTP emits regular `out` only when a process is scheduled out; normal exit uses the
        // separate `out_exiting` event when that flag is enabled.
        // Port of erts/emulator/beam/erl_process.c:10550-10567, OTP-29.1.1.
        if (matches!(result, Ok(RunState::Yield | RunState::Wait { .. }))
            || matches!(result, Err(VmError::Yield | VmError::Dirty(_))))
            && ctx.exit_flags().load(Ordering::Acquire) & proc_flags::TRACE != 0
        {
            let running = crate::trace::running_mfa(process, ctx.pid())?;
            // erl_trace.c:752-760 (trace_sched_session): no current function is reported as 0.
            let running_fields = [running.unwrap_or(Term::small(0).expect("small zero"))];
            // Port of erts/emulator/beam/erl_process.c:10556-10560 (trace_schedule_out).
            if crate::trace::flags(process, ctx.pid()) & crate::trace::CALL != 0 {
                crate::trace_bp::schedule_time_break(process, ctx.pid(), true);
            }
            crate::trace::emit(
                Some(&mut self.vm),
                process,
                ctx,
                ctx.pid(),
                crate::trace::RUNNING,
                "out",
                &running_fields,
            );
        }
        if let Some(schedule_started) = schedule_started {
            crate::natives::erts_debug::after_schedule(
                process,
                schedule_started.elapsed().as_nanos() as u64,
            );
        }
        result
    }
}

/// The signal handling of a schedule-in: a process with signals or system tasks queued
/// handles them before Erlang code, at most `SIG_HANDLE_REDS_MAX_PREFERED` reductions of
/// signals when it has Erlang work and no dirty work.
// Port of erts/emulator/beam/erl_process.c:10318-10351 (erts_schedule: the
// ERTS_PSFLG_RUNNING_SYS branch, erts_proc_sig_handle_incoming then execute_sys_tasks),
// OTP-29.1.1.
fn schedule_in_signals(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<(), VmError> {
    let reds = i32::try_from(ctx.remaining()).unwrap_or(i32::MAX);
    let mut sig_reds = if process.slice().is_some_and(|work| work.dirty_sys_gc) {
        reds
    } else {
        SIG_HANDLE_REDS_MAX_PREFERED
    };
    if ctx.sys_task_run() {
        process.cold_mut().sys_task_point = true;
    }
    let max_reds = sig_reds;
    let handled = process.handle_incoming(ctx, &mut sig_reds, max_reds, false);
    ctx.consume(u32::try_from(sig_reds).unwrap_or(0));
    // Port of erts/emulator/beam/erl_process.c (schedule: `reds -= sig_reds`,
    // then `p->fcalls = reds`; the process's reductions are what the slice
    // used), OTP-29.1.1: the signal handling is the process's own work.
    process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(sig_reds.max(0));
    process.reductions_used = process
        .reductions_used
        .saturating_add(u64::try_from(sig_reds).unwrap_or(0));
    let executed = handled.and_then(|_| {
        if ctx.sys_task_run() {
            crate::signals::execute_sys_tasks(process, ctx)
        } else {
            Ok(())
        }
    });
    if ctx.sys_task_run() {
        process.cold_mut().sys_task_point = false;
    }
    executed?;
    Ok(())
}
