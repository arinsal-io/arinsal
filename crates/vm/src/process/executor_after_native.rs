use super::*;

impl Executor {
    /// What the exit of a native call asks of the entry loop.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp (the labels `process_main` jumps to
    // after a native call returns to the scheduler), OTP-29.1.1.
    // The arms are the entry loop's own, moved as they were; their exits are explicit returns.
    #[allow(clippy::needless_return)]
    pub(super) fn after_native(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        outcome: arinsal_beamasm::ExitReason,
        code_ptr: usize,
        reenter: &mut bool,
    ) -> Result<Flow, VmError> {
        match outcome {
            arinsal_beamasm::ExitReason::Yield => {
                crate::beamasm_integration::count_native_yield();
                let exit_kind = std::mem::take(&mut process.native_exit_kind);
                if exit_kind != crate::proc_create::NativeExit::None {
                    if exit_kind == crate::proc_create::NativeExit::ReserveFetch {
                        // Native `recv_marker_reserve` needs the outer queue
                        // fetched first. Port of erts/emulator/beam/
                        // erl_proc_sig_queue.h:2226 (erts_msgq_recv_marker_insert),
                        // OTP-29.1.1: fetch (no handling), then rerun the
                        // instruction in place: erts does not schedule out there.
                        if process.signal_probe().is_none() {
                            process.set_signal_probe(ctx.signal_probe());
                        }
                        process.fetch_signals(ctx)?;
                        *reenter = true;
                        return Ok(Flow::Continue);
                    }
                    if exit_kind == crate::proc_create::NativeExit::SignalFetch {
                        // Native `loop_rec` reached the end of the message queue
                        // with signals to fetch or handle. Port of
                        // erts/emulator/beam/jit/arm/instr_msg.cpp:84-104
                        // (i_loop_rec_shared calls erts_proc_sig_receive_helper),
                        // OTP-29.1.1: the helper runs here, then the `loop_rec`
                        // reruns; a yield schedules out there.
                        if process.signal_probe().is_none() {
                            process.set_signal_probe(ctx.signal_probe());
                        }
                        let fcalls = i32::try_from(ctx.remaining()).unwrap_or(i32::MAX);
                        let (used, _) = process.receive_helper(ctx, fcalls)?;
                        let used = u32::try_from(used).unwrap_or(0);
                        ctx.consume(used);
                        process.reductions_used =
                            process.reductions_used.saturating_add(u64::from(used));
                        return Ok(Flow::Continue);
                    }
                    if exit_kind == crate::proc_create::NativeExit::Wait
                        && let Some(timeout_pos) = process.native_wait.take()
                    {
                        // A native receive found no matching message. Like the
                        // interpreter's `wait`, sleep only if nothing arrived since the
                        // slice began; the process resumes at the `loop_rec` label with
                        // no live X registers.
                        process.gc_live = 0;
                        process.set_native_resume_arity(0);
                        // A receive without clauses blocks even with messages queued,
                        // like the interpreter's self-targeting `wait`.
                        let self_wait = std::mem::take(&mut process.native_wait_self);
                        if self_wait {
                            // Queued messages never match; fetch them so the outer
                            // queue does not keep waking the process.
                            process.fetch_signals(ctx)?;
                        } else if !Vm::mailbox_ready_to_wait(process, &mut Some(&mut *ctx))? {
                            return Ok(Flow::Continue);
                        }
                        return Ok(Flow::Break(Ok(RunState::Wait { timeout_pos })));
                    }
                }
                // A native `i_yield` is a scheduler boundary even when the
                // interpreter left a deferred yield request in the process.
                // Port of erts/emulator/beam/erl_process.c:10550
                // (trace_schedule_out), OTP-29.1.1.
                process.set_force_yield(false);
                return Ok(Flow::Break(Ok(RunState::Yield)));
            }
            arinsal_beamasm::ExitReason::CallUnported {
                target_pc,
                resume_pc,
            } => {
                crate::beamasm_integration::count_call_unported();
                // The native call site names the caller only if the called BIF
                // raises; any other continuation must not inherit it.
                let call_site_pc = std::mem::take(&mut process.native_error_pc);
                process.set_native_retry_site(Some((resume_pc, call_site_pc)));
                if target_pc == arinsal_beamasm::dispatch::RETURN_TO_DISPATCH_IDENTITY {
                    // A traced native return: its return_from events are out
                    // and its frame is gone; resume_pc is the caller.
                    if let Some((frames, value)) = process
                        .cold_mut()
                        .native_return_events
                        .take()
                        .map(|boxed| *boxed)
                    {
                        self.emit_native_return_frames(process, ctx, frames, value, resume_pc)?;
                    }
                    let bridge =
                        arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
                    if resume_pc == bridge {
                        if !resume_after_native_return(process) {
                            return Ok(Flow::Break(Ok(RunState::Done(process.x[0]))));
                        }
                    } else {
                        process.native_continuation_resume = true;
                        process.set_native_resume_arity(1);
                        process.set_native_pc(Some(resume_pc));
                    }
                    return Ok(Flow::Continue);
                }
                if target_pc == arinsal_beamasm::dispatch::DIRTY_NIF_DISPATCH_IDENTITY {
                    // The NIF body's return point resumes once the dirty
                    // scheduler ran the NIF.
                    if process
                        .heap
                        .stack_get(0)
                        .is_some_and(|word| word.tagged_word() as usize == resume_pc)
                    {
                        process.heap.release_stack(1);
                    }
                    let class = process.native_dirty_nif_mut().map(|(_, resume, class)| {
                        *resume = resume_pc;
                        *class
                    });
                    return Ok(Flow::Break(Err(match class {
                        Some(arinsal_bifs::SchedulerClass::DirtyCpu) => {
                            VmError::Dirty(arinsal_sched::DirtyKind::Cpu)
                        }
                        Some(arinsal_bifs::SchedulerClass::Normal) => VmError::Yield,
                        _ => VmError::Dirty(arinsal_sched::DirtyKind::Io),
                    })));
                }
                if let Some((line, live)) =
                    arinsal_beamasm::dispatch::decode_line_breakpoint_identity(target_pc)
                {
                    // Port of erts/emulator/beam/beam_bp.c:1821-1865
                    // (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1:
                    // spill the live X registers, then call
                    // erts_internal:breakpoint/4; the native code at
                    // `resume_pc` restores them when it returns.
                    let function = crate::native_function_at(resume_pc).ok_or_else(|| {
                        VmError::Unsupported(format!(
                            "native line breakpoint resume address is unregistered: {resume_pc:#x}"
                        ))
                    })?;
                    if process
                        .heap
                        .stack_get(0)
                        .is_some_and(|word| word.tagged_word() as usize == resume_pc)
                    {
                        process.heap.release_stack(1);
                    }
                    let live = usize::from(live);
                    let handler = self.vm.load_named("erts_internal").is_ok_and(|id| {
                        self.vm.code.modules[id]
                            .functions
                            .iter()
                            .any(|(_, name, arity)| *name == "breakpoint" && *arity == 4)
                    });
                    // The handler's own breakpoints are not reported.
                    let cycle = function.module == "erts_internal"
                        && function.function == "breakpoint"
                        && function.arity == 4;
                    // Port of erts/emulator/beam/emu/instrs.tab:1269-1286
                    // (i_enabled_line_breakpoint), OTP-29.1.1: the frame's own
                    // return address, then the spilled registers above it.
                    let site = crate::beamasm_integration::line_breakpoint_site(resume_pc)
                        .ok_or_else(|| {
                            VmError::Unsupported(format!(
                                "native line breakpoint site is unregistered: {resume_pc:#x}"
                            ))
                        })?;
                    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:276-292
                    // (emit_i_line_breakpoint_trampoline_shared), OTP-29.1.1:
                    // collect when the spilled registers and S_RESERVED do not fit.
                    process.ensure(live + 2 + arinsal_term::S_RESERVED, live)?;
                    if !process.heap.reserve_stack(1)
                        || !process
                            .heap
                            .stack_set(0, crate::proc_create::native_continuation_term(site))
                        || !process.heap.reserve_stack(live)
                    {
                        return Ok(Flow::Break(Err(VmError::Unsupported(
                            "line breakpoint stack is full".into(),
                        ))));
                    }
                    for index in 0..live {
                        let value = process.x[index];
                        if !process.heap.stack_set(index, value) {
                            break;
                        }
                    }
                    if !handler || cycle {
                        process.native_continuation_resume = true;
                        process.set_native_resume_arity(1);
                        process.set_native_pc(Some(resume_pc));
                        return Ok(Flow::Continue);
                    }
                    if !process.heap.reserve_stack(1)
                        || !process
                            .heap
                            .stack_set(0, crate::proc_create::native_continuation_term(resume_pc))
                    {
                        return Ok(Flow::Break(Err(VmError::Unsupported(
                            "line breakpoint stack is full".into(),
                        ))));
                    }
                    let module_atom = arinsal_term::global_atoms()
                        .intern(function.module)
                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                    let function_atom = arinsal_term::global_atoms()
                        .intern(function.function)
                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                    let handler_module = arinsal_term::global_atoms()
                        .intern("erts_internal")
                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                    let handler_function = arinsal_term::global_atoms()
                        .intern("breakpoint")
                        .map_err(|_| VmError::Unsupported("atom table".into()))?;
                    process.x[0] = Term::atom(module_atom);
                    process.x[1] = Term::atom(function_atom);
                    process.x[2] =
                        Term::small(i64::from(function.arity)).expect("arity is a small integer");
                    process.x[3] = Term::small(i64::from(line)).expect("line is a small integer");
                    process.x[4] = Term::atom(handler_module);
                    process.x[5] = Term::atom(handler_function);
                    process.gc_live = 4;
                    process.native_apply = true;
                    let result = self.vm.apply_fixed(process, 4, true, 0, Some(ctx));
                    process.native_apply = false;
                    match result? {
                        crate::ImportOutcome::Jump(_) => self.vm.enter_native_at_jump(process),
                        crate::ImportOutcome::Advanced => {}
                        crate::ImportOutcome::Yield => {
                            if process.native_pc().is_some()
                                && native_transfer_continues(process, ctx)
                            {
                                return Ok(Flow::Continue);
                            }
                            return Ok(Flow::Break(Ok(RunState::Yield)));
                        }
                        crate::ImportOutcome::Returned(value) => {
                            process.x[0] = value;
                            if process.native_pc().is_none() {
                                return Ok(Flow::Break(Ok(RunState::Done(value))));
                            }
                        }
                    }
                    return Ok(Flow::Continue);
                }
                if target_pc == arinsal_beamasm::dispatch::BREAKPOINT_DISPATCH_IDENTITY {
                    // Port of erts/emulator/beam/beam_bp.c (erts_generic_breakpoint),
                    // OTP-29.1.1: count, then call/meta events in the interpreter's
                    // order; the trap's CP is the native resume point.
                    let function = crate::native_function_at(resume_pc).ok_or_else(|| {
                        VmError::Unsupported(format!(
                            "native breakpoint resume address is unregistered: {resume_pc:#x}"
                        ))
                    })?;
                    if process
                        .heap
                        .stack_get(0)
                        .is_some_and(|word| word.tagged_word() as usize == resume_pc)
                    {
                        process.heap.release_stack(1);
                    }
                    // The trace callbacks read every argument from the scheduler
                    // array, which is the process's X file.
                    let arity = usize::from(function.arity).min(process.x.len());
                    let actions = crate::trace::executor_native_call_event(
                        &mut self.vm,
                        process,
                        ctx,
                        &function,
                        true,
                    )?;
                    crate::trace::push_native_trace_frame(process, resume_pc, &actions, arity)?;
                    if crate::trace_bp::debug_breakpoint_enabled(
                        process,
                        function.module,
                        function.function,
                        function.arity,
                    ) {
                        // Port of erts/emulator/beam/jit/arm/instr_trace.cpp:90-125
                        // (`emit_debug_bp`) and beam_common.c:1294-1345
                        // (`call_error_handler`), OTP-29.1.1: debug breakpoints
                        // tail-call the process-configured breakpoint handler.
                        process.gc_live = arity;
                        process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(1);
                        process.reductions_used = process.reductions_used.saturating_add(1);
                        match self.vm.call_debug_breakpoint_handler(
                            process,
                            function.module,
                            function.function,
                            arity,
                            Some(ctx),
                        )? {
                            crate::ImportOutcome::Jump(_) => self.vm.enter_native_at_jump(process),
                            crate::ImportOutcome::Advanced => {}
                            crate::ImportOutcome::Yield => {
                                if process.native_pc().is_some()
                                    && native_transfer_continues(process, ctx)
                                {
                                    return Ok(Flow::Continue);
                                }
                                return Ok(Flow::Break(Ok(RunState::Yield)));
                            }
                            crate::ImportOutcome::Returned(value) => {
                                process.x[0] = value;
                                if process.native_pc().is_none() {
                                    return Ok(Flow::Break(Ok(RunState::Done(value))));
                                }
                            }
                        }
                        return Ok(Flow::Continue);
                    }
                    process.native_continuation_resume = true;
                    // Port of erts/emulator/beam/jit/arm/instr_trace.cpp (the
                    // breakpoint stub saves the function's arguments in
                    // `c_p->arity`), OTP-29.1.1: a collection while the process
                    // is switched out, such as a delayed dirty one, roots them.
                    process.set_native_resume_arity(function.arity);
                    process.gc_live = usize::from(function.arity);
                    process.set_native_pc(Some(resume_pc));
                    // A loop of traced calls leaves native code on every call and
                    // would never reach the end-of-slice check: preempt here once
                    // the budget is used up (erts counts reductions per call).
                    // The breakpoint left native code before its call's reduction was
                    // charged.
                    process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(1);
                    process.reductions_used = process.reductions_used.saturating_add(1);
                    if !ctx.consume(1) || process.heap.abi.fcalls <= 0 {
                        return Ok(Flow::Break(Ok(RunState::Yield)));
                    }
                    return Ok(Flow::Continue);
                }
                if target_pc == arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY {
                    let value = match process.send_message_prio(
                        Some(&mut self.vm),
                        Some(ctx),
                        process.x[0],
                        process.x[1],
                        false,
                    ) {
                        Ok(value) => value,
                        // Port of erts/emulator/beam/bif.c:2581 (SEND_YIELD): a
                        // busy port suspended the sender; the send is redone
                        // when it is resumed.
                        Err(VmError::Trap(_)) if crate::port::take_busy_suspend() => {
                            process.set_native_retry(Some(target_pc));
                            process.set_native_pc(Some(code_ptr));
                            return Ok(Flow::Break(Ok(RunState::Wait { timeout_pos: None })));
                        }
                        Err(error) => return Err(error),
                    };
                    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624
                    // (emit_send, call_light_bif_shared GC test), OTP-29.1.1.
                    let value = process.gc_after_bif(value)?;
                    process.x[0] = value;
                    if !resume_after_native_return(process) {
                        return Ok(Flow::Break(Ok(RunState::Done(value))));
                    }
                    return Ok(Flow::Continue);
                }
                if matches!(
                    target_pc,
                    arinsal_beamasm::dispatch::CALL_FUN_UNPORTED
                        | arinsal_beamasm::dispatch::APPLY_FIXED_UNPORTED
                        | arinsal_beamasm::dispatch::APPLY2_UNPORTED
                        | arinsal_beamasm::dispatch::APPLY3_UNPORTED
                ) {
                    // The fragment pushed the native continuation as a CP, so the
                    // interpreter performs these as tail calls.
                    // The retry redoes the apply from its operands: the
                    // arguments, the fun or module and function, and apply/3's
                    // three. Registers above them are dead.
                    let saved_live = (usize::from(process.heap.abi.arity) + 2)
                        .max(3)
                        .min(process.x.len());
                    let saved_x = process.x[..saved_live].to_vec();
                    let collections_before = process.stats.gc.collections;
                    let result = match target_pc {
                        arinsal_beamasm::dispatch::CALL_FUN_UNPORTED => {
                            let arity = usize::from(process.heap.abi.arity);
                            let fun = process.x.get(arity).copied().unwrap_or(Term::NIL);
                            self.vm.call_fun_term(process, fun, arity, true, Some(ctx))
                        }
                        _ => {
                            process.native_apply = true;
                            let result = match target_pc {
                                arinsal_beamasm::dispatch::APPLY_FIXED_UNPORTED => {
                                    let arity = usize::from(process.heap.abi.arity);
                                    self.vm.apply_fixed(process, arity, true, 0, Some(ctx))
                                }
                                arinsal_beamasm::dispatch::APPLY2_UNPORTED => {
                                    self.vm.apply_bif(process, 2, true, 0, Some(ctx))
                                }
                                _ => self.vm.apply_bif(process, 3, true, 0, Some(ctx)),
                            };
                            process.native_apply = false;
                            result
                        }
                    };
                    let trap = match result {
                        Ok(outcome) => {
                            match outcome {
                                crate::ImportOutcome::Jump(_) => {
                                    self.vm.enter_native_at_jump(process)
                                }
                                crate::ImportOutcome::Advanced => {}
                                crate::ImportOutcome::Yield => {
                                    if process.native_pc().is_some()
                                        && native_transfer_continues(process, ctx)
                                    {
                                        return Ok(Flow::Continue);
                                    }
                                    // Port of erts/emulator/beam/bif.h (BIF_TRAP*) and
                                    // beam_bif_export_trap, OTP-29.1.1: a BIF that trapped
                                    // with its state pending context-switches into its trap
                                    // export with the arguments the trap kept; the apply is
                                    // not redone.
                                    if process
                                        .cold
                                        .as_ref()
                                        .is_some_and(|cold| cold.bif_trap.is_some())
                                    {
                                        let retry_pc = crate::bif_traps::bif_export_trap_pc();
                                        process.set_native_retry(Some(retry_pc));
                                        process.set_native_pc(Some(code_ptr));
                                    }
                                    return Ok(Flow::Break(Ok(RunState::Yield)));
                                }
                                crate::ImportOutcome::Returned(value) => {
                                    // The applied BIF ran through its export
                                    // trampoline, which charges the call.
                                    process.reductions_used =
                                        process.reductions_used.saturating_add(1);
                                    process.x[0] = value;
                                    if process.native_pc().is_none() {
                                        return Ok(Flow::Break(Ok(RunState::Done(value))));
                                    }
                                    if ctx.scheduler_type().is_dirty() {
                                        return Ok(Flow::Break(Ok(RunState::Yield)));
                                    }
                                }
                            }
                            return Ok(Flow::Continue);
                        }
                        // A suspending or yielding applied BIF (busy port,
                        // cross-process await, ERTS_BIF_YIELD) is redone when
                        // the process runs again, as for direct native calls.
                        Err(VmError::Trap(_)) if crate::port::take_busy_suspend() => {
                            for (register, value) in process.x.iter_mut().zip(&saved_x) {
                                *register = *value;
                            }
                            process.set_native_retry(Some(target_pc));
                            process.set_native_pc(Some(code_ptr));
                            return Ok(Flow::Break(Ok(RunState::Wait { timeout_pos: None })));
                        }
                        Err(VmError::Yield) => {
                            // A collection the call ran (the epilogue of a
                            // yielding BIF that allocated) moved the registers;
                            // the copies taken before it are stale.
                            if process.stats.gc.collections == collections_before {
                                for (register, value) in process.x.iter_mut().zip(&saved_x) {
                                    *register = *value;
                                }
                            }
                            process.set_native_retry(Some(target_pc));
                            process.set_native_pc(Some(code_ptr));
                            return Ok(Flow::Break(Ok(RunState::Yield)));
                        }
                        Err(VmError::Dirty(kind)) => {
                            for (register, value) in process.x.iter_mut().zip(&saved_x) {
                                *register = *value;
                            }
                            process.set_native_retry(Some(target_pc));
                            process.set_native_pc(Some(code_ptr));
                            return Ok(Flow::Break(Err(VmError::Dirty(kind))));
                        }
                        Err(VmError::Trap(trap)) => trap,
                        Err(VmError::Exception { reason, frame }) => {
                            legacy_exception_trap(process, &reason, &frame)?
                        }
                        // Port of erts/emulator/beam/beam_common.c:1568
                        // (erts_hibernate), OTP-29.1.1: apply(erlang, hibernate, _)
                        // discarded the stack like a direct call.
                        Err(VmError::Unsupported(_)) if hibernate_stopped(process) => {
                            if hibernate_resumes_in_place(process) {
                                hibernate_fetch_collect(process, ctx)?;
                                process.set_native_retry(Some(target_pc));
                                process.set_native_pc(Some(code_ptr));
                                return Ok(Flow::Break(Ok(RunState::Wait { timeout_pos: None })));
                            }
                            process.set_native_pc(None);
                            process.native_continuation_resume = false;
                            if hibernate_fetch_collect(process, ctx)? {
                                if let Some(runtime) = process.runtime {
                                    runtime.mark_hibernating(ctx.pid(), true);
                                    // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                                    process.slice_mut().hibernate_sched = true;
                                }
                                return Ok(Flow::Break(Ok(RunState::Wait { timeout_pos: None })));
                            }
                            self.install_apply(process, ctx)?;
                            return Ok(Flow::Continue);
                        }
                        Err(error) => return Err(error),
                    };
                    // Port of erts/emulator/beam/beam_common.c:1345-1427
                    // (apply_bif_error_adjustment), OTP-29.1.1: the applied
                    // function raised at the apply instruction, which names the
                    // calling function; its continuation is not another frame.
                    if call_site_pc != 0
                        && target_pc != arinsal_beamasm::dispatch::CALL_FUN_UNPORTED
                    {
                        // Port of erts/emulator/beam/jit/arm/instr_call.cpp
                        // (emit_i_apply_last, OTP-29.1.1): a tail apply has
                        // deallocated its frame, so a BIF failure other than the
                        // error/exit/throw adjustment is attributed to the
                        // continuation it returns to, not to the apply site.
                        let tail_site =
                            call_site_pc & arinsal_beamasm::module::RETURN_SITE_TAG == 0;
                        let bridge =
                            arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
                        process.native_error_pc = if tail_site
                            && resume_pc != bridge
                            && matches!(
                                trap.top,
                                Some(crate::stacktrace::TopFrame::Bif { module, function, .. })
                                    if !(global_atoms().text(module) == Some("erlang")
                                        && global_atoms().text(function) == Some("apply"))
                            ) {
                            resume_pc | arinsal_beamasm::module::RETURN_SITE_TAG
                        } else {
                            call_site_pc
                        };
                        if process
                            .heap
                            .stack_get(0)
                            .is_some_and(|word| word.tagged_word() as usize == resume_pc)
                        {
                            process.heap.release_stack(1);
                        }
                    }
                    if let Some(error) =
                        crate::exceptions::resume(&mut self.vm, process, Some(ctx), trap)?
                    {
                        return Ok(Flow::Break(Err(error)));
                    }
                    process.heap.abi.exc.freason = 0;
                    process.heap.abi.exc.fvalue = 0;
                    process.heap.abi.exc.ftrace = 0;
                    return Ok(Flow::Continue);
                }
                if target_pc == crate::bif_traps::bif_export_trap_pc() {
                    // Port of jit/arm/beam_asm_global.cpp:145
                    // (emit_bif_export_trap) and instr_bif.cpp:525-536
                    // (context_switch_simplified), OTP-29.1.1.
                    let schedule_out = process
                        .cold
                        .as_ref()
                        .and_then(|cold| cold.bif_trap.as_ref())
                        .is_some_and(|pending| pending.schedule_out);
                    if schedule_out {
                        let trap_site = process.trap_site();
                        if let Some(pending) = process.bif_trap_mut() {
                            pending.schedule_out = false;
                            (pending.caller_module, pending.caller_ip) = trap_site;
                        }
                        crate::bif_traps::arm_export_trap(process);
                        process.set_native_retry(Some(target_pc));
                        process.set_native_pc(Some(code_ptr));
                        return Ok(Flow::Break(Ok(RunState::Yield)));
                    }
                    // Port of erts/emulator/beam/beam_bp.c:321-330 and
                    // erl_bif_trace.c (the bif return trap frame stays on the
                    // stack across BIF_TRAP), OTP-29.1.1: the call event of a
                    // traced BIF that trapped was emitted at the first call; the
                    // return or exception event belongs to the last slice.
                    let trapped_callee = process
                        .cold
                        .as_ref()
                        .filter(|cold| cold.traced_native_call.is_some())
                        .and_then(|cold| cold.bif_trap.as_ref())
                        .and_then(|pending| {
                            let atoms = global_atoms();
                            Some((
                                atoms.text(pending.callee.0)?.to_owned(),
                                atoms.text(pending.callee.1)?.to_owned(),
                                pending.arity,
                            ))
                        });
                    let meter =
                        crate::bif_traps::TrapMeter::start_continuation(process, Some(&*ctx));
                    let trapped = crate::bif_traps::run_trapped_export(process, Some(ctx));
                    if let Some(Ok(crate::bif_traps::ResumeResult::Handler(result))) = &trapped {
                        meter.finish(process, Some(ctx), result.reductions());
                    }
                    if let Some((module, function, arity)) = &trapped_callee {
                        let outcome = match &trapped {
                            Some(Ok(crate::bif_traps::ResumeResult::Handler(
                                crate::bif_traps::HandlerResult::Done { value, .. },
                            ))) => Some(Ok(*value)),
                            Some(Err(VmError::Trap(trap))) => {
                                crate::exceptions::trace_class_reason(
                                    process,
                                    trap.class,
                                    trap.reason,
                                )
                                .ok()
                                .map(Err)
                            }
                            _ => None,
                        };
                        if let Some(outcome) = outcome {
                            let args = vec![Term::NIL; *arity];
                            self.vm.trace_native_return_outcome(
                                process, ctx, module, function, &args, outcome,
                            );
                        }
                    }
                    match trapped {
                        Some(Ok(crate::bif_traps::ResumeResult::Handler(
                            crate::bif_traps::HandlerResult::Yield { .. }
                            | crate::bif_traps::HandlerResult::YieldDirect { .. },
                        ))) => {
                            if let Some(pending) = process.bif_trap_mut() {
                                pending.schedule_out = false;
                            }
                            crate::bif_traps::arm_export_trap(process);
                            process.set_native_retry(Some(target_pc));
                            process.set_native_pc(Some(code_ptr));
                            return Ok(Flow::Break(Ok(RunState::Yield)));
                        }
                        // The trapped BIF's continuation is an Erlang export: it is
                        // called with the saved arguments, and returns to the caller's
                        // native continuation. Port of erts/emulator/beam/beam_common.c
                        // (BIF_TRAP), OTP-29.1.1.
                        Some(Ok(crate::bif_traps::ResumeResult::Export(trap))) => {
                            process.native_apply = true;
                            let outcome = self.vm.trap_to_export(process, trap, true, Some(ctx));
                            process.native_apply = false;
                            match outcome? {
                                crate::ImportOutcome::Jump(_) => {
                                    self.vm.enter_native_at_jump(process)
                                }
                                crate::ImportOutcome::Advanced => {}
                                crate::ImportOutcome::Yield => {
                                    if process.native_pc().is_some()
                                        && native_transfer_continues(process, ctx)
                                    {
                                        return Ok(Flow::Continue);
                                    }
                                    return Ok(Flow::Break(Ok(RunState::Yield)));
                                }
                                crate::ImportOutcome::Returned(value) => {
                                    process.x[0] = value;
                                    if process.native_pc().is_none() {
                                        return Ok(Flow::Break(Ok(RunState::Done(value))));
                                    }
                                }
                            }
                            return Ok(Flow::Continue);
                        }
                        Some(Ok(crate::bif_traps::ResumeResult::Handler(
                            crate::bif_traps::HandlerResult::Done { value, .. },
                        ))) => {
                            process.x[0] = value;
                            if !resume_after_native_return(process) {
                                return Ok(Flow::Break(Ok(RunState::Done(value))));
                            }
                            return Ok(Flow::Continue);
                        }
                        Some(Ok(crate::bif_traps::ResumeResult::Handler(
                            crate::bif_traps::HandlerResult::Failed { .. },
                        ))) => {
                            return Ok(Flow::Break(Err(VmError::Unsupported(
                                "failed trapping BIF without exception".into(),
                            ))));
                        }
                        Some(Ok(crate::bif_traps::ResumeResult::Handler(
                            crate::bif_traps::HandlerResult::Export(_),
                        ))) => {
                            unreachable!("resumed BIF handlers cannot install first-call exports")
                        }
                        // The continuation export raised. It is the same BIF
                        // failure erts reports with ERTS_BIF_ERROR_TRAPPED:
                        // catch sees it, and the process does not exit.
                        Some(Err(VmError::Trap(trap))) => {
                            process.native_error_pc = call_site_pc;
                            if process
                                .heap
                                .stack_get(0)
                                .is_some_and(|word| word.tagged_word() as usize == resume_pc)
                            {
                                process.heap.release_stack(1);
                            }
                            if let Some(error) =
                                crate::exceptions::resume(&mut self.vm, process, Some(ctx), trap)?
                            {
                                return Ok(Flow::Break(Err(error)));
                            }
                            process.heap.abi.exc.freason = 0;
                            process.heap.abi.exc.fvalue = 0;
                            process.heap.abi.exc.ftrace = 0;
                            return Ok(Flow::Continue);
                        }
                        Some(Err(error)) => return Err(error),
                        None => {
                            return Ok(Flow::Break(Err(VmError::Unsupported(
                                "missing BIF trap export".into(),
                            ))));
                        }
                    }
                }
                let Some(export) = crate::beamasm_integration::export_dispatch(target_pc) else {
                    return Err(VmError::Unsupported(format!(
                        "unknown native export entry {target_pc:#x}"
                    )));
                };
                if trace_boot_enabled() && export.module == "prim_file" {
                    eprintln!(
                        "arinsal boot: export dispatch {}:{}/{} class={:?}",
                        export.module, export.function, export.arity, export.class
                    );
                }
                process.gc_live = usize::from(export.arity);
                // Like call_import_general: code loaded by another scheduler must be
                // visible to the BIF (function_exported/3, module_loaded/1, ...).
                self.vm.refresh_code();
                if matches!(
                    export.class,
                    arinsal_loader::ImportClass::Native
                        | arinsal_loader::ImportClass::Dynamic
                        | arinsal_loader::ImportClass::Fun
                ) || export.trap_entry
                    || (crate::trace_bp::any_pattern()
                        && crate::beamasm_integration::dispatch_bif(target_pc).is_some()
                        && crate::trace_bp::selects(
                            process,
                            &export.module,
                            &export.function,
                            export.arity,
                        ))
                {
                    let saved_arguments: smallvec::SmallVec<[Term; 8]> =
                        smallvec::SmallVec::from_slice(&process.x[..usize::from(export.arity)]);
                    let collections_before = process.stats.gc.collections;
                    // BIFs such as load_nif/2 identify their caller through
                    // `process.module`, which native code does not maintain: the
                    // caller is the native function holding the return address.
                    let interpreter_module = process.module;
                    // A module whose on_load is running is not current yet.
                    if let Some(caller) = native_caller_module(&self.vm, resume_pc) {
                        process.module = caller;
                    }
                    // erlang:make_fun/3 is implemented by the VM's call path (funs.rs), not
                    // by the native BIF table; handle it here like the interpreter does.
                    // erlang:make_fun/3 and fun_info/1,2, fun_info_mfa/1 are implemented
                    // by the VM's call path (funs.rs), not by the native BIF table.
                    let result = if export.class == arinsal_loader::ImportClass::Fun
                        && export.module == "erlang"
                        && matches!(
                            (export.function.as_str(), export.arity),
                            ("make_fun", 3) | ("fun_info", 1 | 2) | ("fun_info_mfa", 1)
                        ) {
                        Some(match export.function.as_str() {
                            "make_fun" => {
                                let args = [process.x[0], process.x[1], process.x[2]];
                                self.vm.make_export_fun(process, &args)
                            }
                            "fun_info" => self.vm.fun_info(process, export.arity == 2),
                            _ => self.vm.fun_info_mfa(process),
                        })
                    } else {
                        // Port of erts/emulator/beam/beam_common.c (BIF trap to a
                        // continuation export), OTP-29.1.1: a trapping BIF keeps
                        // its state between retries of this native call site.
                        let trap_args = [
                            process.x.first().copied().unwrap_or(Term::NIL),
                            process.x.get(1).copied().unwrap_or(Term::NIL),
                            process.x.get(2).copied().unwrap_or(Term::NIL),
                            process.x.get(3).copied().unwrap_or(Term::NIL),
                        ];
                        let traps_here = export.trap_entry
                            || process.slice().is_some_and(|work| work.bif_trap.is_some());
                        // Port of erts/emulator/beam/jit/arm/process_main.cpp
                        // (context_switch_simplified), OTP-29.1.1: a light BIF
                        // call that trapped context-switches; the process
                        // resumes in the continuation when it next runs.
                        let trap_site = process.trap_site();
                        if let Some(pending) = process
                            .bif_trap_mut()
                            .filter(|pending| pending.schedule_out && pending.import == target_pc)
                        {
                            pending.schedule_out = false;
                            (pending.caller_module, pending.caller_ip) = trap_site;
                            process.set_native_retry(Some(target_pc));
                            process.set_native_pc(Some(code_ptr));
                            crate::native_helpers::debug_assert_native_heap(process);
                            return Ok(Flow::Break(Ok(RunState::Yield)));
                        }
                        // A traced trapping BIF reports its call once, when it is
                        // first entered, and its return when it finishes.
                        // Port of erts/emulator/beam/beam_bp.c:321-330
                        // (erts_export_is_bif_traced), OTP-29.1.1.
                        let trap_traced = if traps_here
                            && crate::bif_traps::traps(
                                &export.module,
                                &export.function,
                                export.arity,
                            ) {
                            self.vm.trace_native_call_named(
                                process,
                                ctx,
                                &export.module,
                                &export.function,
                                usize::from(export.arity),
                                (usize::MAX, call_site_pc),
                                crate::trace::StackScan::None,
                            )
                        } else {
                            None
                        };
                        let meter =
                            crate::bif_traps::TrapMeter::start_continuation(process, Some(&*ctx));
                        if traps_here
                            && let Some(trapped) = crate::bif_traps::execute_named(
                                process,
                                &export.module,
                                &export.function,
                                target_pc,
                                usize::from(export.arity),
                                trap_args,
                                Some(ctx),
                            )
                        {
                            if let Ok(result) = &trapped {
                                meter.finish(process, Some(ctx), result.reductions());
                            }
                            let outcome = match trapped {
                                Ok(
                                    crate::bif_traps::HandlerResult::Yield { .. }
                                    | crate::bif_traps::HandlerResult::YieldDirect { .. },
                                ) => {
                                    // The continuation export runs on the next
                                    // schedule-in. This call site is not redone.
                                    if let Some(pending) = process.bif_trap_mut() {
                                        pending.schedule_out = false;
                                    }
                                    crate::bif_traps::arm_export_trap(process);
                                    process.set_native_retry(Some(
                                        crate::bif_traps::bif_export_trap_pc(),
                                    ));
                                    process.set_native_pc(Some(code_ptr));
                                    return Ok(Flow::Break(Ok(RunState::Yield)));
                                }
                                Ok(crate::bif_traps::HandlerResult::Done { value, .. }) => {
                                    process.x[0] = process.gc_after_bif(value)?;
                                    Some(Ok(process.x[0]))
                                }
                                Ok(crate::bif_traps::HandlerResult::Failed { .. }) => {
                                    Some(Err(VmError::Unsupported(
                                        "failed trapping BIF without exception".into(),
                                    )))
                                }
                                Ok(crate::bif_traps::HandlerResult::Export(_)) => {
                                    unreachable!("resumed BIF handler export")
                                }
                                Err(error) => Some(Err(error)),
                            };
                            if let (Some((module, function, args)), Some(result)) =
                                (&trap_traced, &outcome)
                            {
                                let reduced = match result {
                                    Ok(value) => Some(Ok(*value)),
                                    Err(VmError::Exception { reason, frame }) => {
                                        legacy_exception_trap(process, reason, frame)
                                            .ok()
                                            .and_then(|trap| {
                                                crate::exceptions::trace_class_reason(
                                                    process,
                                                    trap.class,
                                                    trap.reason,
                                                )
                                                .ok()
                                            })
                                            .map(Err)
                                    }
                                    Err(VmError::Trap(trap)) => {
                                        crate::exceptions::trace_class_reason(
                                            process,
                                            trap.class,
                                            trap.reason,
                                        )
                                        .ok()
                                        .map(Err)
                                    }
                                    Err(_) => None,
                                };
                                if let Some(reduced) = reduced {
                                    self.vm.trace_native_return_outcome(
                                        process, ctx, module, function, args, reduced,
                                    );
                                }
                            }
                            outcome
                        } else {
                            // The BIF runs at the native call site (erts c_p->i).
                            let (module_before, position_before) =
                                (process.module, process.position_marker());
                            process.native_call_pc = call_site_pc;
                            let traced = self.vm.trace_native_call_named(
                                process,
                                ctx,
                                &export.module,
                                &export.function,
                                usize::from(export.arity),
                                (usize::MAX, call_site_pc),
                                crate::trace::StackScan::None,
                            );
                            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp
                            // (call_light_bif_shared), OTP-29.1.1: a light BIF
                            // runs with E at the caller's frame; the return
                            // address is pushed only when it traps. A heavy BIF
                            // is entered through its export entry, whose frame
                            // holds the return address.
                            let light = process.native_light_bif_call && export.light_kind;
                            let hidden = usize::from(
                                light
                                    && process.heap.stack_get(0).is_some_and(|word| {
                                        word.tagged_word() as usize == resume_pc
                                    }),
                            );
                            process.heap.set_bif_hidden_words(hidden);
                            let result = self.vm.dispatch_native(
                                process,
                                ctx,
                                &export.module,
                                &export.function,
                                usize::from(export.arity),
                                (export.class, export.native_bits),
                            );
                            process.heap.set_bif_hidden_words(0);
                            process.native_call_pc = 0;
                            // A BIF that traps to an Erlang export (erts BIF_TRAP*)
                            // context-switches to beam_bif_export_trap, which runs
                            // the export on schedule-in. Port of erts/emulator/beam/
                            // jit/arm/instr_bif.cpp (trap to the export), OTP-29.1.1.
                            let result = match result {
                                Some(Err(VmError::TrapExport(trap))) => {
                                    let callee = (export.module_atom, export.function_atom);
                                    crate::bif_traps::install_export_trap(
                                        process, target_pc, callee, &trap,
                                    );
                                    crate::bif_traps::arm_export_trap(process);
                                    process.set_native_retry(Some(
                                        crate::bif_traps::bif_export_trap_pc(),
                                    ));
                                    process.set_native_pc(Some(code_ptr));
                                    return Ok(Flow::Break(Ok(RunState::Yield)));
                                }
                                other => other,
                            };
                            if let (Some((module, function, args)), Some(result)) =
                                (&traced, &result)
                            {
                                self.vm.trace_native_return(
                                    process, ctx, module, function, args, result,
                                );
                            }
                            // Port of erts/emulator/beam/beam_bif_load.c:793
                            // (call_on_load_function_1), OTP-29.1.1: the BIF traps
                            // into the on_load function like a call; the native
                            // continuation the trampoline pushed is its CP.
                            if export.module == "erlang"
                                && export.function == "call_on_load_function"
                                && matches!(result, Some(Ok(_)))
                                && (process.module, process.position_marker())
                                    != (module_before, position_before)
                            {
                                process.tick();
                                self.vm.enter_native_at_jump(process);
                                return Ok(Flow::Continue);
                            }
                            result
                        }
                    };
                    process.module = interpreter_module;
                    let result = result.or_else(|| {
                        let (bif, arity) = crate::beamasm_integration::dispatch_bif(target_pc)?;
                        let arity = usize::from(arity);
                        let (result, reductions) = self.vm.call_bif_traced_named(
                            process,
                            ctx,
                            &export.module,
                            &export.function,
                            bif,
                            arity,
                        );
                        process.reductions_used = process
                            .reductions_used
                            .saturating_add(u64::from(reductions));
                        Some(match result {
                            Ok(value) => Ok(value),
                            Err(error) => {
                                let arguments = process.x[..arity].to_vec();
                                Err(crate::exceptions::bif_error_with_atoms(
                                    process,
                                    &export.module,
                                    &export.function,
                                    export.module_atom,
                                    export.function_atom,
                                    &arguments,
                                    error,
                                ))
                            }
                        })
                    });
                    // Interpreter-style BIF errors raise like traps, as in
                    // the interpreter's own call_ext path.
                    let result = match result {
                        Some(Err(VmError::Exception { reason, frame })) => Some(Err(
                            VmError::Trap(legacy_exception_trap(process, &reason, &frame)?),
                        )),
                        other => other,
                    };
                    if let Some(result) = result {
                        let value = match result {
                            Ok(value) => value,
                            // A busy port_command suspends the native
                            // caller and redoes the call when the port is
                            // no longer busy, like the interpreter.
                            Err(VmError::Trap(_)) if crate::port::take_busy_suspend() => {
                                for (register, value) in process.x.iter_mut().zip(&saved_arguments)
                                {
                                    *register = *value;
                                }
                                process.set_native_retry(Some(target_pc));
                                process.set_native_pc(Some(code_ptr));
                                return Ok(Flow::Break(Ok(RunState::Wait { timeout_pos: None })));
                            }
                            Err(VmError::Trap(mut trap)) => {
                                // Port of erts/emulator/beam/beam_common.c
                                // (save_stacktrace: a failing BIF is the top
                                // frame, the calling function the next one),
                                // OTP-29.1.1.
                                // erts omits erlang:error/1,2,3 from the trace
                                // (beam_common.c save_stacktrace).
                                if trap.class == arinsal_bifs::Class::Error
                                    && trap.top.is_none()
                                    && trap.trace.is_none()
                                    && !(export.module == "erlang" && export.function == "error")
                                {
                                    trap.top = Some(crate::stacktrace::TopFrame::Bif {
                                        module: export.module_atom,
                                        function: export.function_atom,
                                        // The X registers still hold the arguments, moved
                                        // by any collection the call ran; the copies taken
                                        // before it are stale.
                                        args: crate::stacktrace::BifArgs::from_terms(
                                            &process.x[..saved_arguments.len()],
                                        )?,
                                        info: crate::stacktrace::BifErrorInfo::Plain,
                                    });
                                }
                                process.native_error_pc = call_site_pc;
                                // The BIF does not return: drop the native
                                // continuation the trap pushed as its CP, which
                                // erts never creates for a BIF call.
                                if process
                                    .heap
                                    .stack_get(0)
                                    .is_some_and(|word| word.tagged_word() as usize == resume_pc)
                                {
                                    process.heap.release_stack(1);
                                }
                                if let Some(error) = crate::exceptions::resume(
                                    &mut self.vm,
                                    process,
                                    Some(ctx),
                                    trap,
                                )? {
                                    return Ok(Flow::Break(Err(error)));
                                }
                                process.heap.abi.exc.freason = 0;
                                process.heap.abi.exc.fvalue = 0;
                                process.heap.abi.exc.ftrace = 0;
                                return Ok(Flow::Continue);
                            }
                            // ERTS_BIF_YIELD (e.g. a persistent_term updater
                            // waiting for thread progress): the native call is
                            // redone when the process is scheduled again.
                            Err(VmError::Yield) => {
                                // A collection the call ran (the epilogue of a
                                // yielding BIF that allocated) moved the
                                // registers; the copies taken before it are stale.
                                if process.stats.gc.collections == collections_before {
                                    for (register, value) in
                                        process.x.iter_mut().zip(&saved_arguments)
                                    {
                                        *register = *value;
                                    }
                                }
                                process.set_native_retry(Some(target_pc));
                                process.set_native_pc(Some(code_ptr));
                                return Ok(Flow::Break(Ok(RunState::Yield)));
                            }
                            // A dirty BIF called on a normal scheduler is redone
                            // on a dirty one (erts_schedule_bif), OTP-29.1.1.
                            Err(VmError::Dirty(kind)) => {
                                for (register, value) in process.x.iter_mut().zip(&saved_arguments)
                                {
                                    *register = *value;
                                }
                                process.set_native_retry(Some(target_pc));
                                process.set_native_pc(Some(code_ptr));
                                return Ok(Flow::Break(Err(VmError::Dirty(kind))));
                            }
                            // Port of erts/emulator/beam/beam_common.c:1568
                            // (erts_hibernate), OTP-29.1.1: hibernate/3 discarded
                            // the stack, so the native caller is gone; the process
                            // resumes through apply/3 like the interpreter's path.
                            Err(VmError::Unsupported(_)) if hibernate_stopped(process) => {
                                // hibernate/0 keeps its stack: after the wakeup the
                                // native call is retried and returns `ok` in place.
                                if hibernate_resumes_in_place(process) {
                                    hibernate_fetch_collect(process, ctx)?;
                                    process.set_native_retry(Some(target_pc));
                                    process.set_native_pc(Some(code_ptr));
                                    return Ok(Flow::Break(Ok(RunState::Wait {
                                        timeout_pos: None,
                                    })));
                                }
                                process.set_native_pc(None);
                                process.native_continuation_resume = false;
                                if hibernate_fetch_collect(process, ctx)? {
                                    if let Some(runtime) = process.runtime {
                                        runtime.mark_hibernating(ctx.pid(), true);
                                        // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                                        process.slice_mut().hibernate_sched = true;
                                    }
                                    return Ok(Flow::Break(Ok(RunState::Wait {
                                        timeout_pos: None,
                                    })));
                                }
                                self.install_apply(process, ctx)?;
                                return Ok(Flow::Continue);
                            }
                            Err(error) => return Err(error),
                        };
                        process.x[0] = value;
                        if !resume_after_native_return(process) {
                            return Ok(Flow::Break(Ok(RunState::Done(value))));
                        }
                        // Port of erts/emulator/beam/erl_process.c:10190: a
                        // finished dirty job continues on a normal scheduler.
                        if ctx.scheduler_type().is_dirty() {
                            return Ok(Flow::Break(Ok(RunState::Yield)));
                        }
                        return Ok(Flow::Continue);
                    }
                }
                let module_id = match self.vm.code.loaded.get(&export.module).copied() {
                    Some(module_id) => module_id,
                    // Like call_import: a module with -on_load is loaded through
                    // the error handler and code server, which run its on_load.
                    None => {
                        // Port of beam_common.c (call_error_handler): with the code
                        // server up, the error handler loads the module.
                        match if self.vm.unloaded_on_load(process, &export.module)
                            || self.vm.should_autoload(process, &export.module)
                        {
                            Err(VmError::Load("module has -on_load".into()))
                        } else {
                            self.vm.load_named(&export.module)
                        } {
                            Ok(module_id) => module_id,
                            Err(_) => {
                                let saved = process.x[..usize::from(export.arity)].to_vec();
                                let outcome = match self.vm.call_undefined_function(
                                    process,
                                    &export.module,
                                    &export.function,
                                    usize::from(export.arity),
                                    true,
                                ) {
                                    Ok(outcome) => outcome,
                                    Err(error) => {
                                        if let Some(error) = raise_undefined_call(
                                            &mut self.vm,
                                            process,
                                            ctx,
                                            &saved,
                                            error,
                                        )? {
                                            return Ok(Flow::Break(Err(error)));
                                        }
                                        return Ok(Flow::Continue);
                                    }
                                };
                                match outcome {
                                    crate::ImportOutcome::Jump(_) => {
                                        self.vm.enter_native_at_jump(process)
                                    }
                                    crate::ImportOutcome::Advanced => {}
                                    crate::ImportOutcome::Yield => {
                                        if process.native_pc().is_some()
                                            && native_transfer_continues(process, ctx)
                                        {
                                            return Ok(Flow::Continue);
                                        }
                                        return Ok(Flow::Break(Ok(RunState::Yield)));
                                    }
                                    crate::ImportOutcome::Returned(value) => {
                                        process.x[0] = value;
                                        if process.native_pc().is_none() {
                                            return Ok(Flow::Break(Ok(RunState::Done(value))));
                                        }
                                        if ctx.scheduler_type().is_dirty() {
                                            return Ok(Flow::Break(Ok(RunState::Yield)));
                                        }
                                    }
                                }
                                return Ok(Flow::Continue);
                            }
                        }
                    }
                };
                // Port of erts/emulator/beam/beam_bp.c (erts_generic_breakpoint
                // through the export's breakpoint trampoline), OTP-29.1.1: a
                // call through an export with a global call breakpoint reports
                // the call, then enters the function's code; a traced return
                // leaves through the native trace stub.
                if crate::beamasm_integration::is_global_breakpoint(
                    self.vm.code_scope,
                    &export.module,
                    &export.function,
                    export.arity,
                ) {
                    let module = Arc::clone(&self.vm.code.modules[module_id]);
                    let function = module
                        .exports
                        .iter()
                        .position(|slot| {
                            slot.function == export.function && slot.arity == export.arity
                        })
                        .and_then(|index| module.export_entry_targets.get(index))
                        .and_then(|&entry| {
                            self.vm.beamasm_targets.function_for_target(
                                module_id,
                                &module,
                                crate::load::native_code_range(&self.vm.code.code_meta, module_id),
                                entry,
                            )
                        });
                    if let Some(function) = function {
                        let actions = crate::trace::executor_native_call_event(
                            &mut self.vm,
                            process,
                            ctx,
                            &function,
                            false,
                        )?;
                        crate::trace::push_native_trace_frame(
                            process,
                            function.start,
                            &actions,
                            usize::from(function.arity),
                        )?;
                        process.gc_live = usize::from(export.arity);
                        process.set_native_pc(Some(function.start));
                        process.tick();
                        return Ok(Flow::Continue);
                    }
                }
                let target_ip = crate::beamasm_integration::interpreted_target(
                    self.vm.code_scope,
                    &export.module,
                    &export.function,
                    export.arity,
                )
                .or_else(|| {
                    self.vm.code.modules[module_id]
                        .export_slot(&export.function, export.arity)
                        .map(arinsal_loader::ExportSlot::target)
                });
                if let Some(target_ip) = target_ip {
                    process.gc_live = usize::from(export.arity);
                    self.vm.set_position(process, module_id, target_ip);
                    process.tick();
                    self.vm.enter_native_at_jump(process);
                } else {
                    let saved = process.x[..usize::from(export.arity)].to_vec();
                    let outcome = match self.vm.call_undefined_function(
                        process,
                        &export.module,
                        &export.function,
                        usize::from(export.arity),
                        true,
                    ) {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            if let Some(error) =
                                raise_undefined_call(&mut self.vm, process, ctx, &saved, error)?
                            {
                                return Ok(Flow::Break(Err(error)));
                            }
                            return Ok(Flow::Continue);
                        }
                    };
                    match outcome {
                        crate::ImportOutcome::Jump(_) => self.vm.enter_native_at_jump(process),
                        crate::ImportOutcome::Advanced => {}
                        crate::ImportOutcome::Yield => {
                            if process.native_pc().is_some()
                                && native_transfer_continues(process, ctx)
                            {
                                return Ok(Flow::Continue);
                            }
                            return Ok(Flow::Break(Ok(RunState::Yield)));
                        }
                        crate::ImportOutcome::Returned(value) => {
                            process.x[0] = value;
                            if process.native_pc().is_none() {
                                return Ok(Flow::Break(Ok(RunState::Done(value))));
                            }
                            if ctx.scheduler_type().is_dirty() {
                                return Ok(Flow::Break(Ok(RunState::Yield)));
                            }
                        }
                    }
                }
                return Ok(Flow::Continue);
            }
            arinsal_beamasm::ExitReason::Returned => {
                if !resume_after_native_return(process) {
                    return Ok(Flow::Break(Ok(RunState::Done(process.x[0]))));
                }
                return Ok(Flow::Continue);
            }
            arinsal_beamasm::ExitReason::Unsupported => {
                return Err(VmError::Unsupported("native execution unavailable".into()));
            }
        }
    }
}
