use super::*;

/// Raises the error of a native call to an undefined function that has no error handler
/// (`undef`) at the call, like the interpreter's call_ext; the arguments are restored first.
// Port of erts/emulator/beam/beam_common.c (call_error_handler), OTP-29.1.1.
pub(super) fn raise_undefined_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    arguments: &[Term],
    error: VmError,
) -> Result<Option<VmError>, VmError> {
    for (register, value) in process.x.iter_mut().zip(arguments) {
        *register = *value;
    }
    let trap = match error {
        VmError::Exception { reason, frame } => legacy_exception_trap(process, &reason, &frame)?,
        VmError::Trap(trap) => trap,
        other => return Err(other),
    };
    let resumed = crate::exceptions::resume(vm, process, Some(ctx), trap)?;
    if resumed.is_none() {
        process.heap.abi.exc.freason = 0;
        process.heap.abi.exc.fvalue = 0;
        process.heap.abi.exc.ftrace = 0;
    }
    Ok(resumed)
}

/// Turns a legacy interpreter exception into a trap, attaching the `undef` call arguments.
pub(crate) fn legacy_exception_trap(
    process: &mut Process,
    reason: &str,
    frame: &str,
) -> Result<crate::exceptions::Trap, VmError> {
    let mut trap = crate::exceptions::from_legacy(reason)?;
    if reason == "undef"
        && let Some((mfa, arity)) = frame.rsplit_once('/')
        && let Some((module, function)) = mfa.split_once(':')
        && let Ok(arity) = arity.parse::<usize>()
        && arity <= process.x.len()
    {
        trap.top = Some(crate::stacktrace::TopFrame::Bif {
            module: global_atoms()
                .intern(module)
                .map_err(|_| VmError::Unsupported("undef module atom".into()))?,
            function: global_atoms()
                .intern(function)
                .map_err(|_| VmError::Unsupported("undef function atom".into()))?,
            args: crate::stacktrace::BifArgs::from_terms(&process.x[..arity])?,
            info: crate::stacktrace::BifErrorInfo::None,
        });
    }
    Ok(trap)
}

/// `BUMP_REDS` by the executor itself, between two native runs: FCALLS is the slice's one
/// counter, which the context switch reads.
// Port of erts/emulator/beam/bif.h (BUMP_REDS) and jit/arm/instr_msg.cpp (i_loop_rec_shared:
// `FCALLS -= erts_proc_sig_receive_helper(...)`), OTP-29.1.1.
pub(crate) fn bump_fcalls(process: &mut Process, reds: i32) {
    process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(reds.max(0)).max(0);
}

/// Whether an interpreted step yielded only to hand control to native code, which
/// erts does without a scheduling point. Native FCALLS stay within this slice's
/// quantum so that its reductions are charged to the scheduler.
pub(super) fn native_transfer_continues(process: &mut Process) -> bool {
    std::mem::take(&mut process.native_transfer) && process.heap.abi.fcalls > 0
}

#[inline]
pub(super) fn trace_boot_enabled() -> bool {
    crate::calls::trace_boot_enabled()
}

#[cfg(feature = "pf-mem-counters")]
static PF_MONITOR_DOWN: AtomicU64 = AtomicU64::new(0);

/// VM part of one scheduler's data (`ErtsSchedulerData`): the scheduler's code replica and
/// register file, created on its first process turn and kept for the scheduler's lifetime.
///
/// Port of erts/emulator/beam/erl_process.h:687 (struct ErtsSchedulerData_: `registers`,
/// `current_process`) and erl_process.c:5994 (init_scheduler_data), OTP-29.1.1: one per
/// normal, dirty or simulated scheduler, handed down explicitly instead of looked up.
#[derive(Default)]
pub struct SchedulerData {
    pub(super) executor: Option<Box<Executor>>,
    /// `esdp->no` as the allocator numbers it: the allocator index of this scheduler's thread,
    /// read once on its first process turn and handed to the heap of each process it runs.
    pub(super) alloc_ix: Option<usize>,
}

/// How the entry loop goes on after a native call's exit was dispatched.
pub(super) enum Flow {
    /// Take the next iteration of the entry loop.
    Continue,
    /// Leave the entry loop with this result.
    Break(Result<RunState, VmError>),
}

pub(super) struct Executor {
    /// `esdp->current_process`, shared with this scheduler thread's NIF hub.
    pub(super) current_process: crate::natives::nif::CurrentProcess,
    /// The scheduler thread's hub is bound to `current_process`.
    pub(super) hub_bound: bool,
    /// The reference and unique-integer counters of this scheduler, bound on its first turn
    /// (`esdp->ref`, `esdp->unique`): a process scheduled in takes them from here.
    pub(super) ref_state: Option<arinsal_bifs::SchedulerRefState>,
    pub(super) vm: Vm,
    /// Native register backing is scheduler-local, as required by x19.
    pub(super) native_registers: SchedulerRegisters,
}

impl Executor {
    /// Emit the trace event a return through a trace frame left for the scheduler.
    pub(super) fn emit_native_return_event(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        event: crate::trace::NativeReturnEvent,
    ) -> Result<(), VmError> {
        match event {
            crate::trace::NativeReturnEvent::Return {
                function_pc,
                session,
                value,
            } => crate::trace::native_return_event(
                &mut self.vm,
                process,
                ctx,
                function_pc,
                session,
                value,
                false,
            ),
            crate::trace::NativeReturnEvent::ReturnTo { session, target } => {
                crate::trace::native_return_to_event(&mut self.vm, process, ctx, session, target)
            }
        }
    }

    /// Whether the slice can enter `fast_resume`: a native continuation with none of the rare
    /// per-slice work pending. Each test is a field the full path reads before it enters
    /// native code; when one holds, the full path does the work.
    // Port of erts/emulator/beam/erl_process.c (erts_schedule tests `p->state` and `p->flags`
    // once) and jit/arm/process_main.cpp (process_main: copy_in_registers, FCALLS, `br c_p->i`),
    // OTP-29.1.1.
    #[inline(always)]
    pub(super) fn fast_entry_ok(process: &Process, ctx: &RunCtx<'_, Message>) -> bool {
        !ctx.has_pending_nmsg() && Self::fast_entry_ok_before_signals(process, ctx)
    }

    /// [`Self::fast_entry_ok`] before the schedule-in signal handling: everything but the
    /// queued non-message signals, which the scheduler handles first (erts_schedule).
    #[inline(always)]
    pub(super) fn fast_entry_ok_before_signals(
        process: &Process,
        ctx: &RunCtx<'_, Message>,
    ) -> bool {
        process.slice_is_plain()
            && !process.dirty_bif_completed()
            && ctx.fast_slice_ok_before_signals()
            && !crate::suspend::ctx_suspended(ctx)
            && !trace_boot_enabled()
            && !process
                .native_pc()
                .is_some_and(|pc| crate::trace::TraceFrameKind::of(pc).is_some())
    }

    /// The native entry loop of the full path, for the common slices: enter native code at the
    /// continuation, and handle the two exits every receive-driven process takes (a yield and a
    /// wait) and the signal fetch of `loop_rec`. `None` hands the slice to the full loop with
    /// the process state untouched; every other exit goes through `after_native`, the same
    /// dispatch the full loop uses.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp (process_main: the scheduler enters
    // `c_p->i` directly), OTP-29.1.1.
    // Inlined into the slice: see `Executor::run`.
    #[inline(always)]
    pub(super) fn fast_resume(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        ran: &mut bool,
    ) -> Option<Result<RunState, VmError>> {
        let mut first = true;
        let mut reenter = false;
        loop {
            let code_ptr = process.native_pc()?;
            // A fetch that reenters native code runs the instruction in place, with no scheduling
            // point in between.
            if !first && !std::mem::take(&mut reenter) && !Self::fast_entry_ok(process, ctx) {
                return None;
            }
            crate::beamasm_integration::count_native_call();
            if first {
                first = false;
                if let Err(error) = collect_on_schedule_in(process) {
                    return Some(Err(error));
                }
            }
            *ran = true;
            process.native_transfer = false;
            process.set_native_pc(None);
            if crate::code_ix::take_code_barrier() {
                ctx.block_thread_progress(std::time::Duration::ZERO);
            }
            self.native_registers.active_code_ix =
                self.vm
                    .code_ix
                    .process_code_ix(crate::trace::saves_calls(process)) as u64;
            let native = {
                // Port of erts `c_p->scheduler_data`: a BIF native code calls reaches this
                // scheduler's data through the process while the slice runs.
                let _slice = super::sched_data::NativeSlice::enter(&mut self.vm, ctx);
                crate::native_bridge::run_native_resume(
                    process,
                    &mut self.native_registers,
                    code_ptr,
                )
            };
            // Native `timeout` has no scheduler context to send its trace event.
            if process.native_exit_kind != crate::proc_create::NativeExit::None
                && process.take_native_timeout_trace()
            {
                crate::trace::timeout_event(Some(&mut self.vm), process, ctx);
            }
            let outcome = match native {
                Ok(outcome) => outcome,
                Err(VmError::Trap(trap)) => {
                    match crate::exceptions::resume(&mut self.vm, process, Some(ctx), trap) {
                        Err(error) => return Some(Err(error)),
                        Ok(Some(error)) => {
                            return Some(Err(error));
                        }
                        Ok(None) => {
                            process.heap.abi.exc.freason = 0;
                            process.heap.abi.exc.fvalue = 0;
                            process.heap.abi.exc.ftrace = 0;
                            continue;
                        }
                    }
                }
                Err(error) => return Some(Err(error)),
            };
            if matches!(outcome, arinsal_beamasm::ExitReason::Returned) {
                // The entry function returned: the process continues in its caller or is done.
                if !resume_after_native_return(process) {
                    return Some(Ok(RunState::Done(process.x[0])));
                }
                continue;
            }
            if !matches!(outcome, arinsal_beamasm::ExitReason::Yield) {
                match self.after_native(process, ctx, outcome, code_ptr, &mut reenter) {
                    Ok(Flow::Continue) => continue,
                    Ok(Flow::Break(result)) => return Some(result),
                    Err(error) => return Some(Err(error)),
                }
            }
            match process.native_exit_kind {
                crate::proc_create::NativeExit::None => {
                    crate::beamasm_integration::count_native_yield();
                    process.native_exit_kind = crate::proc_create::NativeExit::None;
                    return Some(Ok(RunState::Yield));
                }
                crate::proc_create::NativeExit::Wait if process.native_wait.is_some() => {
                    crate::beamasm_integration::count_native_yield();
                    process.native_exit_kind = crate::proc_create::NativeExit::None;
                    let timeout_pos = process.native_wait.take().expect("checked above");
                    // A native receive found no matching message; see the full path.
                    process.gc_live = 0;
                    process.set_native_resume_arity(0);
                    let self_wait = std::mem::take(&mut process.native_wait_self);
                    if self_wait && let Err(error) = process.fetch_signals(ctx) {
                        return Some(Err(error));
                    }
                    return Some(Ok(RunState::Wait { timeout_pos }));
                }
                crate::proc_create::NativeExit::SignalFetch => {
                    crate::beamasm_integration::count_native_yield();
                    process.native_exit_kind = crate::proc_create::NativeExit::None;
                    let fcalls = process.heap.abi.fcalls;
                    match process.receive_helper(ctx, fcalls) {
                        Ok((used, _)) => bump_fcalls(process, used),
                        Err(error) => return Some(Err(error)),
                    }
                    continue;
                }
                _ => match self.after_native(process, ctx, outcome, code_ptr, &mut reenter) {
                    Ok(Flow::Continue) => continue,
                    Ok(Flow::Break(result)) => return Some(result),
                    Err(error) => return Some(Err(error)),
                },
            }
        }
    }

    // g_proc_sched. A suspended process drains its mailbox and does not run.
    // A hibernating process waits until the inbox is non-empty, then continues
    // at `erlang:apply/3`. Port of beam_common.c:1568 (`erts_hibernate`) and
    // erl_process.c:9304 (`erts_process_state2status`), OTP-29.1.1.
    pub(super) fn sched_preempt(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
    ) -> Result<Option<RunState>, VmError> {
        // Nothing to do at most scheduling points: no suspend and no hibernation. Checked
        // before the runtime handle is cloned.
        if process.runtime.is_some()
            && !crate::suspend::ctx_suspended(ctx)
            && !process.slice().is_some_and(|work| work.hibernate_sched)
        {
            return Ok(None);
        }
        let Some(runtime) = process.runtime else {
            return Ok(None);
        };
        let pid = ctx.pid();
        if runtime.suspend_total_of(pid) > 0 {
            return match park_suspended(process, ctx)? {
                RunState::Yield => Ok(None),
                parked => Ok(Some(parked)),
            };
        }
        if process.slice().is_some_and(|work| work.hibernate_sched) {
            process.drain(ctx)?;
            if process.inbox.is_empty() {
                return Ok(Some(RunState::Wait { timeout_pos: None }));
            }
            // elixir_loop1: unlike hibernate/3, hibernate/0 keeps its stack.
            let resume_in_place = process
                .cold
                .as_ref()
                .and_then(|cold| cold.hibernate.as_ref())
                .is_some_and(|cont| cont.resume_in_place);
            if resume_in_place {
                runtime.mark_hibernating(pid, false);
                // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                process.slice_mut().hibernate_sched = false;
            } else {
                self.install_apply(process, ctx)?;
            }
        }
        Ok(None)
    }

    // g_proc_sched. Port of bif.c:1402 (`hibernate_3` resumes via apply/3), OTP-29.1.1.
    pub(super) fn install_apply(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
    ) -> Result<(), VmError> {
        let pid = ctx.pid();
        let runtime = process
            .runtime
            .ok_or_else(|| VmError::Unsupported("hibernate without a scheduler".into()))?;
        process
            .cold_mut()
            .hibernate
            .take()
            .ok_or_else(|| VmError::Unsupported("hibernate continuation missing".into()))?;
        runtime.mark_hibernating(pid, false);
        // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
        process.slice_mut().hibernate_sched = false;
        // hibernate/3 left `apply(M, F, A)` in X0..X2.
        if process.x.len() < 3 {
            return Err(VmError::Unsupported("hibernate registers".into()));
        }
        // Port of erts/emulator/beam/bif.c:1426-1427 (hibernate_3: erts_hibernate, then
        // BIF_TRAP_CODE_PTR(beam_run_process, 3)), OTP-29.1.1: the process wakes in the
        // beam_run_process stub, which applies X0..X2.
        process.set_run_process_entry()?;
        process.msgq_set_save_first();
        process.cancel_receive_timer();
        Ok(())
    }
}

/// Exact live X register count of a switched-out process, erts `c_p->arity`. Every
/// producer of a saved register file stores it in `header.arity`: the native yield
/// sites and trap continuations directly, an interpreted switch-out through the
/// executor epilogue, a spawn or hibernate when it fills the file.
pub(crate) fn switched_out_live(process: &Process) -> usize {
    // A trap whose arguments are GC roots of its own keeps no live X registers.
    if process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .is_some_and(|trap| trap.args_are_roots())
    {
        return 0;
    }
    process.saved_arity()
}

pub(super) fn resume_after_native_return(process: &mut Process) -> bool {
    loop {
        let Some(word) = process.heap.stack_get(0) else {
            return false;
        };
        // SAFETY: A live stack slot contains a tagged term or a raw native CP.
        let raw = unsafe { word.raw_bits() } as usize;
        if raw == arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize {
            process.heap.release_stack(1);
            continue;
        }
        if crate::native_bridge::is_native_continuation(raw) {
            process.heap.release_stack(1);
            process.native_continuation_resume = true;
            process.set_native_resume_arity(1);
            process.set_native_pc(Some(raw));
            return true;
        }
        return false;
    }
}

// g_proc_sched. `erlang:apply/3` is the continuation erts installs after
// `erts_hibernate` and the body of `erts_internal:spawn_init/1`.
/// Process-table slot of a local pid; `erlang:processes/0` lists pids in slot order.
///
/// Port of erts/emulator/beam/erl_node_container_utils.h:128 (internal_pid_index), OTP-29.1.1.
pub(crate) fn pid_table_index(pid: Pid) -> u32 {
    arinsal_term::ptab::process_table_layout().data2pix(pid.data())
}

impl Process {
    /// `p->i = beam_run_process; p->arity = 3`: the process starts like any switched-out one,
    /// resuming at its code address with three live registers.
    // Port of erts/emulator/beam/erl_process.c:12616 (erl_create_process), OTP-29.1.1.
    pub(crate) fn set_run_process_entry(&mut self) -> Result<(), VmError> {
        let Some((start, _)) = crate::beamasm_integration::run_process_entry() else {
            return Err(VmError::Unsupported(
                "the beam_run_process stub is not built".into(),
            ));
        };
        self.set_native_pc(Some(start));
        self.native_continuation_resume = true;
        self.set_native_resume_arity(3);
        Ok(())
    }

    /// Start the process at beam_run_process: X0..X2 hold the module, the function and the
    /// argument list, and `p->u.initial` names the MFA (`process_info(initial_call)`).
    // Port of erts/emulator/beam/erl_process.c:12610-12616 (erl_create_process: `p->u.initial`,
    // `p->current = &p->u.initial`, `p->i = beam_run_process`, `p->arity = 3`), OTP-29.1.1.
    pub(crate) fn start_at_run_process(
        &mut self,
        module: arinsal_term::Atom,
        function: arinsal_term::Atom,
        args: Term,
        arity: u8,
    ) -> Result<(), VmError> {
        self.x[0] = Term::atom(module);
        self.x[1] = Term::atom(function);
        self.x[2] = args;
        self.gc_live = 3;
        self.heap.abi.arity = 3;
        self.initial_mfa = Some((module, function, arity));
        Ok(())
    }
}

thread_local! {
    static TRACER_REPLICAS: std::cell::RefCell<Vec<(usize, Vm)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` on a code replica of `runtime` private to this worker, for callers that need a
/// [`Vm`] while the executor's own is borrowed (receive tracing runs inside signal handling,
/// which has only the process). The replica is taken out while `f` runs, so a nested call
/// simply builds another one.
pub(crate) fn with_replica_vm<R>(runtime: &'static Runtime, f: impl FnOnce(&mut Vm) -> R) -> R {
    let key = runtime as *const Runtime as usize;
    let cached = TRACER_REPLICAS.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.iter()
            .position(|(cached_key, _)| *cached_key == key)
            .map(|index| slot.swap_remove(index).1)
    });
    let mut vm = cached.unwrap_or_else(|| Vm::shared_replica(&runtime.paths));
    vm.refresh_code();
    let result = f(&mut vm);
    TRACER_REPLICAS.with(|slot| {
        let mut slot = slot.borrow_mut();
        // Runtimes come and go in tests; keep only the most recent replicas.
        if slot.len() >= 4 {
            slot.remove(0);
        }
        slot.push((key, vm));
    });
    result
}

/// Run `f` on this scheduler's executor, creating it for `runtime` on first use.
pub(super) fn with_executor<R>(
    data: &mut SchedulerData,
    runtime: &'static Runtime,
    f: impl FnOnce(&mut Executor) -> R,
) -> R {
    let executor = data.executor.get_or_insert_with(|| new_executor(runtime));
    f(executor)
}

/// The executor a scheduler creates on its first process turn. Kept out of line: the
/// register file is built once per scheduler, not in the frame of every turn.
// Port of erts/emulator/beam/erl_process.c:5994 (init_scheduler_data allocates
// `esdp->registers` once), OTP-29.1.1.
#[cold]
#[inline(never)]
pub(super) fn new_executor(runtime: &'static Runtime) -> Box<Executor> {
    arinsal_nif_zlib::set_scheduler_caller(crate::natives::nif::scheduler_caller);
    Box::new(Executor {
        current_process: Default::default(),
        hub_bound: false,
        ref_state: None,
        vm: Vm::shared_replica(&runtime.paths),
        native_registers: {
            let mut registers = SchedulerRegisters::default();
            // The trace-return stub address is a per-scheduler constant (process_main sets it once).
            registers.tmp_mem[5] = crate::native_helpers::arinsal_beamasm_native_trace_return
                as *const () as usize as u64;
            registers
        },
    })
}
