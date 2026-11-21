use super::executor_after_native::context_switch;
use super::*;

/// `beam_exit_`: the one instruction `beam_exit` points to while arm runs this Rust
/// process_main; its address only identifies `error_action_code`.
// Port of erts/emulator/beam/emu/beam_emu.c (`static BeamInstr beam_exit_[1]`, set to
// `OpCode(error_action_code)`, `beam_exit = &beam_exit_[0]`), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
static BEAM_EXIT_: u64 = 0;

/// The address of [`BEAM_EXIT_`], published as `beam_exit` by the arm `beamasm_init`.
#[cfg(target_arch = "aarch64")]
pub(crate) fn beam_exit_address() -> usize {
    std::ptr::addr_of!(BEAM_EXIT_) as usize
}

/// Whether the process continues at `beam_exit` (`c_p->i == beam_exit`): an exit signal made
/// it exiting.
pub(super) fn at_beam_exit(process: &Process) -> bool {
    process.heap.abi.i as usize == crate::beam_jit_main::beam_exit()
}

/// `error_action_code`, the instruction at `beam_exit`: `handle_error(c_p, NULL, reg, NULL)`
/// finds no catch (erts_set_self_exiting killed them), so the process terminates in place
/// with `c_p->fvalue` (terminate_proc; an EXTAG_EXIT is not logged), then `do_schedule`.
// Port of erts/emulator/beam/emu/beam_emu.c (error_action_code) and beam_common.c
// (handle_error -> terminate_proc), OTP-29.1.1.
pub(super) fn error_action_code(
    process: &mut Process,
    reg: &mut SchedulerRegisters,
) -> Result<RunState, VmError> {
    let c_p = std::ptr::from_mut(process).cast::<arinsal_beamasm::ProcessHeader>();
    let x_reg_array = std::ptr::from_mut(reg)
        .cast::<u8>()
        .wrapping_add(std::mem::offset_of!(SchedulerRegisters, x_reg_array))
        .cast::<u64>();
    let handler = crate::beam_common::handle_error(c_p, 0, x_reg_array, std::ptr::null());
    debug_assert_eq!(handler, 0, "beam_exit: the exiting process has no catch");
    Err(VmError::Yield)
}

/// What one pass of the scheduler loop body asks of its driver: enter native code at the
/// prepared `c_p->i` (its exit comes back as the next pass), or end the slice with the
/// outcome `erts_schedule` takes at schedule-out.
// Port of erts/emulator/beam/jit/x86/process_main.cpp (emit_process_main: `jmp c_p->i`
// after schedule_next; native code returns to context_switch / do_schedule at the top),
// OTP-29.1.1.
pub(super) enum SliceStep {
    /// `jmp c_p->i`.
    Enter(crate::native_bridge::NativeEntry),
    /// The slice is over: `erts_schedule` takes the process.
    End(Result<RunState, VmError>),
}

/// Where the loop body of this slice is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The process was just scheduled in.
    Begin,
    /// The plain continuation loop; `first` until the schedule-in GC check ran.
    Fast { first: bool },
    /// The full loop; `first` until its schedule-in checks ran.
    Full { first: bool },
}

/// The native entry the loop body handed out; its exit arrives at the next pass.
pub(super) struct Pending {
    pub(super) entry: crate::native_bridge::NativeEntry,
    /// `ARINSAL_TRACE_BOOT`: the function the full loop entered.
    function: Option<crate::NativeFunction>,
}

/// The state one slice keeps across native entries: the locals of erts process_main
/// between `erts_schedule` returning and the next `do_schedule`.
pub(super) struct Slice {
    /// `start_time` when long_schedule is monitored.
    schedule_started: Option<std::time::Instant>,
    /// erts_schedule's `state & ERTS_PSFLG_SYS_TASKS` of this schedule-in.
    sys_task_run: bool,
    phase: Phase,
    pending: Option<Pending>,
}

impl Slice {
    /// erts_schedule's `state & ERTS_PSFLG_SYS_TASKS` of this schedule-in.
    pub(super) fn sys_task_run(&self) -> bool {
        self.sys_task_run
    }

    /// Whether the plain continuation loop has not run its schedule-in GC check yet.
    pub(super) fn fast_first(&self) -> bool {
        self.phase == (Phase::Fast { first: true })
    }

    /// The plain continuation loop ran its schedule-in GC check.
    pub(super) fn clear_fast_first(&mut self) {
        self.phase = Phase::Fast { first: false };
    }

    /// Hand out the prepared entry of the plain continuation loop: `jmp c_p->i`.
    pub(super) fn enter(&mut self, entry: crate::native_bridge::NativeEntry) -> SliceStep {
        self.pending = Some(Pending {
            entry,
            function: None,
        });
        SliceStep::Enter(entry)
    }
}

/// One process slice on this scheduler: the loop body of erts process_main driven until
/// the slice ends; each [`SliceStep::Enter`] enters native code and hands its exit back.
// Port of erts/emulator/beam/jit/x86/process_main.cpp (emit_process_main) and
// beam/emu/beam_emu.c (process_main), OTP-29.1.1.
#[inline(always)]
pub(super) fn process_main(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    reg: &mut SchedulerRegisters,
) -> Result<RunState, VmError> {
    let mut slice = slice_begin(process, ctx, reg);
    let mut exit = None;
    loop {
        match slice_step(process, ctx, reg, &mut slice, exit.take()) {
            SliceStep::Enter(entry) => {
                exit = Some(crate::native_bridge::native_enter(process, reg, &entry));
            }
            SliceStep::End(result) => break result,
        }
    }
}

/// The schedule-in part of process_main after `erts_schedule` returned: `start_time`,
/// `esdp->registers`, the X registers the scheduler loaded (copy_in_registers).
// Port of erts/emulator/beam/jit/x86/process_main.cpp:200-280 (schedule_next ..
// copy_in_registers), OTP-29.1.1.
#[inline(always)]
pub(super) fn slice_begin(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    reg: &mut SchedulerRegisters,
) -> Slice {
    let esdp = ctx.esdp();
    let data = arinsal_sched::erts_sched_registers(esdp);
    // Port of jit/x86/process_main.cpp:200-230 and beam_emu.c (process_main: `start_time =
    // erts_timestamp_millis()` after erts_schedule returns, when long_schedule is monitored),
    // OTP-29.1.1.
    let schedule_started =
        crate::natives::erts_debug::long_schedule_monitored(process).then(std::time::Instant::now);
    // A spawned process entered at `p->i = beam_run_process` (erl_create_process); from its
    // first run on, `p->current` is no longer `&p->u.initial`.
    process.replace_entry_started(true);
    // The scheduler loop has loaded the `c_p->arity` saved registers into the scheduler's
    // one X register array (copy_in_registers), which is the process's file for the slice.
    let saved_len = process.x.saved_arity();
    // `esdp->registers` of this scheduler: the VM paths the slice runs reach `reg` here.
    data.registers_addr
        .set(std::ptr::from_mut(&mut *reg) as usize);
    if crate::xreg_poison_enabled() {
        process.x[saved_len..].fill(crate::XREG_POISON);
    }
    // erts_schedule's `state & ERTS_PSFLG_SYS_TASKS` of this schedule-in, a local. The
    // RUNNING_SYS signal handling, system tasks and GC check already ran inside erts_schedule
    // (`Task::schedule_in`, `schedule_in_running_sys`).
    let sys_task_run = ctx.sys_task_run();
    Slice {
        schedule_started,
        sys_task_run,
        phase: Phase::Begin,
        pending: None,
    }
}

/// One pass of the process_main loop body. `exit` is the native exit of the previous
/// [`SliceStep::Enter`]: it is handled first (context_switch / do_schedule), then the body
/// continues to the next native entry or the end of the slice.
// Port of erts/emulator/beam/jit/x86/process_main.cpp (emit_process_main: context_switch,
// context_switch_simplified, do_schedule, schedule_next, `jmp c_p->i`), OTP-29.1.1.
#[inline(always)]
pub(super) fn slice_step(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    reg: &mut SchedulerRegisters,
    slice: &mut Slice,
    exit: Option<arinsal_beamasm::ExitReason>,
) -> SliceStep {
    let mut native = exit.map(|exit| {
        let pending = slice
            .pending
            .take()
            .expect("a native exit follows the entry the slice handed out");
        (
            crate::native_bridge::native_exit(process, reg, pending.entry, exit),
            pending,
        )
    });
    if slice.phase == Phase::Begin {
        slice.phase = if at_beam_exit(process) {
            // process_main: `jmp c_p->i` enters beam_exit.
            let result = error_action_code(process, reg);
            return slice_end(process, ctx, slice, result);
        } else if fast_entry_ok(process, ctx, slice.sys_task_run) {
            Phase::Fast { first: true }
        } else {
            Phase::Full { first: true }
        };
    }
    if let Phase::Fast { .. } = slice.phase {
        match process_main_dispatch(process, ctx, reg, slice, native.take()) {
            Some(SliceStep::End(result)) => return slice_end(process, ctx, slice, result),
            Some(step) => return step,
            None => slice.phase = Phase::Full { first: true },
        }
    }
    match full_loop(process, ctx, reg, slice, native) {
        Ok(SliceStep::End(result)) => slice_end(process, ctx, slice, result),
        Ok(step) => step,
        Err(error) => slice_end(process, ctx, slice, Err(error)),
    }
}

/// The full loop of the process_main body: every exit and scheduling case the plain
/// continuation loop hands over.
fn full_loop(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    reg: &mut SchedulerRegisters,
    slice: &mut Slice,
    mut native: Option<(Result<arinsal_beamasm::ExitReason, VmError>, Pending)>,
) -> Result<SliceStep, VmError> {
    let result = 'execution: {
        if slice.phase == (Phase::Full { first: true }) {
            slice.phase = Phase::Full { first: false };
            let dirty_sys_gc = process.slice().is_some_and(|work| work.dirty_sys_gc);
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
                process.run_dirty_gc();
                crate::signals::execute_dirty_sys_tasks(process, ctx)?;
                // The signals are handled on the normal scheduler the process returns to.
                break 'execution Ok(RunState::Yield);
            }
            // process_main: `jmp c_p->i` enters beam_exit.
            if at_beam_exit(process) {
                break 'execution error_action_code(process, &mut *reg);
            }
        }
        loop {
            let (native, code_ptr, function) = match native.take() {
                Some((native, pending)) => (native, pending.entry.code_address, pending.function),
                None => {
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
                    // Port of erts/emulator/beam/erl_process.c (schedule: a process with
                    // ERTS_PSFLG_DIRTY_CPU_PROC / ERTS_PSFLG_DIRTY_IO_PROC set by
                    // static_schedule_dirty_nif or enif_schedule_nif goes to that dirty run
                    // queue), OTP-29.1.1.
                    if !ctx.scheduler_type().is_dirty()
                        && let Some(kind) = dirty_proc_kind(ctx.proc_state())
                    {
                        break Err(VmError::Dirty(kind));
                    }
                    match pending_dirty {
                        Some(arinsal_bifs::SchedulerClass::DirtyCpu) if !dirty_here => {
                            break Err(VmError::Dirty(arinsal_sched::DirtyKind::Cpu));
                        }
                        Some(arinsal_bifs::SchedulerClass::DirtyIo) if !dirty_here => {
                            break Err(VmError::Dirty(arinsal_sched::DirtyKind::Io));
                        }
                        _ => {}
                    }
                    // Port of erts/emulator/beam/beam_common.c (erts_dirty_process_main)
                    // and erl_nif.c (erts_call_dirty_nif), OTP-29.1.1: the dirty call ran
                    // as this slice's dirty job and scheduled `dirty_nif_finalizer`,
                    // `dirty_nif_exception` or a new call; a call for a dirty scheduler
                    // goes back to a dirty run queue, any other runs on a normal one.
                    if ctx.scheduler_type().is_dirty()
                        && crate::erl_nfunc_sched::i_is_call_nif(process)
                    {
                        break match dirty_proc_kind(ctx.proc_state()) {
                            Some(kind) => Err(VmError::Dirty(kind)),
                            None => Ok(RunState::Yield),
                        };
                    }
                    if !dirty_here {
                        // A caught exception re-enters this loop without replenishing its process slice.
                        if process.heap.abi.fcalls <= 0 {
                            break Ok(RunState::Yield);
                        }
                        // g_proc_sched: a suspended process is not scheduled; a hibernating
                        // one stays waiting until a message arrives, then continues at apply/3.
                        if let Some(wait) = schedule_suspend_hibernate(process, ctx, reg)? {
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
                        reg.x_reg_array[arity] =
                            Term::atom(arinsal_term::global_atoms().intern(module).map_err(
                                |_| VmError::Unsupported("dirty continuation module atom".into()),
                            )?);
                        reg.x_reg_array[arity + 1] =
                            Term::atom(arinsal_term::global_atoms().intern(function).map_err(
                                |_| VmError::Unsupported("dirty continuation function atom".into()),
                            )?);
                        reg.x_reg_array[..arity].copy_from_slice(&args);
                        process.heap.abi.arity = arity as u8;
                        process.gc_live = arity;
                        let continuation = crate::beam_common::fixed_apply(
                            process,
                            (Vm {}).x_regs()?,
                            arity,
                            &mut Vm {},
                            Some(ctx),
                        );
                        let continuation = match continuation {
                            Ok(outcome) => outcome,
                            Err(VmError::Trap(trap)) => {
                                if let Some(error) =
                                    crate::exceptions::resume(&mut Vm {}, process, Some(ctx), trap)?
                                {
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
                    // Port of erts/emulator/beam/erl_nif.c (erts_call_dirty_nif), OTP-29.1.1:
                    // the dirty scheduler runs the NIF, then the process returns to a normal
                    // scheduler to continue after the call.
                    if let Some((identity, resume_pc, class)) =
                        process.cold.as_ref().and_then(|cold| cold.native_dirty_nif)
                        && scheduler_class(ctx.scheduler_type()) == class
                    {
                        // Port of erts/emulator/beam/erl_nif.c (erts_call_dirty_nif: the
                        // finished call schedules `dirty_nif_finalizer/1` or
                        // `dirty_nif_exception/1`), OTP-29.1.1: the dirty scheduler only runs
                        // the NIF. Its result or exception is taken on the normal scheduler
                        // the process returns to, so no Erlang code (an exception handler
                        // included) runs on the dirty scheduler.
                        if ctx.scheduler_type().is_dirty() && process.dirty_nif_done() {
                            process.slice_mut().native_dirty_nif =
                                Some((identity, resume_pc, arinsal_bifs::SchedulerClass::Normal));
                            break Ok(RunState::Yield);
                        }
                        process.slice_mut().native_dirty_nif = None;
                        match crate::native_helpers::run_static_nif(
                            process,
                            &reg.x_reg_array,
                            identity,
                        ) {
                            Ok(value) => {
                                reg.x_reg_array[0] = value;
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
                                if let Some(error) =
                                    crate::exceptions::resume(&mut Vm {}, process, Some(ctx), trap)?
                                {
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
                            reg.x_reg_array[0],
                            kind,
                            |p, words| {
                                p.heap.release_stack(words);
                            },
                        );
                        let Some((event, caller)) = returned else {
                            break Err(VmError::Unsupported("native trace frame".into()));
                        };
                        if let Some(event) = event {
                            trace_native_return_event(process, ctx, event)?;
                        }
                        let resume_pc = caller.tagged_word() as usize;
                        let bridge =
                            arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
                        if resume_pc == bridge {
                            if !resume_after_native_return(process) {
                                break Ok(RunState::Done(reg.x_reg_array[0]));
                            }
                        } else {
                            process.native_continuation_resume = true;
                            process.set_native_resume_arity(1);
                            process.set_native_pc(Some(resume_pc));
                        }
                        continue;
                    }

                    let Some(code_ptr) = process.native_pc() else {
                        // `jmp c_p->i` at beam_exit: the process was made exiting in this slice.
                        if at_beam_exit(process) {
                            break error_action_code(process, &mut *reg);
                        }
                        process.heap.clear_native_redzone();
                        let result = (Vm {}).enter_native_position(process);
                        // erts schedules out only when FCALLS runs out; entering the native code
                        // of the process's position continues the slice.
                        if matches!(&result, Ok(RunState::Yield))
                            && process.native_pc().is_some()
                            && native_transfer_continues(process)
                        {
                            continue;
                        }
                        if hibernate_stopped(process) {
                            if hibernate_fetch_collect(process, ctx)? {
                                if process.runtime.is_some() {
                                    // Port of erts `F_HIBERNATE_SCHED` in `p->flags`: the process tests its own flag.
                                    process.set_hibernate_sched(true);
                                }
                                break Ok(RunState::Wait);
                            }
                            hibernate_wakeup(process, reg)?;
                            continue;
                        }
                        if matches!(&result, Ok(RunState::Yield))
                            && process.runtime.is_some()
                            && crate::suspend::ctx_suspended(ctx)
                        {
                            break park_suspended(process, ctx);
                        }
                        let trap = match result {
                            Err(VmError::Trap(trap)) => trap,
                            Err(VmError::Exception { reason, frame }) => {
                                if trace_boot_enabled() {
                                    eprintln!("arinsal boot: exception {reason} at {frame}");
                                }
                                let mut trap = crate::exceptions::from_legacy(&reason)?;
                                if reason == "undef"
                                    && let Some((mfa, arity)) = frame.rsplit_once('/')
                                    && let Some((module, function)) = mfa.split_once(':')
                                    && let Ok(arity) = arity.parse::<usize>()
                                    && arity <= reg.x_reg_array.len()
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
                                            &reg.x_reg_array[..arity],
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
                                (Vm {}).frame_name(process),
                                process.native_pc(),
                                trap.class,
                                arinsal_term::to_owned(trap.reason)
                            );
                        }
                        let resumed =
                            crate::exceptions::resume(&mut Vm {}, process, Some(ctx), trap)?;
                        if let Some(error) = resumed {
                            break Err(error);
                        }
                        process.heap.abi.exc.freason = 0;
                        process.heap.abi.exc.fvalue = 0;
                        process.heap.abi.exc.ftrace = 0;
                        continue;
                    };
                    #[cfg(target_arch = "aarch64")]
                    crate::beamasm_integration::count_native_call();
                    process.set_native_pc(None);

                    let trace_boot = trace_boot_enabled();
                    let function = trace_boot
                        .then(|| crate::native_function_at(code_ptr))
                        .flatten();
                    if trace_boot {
                        eprintln!("arinsal boot: enter native {:?} pc={code_ptr:#x}", function);
                        if function
                            .as_ref()
                            .is_some_and(|f| f.module == "prim_file" && f.function == "decode_path")
                        {
                            eprintln!(
                                "arinsal boot: decode_path input={:?}",
                                reg.x_reg_array.first()
                            );
                        }
                    }
                    // A native call to a BIF that parked the process (cross-process signal
                    // reply) is redone once the process wakes, like the interpreter re-executes
                    // the call instruction.
                    let retry = process.take_native_retry();
                    if let Some(target_pc) = retry {
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
                        #[cfg(target_arch = "aarch64")]
                        crate::beamasm_integration::note_call_retry();
                        if call_site_pc != 0 {
                            process.native_error_pc = call_site_pc;
                        }
                        (
                            Ok(arinsal_beamasm::ExitReason::CallUnported {
                                target_pc,
                                resume_pc,
                            }),
                            code_ptr,
                            function,
                        )
                    } else {
                        // Port of erts/emulator/beam/erl_process.c (schedule: reductions
                        // used = REDS_IN - FCALLS), OTP-29.1.1: native code counts down
                        // FCALLS, the slice's one counter; the context switch charges it.
                        // A code change this scheduler committed waits for thread
                        // progress first: every other scheduler then finishes the slice it
                        // runs with the previous code index (erts' code barrier).
                        if crate::code_ix::take_code_barrier() {
                            ctx.block_thread_progress(std::time::Duration::ZERO);
                        }
                        reg.active_code_ix = crate::code_ix::global()
                            .process_code_ix(crate::trace::saves_calls(process))
                            as u64;
                        match crate::native_bridge::native_prepare(process, &mut *reg, code_ptr) {
                            Ok(entry) => {
                                slice.pending = Some(Pending { entry, function });
                                return Ok(SliceStep::Enter(entry));
                            }
                            Err(error) => (Err(error), code_ptr, function),
                        }
                    }
                }
            };
            let outcome = match native {
                Ok(outcome) => outcome,
                Err(VmError::Trap(trap)) => {
                    if let Some(error) =
                        crate::exceptions::resume(&mut Vm {}, process, Some(ctx), trap)?
                    {
                        break Err(error);
                    }
                    process.heap.abi.exc.freason = 0;
                    process.heap.abi.exc.fvalue = 0;
                    process.heap.abi.exc.ftrace = 0;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if function
                .as_ref()
                .is_some_and(|f| f.module == "prim_file" && f.function == "decode_path")
            {
                eprintln!(
                    "arinsal boot: decode_path exit={outcome:?} output={:?}",
                    reg.x_reg_array.first()
                );
            }
            match context_switch(process, ctx, reg, outcome, code_ptr) {
                Ok(Flow::Continue) => continue,
                Ok(Flow::Break(result)) => break result,
                Err(error) => return Err(error),
            }
        }
    };
    Ok(SliceStep::End(result))
}

/// do_schedule: the slice's outcome as `erts_schedule` takes it, with the live X register
/// count saved in `c_p->arity`.
// Port of erts/emulator/beam/jit/x86/process_main.cpp (do_schedule) and erl_process.c
// (erts_schedule), OTP-29.1.1.
#[inline(always)]
fn slice_end(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    slice: &mut Slice,
    result: Result<RunState, VmError>,
) -> SliceStep {
    let schedule_started = slice.schedule_started;
    // erts keeps a process whose middle queue holds unhandled signals (ERTS_PSFLG_SIG_Q)
    // scheduled for signal handling even when it waits (erl_process.c:10318-10351, with
    // all reductions since it has no Erlang work); this scheduler only wakes a process for
    // new input, so the rest is handled before it sleeps. Messages it produces end the
    // wait like a new message would.
    let result = match result {
        Ok(RunState::Wait) if !process.sig_cont_empty() => {
            let queued = process.inbox.len();
            match process.handle_local_signals(ctx) {
                Ok(()) if process.inbox.len() == queued => Ok(RunState::Wait),
                // A message reached the queue after the wait cleared ERTS_PSFLG_ACTIVE: it
                // makes the process active again, as erts_proc_notify_new_message does for a
                // process that is not active (erl_proc_sig_queue.h:2080).
                Ok(()) => {
                    ctx.proc_state()
                        .fetch_or(arinsal_sched::psflg::ACTIVE, Ordering::AcqRel);
                    Ok(RunState::Yield)
                }
                Err(error) => Err(error),
            }
        }
        other => other,
    };
    if matches!(
        result,
        Ok(RunState::Yield | RunState::Wait) | Err(VmError::Yield | VmError::Dirty(_))
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
        let live_x = if arity_set {
            call_arity
        } else if process.native_pc().is_some() {
            process.gc_live.max(call_arity)
        } else {
            process.gc_live
        };
        process.heap.abi.arity = live_x.min(usize::from(u8::MAX)) as u8;
        process.gc_live = live_x;
        if crate::native_bridge::return_trace_enabled() && process.native_pc().is_some() {
            eprintln!(
                "[sched-save-native] live_x={live_x} x0={:#x} native_pc={:?}",
                process.x[0].tagged_word(),
                process.native_pc()
            );
        }
        // The scheduler loop's copy_out_registers saves these `c_p->arity` registers.
    } else {
        // Port of erts/emulator/beam/jit/arm/process_main.cpp:140-144 (process_exit:
        // `c_p->arity = 0`), OTP-29.1.1: an exiting or finished process saves no register.
        process.heap.abi.arity = 0;
    }
    // Port of erts/emulator/beam/erl_process.c:10415 (erts_schedule), OTP-29.1.1: erts has no
    // collection at schedule-out. ERTS_IS_GC_DESIRED is tested once, when the process is
    // scheduled in (`collect_on_schedule_in`), so a yielded process is collected there.
    if let Some(schedule_started) = schedule_started {
        crate::natives::erts_debug::after_schedule(
            process,
            schedule_started.elapsed().as_nanos() as u64,
        );
    }
    SliceStep::End(result)
}

/// The `ERTS_PSFLG_RUNNING_SYS` part of a normal scheduler's `erts_schedule` schedule-in,
/// after `p->fcalls = reds`: signal handling and system tasks, the `RUNNING_SYS` to `RUNNING`
/// transition (or, without Erlang work, the GC check and `goto sched_out_proc`), then the GC
/// check. `Ok(false)` is `goto sched_out_proc` (the reductions are used up, dirty work is
/// pending, the process has no Erlang work, or the collection asked for it); an error is the
/// slice's outcome without running Erlang code.
// Port of erts/emulator/beam/erl_process.c:10318-10427 (erts_schedule), OTP-29.1.1.
pub(super) fn schedule_in_running_sys(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
) -> Result<bool, VmError> {
    use arinsal_sched::psflg;
    let state = ctx.proc_state().load(Ordering::Acquire);
    if state & psflg::RUNNING_SYS != 0 {
        // `if (state & (ERTS_PSFLG_SIG_Q|ERTS_PSFLG_NMSG_SIG_IN_Q))`.
        // A system task request handled with the signals runs here, at the scheduling point
        // (`sys_task_point`), as execute_sys_tasks would run it.
        let sys_tasks = state & psflg::SYS_TASKS != 0;
        if state & (psflg::SIG_Q | psflg::NMSG_SIG_IN_Q) != 0 {
            if sys_tasks {
                process.cold_mut().sys_task_point = true;
            }
            let handled = schedule_in_signals(process, ctx, state);
            if sys_tasks {
                process.cold_mut().sys_task_point = false;
            }
            handled?;
        }
        // `if ((state & (ERTS_PSFLG_SYS_TASKS | ERTS_PSFLG_EXITING)) == ERTS_PSFLG_SYS_TASKS)`
        // with `!(p->flags & F_DELAY_GC)`: a process scheduled out with a delayed GC (the hand
        // written receive of prim_eval) runs no system task (erl_process.c:10352-10372).
        let state = ctx.proc_state().load(Ordering::Acquire);
        if state & (psflg::SYS_TASKS | psflg::EXITING) == psflg::SYS_TASKS
            && !process.delay_gc()
            && process.inbox.flags & crate::receive::FS_FLUSHING_SIGS == 0
        {
            process.cold_mut().sys_task_point = true;
            let executed = crate::signals::execute_sys_tasks(process, ctx);
            process.cold_mut().sys_task_point = false;
            executed?;
        }
        // `if (reds <= 0 || (state & ERTS_PSFLGS_DIRTY_WORK)) goto sched_out_proc;`
        if process.heap.abi.fcalls <= 0
            || process.slice().is_some_and(|work| work.dirty_sys_gc)
            || dirty_proc_kind(ctx.proc_state()).is_some()
        {
            return Ok(false);
        }
        // The cmpxchg loop: without Erlang work (`ACTIVE`, not suspended) and not exiting, the
        // process is collected if desired and scheduled out.
        if ctx.running_sys_to_running().is_err() {
            collect_on_schedule_in(process);
            return Ok(false);
        }
    }
    // An exit signal made the process exiting: it continues at `beam_exit` or its exit
    // continuation, and `ERTS_IS_GC_DESIRED` is not acted on (`!(state & ERTS_PSFLG_EXITING)`).
    if process.has_exit_cont()
        || ctx.proc_state().load(Ordering::Acquire) & (psflg::EXITING | psflg::FREE) != 0
    {
        return Ok(true);
    }
    // `if (ERTS_IS_GC_DESIRED(p)) { if (!(state & ERTS_PSFLG_EXITING) ...) scheduler_gc_proc`;
    // `reds <= 0` or a dirty collection goes to sched_out_proc.
    if collect_on_schedule_in(process) {
        return Ok(false);
    }
    Ok(true)
}

/// The signal handling of a `RUNNING_SYS` schedule-in: at most
/// `SIG_HANDLE_REDS_MAX_PREFERED` reductions of signals when the process has Erlang work and
/// no dirty work, all its reductions otherwise.
// Port of erts/emulator/beam/erl_process.c:10319-10350 (erts_schedule:
// erts_proc_sig_handle_incoming with `sig_reds`, then `reds -= sig_reds`), OTP-29.1.1.
pub(crate) fn schedule_in_signals(
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    state: u32,
) -> Result<(), VmError> {
    use arinsal_sched::psflg;
    let reds = process.heap.abi.fcalls;
    // `sig_reds = reds`, limited to ERTS_SIG_HANDLE_REDS_MAX_PREFERED when the process has
    // Erlang work (`ERTS_PSFLG_ACTIVE`) and no dirty work, unless a BIF is flushing signals.
    // Port of erl_process.c:10334-10344, OTP-29.1.1.
    let mut sig_reds = if state & (psflg::DIRTY_WORK | psflg::ACTIVE) == psflg::ACTIVE
        && !process.slice().is_some_and(|work| work.dirty_sys_gc)
        && process.inbox.flags & crate::receive::FS_FLUSHING_SIGS == 0
    {
        SIG_HANDLE_REDS_MAX_PREFERED
    } else {
        reds
    };
    let max_reds = sig_reds;
    let handled = process.handle_incoming(ctx, &mut sig_reds, max_reds, false);
    // Port of erts/emulator/beam/erl_process.c (schedule: `reds -= sig_reds`,
    // then `p->fcalls = reds`; the process's reductions are what the slice
    // used), OTP-29.1.1: the signal handling is the process's own work.
    super::executor::bump_fcalls(process, sig_reds);
    handled.map(|_| ())
}

/// The dirty run queue `ERTS_PSFLG_DIRTY_CPU_PROC` / `ERTS_PSFLG_DIRTY_IO_PROC` in the process
/// state asks for.
pub(super) fn dirty_proc_kind(
    state: &std::sync::atomic::AtomicU32,
) -> Option<arinsal_sched::DirtyKind> {
    use arinsal_sched::psflg;
    let state = state.load(std::sync::atomic::Ordering::Acquire);
    if state & psflg::DIRTY_CPU_PROC != 0 {
        Some(arinsal_sched::DirtyKind::Cpu)
    } else if state & psflg::DIRTY_IO_PROC != 0 {
        Some(arinsal_sched::DirtyKind::Io)
    } else {
        None
    }
}
