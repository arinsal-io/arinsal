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
pub(super) fn legacy_exception_trap(
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

/// Whether an interpreted step yielded only to hand control to native code, which
/// erts does without a scheduling point. Native FCALLS stay within this slice's
/// quantum so that its reductions are charged to the scheduler.
pub(super) fn native_transfer_continues(process: &mut Process, ctx: &RunCtx<'_, Message>) -> bool {
    let transfer = std::mem::take(&mut process.native_transfer);
    let remaining = i32::try_from(ctx.remaining()).unwrap_or(i32::MAX);
    if !transfer || remaining == 0 {
        return false;
    }
    process.heap.abi.fcalls = process.heap.abi.fcalls.min(remaining);
    true
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
    /// The record and code scopes of this scheduler's runtime are selected on its thread.
    pub(super) scopes_selected: bool,
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
    /// Emit the trace events of the native frames a return left, and their return_to events
    /// for the caller at `resume_pc`.
    pub(super) fn emit_native_return_frames(
        &mut self,
        process: &mut Process,
        ctx: &mut RunCtx<'_, Message>,
        frames: crate::trace::NativeTraceFrames,
        value: Term,
        resume_pc: usize,
    ) -> Result<(), VmError> {
        for (function_pc, actions) in frames {
            let Some(function) = crate::native_function_at(function_pc) else {
                continue;
            };
            crate::trace::native_return_events(
                &mut self.vm,
                process,
                ctx,
                &function,
                &actions,
                value,
                false,
            )?;
            for action in actions.iter().filter(|action| action.return_to) {
                crate::trace::native_return_to_event(
                    &mut self.vm,
                    process,
                    ctx,
                    action.session,
                    resume_pc,
                )?;
            }
        }
        Ok(())
    }

    /// Whether the slice can enter `fast_resume`: a native continuation with none of the rare
    /// per-slice work pending. Each test is a field the full path reads before it enters
    /// native code; when one holds, the full path does the work.
    // Port of erts/emulator/beam/erl_process.c (erts_schedule tests `p->state` and `p->flags`
    // once) and jit/arm/process_main.cpp (process_main: copy_in_registers, FCALLS, `br c_p->i`),
    // OTP-29.1.1.
    #[inline]
    pub(super) fn fast_entry_ok(process: &Process, ctx: &RunCtx<'_, Message>) -> bool {
        process.slice_is_plain()
            && ctx.fast_slice_ok()
            && !crate::suspend::ctx_suspended(ctx)
            && !crate::dist::fragment_continuation_pending()
            && !trace_boot_enabled()
            && process.native_pc() != Some(crate::native_bridge::native_trace_return_address())
    }

    /// The native entry loop of the full path, for the common slices: enter native code at the
    /// continuation, and handle the two exits every receive-driven process takes (a yield and a
    /// wait) and the signal fetch of `loop_rec`. `None` hands the slice to the full loop with
    /// the process state untouched; every other exit goes through `after_native`, the same
    /// dispatch the full loop uses.
    // Port of erts/emulator/beam/jit/arm/process_main.cpp (process_main: the scheduler enters
    // `c_p->i` directly), OTP-29.1.1.
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
            if process.heap.abi.fcalls <= 0
                && let Ok(remaining) = i32::try_from(ctx.remaining())
                && remaining > 0
            {
                process.heap.abi.fcalls = remaining;
            }
            let fcalls_before = process.heap.abi.fcalls;
            if crate::code_ix::take_code_barrier() {
                ctx.block_thread_progress(std::time::Duration::ZERO);
            }
            self.native_registers.active_code_ix =
                self.vm
                    .code_ix
                    .process_code_ix(crate::trace::saves_calls(process)) as u64;
            let native = crate::native_bridge::run_native_resume(
                process,
                &mut self.native_registers,
                code_ptr,
            );
            let consumed = fcalls_before.saturating_sub(process.heap.abi.fcalls);
            ctx.consume(u32::try_from(consumed).unwrap_or(0));
            // Native `timeout` has no scheduler context to send its trace event.
            if process.native_exit_kind != crate::proc_create::NativeExit::None
                && process.take_native_timeout_trace()
            {
                crate::trace::timeout_event(Some(&mut self.vm), process, ctx);
            }
            let virtual_reds = std::mem::take(&mut process.virtual_reds);
            ctx.add_virtual_reds(virtual_reds);
            process.reductions_used = process.reductions_used.saturating_add(
                u64::try_from(consumed)
                    .unwrap_or(0)
                    .saturating_sub(u64::from(virtual_reds)),
            );
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
                    process.set_force_yield(false);
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
                    if self_wait {
                        if let Err(error) = process.fetch_signals(ctx) {
                            return Some(Err(error));
                        }
                    } else {
                        match Vm::mailbox_ready_to_wait(process, &mut Some(&mut *ctx)) {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(error) => return Some(Err(error)),
                        }
                    }
                    return Some(Ok(RunState::Wait { timeout_pos }));
                }
                crate::proc_create::NativeExit::SignalFetch => {
                    crate::beamasm_integration::count_native_yield();
                    process.native_exit_kind = crate::proc_create::NativeExit::None;
                    let fcalls = i32::try_from(ctx.remaining()).unwrap_or(i32::MAX);
                    match process.receive_helper(ctx, fcalls) {
                        Ok((used, _)) => {
                            let used = u32::try_from(used).unwrap_or(0);
                            ctx.consume(used);
                            process.reductions_used =
                                process.reductions_used.saturating_add(u64::from(used));
                        }
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
        // Nothing to do at most scheduling points: no suspend, no timer pause and no
        // hibernation. Checked before the runtime handle is cloned.
        if process.runtime.is_some()
            && !crate::suspend::ctx_suspended(ctx)
            && !process
                .slice()
                .is_some_and(|work| work.hibernate_sched || work.timer_pause.is_some())
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
        if let Some(shift) = runtime.take_pause_shift(process)
            && let Some(deadline) = process.receive_timeout_pos.as_mut()
        {
            *deadline += shift.as_millis() as u64;
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
        let (module_id, entry) = erlang_apply_entry(&mut self.vm)?;
        self.vm.set_position(process, module_id, entry);
        process.inbox.set_save(0);
        process.receive_timeout_pos = None;
        process.receive_infinity = false;
        // erts resumes a hibernated process at the export address of apply/3 too.
        self.vm.enter_native_at_jump(process);
        Ok(())
    }
}

/// Registers a redone fun call or apply reads: the arguments and the fun (`call_fun`) or the
/// module and function (`apply_fixed`) above them, `apply/2` and `apply/3`'s own operands.
/// `None` for every other call the scheduler redoes: it takes its `arity` registers.
pub(super) fn retry_operand_count(target_pc: usize, arity: usize) -> Option<usize> {
    use arinsal_beamasm::dispatch::{
        APPLY_FIXED_UNPORTED, APPLY2_UNPORTED, APPLY3_UNPORTED, CALL_FUN_UNPORTED,
    };
    match target_pc {
        CALL_FUN_UNPORTED => Some(arity + 1),
        APPLY_FIXED_UNPORTED => Some(arity + 2),
        APPLY2_UNPORTED => Some(2),
        APPLY3_UNPORTED => Some(3),
        _ => None,
    }
}

/// The call arity of a redone fun call or apply, from the operand count its switch-out saved
/// (`retry_operand_count` backwards). `None` for every other call the scheduler redoes.
pub(super) fn retry_call_arity(target_pc: usize, saved: usize) -> Option<u8> {
    use arinsal_beamasm::dispatch::{
        APPLY_FIXED_UNPORTED, APPLY2_UNPORTED, APPLY3_UNPORTED, CALL_FUN_UNPORTED,
    };
    let arity = match target_pc {
        CALL_FUN_UNPORTED => saved.saturating_sub(1),
        APPLY_FIXED_UNPORTED => saved.saturating_sub(2),
        APPLY2_UNPORTED => 2,
        APPLY3_UNPORTED => 3,
        _ => return None,
    };
    u8::try_from(arity).ok()
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

/// Return address, native code generation, code tables generation and the owning module.
type CallerModuleEntry = (usize, u64, u64, Option<usize>);

thread_local! {
    /// Direct-mapped memo of `native_caller_module`, keyed by return address and validated
    /// against the native code generation and the code tables generation.
    static CALLER_MODULE_CACHE: std::cell::RefCell<[CallerModuleEntry; 256]> =
        const { std::cell::RefCell::new([(0, 0, 0, None); 256]) };
}

/// Module that owns the native function holding `resume_pc`; a module whose `-on_load`
/// is running is not current yet.
pub(super) fn native_caller_module(vm: &Vm, resume_pc: usize) -> Option<usize> {
    let generation = crate::native_bridge::native_registry_generation();
    // A running on_load changes the answer without touching the native code table.
    let memo = vm.code.pending_on_load.is_empty();
    let slot = (resume_pc >> 2) & 255;
    if memo {
        let hit = CALLER_MODULE_CACHE.with(|cache| {
            let entry = cache.borrow()[slot];
            (entry.0 == resume_pc && entry.1 == generation && entry.2 == vm.code_generation())
                .then_some(entry.3)
        });
        if let Some(found) = hit {
            return found;
        }
    }
    let found = crate::native_bridge::with_native_function_at(resume_pc, |caller| {
        // The pc names exactly one code instance: the one being loaded, the old one or the
        // current one (a reload runs the new on_load while the previous code is current).
        [
            vm.code.pending_on_load.get(caller.module),
            vm.code.loaded.get(caller.module),
            vm.code.old.get(caller.module),
        ]
        .into_iter()
        .flatten()
        .copied()
        .find(|id| vm.native_code_contains(*id, resume_pc))
        .or_else(|| vm.code.loaded.get(caller.module).copied())
    })
    .flatten();
    if memo {
        CALLER_MODULE_CACHE.with(|cache| {
            cache.borrow_mut()[slot] = (resume_pc, generation, vm.code_generation(), found);
        });
    }
    found
}

pub(super) fn resume_after_native_return(process: &mut Process) -> bool {
    loop {
        let Some(word) = process.heap.stack_get(0) else {
            return false;
        };
        // SAFETY: A live stack slot contains a tagged continuation or a raw native CP.
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
        let Some((handler, module, ip)) = crate::stacktrace::decode_tag(word) else {
            return false;
        };
        if handler {
            return false;
        }
        process.heap.release_stack(1);
        process.module = module;
        process.set_ip(ip);
        return true;
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

/// Module id of the apply_only start point (erts `beam_run_process`, erl_process.c:12616). A
/// process spawned but not yet run holds it in `module`; no module has this id.
pub(crate) const RUN_PROCESS: usize = usize::MAX;

impl Vm {
    /// First run of a spawned process: erts' apply_only instruction (beam_common.c:1434 `apply`)
    /// on X0..X2 (module, function, argument list). The export is the target when it exists;
    /// otherwise the process starts at erlang:apply/3, so an undefined function fails in the
    /// child with `undef`, as in erts.
    pub(crate) fn resolve_run_process(&mut self, process: &mut Process) -> Result<bool, VmError> {
        let module = process.x[0]
            .as_atom()
            .ok_or_else(|| VmError::Unsupported("run_process module".into()))?;
        let function = process.x[1]
            .as_atom()
            .ok_or_else(|| VmError::Unsupported("run_process function".into()))?;
        let args = crate::signals::list(process.x[2])
            .ok_or_else(|| VmError::Unsupported("run_process arguments".into()))?;
        let (module_id, ip, apply_operands) =
            match self.spawn_export(module, function, args.len() as u8) {
                Ok((module_id, ip)) => {
                    process.x.ensure_x(args.len());
                    for (index, term) in args.iter().enumerate() {
                        process.x[index] = *term;
                    }
                    process.gc_live = args.len();
                    process.heap.abi.arity = args.len().min(usize::from(u8::MAX)) as u8;
                    (module_id, ip, false)
                }
                Err(_) => {
                    let (module_id, entry) = erlang_apply_entry(self)?;
                    (module_id, entry, true)
                }
            };
        process.module = module_id;
        process.set_ip(ip);
        process.initial_call = Some((module_id, ip));
        Ok(apply_operands)
    }
}

pub(crate) fn erlang_apply_entry(vm: &mut Vm) -> Result<(usize, usize), VmError> {
    if let Some(entry) = vm.apply3_entry {
        return Ok(entry);
    }
    let module_id = vm.load_named("erlang")?;
    let entry = vm.code.modules[module_id]
        .functions
        .iter()
        .find(|(_, name, arity)| *name == "apply" && *arity == 3)
        .map(|(ip, _, _)| ip + 1)
        .ok_or_else(|| VmError::Unsupported("erlang:apply/3 is not loaded".into()))?;
    vm.apply3_entry = Some((module_id, entry));
    Ok((module_id, entry))
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
    let mut vm = cached.unwrap_or_else(|| Vm::shared_replica(runtime.code_scope, &runtime.paths));
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
        vm: Vm::shared_replica(runtime.code_scope, &runtime.paths),
        native_registers: {
            let mut registers = SchedulerRegisters::default();
            // The trace-return stub address is a per-scheduler constant (process_main sets it once).
            registers.tmp_mem[5] = crate::native_helpers::arinsal_beamasm_native_trace_return
                as *const () as usize as u64;
            registers
        },
    })
}
