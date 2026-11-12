//! Process-aware BIFs. These use the running process and scheduler context.

use crate::process::{Message, Runtime};
use crate::{Process, Vm, VmError};
use arinsal_sched::{Pid, Priority, RunCtx, Signal};
use arinsal_term::{Atom, Term, TermBuilder, TermKind, global_atoms, to_owned};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "pf-mem-counters")]
pub(crate) static PF_SPAWN_FUN_LOAD_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "pf-mem-counters")]
pub(crate) static PF_SPAWN_FUN_SETUP_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "pf-mem-counters")]
pub(crate) static PF_SPAWN_FUN_SCHED_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn badarg(_name: &str) -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::BADARG,
    )))
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        arinsal_term::atoms::SYSTEM_LIMIT,
    )))
}

fn runtime(process: &Process) -> Result<&Runtime, VmError> {
    process
        .runtime
        .ok_or_else(|| VmError::Unsupported("process BIF requires a scheduler".into()))
}

#[cfg(test)]
mod task_latency_tests {
    use arinsal_difftest::RefErl;

    use crate::Vm;

    const SOURCE: &str = concat!(
        "-module(task_latency_probe). -export([run/0]).\n",
        "task() -> Ref=make_ref(), Pid=spawn(fun() -> receive {Alias, Ref} -> Alias ! {Ref, ok} end end),\n",
        "Alias=erlang:monitor(process, Pid, [{alias,demonitor}]), Pid ! {Alias,Ref}, {Pid,Alias,Ref}.\n",
        "await({Pid,Alias,Ref}) -> receive {Ref,ok} -> erlang:demonitor(Alias,[flush]), ok;\n",
        "{'DOWN',Alias,process,Pid,Reason} -> erlang:error(Reason) after 5000 -> erlang:error(timeout) end.\n",
        "round() -> Tasks=[task() || _ <- lists:seq(1,8)], [await(T) || T <- Tasks], ok.\n",
        "run() -> round(), T0=erlang:monotonic_time(microsecond),\n",
        "[round() || _ <- lists:seq(1,20)], T1=erlang:monotonic_time(microsecond),\n",
        "(T1-T0) div 20."
    );

    #[test]
    fn eight_alias_monitor_replies_wake_the_waiter_without_exit_poll_delay() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping task latency regression test");
            return;
        };
        let beam = reference
            .compile_named("task_latency_probe", SOURCE, &[])
            .expect("compile alias monitor latency probe");
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam)
            .expect("load alias monitor latency probe");
        let elapsed = vm
            .eval_scheduled("task_latency_probe", "run", &[], 1, None)
            .expect("run alias monitor latency probe")
            .term;
        let arinsal_etf::OwnedTerm::Int(micros) = elapsed else {
            panic!("expected elapsed microseconds, got {elapsed:?}");
        };
        assert!(
            micros < 1_000,
            "eight alias monitor replies took {micros} us, expected under 1000 us"
        );
    }

    #[test]
    fn priority_monitor_and_sync_suspend_match_erts_under_busy_low_priority_targets() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping monitor/suspend priority differential test");
            return;
        };
        let source = r#"
-module(sig_prio_mon_probe).
-export([monitor_busy/0, suspend_busy/0]).
spin() -> spin().
monitor_busy() ->
    process_flag(priority, high),
    Pid = spawn_opt(fun() -> receive stop -> ok end end, [{priority, low}]),
    Ref = erlang:monitor(process, Pid),
    Pid ! stop,
    receive {'DOWN', Ref, process, Pid, normal} -> ok after 5000 -> timeout end.
suspend_busy() ->
    process_flag(priority, high),
    Pid = spawn_opt(fun spin/0, [{priority, low}]),
    Ref = erlang:monitor(process, Pid),
    true = erlang:suspend_process(Pid),
    true = erlang:resume_process(Pid),
    exit(Pid, kill),
    receive {'DOWN', Ref, process, Pid, killed} -> ok after 5000 -> timeout end.
"#;
        let beam = reference
            .compile_named("sig_prio_mon_probe", source, &[])
            .expect("compile monitor/suspend priority probe");
        reference.load("sig_prio_mon_probe", &beam).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam)
            .expect("load monitor/suspend priority probe");

        for function in ["monitor_busy", "suspend_busy"] {
            let expected = match reference.call("sig_prio_mon_probe", function, &[]) {
                arinsal_difftest::CallResult::Ok(term) => term,
                failure => panic!("erts {function} failed: {failure:?}"),
            };
            let actual = vm
                .eval_scheduled("sig_prio_mon_probe", function, &[], 2, None)
                .unwrap_or_else(|error| panic!("Arinsal {function} failed: {error:?}"));
            assert_eq!(actual.term, expected, "{function} differs from erts");
        }
    }

    #[test]
    fn spawn_opt_scheduler_bindings_are_accepted_for_each_online_scheduler() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping spawn scheduler option differential test");
            return;
        };
        let source = r#"
-module(spawn_scheduler_probe).
-export([run/0]).
run() ->
    Count = erlang:system_info(schedulers_online),
    Processes = [spawn_opt(fun() -> ok end, [{scheduler, I}]) || I <- lists:seq(1, Count)],
    length(Processes).
"#;
        let beam = reference
            .compile_named("spawn_scheduler_probe", source, &[])
            .unwrap();
        reference.load("spawn_scheduler_probe", &beam).unwrap();
        let expected = reference.call("spawn_scheduler_probe", "run", &[]);
        let workers = match reference
            .eval("erlang:system_info(schedulers_online)")
            .unwrap()
        {
            arinsal_etf::OwnedTerm::Int(workers) => workers as usize,
            value => panic!("expected scheduler count, got {value:?}"),
        };
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("spawn_scheduler_probe", "run", &[], workers, None)
            .unwrap()
            .term;
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual));
    }

    #[test]
    fn light_spawn_variants_match_erts() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping light spawn differential test");
            return;
        };
        let source = r#"
-module(light_spawn_probe).
-export([run/0]).
run() ->
    P = self(),
    {Pid, Ref} = spawn_opt(erlang, apply, [fun() -> receive go -> P ! went end end, []],
                           [monitor, link, {priority, high}, {min_heap_size, 1000}]),
    Pid ! go,
    Went = receive went -> ok after 1000 -> timeout end,
    Down = receive {'DOWN', Ref, process, Pid, X} -> X after 1000 -> timeout end,
    {links, Links} = process_info(self(), links),
    {Pid2, Ref2} = spawn_opt(fun() -> exit(boom) end, [{monitor, [{tag, tg}]}]),
    Down2 = receive {tg, Ref2, process, Pid2, X2} -> X2 after 1000 -> timeout end,
    Q = spawn_link(erlang, apply, [fun() -> P ! linked end, []]),
    Linked = receive linked -> ok after 1000 -> timeout end,
    Bad = [catch_error(fun() -> spawn(a, b, c) end),
           catch_error(fun() -> spawn_opt(m, f, [], [bogus]) end),
           catch_error(fun() -> spawn_link(m, 1, []) end)],
    {Went, Down, lists:member(Pid, Links), Down2, is_pid(Q), Linked, Bad}.
catch_error(F) -> try F() catch error:R -> R end.
"#;
        let beam = reference
            .compile_named("light_spawn_probe", source, &[])
            .unwrap();
        reference.load("light_spawn_probe", &beam).unwrap();
        let expected = reference.call("light_spawn_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("light_spawn_probe", "run", &[], 2, None)
            .unwrap()
            .term;
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual));
    }

    #[test]
    fn absolute_timer_deadline_matches_otp_monotonic_clock() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping absolute timer differential test");
            return;
        };
        let source = "-module(absolute_timer_probe). -export([run/0]). run() -> Deadline=erlang:monotonic_time(millisecond)+25, Ref=erlang:start_timer(Deadline,self(),done,[{abs,true}]), receive {timeout,Ref,done} -> ok after 1000 -> timeout end.";
        let beam = reference
            .compile_named("absolute_timer_probe", source, &[])
            .unwrap();
        reference.load("absolute_timer_probe", &beam).unwrap();
        let expected = reference.call("absolute_timer_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("absolute_timer_probe", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("absolute timer VM error: {error:?}"));
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }

    #[test]
    fn cancel_after_timeout_is_queued_keeps_the_original_reference() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping queued-timeout cancellation differential test");
            return;
        };
        let source = r#"
-module(queued_timeout_cancel_probe).
-export([run/0]).
run() ->
    Ref = erlang:start_timer(5, self(), done),
    Until = erlang:monotonic_time(millisecond) + 20,
    busy_wait(Until),
    Cancel = erlang:cancel_timer(Ref),
    receive {timeout, Ref, done} -> {Cancel =:= false, received}
    after 100 -> timeout end.
busy_wait(Until) ->
    case erlang:monotonic_time(millisecond) >= Until of
        true -> ok;
        false -> busy_wait(Until)
    end.
"#;
        let beam = reference
            .compile_named("queued_timeout_cancel_probe", source, &[])
            .expect("compile queued-timeout cancellation probe");
        reference
            .load("queued_timeout_cancel_probe", &beam)
            .unwrap();
        let expected = reference.call("queued_timeout_cancel_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("queued_timeout_cancel_probe", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("queued-timeout cancellation VM error: {error:?}"));
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }

    #[test]
    fn timers_for_dead_pids_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping dead-pid timer differential test");
            return;
        };
        let source = concat!(
            "-module(dead_pid_timer_probe). -export([run/0]).\n",
            "run() -> P=spawn(fun()->ok end), wait_dead(P), ",
            "R1=erlang:start_timer(60000,P,probe), ",
            "R2=erlang:send_after(60000,P,probe), ",
            "{erlang:read_timer(R1),erlang:cancel_timer(R1), ",
            "erlang:read_timer(R2),erlang:cancel_timer(R2)}.\n",
            "wait_dead(P) -> case erlang:is_process_alive(P) of ",
            "true -> erlang:yield(), wait_dead(P); false -> ok end."
        );
        let beam = reference
            .compile_named("dead_pid_timer_probe", source, &[])
            .unwrap();
        reference.load("dead_pid_timer_probe", &beam).unwrap();
        let expected = reference.call("dead_pid_timer_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("dead_pid_timer_probe", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("dead-pid timer VM error: {error:?}"));
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }

    #[test]
    fn read_timer_preserves_deadlines_above_signed_32_bit_range() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping wide timer differential test");
            return;
        };
        let source = concat!(
            "-module(wide_timer_probe). -export([run/0]).\n",
            "run() -> R=erlang:send_after(2147488000,self(),probe), ",
            "Left=erlang:read_timer(R), erlang:cancel_timer(R), ",
            "is_integer(Left) andalso Left > 2147483647."
        );
        let beam = reference
            .compile_named("wide_timer_probe", source, &[])
            .unwrap();
        reference.load("wide_timer_probe", &beam).unwrap();
        let expected = reference.call("wide_timer_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("wide_timer_probe", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("wide timer VM error: {error:?}"));
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }

    /// Port of erl_hl_timer.c:2237 (access_bif_timer): a synchronous cancel or read of a
    /// timer owned by another scheduler waits for the owner's reply message, so two
    /// schedulers accessing each other's timers at the same time make progress.
    #[test]
    fn cross_scheduler_sync_timer_access_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping cross-scheduler timer differential test");
            return;
        };
        let source = concat!(
            "-module(cross_timer_probe). -export([run/0]).\n",
            "run() -> S=self(), ",
            "Ps=[spawn_opt(fun() -> worker(S) end, [{scheduler, N}]) || N <- [1,2]], ",
            "[P ! {peers, Ps} || P <- Ps], ",
            "Rs=lists:sort([receive {P, R} -> R end || P <- Ps]), ",
            "[P ! stop || P <- Ps], Rs.\n",
            "worker(S) -> receive {peers, Ps} -> ok end, ",
            "Ts=[erlang:send_after(60000, self(), x) || _ <- lists:seq(1,200)], ",
            "[P ! {timers, self(), Ts} || P <- Ps, P =/= self()], ",
            "Other=receive {timers, _, O} -> O end, ",
            "Read=[erlang:read_timer(T) || T <- Other], ",
            "Cancel=[erlang:cancel_timer(T, [{info, false}]) || T <- Other], ",
            "Again=[erlang:cancel_timer(T) || T <- Other], ",
            "S ! {self(), {lists:all(fun is_integer/1, Read), lists:usort(Cancel), ",
            "lists:usort(Again), length(Ts)}}, ",
            "receive stop -> ok end."
        );
        let beam = reference
            .compile_named("cross_timer_probe", source, &[])
            .unwrap();
        reference.load("cross_timer_probe", &beam).unwrap();
        let expected = reference.call("cross_timer_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("cross_timer_probe", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("cross-scheduler timer VM error: {error:?}"));
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }

    #[test]
    fn unresolved_registered_timer_destination_resolves_at_expiry_like_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping registered-name timer differential test");
            return;
        };
        let source = concat!(
            "-module(registered_timer_probe). -export([run/0]).\n",
            "run() -> Ref=make_ref(), T1=erlang:start_timer(25,late_timer_probe,Ref), ",
            "T2=erlang:send_after(25,late_timer_probe,Ref), ",
            "true=register(late_timer_probe,self()), ",
            "receive {timeout,T1,Ref}->ok after 1000->timeout1 end, ",
            "receive Ref->ok after 1000->timeout2 end, ",
            "{erlang:read_timer(T1),erlang:read_timer(T2)}."
        );
        let beam = reference
            .compile_named("registered_timer_probe", source, &[])
            .unwrap();
        reference.load("registered_timer_probe", &beam).unwrap();
        let expected = reference.call("registered_timer_probe", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("registered_timer_probe", "run", &[], 2, None)
            .unwrap_or_else(|error| panic!("registered-name timer VM error: {error:?}"));
        assert_eq!(expected, arinsal_difftest::CallResult::Ok(actual.term));
    }
}

pub(crate) fn each_list_item(term: Term, mut visit: impl FnMut(Term)) -> Option<()> {
    let mut current = term;
    while current.classify() == TermKind::List {
        // SAFETY: The source heap remains live during this BIF call.
        let (head, tail) = unsafe { current.cons_ref()? };
        visit(head);
        current = tail;
    }
    (current == Term::NIL).then_some(())
}

/// Length of a proper list, `None` for an improper one (erts `erts_list_length`).
pub(crate) fn list_length(term: Term) -> Option<usize> {
    let mut length = 0;
    each_list_item(term, |_| length += 1)?;
    Some(length)
}

pub(crate) fn list(term: Term) -> Option<Vec<Term>> {
    let mut values = Vec::new();
    each_list_item(term, |head| values.push(head))?;
    Some(values)
}

/// `demonitor/2` options, walked in place like `bif.c` `demonitor_2`.
/// `None` is a bad option list; the full BIF raises `badarg`.
pub(crate) fn demonitor_flags(term: Term) -> Option<(bool, bool)> {
    let flush_atom = Term::atom(arinsal_term::atoms::FLUSH);
    let info_atom = Term::atom(arinsal_term::atoms::INFO);
    let mut flush = false;
    let mut info = false;
    let mut bad = false;
    each_list_item(term, |option| {
        if option == flush_atom {
            flush = true;
        } else if option == info_atom {
            info = true;
        } else {
            bad = true;
        }
    })?;
    (!bad).then_some((flush, info))
}

/// The trap of `demonitor(Ref, [flush])` when the monitor is already gone: the flush runs as
/// `erts_internal:flush_monitor_messages(Ref, Multi, Res)`, with `Multi` false for a plain monitor.
// Port of erts/emulator/beam/bif.c:640-654 (demonitor_2 flush_messages: BIF_TRAP3
// flush_monitor_messages_trap), OTP-29.1.1.
pub(crate) fn flush_monitor_trap(process: &Process, reference: Term, result: Term) -> VmError {
    VmError::TrapExport(crate::ExportTrap::new(
        // This BIF may run without a scheduler runtime in unit-level VM calls; the export entry
        // helper then uses the same unloaded-export stub as `make_fun/3`.
        process,
        FLUSH_MONITOR_CONTINUATION,
        vec![reference, Term::atom(arinsal_term::atoms::FALSE), result],
    ))
}

const FLUSH_MONITOR_CONTINUATION: &str = "erts_internal:flush_monitor_messages/3";

pub(crate) fn reference(process: &mut Process, id: u64) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    Term::local_ref(&mut heap, arinsal_bifs::ordinary_ref_words(id))
        .map_err(|error| VmError::Unsupported(format!("reference allocation: {error:?}")))
}

/// Create a local PID reference whose creator is `owner`.
// Port of erts_make_pid_ref (erl_bif_unique.c), OTP-29.1.1.
pub(crate) fn pid_reference(process: &mut Process, id: u64, owner: Pid) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let owner = owner
        .to_term()
        .ok_or_else(|| VmError::Unsupported("PID reference owner is not representable".into()))?;
    Term::local_pid_ref(&mut heap, arinsal_bifs::ordinary_ref_words(id), owner)
        .map_err(|error| VmError::Unsupported(format!("PID reference allocation: {error:?}")))
}

pub(crate) fn ref_id(term: Term) -> Option<u64> {
    if let Some(ids) = term.local_ref_numbers() {
        return Some(arinsal_bifs::ordinary_ref_key(ids));
    }
    match term.identity()? {
        arinsal_term::Identity::Ref { ids, .. } if ids.len() == 3 && ids[2] != u32::MAX => {
            Some(arinsal_bifs::ordinary_ref_key([ids[0], ids[1], ids[2]]))
        }
        _ => None,
    }
}

// Port of erts/emulator/beam/erl_proc_sig_queue.c:8893
// (erts_internal_dirty_process_handle_signals_1), OTP-29.1.1.
fn dirty_process_handle_signals(
    vm: &mut Vm,
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
) -> Result<Term, VmError> {
    // erts compares BIF_P with the three dirty signal handler processes.
    if !process.runtime.as_ref().is_some_and(|runtime| {
        runtime
            .dirty_signal_handlers
            .lock()
            .unwrap()
            .contains(&ctx.pid())
    }) {
        return Err(VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::NOTSUP,
        ))));
    }
    let Some(pid) = Pid::from_term(target) else {
        return Ok(Term::atom(arinsal_term::atoms::FALSE));
    };
    // `ERTS_BIF_REDS_LEFT(BIF_P)`: the caller's reductions bound the target's signal handling.
    let reds = u32::try_from(process.heap.abi.fcalls.max(1)).unwrap_or(1);
    let result = ctx.handle_dirty_signals(pid, reds, &mut |task, target_ctx| {
        task.downcast_mut::<Process>()
            .is_none_or(|target| target.handle_dirty_signals(vm, target_ctx))
    });
    Ok(Term::atom(match result {
        arinsal_sched::DirtySignals::NoProc => arinsal_term::atoms::NOPROC,
        arinsal_sched::DirtySignals::Normal => arinsal_term::atoms::NORMAL,
        arinsal_sched::DirtySignals::More => arinsal_term::atoms::MORE,
        arinsal_sched::DirtySignals::Idle | arinsal_sched::DirtySignals::Handled => {
            arinsal_term::atoms::OK
        }
    }))
}

fn deliver(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    to: Pid,
    message: Term,
) -> Result<(), VmError> {
    // Port of erts/emulator/beam/erl_process.c:10574 (notify_sys_task_executed), OTP-29.1.1:
    // `erts_queue_proc_message` to the requester, the caller itself included, so a reply to
    // self goes through the signal in-queue like any other message.
    if to != ctx.pid() && !crate::natives::proc::live(process, to)? {
        return Ok(());
    }
    ctx.send(to, Message::copy_from(message)?)
        .map_err(|error| VmError::Unsupported(format!("system task reply: {error}")))?;
    Ok(())
}

fn task_tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(values)
        .map_err(|error| VmError::Unsupported(format!("system task tuple: {error:?}")))
}

// Port of erts/emulator/beam/erl_process.c:11309 (request_system_task), OTP-29.1.1.
// `copy_literals` is not a request type here; the literal-area collector sends
// that work through `send_copy_request/3`.
fn request_system_task(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let (requester, target, priority, operation) = if args.len() == 3 {
        (ctx.pid(), args[0], args[1], args[2])
    } else {
        let requester = Pid::from_term(args[0]).ok_or_else(|| badarg("request_system_task"))?;
        (requester, args[1], args[2], args[3])
    };
    let priority_name = atom_name(priority).ok_or_else(|| badarg("request_system_task"))?;
    // `inherit` takes the caller's user priority.
    let priority = match priority_name.as_str() {
        "inherit" => crate::natives::proc::user_priority(process),
        name => crate::natives::proc::scheduler_priority(name)
            .ok_or_else(|| badarg("request_system_task"))?,
    };
    let Some(target_pid) = Pid::from_term(target) else {
        return Err(badarg("request_system_task"));
    };
    // SAFETY: The operation tuple stays rooted in the caller heap.
    let tuple = unsafe { operation.tuple_ref() }.ok_or_else(|| badarg("request_system_task"))?;
    if !(2..=4).contains(&tuple.len()) {
        return Err(badarg("request_system_task"));
    }
    let req_type = tuple.get(0).ok_or_else(|| badarg("request_system_task"))?;
    let req_id = tuple.get(1).ok_or_else(|| badarg("request_system_task"))?;
    let arg0 = tuple.get(2);
    let type_name = atom_name(req_type).ok_or_else(|| badarg("request_system_task"))?;
    let alive = crate::natives::proc::live(process, target_pid)?;
    let tag = match type_name.as_str() {
        "garbage_collect" => {
            let major = match arg0.and_then(atom_name).as_deref() {
                Some("major") => true,
                Some("minor") => false,
                _ => return Err(badarg("request_system_task")),
            };
            // A request on the caller itself is a system task like any other: erts schedules
            // it on the process (or sends it as an rpc signal behind pending signals) and the
            // collection runs when the process executes its system tasks
            // (erl_process.c:11309 request_system_task, `c_p->common.id == requester`).
            let op = RemoteOp::Collect {
                request_id: Message::copy_from(req_id)?,
                major,
            };
            (op, "garbage_collect")
        }
        "check_process_code" => {
            let module = arg0
                .and_then(atom_name)
                .ok_or_else(|| badarg("request_system_task"))?;
            vm.refresh_code();
            let old = vm.code.old.get(&module).copied();
            let op = RemoteOp::CheckProcessCode {
                module: old,
                native: old.and_then(|old| {
                    crate::load::native_code_version(&vm.code.code_meta, old).cloned()
                }),
                async_request: Some(Message::copy_from(req_id)?),
                kill: false,
            };
            (op, "check_process_code")
        }
        "system_task_test" => {
            let op = RemoteOp::SystemTaskTest {
                request_id: Message::copy_from(req_id)?,
            };
            (op, "system_task_test")
        }
        _ => return Err(badarg("request_system_task")),
    };
    let (op, tag) = tag;
    if alive
        && matches!(
            submit_sys_task(process, ctx, requester, target_pid, op, priority)?,
            Submit::Sent
        )
    {
        return Ok(Term::atom(arinsal_term::atoms::OK));
    }
    // Port of erts/emulator/beam/erl_process.c:11466 (noproc: notify_sys_task_executed), OTP-29.1.1.
    let message = task_tuple(
        process,
        &[
            crate::atom_cache::put(tag),
            req_id,
            Term::atom(arinsal_term::atoms::FALSE),
        ],
    )?;
    deliver(process, ctx, requester, message)?;
    Ok(Term::atom(arinsal_term::atoms::OK))
}

/// Process BIFs resolved before the process-independent BIF table.
///
/// [`call`] admits every `erlang` function name in this table at any arity.
/// `erts_internal:spawn_system_process/3` is `spawn/3` for system processes.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "monitor", 2),
    ("erlang", "monitor", 3),
    ("erlang", "demonitor", 1),
    ("erlang", "demonitor", 2),
    ("erlang", "trace_delivered", 1),
    ("erts_internal", "spawn_system_process", 3),
    ("erts_internal", "dirty_process_handle_signals", 1),
    ("erts_internal", "is_process_alive", 2),
    ("erts_internal", "is_process_executing_dirty", 1),
    ("erts_internal", "request_system_task", 3),
    ("erts_internal", "request_system_task", 4),
    ("erts_trace_cleaner", "check", 0),
    ("erts_trace_cleaner", "send_trace_clean_signal", 1),
];

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    IMPLEMENTED
        .iter()
        .any(|&(item_module, item_function, item_arity)| {
            item_module == module && item_function == function && item_arity == arity
        })
}

#[derive(Clone, Copy)]
enum SignalBif {
    TraceDelivered1,
    SpawnSystemProcess3,
    DirtyProcessHandleSignals1,
    IsProcessAlive2,
    IsProcessExecutingDirty1,
    RequestSystemTask3,
    RequestSystemTask4,
    TraceCleanerCheck0,
    TraceCleanerSend1,
}

macro_rules! resolved_signal_handler {
    ($name:ident, $entry:ident) => {
        fn $name(
            vm: &mut Vm,
            process: &mut Process,
            ctx: &mut RunCtx<'_, Message>,
            args: crate::natives::NativeArgs<'_>,
        ) -> Option<Result<Term, VmError>> {
            Some(args.with_values(process, |process, args| {
                call_resolved(vm, process, ctx, SignalBif::$entry, args)
            }))
        }
    };
}

/// Clear alias state from this process's monitor tree, retaining an active monitor when present.
// Port of erts/emulator/beam/bif.c (unalias_1), OTP-29.1.1.
pub(crate) fn unalias_origin(process: &mut Process, id: u64) -> bool {
    let mut remove = false;
    let node_alias = process
        .monitors
        .get(id)
        .is_some_and(|entry| entry.alias_mode().is_some());
    let owned = {
        match process.monitors.get_state_mut(id) {
            Some(crate::proc_create::OriginMonitor::Process(_)) => node_alias,
            Some(crate::proc_create::OriginMonitor::Alias) => {
                remove = true;
                true
            }
            Some(crate::proc_create::OriginMonitor::Distributed) => node_alias,
            Some(
                crate::proc_create::OriginMonitor::Port { .. }
                | crate::proc_create::OriginMonitor::DistPort { .. },
            ) => node_alias,
            Some(crate::proc_create::OriginMonitor::PortOrigin) | None => false,
        }
    };
    if owned && remove {
        process.monitors.remove(id);
    }
    owned
}

/// Apply the alias transition that erts performs when an origin monitor reports DOWN.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_monitor_down), OTP-29.1.1.
pub(crate) fn take_origin_monitor_down(
    process: &mut Process,
    id: u64,
) -> Option<crate::proc_create::ProcessMonitor> {
    let view = process.monitors.get(id)?;
    if view.kind() == crate::monitor_link::node_type::MONITOR_ALIAS {
        return None;
    }
    let mode = view.alias_mode();
    let entry = process.monitors.remove(id)?;
    if let Some(cold) = process.cold.as_mut() {
        cold.dist_monitors.remove(&id);
    }
    match mode {
        Some(crate::proc_create::AliasMode::ExplicitUnalias) => {
            insert_explicit_unalias(process, id);
        }
        Some(
            crate::proc_create::AliasMode::Demonitor
            | crate::proc_create::AliasMode::ReplyDemonitor,
        ) => {}
        None => {}
    }
    process.cold_mut().prio_monitors.remove(&id);
    Some(entry)
}

/// The alias a monitor with `explicit_unalias` leaves behind once it is gone.
fn insert_explicit_unalias(process: &mut Process, id: u64) {
    let creator = process.self_pid.map_or(0, Pid::data);
    process
        .monitors
        .insert(crate::proc_create::origin_monitor_with_reference(
            crate::proc_create::monitor_reference(
                id,
                Some(crate::proc_create::AliasMode::ExplicitUnalias),
                false,
            ),
            creator,
            0,
            crate::proc_create::OriginMonitor::Alias,
        ));
}

pub(crate) enum OriginDemonitor {
    Missing,
    Alias,
    /// The origin half of a local process monitor, to be sent to its target.
    Process(crate::proc_create::ProcessMonitor),
    Port(Option<u64>, Option<crate::proc_create::ProcessMonitor>),
    /// The origin half of a monitor of a remote process.
    Distributed(crate::proc_create::ProcessMonitor),
}

// Port of erts/emulator/beam/bif.c (demonitor), OTP-29.1.1.
pub(crate) fn demonitor_origin(process: &mut Process, id: u64) -> OriginDemonitor {
    // The reference lookup also decides whether this is an alias placeholder; erts performs
    // the same classification from the found node's type before deleting it.
    let entry = match process.monitors.remove_if(id, |flags| {
        flags & crate::monitor_link::node_flag::TYPE_MASK
            != crate::monitor_link::node_type::MONITOR_ALIAS
    }) {
        Ok(Some(entry)) => entry,
        Ok(None) => return OriginDemonitor::Missing,
        Err(_) => return OriginDemonitor::Alias,
    };
    finish_demonitor_origin(process, id, entry)
}

fn finish_demonitor_origin(
    process: &mut Process,
    id: u64,
    entry: crate::proc_create::ProcessMonitor,
) -> OriginDemonitor {
    let mode = entry.view().alias_mode();
    if mode == Some(crate::proc_create::AliasMode::ExplicitUnalias) {
        insert_explicit_unalias(process, id);
    }
    // `erts_proc_sig_prio_item_deleted` only for a priority monitor.
    if let Some(cold) = process.cold.as_mut()
        && !cold.prio_monitors.is_empty()
    {
        cold.prio_monitors.remove(&id);
    }
    // The type of the deleted node (`ERTS_ML_GET_TYPE(mon)`), read in place.
    enum Kind {
        Process,
        Port(Option<u64>),
        DistPort,
        Distributed,
    }
    let kind = match entry.state() {
        Some(crate::proc_create::OriginMonitor::Process(_)) => Kind::Process,
        Some(crate::proc_create::OriginMonitor::Port { port_id, .. }) => Kind::Port(*port_id),
        Some(crate::proc_create::OriginMonitor::DistPort { .. }) => Kind::DistPort,
        _ => Kind::Distributed,
    };
    match kind {
        Kind::Process => OriginDemonitor::Process(entry),
        Kind::Port(port_id) => OriginDemonitor::Port(port_id, Some(entry)),
        Kind::DistPort => OriginDemonitor::Port(None, None),
        Kind::Distributed => OriginDemonitor::Distributed(entry),
    }
}

resolved_signal_handler!(trace_delivered1, TraceDelivered1);
resolved_signal_handler!(spawn_system_process3, SpawnSystemProcess3);
resolved_signal_handler!(dirty_process_handle_signals1, DirtyProcessHandleSignals1);
resolved_signal_handler!(is_process_alive2, IsProcessAlive2);
resolved_signal_handler!(is_process_executing_dirty1, IsProcessExecutingDirty1);
resolved_signal_handler!(request_system_task3, RequestSystemTask3);
resolved_signal_handler!(request_system_task4, RequestSystemTask4);
resolved_signal_handler!(trace_cleaner_check0, TraceCleanerCheck0);
resolved_signal_handler!(trace_cleaner_send1, TraceCleanerSend1);

pub(crate) fn handler(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<crate::natives::ResolvedNative> {
    Some(match (module, function, arity) {
        ("erlang", "trace_delivered", 1) => trace_delivered1,
        ("erts_internal", "spawn_system_process", 3) => spawn_system_process3,
        ("erts_internal", "dirty_process_handle_signals", 1) => dirty_process_handle_signals1,
        ("erts_internal", "is_process_alive", 2) => is_process_alive2,
        ("erts_internal", "is_process_executing_dirty", 1) => is_process_executing_dirty1,
        ("erts_internal", "request_system_task", 3) => request_system_task3,
        ("erts_internal", "request_system_task", 4) => request_system_task4,
        ("erts_trace_cleaner", "check", 0) => trace_cleaner_check0,
        ("erts_trace_cleaner", "send_trace_clean_signal", 1) => trace_cleaner_send1,
        _ => return None,
    })
}

/// Resolve a process-aware BIF from the atom identities carried by apply/3.
/// The table is built once from the same load-time resolver used for imports.
pub(crate) fn handler_atoms(
    module: Atom,
    function: Atom,
    arity: u8,
) -> Option<crate::natives::NativeEntry> {
    static HANDLERS: OnceLock<HashMap<(Atom, Atom, u8), crate::natives::NativeEntry>> =
        OnceLock::new();
    let handlers = HANDLERS.get_or_init(|| {
        let handlers: HashMap<_, _> = IMPLEMENTED
            .iter()
            .filter_map(|&(module, function, arity)| {
                let module = global_atoms().intern(module).ok()?;
                let function = global_atoms().intern(function).ok()?;
                let entry = match (module, function, arity) {
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("monitor")? => {
                        crate::natives::NativeEntry::Direct(crate::natives::bif::monitor_executor)
                    }
                    (m, f, 3) if m == arinsal_term::atoms::ERLANG && f == atom_id("monitor")? => {
                        crate::natives::NativeEntry::Direct(crate::natives::bif::monitor_executor)
                    }
                    (m, f, 1) if m == arinsal_term::atoms::ERLANG && f == atom_id("demonitor")? => {
                        crate::natives::NativeEntry::Direct(crate::natives::bif::demonitor_executor)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("demonitor")? => {
                        crate::natives::NativeEntry::Direct(crate::natives::bif::demonitor_executor)
                    }
                    _ => crate::natives::NativeEntry::Resolved(handler(
                        global_atoms().text(module)?,
                        global_atoms().text(function)?,
                        arity,
                    )?),
                };
                Some(((module, function, arity), entry))
            })
            .collect();
        handlers
    });
    handlers.get(&(module, function, arity)).copied()
}

fn atom_id(name: &str) -> Option<Atom> {
    global_atoms().intern(name).ok()
}

/// Resolve a process BIF before the process-independent BIF table.
pub(crate) fn call(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _module: &str,
    _function: &str,
    _args: &[Term],
) -> Option<Result<Term, VmError>> {
    None
}

/// `monitor(port, Target)`: a port id, a registered name or `{Name, node()}`.
// Port of erts/emulator/beam/bif.c:895-945 (monitor/3, type `port`), OTP-29.1.1.
pub(crate) fn monitor_port(
    process: &mut Process,
    me: Pid,
    target: Term,
    tag: Term,
    alias_mode: Option<crate::proc_create::AliasMode>,
) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(|| badarg("monitor/2"))?;
    let reference_id = process.next_ref();
    let reference_term = if alias_mode.is_some() {
        pid_reference(process, reference_id, me)?
    } else {
        reference(process, reference_id)?
    };
    // Port of erts/emulator/beam/bif.c:895-945 (monitor/3, type `port`), OTP-29.1.1.
    let local_node = || global_atoms().get(crate::node_tables::this_node().0);
    let (port_id, name) = if let Some(id) = target.as_port() {
        (Some(id), None)
    } else if let Some(name) = target.as_atom() {
        (runtime.reg.whereis_port(name), Some(name))
    } else if let Some(name) = named_on_this_node(target, local_node()) {
        (runtime.reg.whereis_port(name), Some(name))
    } else if let Ok(object @ arinsal_etf::OwnedTerm::Port { .. }) = to_owned(target) {
        // A port of another node is badarg; a port of another incarnation of this node
        // never matches a live port (ERTS_MON_TYPE_DIST_PORT).
        if let arinsal_etf::OwnedTerm::Port { node, .. } = &object
            && *node != crate::node_tables::this_node().0
        {
            return Err(badarg("monitor/2"));
        }
        let (origin, _target) = crate::proc_create::create_monitor_with_reference_at(
            process.heap.alloc_ix(),
            crate::proc_create::monitor_reference(reference_id, alias_mode, false),
            me.data(),
            0,
            monitor_info_for(tag, None)?,
            crate::proc_create::OriginMonitor::DistPort {
                object: Box::new(object),
            },
        );
        process.monitors.insert(origin);
        send_port_noproc_down(runtime, me, reference_id)?;
        return Ok(reference_term);
    } else {
        return Err(badarg("monitor/2"));
    };
    // The port monitor stays in the origin tree until its DOWN signal is processed,
    // just like the monitor object in `erts_proc_sig_send_monitor_down`.
    let (origin, target_half) = crate::proc_create::create_monitor_with_reference_at(
        process.heap.alloc_ix(),
        crate::proc_create::monitor_reference(reference_id, alias_mode, false),
        me.data(),
        0,
        crate::proc_create::MonitorInfo::with_port_name(
            monitor_info_for(tag, None)?.tag().cloned(),
            name,
        ),
        crate::proc_create::OriginMonitor::Port { port_id, name },
    );
    process.monitors.insert(origin);
    let registered = port_id.and_then(|id| {
        runtime.ports.with_from(id, process.on_managed, |handle| {
            crate::port::monitor(process, id, handle, target_half, true)
        })
    });
    // `!prt || erts_port_monitor(..) == ERTS_PORT_OP_DROPPED`: the origin half stays in the
    // tree and the DOWN goes to this process as a signal.
    if !registered.transpose()?.unwrap_or(false) {
        send_port_noproc_down(runtime, me, reference_id)?;
    }
    Ok(reference_term)
}

/// The `noproc` DOWN of a port monitor whose port is gone, sent to the monitoring process
/// itself. It travels through the signal in-queue like any other DOWN, so it is handled (and
/// becomes a message) after the signals sent before it and after a receive marker reserved
/// before the `monitor/2` call; the origin half converts it (convert_to_down_message).
// Port of erts/emulator/beam/bif.c:912,932 (monitor/3, type `port`:
// erts_proc_sig_send_monitor_down(.., am_noproc)), OTP-29.1.1.
fn send_port_noproc_down(
    runtime: &crate::process::Runtime,
    me: Pid,
    reference_id: u64,
) -> Result<(), VmError> {
    runtime
        .scheduler()?
        .signal(
            me,
            me,
            Signal::MonitorDownImmediate {
                reference: reference_id,
                reason: Term::atom(arinsal_term::atoms::NOPROC).word(),
            },
        )
        .map_err(|error| VmError::Unsupported(format!("port monitor DOWN: {error}")))
}

/// `{Name, Node}` with both atoms and `Node` the local node: the by-name port target.
fn named_on_this_node(target: Term, local_node: Option<Atom>) -> Option<Atom> {
    // SAFETY: `target` is a BIF argument, rooted for the duration of the call.
    let tuple = unsafe { target.tuple_ref() }?;
    if tuple.len() != 2 {
        return None;
    }
    let (name, node) = (tuple.get(0)?.as_atom()?, tuple.get(1)?.as_atom()?);
    (Some(node) == local_node).then_some(name)
}

fn call_resolved(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    entry: SignalBif,
    args: &[Term],
) -> Result<Term, VmError> {
    match (entry, args) {
        (SignalBif::TraceDelivered1, [target]) => trace_delivered(process, ctx, *target),
        (SignalBif::IsProcessAlive2, [pid, reference]) => {
            is_process_alive_2(process, ctx, *pid, *reference)
        }
        (SignalBif::IsProcessExecutingDirty1, [pid]) => is_process_executing_dirty(process, *pid),
        (SignalBif::TraceCleanerCheck0, []) => Ok(Term::atom(arinsal_term::atoms::FALSE)),
        (SignalBif::TraceCleanerSend1, [to]) => trace_cleaner_send(process, ctx, *to),
        (SignalBif::SpawnSystemProcess3, [module, function, args]) => {
            // Port of erts/emulator/beam/erl_init.c (erts_internal_spawn_system_process_3:
            // erl_spawn_system_process with default options), OTP-29.1.1.
            let mut so = crate::natives::erl_process::ErlSpawnOpts::new(process.runtime);
            let pid = {
                let _slice = crate::process::sched_data::NativeSlice::enter(vm, ctx);
                crate::natives::erl_process::erl_create_process(
                    process, *module, *function, *args, &mut so,
                )
                .map_err(crate::natives::erl_process::CreateError::into_bif_error)?
            };
            if let (Some(pid), Some(runtime)) = (Pid::from_term(pid), process.runtime.as_ref()) {
                runtime.system_processes.lock().unwrap().insert(pid);
            }
            Ok(pid)
        }
        (SignalBif::DirtyProcessHandleSignals1, [arg]) => {
            dirty_process_handle_signals(vm, process, ctx, *arg)
        }
        (SignalBif::RequestSystemTask3, [_, _, _])
        | (SignalBif::RequestSystemTask4, [_, _, _, _]) => {
            request_system_task(vm, process, ctx, args)
        }
        _ => Err(VmError::Unsupported("resolved signal BIF arity".into())),
    }
}

/// Work a target process runs when it next handles signals.
///
/// Port of the signal-request ops in
/// `erts/emulator/beam/erl_proc_sig_queue.c` (`ERTS_SIG_Q_OP_PROCESS_INFO`,
/// `ERTS_SIG_Q_OP_GROUP_LEADER`, `ERTS_SIG_Q_OP_RPC`, `ERTS_SIG_Q_OP_IS_ALIVE`),
/// OTP-29.1.1. The scheduler `Signal` enum has no request variant, so the
/// payload lives here and [`Signal::UnlinkAck`] carries the id as a wakeup.
pub(crate) enum RemoteOp {
    /// `process_info/1` (`items == None`) or `process_info/2`.
    Info { items: Option<Message> },
    /// `group_leader(Leader, Pid)`.
    GroupLeader { leader: Pid },
    /// `erts_internal:process_flag(Pid, save_calls, Value)` applies on the target process.
    SaveCalls { value: Message },
    /// `garbage_collect` request. `request_id` is the term in the reply tuple.
    Collect { request_id: Message, major: bool },
    /// `process_display(Pid, backtrace)`.
    Display,
    /// Check whether the target still has a direct reference to old module code.
    CheckProcessCode {
        /// Old code of the checked module; `None` when it has none (the result is `false`).
        module: Option<usize>,
        /// Native function ranges of the old module version, when BeamAsm compiled it.
        native: Option<std::sync::Arc<crate::beamasm_integration::CompiledVersion>>,
        async_request: Option<Message>,
        kill: bool,
    },
    /// `erts_internal:request_system_task/3,4` `system_task_test` (erts `ERTS_PSTT_TEST`).
    SystemTaskTest { request_id: Message },
    /// `ERTS_PSTT_PRIO_SIG`: a system task without reply whose only purpose is to elevate
    /// the target's priority until it has handled its incoming signals.
    PrioSig,
}

pub(crate) enum Submit {
    /// The task is in the target's queue.
    Sent,
    /// The target had already exited.
    Dead,
}

/// A queued signal request; `Collect` ones may be saved while GC is disabled.
pub(crate) struct Pending {
    pub(crate) id: u64,
    pub(crate) from: Pid,
    pub(crate) op: RemoteOp,
}

/// The system tasks of one process, per priority, as in erts' `ErtsProcSysTaskQs`
/// (`p->sys_task_qs`).
#[derive(Default)]
pub(crate) struct SysTaskQueues {
    sys: [VecDeque<Pending>; 4],
    /// Normal-priority tasks run since the last low-priority one.
    ncount: u8,
}

/// The payload of `Signal::SysTask`: the task, or `None` for a kick.
pub(crate) struct SysTaskSignal {
    index: usize,
    task: Mutex<Option<Pending>>,
}

impl SysTaskQueues {
    fn is_empty(&self) -> bool {
        self.sys.iter().all(VecDeque::is_empty)
    }

    /// The highest-priority queued check_process_code task.
    fn take_check_process_code(&mut self) -> Option<Pending> {
        self.sys.iter_mut().find_map(|queue| {
            let index = queue
                .iter()
                .position(|pending| matches!(pending.op, RemoteOp::CheckProcessCode { .. }))?;
            queue.remove(index)
        })
    }

    /// Port of erts/emulator/beam/erl_process.c:10646 (fetch_sys_task), OTP-29.1.1:
    /// highest priority first; a waiting low-priority task runs after `RESCHEDULE_LOW`
    /// normal ones (erl_process.h:373).
    fn fetch_sys_task(&mut self) -> Option<Pending> {
        const RESCHEDULE_LOW: u8 = 8;
        const NORMAL: usize = 2;
        const LOW: usize = 3;
        let first = self.sys.iter().position(|queue| !queue.is_empty())?;
        let index = if first == NORMAL && !self.sys[LOW].is_empty() {
            self.ncount += 1;
            if self.ncount <= RESCHEDULE_LOW {
                NORMAL
            } else {
                self.ncount = 0;
                LOW
            }
        } else {
            first
        };
        let task = self.sys[index].pop_front();
        // erts frees the queue set when its last task is fetched, which resets the counter.
        if self.is_empty() {
            self.ncount = 0;
        }
        task
    }
}

fn sys_task_signal(index: usize, task: Option<Pending>) -> Signal<Message> {
    Signal::SysTask(arinsal_sched::SharedPayload(std::sync::Arc::new(
        SysTaskSignal {
            index,
            task: Mutex::new(task),
        },
    )))
}

pub(crate) fn sys_index(priority: Priority) -> usize {
    match priority {
        Priority::Max => 0,
        Priority::High => 1,
        Priority::Normal => 2,
        Priority::Low => 3,
    }
}

/// Whether `pid` of the runtime at `runtime` already began its exit.
// Port of erts/emulator/beam/erl_nif.c:2323 (enif_is_process_alive: erts_proc_lookup),
// OTP-29.1.1: erts removes an exiting process from the process table while its dirty NIF
// still runs; this scheduler keeps the entry until the NIF returns, so exit start decides.
pub(crate) fn has_begun_exit(runtime: &crate::process::Runtime, pid: Pid) -> bool {
    proc_is_exiting_runtime(runtime, pid)
}

fn proc_is_exiting_runtime(runtime: &crate::process::Runtime, pid: Pid) -> bool {
    runtime
        .scheduler()
        .ok()
        .and_then(|scheduler| {
            scheduler.with_proc_flags(pid, |flags| {
                flags.load(std::sync::atomic::Ordering::Acquire)
                    & arinsal_sched::proc_flags::EXITING
                    != 0
            })
        })
        .unwrap_or(false)
}

pub(crate) fn is_waiting(process: &Process, pid: Pid) -> bool {
    process
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.remote_status(pid) == "waiting")
}

/// Queue a process system task on `target` at `priority`; the reply goes to `requester`.
///
/// Port of erts/emulator/beam/erl_process.c:7221 (schedule_process_sys_task), OTP-29.1.1: the
/// task travels in the target's signal queue, so it is ordered after the signals the requester
/// sent before; the target's own queues take it when the signal is handled.
pub(crate) fn submit_sys_task(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    requester: Pid,
    target: Pid,
    op: RemoteOp,
    priority: Priority,
) -> Result<Submit, VmError> {
    let id = process.next_ref();
    let task = Pending {
        id,
        from: requester,
        op,
    };
    match ctx.signal_sys_task(
        target,
        sys_task_signal(sys_index(priority), Some(task)),
        priority,
    ) {
        Ok(()) => Ok(Submit::Sent),
        Err(arinsal_sched::Error::NoProcess) => Ok(Submit::Dead),
        Err(error) => Err(VmError::Unsupported(format!("request signal: {error}"))),
    }
}

/// Raise `target`'s priority to the caller's user priority while it handles incoming signals.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:1275 (maybe_elevate_sig_handling_prio) and
/// erl_process.c:11678 (erts_sig_prio), OTP-29.1.1. The elevation is a reply-less system task
/// at the caller's priority; the scheduler notifies a dirty signal handler when the target
/// executes dirty.
fn elevate_sig_handling_prio(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Pid,
) -> Result<(), VmError> {
    let min_prio = crate::natives::proc::user_priority(process);
    match ctx.process_priority(target) {
        Some(other) if sys_index(other) > sys_index(min_prio) => {}
        _ => return Ok(()),
    }
    let id = process.next_ref();
    let task = Pending {
        id,
        from: ctx.pid(),
        op: RemoteOp::PrioSig,
    };
    match ctx.signal_sys_task(
        target,
        sys_task_signal(sys_index(min_prio), Some(task)),
        min_prio,
    ) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(()),
        Err(error) => Err(VmError::Unsupported(format!(
            "signal priority task: {error}"
        ))),
    }
}

/// Raise a target's signal handling priority from a process BIF outside this module.
///
/// Port of erts/emulator/beam/erl_proc_sig_queue.c:1275 (`maybe_elevate_sig_handling_prio`),
/// OTP-29.1.1.
pub(crate) fn elevate_for_signal_request(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Pid,
) -> Result<(), VmError> {
    elevate_sig_handling_prio(process, ctx, target)
}

/// Handle a system task signal: queue the task on the process' own queues, then run what
/// can run now.
// Port of erts/emulator/beam/erl_process.c:11518 (sched_sig_sys_task: the task enters the
// process' system task queues when its ordered signal is consumed), OTP-29.1.1.
pub(crate) fn handle_sys_task(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    payload: &arinsal_sched::SharedPayload,
) -> Result<(), VmError> {
    let signal = payload
        .0
        .downcast_ref::<SysTaskSignal>()
        .expect("system task signal carries its task");
    if let Some(task) = signal.task.lock().unwrap().take() {
        process.cold_mut().sys_tasks.sys[signal.index].push_back(task);
    }
    // Port of erts/emulator/beam/erl_process.c:10368 (erts_schedule runs
    // execute_sys_tasks only while the process is scheduled in and not executing),
    // OTP-29.1.1: a system task woken in the middle of a BIF, a receive or native code
    // waits for the next scheduling point. check_process_code in particular must see the
    // process' continuation, which a half-done native call keeps outside its stack.
    let at_point = process
        .cold
        .as_ref()
        .is_some_and(|cold| cold.sys_task_point);
    if at_point {
        return Ok(());
    }
    if process
        .cold
        .as_ref()
        .is_some_and(|cold| !cold.sys_tasks.is_empty())
    {
        process.slice_mut().sys_tasks_deferred = true;
    }
    // Port of erts/emulator/beam/erl_process.c:11255 (dispatch_system_task),
    // OTP-29.1.1: check_process_code of a process executing dirty is run by the dirty
    // signal handler on its behalf; the other tasks wait for the process.
    if !ctx.dirty_running() {
        return Ok(());
    }
    let Some(pending) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.sys_tasks.take_check_process_code())
    else {
        return Ok(());
    };
    run_request(process, ctx, pending)?;
    clear_sys_task_priority_if_idle(process, ctx);
    Ok(())
}

/// Run one fetched request: a GC request may be saved or moved to a dirty scheduler first.
fn run_request(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pending: Pending,
) -> Result<(), VmError> {
    // Port of erts/emulator/beam/erl_process.c:10831 (save_gc_task), OTP-29.1.1:
    // a garbage_collect request waits (reply included) until GC is enabled again.
    if !process.heap.gc_enabled && matches!(pending.op, RemoteOp::Collect { .. }) {
        process
            .slice_mut()
            .delayed_gc
            .push(crate::proc_create::DelayedGc::Request(pending));
        return Ok(());
    }
    // Port of erts/emulator/beam/erl_gc.c:688-715 (check_for_possibly_long_gc) as called for
    // the ERTS_PSTT_GC system task (erl_process.c:11018-11040), OTP-29.1.1: a potentially
    // long collection runs on a dirty CPU scheduler, so it cannot hold up the processes
    // queued on this one.
    if let RemoteOp::Collect { major, .. } = &pending.op
        && !ctx.scheduler_type().is_dirty()
        && process
            .cold
            .as_ref()
            .is_some_and(|cold| cold.sys_task_point)
        && potentially_long_gc(process, *major)
    {
        {
            let mut work = process.slice_mut();
            work.delayed_gc
                .push(crate::proc_create::DelayedGc::Request(pending));
            work.dirty_sys_gc = true;
        }
        return Err(VmError::Dirty(arinsal_sched::DirtyKind::Cpu));
    }
    reply_request(process, ctx, pending)
}

/// Port of erts/emulator/beam/erl_gc.c:688-715 (check_for_possibly_long_gc), OTP-29.1.1.
fn potentially_long_gc(process: &Process, major: bool) -> bool {
    // erl_gc.h:26 (ERTS_POTENTIALLY_LONG_GC_HSIZE).
    const POTENTIALLY_LONG_GC_HSIZE: usize = 128 * 1024;
    let words = process.heap.gc_info_words();
    let mut size = words.heap_size + words.mbuf_size + words.stack_size;
    if major {
        size += words.old_heap_size;
    }
    size >= POTENTIALLY_LONG_GC_HSIZE
}

/// Port of erts/emulator/beam/erl_process.c:10803 (execute_sys_tasks), OTP-29.1.1: run the
/// system tasks queued for the process at its scheduling point.
pub(crate) fn execute_sys_tasks(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<(), VmError> {
    process.slice_mut().sys_tasks_deferred = false;
    loop {
        let pending = process
            .cold
            .as_mut()
            .and_then(|cold| cold.sys_tasks.fetch_sys_task());
        let Some(pending) = pending else {
            clear_sys_task_priority_if_idle(process, ctx);
            return Ok(());
        };
        run_request(process, ctx, pending)?;
    }
}

fn clear_sys_task_priority_if_idle(process: &Process, ctx: &RunCtx<'_, Message>) {
    if process
        .cold
        .as_ref()
        .is_none_or(|cold| cold.sys_tasks.is_empty())
    {
        ctx.clear_sys_task_priority();
    }
}

/// Wakes the process again for system tasks deferred during this slice, so that it reaches a
/// scheduling point that runs them (erts keeps ERTS_PSFLG_ACTIVE_SYS set).
#[inline(always)]
pub(crate) fn reschedule_deferred_sys_tasks(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<(), VmError> {
    if process.slice().is_some_and(|work| work.sys_tasks_deferred) {
        return wake_for_deferred_sys_tasks(process, ctx);
    }
    Ok(())
}

#[inline(never)]
fn wake_for_deferred_sys_tasks(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<(), VmError> {
    let Some(index) = process.cold.as_ref().and_then(|cold| {
        cold.sys_tasks
            .sys
            .iter()
            .position(|queue| !queue.is_empty())
    }) else {
        process.slice_mut().sys_tasks_deferred = false;
        return Ok(());
    };
    let priority = [
        Priority::Max,
        Priority::High,
        Priority::Normal,
        Priority::Low,
    ][index];
    // Port of erts/emulator/beam/erl_process.c:7028 (ERTS_PSFLG_ACTIVE_SYS): the process stays
    // active at the task's priority until `execute_sys_tasks` has run the queues.
    ctx.set_active_sys(priority);
    Ok(())
}

/// Run a queued request and send its reply.
pub(crate) fn reply_request(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pending: Pending,
) -> Result<(), VmError> {
    // Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_process_info), OTP-29.1.1: the
    // reply to a process_info request is built in the reply message's own heap fragment, not
    // on the target's heap, which a parked target would never collect.
    // Port of erts/emulator/beam/erl_process.c:11028 (ERTS_PSTT_PRIO_SIG): nothing to run.
    if matches!(pending.op, RemoteOp::PrioSig) {
        return Ok(());
    }
    let message = if let RemoteOp::Collect { request_id, major } = pending.op {
        crate::natives::proc::fulfill_collect(process, ctx, request_id, major)?
    } else {
        let detached = matches!(pending.op, RemoteOp::Info { .. });
        if detached {
            process.heap.begin_detached();
        }
        let message = crate::natives::proc::fulfill_request(process, ctx, pending.id, pending.op)
            .and_then(Message::copy_from);
        if detached {
            process.heap.end_detached();
        }
        message?
    };
    match ctx.send(pending.from, message) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(()),
        Err(error) => Err(VmError::Unsupported(format!("request reply: {error}"))),
    }
}

/// `{Ref, undefined}` to the requester of a `process_info` signal the exiting target never ran.
pub(crate) fn reply_request_failure(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    requester: Pid,
    id: u64,
) -> Result<(), VmError> {
    reply_failure(process, ctx, requester, id, RemoteOp::Info { items: None })
}

/// The failure reply of request `op` to the requester of a signal the exiting target never ran.
pub(crate) fn reply_failure(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    requester: Pid,
    id: u64,
    op: RemoteOp,
) -> Result<(), VmError> {
    let reply =
        crate::natives::proc::failure_reply(process, id, op).and_then(Message::copy_from)?;
    match ctx.send(requester, reply) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(()),
        Err(error) => Err(VmError::Unsupported(format!("request reply: {error}"))),
    }
}

/// The failure reply of a system task signal that reached the exiting target.
pub(crate) fn sys_task_signal_failed(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    payload: &arinsal_sched::SharedPayload,
) {
    let Some(signal) = payload.0.downcast_ref::<SysTaskSignal>() else {
        return;
    };
    let Some(task) = signal.task.lock().unwrap().take() else {
        return;
    };
    if matches!(task.op, RemoteOp::PrioSig) {
        return;
    }
    let Ok(reply) = crate::natives::proc::failure_reply(process, task.id, task.op) else {
        return;
    };
    let Ok(message) = Message::copy_from(reply) else {
        return;
    };
    let _ = ctx.send(task.from, message);
}

/// Reply `false` / `undefined` / `badarg` for requests this process will never run.
pub(crate) fn process_exiting(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    crate::natives::sys::release_multi_scheduling_blocks(process, ctx.pid());
    // OTP destroys the trapped BIF state together with the exiting process.
    // Persistent get/0's snapshot retains a table generation and its literals.
    if let Some(cold) = process.cold.as_mut() {
        cold.persistent_get_all = None;
    }
    // Port of erl_nif.c:2323 (`ERTS_PSFLG_EXITING` on the process).
    let _ =
        arinsal_sched::proc_flags::publish(ctx.exit_flags(), arinsal_sched::proc_flags::EXITING);
    // Port of erts/emulator/beam/erl_process.c:11039 (cleanup_sys_tasks), OTP-29.1.1: the
    // queued tasks of the exiting process get their failure reply.
    let mut pending = VecDeque::new();
    if let Some(cold) = process.cold.as_mut() {
        for queue in std::mem::take(&mut cold.sys_tasks).sys {
            pending.extend(queue);
        }
    }
    {
        for task in process.take_delayed_gc() {
            match task {
                crate::proc_create::DelayedGc::Request(request) => pending.push_back(request),
                // Port of erts/emulator/beam/erl_process.c:11039-11041 (cleanup_sys_tasks),
                // OTP-29.1.1: a saved literal-area copy task of an exiting process answers `ok`.
                crate::proc_create::DelayedGc::Literal {
                    request, requester, ..
                } => {
                    let _ = crate::natives::sys::reply_exiting_literal_area(
                        process, ctx, request, requester,
                    );
                }
                crate::proc_create::DelayedGc::Collect => {}
            }
        }
    }
    for pending in pending {
        if matches!(pending.op, RemoteOp::PrioSig) {
            continue;
        }
        let Ok(reply) = crate::natives::proc::failure_reply(process, pending.id, pending.op) else {
            continue;
        };
        let Ok(message) = Message::copy_from(reply) else {
            continue;
        };
        let _ = ctx.send(pending.from, message);
    }
}

/// Options of `monitor/3` and nested spawn monitors: `{tag, Tag}`, `{alias, Mode}` and `priority`.
// Port of erts/emulator/beam/bif.c (erts_monitor_opts), OTP-29.1.1.
pub(crate) fn monitor_options(
    args: &[Term],
) -> Result<(Term, Option<crate::proc_create::AliasMode>, bool), VmError> {
    if args.len() != 3 {
        return parse_monitor_option_items(&[], "monitor/3");
    }
    // Option lists are one or two items: keep them off the heap.
    let mut small = [Term::NIL; 4];
    let mut count = 0;
    let mut overflow = Vec::new();
    each_list_item(args[2], |item| {
        if overflow.is_empty() && count < small.len() {
            small[count] = item;
            count += 1;
        } else {
            if overflow.is_empty() {
                overflow.extend_from_slice(&small[..count]);
            }
            overflow.push(item);
        }
    })
    .ok_or_else(|| badarg("monitor/3"))?;
    if overflow.is_empty() {
        parse_monitor_option_items(&small[..count], "monitor/3")
    } else {
        parse_monitor_option_items(&overflow, "monitor/3")
    }
}

/// Parse nested options using the same rules as `erts_monitor_opts`.
// Port of erts/emulator/beam/bif.c (erts_monitor_opts), OTP-29.1.1.
pub(crate) fn spawn_monitor_options(
    options: Term,
) -> Option<(
    Option<arinsal_etf::OwnedTerm>,
    Option<crate::proc_create::AliasMode>,
    bool,
)> {
    let items = list(options)?;
    let (tag, alias_mode, priority) = parse_monitor_option_items(&items, "spawn_request").ok()?;
    let tag = if tag == Term::atom(arinsal_term::atoms::DOWN) {
        None
    } else {
        Some(arinsal_term::to_owned(tag).ok()?)
    };
    Some((tag, alias_mode, priority))
}

fn parse_monitor_option_items(
    options: &[Term],
    caller: &str,
) -> Result<(Term, Option<crate::proc_create::AliasMode>, bool), VmError> {
    let mut tag = Term::atom(arinsal_term::atoms::DOWN);
    let mut alias_mode = None;
    let mut priority = false;
    for &option in options {
        if option == Term::atom(arinsal_term::atoms::PRIORITY) {
            priority = true;
            continue;
        }
        // SAFETY: Each option is rooted in the caller's heap.
        let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg(caller))?;
        if tuple.len() != 2 {
            return Err(badarg(caller));
        }
        match (tuple.get(0), tuple.get(1)) {
            (Some(key), Some(value)) if key == Term::atom(arinsal_term::atoms::TAG) => tag = value,
            (Some(key), Some(value)) if key == Term::atom(arinsal_term::atoms::ALIAS) => {
                alias_mode = Some(parse_alias_mode(value).ok_or_else(|| badarg(caller))?);
            }
            _ => return Err(badarg(caller)),
        }
    }
    Ok((tag, alias_mode, priority))
}

fn parse_alias_mode(term: Term) -> Option<crate::proc_create::AliasMode> {
    if term == Term::atom(arinsal_term::atoms::DEMONITOR) {
        return Some(crate::proc_create::AliasMode::Demonitor);
    }
    Some(
        if term == Term::atom(arinsal_term::atoms::EXPLICIT_UNALIAS) {
            crate::proc_create::AliasMode::ExplicitUnalias
        } else if term == Term::atom(arinsal_term::atoms::REPLY_DEMONITOR) {
            crate::proc_create::AliasMode::ReplyDemonitor
        } else {
            return None;
        },
    )
}

/// The object of a local process monitor's `DOWN`: `{Name, node()}` for a name, else the pid.
/// The `noproc` DOWN of a monitor whose target does not exist. It is a monitor-down signal
/// to the monitoring process itself, so it queues behind the signals sent before it and
/// enters the message queue after a receive marker reserved before the monitor call.
// Port of erts/emulator/beam/bif.c:790-823 (monitor: erts_proc_sig_send_monitor_down with
// am_noproc), OTP-29.1.1.
/// The shared part of a monitor with this DOWN tag and registered name (erts `ErtsMonitorData`).
pub(crate) fn monitor_info_for(
    tag: Term,
    name: Option<&str>,
) -> Result<crate::proc_create::MonitorInfo, VmError> {
    let tag = if tag == Term::atom(arinsal_term::atoms::DOWN) {
        None
    } else {
        Some(
            arinsal_term::to_owned(tag)
                .map_err(|error| VmError::Unsupported(format!("monitor tag: {error:?}")))?,
        )
    };
    Ok(crate::proc_create::MonitorInfo::new(
        tag,
        name.map(str::to_owned),
    ))
}

#[allow(clippy::too_many_arguments)] // Keep monitor creation fields aligned with the erts call path.
pub(crate) fn send_noproc_down(
    process: &mut Process,
    me: Pid,
    id: u64,
    name: Option<&str>,
    target_pid: Option<Pid>,
    target: Term,
    tag: Term,
    alias_mode: Option<crate::proc_create::AliasMode>,
) -> Result<(), VmError> {
    // A named target is reported by name; the signal sender is then irrelevant.
    let from = target_pid.or_else(|| name.map(|_| me));
    if let Some(from) = from
        && let Some(runtime) = process.runtime
    {
        let info = monitor_info_for(tag, name)?;
        let (origin, _target) = crate::proc_create::create_monitor_with_reference_at(
            process.heap.alloc_ix(),
            crate::proc_create::monitor_reference(id, alias_mode, false),
            me.data(),
            from.data(),
            info,
            crate::proc_create::OriginMonitor::Process(crate::proc_create::OriginHalf),
        );
        process.monitors.insert(origin);
        let reason = Message::copy_from(Term::atom(arinsal_term::atoms::NOPROC))?;
        return runtime
            .scheduler()?
            .signal(
                from,
                me,
                Signal::MonitorDown {
                    reference: id,
                    reason: Box::new(reason),
                },
            )
            .map_err(|error| VmError::Unsupported(format!("monitor: {error}")));
    }
    // A pid of another incarnation of this node: no local sender to report it.
    let object = monitor_object(process, name, target)?;
    let reference = if alias_mode.is_some() {
        pid_reference(process, id, me)?
    } else {
        reference(process, id)?
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let down = TermBuilder::new(&mut heap)
        .tuple(&[
            tag,
            reference,
            Term::atom(arinsal_term::atoms::PROCESS),
            object,
            Term::atom(arinsal_term::atoms::NOPROC),
        ])
        .map_err(|error| VmError::Unsupported(format!("DOWN tuple: {error:?}")))?;
    // Port of erts/emulator/beam/bif.c:816-823 (monitor/3, an external pid of this node:
    // ERTS_MON_TYPE_DIST_PROC origin, then erts_proc_sig_send_monitor_down(.., am_noproc)),
    // OTP-29.1.1: the origin half goes into the tree and the DOWN reaches this process as a
    // signal through its in-queue, behind a receive marker reserved before the call.
    let (origin, _target) = crate::proc_create::create_monitor_with_reference_at(
        process.heap.alloc_ix(),
        crate::proc_create::monitor_reference(id, alias_mode, false),
        me.data(),
        0,
        monitor_info_for(tag, name)?,
        crate::proc_create::OriginMonitor::Distributed,
    );
    process.monitors.insert(origin);
    let message = Message::copy_from(down)?;
    process
        .runtime
        .ok_or_else(|| badarg("monitor/2"))?
        .scheduler()?
        .signal(
            me,
            me,
            Signal::MonitorDownMsg {
                reference: id,
                message: Box::new(message),
            },
        )
        .map_err(|error| VmError::Unsupported(format!("monitor: {error}")))
}

pub(crate) fn monitor_object(
    process: &mut Process,
    name: Option<&str>,
    target: Term,
) -> Result<Term, VmError> {
    let Some(name) = name else {
        return Ok(target);
    };
    let node = crate::node_tables::this_node().0.to_owned();
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .tuple(&[crate::atom_cache::put(name), crate::atom_cache::put(&node)])
        .map_err(|error| VmError::Unsupported(format!("monitor object: {error:?}")))
}

/// The monitored object of a local port monitor in `'DOWN'` messages and `process_info`.
// Port of erts/emulator/beam/erl_proc_sig_queue.c (convert_to_down_message), OTP-29.1.1:
// a monitor created by name reports `{Name, node()}`, otherwise the port id.
pub(crate) fn port_monitor_object<H: arinsal_term::HeapAlloc + ?Sized>(
    heap: &mut H,
    port_id: Option<u64>,
    name: Option<Atom>,
) -> Result<Term, VmError> {
    if let Some(name) = name {
        let node = crate::node_tables::this_node().0.to_owned();
        return TermBuilder::new(heap)
            .tuple(&[Term::atom(name), crate::atom_cache::put(&node)])
            .map_err(|error| VmError::Unsupported(format!("monitor object: {error:?}")));
    }
    port_id
        .and_then(Term::port)
        .ok_or_else(|| VmError::Unsupported("port monitor without a port id".into()))
}

/// The target's answer to an `ERTS_SIG_Q_OP_IS_ALIVE` signal: `{Ref, Alive}` as an ordinary
/// message to the requester.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:3625 (is_alive_response), OTP-29.1.1.
pub(crate) fn alive_response(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    requester: Pid,
    id: u64,
    alive: bool,
) -> Result<(), VmError> {
    let reference = reference(process, id)?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let tuple = TermBuilder::new(&mut heap)
        .tuple(&[
            reference,
            Term::atom(if alive {
                arinsal_term::atoms::TRUE
            } else {
                arinsal_term::atoms::FALSE
            }),
        ])
        .map_err(|_| system_limit())?;
    let message = Message::copy_from(tuple)?;
    match ctx.send(requester, message) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(()),
        Err(error) => Err(VmError::Unsupported(format!("alive reply: {error}"))),
    }
}

// Port of erts/emulator/beam/erl_bif_info.c:4049 (erts_internal_is_process_alive_2), OTP-29.1.1.
fn is_process_alive_2(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Term,
    reference: Term,
) -> Result<Term, VmError> {
    let pid = Pid::from_term(pid).ok_or_else(|| badarg("is_process_alive/2"))?;
    let id = ref_id(reference).ok_or_else(|| badarg("is_process_alive/2"))?;
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:3027 (erts_proc_sig_send_is_alive_request):
    // queue the signal; a target that is gone is answered here, on the requester itself.
    match ctx.signal(pid, Signal::IsAlive(id)) {
        Ok(()) => {
            elevate_sig_handling_prio(process, ctx, pid)?;
            Ok(Term::atom(arinsal_term::atoms::OK))
        }
        Err(arinsal_sched::Error::NoProcess) => {
            // Port of erl_proc_sig_queue.c:3065-3070: reply `{Ref, false}` to self with
            // `erts_queue_message`, through this process's signal in-queue. The receive marker
            // `erts_internal:is_process_alive/1` bound before this call is in that queue too, so
            // the reply lands after it; put straight into the message queue it lands before the
            // marker and `receive {Ref, Res}` never sees it.
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let reply = TermBuilder::new(&mut heap)
                .tuple(&[reference, Term::atom(arinsal_term::atoms::FALSE)])
                .map_err(|_| system_limit())?;
            ctx.send(ctx.pid(), Message::copy_from(reply)?)
                .map_err(|error| VmError::Unsupported(format!("alive reply: {error}")))?;
            Ok(Term::atom(arinsal_term::atoms::OK))
        }
        Err(error) => Err(VmError::Unsupported(format!("alive request: {error}"))),
    }
}

// Port of erts/emulator/beam/erl_process.c:9216
// (erts_internal_is_process_executing_dirty_1), OTP-29.1.1.
fn is_process_executing_dirty(process: &Process, pid: Term) -> Result<Term, VmError> {
    let Some(pid) = Pid::from_term(pid) else {
        return Err(badarg("is_process_executing_dirty/1"));
    };
    let dirty = runtime(process)?.scheduler()?.is_executing_dirty(pid);
    Ok(Term::atom(if dirty {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    }))
}

// Port of erts/emulator/beam/erl_bif_trace.c:3900 (trace_delivered_1), OTP-29.1.1.
fn trace_delivered(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
) -> Result<Term, VmError> {
    if target != Term::atom(arinsal_term::atoms::ALL) && Pid::from_term(target).is_none() {
        return Err(badarg("trace_delivered/1"));
    }
    let id = process.next_ref();
    let reference = reference(process, id)?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let message = TermBuilder::new(&mut heap)
        .tuple(&[
            Term::atom(arinsal_term::atoms::TRACE_DELIVERED),
            target,
            reference,
        ])
        .map_err(|_| system_limit())?;
    let envelope = Message::copy_from(message)?;
    match ctx.send(ctx.pid(), envelope) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(reference),
        Err(arinsal_sched::Error::Capacity) => Err(system_limit()),
        Err(_) => Err(badarg("trace_delivered/1")),
    }
}

// Port of erts/emulator/beam/erl_bif_trace.c:650
// (erts_trace_cleaner_send_trace_clean_signal_1), OTP-29.1.1.
fn trace_cleaner_send(
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    to: Term,
) -> Result<Term, VmError> {
    let is_cleaner = process.runtime.as_ref().is_some_and(|runtime| {
        runtime.reg.whereis_proc_str("erts_trace_cleaner") == Some(ctx.pid())
    });
    if !is_cleaner {
        return Err(VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::NOTSUP,
        ))));
    }
    if Pid::from_term(to).is_some() {
        // No pending clear sessions in this build; a live target would return true.
        return Ok(Term::atom(
            if runtime(process)?
                .scheduler()?
                .lookup(Pid::from_term(to).expect("pid"))
            {
                arinsal_term::atoms::TRUE
            } else {
                arinsal_term::atoms::FALSE
            },
        ));
    }
    if to.as_port().is_some() {
        return Ok(Term::atom(arinsal_term::atoms::FALSE));
    }
    Err(badarg("send_trace_clean_signal/1"))
}
