//! Process-aware BIFs. These use the running process and scheduler context.

use crate::process::{Message, Runtime};
use crate::{Process, ProcessHeapHandle, Vm, VmError};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, Priority, RunCtx, Signal};
use arinsal_term::{Atom, HeapReservation, Term, TermBuilder, TermKind, global_atoms, to_owned};
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

fn rt_ref(process: &Process) -> Option<&Runtime> {
    process.runtime
}

fn runtime(process: &Process) -> Result<&Runtime, VmError> {
    process
        .runtime
        .ok_or_else(|| VmError::Unsupported("process BIF requires a scheduler".into()))
}

/// `whereis/1` from native code. The light-BIF fragment calls this with `c_p`
/// and the register arguments; it does not trap back into the executor.
// Port of erts/emulator/beam/bif.c:2342 (whereis_1), OTP-29.1.1.
pub(crate) fn whereis_bif(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    Some(match whereis_1(process, args[0]) {
        Ok(term) => Ok(term),
        Err(VmError::Trap(trap)) => Err(trap),
        Err(_) => Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        ))),
    })
}

/// `whereis_1` as the BIF `call_light_bif_shared` branches to.
///
/// Port of erts/emulator/beam/bif.c:2342 (`whereis_1`) and
/// jit/arm/instr_bif.cpp:434-445 (`dynamic_runtime_call<3>`), OTP-29.1.1.
/// Arguments are `(c_p, reg, I)`. The result is a raw term, or `THE_NON_VALUE`
/// after `freason` is set.
pub(crate) extern "C" fn whereis_light(
    header: *mut arinsal_beamasm::ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    if regs.is_null() {
        return 0;
    }
    // reg[0] is BIF_ARG_1. The scheduler file is that array while native code runs.
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let Some(arg) = process.x.first().copied() else {
        return 0;
    };
    // The error returns `THE_NON_VALUE` from a cold function. Building that
    // `Result` here reserved a 128-byte frame on the success path.
    let Some(name) = arg.as_atom() else {
        return whereis_not_atom(process);
    };
    let Some(rt) = process.runtime else {
        return whereis_no_runtime(process);
    };
    let term = match rt.reg.whereis(name) {
        Some(crate::register::RegId::Proc(pid)) => pid.to_term().unwrap_or_else(undefined_term),
        Some(crate::register::RegId::Port(id)) => Term::port(id).unwrap_or_else(undefined_term),
        None => undefined_term(),
    };
    crate::native_hooks::raw(term)
}

#[cold]
#[inline(never)]
fn whereis_not_atom(process: &mut Process) -> u64 {
    whereis_light_error(process, badarg("whereis/1"))
}

#[cold]
#[inline(never)]
fn whereis_no_runtime(process: &mut Process) -> u64 {
    whereis_light_error(
        process,
        VmError::Unsupported("process BIF requires a scheduler".into()),
    )
}

fn undefined_term() -> Term {
    Term::atom(arinsal_term::atoms::UNDEFINED)
}

/// `BIF_ERROR` for `whereis/1`. Cold so the direct call stays the success path.
#[cold]
#[inline(never)]
fn whereis_light_error(process: &mut Process, error: VmError) -> u64 {
    let trap = match error {
        VmError::Trap(trap) => trap,
        _ => crate::exceptions::Trap::error(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT)),
    };
    // `BIF_ERROR(BIF_P, BADARG)`: the light-BIF fragment stored `bif_mfa` in `c_p->current` and
    // the argument is still x0, which is all `save_stacktrace` reads.
    crate::native_helpers::bif_error(process, trap)
}

/// `is_process_alive_1` as the BIF `call_light_bif_shared` branches to.
///
/// Port of erts/emulator/beam/erl_bif_info.c:4060-4112 (`is_process_alive_1`) and
/// jit/arm/instr_bif.cpp:434-445, OTP-29.1.1. The caller compared with
/// `BIF_P->common.id` returns `true` with no signal poll. Anything else is
/// `BIF_TRAP1` into the executor, which already runs the alive request.
pub(crate) extern "C" fn is_process_alive_light(
    header: *mut arinsal_beamasm::ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (_, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let arg = registers.x_reg_array[0]; // BIF_ARG_1
    // erts: `if (BIF_ARG_1 == BIF_P->common.id) BIF_RET(am_true)`, before any table access.
    if arg.is_pid() && arg.tagged_word() == process.heap.abi.self_pid {
        return crate::native_hooks::raw(Term::atom(arinsal_term::atoms::TRUE));
    }
    match alive_fast(process, arg) {
        Some(result) => crate::native_hooks::raw(Term::atom(result)),
        None => alive_trap(process, identity),
    }
}

/// The part of `is_process_alive_1` that needs no signal: the target is gone or has an idle
/// signal state, and the caller has no incoming signals to order against.
// Port of erts/emulator/beam/erl_bif_info.c (is_process_alive_1), OTP-29.1.1. Where erts
// traps out (`is_process_alive_trap`, `ERTS_BIF_HANDLE_SIGNALS_FROM_RETURN`) this returns `None`
// and the executor runs the alive request, which orders strictly more than erts does.
#[inline(always)]
fn alive_fast(process: &Process, arg: Term) -> Option<arinsal_term::Atom> {
    // erts: `if (is_internal_pid(BIF_ARG_1))`; other arguments take the generic path.
    if !arg.is_pid() {
        return None;
    }
    let scheduler = process.runtime.as_ref()?.scheduler_if_started()?;
    // erts: `rp = erts_proc_lookup_raw(pid)`; missing is false, an idle state is true, any
    // signal state traps to `is_process_alive_trap`.
    let found = if process.on_managed {
        scheduler.is_quiet_word(arg.tagged_word())
    } else {
        scheduler.is_quiet_from(Pid::from_term(arg)?, false)
    };
    let result = match found {
        None => arinsal_term::atoms::FALSE,
        Some(true) => arinsal_term::atoms::TRUE,
        Some(false) => return None,
    };
    // erts: `if (ERTS_PROC_HAS_INCOMING_SIGNALS(BIF_P))` reads `c_p->state` after the result.
    let own_quiet = match process.signal_probe() {
        Some(probe) => probe.is_quiet(),
        None => scheduler.is_quiet_from(process.self_pid?, process.on_managed) == Some(true),
    };
    own_quiet.then_some(result)
}

/// `BIF_TRAP1(is_process_alive_trap, ...)`: the fragment context-switches to
/// `c_p->i`, and the scheduler runs the executor body.
#[cold]
#[inline(never)]
fn alive_trap(process: &mut Process, identity: u64) -> u64 {
    process.heap.abi.i = identity as *const _;
    process.heap.abi.arity = 1;
    process.heap.abi.exc.freason = 1 << 10;
    0
}

// Port of erts/emulator/beam/bif.c:2342 (whereis_1) and
// register.c:276 (erts_whereis_name_to_id), OTP-29.1.1:
// atom check, read lock, one hash fetch, unlock, the pid or port id.
fn whereis_1(process: &Process, name: Term) -> Result<Term, VmError> {
    let name = name.as_atom().ok_or_else(|| badarg("whereis/1"))?;
    let rt = runtime(process)?;
    Ok(match rt.reg.whereis(name) {
        Some(crate::register::RegId::Proc(pid)) => pid.to_term().unwrap_or_else(undefined_term),
        Some(crate::register::RegId::Port(id)) => Term::port(id).unwrap_or_else(undefined_term),
        None => undefined_term(),
    })
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
            .eval_scheduled("spawn_scheduler_probe", "run", &[], workers, Some(79))
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
fn demonitor_flags(term: Term) -> Option<(bool, bool)> {
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

/// Local `monitor`/`demonitor` cases that erts returns from the BIF without a
/// signal: monitoring oneself, and demonitoring a ref that is not a monitor.
///
/// `None` leaves the call to the executor path (another local process, a name,
/// a remote or port monitor, a bad argument).
// Port of erts/emulator/beam/bif.c:782-784 (`monitor`, no monitoring of self)
// and bif.c:437-454 (`demonitor` tree miss), OTP-29.1.1.
pub(crate) fn light_monitor_bif(
    process: &mut Process,
    monitor: bool,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    if monitor {
        light_monitor_self(process, args)
    } else {
        light_demonitor_miss(process, args)
    }
}

fn light_monitor_self(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    // monitor/3 options (alias, tag) stay on the full path. monitor/2 of self
    // is `erts_make_ref` and nothing else.
    if args.len() != 2 || args[0] != Term::atom(arinsal_term::atoms::PROCESS) {
        return None;
    }
    let self_pid = process.heap.abi.self_pid;
    if self_pid == 0 || args[1].tagged_word() != self_pid {
        return None;
    }
    Some(light_ref(process))
}

fn light_ref(process: &mut Process) -> Result<Term, crate::exceptions::Trap> {
    let words = arinsal_bifs::next_ref_words();
    match Term::local_ref(&mut process.heap, words) {
        Ok(term) => Ok(term),
        Err(_) => {
            let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            Term::local_ref(&mut fragment, words).map_err(|_| {
                crate::exceptions::Trap::error(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT))
            })
        }
    }
}

fn light_demonitor_miss(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let reference = *args.first()?;
    let ids = reference.local_ref_numbers()?;
    let id = arinsal_bifs::ordinary_ref_key(ids);
    if process.monitors.get_state(id).is_some()
        || process
            .cold
            .as_ref()
            .is_some_and(|cold| cold.dist_monitors.contains(&id))
    {
        return None;
    }
    let (flush, info) = if args.len() < 2 {
        (false, false)
    } else {
        demonitor_flags(args[1])?
    };
    if flush {
        // The flush needs the receive that the Erlang export performs; the executor path traps.
        return None;
    }
    Some(Ok(Term::atom(if info {
        arinsal_term::atoms::FALSE
    } else {
        arinsal_term::atoms::TRUE
    })))
}

/// The trap of `demonitor(Ref, [flush])` when the monitor is already gone: the flush runs as
/// `erts_internal:flush_monitor_messages(Ref, Multi, Res)`, with `Multi` false for a plain monitor.
// Port of erts/emulator/beam/bif.c:640-654 (demonitor_2 flush_messages: BIF_TRAP3
// flush_monitor_messages_trap), OTP-29.1.1.
fn flush_monitor_trap(process: &Process, reference: Term, result: Term) -> VmError {
    VmError::TrapExport(crate::ExportTrap::new(
        // This BIF may run without a scheduler runtime in unit-level VM calls; the export entry
        // helper then uses the same unloaded-export stub as `make_fun/3`.
        process,
        FLUSH_MONITOR_CONTINUATION,
        vec![reference, Term::atom(arinsal_term::atoms::FALSE), result],
    ))
}

const FLUSH_MONITOR_CONTINUATION: &str = "erts_internal:flush_monitor_messages/3";

/// Where `send_after/start_timer` put the timer: the scheduler context of the executor, or the
/// calling scheduler's wheel reached from native code.
pub(crate) trait TimerSink {
    fn schedule_timer(
        &mut self,
        target: Pid,
        ms: u64,
        message: Message,
        wrapped: bool,
    ) -> Result<arinsal_sched::TimerRef, String>;
    fn schedule_resolved_timer(
        &mut self,
        ms: u64,
        message: Message,
        wrapped: bool,
        resolve: std::sync::Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
    ) -> Result<arinsal_sched::TimerRef, String>;
}

impl TimerSink for RunCtx<'_, Message> {
    fn schedule_timer(
        &mut self,
        target: Pid,
        ms: u64,
        message: Message,
        wrapped: bool,
    ) -> Result<arinsal_sched::TimerRef, String> {
        RunCtx::schedule_timer(self, target, ms, message, wrapped).map_err(|e| e.to_string())
    }
    fn schedule_resolved_timer(
        &mut self,
        ms: u64,
        message: Message,
        wrapped: bool,
        resolve: std::sync::Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
    ) -> Result<arinsal_sched::TimerRef, String> {
        RunCtx::schedule_resolved_timer(self, ms, message, wrapped, move || resolve())
            .map_err(|e| e.to_string())
    }
}

/// The calling normal scheduler's timer wheel, reached from native code without a `RunCtx`.
pub(crate) struct NativeTimers(
    pub(crate) Pid,
    pub(crate) Option<arinsal_sched::NativeHandle<Message>>,
);

impl TimerSink for NativeTimers {
    fn schedule_timer(
        &mut self,
        target: Pid,
        ms: u64,
        message: Message,
        wrapped: bool,
    ) -> Result<arinsal_sched::TimerRef, String> {
        let Some(handle) = &self.1 else {
            return Err("no native scheduler".into());
        };
        match handle.start_timer(self.0, target, ms, message, wrapped) {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(_) => Err("no native scheduler".into()),
        }
    }
    fn schedule_resolved_timer(
        &mut self,
        ms: u64,
        message: Message,
        wrapped: bool,
        resolve: std::sync::Arc<dyn Fn() -> Option<Pid> + Send + Sync>,
    ) -> Result<arinsal_sched::TimerRef, String> {
        let Some(handle) = &self.1 else {
            return Err("no native scheduler".into());
        };
        match handle.start_resolved_timer(self.0, ms, resolve, message, wrapped) {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(_) => Err("no native scheduler".into()),
        }
    }
}

/// `erlang:send_after/3,4` and `erlang:start_timer/3,4`.
// Port of erts/emulator/beam/erl_hl_timer.c:1804-1850 (`erts_create_bif_timer`,
// `setup_bif_timer`) and erl_bif_timer.c, OTP-29.1.1.
pub(crate) fn start_timer_bif(
    process: &mut Process,
    sink: &mut dyn TimerSink,
    args: &[Term],
    send_after: bool,
) -> Result<Term, VmError> {
    let (time, target, message) = (args[0], args[1], args[2]);
    let absolute = args
        .get(3)
        .map(|options| timer_start_options(*options))
        .transpose()?
        .unwrap_or(false);
    let time = time.as_small().ok_or_else(|| badarg("timer/3"))?;
    let ms = if absolute {
        let now = arinsal_bifs::monotonic_time_milliseconds();
        (i128::from(time) - now).clamp(0, i128::from(u64::MAX)) as u64
    } else {
        u64::try_from(time).map_err(|_| badarg("timer/3"))?
    };
    let pid = Pid::from_term(target);
    let registered_name = if pid.is_none() {
        Some(target.as_atom().ok_or_else(|| badarg("timer/3"))?)
    } else {
        None
    };
    let rt = process.runtime.ok_or_else(|| badarg("timer/3"))?;
    // A dead pid gets a ref but no timer entry; an unresolved name can become registered
    // before its timer expires.
    let id = process.next_ref();
    let reference = reference(process, id)?;
    // Port of erl_hl_timer.c (setup_bif_timer): the timeout tuple is the timer's queued
    // message, so expiry can enqueue it without receiver-side signal conversion.
    let message = if send_after {
        message
    } else {
        process.tuple(&[Term::atom(arinsal_term::atoms::TIMEOUT), reference, message])?
    };
    let message = Message::copy_from_timer(message, id, process.heap.alloc_ix())?;
    // setup_bif_timer: a timer for a process that does not exist is never created.
    if let Some(pid) = pid
        && !rt
            .scheduler()
            .is_ok_and(|scheduler| scheduler.lookup_from(pid, process.on_managed))
    {
        return Ok(reference);
    }
    let timer = if let Some(pid) = pid {
        sink.schedule_timer(pid, ms, message, false)
    } else {
        let runtime = process.runtime.ok_or_else(|| badarg("timer/3"))?;
        let name = registered_name.expect("resolved timer name");
        sink.schedule_resolved_timer(
            ms,
            message,
            false,
            std::sync::Arc::new(move || runtime.reg.whereis_proc(name)),
        )
    }
    .map_err(|error| VmError::Unsupported(format!("timer: {error}")))?;
    // The timer is on the wheel of the scheduler the reference names and, when aimed at a
    // process, linked to it through that process' bif-timer word (erl_hl_timer.c:1832), so exit
    // cancels it without any table of timers.
    if let Some(pid) = pid
        && !rt
            .scheduler()
            .is_ok_and(|scheduler| scheduler.lookup_from(pid, process.on_managed))
        && let Ok(scheduler) = rt.scheduler()
    {
        // The receiver exited meanwhile; its exit may already have swept its timers.
        scheduler.cancel_timer_async(timer, |_| {});
    }
    Ok(reference)
}

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

#[allow(clippy::too_many_arguments)] // spawn_opt flags stay positional; packing them hides the monitor race.
fn spawn_mfa(
    vm: &mut Vm,
    parent: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    mfa: (Term, Term, Term),
    linked: bool,
    monitored: bool,
    min_heap_size: Option<usize>,
    monitor_tag: Option<arinsal_etf::OwnedTerm>,
    monitor_alias: Option<crate::proc_create::AliasMode>,
    scheduler_id: Option<usize>,
) -> Result<Term, VmError> {
    let mut opts = default_spawn_options(Term::NIL, parent.runtime);
    opts.link = linked;
    opts.monitor = monitored.then_some(SpawnMonitor {
        id: None,
        tag: monitor_tag,
        alias: monitor_alias,
        priority: false,
    });
    opts.min_heap = min_heap_size;
    opts.scheduler = scheduler_id;
    spawn_mfa_with_priority(vm, parent, ctx, mfa, opts)
}

// Port of erts/emulator/beam/erl_process.c (erts_parse_spawn_opts), OTP-29.1.1.
/// Spawn options of `erl_create_process` (erl_process.c:12437, `ErlSpawnOpts`).
pub(crate) struct ErlSpawnOpts {
    pub link: bool,
    pub monitor: Option<SpawnMonitor>,
    pub min_heap: Option<usize>,
    pub min_bin_vheap: Option<usize>,
    pub fullsweep: Option<u16>,
    pub max_heap: Option<crate::process::MaxHeap>,
    pub off_heap_queue: Option<bool>,
    /// `SPO_ASYNC_DIST`: the child starts with the `async_dist` process flag set.
    pub async_dist: bool,
    pub scheduler: Option<usize>,
    pub priority: Priority,
    /// The option list as the caller gave it (`so->opts`), reported by the seq_trace spawn request.
    pub opts: Term,
    /// The spawn_request reply the parent gets (erl_process.c:13146), if one is asked for.
    pub reply: Option<SpawnReply>,
}

/// The spawn_request reply: `{Tag, Ref, ok, Pid}` sent to the parent before the child runs.
pub(crate) struct SpawnReply {
    pub tag: Term,
    pub reference: Term,
}

/// The monitor the parent creates on the child. `id` is preallocated by `spawn_request`;
/// otherwise `erl_create_process` allocates it.
pub(crate) struct SpawnMonitor {
    pub id: Option<u64>,
    pub tag: Option<arinsal_etf::OwnedTerm>,
    pub alias: Option<crate::proc_create::AliasMode>,
    pub priority: bool,
}

/// What `erl_create_process` returns: the child and the monitor it set up, if any.
pub(crate) struct CreatedProcess {
    pub pid: Pid,
    pub monitor: Option<u64>,
}

// Port of erts/emulator/beam/erl_process.c:12437 (erl_create_process), OTP-29.1.1. Every spawn
// variant comes through here: the child starts at erlang:apply/3 with `mod`, `func` and `args`
// in X0..X2, its links and monitors exist before it is inserted, and it is scheduled last.
/// The child `erl_create_process` has built and inserted but not yet queued.
struct UnscheduledChild {
    spawned: arinsal_sched::SpawnedProcess<Message>,
    seq_spawn: Option<crate::seq_trace::Token>,
    arity: usize,
    monitor_id: Option<u64>,
}

/// The argument count of a spawn MFA, or `None` for a bad module, function or argument list.
// Port of erts/emulator/beam/erl_process.c (erl_create_process: erts_list_length), OTP-29.1.1.
fn spawn_arity(mfa: (Term, Term, Term)) -> Option<usize> {
    let (module, function, args) = mfa;
    module.as_atom()?;
    function.as_atom()?;
    list_length(args).filter(|&arity| arity <= 1024)
}

/// `erl_create_process` up to the point where the child is linked and ready to be queued: the
/// part that needs only the parent (`c_p`), shared by the executor path and the light BIF.
// Port of erts/emulator/beam/erl_process.c:12437 (erl_create_process), OTP-29.1.1.
fn create_child(
    parent: &mut Process,
    parent_pid: Pid,
    mfa: (Term, Term, Term),
    arity: usize,
    so: &ErlSpawnOpts,
) -> Result<UnscheduledChild, VmError> {
    let (module, function, args) = mfa;
    let m = module.as_atom().ok_or_else(|| badarg("erlang:spawn/3"))?;
    let f = function.as_atom().ok_or_else(|| badarg("erlang:spawn/3"))?;
    // Port of erts/emulator/beam/erl_process.c (erl_create_process: erts_get_runq), OTP-29.1.1:
    // resolve the parent's run queue once and keep its non-owning runtime borrow through enqueue.
    let runtime = parent
        .runtime
        .ok_or_else(|| VmError::Unsupported("spawn requires a scheduler".into()))?;
    let scheduler = runtime.scheduler()?;
    let defaults = crate::natives::sys::gc_spawn_defaults(Some(runtime));
    // Port of erts/emulator/beam/erl_process.c (erl_create_process: min_heap_size rounded up by
    // erts_next_heap_size), OTP-29.1.1.
    let min_heap =
        crate::natives::sys::normalize_spawn_heap_minimum(Some(runtime), so.min_heap, false);
    // Port of erts/emulator/beam/erl_process.c (erl_create_process), OTP-29.1.1: the initial
    // heap holds the copied arguments and the reserved words, rounded up to a heap size, is
    // never smaller than the process's minimum heap, and is allocated once.
    let literals = arinsal_term::LiteralAreas::current();
    let arg_size = std::cell::Cell::new(0);
    let parent_alloc_ix = parent.heap.alloc_ix();
    // Port of erts/emulator/beam/erl_process.c (erts_parse_spawn_opts), OTP-29.1.1: an
    // explicit min_bin_vheap_size alone takes the runtime default when no other heap option is set.
    let min_bin_vheap =
        if so.min_bin_vheap.is_some() && so.min_heap.is_none() && so.max_heap.is_none() {
            defaults.min_bin_vheap_size as usize
        } else {
            crate::natives::sys::normalize_spawn_heap_minimum(Some(runtime), so.min_bin_vheap, true)
        };
    let group_leader = parent.group_leader_pid(parent_pid);
    let monitor_id = so
        .monitor
        .as_ref()
        .map(|monitor| monitor.id.unwrap_or_else(|| parent.next_ref()));
    // Port of erts/emulator/beam/erl_process.c (erl_create_process), OTP-29.1.1: alloc_process
    // takes the process struct and its table entry first, and the fields are then initialized
    // in place.
    let init_child = |child_pid: Pid, child: &mut Process| -> Result<(), VmError> {
        child.set_runtime_with_min_bin_vheap_size(Some(runtime), min_bin_vheap as u64);
        // Port of erts/emulator/beam/erl_process.c (erl_create_process initializes both
        // active and user priority from so->priority), OTP-29.1.1. The scheduler entry already
        // receives this priority; keep process_info/process_flag's process-side value aligned.
        // A normal priority is the absent flag (process_info reports `normal` for it).
        if so.priority != Priority::Normal {
            crate::natives::proc::set_flag(
                child,
                "priority",
                Term::atom(match so.priority {
                    Priority::Max => arinsal_term::atoms::MAX,
                    Priority::High => arinsal_term::atoms::HIGH,
                    Priority::Normal => arinsal_term::atoms::NORMAL,
                    Priority::Low => arinsal_term::atoms::LOW,
                }),
            );
        }
        let fullsweep_after = so.fullsweep.unwrap_or(defaults.fullsweep_after);
        child.heap.set_fullsweep_after(fullsweep_after);
        // Port of erts/emulator/beam/erl_process.c:12552 (erl_create_process: SPO_ASYNC_DIST
        // sets F_ASYNC_DIST); an unset field already reads as false.
        if so.async_dist {
            child.cold_mut().flags.async_dist = Some(Term::atom(arinsal_term::atoms::TRUE));
        }
        let max_heap = so.max_heap.unwrap_or(defaults.max_heap_size);
        if !crate::natives::proc::is_default_max_heap(max_heap) {
            child.cold_mut().max_heap = max_heap;
        }
        if let Some(off_heap) = so.off_heap_queue {
            child.cold_mut().off_heap_msgq = off_heap;
        }
        // `p->u.initial` is the spawned MFA, reported by process_info(initial_call); `p->i` is
        // the apply/3 entry the child starts at.
        // erl_create_process sets `p->i = beam_run_process`; the child's first run installs it
        // (Executor::run) and applies X0..X2.
        child.initial_mfa = Some((m, f, arity as u8));
        child.group_leader = Some(group_leader);
        child.parent = Some(parent_pid);
        // Port of erts/emulator/beam/erl_process.c (erl_create_process: `args` is
        // copied with copy_struct_litopt and the three arg registers take mod, func and the
        // copy), OTP-29.1.1.
        let copied_args = {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut child.heap);
            // copy_struct_litopt with the size computed above, as erts does.
            arinsal_term::copy_struct_litopt(args, &mut heap, arg_size.get(), &literals)
                .map_err(|error| VmError::Unsupported(format!("spawn arguments: {error:?}")))?
        };
        child.x[0] = module;
        child.x[1] = function;
        child.x[2] = copied_args;
        // The link must be on the child before it becomes schedulable.
        if so.link {
            child
                .links
                .insert(crate::proc_create::process_link(parent_pid, false));
        }
        if let (Some(id), Some(monitor)) = (monitor_id, so.monitor.as_ref()) {
            // Port of erts/emulator/beam/erl_process.c:12932-12942 (erl_create_process):
            // the child has a pid and remains locked while both monitor halves are installed.
            let (origin, target) = crate::proc_create::create_monitor_with_reference_at(
                parent.heap.alloc_ix(),
                crate::proc_create::monitor_reference(id, monitor.alias, monitor.priority),
                parent_pid.data(),
                child_pid.data(),
                crate::proc_create::MonitorInfo::new(monitor.tag.clone(), None),
                crate::proc_create::OriginMonitor::Process(crate::proc_create::OriginHalf),
            );
            parent.monitors.insert(origin);
            child.lt_monitors.insert(target);
            if monitor.priority {
                parent.cold_mut().prio_monitors.insert(id);
            }
        }
        Ok(())
    };
    let spawned = scheduler
        .spawn_unscheduled_try_prepare_init(
            || {
                // erts allocates the Process before sizing the copied argument graph and
                // allocating its initial heap.
                let size = arinsal_term::size_object_litopt(args, &literals);
                arg_size.set(size);
                let heap_need = size.saturating_add(arinsal_term::S_RESERVED);
                arinsal_term::spawned_heap_words(heap_need, min_heap)
                    .map_err(|error| VmError::Unsupported(format!("spawn heap: {error:?}")))
            },
            |heap_words, slot| {
                crate::proc_create::raw::initialize_spawned(
                    slot,
                    3,
                    heap_words,
                    parent_alloc_ix,
                    min_heap,
                )
            },
            init_child,
            so.priority,
            so.scheduler,
            parent_alloc_ix,
        )
        .map_err(|error| match error {
            arinsal_sched::SpawnInitError::Init(error) => error,
            arinsal_sched::SpawnInitError::Table(error) => {
                VmError::Unsupported(format!("spawn: {error}"))
            }
        })?;
    let seq_spawn = if crate::seq_trace::has_token(parent) {
        spawned
            .with_task(|child: &mut Process| {
                crate::seq_trace::spawn_prepare(parent, parent_pid, child)
            })
            .flatten()
    } else {
        None
    };
    let pid = spawned.pid();
    if so.link {
        parent
            .links
            .insert(crate::proc_create::process_link(pid, false));
    }
    Ok(UnscheduledChild {
        spawned,
        seq_spawn,
        arity,
        monitor_id,
    })
}

// Port of erts/emulator/beam/erl_process.c:12437 (erl_create_process), OTP-29.1.1. Every spawn
// variant comes through here: the child starts at erlang:apply/3 with `mod`, `func` and `args`
// in X0..X2, its links and monitors exist before it is inserted, and it is scheduled last.
pub(crate) fn erl_create_process(
    vm: &mut Vm,
    parent: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    mfa: (Term, Term, Term),
    so: ErlSpawnOpts,
) -> Result<CreatedProcess, VmError> {
    let (module, function, args) = mfa;
    let parent_pid = ctx.pid();
    let arity = spawn_arity(mfa).ok_or_else(|| badarg("erlang:spawn/3"))?;
    let UnscheduledChild {
        spawned,
        seq_spawn,
        arity,
        monitor_id,
    } = create_child(parent, parent_pid, mfa, arity, &so)?;
    let scheduler = parent
        .runtime
        .ok_or_else(|| VmError::Unsupported("spawn requires a scheduler".into()))?
        .scheduler()?;
    let pid = spawned.pid();
    if crate::trace::spawn_interested(parent, parent_pid) {
        let arg_list = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut parent.heap))
            .list_from_iter(list(args).unwrap_or_default())
            .map_err(|error| VmError::Unsupported(format!("spawn trace args: {error:?}")))?;
        let mfa = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut parent.heap))
            .tuple(&[module, function, arg_list])
            .map_err(|error| VmError::Unsupported(format!("spawn trace MFA: {error:?}")))?;
        crate::trace::spawned(vm, parent, ctx, pid, mfa, so.link);
    }
    let mut seq_reply_token = None;
    if let Some(request) = seq_spawn.as_ref()
        && let Some(child_term) = pid.to_term()
        && let Some(parent_term) = parent_pid.to_term()
    {
        let owned = |term: Term| {
            arinsal_term::to_owned(term)
                .unwrap_or_else(|_| arinsal_etf::OwnedTerm::atom("undefined"))
        };
        let (tag, reference) = match so.reply.as_ref() {
            Some(reply) => (reply.tag, reply.reference),
            None => (
                Term::atom(arinsal_term::atoms::SPAWN_REPLY),
                crate::signals::reference(parent, arinsal_bifs::next_ref_id())?,
            ),
        };
        let arity = Term::small(arity as i64).unwrap_or(Term::NIL);
        let group_leader = child_group_leader_term(parent, ctx.pid());
        let request_message = arinsal_etf::OwnedTerm::tuple(vec![
            arinsal_etf::OwnedTerm::atom("spawn_request"),
            owned(reference),
            owned(parent_term),
            owned(group_leader),
            arinsal_etf::OwnedTerm::tuple(vec![owned(module), owned(function), owned(arity)]),
            owned(so.opts),
            owned(tag),
            owned(args),
        ]);
        let reply_message = arinsal_etf::OwnedTerm::tuple(vec![
            owned(tag),
            owned(reference),
            arinsal_etf::OwnedTerm::atom("ok"),
            owned(child_term),
        ]);
        seq_reply_token = Some(crate::seq_trace::spawn_events(
            vm,
            parent,
            ctx,
            request,
            pid,
            (request_message, reply_message),
            so.reply.is_none(),
        ));
    }
    if let Some(reply) = so.reply {
        // Port of erts/emulator/beam/erl_process.c:13146 (erts_send_local_spawn_reply), OTP-29.1.1:
        // the reply is queued from the child before the child can run, so the parent sees it
        // ahead of anything the child sends.
        let pid_term = pid
            .to_term()
            .ok_or_else(|| VmError::Unsupported("pid limit".into()))?;
        let message = {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut parent.heap);
            TermBuilder::new(&mut heap)
                .tuple(&[
                    reply.tag,
                    reply.reference,
                    Term::atom(arinsal_term::atoms::OK),
                    pid_term,
                ])
                .map_err(|error| VmError::Unsupported(format!("spawn reply: {error:?}")))?
        };
        let mut envelope = Message::copy_from(message)?;
        if let Some(token) = seq_reply_token.take() {
            envelope.attach_seq_token(Box::new(token));
        }
        scheduler
            .send(pid, parent_pid, envelope)
            .map_err(|error| VmError::Unsupported(format!("spawn_reply: {error}")))?;
    }
    ctx.schedule_spawned(spawned)
        .map_err(|error| VmError::Unsupported(format!("schedule spawn: {error}")))?;
    Ok(CreatedProcess {
        pid,
        monitor: monitor_id,
    })
}

/// The group leader the child inherits, as a term.
fn child_group_leader_term(parent: &Process, fallback: Pid) -> Term {
    parent
        .group_leader_pid(fallback)
        .to_term()
        .unwrap_or(Term::NIL)
}

#[allow(clippy::too_many_arguments)] // spawn_opt flags stay positional; the BIF callers pass them so.
fn spawn_mfa_with_priority(
    vm: &mut Vm,
    parent: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    mfa: (Term, Term, Term),
    opts: ErlSpawnOpts,
) -> Result<Term, VmError> {
    let alias_mode = opts.monitor.as_ref().and_then(|monitor| monitor.alias);
    let created = erl_create_process(vm, parent, ctx, mfa, opts)?;
    let pid_term = created
        .pid
        .to_term()
        .ok_or_else(|| VmError::Unsupported("pid limit".into()))?;
    let Some(id) = created.monitor else {
        return Ok(pid_term);
    };
    let ref_term = if alias_mode.is_some() {
        pid_reference(parent, id, ctx.pid())?
    } else {
        reference(parent, id)?
    };
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut parent.heap);
    TermBuilder::new(&mut heap)
        .tuple(&[pid_term, ref_term])
        .map_err(|error| VmError::Unsupported(format!("spawn result: {error:?}")))
}

/// `spawn_opt/4` called directly from native code (erts `spawn_opt_4` with `c_p`). Only the
/// untraced local case takes this path: tracing, seq_trace, a bad MFA or option list, and a
/// thread that is not a normal scheduler return `None` before any state changes, and the
/// executor runs the full BIF.
// Port of erts/emulator/beam/bif.c:1027 (spawn_opt_4) and erl_process.c:12437
// (erl_create_process), OTP-29.1.1: the child joins the calling scheduler's run queue.
pub(crate) fn spawn_opt_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [module, function, mfa_args, options] = args else {
        return None;
    };
    let mfa = (*module, *function, *mfa_args);
    let arity = light_spawn_arity(process, mfa)?;
    let opts = spawn_options(process.runtime, *options).ok()?;
    Some(spawn_light(process, mfa, arity, opts))
}

/// `spawn/3` called directly from native code (erts `spawn_3`).
// Port of erts/emulator/beam/bif.c (spawn_3), OTP-29.1.1.
pub(crate) fn spawn_light3(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    spawn_light_default(process, args, false)
}

/// `spawn_link/3` called directly from native code (erts `spawn_link_3`).
// Port of erts/emulator/beam/bif.c (spawn_link_3), OTP-29.1.1.
pub(crate) fn spawn_link_light3(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    spawn_light_default(process, args, true)
}

fn spawn_light_default(
    process: &mut Process,
    args: &[Term],
    link: bool,
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [module, function, mfa_args] = args else {
        return None;
    };
    let mfa = (*module, *function, *mfa_args);
    let arity = light_spawn_arity(process, mfa)?;
    let so = ErlSpawnOpts {
        async_dist: crate::natives::sys::gc_defaults(process.runtime).async_dist(),
        link,
        monitor: None,
        min_heap: None,
        min_bin_vheap: None,
        fullsweep: None,
        max_heap: None,
        off_heap_queue: None,
        scheduler: None,
        priority: Priority::Normal,
        opts: Term::NIL,
        reply: None,
    };
    Some(spawn_light(process, mfa, arity, so))
}

/// The argument count when the light spawn path applies: tracing and seq_trace off, a normal
/// scheduler thread, and a well-formed MFA. Otherwise `None`, with no state touched.
fn light_spawn_arity(process: &Process, mfa: (Term, Term, Term)) -> Option<usize> {
    if crate::trace::active()
        || crate::trace::new_processes_traced()
        || crate::seq_trace::has_token(process)
        || !process.on_managed
    {
        return None;
    }
    process.self_pid?;
    spawn_arity(mfa)
}

/// Create the child and queue it on the calling scheduler, returning `Pid` or `{Pid, Ref}`.
fn spawn_light(
    process: &mut Process,
    mfa: (Term, Term, Term),
    arity: usize,
    so: ErlSpawnOpts,
) -> Result<Term, crate::exceptions::Trap> {
    let Some(parent_pid) = process.self_pid else {
        return Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )));
    };
    let failure = |error: VmError| match error {
        VmError::Trap(trap) => trap,
        _ => crate::exceptions::Trap::error(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT)),
    };
    let child = create_child(process, parent_pid, mfa, arity, &so).map_err(failure)?;
    let pid = child.spawned.pid();
    // erl_create_process: add2runq on the calling scheduler. Off a normal scheduler thread
    // the child goes through the shared queue instead.
    let queued = match match process.native_handle() {
        Some(handle) => handle.schedule_spawned(child.spawned),
        None => Err(child.spawned),
    } {
        Ok(queued) => queued,
        Err(spawned) => match process.runtime.map(Runtime::scheduler) {
            Some(Ok(scheduler)) => scheduler.schedule_unscheduled(spawned.pid()),
            _ => Err(arinsal_sched::Error::NoProcess),
        },
    };
    if queued.is_err() {
        return Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )));
    }
    let Some(pid_term) = pid.to_term() else {
        return Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )));
    };
    let Some(id) = child.monitor_id else {
        return Ok(pid_term);
    };
    let ref_term = if so
        .monitor
        .as_ref()
        .is_some_and(|monitor| monitor.alias.is_some())
    {
        pid_reference(process, id, parent_pid)
    } else {
        reference(process, id)
    };
    let result = ref_term.and_then(|ref_term| {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        TermBuilder::new(&mut heap)
            .tuple(&[pid_term, ref_term])
            .map_err(|error| VmError::Unsupported(format!("spawn result: {error:?}")))
    });
    result.map_err(failure)
}

// Port of erts/emulator/beam/erl_process.c:12222 (`erts_parse_spawn_opts`), OTP-29.1.1.
/// Defaults that `erts_parse_spawn_opts` establishes before walking an option list.
fn default_spawn_options(options: Term, runtime: Option<&Runtime>) -> ErlSpawnOpts {
    ErlSpawnOpts {
        async_dist: crate::natives::sys::gc_defaults(runtime).async_dist(),
        link: false,
        monitor: None,
        min_heap: None,
        min_bin_vheap: None,
        fullsweep: None,
        max_heap: None,
        off_heap_queue: None,
        scheduler: None,
        priority: Priority::Normal,
        opts: options,
        reply: None,
    }
}

// Port of erts/emulator/beam/erl_process.c (erts_parse_spawn_opts), OTP-29.1.1.
/// The atom `link`, interned once (erts `am_link`).
fn link_atom() -> Term {
    static LINK: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    *LINK.get_or_init(|| Term::atom(arinsal_term::atoms::LINK))
}

/// One `spawn_opt` option into `opts`.
fn parse_spawn_option(
    runtime: Option<&Runtime>,
    opts: &mut ErlSpawnOpts,
    option: Term,
) -> Result<(), VmError> {
    if option == link_atom() {
        opts.link = true;
    } else if option == Term::atom(arinsal_term::atoms::MONITOR) {
        opts.monitor.get_or_insert(SpawnMonitor {
            id: None,
            tag: None,
            alias: None,
            priority: false,
        });
    } else if option.classify() == TermKind::Tuple {
        // SAFETY: The option term remains in the caller's live heap.
        let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("erlang:spawn_opt"))?;
        if tuple.len() == 2 && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::MIN_HEAP_SIZE))
        {
            let words = tuple
                .get(1)
                .and_then(Term::as_small)
                .filter(|&words| words >= 0)
                .ok_or_else(|| badarg("erlang:spawn_opt"))?;
            opts.min_heap = Some(words as usize);
        } else if tuple.len() == 2 && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::MONITOR))
        {
            // code_server:spawn_opt(Fun, [{monitor, [{tag, {'ON_LOAD_DOWN', Mod}}]}]).
            // Port of erl_process.c spawn option `{monitor, MonitorOpts}`, OTP-29.1.1.
            let monitor = opts.monitor.get_or_insert(SpawnMonitor {
                id: None,
                tag: None,
                alias: None,
                priority: false,
            });
            let items = list(tuple.get(1).ok_or_else(|| badarg("erlang:spawn_opt"))?)
                .ok_or_else(|| badarg("erlang:spawn_opt"))?;
            for item in items {
                // SAFETY: Each option stays rooted in the caller's heap.
                let item = unsafe { item.tuple_ref() }.ok_or_else(|| badarg("erlang:spawn_opt"))?;
                if item.len() != 2 {
                    return Err(badarg("erlang:spawn_opt"));
                }
                match (item.get(0), item.get(1)) {
                    (Some(key), Some(value)) if key == Term::atom(arinsal_term::atoms::TAG) => {
                        monitor.tag = Some(arinsal_term::to_owned(value).map_err(|error| {
                            VmError::Unsupported(format!("monitor tag: {error:?}"))
                        })?);
                    }
                    (Some(key), Some(value)) if key == Term::atom(arinsal_term::atoms::ALIAS) => {
                        monitor.alias = Some(
                            parse_alias_mode(value).ok_or_else(|| badarg("erlang:spawn_opt"))?,
                        );
                    }
                    _ => return Err(badarg("erlang:spawn_opt")),
                }
            }
        } else if tuple.len() == 2
            && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::PRIORITY))
        {
            opts.priority = match atom_name(tuple.get(1).ok_or_else(|| badarg("erlang:spawn_opt"))?)
                .as_deref()
            {
                Some("low") => Priority::Low,
                Some("normal") => Priority::Normal,
                Some("high") => Priority::High,
                Some("max") => Priority::Max,
                _ => return Err(badarg("erlang:spawn_opt")),
            };
        } else if tuple.len() == 2
            && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::MAX_HEAP_SIZE))
        {
            opts.max_heap = Some(
                crate::natives::proc::parse_max_heap_from(
                    tuple.get(1).ok_or_else(|| badarg("erlang:spawn_opt"))?,
                    crate::natives::sys::gc_spawn_defaults(runtime).max_heap_size,
                )
                .map_err(|()| badarg("erlang:spawn_opt"))?,
            );
        } else if tuple.len() == 2
            && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::FULLSWEEP_AFTER))
        {
            let value = tuple
                .get(1)
                .and_then(Term::as_small)
                .filter(|&value| value >= 0)
                .ok_or_else(|| badarg("erlang:spawn_opt"))?;
            opts.fullsweep = Some(value.min(i64::from(u16::MAX)) as u16);
        } else if tuple.len() == 2
            && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::MIN_BIN_VHEAP_SIZE))
        {
            let value = tuple
                .get(1)
                .and_then(Term::as_small)
                .filter(|&value| value >= 0)
                .ok_or_else(|| badarg("erlang:spawn_opt"))?;
            opts.min_bin_vheap = Some(value as usize);
        } else if tuple.len() == 2
            && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::MESSAGE_QUEUE_DATA))
        {
            match tuple.get(1) {
                Some(value) if value == Term::atom(arinsal_term::atoms::OFF_HEAP) => {
                    opts.off_heap_queue = Some(true);
                }
                Some(value) if value == Term::atom(arinsal_term::atoms::ON_HEAP) => {
                    opts.off_heap_queue = Some(false);
                }
                _ => return Err(badarg("erlang:spawn_opt")),
            }
        } else if tuple.len() == 2
            && tuple
                .get(0)
                .and_then(atom_name)
                .is_some_and(|name| matches!(name.as_str(), "async_dist"))
        {
            // Port of erts/emulator/beam/erl_process.c:12289 (erts_parse_spawn_opts, async_dist).
            opts.async_dist = match tuple.get(1) {
                Some(value) if value == Term::atom(arinsal_term::atoms::TRUE) => true,
                Some(value) if value == Term::atom(arinsal_term::atoms::FALSE) => false,
                _ => return Err(badarg("erlang:spawn_opt")),
            };
        } else if tuple.len() == 2
            && tuple.get(0) == Some(Term::atom(arinsal_term::atoms::SCHEDULER))
        {
            let scheduler_count = runtime
                .and_then(|runtime| runtime.scheduler().ok())
                .map_or(0, |scheduler| scheduler.scheduler_count());
            let scheduler = tuple
                .get(1)
                .and_then(Term::as_small)
                .filter(|&scheduler| scheduler >= 0 && scheduler as usize <= scheduler_count)
                .ok_or_else(|| badarg("erlang:spawn_opt"))?;
            // Port of erts/emulator/beam/erl_process.c:12361 (erts_parse_spawn_opts): 0 means unbound.
            opts.scheduler = (scheduler != 0).then_some(scheduler as usize);
        } else {
            return Err(badarg("erlang:spawn_opt"));
        }
    } else {
        return Err(badarg("erlang:spawn_opt"));
    }
    Ok(())
}

fn spawn_options(runtime: Option<&Runtime>, term: Term) -> Result<ErlSpawnOpts, VmError> {
    let mut opts = default_spawn_options(term, runtime);
    // Port of erts/emulator/beam/erl_process.c (erts_parse_spawn_opts), OTP-29.1.1: the option
    // list is walked in place and each option compared with its atom.
    let mut failure = None;
    let proper = each_list_item(term, |option| {
        if failure.is_none()
            && let Err(error) = parse_spawn_option(runtime, &mut opts, option)
        {
            failure = Some(error);
        }
    });
    if proper.is_none() {
        return Err(badarg("erlang:spawn_opt"));
    }
    if let Some(error) = failure {
        return Err(error);
    }
    // The child keeps the system default virtual binary heap minimum unless `min_heap_size` or
    // `max_heap_size` is also given (verified against `erl` 29.1.1).
    if opts.min_heap.is_none() && opts.max_heap.is_none() {
        opts.min_bin_vheap = None;
    }
    let min_heap = crate::natives::sys::normalize_spawn_heap_minimum(runtime, opts.min_heap, false);
    if opts
        .max_heap
        .is_some_and(|limit| limit.size != 0 && limit.size < min_heap as u64)
    {
        return Err(badarg("erlang:spawn_opt"));
    }
    Ok(opts)
}

fn timer_start_options(term: Term) -> Result<bool, VmError> {
    let mut absolute = false;
    for option in list(term).ok_or_else(|| badarg("timer options"))? {
        // SAFETY: The option term remains in the caller's live heap.
        let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("timer options"))?;
        if tuple.len() != 2 || tuple.get(0) != Some(Term::atom(arinsal_term::atoms::ABS)) {
            return Err(badarg("timer options"));
        }
        match tuple.get(1) {
            Some(value) if value == Term::atom(arinsal_term::atoms::FALSE) => {}
            Some(value) if value == Term::atom(arinsal_term::atoms::TRUE) => absolute = true,
            _ => return Err(badarg("timer options")),
        }
    }
    Ok(absolute)
}

#[derive(Clone, Copy)]
pub(crate) struct TimerQueryOptions {
    pub(crate) asynchronous: bool,
    pub(crate) info: bool,
}

pub(crate) fn timer_query_options(term: Term, cancel: bool) -> Result<TimerQueryOptions, VmError> {
    let mut asynchronous = false;
    let mut info = true;
    for option in list(term).ok_or_else(|| badarg("timer options"))? {
        // SAFETY: The option term remains in the caller's live heap.
        let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("timer options"))?;
        if tuple.len() != 2 {
            return Err(badarg("timer options"));
        }
        match (tuple.get(0), tuple.get(1)) {
            (Some(name), Some(value))
                if name == Term::atom(arinsal_term::atoms::ASYNC)
                    && value == Term::atom(arinsal_term::atoms::FALSE) =>
            {
                asynchronous = false;
            }
            (Some(name), Some(value))
                if name == Term::atom(arinsal_term::atoms::ASYNC)
                    && value == Term::atom(arinsal_term::atoms::TRUE) =>
            {
                asynchronous = true;
            }
            (Some(name), Some(value))
                if cancel && name == Term::atom(arinsal_term::atoms::INFO) =>
            {
                if value == Term::atom(arinsal_term::atoms::FALSE) {
                    info = false;
                } else if value == Term::atom(arinsal_term::atoms::TRUE) {
                    info = true;
                } else {
                    return Err(badarg("timer options"));
                }
            }
            _ => return Err(badarg("timer options")),
        }
    }
    Ok(TimerQueryOptions { asynchronous, info })
}

// Port of erts/emulator/beam/erl_hl_timer.c:2222 (no_timer_result), OTP-29.1.1.
/// Where the answer of a synchronous timer access goes.
enum TimerAccess {
    /// The owning scheduler has not answered yet and the caller is still in the BIF.
    Pending,
    /// Answered before the caller parked.
    Done(Option<u64>),
    /// The caller parked on `{Ref, Result}`; the owner sends it.
    Parked {
        target: Pid,
        reply: OwnedTerm,
        info: bool,
        scheduler: std::sync::Arc<arinsal_sched::Scheduler<Process>>,
    },
}

/// Synchronous `cancel_timer/1,2` (`cancel`) and `read_timer/1,2`: the timer's answer, or the
/// reply wait when another scheduler's wheel owns it.
// Port of erts/emulator/beam/erl_hl_timer.c:2083-2200 (bif_timer_access_request,
// erts_cancel_bif_timer / erts_read_bif_timer), OTP-29.1.1.
pub(crate) fn timer_query_sync(
    process: &mut Process,
    caller: Pid,
    reference: Term,
    cancel: bool,
    info: bool,
    request: bool,
) -> Result<Term, VmError> {
    let id = ref_id(reference).ok_or_else(|| {
        badarg(if cancel {
            "cancel_timer/1"
        } else {
            "read_timer/1"
        })
    })?;
    let rt = runtime(process)?;
    let timer = rt
        .scheduler()
        .ok()
        .map(|scheduler| scheduler.timer_for_ref_key(id));
    access_timer_sync(process, caller, reference, timer, cancel, info, request)
}

/// Synchronous `cancel_timer`/`read_timer`.
///
/// Port of erts/emulator/beam/erl_hl_timer.c:2237 (access_bif_timer), OTP-29.1.1: the
/// scheduler owning the timer answers directly; otherwise the request is scheduled on
/// the owner and the caller waits for `{Ref, Result}` like `erts_await_result`, so no
/// scheduler thread ever blocks on another one.
fn access_timer_sync(
    process: &mut Process,
    caller: Pid,
    timer_reference: Term,
    timer: Option<arinsal_sched::TimerRef>,
    cancel: bool,
    info: bool,
    request: bool,
) -> Result<Term, VmError> {
    let rt = runtime(process)?;
    let (Some(timer), Ok(scheduler)) = (timer, rt.scheduler()) else {
        return Ok(Term::atom(if info {
            arinsal_term::atoms::FALSE
        } else {
            arinsal_term::atoms::OK
        }));
    };
    // The owning scheduler answers directly, without a request or a reply.
    if let Some(remaining) = scheduler.try_access_timer_local(timer, cancel) {
        let value = remaining
            .and_then(|ms| Term::small(ms as i64))
            .unwrap_or_else(|| Term::atom(arinsal_term::atoms::FALSE));
        return Ok(if info {
            value
        } else {
            Term::atom(arinsal_term::atoms::OK)
        });
    }
    // The light-BIF fragment sends no request: it hands the call to the executor, which would
    // otherwise find the timer already cancelled by the first attempt.
    if !request {
        return Err(VmError::Yield);
    }
    // Slow path: the parked reply keeps the scheduler while `process` is mutated.
    let scheduler = std::sync::Arc::clone(scheduler);
    let state = std::sync::Arc::new(Mutex::new(TimerAccess::Pending));
    let answer = std::sync::Arc::clone(&state);
    let callback = move |remaining: Option<u64>| {
        let mut state = answer.lock().unwrap();
        let TimerAccess::Parked {
            target,
            reply,
            info,
            scheduler,
        } = std::mem::replace(&mut *state, TimerAccess::Done(remaining))
        else {
            return;
        };
        let value = if !info {
            OwnedTerm::atom("ok")
        } else {
            remaining.map_or_else(
                || OwnedTerm::atom("false"),
                |ms| match i64::try_from(ms) {
                    Ok(value) => OwnedTerm::Int(value),
                    Err(_) => OwnedTerm::BigInt(num_bigint::BigInt::from(ms)),
                },
            )
        };
        if let Ok(message) = Message::from_owned(&OwnedTerm::Tuple(vec![reply, value])) {
            let _ = scheduler.send(target, target, message);
        }
    };
    if cancel {
        scheduler.cancel_timer_async(timer, callback);
    } else {
        scheduler.read_timer_async(timer, callback);
    }
    let mut guard = state.lock().unwrap();
    if let TimerAccess::Done(remaining) = *guard {
        let value = remaining
            .and_then(|ms| Term::small(ms as i64))
            .unwrap_or_else(|| Term::atom(arinsal_term::atoms::FALSE));
        return Ok(if info {
            value
        } else {
            Term::atom(arinsal_term::atoms::OK)
        });
    }
    let id = process.next_ref();
    // The reply reference shares node and creation with the (local) timer reference.
    // Nothing is allocated on the caller's heap: the BIF is retried once the reply is in.
    let reply = match to_owned(timer_reference) {
        Ok(OwnedTerm::Ref {
            ref node, creation, ..
        }) => OwnedTerm::Ref {
            node: node.clone(),
            creation,
            ids: arinsal_bifs::ordinary_ref_words(id).to_vec(),
        },
        _ => return Err(badarg("timer reference")),
    };
    // Port of erts/emulator/beam/erl_hl_timer.c:2290 (ERTS_BIF_PREP_TRAP1(erts_await_result,
    // rref)), OTP-29.1.1: the caller continues in erts_internal:await_result/1.
    let rref = reference(process, id)?;
    *guard = TimerAccess::Parked {
        target: caller,
        reply,
        info,
        scheduler,
    };
    drop(guard);
    Err(VmError::TrapExport(crate::ExportTrap::new(
        process,
        "erts_internal:await_result/1",
        vec![rref],
    )))
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
    let result = ctx.handle_dirty_signals(pid, &mut |task, target_ctx| {
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
    if to == ctx.pid() {
        process.inbox.push_back(message);
        return Ok(());
    }
    if !crate::natives::proc::live(process, to)? {
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
    let mut req_id = tuple.get(1).ok_or_else(|| badarg("request_system_task"))?;
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
            if alive && target_pid == ctx.pid() {
                let mut rooted = [req_id];
                crate::natives::proc::collect_heap(process, major, &mut rooted)?;
                req_id = rooted[0];
                let message = task_tuple(
                    process,
                    &[
                        Term::atom(arinsal_term::atoms::GARBAGE_COLLECT),
                        req_id,
                        Term::atom(arinsal_term::atoms::TRUE),
                    ],
                )?;
                deliver(process, ctx, requester, message)?;
                return Ok(Term::atom(arinsal_term::atoms::OK));
            }
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
    ("erlang", "self", 0),
    ("erlang", "!", 2),
    ("erlang", "send", 2),
    ("erlang", "send", 3),
    ("erlang", "spawn", 3),
    ("erlang", "spawn_link", 3),
    ("erlang", "spawn_opt", 4),
    ("erlang", "is_process_alive", 1),
    ("erlang", "register", 2),
    ("erlang", "unregister", 1),
    ("erlang", "whereis", 1),
    ("erlang", "registered", 0),
    ("erlang", "link", 1),
    ("erlang", "link", 2),
    ("erlang", "unlink", 1),
    ("erlang", "monitor", 2),
    ("erlang", "monitor", 3),
    ("erlang", "demonitor", 1),
    ("erlang", "demonitor", 2),
    ("erlang", "exit", 2),
    ("erlang", "exit", 3),
    ("erlang", "exit_signal", 2),
    ("erlang", "exit_signal", 3),
    ("erlang", "trace_delivered", 1),
    ("erlang", "send_after", 3),
    ("erlang", "send_after", 4),
    ("erlang", "start_timer", 3),
    ("erlang", "start_timer", 4),
    ("erlang", "cancel_timer", 1),
    ("erlang", "cancel_timer", 2),
    ("erlang", "read_timer", 1),
    ("erlang", "read_timer", 2),
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

/// Direct load-time entry for `self/0`.
pub(crate) fn native_self(
    _vm: &mut Vm,
    _process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    ctx.pid().to_term().ok_or_else(|| badarg("self/0"))
}

/// Direct load-time entry for `send/2`.
pub(crate) fn native_send(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    process.send_message_in(vm, ctx, args[0], args[1])
}

/// Direct load-time entry for `send/3`.
pub(crate) fn native_send3(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    crate::dist::native_send3(vm, process, ctx, args)
}

/// Direct load-time entry for `is_process_alive/1`.
pub(crate) fn native_is_process_alive(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    is_process_alive(process, ctx, args[0])
}

#[derive(Clone, Copy)]
enum SignalBif {
    Spawn3,
    SpawnLink3,
    SpawnOpt4,
    Register2,
    Unregister1,
    Whereis1,
    Registered0,
    Link1,
    Link2,
    Unlink1,
    Monitor2,
    Monitor3,
    Demonitor1,
    Demonitor2,
    Exit2,
    Exit3,
    ExitSignal2,
    ExitSignal3,
    TraceDelivered1,
    SendAfter3,
    SendAfter4,
    StartTimer3,
    StartTimer4,
    CancelTimer1,
    CancelTimer2,
    ReadTimer1,
    ReadTimer2,
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

/// The local arms of `monitor/2,3` (bif.c `monitor`): a local pid, a local name, a port, the
/// time offset. The distributed arm is `dist::native_monitor`'s.
pub(crate) fn monitor_local(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let entry = if args.len() == 3 {
        SignalBif::Monitor3
    } else {
        SignalBif::Monitor2
    };
    call_resolved(vm, process, ctx, entry, args)
}

/// The local arms of `demonitor/1,2` (bif.c `demonitor`); a distributed origin is
/// `dist::native_demonitor`'s.
pub(crate) fn demonitor_local(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    let entry = if args.len() == 2 {
        SignalBif::Demonitor2
    } else {
        SignalBif::Demonitor1
    };
    call_resolved(vm, process, ctx, entry, args)
}

resolved_signal_handler!(spawn3, Spawn3);
resolved_signal_handler!(spawn_link3, SpawnLink3);
resolved_signal_handler!(spawn_opt4, SpawnOpt4);
/// `register(Name, Pid)` called directly from native code (erts `register_2` with `c_p`).
/// Only the success path runs here: tracing, ports, and every error return `None` before the
/// registry is touched, and the executor then runs the full BIF.
// Port of erts/emulator/beam/register.c:184-240 (erts_register_name), OTP-29.1.1.
pub(crate) fn register_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [name, id] = args else {
        return None;
    };
    if crate::trace::active() {
        return None;
    }
    let name = name.as_atom()?;
    if name == arinsal_term::atoms::UNDEFINED {
        return None;
    }
    let pid = Pid::from_term(*id)?;
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    let scheduler = rt_ref(process)?.scheduler().ok()?;
    let mut table = rt_ref(process)?.reg.write();
    if !scheduler.lookup(pid)
        || scheduler.registered_atom_index(pid).is_some()
        || table.contains(name)
        || !rt_ref(process)?.publish_proc_flag(pid, arinsal_sched::proc_flags::REG)
    {
        return None;
    }
    table.insert_proc(name, pid);
    scheduler.set_registered_atom_index(pid, name.0);
    drop(table);
    Some(Ok(Term::atom(arinsal_term::atoms::TRUE)))
}

/// `unregister(Name)` called directly from native code: a registered process name, with
/// tracing off. Everything else returns `None` before the registry changes.
// Port of erts/emulator/beam/register.c:507-519 (erts_unregister_name), OTP-29.1.1.
pub(crate) fn unregister_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [name] = args else {
        return None;
    };
    if crate::trace::active() {
        return None;
    }
    let name = name.as_atom()?;
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    let mut table = rt_ref(process)?.reg.write();
    let Some(crate::register::RegId::Proc(pid)) = table.fetch(name) else {
        return None;
    };
    let _ = table.erase(name);
    if let Ok(scheduler) = rt_ref(process)?.scheduler() {
        scheduler.clear_registered_atom_index(pid, name.0);
    }
    drop(table);
    Some(Ok(Term::atom(arinsal_term::atoms::TRUE)))
}

/// `monitor(process, Pid)` called directly from native code (erts `monitor_2`, bif.c:782-784
/// and the local arm of erts_proc_sig_send_monitor). Only a live local pid with the default
/// options takes this path; everything else returns `None` before any state changes.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:1090-1150 (erts_proc_sig_send_monitor),
// OTP-29.1.1: the monitor is sent through the scheduler's held-monitor slot.
pub(crate) fn monitor_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    // `monitor/3` with `{alias, Mode}` is what `gen:call` and every `gen_server:call` with a
    // timeout issue; a custom tag or `priority` takes the executor.
    let (kind, target, alias_mode) = match args {
        [kind, target] => (*kind, *target, None),
        [kind, target, _] => {
            let (tag, alias_mode, priority) = monitor_options(args).ok()?;
            if tag != Term::atom(arinsal_term::atoms::DOWN) || priority {
                return None;
            }
            (*kind, *target, alias_mode)
        }
        _ => return None,
    };
    if crate::trace::active() {
        return None;
    }
    let me = process.self_pid?;
    if kind == Term::atom(arinsal_term::atoms::PORT) {
        // Only the default tag takes this path; a custom tag or `priority` is the executor's.
        let (tag, alias_mode, priority) = match args {
            [_, _] => (Term::atom(arinsal_term::atoms::DOWN), None, false),
            _ => monitor_options(args).ok()?,
        };
        if tag != Term::atom(arinsal_term::atoms::DOWN) || priority {
            return None;
        }
        return Some(match monitor_port(process, me, target, tag, alias_mode) {
            Ok(term) => Ok(term),
            Err(VmError::Trap(trap)) => Err(trap),
            Err(_) => Err(crate::exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            ))),
        });
    }
    if kind != Term::atom(arinsal_term::atoms::PROCESS) {
        return None;
    }
    let pid = Pid::from_term(target)?;
    if pid == me {
        return None;
    }
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    if !rt_ref(process)?
        .scheduler()
        .ok()?
        .lookup_from(pid, process.on_managed)
    {
        return None;
    }
    let id = process.next_ref();
    let ref_term = if alias_mode.is_some() {
        pid_reference(process, id, me).ok()?
    } else {
        reference(process, id).ok()?
    };
    // Port of erts/emulator/beam/bif.c (monitor_2, ERTS_MON_TYPE_PROC): one
    // `erts_monitor_create` for both halves; the origin goes into the tree, the target half is
    // the monitor signal.
    let (origin, target) = crate::proc_create::create_monitor_with_reference_at(
        process.heap.alloc_ix(),
        crate::proc_create::monitor_reference(id, alias_mode, false),
        me.data(),
        pid.data(),
        crate::proc_create::MonitorInfo::default(),
        crate::proc_create::OriginMonitor::Process(crate::proc_create::OriginHalf),
    );
    process.monitors.insert(origin);
    if rt_ref(process)?
        .scheduler()
        .ok()?
        .signal_ordered_from(
            me,
            pid,
            arinsal_sched::Signal::Monitor {
                reference: id,
                shared: target.into_shared(),
            },
            process.on_managed,
        )
        .is_err()
    {
        process.monitors.remove(id);
        return None;
    }
    Some(Ok(ref_term))
}

/// `alias/1` called directly from native code. An unknown option takes the executor, which raises
/// `badarg`.
// Port of erts/emulator/beam/bif.c (alias_1), OTP-29.1.1.
pub(crate) fn alias_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [options] = args else {
        return None;
    };
    let (explicit_unalias, reply, priority_atom) = (
        Term::atom(arinsal_term::atoms::EXPLICIT_UNALIAS),
        Term::atom(arinsal_term::atoms::REPLY),
        Term::atom(arinsal_term::atoms::PRIORITY),
    );
    let (mut mode, mut priority) = (crate::proc_create::AliasMode::ExplicitUnalias, false);
    let mut bad = false;
    each_list_item(*options, |option| {
        if option == reply {
            mode = crate::proc_create::AliasMode::ReplyDemonitor;
        } else if option == priority_atom {
            priority = true;
        } else if option == explicit_unalias {
            mode = crate::proc_create::AliasMode::ExplicitUnalias;
        } else {
            bad = true;
        }
    })?;
    if bad {
        return None;
    }
    let me = process.self_pid?;
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    let id = process.next_ref();
    let reference = pid_reference(process, id, me).ok()?;
    process
        .monitors
        .insert(crate::proc_create::origin_monitor_with_reference(
            crate::proc_create::monitor_reference(id, Some(mode), priority),
            me.data(),
            0,
            crate::proc_create::OriginMonitor::Alias,
        ));
    Some(Ok(reference))
}

/// `unalias/1` called directly from native code.
// Port of erts/emulator/beam/bif.c (unalias_1), OTP-29.1.1.
pub(crate) fn unalias_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [reference] = args else {
        return None;
    };
    let id = ref_id(*reference)?;
    let owned = unalias_origin(process, id);
    Some(Ok(Term::atom(if owned {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    })))
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
    process.cold_mut().prio_monitors.remove(&id);
    match entry.state().cloned() {
        Some(crate::proc_create::OriginMonitor::Process(_)) => OriginDemonitor::Process(entry),
        Some(crate::proc_create::OriginMonitor::Port { port_id, .. }) => {
            OriginDemonitor::Port(port_id, Some(entry))
        }
        Some(crate::proc_create::OriginMonitor::DistPort { .. }) => {
            OriginDemonitor::Port(None, None)
        }
        _ => OriginDemonitor::Distributed(entry),
    }
}

fn demonitor_process_origin(process: &mut Process, id: u64) -> Option<OriginDemonitor> {
    // Port of erts/emulator/beam/bif.c (demonitor_2), OTP-29.1.1: classify the located origin
    // monitor and delete it only when it is a local process monitor.
    let entry = match process.monitors.remove_if(id, |flags| {
        flags & crate::monitor_link::node_flag::TYPE_MASK
            == crate::monitor_link::node_type::MONITOR_PROC
    }) {
        Ok(Some(entry)) => entry,
        Ok(None) => return Some(OriginDemonitor::Missing),
        Err(flags)
            if flags & crate::monitor_link::node_flag::TYPE_MASK
                == crate::monitor_link::node_type::MONITOR_ALIAS =>
        {
            return Some(OriginDemonitor::Alias);
        }
        Err(_) => return None,
    };
    Some(finish_demonitor_origin(process, id, entry))
}

/// `demonitor(Ref)` / `demonitor(Ref, Opts)` called directly from native code (erts bif.c:437-454
/// and the local monitor case). Aliases, port and remote monitors take the executor. A flush
/// with the monitor already gone traps to `flush_monitor_messages` with its resolved export.
// Port of erts/emulator/beam/bif.c:437-454 (demonitor), OTP-29.1.1.
pub(crate) fn demonitor_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let (reference, options) = match args {
        [reference] => (*reference, Term::NIL),
        [reference, options] => (*reference, *options),
        _ => return None,
    };
    if crate::trace::active() {
        return None;
    }
    let (flush, info) = demonitor_flags(options)?;
    let id = ref_id(reference)?;
    if process.cold.as_ref()?.dist_monitors.contains(&id) {
        return None;
    }
    let me = process.self_pid?;
    let entry = demonitor_process_origin(process, id)?;
    let (active, origin) = match entry {
        OriginDemonitor::Process(origin) => {
            (Some(Pid::from_data(origin.view().other())), Some(origin))
        }
        OriginDemonitor::Alias => {
            return Some(Ok(Term::atom(arinsal_term::atoms::FALSE)));
        }
        OriginDemonitor::Missing => (None, None),
        OriginDemonitor::Distributed(_) | OriginDemonitor::Port(_, _) => unreachable!(),
    };
    if active.is_none() && flush {
        let result = Term::atom(if info {
            arinsal_term::atoms::FALSE
        } else {
            arinsal_term::atoms::TRUE
        });
        let trap = crate::ExportTrap::new(
            process,
            FLUSH_MONITOR_CONTINUATION,
            vec![reference, Term::atom(arinsal_term::atoms::FALSE), result],
        );
        return Some(Err(crate::exceptions::Trap::export(trap)));
    }
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    let result = if let Some(pid) = active {
        let origin = origin.expect("active origin monitor carries its half");
        let scheduler = rt_ref(process)?.scheduler().ok()?;
        // Port of erts/emulator/beam/bif.c:521 (demonitor, ERTS_MON_TYPE_PROC): the demonitor
        // always goes through proc_queue_signal, which sends a held monitor first; the signal is
        // the origin half itself (erts_proc_sig_send_demonitor).
        let _ = scheduler.signal_ordered_from(
            me,
            pid,
            arinsal_sched::Signal::DemonitorOrigin(origin.into_shared()),
            process.on_managed,
        );
        Term::atom(arinsal_term::atoms::TRUE)
    } else {
        Term::atom(if info {
            arinsal_term::atoms::FALSE
        } else {
            arinsal_term::atoms::TRUE
        })
    };
    Some(Ok(result))
}

/// Port of erts/emulator/beam/bif.c:1231-1248 (unlink_1): after sending the unlink op, mark the node
/// with its id; a refused send (the peer is gone) deletes the node.
fn unlink_mark(process: &mut Process, pid: Pid, id: u64, sent: bool) {
    let links = &mut process.links;
    if sent {
        if let Some(mut node) = links.get_mut(pid.data()) {
            node.set_unlinking(id);
            node.set_priority(false);
        }
    } else {
        links.remove(pid.data());
    }
}

/// `unlink(Pid)` called directly from native code (erts unlink_1 with `c_p`) with tracing off.
// Port of erts/emulator/beam/bif.c (unlink_1), OTP-29.1.1.
pub(crate) fn unlink_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [target] = args else {
        return None;
    };
    if crate::trace::active() {
        return None;
    }
    let pid = Pid::from_term(*target)?;
    let me = process.self_pid?;
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    if !process
        .links
        .get(pid.data())
        .is_some_and(|node| node.unlinking() == 0)
    {
        return Some(Ok(Term::atom(arinsal_term::atoms::TRUE)));
    }
    let id = process.next_ref();
    let sent = rt_ref(process)?
        .scheduler()
        .ok()?
        .signal_ordered_from(
            me,
            pid,
            arinsal_sched::Signal::Unlink(id),
            process.on_managed,
        )
        .is_ok();
    unlink_mark(process, pid, id, sent);
    Some(Ok(Term::atom(arinsal_term::atoms::TRUE)))
}

/// `link(Pid)` called directly from native code (erts link_2 with `c_p`) for a live local pid
/// other than the caller. A dead target, a self link and tracing take the executor.
// Port of erts/emulator/beam/bif.c:1286 (link_2) and bif.c:180 (link_opt), OTP-29.1.1.
pub(crate) fn link_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [target] = args else {
        return None;
    };
    if crate::trace::active() {
        return None;
    }
    let pid = Pid::from_term(*target)?;
    let me = process.self_pid?;
    if pid == me {
        return None;
    }
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    if !rt_ref(process)?
        .scheduler()
        .ok()?
        .lookup_from(pid, process.on_managed)
    {
        return None;
    }
    // Port of erts/emulator/beam/bif.c:165-183 (link_opt): a link that exists and is not
    // unlinking sends nothing.
    if process
        .links
        .get(pid.data())
        .is_some_and(|node| node.unlinking() == 0)
    {
        process.links.get_mut(pid.data())?.set_priority(false);
        return Some(Ok(Term::atom(arinsal_term::atoms::TRUE)));
    }
    // A refused signal means the target is gone: leave the link state untouched and let the
    // executor answer noproc.
    rt_ref(process)?
        .scheduler()
        .ok()?
        .signal_ordered_from(
            me,
            pid,
            arinsal_sched::Signal::Link { priority: false },
            process.on_managed,
        )
        .ok()?;
    link_node_create(&mut process.links, pid, false);
    Some(Ok(Term::atom(arinsal_term::atoms::TRUE)))
}

/// `erlang:send(Pid, Msg, Options)` called directly from native code for a local pid, options
/// without `priority`, and a sender with no trace or seq-trace hooks. Everything else declines
/// before any state changes and takes the executor.
// Port of erts/emulator/beam/bif.c:2697-2759 (send_3) and bif.c:2458 (do_send), OTP-29.1.1:
// `noconnect` and `nosuspend` only matter for a remote destination or a port.
pub(crate) fn send3_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    if !send3_light_eligible(process, args) {
        return None;
    }
    Some(send3_light_call(process, args).map_err(|trap| *trap))
}

/// Check whether `send_3` can use the local, untraced process path without changing state.
pub(crate) fn send3_light_eligible(process: &Process, args: &[Term]) -> bool {
    let [target, _message, options] = args else {
        return false;
    };
    if Pid::from_term(*target).is_none() {
        return false;
    }
    if !crate::trace::send_hooks_idle(process) {
        return false;
    }
    let atoms = global_atoms();
    let mut plain = true;
    let Some(()) = each_list_item(*options, |option| {
        plain &= option
            .as_atom()
            .and_then(|a| atoms.text(a))
            .is_some_and(|name| name == "noconnect" || name == "nosuspend");
    }) else {
        return false;
    };
    if !plain {
        return false;
    }
    true
}

/// Run the successful local `send_3` path with a register-return-compatible error value.
pub(crate) fn send3_light_call(
    process: &mut Process,
    args: &[Term],
) -> Result<Term, Box<crate::exceptions::Trap>> {
    let [target, message, _options] = args else {
        return Err(Box::new(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::BADARG,
        ))));
    };
    let Some(pid) = Pid::from_term(*target) else {
        return Err(Box::new(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::BADARG,
        ))));
    };
    // Port of erts/emulator/beam/bif.c:2742 (send_3: ERTS_VBUMP_REDS(p, 4) after a completed
    // send), OTP-29.1.1.
    match process.send_to_pid_idle(pid, *message) {
        Ok(_) => {
            crate::native_helpers::vbump_reds(process, 4);
            Ok(Term::atom(arinsal_term::atoms::OK))
        }
        Err(_) => Err(Box::new(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::BADARG,
        )))),
    }
}

/// `erlang:send(Dest, Msg)` called directly from native code for a local pid and a sender with
/// no trace or seq-trace hooks. A name, a port, a remote destination and every hook decline
/// before any state changes and take the executor.
// Port of erts/emulator/beam/bif.c:2862 (erl_send: ERTS_VBUMP_REDS after a completed send) and
// bif.c:2458 (do_send), OTP-29.1.1.
pub(crate) fn send2_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [target, message] = args else {
        return None;
    };
    let pid = Pid::from_term(*target)?;
    if !crate::trace::send_hooks_idle(process) {
        return None;
    }
    Some(match process.send_to_pid_idle(pid, *message) {
        Ok(value) => {
            crate::native_helpers::vbump_reds(process, 4);
            Ok(value)
        }
        Err(_) => Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::BADARG,
        ))),
    })
}

/// `exit(Pid, Reason)` called directly from native code (erts bif.c:1721 send_exit_signal_bif)
/// for a local pid other than the caller.
// Port of erts/emulator/beam/bif.c:1721 (send_exit_signal_bif), OTP-29.1.1.
pub(crate) fn exit2_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [target, reason] = args else {
        return None;
    };
    let pid = Pid::from_term(*target)?;
    let me = process.self_pid?;
    if pid == me {
        return None;
    }
    let message = Message::copy_from(*reason).ok()?;
    // erts reads the runtime through globals; borrow it per use instead of a refcounted clone.
    let _ = rt_ref(process)?.scheduler().ok()?.signal_ordered_from(
        me,
        pid,
        arinsal_sched::Signal::Exit(Box::new(message)),
        process.on_managed,
    );
    Some(Ok(Term::atom(arinsal_term::atoms::TRUE)))
}

resolved_signal_handler!(register2, Register2);
resolved_signal_handler!(unregister1, Unregister1);
resolved_signal_handler!(whereis1, Whereis1);
resolved_signal_handler!(registered0, Registered0);
resolved_signal_handler!(link1, Link1);
resolved_signal_handler!(link2, Link2);
resolved_signal_handler!(unlink1, Unlink1);
resolved_signal_handler!(monitor2, Monitor2);
resolved_signal_handler!(monitor3, Monitor3);
resolved_signal_handler!(demonitor1, Demonitor1);
resolved_signal_handler!(demonitor2, Demonitor2);
resolved_signal_handler!(exit2, Exit2);
resolved_signal_handler!(exit3, Exit3);
resolved_signal_handler!(exit_signal2, ExitSignal2);
resolved_signal_handler!(exit_signal3, ExitSignal3);
resolved_signal_handler!(trace_delivered1, TraceDelivered1);
resolved_signal_handler!(send_after3, SendAfter3);
resolved_signal_handler!(send_after4, SendAfter4);
resolved_signal_handler!(start_timer3, StartTimer3);
resolved_signal_handler!(start_timer4, StartTimer4);
resolved_signal_handler!(cancel_timer1, CancelTimer1);
resolved_signal_handler!(cancel_timer2, CancelTimer2);
resolved_signal_handler!(read_timer1, ReadTimer1);
resolved_signal_handler!(read_timer2, ReadTimer2);
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
        ("erlang", "spawn", 3) => spawn3,
        ("erlang", "spawn_link", 3) => spawn_link3,
        ("erlang", "spawn_opt", 4) => spawn_opt4,
        ("erlang", "register", 2) => register2,
        ("erlang", "unregister", 1) => unregister1,
        ("erlang", "whereis", 1) => whereis1,
        ("erlang", "registered", 0) => registered0,
        ("erlang", "link", 1) => link1,
        ("erlang", "link", 2) => link2,
        ("erlang", "unlink", 1) => unlink1,
        ("erlang", "monitor", 2) => monitor2,
        ("erlang", "monitor", 3) => monitor3,
        ("erlang", "demonitor", 1) => demonitor1,
        ("erlang", "demonitor", 2) => demonitor2,
        ("erlang", "exit", 2) => exit2,
        ("erlang", "exit", 3) => exit3,
        ("erlang", "exit_signal", 2) => exit_signal2,
        ("erlang", "exit_signal", 3) => exit_signal3,
        ("erlang", "trace_delivered", 1) => trace_delivered1,
        ("erlang", "send_after", 3) => send_after3,
        ("erlang", "send_after", 4) => send_after4,
        ("erlang", "start_timer", 3) => start_timer3,
        ("erlang", "start_timer", 4) => start_timer4,
        ("erlang", "cancel_timer", 1) => cancel_timer1,
        ("erlang", "cancel_timer", 2) => cancel_timer2,
        ("erlang", "read_timer", 1) => read_timer1,
        ("erlang", "read_timer", 2) => read_timer2,
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
        let mut handlers: HashMap<_, _> = IMPLEMENTED
            .iter()
            .filter_map(|&(module, function, arity)| {
                let module = global_atoms().intern(module).ok()?;
                let function = global_atoms().intern(function).ok()?;
                let entry = match (module, function, arity) {
                    (m, f, 0) if m == arinsal_term::atoms::ERLANG && f == atom_id("self")? => {
                        crate::natives::NativeEntry::Direct(native_self)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("send")? => {
                        crate::natives::NativeEntry::Direct(native_send)
                    }
                    (m, f, 3) if m == arinsal_term::atoms::ERLANG && f == atom_id("send")? => {
                        crate::natives::NativeEntry::Direct(native_send3)
                    }
                    (m, f, 1)
                        if m == arinsal_term::atoms::ERLANG
                            && f == atom_id("is_process_alive")? =>
                    {
                        crate::natives::NativeEntry::Direct(native_is_process_alive)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("!")? => {
                        crate::natives::NativeEntry::Direct(native_send)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("monitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_monitor)
                    }
                    (m, f, 3) if m == arinsal_term::atoms::ERLANG && f == atom_id("monitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_monitor)
                    }
                    (m, f, 1) if m == arinsal_term::atoms::ERLANG && f == atom_id("demonitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_demonitor)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("demonitor")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_demonitor)
                    }
                    // erts has one link_1/unlink_1/exit_2 for every caller (bif.c); an external
                    // pid reaches the distribution signal from apply as from a static import.
                    (m, f, 1) if m == arinsal_term::atoms::ERLANG && f == atom_id("link")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_link)
                    }
                    (m, f, 1) if m == arinsal_term::atoms::ERLANG && f == atom_id("unlink")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_unlink)
                    }
                    (m, f, 2) if m == arinsal_term::atoms::ERLANG && f == atom_id("exit")? => {
                        crate::natives::NativeEntry::Direct(crate::dist::native_exit2)
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
        if let (Some(module), Some(function)) = (atom_id("erlang"), atom_id("!")) {
            handlers.insert(
                (module, function, 2),
                crate::natives::NativeEntry::Direct(native_send),
            );
        }
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
fn monitor_port(
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
        process
            .monitors
            .insert(crate::proc_create::origin_monitor_with_reference(
                crate::proc_create::monitor_reference(reference_id, alias_mode, false),
                me.data(),
                0,
                crate::proc_create::OriginMonitor::DistPort {
                    object: Box::new(object.clone()),
                },
            ));
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let object =
            arinsal_term::from_owned(&object, &mut heap).map_err(|_| badarg("monitor/2"))?;
        let down = TermBuilder::new(&mut heap)
            .tuple(&[
                tag,
                reference_term,
                Term::atom(arinsal_term::atoms::PORT),
                object,
                Term::atom(arinsal_term::atoms::NOPROC),
            ])
            .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
        process.inbox.push_back(down);
        let _ = take_origin_monitor_down(process, reference_id);
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
        crate::proc_create::MonitorInfo::with_port_name(name),
        crate::proc_create::OriginMonitor::Port { port_id, name },
    );
    process.monitors.insert(origin);
    let registered = port_id.and_then(|id| {
        runtime.ports.with_from(id, process.on_managed, |handle| {
            if tag != Term::atom(arinsal_term::atoms::DOWN) {
                // Port monitors carry no tag yet (typed gap, see report).
                return Err(VmError::Unsupported("monitor(port, _, [{tag, _}])".into()));
            }
            crate::port::monitor(process, id, handle, target_half, true)
        })
    });
    if let Some(registered) = registered {
        if !registered? {
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let object = port_monitor_object(&mut heap, port_id, name)?;
            let down = TermBuilder::new(&mut heap)
                .tuple(&[
                    tag,
                    reference_term,
                    Term::atom(arinsal_term::atoms::PORT),
                    object,
                    Term::atom(arinsal_term::atoms::NOPROC),
                ])
                .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
            process.inbox.push_back(down);
            let _ = take_origin_monitor_down(process, reference_id);
        }
        // Origin stays in this process; the target half is on the port.
        Ok(reference_term)
    } else {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let object = port_monitor_object(&mut heap, port_id, name)?;
        let down = TermBuilder::new(&mut heap)
            .tuple(&[
                tag,
                reference_term,
                Term::atom(arinsal_term::atoms::PORT),
                object,
                Term::atom(arinsal_term::atoms::NOPROC),
            ])
            .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
        process.inbox.push_back(down);
        let _ = take_origin_monitor_down(process, reference_id);
        Ok(reference_term)
    }
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
        (SignalBif::Spawn3, [module, function, args]) => spawn_mfa(
            vm,
            process,
            ctx,
            (*module, *function, *args),
            false,
            false,
            None,
            None,
            None,
            None,
        ),
        (SignalBif::SpawnLink3, [module, function, args]) => spawn_mfa(
            vm,
            process,
            ctx,
            (*module, *function, *args),
            true,
            false,
            None,
            None,
            None,
            None,
        ),
        (SignalBif::SpawnOpt4, [module, function, args, options]) => {
            spawn_options(process.runtime, *options).and_then(|opts| {
                spawn_mfa_with_priority(vm, process, ctx, (*module, *function, *args), opts)
            })
        }
        (SignalBif::Register2, [name, id]) => {
            let name = name.as_atom().ok_or_else(|| badarg("register/2"))?;
            // Port of erts/emulator/beam/register.c:184 (erts_register_name): `undefined` is not a name.
            if name == arinsal_term::atoms::UNDEFINED {
                return Err(badarg("register/2"));
            }
            let rt = process.runtime.ok_or_else(|| badarg("register/2"))?;
            let scheduler = rt.scheduler()?;
            if let Some(pid) = Pid::from_term(*id) {
                let mut table = rt.reg.write();
                if !scheduler.lookup(pid)
                    || scheduler.registered_atom_index(pid).is_some()
                    || table.contains(name)
                    || !rt.publish_proc_flag(pid, arinsal_sched::proc_flags::REG)
                {
                    return Err(badarg("register/2"));
                }
                table.insert_proc(name, pid);
                scheduler.set_registered_atom_index(pid, name.0);
                drop(table);
                // Port of erts/emulator/beam/register.c:237-240 (erts_register_name), OTP-29.1.1:
                // the event belongs to the process that gets the name.
                crate::trace::emit(
                    Some(vm),
                    process,
                    ctx,
                    pid,
                    crate::trace::PROCS,
                    "register",
                    &[Term::atom(name)],
                );
                Ok(Term::atom(arinsal_term::atoms::TRUE))
            } else if let Some(port_id) = id.as_port() {
                let handle = {
                    let _ports = rt.ports.lock().unwrap();
                    let handle = rt.ports.get(port_id).ok_or_else(|| badarg("register/2"))?;
                    if handle.exit_complete() {
                        return Err(badarg("register/2"));
                    }
                    handle
                };
                let mut table = rt.reg.write();
                if handle.reg_closing()
                    || handle.registered_atom().is_some()
                    || table.contains(name)
                {
                    return Err(badarg("register/2"));
                }
                table.insert_port(name, port_id, handle.reg_word());
                handle.set_registered_atom(name);
                drop(table);
                crate::trace::emit_port_event(
                    rt,
                    port_id,
                    crate::trace::PORTS,
                    "register",
                    &[Term::atom(name)],
                );
                Ok(Term::atom(arinsal_term::atoms::TRUE))
            } else {
                Err(badarg("register/2"))
            }
        }
        (SignalBif::Unregister1, [name]) => {
            let name = name.as_atom().ok_or_else(|| badarg("unregister/1"))?;
            let rt = process.runtime.ok_or_else(|| badarg("unregister/1"))?;
            let mut table = rt.reg.write();
            match table.erase(name) {
                Some(crate::register::RegId::Proc(pid)) => {
                    if let Ok(scheduler) = rt.scheduler() {
                        scheduler.clear_registered_atom_index(pid, name.0);
                    }
                    drop(table);
                    // Port of erts/emulator/beam/register.c:507-519 (erts_unregister_name), OTP-29.1.1.
                    crate::trace::emit(
                        Some(vm),
                        process,
                        ctx,
                        pid,
                        crate::trace::PROCS,
                        "unregister",
                        &[Term::atom(name)],
                    );
                    Ok(Term::atom(arinsal_term::atoms::TRUE))
                }
                Some(crate::register::RegId::Port(port_id)) => {
                    drop(table);
                    crate::trace::emit_port_event(
                        rt,
                        port_id,
                        crate::trace::PORTS,
                        "unregister",
                        &[Term::atom(name)],
                    );
                    Ok(Term::atom(arinsal_term::atoms::TRUE))
                }
                None => Err(badarg("unregister/1")),
            }
        }
        (SignalBif::Whereis1, [name]) => whereis_1(process, *name),
        (SignalBif::Registered0, []) => registered_names(process),
        // Port of erts/emulator/beam/bif.c (link_opt and unlink_1, is_external_pid): one BIF
        // for every caller, so an applied call reaches the external-link path too.
        (SignalBif::Link1, [target]) | (SignalBif::Unlink1, [target])
            if crate::dist::is_remote_target(*target)? =>
        {
            let function = if matches!(entry, SignalBif::Link1) {
                "link"
            } else {
                "unlink"
            };
            crate::dist::native_signal(vm, process, ctx, args, function)
        }
        (SignalBif::Link1, [target]) => link_opt(vm, process, ctx, *target, Term::NIL),
        (SignalBif::Link2, [target, opts]) => link_opt(vm, process, ctx, *target, *opts),
        (SignalBif::Unlink1, [port]) if port.as_port().is_some() => {
            // A dead port has nothing left to unlink from.
            if port
                .as_port()
                .is_some_and(|id| crate::port::is_live(process, id))
            {
                crate::port::link(process, *port, ctx.pid(), false)?;
            }
            Ok(Term::atom(arinsal_term::atoms::TRUE))
        }
        (SignalBif::Unlink1, [pid]) => {
            let pid = Pid::from_term(*pid).ok_or_else(|| badarg("unlink/1"));
            pid.map(|pid| {
                if let Some(pid_term) = pid.to_term() {
                    crate::trace::emit(
                        Some(vm),
                        process,
                        ctx,
                        ctx.pid(),
                        crate::trace::PROCS,
                        "unlink",
                        &[pid_term],
                    );
                }
                let should_unlink = process
                    .links
                    .get(pid.data())
                    .is_some_and(|node| node.unlinking() == 0);
                if should_unlink {
                    let id = process
                        .runtime
                        .as_ref()
                        .map_or(1, |runtime| runtime.next_ref());
                    let sent = ctx.signal(pid, Signal::Unlink(id)).is_ok();
                    unlink_mark(process, pid, id, sent);
                }
                wake_for_procs_trace(process, pid);
                Term::atom(arinsal_term::atoms::TRUE)
            })
        }
        (SignalBif::Monitor2, [kind, target]) | (SignalBif::Monitor3, [kind, target, _])
            if *kind == Term::atom(arinsal_term::atoms::PROCESS) =>
        {
            let (tag, alias_mode, priority) = monitor_options(args)?;
            let rt = process.runtime.ok_or_else(|| badarg("monitor/2"))?;
            // boot_loop1: code_server:call/1 monitors its registered name.
            // Port of erts/emulator/beam/bif.c:1100 (erts_internal_monitor? monitor_2/3
            // local arm), OTP-29.1.1: `Name` and `{Name, node()}` both monitor by name.
            let name = match atom_name(*target) {
                Some(name) => Some(name),
                None if Pid::from_term(*target).is_none() => {
                    crate::dist::name_node_tuple(*target)?.map(|(name, _node)| name)
                }
                None => None,
            };
            let pid = if let Some(pid) = Pid::from_term(*target) {
                Some(pid)
            } else if let Some(name) = name.as_ref() {
                rt.reg.whereis_proc_str(name)
            } else if matches!(to_owned(*target), Ok(arinsal_etf::OwnedTerm::Pid { .. })) {
                // A pid of another incarnation of this node never matches a live process.
                None
            } else {
                return Err(badarg("monitor/2"));
            };
            let id = process.next_ref();
            let ref_term = if alias_mode.is_some() {
                pid_reference(process, id, ctx.pid())?
            } else {
                reference(process, id)?
            };
            // Port of erts/emulator/beam/bif.c:782-784 (monitor), OTP-29.1.1.
            // Monitoring oneself creates no monitor and sends no signal.
            if pid == Some(ctx.pid()) {
                return Ok(ref_term);
            }
            let info = monitor_info_for(tag, name.as_deref())?;
            if priority {
                process.cold_mut().prio_monitors.insert(id);
            }
            if let Some(pid) = pid.filter(|pid| rt.scheduler().is_ok_and(|s| s.lookup(*pid))) {
                // One `ErtsMonitorData` for both halves: the origin goes into the tree, the
                // target half is the monitor signal.
                let (origin, target_half) = crate::proc_create::create_monitor_with_reference_at(
                    process.heap.alloc_ix(),
                    crate::proc_create::monitor_reference(id, alias_mode, priority),
                    ctx.pid().data(),
                    pid.data(),
                    info,
                    crate::proc_create::OriginMonitor::Process(crate::proc_create::OriginHalf),
                );
                process.monitors.insert(origin);
                let signal = arinsal_sched::Signal::Monitor {
                    reference: id,
                    shared: target_half.into_shared(),
                };
                if let Err(error) = ctx.signal(pid, signal) {
                    process.monitors.remove(id);
                    if error != arinsal_sched::Error::NoProcess {
                        return Err(VmError::Unsupported(format!("monitor: {error}")));
                    }
                    // The target stopped accepting monitor signals before this request.
                    send_noproc_down(
                        process,
                        ctx,
                        id,
                        name.as_deref(),
                        Some(pid),
                        *target,
                        tag,
                        alias_mode,
                    )?;
                }
            } else {
                send_noproc_down(
                    process,
                    ctx,
                    id,
                    name.as_deref(),
                    pid,
                    *target,
                    tag,
                    alias_mode,
                )?;
            }
            Ok(ref_term)
        }
        (SignalBif::Monitor2, [kind, target])
            if *kind == Term::atom(arinsal_term::atoms::TIME_OFFSET) =>
        {
            // Port of erts/emulator/beam/erl_time_sup.c:1964-1968
            // (erts_monitor_time_offset), OTP-29.1.1. There is no clock warp
            // source in this runtime, but monitor creation still returns a ref.
            if *target != Term::atom(arinsal_term::atoms::CLOCK_SERVICE) {
                return Err(badarg("monitor/2"));
            }
            process.runtime.ok_or_else(|| badarg("monitor/2"))?;
            let id = process.next_ref();
            reference(process, id)
        }
        (SignalBif::Monitor2, [kind, target]) | (SignalBif::Monitor3, [kind, target, _])
            if *kind == Term::atom(arinsal_term::atoms::PORT) =>
        {
            let (tag, alias_mode, _priority) = monitor_options(args)?;
            monitor_port(process, ctx.pid(), *target, tag, alias_mode)
        }
        (SignalBif::Demonitor1, [reference]) | (SignalBif::Demonitor2, [reference, _]) => {
            let id = ref_id(*reference).ok_or_else(|| badarg("demonitor/1"))?;
            // Port of erts/emulator/beam/bif.c (demonitor_2): the option list is walked in
            // place.
            let (flush, info) = match args.get(1) {
                Some(options) => demonitor_flags(*options).ok_or_else(|| badarg("demonitor/2"))?,
                None => (false, false),
            };
            let entry = demonitor_origin(process, id);
            let (was_alias, process_target, port_target, port_origin, distributed) = match entry {
                OriginDemonitor::Alias => (true, None, None, None, None),
                OriginDemonitor::Process(origin) => (false, Some(origin), None, None, None),
                OriginDemonitor::Port(port_id, origin) => (false, None, port_id, origin, None),
                OriginDemonitor::Distributed(origin) => (false, None, None, None, Some(origin)),
                OriginDemonitor::Missing => (false, None, None, None, None),
            };
            let mut was_active = false;
            if let Some(origin) = process_target {
                // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_send_demonitor):
                // the origin half itself is the demonitor signal.
                let target = Pid::from_data(origin.view().other());
                let shared = origin.into_shared();
                let _ = ctx.signal(target, Signal::DemonitorOrigin(shared));
                was_active = true;
            }
            // Port of erts/emulator/beam/bif.c:504-510 (demonitor, ERTS_MON_TYPE_PORT),
            // OTP-29.1.1: the origin is in this process's monitor tree. The port id
            // there selects the port; `erts_port_demonitor` sends the demonitor signal.
            if let (Some(port_id), Some(origin)) = (port_target, port_origin) {
                crate::port::demonitor_port(process, ctx.pid(), port_id, origin);
                was_active = true;
            }
            if let Some(origin) = distributed {
                // Port of erts/emulator/beam/bif.c (demonitor, ERTS_MON_TYPE_DIST_PROC).
                if let Some(cold) = process.cold.as_mut() {
                    cold.dist_monitors.remove(&id);
                }
                crate::dist::demonitor_remote(process.runtime, ctx.pid(), origin);
                was_active = true;
            }
            // Port of erts/emulator/beam/bif.c:640-654 (demonitor_2), OTP-29.1.1.
            // Flush runs only when the monitor is already gone (`am_false`). An
            // active process monitor just queues the demonitor signal.
            let failed = was_alias || (info && !was_active);
            let result = Term::atom(if failed {
                arinsal_term::atoms::FALSE
            } else {
                arinsal_term::atoms::TRUE
            });
            if flush && !was_active {
                return Err(flush_monitor_trap(process, *reference, result));
            }
            Ok(result)
        }
        (SignalBif::Exit2, [target, reason]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, Term::NIL, true)
        }
        (SignalBif::Exit3, [target, reason, opts]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, *opts, true)
        }
        (SignalBif::ExitSignal2, [target, reason]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, Term::NIL, false)
        }
        (SignalBif::ExitSignal3, [target, reason, opts]) => {
            send_exit_signal_bif(process, ctx, *target, *reason, *opts, false)
        }
        (SignalBif::TraceDelivered1, [target]) => trace_delivered(process, ctx, *target),
        (SignalBif::IsProcessAlive2, [pid, reference]) => {
            is_process_alive_2(process, ctx, *pid, *reference)
        }
        (SignalBif::IsProcessExecutingDirty1, [pid]) => is_process_executing_dirty(process, *pid),
        (SignalBif::TraceCleanerCheck0, []) => Ok(Term::atom(arinsal_term::atoms::FALSE)),
        (SignalBif::TraceCleanerSend1, [to]) => trace_cleaner_send(process, ctx, *to),
        (SignalBif::SendAfter3, [..])
        | (SignalBif::SendAfter4, [..])
        | (SignalBif::StartTimer3, [..])
        | (SignalBif::StartTimer4, [..]) => start_timer_bif(
            process,
            ctx,
            args,
            matches!(entry, SignalBif::SendAfter3 | SignalBif::SendAfter4),
        ),
        (SignalBif::CancelTimer1, [reference]) | (SignalBif::CancelTimer2, [reference, _]) => {
            let options = if let Some(options) = args.get(1) {
                timer_query_options(*options, true)?
            } else {
                TimerQueryOptions {
                    asynchronous: false,
                    info: true,
                }
            };
            let id = ref_id(*reference).ok_or_else(|| badarg("cancel_timer/1"))?;
            if !options.asynchronous {
                return timer_query_sync(process, ctx.pid(), *reference, true, options.info, true);
            }
            let rt = runtime(process)?;
            if options.asynchronous {
                let timer = rt
                    .scheduler()
                    .ok()
                    .map(|scheduler| scheduler.timer_for_ref_key(id));
                if options.info {
                    let reference = arinsal_term::to_owned(*reference).map_err(|error| {
                        VmError::Unsupported(format!("timer reference snapshot: {error:?}"))
                    })?;
                    if let (Some(timer), Ok(scheduler)) = (timer, rt.scheduler()) {
                        let target = ctx.pid();
                        let reply_scheduler = scheduler.clone();
                        scheduler.cancel_timer_async(timer, move |remaining| {
                            let value = remaining.map_or_else(
                                || OwnedTerm::atom("false"),
                                |ms| {
                                    if let Ok(value) = i64::try_from(ms) {
                                        OwnedTerm::Int(value)
                                    } else {
                                        OwnedTerm::BigInt(num_bigint::BigInt::from(ms))
                                    }
                                },
                            );
                            let term = OwnedTerm::Tuple(vec![
                                OwnedTerm::atom("cancel_timer"),
                                reference,
                                value,
                            ]);
                            if let Ok(message) = Message::from_owned(&term) {
                                let _ = reply_scheduler.send(target, target, message);
                            }
                        });
                    } else {
                        let term = OwnedTerm::Tuple(vec![
                            OwnedTerm::atom("cancel_timer"),
                            reference,
                            OwnedTerm::atom("false"),
                        ]);
                        if let Ok(message) = Message::from_owned(&term) {
                            let _ = ctx.send(ctx.pid(), message);
                        }
                    }
                } else if let (Some(timer), Ok(scheduler)) = (timer, rt.scheduler()) {
                    scheduler.cancel_timer_async(timer, move |_| {});
                }
                return Ok(Term::atom(arinsal_term::atoms::OK));
            }
            unreachable!("synchronous cancel_timer returned above")
        }
        (SignalBif::ReadTimer1, [reference]) | (SignalBif::ReadTimer2, [reference, _]) => {
            let options = if let Some(options) = args.get(1) {
                timer_query_options(*options, false)?
            } else {
                TimerQueryOptions {
                    asynchronous: false,
                    info: true,
                }
            };
            let id = ref_id(*reference).ok_or_else(|| badarg("read_timer/1"))?;
            if !options.asynchronous {
                return timer_query_sync(process, ctx.pid(), *reference, false, options.info, true);
            }
            let rt = runtime(process)?;
            let timer = rt
                .scheduler()
                .ok()
                .map(|scheduler| scheduler.timer_for_ref_key(id));
            if options.asynchronous {
                let reference = arinsal_term::to_owned(*reference).map_err(|error| {
                    VmError::Unsupported(format!("timer reference snapshot: {error:?}"))
                })?;
                if let (Some(timer), Ok(scheduler)) = (timer, rt.scheduler()) {
                    let target = ctx.pid();
                    let reply_scheduler = scheduler.clone();
                    scheduler.read_timer_async(timer, move |remaining| {
                        let value = remaining.map_or_else(
                            || OwnedTerm::atom("false"),
                            |ms| {
                                if let Ok(value) = i64::try_from(ms) {
                                    OwnedTerm::Int(value)
                                } else {
                                    OwnedTerm::BigInt(num_bigint::BigInt::from(ms))
                                }
                            },
                        );
                        let term =
                            OwnedTerm::Tuple(vec![OwnedTerm::atom("read_timer"), reference, value]);
                        if let Ok(message) = Message::from_owned(&term) {
                            let _ = reply_scheduler.send(target, target, message);
                        }
                    });
                } else {
                    let term = OwnedTerm::Tuple(vec![
                        OwnedTerm::atom("read_timer"),
                        reference,
                        OwnedTerm::atom("false"),
                    ]);
                    if let Ok(message) = Message::from_owned(&term) {
                        let _ = ctx.send(ctx.pid(), message);
                    }
                }
                return Ok(Term::atom(arinsal_term::atoms::OK));
            }
            unreachable!("synchronous read_timer returned above")
        }
        (SignalBif::SpawnSystemProcess3, [module, function, args]) => {
            let pid = spawn_mfa(
                vm,
                process,
                ctx,
                (*module, *function, *args),
                false,
                false,
                None,
                None,
                None,
                None,
            )?;
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

fn registered_names(process: &mut Process) -> Result<Term, VmError> {
    let rt = process
        .runtime
        .ok_or_else(|| VmError::Unsupported("process BIF requires a scheduler".into()))?;
    // Port of erts/emulator/beam/register.c:585-599, OTP-29.1.1: count while locked, reserve
    // the exact young-heap space, then prepend each bucket entry before releasing the read lock.
    let registry = rt.reg.read();
    let count = registry.registered_count();
    if count == 0 {
        return Ok(Term::NIL);
    }
    let words = count.checked_mul(2).ok_or_else(|| {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut block = HeapReservation::with_extra(&mut heap, words, 0).map_err(|_| {
        VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        )))
    })?;
    let mut builder = TermBuilder::new(&mut block);
    let mut tail = Term::NIL;
    registry
        .try_for_each_registered_atom(|name| {
            tail = builder.cons(Term::atom(name), tail)?;
            Ok::<_, arinsal_term::TermError>(())
        })
        .map_err(|_| {
            VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                arinsal_term::atoms::SYSTEM_LIMIT,
            )))
        })?;
    Ok(tail)
}

/// `registered/0` only snapshots the process registry and builds the resulting list.
// Port of erts/emulator/beam/register.c:567 (`registered_atoms`), OTP-29.1.1.
pub(crate) fn registered_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    if !args.is_empty() {
        return None;
    }
    Some(registered_names(process).map_err(|error| match error {
        VmError::Trap(trap) => trap,
        _ => crate::exceptions::Trap::error(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT)),
    }))
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
fn send_noproc_down(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: u64,
    name: Option<&str>,
    target_pid: Option<Pid>,
    target: Term,
    tag: Term,
    alias_mode: Option<crate::proc_create::AliasMode>,
) -> Result<(), VmError> {
    // A named target is reported by name; the signal sender is then irrelevant.
    let from = target_pid.or_else(|| name.map(|_| ctx.pid()));
    if let Some(from) = from
        && let Some(runtime) = process.runtime
    {
        let info = monitor_info_for(tag, name)?;
        let (origin, _target) = crate::proc_create::create_monitor_with_reference_at(
            process.heap.alloc_ix(),
            crate::proc_create::monitor_reference(id, alias_mode, false),
            ctx.pid().data(),
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
                ctx.pid(),
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
        pid_reference(process, id, ctx.pid())?
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
    process.inbox.push_back(down);
    Ok(())
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

// Port of erts/emulator/beam/erl_proc_sig_queue.c:3027
// (erts_proc_sig_send_is_alive_request), OTP-29.1.1.
fn is_process_alive(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Term,
) -> Result<Term, VmError> {
    let pid_term = pid;
    let pid = Pid::from_term(pid).ok_or_else(|| badarg("is_process_alive/1"))?;
    if pid == ctx.pid() {
        return Ok(Term::atom(arinsal_term::atoms::TRUE));
    }
    if !runtime(process)?.scheduler()?.lookup(pid) {
        return Ok(Term::atom(arinsal_term::atoms::FALSE));
    }
    if let Some(result) = alive_fast(process, pid_term) {
        return Ok(Term::atom(result));
    }
    // Port of erts/emulator/beam/erl_bif_info.c:4090 (BIF_TRAP1(is_process_alive_trap)):
    // erts_internal:is_process_alive/1 sends the request and receives `{Ref, Res}`.
    Err(VmError::TrapExport(crate::ExportTrap::new(
        process,
        "erts_internal:is_process_alive/1",
        vec![pid_term],
    )))
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

// Port of erts/emulator/beam/bif.c:136 (link_opt) and bif.c:675 (erts_link_opts), OTP-29.1.1.
fn link_opt(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
    opts: Term,
) -> Result<Term, VmError> {
    let priority = parse_priority_opts(opts)?;
    if let Some(id) = target.as_port() {
        // Port of erts/emulator/beam/bif.c:1286 (link_2): a dead local port answers noproc.
        if !crate::port::is_live(process, id) {
            return link_noproc_term(process, target, priority);
        }
        if !crate::port::link(process, target, ctx.pid(), true)? {
            return link_noproc_term(process, target, priority);
        }
        return Ok(Term::atom(arinsal_term::atoms::TRUE));
    }
    let pid = Pid::from_term(target).ok_or_else(|| badarg("link"))?;
    if pid == ctx.pid() {
        return Ok(Term::atom(arinsal_term::atoms::TRUE));
    }
    if !runtime(process)?.scheduler()?.lookup(pid) {
        return link_noproc(process, pid, priority);
    }
    // Port of erts/emulator/beam/bif.c:165-183 (link_opt): one lookup_create on the link tree;
    // a link that exists and is not unlinking sends nothing.
    let send = link_node_create(&mut process.links, pid, priority);
    let trace_changes = if send {
        crate::trace::linked(process, ctx.pid())
    } else {
        Vec::new()
    };
    let linked_term = pid.to_term().ok_or_else(|| badarg("link"))?;
    crate::trace::emit(
        Some(vm),
        process,
        ctx,
        ctx.pid(),
        crate::trace::PROCS,
        "link",
        &[linked_term],
    );
    let mut signal_result = Ok(());
    if send {
        for change in trace_changes {
            signal_result = ctx.signal(
                pid,
                Signal::TraceChangeState(arinsal_sched::SharedPayload(std::sync::Arc::new(change))),
            );
            if signal_result.is_err() {
                break;
            }
        }
        if signal_result.is_ok() {
            signal_result = ctx.signal(pid, Signal::Link { priority });
        }
    }
    match signal_result {
        // The linked process reports getting_linked when it handles the signal.
        Ok(()) => {}
        Err(arinsal_sched::Error::NoProcess) => {
            // The target exited between the lookup and the signal: like erts, keep the link
            // and let a `noproc` link exit from the target dissolve it.
            // Port of erts/emulator/beam/bif.c:180-183 (link_opt), OTP-29.1.1.
            let reason = Message::copy_from(Term::atom(arinsal_term::atoms::NOPROC))?;
            runtime(process)?
                .scheduler()?
                .signal(pid, ctx.pid(), Signal::ExitLinked(Box::new(reason)))
                .map_err(|_| badarg("link"))?;
        }
        Err(arinsal_sched::Error::Capacity) => return Err(system_limit()),
        Err(_) => return Err(badarg("link")),
    }
    wake_for_procs_trace(process, pid);
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

/// `erts_link_internal_tree_lookup_create` plus the `unlinking` reset of `link_opt`
/// (bif.c:165-183): returns whether a link signal must be sent.
fn link_node_create(links: &mut crate::proc_create::LinkTree, pid: Pid, priority: bool) -> bool {
    match links.get_mut(pid.data()) {
        Some(mut node) => {
            node.set_priority(priority);
            let unlinking = node.view().unlinking();
            node.set_unlinking(0);
            unlinking != 0
        }
        None => {
            links.insert(crate::proc_create::process_link(pid, priority));
            true
        }
    }
}

/// Linking to a process that does not exist: an `{'EXIT', Pid, noproc}` message when trapping
/// exits, else a `noproc` error.
// Port of erts/emulator/beam/bif.c:675 (erts_link_opts / link noproc arm), OTP-29.1.1.
fn link_noproc(process: &mut Process, pid: Pid, priority: bool) -> Result<Term, VmError> {
    let pid_term = pid.to_term().ok_or_else(|| badarg("link"))?;
    link_noproc_term(process, pid_term, priority)
}

fn link_noproc_term(process: &mut Process, target: Term, priority: bool) -> Result<Term, VmError> {
    let reason = Term::atom(arinsal_term::atoms::NOPROC);
    if process.trap_exit {
        let pid_term = target;
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let exit = TermBuilder::new(&mut heap)
            .tuple(&[Term::atom(arinsal_term::atoms::EXIT_2), pid_term, reason])
            .map_err(|_| system_limit())?;
        if priority {
            process.push_priority_message(exit)?;
        } else {
            process.inbox.push_back(exit);
        }
        return Ok(Term::atom(arinsal_term::atoms::TRUE));
    }
    process.heap.abi.exc.fvalue = reason.tagged_word();
    Err(VmError::Trap(crate::exceptions::Trap::error(reason)))
}

/// Link and unlink signals are applied lazily, but erts handles them on arrival, which is when a
/// `procs` trace reports getting_linked/getting_unlinked: wake a receiver that is traced for it.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:8578-8589 (getting_unlinked/getting_linked), OTP-29.1.1.
fn wake_for_procs_trace(process: &Process, target: Pid) {
    if crate::trace::flags(process, target) & crate::trace::PROCS != 0
        && let Some(runtime) = process.runtime.as_ref()
        && let Ok(scheduler) = runtime.scheduler()
    {
        let _ = scheduler.wake(target);
    }
}

// Port of erts/emulator/beam/bif.c:1721 (send_exit_signal_bif), OTP-29.1.1.
fn send_exit_signal_bif(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: Term,
    reason: Term,
    opts: Term,
    exit2: bool,
) -> Result<Term, VmError> {
    let want_priority = parse_priority_opts(opts)?;
    if let Some(port_id) = id.as_port() {
        // Port of erts/emulator/beam/bif.c:1721: an exit signal to a dead port is dropped.
        if crate::port::is_live(process, port_id) {
            crate::port::exit_port(process, ctx, id, reason)?;
        }
        return Ok(Term::atom(arinsal_term::atoms::TRUE));
    }
    let (pid, alias) = if let Some(pid) = Pid::from_term(id) {
        (pid, 0)
    } else if let (Some(pid_data), Some(alias)) = (id.local_pid_ref_pid_data(), ref_id(id)) {
        // Port of erts_get_pid_of_ref (erl_bif_unique.h), OTP-29.1.1.
        (Pid::from_data(pid_data), alias)
    } else {
        return Err(badarg("exit"));
    };
    let suicide = exit2
        && pid == ctx.pid()
        && (reason == Term::atom(arinsal_term::atoms::KILL) || !process.trap_exit);
    if suicide {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c (handle_exit_signal), OTP-29.1.1:
        // the self-signal is handled like any exit signal, so `kill` becomes `killed`.
        if reason == Term::atom(arinsal_term::atoms::KILL) {
            return Err(VmError::Trap(crate::exceptions::Trap::killed()));
        }
        process.heap.abi.exc.fvalue = reason.tagged_word();
        return Err(VmError::Trap(crate::exceptions::Trap::untrappable_exit(
            reason,
        )));
    }
    let mut message = Message::copy_from(reason)?;
    if alias != 0 {
        message = message.with_alias(alias);
    }
    if alias != 0 && want_priority {
        message = message.with_priority();
    }
    let _ = ctx.signal(pid, Signal::Exit(Box::new(message)));
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

fn parse_priority_opts(opts: Term) -> Result<bool, VmError> {
    let mut priority = false;
    let mut current = opts;
    while current.classify() == TermKind::List {
        // SAFETY: Option list stays rooted for this BIF call.
        let (head, tail) = unsafe { current.cons_ref() }.ok_or_else(|| badarg("badopt"))?;
        if head != Term::atom(arinsal_term::atoms::PRIORITY) {
            return Err(badarg("badopt"));
        }
        priority = true;
        current = tail;
    }
    if current != Term::NIL {
        return Err(badarg("badopt"));
    }
    Ok(priority)
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
            // Port of erl_proc_sig_queue.c:3065-3070: reply `{Ref, false}` to self.
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let reply = TermBuilder::new(&mut heap)
                .tuple(&[reference, Term::atom(arinsal_term::atoms::FALSE)])
                .map_err(|_| system_limit())?;
            process.inbox.push_back(reply);
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
