//! Process-aware BIFs. These use the running process and scheduler context.

use crate::process::{Message, Runtime};
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm;
use arinsal_sched::{Pid, Priority, RunCtx, Signal};
use arinsal_term::{Atom, Term, TermBuilder, TermKind, global_atoms, to_owned};
use std::collections::{BTreeMap, HashMap, VecDeque};
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

pub(crate) fn atom(name: &str) -> Term {
    // Predefined OTP atoms. Interning on every monitor/send/demonitor took the
    // atom-table lock on the `gen_server:call` path.
    let known = match name {
        "false" => arinsal_term::atoms::FALSE,
        "true" => arinsal_term::atoms::TRUE,
        "ok" => arinsal_term::atoms::OK,
        "DOWN" => arinsal_term::atoms::DOWN,
        "process" => arinsal_term::atoms::PROCESS,
        "port" => arinsal_term::atoms::PORT,
        "alias" => arinsal_term::atoms::ALIAS,
        "demonitor" => arinsal_term::atoms::DEMONITOR,
        "noconnect" => arinsal_term::atoms::NOCONNECT,
        "nosuspend" => arinsal_term::atoms::NOSUSPEND,
        "flush" => arinsal_term::atoms::FLUSH,
        "info" => arinsal_term::atoms::INFO,
        "badarg" => arinsal_term::atoms::BADARG,
        "noproc" => arinsal_term::atoms::NOPROC,
        "normal" => arinsal_term::atoms::NORMAL,
        "EXIT" => arinsal_term::atoms::EXIT_2,
        "kill" => arinsal_term::atoms::KILL,
        "killed" => arinsal_term::atoms::KILLED,
        "undefined" => arinsal_term::atoms::UNDEFINED,
        "error" => arinsal_term::atoms::ERROR,
        "timeout" => arinsal_term::atoms::TIMEOUT,
        "timeout_value" => arinsal_term::atoms::TIMEOUT_VALUE,
        "infinity" => arinsal_term::atoms::INFINITY,
        "monitor" => arinsal_term::atoms::MONITOR,
        "tag" => arinsal_term::atoms::TAG,
        "min_heap_size" => arinsal_term::atoms::MIN_HEAP_SIZE,
        "explicit_unalias" => arinsal_term::atoms::EXPLICIT_UNALIAS,
        "reply_demonitor" => arinsal_term::atoms::REPLY_DEMONITOR,
        "garbage_collect" => arinsal_term::atoms::GARBAGE_COLLECT,
        "async" => arinsal_term::atoms::ASYNC,
        _ => {
            return Term::atom(global_atoms().intern(name).expect("short built-in atom"));
        }
    };
    Term::atom(known)
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn badarg(_name: &str) -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("system_limit")))
}

fn runtime(process: &Process) -> Result<&Runtime, VmError> {
    process
        .runtime
        .as_deref()
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
        Err(_) => Err(crate::exceptions::Trap::error(atom("system_limit"))),
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
    let Some(arg) = crate::native_hooks::x_reg(process, 0) else {
        return 0;
    };
    // The error returns `THE_NON_VALUE` from a cold function. Building that
    // `Result` here reserved a 128-byte frame on the success path.
    let Some(name) = arg.as_atom() else {
        return whereis_not_atom(process, arg);
    };
    let Some(rt) = process.runtime.as_deref() else {
        return whereis_no_runtime(process, arg);
    };
    let term = match rt.whereis_in(process.ns, name) {
        Some(crate::register::RegId::Proc(pid)) => pid.to_term().unwrap_or_else(undefined_term),
        Some(crate::register::RegId::Port(id)) => Term::port(id).unwrap_or_else(undefined_term),
        None => undefined_term(),
    };
    crate::native_hooks::raw(term)
}

#[cold]
#[inline(never)]
fn whereis_not_atom(process: &mut Process, arg: Term) -> u64 {
    whereis_light_error(process, arg, badarg("whereis/1"))
}

#[cold]
#[inline(never)]
fn whereis_no_runtime(process: &mut Process, arg: Term) -> u64 {
    whereis_light_error(
        process,
        arg,
        VmError::Unsupported("process BIF requires a scheduler".into()),
    )
}

fn undefined_term() -> Term {
    Term::atom(arinsal_term::atoms::UNDEFINED)
}

/// `BIF_ERROR` for `whereis/1`. Cold so the direct call stays the success path.
#[cold]
#[inline(never)]
fn whereis_light_error(process: &mut Process, arg: Term, error: VmError) -> u64 {
    let mut trap = match error {
        VmError::Trap(trap) => trap,
        _ => crate::exceptions::Trap::error(atom("system_limit")),
    };
    if trap.class == arinsal_bifs::Class::Error
        && trap.top.is_none()
        && trap.trace.is_none()
        && let Ok(args) = crate::stacktrace::BifArgs::from_terms(&[arg])
        && let Ok(function) = global_atoms().intern("whereis")
    {
        trap.top = Some(crate::stacktrace::TopFrame::Bif {
            module: arinsal_term::atoms::ERLANG,
            function,
            args,
            info: crate::stacktrace::BifErrorInfo::Plain,
        });
    }
    let freason = match trap.class {
        arinsal_bifs::Class::Error => 1,
        arinsal_bifs::Class::Exit => 2,
        arinsal_bifs::Class::Throw => 3,
    };
    let fvalue = crate::native_hooks::raw(trap.reason);
    process.header.freason = freason;
    process.header.fvalue = fvalue;
    process.cold_mut().native_trap = Some(crate::proc_create::NativeTrap {
        trap,
        freason,
        fvalue,
    });
    0
}

/// `is_process_alive_1` as the BIF `call_light_bif_shared` branches to.
///
/// Port of erts/emulator/beam/erl_bif_info.c:4060-4112 (`is_process_alive_1`) and
/// jit/arm/instr_bif.cpp:434-445, OTP-29.1.1. The caller compared with
/// `BIF_P->common.id` returns `true` with no signal poll. Anything else is
/// `BIF_TRAP1` into the executor, which already runs the alive request.
pub(crate) extern "C" fn is_process_alive_light(
    header: *mut arinsal_beamasm::ProcessHeader,
    regs: *mut u64,
    _i: u64,
    _entry: u64,
    identity: u64,
) -> u64 {
    if regs.is_null() {
        return 0;
    }
    // `self_pid` is `BIF_P->common.id`. reg[0] is BIF_ARG_1, the same word in the
    // scheduler file. The export entry stays in x4.
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let self_pid = process.header.self_pid;
    let Some(arg) = crate::native_hooks::x_reg(process, 0) else {
        return 0;
    };
    if self_pid != 0 && arg.tagged_word() == self_pid {
        return crate::native_hooks::raw(Term::atom(arinsal_term::atoms::TRUE));
    }
    alive_trap(process, identity)
}

/// `BIF_TRAP1(is_process_alive_trap, ...)`: the fragment context-switches to
/// `c_p->i`, and the scheduler runs the executor body.
#[cold]
#[inline(never)]
fn alive_trap(process: &mut Process, identity: u64) -> u64 {
    process.header.i = identity as *const _;
    process.header.arity = 1;
    process.header.freason = 1 << 10;
    0
}

// Port of erts/emulator/beam/bif.c:2342 (whereis_1) and
// register.c:276 (erts_whereis_name_to_id), OTP-29.1.1:
// atom check, read lock, one hash fetch, unlock, the pid or port id.
fn whereis_1(process: &Process, name: Term) -> Result<Term, VmError> {
    let name = name.as_atom().ok_or_else(|| badarg("whereis/1"))?;
    let rt = runtime(process)?;
    Ok(match rt.whereis_in(process.ns, name) {
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

fn each_list_item(term: Term, mut visit: impl FnMut(Term)) -> Option<()> {
    let mut current = term;
    while current.classify() == TermKind::List {
        // SAFETY: The source heap remains live during this BIF call.
        let (head, tail) = unsafe { current.cons_ref()? };
        visit(head);
        current = tail;
    }
    (current == Term::NIL).then_some(())
}

pub(crate) fn list(term: Term) -> Option<Vec<Term>> {
    let mut values = Vec::new();
    each_list_item(term, |head| values.push(head))?;
    Some(values)
}

/// `demonitor/2` options, walked in place like `bif.c` `demonitor_2`.
/// `None` is a bad option list; the full BIF raises `badarg`.
fn demonitor_flags(term: Term) -> Option<(bool, bool)> {
    let flush_atom = atom("flush");
    let info_atom = atom("info");
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
    if args.len() != 2 || args[0] != atom("process") {
        return None;
    }
    let self_pid = process.header.self_pid;
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
            Term::local_ref(&mut fragment, words)
                .map_err(|_| crate::exceptions::Trap::error(atom("system_limit")))
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
    if let Some(cold) = process.cold.as_ref()
        && (cold.monitors.contains_key(&id)
            || cold.aliases.contains(&id)
            || cold.dist_monitors.contains(&id)
            || cold.port_monitors.contains_key(&id))
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
    Some(Ok(atom(if info { "false" } else { "true" })))
}

/// The trap of `demonitor(Ref, [flush])` when the monitor is already gone: the flush runs as
/// `erts_internal:flush_monitor_messages(Ref, Multi, Res)`, with `Multi` false for a plain monitor.
// Port of erts/emulator/beam/bif.c:640-654 (demonitor_2 flush_messages: BIF_TRAP3
// flush_monitor_messages_trap), OTP-29.1.1.
fn flush_monitor_trap(reference: Term, result: Term) -> VmError {
    VmError::TrapExport(crate::ExportTrap {
        continuation: FLUSH_MONITOR_CONTINUATION,
        args: vec![reference, atom("false"), result],
    })
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
pub(crate) struct NativeTimers(pub(crate) Pid);

impl TimerSink for NativeTimers {
    fn schedule_timer(
        &mut self,
        target: Pid,
        ms: u64,
        message: Message,
        wrapped: bool,
    ) -> Result<arinsal_sched::TimerRef, String> {
        match arinsal_sched::native_start_timer(self.0, target, ms, message, wrapped) {
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
        match arinsal_sched::native_start_resolved_timer(self.0, ms, resolve, message, wrapped) {
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
    let rt = process.runtime.clone().ok_or_else(|| badarg("timer/3"))?;
    // A dead pid gets a ref but no timer entry; an unresolved name can become registered
    // before its timer expires.
    let id = rt.next_ref();
    let message = Message::copy_from(message)?.with_timer_id(id);
    // setup_bif_timer: a timer for a process that does not exist is never created.
    if let Some(pid) = pid
        && !rt.scheduler().is_ok_and(|scheduler| scheduler.lookup(pid))
    {
        return reference(process, id);
    }
    let wrapped = !send_after;
    let timer = if let Some(pid) = pid {
        sink.schedule_timer(pid, ms, message, wrapped)
    } else {
        let runtime = rt.clone();
        let ns = process.ns;
        let name = registered_name.expect("resolved timer name");
        sink.schedule_resolved_timer(
            ms,
            message,
            wrapped,
            std::sync::Arc::new(move || runtime.whereis_proc_in(ns, name)),
        )
    }
    .map_err(|error| VmError::Unsupported(format!("timer: {error}")))?;
    // The timer is on the wheel of the scheduler the reference names and, when aimed at a
    // process, linked to it through that process' bif-timer word (erl_hl_timer.c:1832), so exit
    // cancels it without any table of timers.
    if let Some(pid) = pid
        && !rt.scheduler().is_ok_and(|scheduler| scheduler.lookup(pid))
        && let Ok(scheduler) = rt.scheduler()
    {
        // The receiver exited meanwhile; its exit may already have swept its timers.
        scheduler.cancel_timer_async(timer, |_| {});
    }
    reference(process, id)
}

pub(crate) fn reference(process: &mut Process, id: u64) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    Term::local_ref(&mut heap, arinsal_bifs::ordinary_ref_words(id))
        .map_err(|error| VmError::Unsupported(format!("reference allocation: {error:?}")))
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
    monitor_alias: bool,
    scheduler_id: Option<usize>,
) -> Result<Term, VmError> {
    spawn_mfa_with_priority(
        vm,
        parent,
        ctx,
        mfa,
        linked,
        monitored,
        min_heap_size,
        monitor_tag,
        monitor_alias,
        scheduler_id,
        Priority::Normal,
    )
}

/// Whether `module:function/arity` is a BIF export.
// Port of erts/emulator/beam/erl_init.c / export.c (BIF export entries carry `bif_number`,
// set once from bif.tab when the emulator starts), OTP-29.1.1.
fn is_bif_export(module: arinsal_term::Atom, function: arinsal_term::Atom, arity: u8) -> bool {
    static BIF_EXPORTS: std::sync::OnceLock<
        std::collections::HashSet<(arinsal_term::Atom, arinsal_term::Atom, u8)>,
    > = std::sync::OnceLock::new();
    BIF_EXPORTS
        .get_or_init(|| {
            let atoms = arinsal_term::global_atoms();
            arinsal_spec::BIFS
                .iter()
                .filter_map(|bif| {
                    Some((
                        atoms.intern(bif.module).ok()?,
                        atoms.intern(bif.name).ok()?,
                        bif.arity,
                    ))
                })
                .collect()
        })
        .contains(&(module, function, arity))
}

#[allow(clippy::too_many_arguments)]
// spawn_opt flags stay positional; packing them hides the monitor race.
// Port of erts/emulator/beam/erl_process.c:12222 (erts_parse_spawn_opts), OTP-29.1.1.
/// Spawn options of `erl_create_process` (erl_process.c:12437, `ErlSpawnOpts`).
pub(crate) struct ErlSpawnOpts {
    pub link: bool,
    pub monitor: Option<SpawnMonitor>,
    pub min_heap: Option<usize>,
    pub min_bin_vheap: Option<usize>,
    pub fullsweep: Option<u16>,
    pub max_heap: Option<crate::process::MaxHeap>,
    pub off_heap_queue: Option<bool>,
    pub scheduler: Option<usize>,
    pub priority: Priority,
    /// The option list as the caller gave it (`so->opts`), reported by the seq_trace spawn request.
    pub opts: Term,
    /// The spawn_request reply the parent gets (erl_process.c:13146), if one is asked for.
    pub reply: Option<SpawnReply>,
    /// Namespace of the child; the parent's when `None`.
    pub ns: Option<u32>,
    /// Group leader of the child; the parent's when `None`.
    pub group_leader: Option<Pid>,
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
    pub alias: bool,
}

/// What `erl_create_process` returns: the child and the monitor it set up, if any.
pub(crate) struct CreatedProcess {
    pub pid: Pid,
    pub monitor: Option<u64>,
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
    let m = module.as_atom().ok_or_else(|| badarg("erlang:spawn/3"))?;
    let f = function.as_atom().ok_or_else(|| badarg("erlang:spawn/3"))?;
    let args_list = list(args).ok_or_else(|| badarg("erlang:spawn/3"))?;
    if args_list.len() > 1024 {
        return Err(badarg("erlang:spawn/3"));
    }
    let rt = parent
        .runtime
        .clone()
        .ok_or_else(|| VmError::Unsupported("spawn requires a scheduler".into()))?;
    let scheduler = rt.scheduler()?;
    let defaults = crate::natives::sys::gc_spawn_defaults(Some(&rt));
    let mut child = Process::with_spawn_registers(args_list.len().max(3), 0);
    child.set_runtime(parent.runtime.clone());
    // Port of erts/emulator/beam/erl_process.c:12594 (min_heap_size rounded up by
    // erts_next_heap_size), OTP-29.1.1.
    let min_heap = crate::natives::sys::normalize_spawn_heap_minimum(
        parent.runtime.as_deref(),
        so.min_heap,
        false,
    );
    // Port of erts/emulator/beam/erl_process.c:12550-12591 (erl_create_process), OTP-29.1.1: the
    // initial heap holds the copied arguments and the reserved words, rounded up to a heap
    // size, and is never smaller than the process's minimum heap.
    let literals = arinsal_term::LiteralAreas::current();
    let heap_need =
        arinsal_term::size_object_litopt(args, &literals).saturating_add(arinsal_term::S_RESERVED);
    let heap_words = arinsal_term::spawned_heap_words(heap_need, min_heap)
        .map_err(|error| VmError::Unsupported(format!("spawn heap: {error:?}")))?;
    child.heap = arinsal_term::ProcessHeap::with_words(heap_words);
    child.heap.set_min_heap_size(min_heap);
    // Port of erts/emulator/beam/erl_process.c:12222 (erts_parse_spawn_opts), OTP-29.1.1: an
    // explicit min_bin_vheap_size alone takes the runtime default when no other heap option is set.
    let min_bin_vheap =
        if so.min_bin_vheap.is_some() && so.min_heap.is_none() && so.max_heap.is_none() {
            defaults.min_bin_vheap_size as usize
        } else {
            crate::natives::sys::normalize_spawn_heap_minimum(
                parent.runtime.as_deref(),
                so.min_bin_vheap,
                true,
            )
        };
    child.heap.set_min_bin_vheap_size(min_bin_vheap as u64);
    let fullsweep_after = so.fullsweep.unwrap_or(defaults.fullsweep_after);
    child.heap.set_fullsweep_after(fullsweep_after);
    let max_heap = so.max_heap.unwrap_or(defaults.max_heap_size);
    if !crate::natives::proc::is_default_max_heap(max_heap) {
        child.cold_mut().max_heap = max_heap;
    }
    if let Some(off_heap) = so.off_heap_queue {
        child.cold_mut().off_heap_msgq = off_heap;
    }
    // `p->u.initial` is the spawned MFA, reported by process_info(initial_call); `p->i` is the
    // apply/3 entry the child starts at.
    // Port of erts/emulator/beam/erl_process.c:12616 (`p->i = beam_run_process`): the child starts at
    // the apply_only sentinel; its first run applies X0..X2 (Vm::resolve_run_process).
    child.module = crate::process::RUN_PROCESS;
    child.ip = 0;
    child.initial_mfa = Some((m, f, args_list.len() as u8));
    if let Ok(arity) = u8::try_from(args_list.len())
        && is_bif_export(m, f, arity)
        && let (Some(m_name), Some(f_name)) = (atom_name(module), atom_name(function))
    {
        child.cold_mut().initial_bif = Some((m_name, f_name, arity));
    }
    child.group_leader = Some(
        so.group_leader
            .unwrap_or_else(|| parent.group_leader_pid(ctx.pid())),
    );
    child.parent = Some(ctx.pid());
    child.code_chain = parent.code_chain.clone();
    child.ns = so.ns.unwrap_or(parent.ns);
    // Port of erts/emulator/beam/erl_process.c:12546,12638 (erl_create_process: `args` is copied
    // with copy_struct_litopt and the three arg registers take mod, func and the copy), OTP-29.1.1.
    let copied_args = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut child.heap);
        arinsal_term::copy_term_litopt(args, &mut heap, &literals)
            .map_err(|error| VmError::Unsupported(format!("spawn arguments: {error:?}")))?
    };
    child.x[0] = module;
    child.x[1] = function;
    child.x[2] = copied_args;
    // The link and monitor must be on the child before enqueue. Another scheduler can run
    // `code_server`'s on_load fun to `exit/1` before a Monitor signal sent after `spawn` is
    // delivered, and the DOWN is then lost. Port of erts/emulator/beam/erl_process.c
    // (spawn_opt monitor before schedule), OTP-29.1.1.
    let parent_pid = ctx.pid();
    if so.link {
        child.cold_mut().links.insert(parent_pid);
    }
    let monitor_id = so
        .monitor
        .as_ref()
        .map(|monitor| monitor.id.unwrap_or_else(arinsal_bifs::next_ref_id));
    // Both halves of a spawn monitor share its data (erts `ErtsMonitorData`).
    let monitor_data = so
        .monitor
        .as_ref()
        .map(|monitor| match monitor.tag.clone() {
            Some(tag) => std::sync::Arc::new(crate::proc_create::MonitorData {
                tag: Some(tag),
                name: None,
            }),
            None => crate::proc_create::default_monitor_data(),
        });
    if let (Some(id), Some(data)) = (monitor_id, monitor_data.as_ref()) {
        child.cold_mut().monitored_by.insert(
            id,
            crate::proc_create::TargetHalf {
                origin: parent_pid,
                data: data.clone(),
            },
        );
    }
    let seq_spawn = if crate::seq_trace::has_token(parent) {
        crate::seq_trace::spawn_prepare(parent, parent_pid, &mut child)
    } else {
        None
    };
    let child_ns = child.ns;
    if child_ns != 0 && rt.namespaces.live(child_ns).is_none() {
        return Err(system_limit());
    }
    let pid = scheduler
        .spawn_unscheduled_in_ns(child, so.priority, so.scheduler, child_ns)
        .map_err(|error| VmError::Unsupported(format!("spawn: {error}")))?;
    if so.link {
        parent.cold_mut().links.insert(pid);
    }
    if crate::trace::spawn_interested(parent, parent_pid) {
        let arg_list = TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut parent.heap))
            .list_from_iter(args_list.iter().copied())
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
                atom("spawn_reply"),
                crate::signals::reference(parent, arinsal_bifs::next_ref_id())?,
            ),
        };
        let arity = Term::small(args_list.len() as i64).unwrap_or(Term::NIL);
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
    if let (Some(id), Some(data), Some(monitor)) = (monitor_id, monitor_data, so.monitor.as_ref()) {
        parent
            .cold_mut()
            .monitors
            .insert(id, crate::proc_create::OriginHalf { target: pid, data });
        if monitor.alias {
            parent.cold_mut().aliases.insert(id);
            rt.alias_bind(id, Some(parent_pid));
        }
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
                .tuple(&[reply.tag, reply.reference, atom("ok"), pid_term])
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
    ctx.schedule_spawn(pid)
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
    linked: bool,
    monitored: bool,
    min_heap_size: Option<usize>,
    monitor_tag: Option<arinsal_etf::OwnedTerm>,
    monitor_alias: bool,
    scheduler_id: Option<usize>,
    priority: Priority,
) -> Result<Term, VmError> {
    // Spawn options reach the child set-up through the thread-local tuning, as erts passes
    // `ErlSpawnOpts` down; `take` clears it on every path.
    let tuning = SpawnTuning::take();
    let created = erl_create_process(
        vm,
        parent,
        ctx,
        mfa,
        ErlSpawnOpts {
            link: linked,
            monitor: monitored.then_some(SpawnMonitor {
                id: None,
                tag: monitor_tag,
                alias: monitor_alias,
            }),
            min_heap: min_heap_size,
            min_bin_vheap: tuning.min_bin_vheap,
            fullsweep: tuning.fullsweep,
            max_heap: tuning.max_heap,
            off_heap_queue: tuning.off_heap_queue,
            scheduler: scheduler_id,
            priority,
            opts: tuning.options.unwrap_or(Term::NIL),
            reply: None,
            ns: None,
            group_leader: None,
        },
    )?;
    let pid_term = created
        .pid
        .to_term()
        .ok_or_else(|| VmError::Unsupported("pid limit".into()))?;
    let Some(id) = created.monitor else {
        return Ok(pid_term);
    };
    let ref_term = reference(parent, id)?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut parent.heap);
    TermBuilder::new(&mut heap)
        .tuple(&[pid_term, ref_term])
        .map_err(|error| VmError::Unsupported(format!("spawn result: {error:?}")))
}

/// `spawn_opt` GC and mailbox options that the child must carry from its first slice.
///
/// Port of erts/emulator/beam/erl_process.c:12222 (`erts_parse_spawn_opts`), OTP-29.1.1.
/// The spawn helpers take it through a thread-local so their positional flag lists stay frozen.
#[derive(Clone, Copy, Default)]
pub(crate) struct SpawnTuning {
    options: Option<Term>,
    max_heap: Option<crate::process::MaxHeap>,
    fullsweep: Option<u16>,
    min_bin_vheap: Option<usize>,
    off_heap_queue: Option<bool>,
}

thread_local! {
    static SPAWN_TUNING: std::cell::Cell<SpawnTuning> = std::cell::Cell::new(SpawnTuning::default());
}

impl SpawnTuning {
    /// Run `spawn` with this tuning visible to the child set-up, clearing it on every exit path.
    fn around<T>(self, spawn: impl FnOnce() -> T) -> T {
        SPAWN_TUNING.with(|cell| cell.set(self));
        let result = spawn();
        SPAWN_TUNING.with(|cell| cell.set(SpawnTuning::default()));
        result
    }

    fn take() -> SpawnTuning {
        SPAWN_TUNING.with(std::cell::Cell::take)
    }
}

struct SpawnOpts {
    tuning: SpawnTuning,
    link: bool,
    monitor: bool,
    monitor_tag: Option<arinsal_etf::OwnedTerm>,
    monitor_alias: bool,
    min_heap_size: Option<usize>,
    scheduler: Option<usize>,
    priority: Priority,
}

// Port of erts/emulator/beam/erl_process.c:12222 (erts_parse_spawn_opts), OTP-29.1.1.
fn spawn_options(runtime: Option<&Runtime>, term: Term) -> Result<SpawnOpts, VmError> {
    let mut opts = SpawnOpts {
        tuning: SpawnTuning {
            options: Some(term),
            ..SpawnTuning::default()
        },
        link: false,
        monitor: false,
        monitor_tag: None,
        monitor_alias: false,
        min_heap_size: None,
        scheduler: None,
        priority: Priority::Normal,
    };
    for option in list(term).ok_or_else(|| badarg("erlang:spawn_opt"))? {
        if option == atom("link") {
            opts.link = true;
        } else if option == atom("monitor") {
            opts.monitor = true;
        } else if option.classify() == TermKind::Tuple {
            // SAFETY: The option term remains in the caller's live heap.
            let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("erlang:spawn_opt"))?;
            if tuple.len() == 2 && tuple.get(0) == Some(atom("min_heap_size")) {
                let words = tuple
                    .get(1)
                    .and_then(Term::as_small)
                    .filter(|&words| words >= 0)
                    .ok_or_else(|| badarg("erlang:spawn_opt"))?;
                opts.min_heap_size = Some(words as usize);
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("monitor")) {
                // code_server:spawn_opt(Fun, [{monitor, [{tag, {'ON_LOAD_DOWN', Mod}}]}]).
                // Port of erl_process.c spawn option `{monitor, MonitorOpts}`, OTP-29.1.1.
                opts.monitor = true;
                let items = list(tuple.get(1).ok_or_else(|| badarg("erlang:spawn_opt"))?)
                    .ok_or_else(|| badarg("erlang:spawn_opt"))?;
                for item in items {
                    // SAFETY: Each option stays rooted in the caller's heap.
                    let item =
                        unsafe { item.tuple_ref() }.ok_or_else(|| badarg("erlang:spawn_opt"))?;
                    if item.len() != 2 {
                        return Err(badarg("erlang:spawn_opt"));
                    }
                    match (item.get(0), item.get(1)) {
                        (Some(key), Some(value)) if key == atom("tag") => {
                            opts.monitor_tag =
                                Some(arinsal_term::to_owned(value).map_err(|error| {
                                    VmError::Unsupported(format!("monitor tag: {error:?}"))
                                })?);
                        }
                        (Some(key), Some(value))
                            if key == atom("alias")
                                && atom_name(value).is_some_and(|name| {
                                    matches!(
                                        name.as_str(),
                                        "explicit_unalias" | "demonitor" | "reply_demonitor"
                                    )
                                }) =>
                        {
                            opts.monitor_alias = true;
                        }
                        _ => return Err(badarg("erlang:spawn_opt")),
                    }
                }
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("priority")) {
                opts.priority =
                    match atom_name(tuple.get(1).ok_or_else(|| badarg("erlang:spawn_opt"))?)
                        .as_deref()
                    {
                        Some("low") => Priority::Low,
                        Some("normal") => Priority::Normal,
                        Some("high") => Priority::High,
                        Some("max") => Priority::Max,
                        _ => return Err(badarg("erlang:spawn_opt")),
                    };
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("max_heap_size")) {
                opts.tuning.max_heap = Some(
                    crate::natives::proc::parse_max_heap_from(
                        tuple.get(1).ok_or_else(|| badarg("erlang:spawn_opt"))?,
                        crate::natives::sys::gc_spawn_defaults(runtime).max_heap_size,
                    )
                    .map_err(|()| badarg("erlang:spawn_opt"))?,
                );
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("fullsweep_after")) {
                let value = tuple
                    .get(1)
                    .and_then(Term::as_small)
                    .filter(|&value| value >= 0)
                    .ok_or_else(|| badarg("erlang:spawn_opt"))?;
                opts.tuning.fullsweep = Some(value.min(i64::from(u16::MAX)) as u16);
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("min_bin_vheap_size")) {
                let value = tuple
                    .get(1)
                    .and_then(Term::as_small)
                    .filter(|&value| value >= 0)
                    .ok_or_else(|| badarg("erlang:spawn_opt"))?;
                opts.tuning.min_bin_vheap = Some(value as usize);
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("message_queue_data")) {
                match tuple.get(1) {
                    Some(value) if value == atom("off_heap") => {
                        opts.tuning.off_heap_queue = Some(true);
                    }
                    Some(value) if value == atom("on_heap") => {
                        opts.tuning.off_heap_queue = Some(false);
                    }
                    _ => return Err(badarg("erlang:spawn_opt")),
                }
            } else if tuple.len() == 2
                && tuple
                    .get(0)
                    .and_then(atom_name)
                    .is_some_and(|name| matches!(name.as_str(), "async_dist"))
            {
                // Accepted; async_dist is applied through process_flag.
            } else if tuple.len() == 2 && tuple.get(0) == Some(atom("scheduler")) {
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
    }
    // The child keeps the system default virtual binary heap minimum unless `min_heap_size` or
    // `max_heap_size` is also given (verified against `erl` 29.1.1).
    if opts.min_heap_size.is_none() && opts.tuning.max_heap.is_none() {
        opts.tuning.min_bin_vheap = None;
    }
    let min_heap =
        crate::natives::sys::normalize_spawn_heap_minimum(runtime, opts.min_heap_size, false);
    if opts
        .tuning
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
        if tuple.len() != 2 || tuple.get(0) != Some(atom("abs")) {
            return Err(badarg("timer options"));
        }
        match tuple.get(1) {
            Some(value) if value == atom("false") => {}
            Some(value) if value == atom("true") => absolute = true,
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
            (Some(name), Some(value)) if name == atom("async") && value == atom("false") => {
                asynchronous = false;
            }
            (Some(name), Some(value)) if name == atom("async") && value == atom("true") => {
                asynchronous = true;
            }
            (Some(name), Some(value)) if cancel && name == atom("info") => {
                if value == atom("false") {
                    info = false;
                } else if value == atom("true") {
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
) -> Result<Term, VmError> {
    let id = ref_id(reference).ok_or_else(|| {
        badarg(if cancel {
            "cancel_timer/1"
        } else {
            "read_timer/1"
        })
    })?;
    if let Some(done) = poll(process)? {
        return Ok(done);
    }
    let rt = runtime(process)?;
    let timer = rt
        .scheduler()
        .ok()
        .map(|scheduler| scheduler.timer_for_ref_key(id));
    access_timer_sync(process, caller, reference, timer, cancel, info)
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
) -> Result<Term, VmError> {
    let rt = runtime(process)?;
    let (Some(timer), Ok(scheduler)) = (timer, rt.scheduler()) else {
        return Ok(atom(if info { "false" } else { "ok" }));
    };
    // The owning scheduler answers directly, without a request or a reply.
    if let Some(remaining) = scheduler.try_access_timer_local(timer, cancel) {
        let value = remaining
            .and_then(|ms| Term::small(ms as i64))
            .unwrap_or_else(|| atom("false"));
        return Ok(if info { value } else { atom("ok") });
    }
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
            .unwrap_or_else(|| atom("false"));
        return Ok(if info { value } else { atom("ok") });
    }
    let id = rt.next_ref();
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
    process.pending_signal_waiter = Some(Waiter {
        id,
        kind: WaitKind::Info,
        save: process.inbox.len(),
    });
    *guard = TimerAccess::Parked {
        target: caller,
        reply,
        info,
        scheduler,
    };
    Err(await_reply())
}

fn system_process(vm: &Vm, process: &Process, pid: Pid, names: &[&str]) -> bool {
    if names.contains(&"erts_dirty_process_signal_handler")
        && process
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.dirty_signal_handlers.lock().unwrap().contains(&pid))
    {
        return true;
    }
    let registered = process.runtime.as_ref().is_some_and(|runtime| {
        runtime
            .scheduler()
            .ok()
            .and_then(|scheduler| scheduler.registered_atom_index(pid))
            .is_some_and(|index| {
                names
                    .iter()
                    .any(|name| global_atoms().get(name).is_some_and(|atom| atom.0 == index))
            })
    });
    if registered {
        return true;
    }
    vm.code
        .modules
        .get(process.module)
        .is_some_and(|module| names.iter().any(|name| module.name == *name))
}

// Port of erts/emulator/beam/erl_proc_sig_queue.c:8893
// (erts_internal_dirty_process_handle_signals_1), OTP-29.1.1.
fn dirty_process_handle_signals(
    vm: &mut Vm,
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
) -> Result<Term, VmError> {
    if !system_process(
        vm,
        process,
        ctx.pid(),
        &[
            "erts_dirty_process_signal_handler",
            "erts_dirty_process_signal_handler_high",
            "erts_dirty_process_signal_handler_max",
        ],
    ) {
        return Err(VmError::Trap(crate::exceptions::Trap::error(atom(
            "notsup",
        ))));
    }
    let Some(pid) = Pid::from_term(target) else {
        return Ok(atom("false"));
    };
    let result = ctx.handle_dirty_signals(pid, &mut |task, target_ctx| {
        task.downcast_mut::<Process>()
            .is_none_or(|target| target.handle_dirty_signals(vm, target_ctx))
    });
    Ok(atom(match result {
        arinsal_sched::DirtySignals::NoProc => "noproc",
        arinsal_sched::DirtySignals::Normal => "normal",
        arinsal_sched::DirtySignals::More => "more",
        arinsal_sched::DirtySignals::Idle | arinsal_sched::DirtySignals::Handled => "ok",
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
    ctx.send_runtime(to, Message::copy_from(message)?)
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
                let message =
                    task_tuple(process, &[atom("garbage_collect"), req_id, atom("true")])?;
                deliver(process, ctx, requester, message)?;
                return Ok(atom("ok"));
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
            Submit::Sent(_)
        )
    {
        return Ok(atom("ok"));
    }
    // Port of erts/emulator/beam/erl_process.c:11466 (noproc: notify_sys_task_executed), OTP-29.1.1.
    let message = task_tuple(process, &[atom(tag), req_id, atom("false")])?;
    deliver(process, ctx, requester, message)?;
    Ok(atom("ok"))
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
    ("erlang", "exit", 1),
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
    let options = list(args[2]).ok_or_else(|| badarg("erlang:send/3"))?;
    let mut want_priority = false;
    let mut nosuspend = false;
    for option in &options {
        if *option == atom("priority") {
            want_priority = true;
        } else if *option == atom("nosuspend") {
            nosuspend = true;
        } else if *option != atom("noconnect") {
            return Err(badarg("erlang:send/3"));
        }
    }
    if nosuspend {
        // Port of erts/emulator/beam/bif.c:2390 (send_3): a busy port gives `nosuspend`.
        let (sent, busy) = crate::port::send_nosuspend(|| {
            process.send_message_prio(Some(vm), Some(ctx), args[0], args[1], want_priority)
        });
        sent?;
        return Ok(atom(if busy { "nosuspend" } else { "ok" }));
    }
    process.send_message_prio(Some(vm), Some(ctx), args[0], args[1], want_priority)?;
    Ok(atom("ok"))
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
    Exit1,
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
    let ns = process.ns;
    let rt = std::sync::Arc::clone(process.runtime.as_ref()?);
    let scheduler = rt.scheduler().ok()?;
    let reg = rt.reg_for(ns)?;
    let mut table = reg.write();
    if !scheduler.lookup(pid)
        || (ns != 0 && !same_ns(&scheduler, pid, ns))
        || scheduler.registered_atom_index(pid).is_some()
        || table.contains(name)
        || !rt.publish_proc_flag(pid, arinsal_sched::proc_flags::REG)
    {
        return None;
    }
    table.insert_proc(name, pid);
    scheduler.set_registered_atom_index(pid, name.0);
    drop(table);
    Some(Ok(atom("true")))
}

/// True when `pid` lives in namespace `ns`.
fn same_ns(scheduler: &arinsal_sched::Scheduler<Process>, pid: Pid, ns: u32) -> bool {
    scheduler
        .ns_word(pid)
        .is_some_and(|word| word & arinsal_sched::NS_ID_MASK == ns)
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
    let ns = process.ns;
    let rt = std::sync::Arc::clone(process.runtime.as_ref()?);
    let reg = rt.reg_for(ns)?;
    let mut table = reg.write();
    let Some(crate::register::RegId::Proc(pid)) = table.fetch(name) else {
        return None;
    };
    let _ = table.erase(name);
    if let Ok(scheduler) = rt.scheduler() {
        scheduler.clear_registered_atom_index(pid, name.0);
    }
    drop(table);
    Some(Ok(atom("true")))
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
    let [kind, target] = args else {
        return None;
    };
    if *kind != atom("process") || crate::trace::active() {
        return None;
    }
    let me = process.self_pid?;
    let pid = Pid::from_term(*target)?;
    if pid == me {
        return None;
    }
    let rt = std::sync::Arc::clone(process.runtime.as_ref()?);
    if !rt.scheduler().ok()?.lookup(pid) {
        return None;
    }
    let id = rt.next_ref();
    let ref_term = reference(process, id).ok()?;
    let data = crate::proc_create::default_monitor_data();
    process.cold_mut().monitors.insert(
        id,
        crate::proc_create::OriginHalf {
            target: pid,
            data: data.clone(),
        },
    );
    if rt
        .scheduler()
        .ok()?
        .signal_ordered(
            me,
            pid,
            arinsal_sched::Signal::Monitor {
                reference: id,
                shared: arinsal_sched::SharedPayload(data),
            },
        )
        .is_err()
    {
        process.cold_mut().monitors.remove(&id);
        return None;
    }
    Some(Ok(ref_term))
}

/// `demonitor(Ref)` / `demonitor(Ref, Opts)` called directly from native code (erts bif.c:437-454
/// and the local monitor case). Aliases, port and remote monitors take the executor. A flush
/// with the monitor already gone traps to `flush_monitor_messages`, so that case also falls back.
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
    let cold = process.cold.as_ref()?;
    if cold.aliases.contains(&id)
        || cold.dist_monitors.contains(&id)
        || cold.port_monitors.contains_key(&id)
    {
        return None;
    }
    let active = cold.monitors.get(&id).map(|half| half.target);
    if active.is_none() && flush {
        return None;
    }
    let me = process.self_pid?;
    let rt = std::sync::Arc::clone(process.runtime.as_ref()?);
    let scheduler = rt.scheduler().ok()?;
    let result = if let Some(pid) = active {
        process.cold_mut().monitors.remove(&id);
        // erts consumes the held process monitor instead of sending the demonitor when it can
        // (erl_proc_sig_queue.c:1104). The executor ignores a dead target here as well.
        if !flush || !scheduler.cancel_pending_monitor(pid, id) {
            let _ = scheduler.signal_ordered(me, pid, arinsal_sched::Signal::Demonitor(id));
        }
        atom("true")
    } else {
        atom(if info { "false" } else { "true" })
    };
    Some(Ok(result))
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
    let rt = std::sync::Arc::clone(process.runtime.as_ref()?);
    let id = rt.next_ref();
    process.cold_mut().unlinking.insert(id, pid);
    let _ = rt
        .scheduler()
        .ok()?
        .signal_ordered(me, pid, arinsal_sched::Signal::Unlink(id));
    Some(Ok(atom("true")))
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
    let rt = std::sync::Arc::clone(process.runtime.as_ref()?);
    if !rt.scheduler().ok()?.lookup(pid) {
        return None;
    }
    // A refused signal means the target is gone: leave the link state untouched and let the
    // executor answer noproc.
    rt.scheduler()
        .ok()?
        .signal_ordered(me, pid, arinsal_sched::Signal::Link)
        .ok()?;
    process.cold_mut().links.insert(pid);
    process.cold_mut().prio_links.remove(&pid);
    Some(Ok(atom("true")))
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
    let rt = std::sync::Arc::clone(process.runtime.as_ref()?);
    let _ = rt
        .scheduler()
        .ok()?
        .signal_ordered(me, pid, arinsal_sched::Signal::Exit(message));
    Some(Ok(atom("true")))
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
resolved_signal_handler!(exit1, Exit1);
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
        ("erlang", "exit", 1) => exit1,
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
            false,
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
            false,
            None,
        ),
        (SignalBif::SpawnOpt4, [module, function, args, options]) => {
            spawn_options(process.runtime.as_deref(), *options).and_then(|opts| {
                opts.tuning.around(|| {
                    spawn_mfa_with_priority(
                        vm,
                        process,
                        ctx,
                        (*module, *function, *args),
                        opts.link,
                        opts.monitor,
                        opts.min_heap_size,
                        opts.monitor_tag,
                        opts.monitor_alias,
                        opts.scheduler,
                        opts.priority,
                    )
                })
            })
        }
        (SignalBif::Register2, [name, id]) => {
            let name = name.as_atom().ok_or_else(|| badarg("register/2"))?;
            // Port of erts/emulator/beam/register.c:184 (erts_register_name): `undefined` is not a name.
            if name == arinsal_term::atoms::UNDEFINED {
                return Err(badarg("register/2"));
            }
            let rt = std::sync::Arc::clone(
                process
                    .runtime
                    .as_ref()
                    .ok_or_else(|| badarg("register/2"))?,
            );
            let scheduler = rt.scheduler()?;
            let ns = process.ns;
            let reg = rt.reg_for(ns).ok_or_else(|| badarg("register/2"))?;
            if let Some(pid) = Pid::from_term(*id) {
                let mut table = reg.write();
                if !scheduler.lookup(pid)
                    || (ns != 0 && !same_ns(&scheduler, pid, ns))
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
                Ok(atom("true"))
            } else if let Some(port_id) = id.as_port() {
                if ns != 0 {
                    return Err(badarg("register/2"));
                }
                let handle = {
                    let ports = rt.ports.lock().unwrap();
                    let handle = ports
                        .get(&port_id)
                        .cloned()
                        .ok_or_else(|| badarg("register/2"))?;
                    if handle.exit_complete() {
                        return Err(badarg("register/2"));
                    }
                    handle
                };
                let mut table = reg.write();
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
                    &rt,
                    port_id,
                    crate::trace::PORTS,
                    "register",
                    &[Term::atom(name)],
                );
                Ok(atom("true"))
            } else {
                Err(badarg("register/2"))
            }
        }
        (SignalBif::Unregister1, [name]) => {
            let name = name.as_atom().ok_or_else(|| badarg("unregister/1"))?;
            let rt = std::sync::Arc::clone(
                process
                    .runtime
                    .as_ref()
                    .ok_or_else(|| badarg("unregister/1"))?,
            );
            let reg = rt
                .reg_for(process.ns)
                .ok_or_else(|| badarg("unregister/1"))?;
            let mut table = reg.write();
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
                    Ok(atom("true"))
                }
                Some(crate::register::RegId::Port(port_id)) => {
                    drop(table);
                    crate::trace::emit_port_event(
                        &rt,
                        port_id,
                        crate::trace::PORTS,
                        "unregister",
                        &[Term::atom(name)],
                    );
                    Ok(atom("true"))
                }
                None => Err(badarg("unregister/1")),
            }
        }
        (SignalBif::Whereis1, [name]) => whereis_1(process, *name),
        (SignalBif::Registered0, []) => {
            let rt = runtime(process)?;
            // Snapshot under the read lock, then build the list. Order is the
            // reverse bucket walk from register.c:567.
            let reg = rt
                .reg_for(process.ns)
                .ok_or_else(|| badarg("registered/0"))?;
            let names: Vec<Term> = reg
                .read()
                .registered_atoms()
                .into_iter()
                .map(Term::atom)
                .collect();
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            TermBuilder::new(&mut heap)
                .list_from_iter(names)
                .map_err(|error| VmError::Unsupported(format!("registered list: {error:?}")))
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
            Ok(atom("true"))
        }
        (SignalBif::Unlink1, [pid]) => {
            let pid = Pid::from_term(*pid).ok_or_else(|| badarg("unlink/1"));
            pid.map(|pid| {
                let id = process
                    .runtime
                    .as_ref()
                    .map_or(1, |runtime| runtime.next_ref());
                process.cold_mut().unlinking.insert(id, pid);
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
                let _ = ctx.signal(pid, Signal::Unlink(id));
                wake_for_procs_trace(process, ctx, pid);
                atom("true")
            })
        }
        (SignalBif::Monitor2, [kind, target]) | (SignalBif::Monitor3, [kind, target, _])
            if *kind == atom("process") =>
        {
            let (tag, alias, priority) = monitor_options(args)?;
            let rt = process.runtime.clone().ok_or_else(|| badarg("monitor/2"))?;
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
                rt.whereis_proc_str_in(process.ns, name)
            } else if matches!(to_owned(*target), Ok(arinsal_etf::OwnedTerm::Pid { .. })) {
                // A pid of another incarnation of this node never matches a live process.
                None
            } else {
                return Err(badarg("monitor/2"));
            };
            let id = rt.next_ref();
            let ref_term = reference(process, id)?;
            // Port of erts/emulator/beam/bif.c:782-784 (monitor), OTP-29.1.1.
            // Monitoring oneself creates no monitor and sends no signal.
            if name.is_none() && pid == Some(ctx.pid()) {
                return Ok(ref_term);
            }
            // The default `DOWN` tag without a name is the shared default data: no allocation.
            let data = monitor_data_for(tag, name.as_deref())?;
            if alias {
                process.cold_mut().aliases.insert(id);
                // Monitor aliases with `priority` are priority aliases.
                rt.alias_bind_prio(id, Some(ctx.pid()), priority);
            }
            if priority {
                process.cold_mut().prio_monitors.insert(id);
            }
            if let Some(pid) = pid.filter(|pid| rt.scheduler().is_ok_and(|s| s.lookup(*pid))) {
                process.cold_mut().monitors.insert(
                    id,
                    crate::proc_create::OriginHalf {
                        target: pid,
                        data: data.clone(),
                    },
                );
                // The target half shares this object (erts: one ErtsMonitorData for both halves).
                let signal = arinsal_sched::Signal::Monitor {
                    reference: id,
                    shared: arinsal_sched::SharedPayload(data.clone()),
                };
                if let Err(error) = ctx.signal(pid, signal) {
                    process.cold_mut().monitors.remove(&id);
                    if error != arinsal_sched::Error::NoProcess {
                        return Err(VmError::Unsupported(format!("monitor: {error}")));
                    }
                    // The target stopped accepting monitor signals before this request.
                    send_noproc_down(process, ctx, id, name.as_deref(), Some(pid), *target, tag)?;
                }
            } else {
                send_noproc_down(process, ctx, id, name.as_deref(), pid, *target, tag)?;
            }
            Ok(ref_term)
        }
        (SignalBif::Monitor2, [kind, target]) if *kind == atom("time_offset") => {
            // Port of erts/emulator/beam/erl_time_sup.c:1964-1968
            // (erts_monitor_time_offset), OTP-29.1.1. There is no clock warp
            // source in this runtime, but monitor creation still returns a ref.
            if *target != atom("clock_service") {
                return Err(badarg("monitor/2"));
            }
            let runtime = process.runtime.clone().ok_or_else(|| badarg("monitor/2"))?;
            let id = runtime.next_ref();
            reference(process, id)
        }
        (SignalBif::Monitor2, [kind, target]) | (SignalBif::Monitor3, [kind, target, _])
            if *kind == atom("port") =>
        {
            let (tag, alias, _priority) = monitor_options(args)?;
            let runtime = process.runtime.clone().ok_or_else(|| badarg("monitor/2"))?;
            let reference_id = runtime.next_ref();
            let reference_term = reference(process, reference_id)?;
            if alias {
                process.cold_mut().aliases.insert(reference_id);
                runtime.alias_bind_prio(reference_id, Some(ctx.pid()), false);
            }
            let (port_id, object) = if let Some(id) = target.as_port() {
                (
                    Some(id),
                    to_owned(*target).map_err(|_| badarg("monitor/2"))?,
                )
            } else if let Some(name) = atom_name(*target).or_else(|| {
                crate::dist::name_node_tuple(*target)
                    .ok()
                    .flatten()
                    .map(|(name, _node)| name)
            }) {
                let id = if process.ns == 0 {
                    runtime.reg.whereis_port_str(&name)
                } else {
                    None
                };
                let node = crate::node_tables::lock().local_name.clone();
                (
                    id,
                    arinsal_etf::OwnedTerm::Tuple(vec![
                        arinsal_etf::OwnedTerm::Atom(name),
                        arinsal_etf::OwnedTerm::Atom(node),
                    ]),
                )
            } else if let Ok(object @ arinsal_etf::OwnedTerm::Port { .. }) = to_owned(*target) {
                // Port of erts/emulator/beam/bif.c:923 (monitor/3): a port of another node is badarg;
                // a port of another incarnation of this node never matches a live port.
                if let arinsal_etf::OwnedTerm::Port { node, .. } = &object
                    && *node != crate::node_tables::lock().local_name
                {
                    return Err(badarg("monitor/2"));
                }
                (None, object)
            } else {
                return Err(badarg("monitor/2"));
            };
            if let Some(id) = port_id.filter(|id| runtime.ports.lock().unwrap().contains_key(id)) {
                if tag != atom("DOWN") {
                    // Port monitors carry no tag yet (typed gap, see report).
                    return Err(VmError::Unsupported("monitor(port, _, [{tag, _}])".into()));
                }
                let port = Term::port(id).ok_or_else(|| badarg("monitor/2"))?;
                if !crate::port::monitor(
                    process,
                    port,
                    reference_id,
                    ctx.pid(),
                    object.clone(),
                    true,
                )? {
                    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                    let object = arinsal_term::from_owned(&object, &mut heap)
                        .map_err(|_| badarg("monitor/2"))?;
                    let down = TermBuilder::new(&mut heap)
                        .tuple(&[tag, reference_term, atom("port"), object, atom("noproc")])
                        .map_err(|error| {
                            VmError::Unsupported(format!("port DOWN tuple: {error:?}"))
                        })?;
                    process.inbox.push_back(down);
                } else {
                    // Origin stays in this process; the target half is on the port.
                    process.cold_mut().port_monitors.insert(reference_id, id);
                }
                Ok(reference_term)
            } else {
                let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                let object = arinsal_term::from_owned(&object, &mut heap)
                    .map_err(|_| badarg("monitor/2"))?;
                let down = TermBuilder::new(&mut heap)
                    .tuple(&[tag, reference_term, atom("port"), object, atom("noproc")])
                    .map_err(|error| VmError::Unsupported(format!("port DOWN tuple: {error:?}")))?;
                process.inbox.push_back(down);
                Ok(reference_term)
            }
        }
        (SignalBif::Demonitor1, [reference]) | (SignalBif::Demonitor2, [reference, _]) => {
            let id = ref_id(*reference).ok_or_else(|| badarg("demonitor/1"))?;
            let options = if args.len() == 2 {
                list(args[1]).ok_or_else(|| badarg("demonitor/2"))?
            } else {
                Vec::new()
            };
            if options
                .iter()
                .any(|option| *option != atom("flush") && *option != atom("info"))
            {
                return Err(badarg("demonitor/2"));
            }
            let flush = options.contains(&atom("flush"));
            let mut was_active = if let Some(pid) = process
                .cold
                .as_mut()
                .and_then(|cold| cold.monitors.remove(&id))
                .map(|half| half.target)
            {
                if !flush || !ctx.cancel_pending_monitor(pid, id) {
                    let _ = ctx.signal(pid, Signal::Demonitor(id));
                }
                true
            } else {
                false
            };
            let alias_active = process
                .cold
                .as_mut()
                .is_some_and(|cold| cold.aliases.remove(&id));
            if alias_active && let Some(runtime) = &process.runtime {
                runtime.alias_bind(id, None);
            }
            // Port of erts/emulator/beam/bif.c:504-510 (demonitor, ERTS_MON_TYPE_PORT),
            // OTP-29.1.1: the origin is in this process's monitor tree. The port id
            // there selects the port; `erts_port_demonitor` sends the demonitor signal.
            if let Some(port_id) = process
                .cold
                .as_mut()
                .and_then(|cold| cold.port_monitors.remove(&id))
            {
                crate::port::demonitor_port(process, ctx.pid(), port_id, id);
                was_active = true;
            }
            // Port of erts/emulator/beam/bif.c:640-654 (demonitor_2), OTP-29.1.1.
            // Flush runs only when the monitor is already gone (`am_false`). An
            // active process monitor just queues the demonitor signal.
            let result = atom(if options.contains(&atom("info")) && !was_active {
                "false"
            } else {
                "true"
            });
            if flush && !was_active {
                return Err(flush_monitor_trap(*reference, result));
            }
            Ok(result)
        }
        (SignalBif::Exit1, [reason]) => {
            process.note_exit_reason(*reason)?;
            Err(VmError::Trap(crate::exceptions::Trap::exit(*reason)))
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
        (SignalBif::TraceCleanerCheck0, []) => Ok(atom("false")),
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
                return timer_query_sync(process, ctx.pid(), *reference, true, options.info);
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
                return Ok(atom("ok"));
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
                return timer_query_sync(process, ctx.pid(), *reference, false, options.info);
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
                return Ok(atom("ok"));
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
                false,
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
    /// `garbage_collect` request. `request_id` is the term in the reply tuple.
    Collect { request_id: Message, major: bool },
    /// `process_display(Pid, backtrace)`.
    Display,
    /// `is_process_alive/1` signal-ordering probe.
    Alive,
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

/// How the caller extracts the reply once it is in the mailbox.
#[derive(Clone, Copy)]
pub(crate) enum WaitKind {
    /// `{Ref, Result}` and `Result` is the BIF return value.
    Info,
    /// `{Ref, true | badarg}`. Anything but `true` is `badarg`.
    GroupLeader,
    /// `{Ref, true | badarg | badopt}`. Anything but `true` is `badarg`.
    Display,
    /// `{Ref, Bool}`.
    Alive,
}

pub(crate) enum Submit {
    /// The request is in the target's queue. The id is the reply reference.
    Sent(u64),
    /// The target had already exited.
    Dead,
}

/// A queued signal request; `Collect` ones may be saved while GC is disabled.
pub(crate) struct Pending {
    pub(crate) id: u64,
    pub(crate) from: Pid,
    pub(crate) op: RemoteOp,
}

#[derive(Clone, Copy)]
pub(crate) struct Waiter {
    pub(crate) id: u64,
    pub(crate) kind: WaitKind,
    /// Mailbox length when the request was sent: the reply is queued after it.
    ///
    /// Port of erts/emulator/beam/erl_proc_sig_queue.c:3398 (erts_msgq_set_save_end),
    /// OTP-29.1.1: the wait skips the messages that predate the request instead of
    /// rescanning them on every retry.
    pub(crate) save: usize,
}

/// Runtime address plus pid. Simulations reuse pid numbers, and tests run in parallel.
type Slot = (usize, Pid);

/// Requests queued for one target: plain signal requests in submission order and system
/// tasks per priority, as in erts' `ErtsProcSysTaskQs`.
#[derive(Default)]
struct Requests {
    plain: VecDeque<Pending>,
    sys: [VecDeque<Pending>; 4],
    /// Normal-priority tasks run since the last low-priority one.
    ncount: u8,
}

impl Requests {
    fn is_empty(&self) -> bool {
        self.plain.is_empty() && self.sys.iter().all(VecDeque::is_empty)
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
        self.sys[index].pop_front()
    }
}

pub(crate) fn sys_index(priority: Priority) -> usize {
    match priority {
        Priority::Max => 0,
        Priority::High => 1,
        Priority::Normal => 2,
        Priority::Low => 3,
    }
}

struct Tables {
    /// Per-target requests in submission order; wakeups usually arrive in that order,
    /// so lookups hit the front (system task blasts queue hundreds of thousands).
    requests: BTreeMap<Slot, Requests>,
}

fn scope(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .map(|runtime| std::sync::Arc::as_ptr(runtime) as usize)
        .unwrap_or(0)
}

/// Whether `pid` of the runtime at `runtime` already began its exit.
// Port of erts/emulator/beam/erl_nif.c:2323 (enif_is_process_alive: erts_proc_lookup),
// OTP-29.1.1: erts removes an exiting process from the process table while its dirty NIF
// still runs; this scheduler keeps the entry until the NIF returns, so exit start decides.
pub(crate) fn has_begun_exit(runtime: &std::sync::Arc<crate::process::Runtime>, pid: Pid) -> bool {
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

fn proc_is_exiting(process: &Process, pid: Pid) -> bool {
    process
        .runtime
        .as_ref()
        .is_some_and(|runtime| proc_is_exiting_runtime(runtime, pid))
}

/// Record that `pid` has a queued remote request. False when its exit already
/// finished that table, so the caller must drop the queue entry.
fn note_request(process: &Process, pid: Pid) -> bool {
    process
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.publish_proc_flag(pid, arinsal_sched::proc_flags::REQUESTS))
}

fn tables() -> &'static Mutex<Tables> {
    static TABLES: std::sync::OnceLock<Mutex<Tables>> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        Mutex::new(Tables {
            requests: BTreeMap::new(),
        })
    })
}

/// Park the caller until [`poll`] observes the reply. The process retries this BIF.
pub(crate) fn await_reply() -> VmError {
    VmError::Unsupported("AWAIT_SIGNAL_REPLY".into())
}

pub(crate) fn is_await_message(message: &str) -> bool {
    message.contains("AWAIT_SIGNAL_REPLY")
}

pub(crate) fn is_waiting(process: &Process, pid: Pid) -> bool {
    process
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.remote_status(pid) == "waiting")
}

/// Whether `process` is parked in `erlang:process_info/2` awaiting a target reply.
// Port of erts/emulator/beam/erl_bif_info.c:2341 (`current_function`), OTP-29.1.1.
pub(crate) fn is_waiting_for_process_info(process: &Process) -> bool {
    process
        .pending_signal_waiter
        .is_some_and(|waiter| matches!(waiter.kind, WaitKind::Info))
}

/// `Ok(None)` when this process has no outstanding request.
/// `Ok(Some(term))` when the reply has arrived.
/// `Err(await)` when the reply is still pending.
pub(crate) fn poll(process: &mut Process) -> Result<Option<Term>, VmError> {
    let Some(waiter) = process.pending_signal_waiter else {
        return Ok(None);
    };
    let (id, kind, save) = (waiter.id, waiter.kind, waiter.save);
    let Some(index) = process
        .inbox
        .position_from(save, |term| reply_inner(*term, id, kind).is_some())
    else {
        return Err(await_reply());
    };
    let old_prio_len = process.cold.as_ref().map_or(0, |cold| cold.prio_len);
    let (removed, new_prio_len) =
        process
            .inbox
            .remove_to_heap(index, &mut process.heap, old_prio_len)?;
    process.cold_mut().prio_len = new_prio_len;
    let term = removed.expect("reply index");
    process.message_removed(index);
    process.pending_signal_waiter = None;
    let inner = reply_inner(term, id, kind).ok_or_else(|| badarg("request reply"))?;
    interpret(kind, inner).map(Some)
}

fn interpret(kind: WaitKind, inner: Term) -> Result<Term, VmError> {
    match kind {
        WaitKind::Info | WaitKind::Alive => Ok(inner),
        WaitKind::GroupLeader | WaitKind::Display => {
            if inner == atom("true") {
                Ok(atom("true"))
            } else {
                Err(badarg("remote request"))
            }
        }
    }
}

fn reply_inner(term: Term, id: u64, kind: WaitKind) -> Option<Term> {
    // SAFETY: Inbox terms are rooted on the caller's heap for this scan.
    let tuple = unsafe { term.tuple_ref() }?;
    match kind {
        WaitKind::Info | WaitKind::GroupLeader | WaitKind::Display | WaitKind::Alive => {
            if tuple.len() == 2 && tuple.get(0).and_then(ref_id) == Some(id) {
                tuple.get(1)
            } else {
                None
            }
        }
    }
}

/// Enqueue `op` on `target` and, when `wait` is set, park the caller on the reply.
pub(crate) fn submit(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Pid,
    op: RemoteOp,
    wait: Option<WaitKind>,
) -> Result<Submit, VmError> {
    let id = runtime(process)?.next_ref();
    submit_id(process, ctx, target, id, op, wait)
}

/// Like [`submit`], but the reply reference uses `id` (`0` allocates one).
pub(crate) fn submit_id(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Pid,
    id: u64,
    op: RemoteOp,
    wait: Option<WaitKind>,
) -> Result<Submit, VmError> {
    submit_from(process, ctx, ctx.pid(), target, id, op, wait, None)
}

/// Queue a process system task on `target` at `priority`; the reply goes to `requester`.
///
/// Port of erts/emulator/beam/erl_process.c:7221 (schedule_process_sys_task), OTP-29.1.1.
pub(crate) fn submit_sys_task(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    requester: Pid,
    target: Pid,
    op: RemoteOp,
    priority: Priority,
) -> Result<Submit, VmError> {
    submit_from(process, ctx, requester, target, 0, op, None, Some(priority))
}

#[allow(clippy::too_many_arguments)]
fn submit_from(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    from: Pid,
    target: Pid,
    id: u64,
    op: RemoteOp,
    wait: Option<WaitKind>,
    priority: Option<Priority>,
) -> Result<Submit, VmError> {
    if !runtime(process)?.scheduler()?.ns_may_signal(from, target) {
        return Ok(Submit::Dead);
    }
    let id = if id == 0 {
        runtime(process)?.next_ref()
    } else {
        id
    };
    let slot_of = scope(process);
    let elevates = matches!(
        op,
        RemoteOp::GroupLeader { .. } | RemoteOp::Info { .. } | RemoteOp::Display | RemoteOp::Alive
    );
    {
        let mut tables = tables().lock().unwrap();
        // Port of erts/emulator/beam/erl_proc_sig_queue.c (signals to an exiting process are
        // handled by its exit), OTP-29.1.1: the target already ran its exit handling.
        // `ERTS_PSFLG_EXITING` is the process word; the request table is not a list of
        // every pid that has ever exited.
        if proc_is_exiting(process, target) {
            return Ok(Submit::Dead);
        }
        let queues = tables.requests.entry((slot_of, target)).or_default();
        let pending = Pending { id, from, op };
        match priority {
            Some(priority) => queues.sys[sys_index(priority)].push_back(pending),
            None => queues.plain.push_back(pending),
        }
        if let Some(kind) = wait {
            process.pending_signal_waiter = Some(Waiter {
                id,
                kind,
                save: process.inbox.len(),
            });
        }
        if !note_request(process, target) || proc_is_exiting(process, target) {
            if let Some(queues) = tables.requests.get_mut(&(slot_of, target)) {
                match priority {
                    Some(priority) => {
                        queues.sys[sys_index(priority)].retain(|pending| pending.id != id)
                    }
                    None => queues.plain.retain(|pending| pending.id != id),
                }
            }
            if process
                .pending_signal_waiter
                .is_some_and(|waiter| waiter.id == id)
            {
                process.pending_signal_waiter = None;
            }
            return Ok(Submit::Dead);
        }
    }
    let sent = match priority {
        Some(priority) => ctx.signal_sys_task(target, Signal::UnlinkAck(id), priority),
        None => ctx.signal(target, Signal::UnlinkAck(id)),
    };
    match sent {
        Ok(()) => {
            // Port of erts/emulator/beam/erl_proc_sig_queue.c:3012, 3062, 3183, 3423
            // (erts_proc_sig_send_group_leader, _is_alive_request, _process_info_request,
            // _rpc_request_prio), OTP-29.1.1: these senders elevate the receiver's signal
            // handling priority to their own.
            if elevates && priority.is_none() {
                elevate_sig_handling_prio(process, ctx, slot_of, target)?;
            }
            Ok(Submit::Sent(id))
        }
        Err(arinsal_sched::Error::NoProcess) => {
            let mut tables = tables().lock().unwrap();
            if let Some(queues) = tables.requests.get_mut(&(slot_of, target)) {
                queues.plain.retain(|pending| pending.id != id);
                for queue in &mut queues.sys {
                    queue.retain(|pending| pending.id != id);
                }
            }
            if process
                .pending_signal_waiter
                .is_some_and(|waiter| waiter.id == id)
            {
                process.pending_signal_waiter = None;
            }
            Ok(Submit::Dead)
        }
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
    slot_of: usize,
    target: Pid,
) -> Result<(), VmError> {
    let min_prio = crate::natives::proc::user_priority(process);
    match ctx.process_priority(target) {
        Some(other) if sys_index(other) > sys_index(min_prio) => {}
        _ => return Ok(()),
    }
    let id = runtime(process)?.next_ref();
    {
        let mut tables = tables().lock().unwrap();
        if proc_is_exiting(process, target) {
            return Ok(());
        }
        tables.requests.entry((slot_of, target)).or_default().sys[sys_index(min_prio)].push_back(
            Pending {
                id,
                from: ctx.pid(),
                op: RemoteOp::PrioSig,
            },
        );
        if !note_request(process, target) || proc_is_exiting(process, target) {
            if let Some(queues) = tables.requests.get_mut(&(slot_of, target)) {
                queues.sys[sys_index(min_prio)].retain(|pending| pending.id != id);
            }
            return Ok(());
        }
    }
    match ctx.signal_sys_task(target, Signal::UnlinkAck(id), min_prio) {
        Ok(()) => Ok(()),
        Err(arinsal_sched::Error::NoProcess) => {
            let mut tables = tables().lock().unwrap();
            if let Some(queues) = tables.requests.get_mut(&(slot_of, target)) {
                queues.sys[sys_index(min_prio)].retain(|pending| pending.id != id);
            }
            Ok(())
        }
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
    elevate_sig_handling_prio(process, ctx, scope(process), target)
}

/// Run the request whose wakeup is `id`, if it is still queued for this process.
pub(crate) fn handle_request(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: u64,
) -> Result<(), VmError> {
    let pending = {
        let mut tables = tables().lock().unwrap();
        let Some(queues) = tables.requests.get_mut(&(scope(process), ctx.pid())) else {
            return Ok(());
        };
        // A wakeup for a system task runs whichever task erts would fetch next; ids of
        // plain requests are matched exactly.
        let plain = queues
            .plain
            .iter()
            .position(|pending| pending.id == id)
            .and_then(|index| queues.plain.remove(index));
        // Port of erts/emulator/beam/erl_process.c:10368 (erts_schedule runs
        // execute_sys_tasks only while the process is scheduled in and not executing),
        // OTP-29.1.1: a system task woken in the middle of a BIF, a receive or native code
        // waits for the next scheduling point. check_process_code in particular must see the
        // process' continuation, which a half-done native call keeps outside its stack.
        let at_point = process
            .cold
            .as_ref()
            .is_some_and(|cold| cold.sys_task_point);
        let dirty_cpc = if plain.is_none() && !at_point {
            if queues.sys.iter().any(|queue| !queue.is_empty()) {
                process.cold_mut().sys_tasks_deferred = true;
            }
            // Port of erts/emulator/beam/erl_process.c:11255 (dispatch_system_task),
            // OTP-29.1.1: check_process_code of a process executing dirty is run by the dirty
            // signal handler on its behalf; the other tasks wait for the process.
            if !ctx.dirty_running() {
                return Ok(());
            }
            let Some(pending) = queues.take_check_process_code() else {
                return Ok(());
            };
            Some(pending)
        } else {
            None
        };
        let Some(pending) = plain.or(dirty_cpc).or_else(|| queues.fetch_sys_task()) else {
            return Ok(());
        };
        if queues.is_empty() {
            tables.requests.remove(&(scope(process), ctx.pid()));
        }
        pending
    };
    run_request(process, ctx, pending)
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
            .cold_mut()
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
        let cold = process.cold_mut();
        cold.delayed_gc
            .push(crate::proc_create::DelayedGc::Request(pending));
        cold.dirty_sys_gc = true;
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
    process.cold_mut().sys_tasks_deferred = false;
    loop {
        let pending = {
            let mut tables = tables().lock().unwrap();
            let slot = (scope(process), ctx.pid());
            let Some(queues) = tables.requests.get_mut(&slot) else {
                return Ok(());
            };
            let Some(pending) = queues.fetch_sys_task() else {
                return Ok(());
            };
            if queues.is_empty() {
                tables.requests.remove(&slot);
            }
            pending
        };
        run_request(process, ctx, pending)?;
    }
}

/// Wakes the process again for system tasks deferred during this slice, so that it reaches a
/// scheduling point that runs them (erts keeps ERTS_PSFLG_ACTIVE_SYS set).
pub(crate) fn reschedule_deferred_sys_tasks(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
) -> Result<(), VmError> {
    if !process
        .cold
        .as_ref()
        .is_some_and(|cold| cold.sys_tasks_deferred)
    {
        return Ok(());
    }
    let priority = {
        let tables = tables().lock().unwrap();
        let Some(queues) = tables.requests.get(&(scope(process), ctx.pid())) else {
            process.cold_mut().sys_tasks_deferred = false;
            return Ok(());
        };
        let Some(index) = queues.sys.iter().position(|queue| !queue.is_empty()) else {
            process.cold_mut().sys_tasks_deferred = false;
            return Ok(());
        };
        [
            Priority::Max,
            Priority::High,
            Priority::Normal,
            Priority::Low,
        ][index]
    };
    // No plain request has this id: the wakeup fetches the next system task.
    ctx.signal_sys_task(ctx.pid(), Signal::UnlinkAck(u64::MAX), priority)
        .map_err(|error| VmError::Unsupported(format!("system task wakeup: {error}")))
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
    let detached = matches!(pending.op, RemoteOp::Info { .. });
    if detached {
        process.heap.begin_detached();
    }
    let message = crate::natives::proc::fulfill_request(process, ctx, pending.id, pending.op)
        .and_then(Message::copy_from);
    if detached {
        process.heap.end_detached();
    }
    let message = message?;
    match ctx.send_runtime(pending.from, message) {
        Ok(()) | Err(arinsal_sched::Error::NoProcess) => Ok(()),
        Err(error) => Err(VmError::Unsupported(format!("request reply: {error}"))),
    }
}

/// Reply `false` / `undefined` / `badarg` for requests this process will never run.
pub(crate) fn process_exiting(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    crate::natives::sys::release_multi_scheduling_blocks(process, ctx.pid());
    process.pending_signal_waiter = None;
    // OTP destroys the trapped BIF state together with the exiting process.
    // Persistent get/0's snapshot retains a table generation and its literals.
    if let Some(cold) = process.cold.as_mut() {
        cold.persistent_get_all = None;
        cold.persistent_update_result = None;
    }
    let slot = (scope(process), ctx.pid());
    // Port of erl_nif.c:2323 (`ERTS_PSFLG_EXITING` on the process). The request table is
    // taken only when this process was given a remote request (erl_proc_sig_queue.c).
    let _ =
        arinsal_sched::proc_flags::publish(ctx.exit_flags(), arinsal_sched::proc_flags::EXITING);
    let pending = if ctx.exit_flags().load(std::sync::atomic::Ordering::Acquire)
        & arinsal_sched::proc_flags::REQUESTS
        == 0
    {
        VecDeque::new()
    } else {
        let mut tables = tables().lock().unwrap();
        let queues = tables.requests.remove(&slot).unwrap_or_default();
        let mut all = queues.plain;
        for queue in queues.sys {
            all.extend(queue);
        }
        all
    };
    let mut pending = pending;
    if let Some(cold) = process.cold.as_mut() {
        for task in std::mem::take(&mut cold.delayed_gc) {
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
        let _ = ctx.send_runtime(pending.from, message);
    }
}

/// Options of `monitor/3`: `{tag, Tag}`, `{alias, Mode}` and `priority`.
fn monitor_options(args: &[Term]) -> Result<(Term, bool, bool), VmError> {
    let options = if args.len() == 3 {
        list(args[2]).ok_or_else(|| badarg("monitor/3"))?
    } else {
        Vec::new()
    };
    let mut tag = atom("DOWN");
    let mut alias = false;
    let mut priority = false;
    for option in options {
        if option == atom("priority") {
            priority = true;
            continue;
        }
        // SAFETY: Each option is rooted in the caller's heap.
        let tuple = unsafe { option.tuple_ref() }.ok_or_else(|| badarg("monitor/3"))?;
        if tuple.len() != 2 {
            return Err(badarg("monitor/3"));
        }
        match (tuple.get(0), tuple.get(1)) {
            (Some(key), Some(value)) if key == atom("tag") => tag = value,
            (Some(key), Some(value))
                if key == atom("alias")
                    && ["explicit_unalias", "demonitor", "reply_demonitor"]
                        .iter()
                        .any(|name| value == atom(name)) =>
            {
                alias = true
            }
            _ => return Err(badarg("monitor/3")),
        }
    }
    Ok((tag, alias, priority))
}

/// The object of a local process monitor's `DOWN`: `{Name, node()}` for a name, else the pid.
/// The `noproc` DOWN of a monitor whose target does not exist. It is a monitor-down signal
/// to the monitoring process itself, so it queues behind the signals sent before it and
/// enters the message queue after a receive marker reserved before the monitor call.
// Port of erts/emulator/beam/bif.c:790-823 (monitor: erts_proc_sig_send_monitor_down with
// am_noproc), OTP-29.1.1.
/// The shared data of a monitor with this DOWN tag and registered name (erts `ErtsMonitorData`).
/// The default `DOWN` tag without a name is the shared default object and allocates nothing.
fn monitor_data_for(
    tag: Term,
    name: Option<&str>,
) -> Result<std::sync::Arc<crate::proc_create::MonitorData>, VmError> {
    let tag = if tag == atom("DOWN") {
        None
    } else {
        Some(
            arinsal_term::to_owned(tag)
                .map_err(|error| VmError::Unsupported(format!("monitor tag: {error:?}")))?,
        )
    };
    Ok(std::sync::Arc::new(crate::proc_create::MonitorData {
        tag,
        name: name.map(str::to_owned),
    }))
}

fn send_noproc_down(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    id: u64,
    name: Option<&str>,
    target_pid: Option<Pid>,
    target: Term,
    tag: Term,
) -> Result<(), VmError> {
    // A named target is reported by name; the signal sender is then irrelevant.
    let from = target_pid.or_else(|| name.map(|_| ctx.pid()));
    if let Some(from) = from
        && let Some(runtime) = process.runtime.clone()
    {
        let data = monitor_data_for(tag, name)?;
        process
            .cold_mut()
            .monitors
            .insert(id, crate::proc_create::OriginHalf { target: from, data });
        let reason = Message::copy_from(atom("noproc"))?;
        return runtime
            .scheduler()?
            .signal(
                from,
                ctx.pid(),
                Signal::MonitorDown {
                    reference: id,
                    reason,
                },
            )
            .map_err(|error| VmError::Unsupported(format!("monitor: {error}")));
    }
    // A pid of another incarnation of this node: no local sender to report it.
    let object = monitor_object(process, name, target)?;
    let reference = reference(process, id)?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let down = TermBuilder::new(&mut heap)
        .tuple(&[tag, reference, atom("process"), object, atom("noproc")])
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
    let node = crate::node_tables::lock().local_name.clone();
    TermBuilder::new(&mut arinsal_bifs::ProcessHeapHandle(&mut process.heap))
        .tuple(&[atom(name), atom(&node)])
        .map_err(|error| VmError::Unsupported(format!("monitor object: {error:?}")))
}

// Port of erts/emulator/beam/erl_proc_sig_queue.c:3027
// (erts_proc_sig_send_is_alive_request), OTP-29.1.1.
fn is_process_alive(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    pid: Term,
) -> Result<Term, VmError> {
    if let Some(done) = poll(process)? {
        return Ok(done);
    }
    let pid = Pid::from_term(pid).ok_or_else(|| badarg("is_process_alive/1"))?;
    if pid == ctx.pid() {
        return Ok(atom("true"));
    }
    if !runtime(process)?.scheduler()?.lookup(pid) {
        return Ok(atom("false"));
    }
    match submit(process, ctx, pid, RemoteOp::Alive, Some(WaitKind::Alive))? {
        Submit::Sent(_) => Err(await_reply()),
        Submit::Dead => Ok(atom("false")),
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
        return Ok(atom("true"));
    }
    let pid = Pid::from_term(target).ok_or_else(|| badarg("link"))?;
    if pid == ctx.pid() {
        return Ok(atom("true"));
    }
    if !runtime(process)?.scheduler()?.lookup(pid) {
        return link_noproc(process, pid, priority);
    }
    crate::trace::linked(process, ctx.pid(), pid);
    process.cold_mut().links.insert(pid);
    if priority {
        process.cold_mut().prio_links.insert(pid);
    } else {
        process.cold_mut().prio_links.remove(&pid);
    }
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
    match ctx.signal(pid, Signal::Link) {
        // The linked process reports getting_linked when it handles the signal.
        Ok(()) => {}
        Err(arinsal_sched::Error::NoProcess) => {
            // The target exited between the lookup and the signal: like erts, keep the link
            // and let a `noproc` link exit from the target dissolve it.
            // Port of erts/emulator/beam/bif.c:180-183 (link_opt), OTP-29.1.1.
            let reason = Message::copy_from(atom("noproc"))?;
            runtime(process)?
                .scheduler()?
                .signal(pid, ctx.pid(), Signal::ExitLinked(reason))
                .map_err(|_| badarg("link"))?;
        }
        Err(arinsal_sched::Error::Capacity) => return Err(system_limit()),
        Err(_) => return Err(badarg("link")),
    }
    wake_for_procs_trace(process, ctx, pid);
    Ok(atom("true"))
}

/// Linking to a process that does not exist: an `{'EXIT', Pid, noproc}` message when trapping
/// exits, else a `noproc` error.
// Port of erts/emulator/beam/bif.c:675 (erts_link_opts / link noproc arm), OTP-29.1.1.
fn link_noproc(process: &mut Process, pid: Pid, priority: bool) -> Result<Term, VmError> {
    let pid_term = pid.to_term().ok_or_else(|| badarg("link"))?;
    link_noproc_term(process, pid_term, priority)
}

fn link_noproc_term(process: &mut Process, target: Term, priority: bool) -> Result<Term, VmError> {
    let reason = atom("noproc");
    if process.trap_exit {
        let pid_term = target;
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let exit = TermBuilder::new(&mut heap)
            .tuple(&[atom("EXIT"), pid_term, reason])
            .map_err(|_| system_limit())?;
        if priority {
            process.push_priority_message(exit)?;
        } else {
            process.inbox.push_back(exit);
        }
        return Ok(atom("true"));
    }
    process.note_exit_reason(reason)?;
    Err(VmError::Trap(crate::exceptions::Trap::error(reason)))
}

/// Link and unlink signals are applied lazily, but erts handles them on arrival, which is when a
/// `procs` trace reports getting_linked/getting_unlinked: wake a receiver that is traced for it.
// Port of erts/emulator/beam/erl_proc_sig_queue.c:8578-8589 (getting_unlinked/getting_linked), OTP-29.1.1.
fn wake_for_procs_trace(process: &Process, ctx: &mut RunCtx<'_, Message>, target: Pid) {
    if crate::trace::flags(process, target) & crate::trace::PROCS != 0 {
        let _ = ctx.signal(target, Signal::UnlinkAck(u64::MAX));
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
        return Ok(atom("true"));
    }
    let mut via_prio_alias = false;
    let pid = if let Some(pid) = Pid::from_term(id) {
        pid
    } else if let Some(alias) = ref_id(id) {
        match runtime(process)?.alias_lookup_prio(alias) {
            Some((Some(pid), alias_prio)) => {
                via_prio_alias = alias_prio && want_priority;
                pid
            }
            Some((None, _)) => return Ok(atom("true")),
            None => return Err(badarg("exit")),
        }
    } else {
        return Err(badarg("exit"));
    };
    let suicide = exit2 && pid == ctx.pid() && (reason == atom("kill") || !process.trap_exit);
    if suicide {
        process.note_exit_reason(reason)?;
        return Err(VmError::Trap(crate::exceptions::Trap::untrappable_exit(
            reason,
        )));
    }
    let mut message = Message::copy_from(reason)?;
    if via_prio_alias {
        message = message.with_priority();
    }
    let _ = ctx.signal(pid, Signal::Exit(message));
    Ok(atom("true"))
}

fn parse_priority_opts(opts: Term) -> Result<bool, VmError> {
    let mut priority = false;
    let mut current = opts;
    while current.classify() == TermKind::List {
        // SAFETY: Option list stays rooted for this BIF call.
        let (head, tail) = unsafe { current.cons_ref() }.ok_or_else(|| badarg("badopt"))?;
        if head != atom("priority") {
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
    match submit_id(process, ctx, pid, id, RemoteOp::Alive, None)? {
        Submit::Sent(_) => Ok(atom("ok")),
        Submit::Dead => {
            // Port of erl_proc_sig_queue.c:3065-3070: reply `{Ref, false}` to self.
            let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            let reply = TermBuilder::new(&mut heap)
                .tuple(&[reference, atom("false")])
                .map_err(|_| system_limit())?;
            process.inbox.push_back(reply);
            Ok(atom("ok"))
        }
    }
}

// Port of erts/emulator/beam/erl_process.c:9216
// (erts_internal_is_process_executing_dirty_1), OTP-29.1.1.
fn is_process_executing_dirty(process: &Process, pid: Term) -> Result<Term, VmError> {
    let Some(pid) = Pid::from_term(pid) else {
        return Err(badarg("is_process_executing_dirty/1"));
    };
    let dirty = runtime(process)?.scheduler()?.is_executing_dirty(pid);
    Ok(atom(if dirty { "true" } else { "false" }))
}

// Port of erts/emulator/beam/erl_bif_trace.c:3900 (trace_delivered_1), OTP-29.1.1.
fn trace_delivered(
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    target: Term,
) -> Result<Term, VmError> {
    if target != atom("all") && Pid::from_term(target).is_none() {
        return Err(badarg("trace_delivered/1"));
    }
    let id = runtime(process)?.next_ref();
    let reference = reference(process, id)?;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let message = TermBuilder::new(&mut heap)
        .tuple(&[atom("trace_delivered"), target, reference])
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
        return Err(VmError::Trap(crate::exceptions::Trap::error(atom(
            "notsup",
        ))));
    }
    if Pid::from_term(to).is_some() {
        // No pending clear sessions in this build; a live target would return true.
        return Ok(atom(
            if runtime(process)?
                .scheduler()?
                .lookup(Pid::from_term(to).expect("pid"))
            {
                "true"
            } else {
                "false"
            },
        ));
    }
    if to.as_port().is_some() {
        return Ok(atom("false"));
    }
    Err(badarg("send_trace_clean_signal/1"))
}
