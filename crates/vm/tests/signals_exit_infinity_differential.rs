use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(sig_exit_inf_diff).
-export([self_kill/0, infinity_wakeup/0]).

self_kill() ->
    {Pid, Ref} = spawn_monitor(fun() -> exit(self(), kill) end),
    receive {'DOWN', Ref, process, Pid, Reason} -> Reason after 5000 -> timeout end.

infinity_wakeup() ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        process_flag(trap_exit, true),
        Parent ! ready,
        put(t, infinity),
        wait(get(t))
    end),
    receive ready -> ok end,
    timer:sleep(50),
    exit(Pid, shutdown),
    First = receive {'DOWN', Ref, process, Pid, R0} -> {down, R0} after 200 -> alive end,
    exit(Pid, kill),
    Final = receive {'DOWN', Ref, process, Pid, R} -> R after 5000 -> timeout end,
    {First, Final}.

wait(T) -> receive after T -> ok end.
"#;

fn check(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping signals differential");
        return;
    };
    let beam = reference
        .compile_named("sig_exit_inf_diff", SOURCE, &[])
        .expect("compile");
    reference.load("sig_exit_inf_diff", &beam).unwrap();
    let expected = reference.call("sig_exit_inf_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load");
    let actual = vm
        .eval_scheduled("sig_exit_inf_diff", function, &[], 2, None)
        .expect("run")
        .term;
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "{function}");
}

#[test]
fn self_exit_kill_reports_killed() {
    check("self_kill");
}

#[test]
fn infinite_receive_survives_wakeup() {
    check("infinity_wakeup");
}
