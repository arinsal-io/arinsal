//! Logger events queued by the emulator (utils.c `do_send_logger_message` and its callers),
//! compared with erl 29.1.1: level, format, argument shape, metadata keys, and a `time` within
//! a window of `os:system_time(microsecond)`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::{Mutex, MutexGuard};

const SOURCE: &str = r#"
-module(logger_diff).
-export([cpu_topology/0, scheduler_bind/0, max_heap/0, port_error/0, process_error/0]).

capture(Fun) ->
    group_leader(self(), self()),
    Old = erlang:system_flag(system_logger, self()),
    try
        Fun(),
        receive {log, _, _, _, _} = Msg -> Msg after 5000 -> timeout end
    after
        erlang:system_flag(system_logger, Old)
    end.

meta({log, _Level, _Fmt, _Args, #{time := T} = Meta}) ->
    Gl = case Meta of #{gl := G} -> G =:= group_leader(); _ -> absent end,
    {lists:sort(maps:keys(Meta)),
     maps:get(error_logger, Meta),
     Gl,
     abs(os:system_time(microsecond) - T) < 60000000}.

cpu_topology() ->
    {log, L, F, A, _} = M = capture(fun() ->
        erlang:system_flag(cpu_topology, [{processor, [{core, [{thread, {logical, 0}}]}]}])
    end),
    {L, F, A, meta(M)}.

scheduler_bind() ->
    {log, L, F, A, _} = M = capture(fun() ->
        erlang:system_flag(scheduler_bind_type, unbound)
    end),
    {L, F, A, meta(M)}.

max_heap() ->
    Self = self(),
    {log, L, F, A, #{pid := P}} = M = capture(fun() ->
        {_, Ref} = spawn_opt(fun() -> grow([]) end,
            [monitor, {max_heap_size, #{size => 2000, kill => true, error_logger => true}}]),
        receive {'DOWN', Ref, _, _, _} -> ok after 5000 -> ok end,
        Self ! ok
    end),
    receive ok -> ok after 0 -> ok end,
    [Pid, Size, _Total, Kill, ErrLogger, _MQ, GC, Stack] = A,
    {L, F, {Pid =:= P, Size, Kill, ErrLogger, is_list(GC), is_list(Stack)}, meta(M)}.

grow(Acc) -> grow([0, 1, 2, 3, 4, 5, 6, 7 | Acc]).

port_error() ->
    {log, L, F, A, _} = M = capture(fun() ->
        process_flag(trap_exit, true),
        Port = open_port({spawn, "cat"}, []),
        Port ! {self(), {command, foo}},
        receive after 300 -> ok end,
        catch port_close(Port)
    end),
    {L, F, A, meta(M)}.

process_error() ->
    {log, L, F, A, #{pid := P}} = M = capture(fun() ->
        {_, Ref} = spawn_opt(fun() -> erlang:error(boom) end, [monitor]),
        receive {'DOWN', Ref, _, _, _} -> ok after 5000 -> ok end
    end),
    [Pid, {Reason, _Stack}] = A,
    {L, F, {Pid =:= P, Reason}, meta(M)}.
"#;

fn guard() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn run(function: &str) {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping logger differential test");
        return;
    };
    let beam = reference
        .compile_named("logger_diff", SOURCE, &[])
        .expect("compile");
    reference.load("logger_diff", &beam).expect("load");
    let expected = reference.call("logger_diff", function, &[]);
    assert!(
        matches!(expected, CallResult::Ok(ref term) if *term != OwnedTerm::atom("timeout")),
        "{function}: erl returned {expected:?}"
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load bytes");
    let actual = vm
        .eval_scheduled("logger_diff", function, &[], 1, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn cpu_topology_deprecation_warning_matches_erl() {
    run("cpu_topology");
}

#[test]
fn scheduler_bind_deprecation_warning_matches_erl() {
    run("scheduler_bind");
}

#[test]
fn max_heap_size_kill_report_matches_erl() {
    run("max_heap");
}

#[test]
fn port_bad_output_value_report_matches_erl() {
    run("port_error");
}

#[test]
fn process_exit_error_report_matches_erl() {
    run("process_error");
}
