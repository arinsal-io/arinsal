use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(recv_timeout_diff).
-export([before/0, during/0, down/0, nested/0, marker/0, priority/0, rearm/0]).

before() ->
    self() ! before_timeout,
    receive after 5 -> ok end,
    receive M -> M end.

during() ->
    Parent = self(),
    spawn(fun() -> timer:sleep(5), Parent ! during_timeout end),
    receive after 40 -> ok end,
    receive M -> M end.

down() ->
    {Pid, Ref} = spawn_monitor(fun() -> ok end),
    receive after 40 -> ok end,
    receive {'DOWN', Ref, process, Pid, Reason} -> Reason end.

nested() ->
    self() ! first,
    self() ! second,
    receive after 2 -> ok end,
    receive A ->
        receive after 2 -> ok end,
        receive B -> {A, B} end
    end.

marker() ->
    Ref = make_ref(),
    self() ! {marker_message, Ref},
    self() ! earlier,
    receive after 2 -> ok end,
    receive {marker_message, Ref} -> matched end,
    receive M -> M end.

priority() ->
    Alias = erlang:alias([priority]),
    self() ! ordinary,
    erlang:send(Alias, priority_message, [priority]),
    receive after 5 -> ok end,
    receive First ->
        receive Second -> {First, Second} end
    end.

%% Messages arriving during `receive after Tmo` re-execute wait_timeout with no
%% live X register; the armed timer must not re-read the operand.
rearm() ->
    GoTime = erlang:monotonic_time(millisecond) + 500,
    Self = self(),
    F = fun () ->
                Tmo = case GoTime - erlang:monotonic_time(millisecond) of
                          Left when Left < 0 -> 0;
                          Left -> Left
                      end,
                receive after Tmo -> ok end,
                Self ! {done, self()}
        end,
    Ps = [element(1, spawn_opt(F, [link, monitor, {message_queue_data, on_heap}]))
          || _ <- lists:seq(1, 50)],
    [[P ! [N | N] || N <- lists:seq(1, 1000)] || P <- Ps],
    lists:usort([receive {done, P} -> ok after 10000 -> timeout end || P <- Ps]).
"#;

fn compare(function: &str) {
    compare_with(function, Some(0x71e0));
}

fn compare_with(function: &str, seed: Option<u64>) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {function} receive-timeout differential test");
        return;
    };
    let beam = reference
        .compile_named("recv_timeout_diff", SOURCE, &[])
        .unwrap();
    reference.load("recv_timeout_diff", &beam).unwrap();
    let expected = reference.call("recv_timeout_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("recv_timeout_diff", function, &[], 2, seed)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn recv_timeout_message_before_wait() {
    compare("before");
}

#[test]
fn recv_timeout_message_during_wait() {
    compare("during");
}

#[test]
fn recv_timeout_down_during_wait() {
    compare("down");
}

#[test]
fn recv_timeout_nested_receives_with_after() {
    compare("nested");
}

#[test]
fn recv_timeout_marker_with_after() {
    compare("marker");
}

#[test]
fn recv_timeout_priority_message_with_after() {
    compare("priority");
}

#[test]
fn recv_timeout_rearmed_wait_ignores_dead_operand() {
    compare_with("rearm", None);
}
