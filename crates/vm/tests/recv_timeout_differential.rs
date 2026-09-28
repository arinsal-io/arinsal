use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(recv_timeout_diff).
-export([before/0, during/0, down/0, nested/0, marker/0, priority/0]).

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
"#;

fn compare(function: &str) {
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
        .eval_scheduled("recv_timeout_diff", function, &[], 2, Some(0x71e0))
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
