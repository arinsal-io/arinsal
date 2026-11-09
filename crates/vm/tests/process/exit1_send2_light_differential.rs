//! `exit/1` and `erlang:send/2,3` called from native code (the light BIF entries) match erts.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(exit1_send2_diff).
-export([run/0]).

run() ->
    process_flag(trap_exit, true),
    Big = lists:seq(1, 2000),
    P1 = spawn_link(fun() -> garbage_collect(), exit({big, Big, a}) end),
    R1 = receive {'EXIT', P1, X1} -> X1 end,
    P2 = spawn_link(fun() -> try exit(foo) catch exit:foo -> exit(bar) end end),
    R2 = receive {'EXIT', P2, X2} -> X2 end,
    R3 = try exit(caught) catch C:E -> {C, E} end,
    Self = self(),
    R4 = erlang:send(Self, one),
    R5 = erlang:send(Self, two, [noconnect]),
    R6 = try erlang:send(no_such_registered_name, x) catch error:badarg -> badarg end,
    R7 = [receive M -> M after 0 -> none end || _ <- [1, 2, 3]],
    {R1 =:= {big, Big, a}, R2, R3, R4, R5, R6, R7}.
"#;

#[test]
fn exit1_and_send2_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping exit1_send2_light test");
        return;
    };
    let beam = reference
        .compile_named("exit1_send2_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("exit1_send2_diff", &beam)
        .expect("load reference");
    let expected = reference.call("exit1_send2_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled("exit1_send2_diff", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
