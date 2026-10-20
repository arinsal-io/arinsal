use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(port_mon_diff).
-export([run/0]).

down(R) ->
    receive {'DOWN', R, Type, Obj, Reason} -> {Type, Obj, Reason} after 5000 -> timeout end.

run() ->
    P = open_port({spawn, "cat"}, []),
    % id monitor: info, demonitor results, process_info
    R1 = erlang:monitor(port, P),
    Info1 = [X || {port, X} <- element(2, process_info(self(), monitors))],
    D1 = erlang:demonitor(R1, [info]),
    D1b = erlang:demonitor(R1, [info]),
    % named monitors
    true = register(pm_diff_cat, P),
    R2 = erlang:monitor(port, pm_diff_cat),
    R3 = erlang:monitor(port, {pm_diff_cat, node()}),
    Named = lists:sort([X || {port, X} <- element(2, process_info(self(), monitors))]),
    R4 = erlang:monitor(port, P),
    true = erlang:demonitor(R4, [flush]),
    Bad = [catch erlang:monitor(port, T) || T <- [{pm_diff_cat, 'other@nohost'}, {a, b, c}, 1, "x"]],
    BadClass = [case B of {'EXIT', {badarg, _}} -> badarg; Other -> Other end || B <- Bad],
    port_close(P),
    Down2 = down(R2),
    Down3 = down(R3),
    % noproc cases
    R5 = erlang:monitor(port, pm_diff_gone),
    Down5 = down(R5),
    R6 = erlang:monitor(port, P),
    {Type6, Obj6, Reason6} = down(R6),
    {{Info1 =:= [P], D1, D1b},
     {Named =:= lists:sort([P, {pm_diff_cat, node()}]), BadClass},
     Down2, Down3, Down5, {Type6, Obj6 =:= P, Reason6}}.
"#;

#[test]
fn port_monitors_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port monitor differential");
        return;
    };
    let beam = reference
        .compile_named("port_mon_diff", SOURCE, &[])
        .expect("compile");
    reference.load("port_mon_diff", &beam).unwrap();
    let expected = reference.call("port_mon_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load");
    let actual = vm
        .eval_scheduled("port_mon_diff", "run", &[], 2, None)
        .expect("run")
        .term;
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}
