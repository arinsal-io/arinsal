//! Port links and monitors live in the trees of the processes at both ends: `process_info`
//! of the owner and of a driver-monitored process, and the exit of a process that unlinked.
use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(port_link_trees_diff).
-export([run/0]).

links(Pid) -> {links, L} = process_info(Pid, links), lists:sort([P || P <- L, is_port(P)]).

run() ->
    Parent = self(),
    % the opener is linked; link/unlink of a second port
    P1 = open_port({spawn, "cat"}, []),
    P2 = open_port({spawn, "cat"}, []),
    A = lists:sort([P1, P2]) =:= links(self()),
    true = unlink(P1),
    B = links(self()) =:= [P2],
    true = link(P1),
    C = lists:sort([P1, P2]) =:= links(self()),
    % a closed port leaves the link tree
    port_close(P2),
    receive after 100 -> ok end,
    D = links(self()) =:= [P1],
    % an owner that unlinked leaves the port open when it exits
    {Owner, Ref} = spawn_monitor(fun() ->
        P = open_port({spawn, "cat"}, []),
        true = unlink(P),
        Parent ! {port, P},
        receive stop -> ok end
    end),
    P3 = receive {port, Pp} -> Pp end,
    Owner ! stop,
    receive {'DOWN', Ref, process, Owner, _} -> ok end,
    receive after 100 -> ok end,
    E = erlang:port_info(P3, name),
    port_close(P3),
    % an owner that stays linked takes the port with it on an abnormal exit
    {Owner2, Ref2} = spawn_monitor(fun() ->
        P = open_port({spawn, "cat"}, []),
        Parent ! {port, P},
        receive stop -> exit(boom) end
    end),
    P4 = receive {port, Pp4} -> Pp4 end,
    Owner2 ! stop,
    receive {'DOWN', Ref2, process, Owner2, _} -> ok end,
    receive after 100 -> ok end,
    F = erlang:port_info(P4, name),
    % monitors of ports in process_info
    M = erlang:monitor(port, P1),
    G = [X || {port, X} <- element(2, process_info(self(), monitors))] =:= [P1],
    true = erlang:demonitor(M, [flush]),
    H = [X || {port, X} <- element(2, process_info(self(), monitors))] =:= [],
    port_close(P1),
    {A, B, C, D, E =/= undefined, F, G, H}.
"#;

#[test]
fn port_links_and_monitors_in_process_trees_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port link tree differential");
        return;
    };
    let beam = reference
        .compile_named("port_link_trees_diff", SOURCE, &[])
        .expect("compile");
    reference.load("port_link_trees_diff", &beam).unwrap();
    let expected = reference.call("port_link_trees_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load");
    let actual = vm
        .eval_scheduled("port_link_trees_diff", "run", &[], 5, None)
        .expect("run")
        .term;
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}
