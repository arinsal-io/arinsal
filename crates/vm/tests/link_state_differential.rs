use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(link_state_diff).
-export([run/0, peer/0]).

peer() ->
    receive
        {ping, From} -> From ! pong, peer();
        stop -> ok
    end.

sync(T) ->
    T ! {ping, self()},
    receive pong -> ok after 2000 -> erlang:error(sync_timeout) end.

both(P, T) ->
    {has_link(erts_debug:get_internal_state({link_list, P}), T),
     has_link(erts_debug:get_internal_state({link_list, T}), P)}.

has_link(Links, Pid) ->
    lists:any(fun
        ({erl_link, process, Other, linked, _}) -> Other =:= Pid;
        (_) -> false
    end, Links).

run() ->
    _ = erts_debug:set_internal_state(available_internal_state, true),
    P = self(),
    T = spawn(link_state_diff, peer, []),
    true = link(T),
    true = link(T),
    sync(T),
    Twice = both(P, T),
    {links, I1} = process_info(P, links),
    true = unlink(T),
    true = link(T),
    sync(T),
    Relinked = both(P, T),
    true = unlink(T),
    true = unlink(T),
    sync(T),
    Unlinked = both(P, T),
    {links, I2} = process_info(P, links),
    true = link(T),
    true = unlink(T),
    true = link(T),
    true = unlink(T),
    sync(T),
    Flapped = both(P, T),
    T ! stop,
    Mref = monitor(process, T),
    receive {'DOWN', Mref, _, _, _} -> ok end,
    process_flag(trap_exit, true),
    true = link(T),
    NoProc = receive {'EXIT', T, R} -> R after 2000 -> timeout end,
    {Twice, lists:member(T, I1), Relinked, Unlinked, lists:member(T, I2), Flapped, NoProc}.
"#;

#[test]
fn link_state_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping link state differential");
        return;
    };
    let beam = reference
        .compile_named("link_state_diff", SOURCE, &[])
        .expect("compile link state differential");
    reference
        .load("link_state_diff", &beam)
        .expect("load link state differential");
    let expected = reference.call("link_state_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load link state differential");
    let actual = vm
        .eval_scheduled("link_state_diff", "run", &[], 2, None)
        .expect("run link state differential")
        .term;
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "link state");
}
