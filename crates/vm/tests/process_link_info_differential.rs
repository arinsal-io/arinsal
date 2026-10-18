use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_link_info_diff).
-export([run/0, loop/1, named_loop/2, monitor_origin/2,
         has_link/2, has_monitor/4, has_named_monitor/5]).

run() ->
    _ = erts_debug:set_internal_state(available_internal_state, true),
    Parent = self(),
    true = register(proc_link_info_self, Parent),
    SelfNameRef = monitor(process, proc_link_info_self),
    SelfNameAbsent = not has_monitor(
        erts_debug:get_internal_state({monitor_list, Parent}), origin, SelfNameRef, Parent) andalso
        not has_monitor(
            erts_debug:get_internal_state({monitor_list, Parent}), target, SelfNameRef, Parent),
    Name = proc_link_info_target,
    Pid = spawn(proc_link_info_diff, named_loop, [Parent, Name]),
    receive {target_registered, Pid} -> ok end,
    true = link(Pid),
    LinkedSelf = has_link(erts_debug:get_internal_state({link_list, Parent}), Pid),
    LinkedTarget = has_link(erts_debug:get_internal_state({link_list, Pid}), Parent),
    true = unlink(Pid),
    UnlinkedSelf = not has_link(erts_debug:get_internal_state({link_list, Parent}), Pid),
    UnlinkedTarget = not has_link(erts_debug:get_internal_state({link_list, Pid}), Parent),

    Ref = monitor(process, Pid),
    Pid ! ping,
    receive pong -> ok after 1000 -> erlang:error(monitor_delivery_timeout) end,
    OriginBefore = has_monitor(
        erts_debug:get_internal_state({monitor_list, Parent}), origin, Ref, Pid),
    TargetBefore = has_monitor(
        erts_debug:get_internal_state({monitor_list, Pid}), target, Ref, Parent),
    true = demonitor(Ref, [flush]),
    OriginAfter = not has_monitor(
        erts_debug:get_internal_state({monitor_list, Parent}), origin, Ref, Pid),
    TargetAfter = not has_monitor(
        erts_debug:get_internal_state({monitor_list, Pid}), target, Ref, Parent),
    Origin = spawn(proc_link_info_diff, monitor_origin, [Parent, Pid]),
    receive {origin_monitor, Origin, OriginRef} ->
        ChildOrigin = has_monitor(
            erts_debug:get_internal_state({monitor_list, Origin}), origin, OriginRef, Pid),
        ChildTarget = has_monitor(
            erts_debug:get_internal_state({monitor_list, Pid}), target, OriginRef, Origin),
        Origin ! demonitor,
        receive origin_demonitored -> ok after 1000 -> erlang:error(demonitor_timeout) end,
        ChildTargetAfter = not has_monitor(
            erts_debug:get_internal_state({monitor_list, Pid}), target, OriginRef, Origin)
    end,
    NamedOrigin = spawn(proc_link_info_diff, monitor_origin, [Parent, Name]),
    receive {origin_monitor, NamedOrigin, NamedRef} ->
        NamedOriginBefore = has_named_monitor(
            erts_debug:get_internal_state({monitor_list, NamedOrigin}),
            origin, NamedRef, Pid, Name),
        NamedTargetBefore = has_named_monitor(
            erts_debug:get_internal_state({monitor_list, Pid}),
            target, NamedRef, NamedOrigin, Name),
        NamedOrigin ! demonitor,
        receive origin_demonitored -> ok after 1000 -> erlang:error(named_demonitor_timeout) end,
        NamedTargetAfter = not has_named_monitor(
            erts_debug:get_internal_state({monitor_list, Pid}),
            target, NamedRef, NamedOrigin, Name)
    end,
    Pid ! stop,
    {LinkedSelf, LinkedTarget, UnlinkedSelf, UnlinkedTarget,
     OriginBefore, TargetBefore, OriginAfter, TargetAfter,
     SelfNameAbsent, ChildOrigin, ChildTarget, ChildTargetAfter,
     NamedOriginBefore, NamedTargetBefore, NamedTargetAfter}.

loop(Parent) -> receive ping -> Parent ! pong, loop(Parent); stop -> ok end.

named_loop(Parent, Name) ->
    true = register(Name, self()),
    Parent ! {target_registered, self()},
    loop(Parent).

monitor_origin(Parent, Target) ->
    Ref = monitor(process, Target),
    Parent ! {origin_monitor, self(), Ref},
    receive demonitor -> true = demonitor(Ref), Parent ! origin_demonitored end.

has_link(Links, Pid) ->
    lists:any(fun
        ({erl_link, process, Other, linked, _}) -> Other =:= Pid;
        (_) -> false
    end, Links).

has_monitor(Monitors, Direction, Ref, Pid) ->
    lists:any(fun
        ({erl_monitor, process, OtherDirection, OtherRef, OtherPid, _}) ->
            OtherDirection =:= Direction andalso OtherRef =:= Ref andalso OtherPid =:= Pid;
        (_) -> false
    end, Monitors).

has_named_monitor(Monitors, Direction, Ref, Pid, Name) ->
    lists:any(fun
        ({erl_monitor, process, OtherDirection, OtherRef, OtherPid, OtherName}) ->
            OtherDirection =:= Direction andalso OtherRef =:= Ref andalso
                OtherPid =:= Pid andalso OtherName =:= Name;
        (_) -> false
    end, Monitors).
"#;

#[test]
fn link_and_monitor_introspection_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping link introspection differential");
        return;
    };
    let beam = reference
        .compile_named("proc_link_info_diff", SOURCE, &[])
        .expect("compile link info differential");
    reference
        .load("proc_link_info_diff", &beam)
        .expect("load link info differential");
    let expected = reference.call("proc_link_info_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load link info differential");
    let actual = vm
        .eval_scheduled("proc_link_info_diff", "run", &[], 2, None)
        .expect("run link info differential")
        .term;

    let expected_shape = CallResult::Ok(OwnedTerm::Tuple(vec![
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
        OwnedTerm::atom("true"),
    ]));
    similar_asserts::assert_eq!(expected, expected_shape, "erts introspection checks");
    similar_asserts::assert_eq!(
        expected,
        CallResult::Ok(actual),
        "link and monitor introspection"
    );
}
