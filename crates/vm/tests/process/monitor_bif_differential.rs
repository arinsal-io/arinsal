//! `monitor/2,3` and `demonitor/1,2` (bif.c `monitor`, `demonitor`) against erl: every target
//! kind, aliases, tags, `info`/`flush`, and the badarg cases with their `error_info` cause,
//! called statically and through `apply`.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(monitor_bif).
-export([run/0]).

catching(F) ->
    try F() of
        Ref when is_reference(Ref) -> ref;
        V -> {ok, V}
    catch C:R:St ->
        [{M, Fn, A, Info} | _] = St,
        {C, R, M, Fn, length(A), proplists:get_value(error_info, Info)}
    end.

down(Ref) ->
    receive {'DOWN', Ref, T, O, R} -> {T, norm(O), R} after 1000 -> timeout end.

down(Tag, Ref) ->
    receive {Tag, Ref, T, O, R} -> {T, norm(O), R} after 1000 -> timeout end.

norm(P) when is_pid(P) -> pid;
norm(O) -> O.

run() ->
    Self = self(),
    Live = spawn(fun() -> receive stop -> ok end end),
    Dead = spawn(fun() -> ok end),
    DeadRef = monitor(process, Dead),
    dead = receive {'DOWN', DeadRef, process, _, _} -> dead end,
    register(monitor_bif_name, Live),
    M = erlang,
    Cases = [
        %% pid, self, dead pid
        {pid, (fun() -> R = monitor(process, Live), {erlang:demonitor(R), erlang:demonitor(R)} end)()},
        {self, catching(fun() -> monitor(process, Self) end)},
        {self_demonitor, erlang:demonitor(monitor(process, Self), [info])},
        {dead, down(monitor(process, Dead))},
        {dead_apply, down(M:monitor(process, Dead))},
        %% names
        {name, (fun() -> R = monitor(process, monitor_bif_name), erlang:demonitor(R, [info]) end)()},
        {name_dead, down(monitor(process, no_such_name))},
        {name_node, down(monitor(process, {no_such_name, node()}))},
        {name_node_live,
         (fun() -> R = monitor(process, {monitor_bif_name, node()}), erlang:demonitor(R, [info]) end)()},
        %% options
        {tag, down(my_tag, monitor(process, Dead, [{tag, my_tag}]))},
        {alias, (fun() ->
                    R = monitor(process, Live, [{alias, demonitor}]),
                    {erlang:demonitor(R, [info]), unalias(R)}
                end)()},
        {alias_explicit, (fun() ->
                             R = monitor(process, Live, [{alias, explicit_unalias}]),
                             {erlang:demonitor(R, [info]), unalias(R)}
                         end)()},
        {alias_reply, (fun() ->
                          R = monitor(process, Live, [{alias, reply_demonitor}]),
                          erlang:demonitor(R, [info, flush])
                      end)()},
        {priority, (fun() -> R = monitor(process, Live, [priority]), erlang:demonitor(R) end)()},
        %% info / flush
        {info_gone, erlang:demonitor(make_ref(), [info])},
        {flush_gone, (fun() ->
                         R = monitor(process, Dead),
                         receive after 10 -> ok end,
                         {erlang:demonitor(R, [flush, info]), receive X -> X after 0 -> none end}
                     end)()},
        {flush_apply, (fun() ->
                          R = monitor(process, Dead),
                          receive after 10 -> ok end,
                          {M:demonitor(R, [flush]), receive X -> X after 0 -> none end}
                      end)()},
        {alias_demonitor, (fun() -> A = alias(), {erlang:demonitor(A), erlang:demonitor(A, [info])} end)()},
        %% port and time offset
        {port_dead, down(monitor(port, no_such_port))},
        {time_offset, catching(fun() -> monitor(time_offset, clock_service) end)},
        {time_offset3, catching(fun() -> monitor(time_offset, clock_service, []) end)},
        %% badarg
        {badtype, catching(fun() -> M:monitor(foo, Self) end)},
        {badopt, catching(fun() -> M:monitor(process, Self, [bad]) end)},
        {badopt_alias, catching(fun() -> M:monitor(process, Self, [{alias, bad}]) end)},
        {bad_target, catching(fun() -> M:monitor(process, {a, b, c}) end)},
        {bad_target_int, catching(fun() -> M:monitor(process, 1) end)},
        {remote_not_alive, catching(fun() -> M:monitor(process, {a, other@host}) end)},
        {port_remote, catching(fun() -> M:monitor(port, {a, other@host}) end)},
        {time_offset_bad, catching(fun() -> M:monitor(time_offset, foo) end)},
        {demonitor_bad, catching(fun() -> M:demonitor(foo) end)},
        {demonitor_badopt, catching(fun() -> M:demonitor(make_ref(), [bad]) end)},
        {demonitor_badlist, catching(fun() -> M:demonitor(make_ref(), [info | flush]) end)}
    ],
    Live ! stop,
    {Cases, receive Any -> {leftover, Any} after 50 -> clean end}.
"#;

#[test]
fn monitor_and_demonitor_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("monitor_bif", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("monitor_bif", &beam)
        .expect("load reference module");
    let expected = reference.call("monitor_bif", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("monitor_bif", "run", &[], 2, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("monitor BIFs differ: {diff}"));
}
