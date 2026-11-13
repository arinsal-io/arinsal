//! `'!'/2`, `send/2` and `send/3` (bif.c `erl_send`, `send_3`) against erl: the `send`
//! instruction, static and applied calls, every destination kind, `send/3` options, and the
//! badarg cases with their `error_info`.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::VmError;

const SOURCE: &str = r#"
-module(send_bif).
-export([run/0]).

catching(F) ->
    try F() of
        V -> {ok, V}
    catch C:R:St ->
        [{M, Fn, A, Info} | _] = St,
        {C, R, M, Fn, length(A), proplists:get_value(error_info, Info)}
    end.

got() -> receive X -> {got, X} after 1000 -> timeout end.

run() ->
    Self = self(),
    M = erlang,
    register(send_bif_name, Self),
    Dead = spawn(fun() -> ok end),
    DeadRef = monitor(process, Dead),
    dead = receive {'DOWN', DeadRef, process, _, _} -> dead end,
    Alias = alias(),
    Cases = [
        {bang_pid, Self ! a, got()},
        {bang_name, send_bif_name ! b, got()},
        {bang_name_node, {send_bif_name, node()} ! c, got()},
        {bang_alias, Alias ! d, got()},
        {bang_dead, Dead ! e},
        {apply_bang, M:'!'(Self, f), got()},
        {send2, erlang:send(Self, g), got()},
        {send2_apply, M:send(send_bif_name, h), got()},
        {send3, erlang:send(Self, i, []), got()},
        {send3_opts, erlang:send(Self, j, [noconnect, nosuspend]), got()},
        {send3_name, erlang:send(send_bif_name, k, [nosuspend]), got()},
        {send3_priority, erlang:send(Self, l, [priority]), got()},
        {send3_apply, M:send(Self, m, [noconnect]), got()},
        {name_node_missing, {no_such_name, node()} ! n},
        {bad_bang_name, catching(fun() -> no_such_name ! o end)},
        {bad_bang_int, catching(fun() -> M:'!'(1, o) end)},
        {bad_send2_name, catching(fun() -> M:send(no_such_name, o) end)},
        {bad_send2_tuple, catching(fun() -> M:send({a, b, c}, o) end)},
        {bad_send3_opt, catching(fun() -> M:send(Self, o, [bad]) end)},
        {bad_send3_list, catching(fun() -> M:send(Self, o, [noconnect | nosuspend]) end)},
        {bad_send3_name, catching(fun() -> M:send(no_such_name, o, []) end)},
        {remote_not_alive, catching(fun() -> M:send({a, other@host}, o) end)},
        {remote3_not_alive, catching(fun() -> M:send({a, other@host}, o, [noconnect]) end)}
    ],
    unregister(send_bif_name),
    {Cases, receive Any -> {leftover, Any} after 50 -> clean end}.
"#;

#[test]
fn send_bifs_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("send_bif", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("send_bif", &beam)
        .expect("load reference module");
    let expected = reference.call("send_bif", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("send_bif", "run", &[], 2) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("send BIFs differ: {diff}"));
}
