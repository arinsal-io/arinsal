//! `register/2`, `unregister/1`, `whereis/1`, `registered/0` (register.c) and `is_process_alive/1`
//! (erl_bif_info.c) against erl: taken names, registered pids, dead pids, ports, `undefined`, and the
//! badarg causes in `error_info`.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::VmError;

const SOURCE: &str = r#"
-module(register_bif).
-export([run/0]).
-compile(nowarn_unused_function).

%% Runs in a fresh process: the caller's trap_exit and leftover messages stay out of it.
run() ->
    {P, R} = spawn_monitor(fun() -> exit({result, run1()}) end),
    receive {'DOWN', R, process, P, Reason} -> Reason after 10000 -> timeout end.

norm(T) when is_pid(T) -> pid;
norm(T) when is_port(T) -> port;
norm(T) when is_reference(T) -> ref;
norm(T) when is_list(T) -> [norm(E) || E <- T];
norm(T) when is_tuple(T) -> list_to_tuple(norm(tuple_to_list(T)));
norm(T) -> T.

catching(F) ->
    try F() of
        V -> {ok, V}
    catch C:R:St ->
        [{M, Fn, A, Info} | _] = St,
        {C, R, M, Fn, arity(A), proplists:get_value(error_info, Info)}
    end.

arity(A) when is_list(A) -> length(A);
arity(A) -> A.

dead() ->
    Dead = spawn(fun() -> ok end),
    R = monitor(process, Dead),
    receive {'DOWN', R, process, _, _} -> Dead end.

run1() ->
    M = erlang,
    Self = self(),
    Dead = dead(),
    W = spawn(fun() -> receive stop -> ok end end),
    Port = open_port({spawn, "cat"}, []),
    Before = lists:sort(registered()),
    Cases = [
        {reg_self, register(reg_bif_a, Self)},
        {whereis_self, whereis(reg_bif_a) =:= Self},
        {reg_taken, catching(fun() -> M:register(reg_bif_a, W) end)},
        {reg_again, catching(fun() -> M:register(reg_bif_b, Self) end)},
        {reg_dead, catching(fun() -> M:register(reg_bif_c, Dead) end)},
        {reg_undefined, catching(fun() -> M:register(undefined, W) end)},
        {reg_not_atom, catching(fun() -> M:register("x", W) end)},
        {reg_bad_id, catching(fun() -> M:register(reg_bif_d, foo) end)},
        {reg_other, M:register(reg_bif_w, W)},
        {whereis_other, M:whereis(reg_bif_w) =:= W},
        {reg_port, register(reg_bif_port, Port)},
        {whereis_port, whereis(reg_bif_port) =:= Port},
        {reg_port_again, catching(fun() -> M:register(reg_bif_port2, Port) end)},
        {registered, lists:sort(registered()) -- Before},
        {registered_apply, lists:sort(M:registered()) -- Before},
        {whereis_missing, whereis(reg_bif_missing)},
        {whereis_bad, catching(fun() -> M:whereis("x") end)},
        {unreg_port, unregister(reg_bif_port)},
        {unreg_w, M:unregister(reg_bif_w)},
        {unreg_missing, catching(fun() -> M:unregister(reg_bif_w) end)},
        {unreg_bad, catching(fun() -> M:unregister(1) end)},
        {unreg_self, unregister(reg_bif_a)},
        {whereis_after, whereis(reg_bif_a)},
        {reg_after, register(reg_bif_a, Self), unregister(reg_bif_a)},
        {alive_self, is_process_alive(Self)},
        {alive_other, M:is_process_alive(W)},
        {alive_dead, is_process_alive(Dead)},
        {alive_bad, catching(fun() -> M:is_process_alive(foo) end)},
        {alive_port, catching(fun() -> M:is_process_alive(Port) end)},
        {alive_exiting, begin exit(W, kill), is_process_alive(W) end},
        {alive_signals, begin
            W2 = spawn(fun() -> receive stop -> ok end end),
            [W2 ! x || _ <- lists:seq(1, 10)],
            exit(W2, kill),
            is_process_alive(W2) end}
    ],
    port_close(Port),
    Cases.
"#;

#[test]
fn register_bifs_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("register_bif", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("register_bif", &beam)
        .expect("load reference module");
    let expected = reference.call("register_bif", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("register_bif", "run", &[], 2) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("register BIFs differ: {diff}"));
}
