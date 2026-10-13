//! Differential coverage of the `tcp_inet` poll-set selection (`driver_select`
//! re-arming after each port task) against OTP 29.1.1: many sockets, receive
//! timers, `{active, once}` re-arming, accept bursts and descriptor reuse.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

fn source() -> &'static str {
    r#"
-module(inet_poll_diff).
-export([run/1]).

run(Case) ->
    catch ets:new(ac_tab, [named_table, public, set]),
    case Case of
        many_idle_echo -> many_idle_echo();
        recv_timeout_rearm -> recv_timeout_rearm();
        active_once_rearm -> active_once_rearm();
        accept_burst -> accept_burst();
        fd_reuse -> fd_reuse()
    end.

opts(Extra) ->
    [{tcp_module, inet_tcp}, binary, {active, false} | Extra].

pair(L, Port) ->
    Self = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 5000),
        ok = gen_tcp:controlling_process(S, Self),
        Self ! {accepted, S}
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, opts([]), 5000),
    S = receive {accepted, A} -> A after 5000 -> exit(no_accept) end,
    {C, S}.

listener() ->
    {ok, L} = gen_tcp:listen(0, opts([{backlog, 128}])),
    {ok, Port} = inet:port(L),
    {L, Port}.

%% 100 idle connections, each with a receive pending, while 8 others echo 1 MB.
many_idle_echo() ->
    {L, Port} = listener(),
    Idle = [pair(L, Port) || _ <- lists:seq(1, 100)],
    Waiters = [spawn(fun() -> gen_tcp:recv(S, 0) end) || {_, S} <- Idle],
    Busy = [pair(L, Port) || _ <- lists:seq(1, 8)],
    Self = self(),
    Data = binary:copy(<<"abcdefgh">>, 1 bsl 17),
    [spawn(fun() ->
         {ok, Got} = gen_tcp:recv(S, byte_size(Data), 5000),
         ok = gen_tcp:send(S, Got),
         Self ! echoed
     end) || {_, S} <- Busy],
    [ok = gen_tcp:send(C, Data) || {C, _} <- Busy],
    Echoes = [gen_tcp:recv(C, byte_size(Data), 5000) =:= {ok, Data} || {C, _} <- Busy],
    [receive echoed -> ok after 5000 -> exit(no_echo) end || _ <- Busy],
    [exit(W, kill) || W <- Waiters],
    [begin gen_tcp:close(C), gen_tcp:close(S) end || {C, S} <- Idle ++ Busy],
    gen_tcp:close(L),
    Echoes.

%% A receive timer fires, then data arrives: the next recv must still see it.
recv_timeout_rearm() ->
    {L, Port} = listener(),
    {C, S} = pair(L, Port),
    R1 = gen_tcp:recv(S, 0, 50),
    R2 = gen_tcp:recv(S, 0, 0),
    ok = gen_tcp:send(C, <<"late">>),
    R3 = gen_tcp:recv(S, 0, 2000),
    ok = gen_tcp:send(C, <<"again">>),
    R4 = gen_tcp:recv(S, 5, 2000),
    gen_tcp:close(C), gen_tcp:close(S), gen_tcp:close(L),
    {R1, R2, R3, R4}.

%% {active, once} 200 times: every delivery deselects, every setopts re-arms.
active_once_rearm() ->
    {L, Port} = listener(),
    {C, S} = pair(L, Port),
    N = 200,
    Got = lists:map(fun(I) ->
        ok = inet:setopts(S, [{active, once}]),
        ok = gen_tcp:send(C, <<I:32>>),
        receive {tcp, S, <<I:32>>} -> ok after 2000 -> {timeout, I} end
    end, lists:seq(1, N)),
    gen_tcp:close(C), gen_tcp:close(S), gen_tcp:close(L),
    lists:usort(Got).

%% 50 connects at once against 50 pending accepts.
accept_burst() ->
    {L, Port} = listener(),
    Self = self(),
    [spawn(fun() -> Self ! {acc, gen_tcp:accept(L, 5000)} end) || _ <- lists:seq(1, 50)],
    Cs = [begin {ok, C} = gen_tcp:connect({127,0,0,1}, Port, opts([]), 5000), C end
          || _ <- lists:seq(1, 50)],
    Accepted = [receive {acc, {ok, _}} -> ok; {acc, E} -> E after 5000 -> timeout end
                || _ <- lists:seq(1, 50)],
    [gen_tcp:close(C) || C <- Cs],
    gen_tcp:close(L),
    lists:usort(Accepted).

%% Close sockets with a receive pending, then open new ones (the kernel hands
%% out the same descriptor numbers) and use them.
fd_reuse() ->
    {L, Port} = listener(),
    First = [pair(L, Port) || _ <- lists:seq(1, 20)],
    Self = self(),
    [spawn(fun() -> Self ! {first, gen_tcp:recv(S, 0, 5000)} end) || {_, S} <- First],
    receive after 50 -> ok end,
    [gen_tcp:close(C) || {C, _} <- First],
    Closed = lists:usort([receive {first, R} -> R after 5000 -> timeout end || _ <- First]),
    [gen_tcp:close(S) || {_, S} <- First],
    Second = [pair(L, Port) || _ <- lists:seq(1, 20)],
    Echo = [begin
                ok = gen_tcp:send(C, <<"x">>),
                gen_tcp:recv(S, 1, 2000)
            end || {C, S} <- Second],
    [begin gen_tcp:close(C), gen_tcp:close(S) end || {C, S} <- Second],
    gen_tcp:close(L),
    {Closed, lists:usort(Echo)}.
"#
}

fn run_case(reference: &RefErl, vm: &mut Vm, case_name: &str) {
    let input = OwnedTerm::Atom(case_name.into());
    let expected = reference
        .call_opts(
            "inet_poll_diff",
            "run",
            std::slice::from_ref(&input),
            &CallOptions {
                timeout_ms: Some(60_000),
                ..CallOptions::default()
            },
        )
        .result;
    let mut heap = VecHeap::new();
    let arg = from_owned(&input, &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("inet_poll_diff", "run", &[arg], 2, None)
        .unwrap_or_else(|error| panic!("{case_name}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{case_name}");
}

#[test]
fn tcp_poll_selection_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet_poll differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_poll_diff", source(), &[])
        .expect("compile inet_poll_diff");
    reference
        .load("inet_poll_diff", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    for case in [
        "many_idle_echo",
        "recv_timeout_rearm",
        "active_once_rearm",
        "accept_burst",
        "fd_reuse",
    ] {
        run_case(&reference, &mut vm, case);
    }
}
