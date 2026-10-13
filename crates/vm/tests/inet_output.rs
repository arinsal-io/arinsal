//! Differential coverage of `tcp_inet_output` (queued sends drained on write
//! readiness) against OTP 29.1.1.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

fn source() -> &'static str {
    r#"
-module(inet_output_diff).
-export([run/1]).

run(Case) ->
    catch ets:new(ac_tab, [named_table, public, set]),
    case Case of
        passive_queued_send -> passive_queued_send();
        passive_queued_send_closed -> passive_queued_send_closed()
    end.

%% The sender is passive and never calls recv: the first send leaves bytes in
%% the driver queue, the later ones go over the high watermark and block in
%% gen_tcp:send/2 until the queue drains on write readiness (as Bandit's
%% file:sendfile/5 fallback does with a ranged response).
passive_queued_send() ->
    Chunk = binary:copy(<<"0123456789abcdef">>, 1 bsl 17),
    Chunks = 6,
    {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp}, binary, {active, false}]),
    {ok, Port} = inet:port(L),
    Self = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 5000),
        Sent = [gen_tcp:send(S, Chunk) || _ <- lists:seq(1, Chunks)],
        Self ! {sent, Sent},
        receive done -> gen_tcp:close(S) end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp}, binary, {active, false}], 5000),
    Got = recv_all(C, Chunks * byte_size(Chunk), []),
    Sent = receive {sent, R} -> R after 5000 -> no_sent end,
    gen_tcp:close(C),
    gen_tcp:close(L),
    {Got =:= binary:copy(Chunk, Chunks), Sent}.

%% The peer closes while the sender is blocked in gen_tcp:send/2 on a passive
%% socket: the blocked send returns an error instead of hanging.
passive_queued_send_closed() ->
    Chunk = binary:copy(<<"0123456789abcdef">>, 1 bsl 17),
    {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp}, binary, {active, false}]),
    {ok, Port} = inet:port(L),
    Self = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 5000),
        Self ! accepted,
        Sent = send_until_error(S, Chunk, 64),
        Self ! {sent, Sent}
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp}, binary, {active, false}], 5000),
    receive accepted -> ok end,
    {ok, _} = gen_tcp:recv(C, 1, 5000),
    ok = gen_tcp:close(C),
    Sent = receive {sent, R} -> R after 10000 -> hung end,
    gen_tcp:close(L),
    Sent.

send_until_error(_S, _Chunk, 0) -> all_sent;
send_until_error(S, Chunk, N) ->
    case gen_tcp:send(S, Chunk) of
        ok -> send_until_error(S, Chunk, N - 1);
        {error, Reason} -> {error, Reason}
    end.

recv_all(_S, 0, Acc) -> iolist_to_binary(lists:reverse(Acc));
recv_all(S, Left, Acc) ->
    case gen_tcp:recv(S, 0, 5000) of
        {ok, Bin} -> recv_all(S, Left - byte_size(Bin), [Bin | Acc]);
        {error, Reason} -> {error, Reason, Left}
    end.
"#
}

fn run_case(reference: &RefErl, vm: &mut Vm, case_name: &str) {
    let input = OwnedTerm::Atom(case_name.into());
    let expected = reference
        .call_opts(
            "inet_output_diff",
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
        .eval_scheduled("inet_output_diff", "run", &[arg], 2, None)
        .unwrap_or_else(|error| panic!("{case_name}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{case_name}");
}

#[test]
fn tcp_inet_output_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet_output differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_output_diff", source(), &[])
        .expect("compile inet_output_diff");
    reference
        .load("inet_output_diff", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    for case in ["passive_queued_send", "passive_queued_send_closed"] {
        run_case(&reference, &mut vm, case);
    }
}
