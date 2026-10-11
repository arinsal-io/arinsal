//! Differential `gen_tcp` over the `tcp_inet` port driver against OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

fn source() -> &'static str {
    r#"
-module(inet_tcp_diff).
-export([run/1]).

run(Case) ->
    catch ets:new(ac_tab, [named_table, public, set]),
    case Case of
        listen -> listen();
        echo -> echo();
        active_once -> active_once();
        active_true -> active_true();
        packet4 -> packet4();
        line -> line();
        closed_peer -> closed_peer();
        closed_local -> closed_local();
        accept_timeout -> accept_timeout();
        refused -> refused();
        connect_timeout -> connect_timeout();
        names -> names();
        udp -> udp();
        sctp -> sctp();
        inet6 -> inet6()
    end.

tcp(Extra) ->
    [{tcp_module, inet_tcp} | Extra].

listen() ->
    {ok, L} = gen_tcp:listen(0, tcp([{active, false}])),
    {ok, P} = inet:port(L),
    ok = gen_tcp:close(L),
    is_integer(P) andalso P > 0.

echo() ->
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    {ok, Port} = inet:port(L),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        {ok, Bin} = gen_tcp:recv(S, 4, 2000),
        ok = gen_tcp:send(S, Bin),
        receive after 200 -> ok end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary, {active, false}]), 2000),
    ok = gen_tcp:send(C, <<"ping">>),
    {ok, Got} = gen_tcp:recv(C, 4, 2000),
    gen_tcp:close(C),
    gen_tcp:close(L),
    Got.

active_once() ->
    exchange(tcp([{active, once}, binary]), <<"once">>).

active_true() ->
    exchange(tcp([{active, true}, binary]), <<"true">>).

exchange(Opts, Payload) ->
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    {ok, Port} = inet:port(L),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        ok = gen_tcp:send(S, Payload),
        receive after 300 -> ok end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, Opts, 2000),
    Got = receive
        {tcp, C, Data} -> Data
    after 2000 ->
        timeout
    end,
    {ok, [{active, Active}]} = inet:getopts(C, [active]),
    gen_tcp:close(C),
    gen_tcp:close(L),
    {Got, Active}.

packet4() ->
    framed(4, <<"abcd">>).

line() ->
    framed(line, <<"hi\n">>).

framed(Mode, Payload) ->
    Opts = tcp([binary, {active, false}, {packet, Mode}]),
    {ok, L} = gen_tcp:listen(0, Opts),
    {ok, Port} = inet:port(L),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        {ok, Bin} = gen_tcp:recv(S, 0, 2000),
        ok = gen_tcp:send(S, Bin)
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, Opts, 2000),
    ok = gen_tcp:send(C, Payload),
    {ok, Got} = gen_tcp:recv(C, 0, 2000),
    gen_tcp:close(C),
    gen_tcp:close(L),
    Got.

closed_peer() ->
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    {ok, Port} = inet:port(L),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        gen_tcp:close(S)
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary, {active, true}]), 2000),
    Msg = receive
        {tcp_closed, C} -> closed
    after 2000 ->
        timeout
    end,
    gen_tcp:close(L),
    Msg.

closed_local() ->
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    {ok, Port} = inet:port(L),
    Parent = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        ok = inet:setopts(S, [{active, true}]),
        receive
            {tcp_closed, S} -> Parent ! closed
        after 2000 ->
            Parent ! timeout
        end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary, {active, false}]), 2000),
    ok = gen_tcp:send(C, <<"x">>),
    ok = gen_tcp:close(C),
    Msg = receive
        M -> M
    after 2000 ->
        parent_timeout
    end,
    gen_tcp:close(L),
    Msg.

accept_timeout() ->
    {ok, L} = gen_tcp:listen(0, tcp([{active, false}])),
    Result = gen_tcp:accept(L, 80),
    gen_tcp:close(L),
    Result.

refused() ->
    gen_tcp:connect({127,0,0,1}, 1, tcp([{active, false}]), 400).

%% 192.0.2.1 is TEST-NET-1 (RFC 5737): the SYN is not answered, so the
%% connect timer fires. erts closes the socket and returns `{error, timeout}`.
connect_timeout() ->
    gen_tcp:connect({192,0,2,1}, 1, tcp([{active, false}]), 200).

names() ->
    {ok, L} = gen_tcp:listen(0, tcp([{ip, {127,0,0,1}}, {active, false}])),
    {ok, Port} = inet:port(L),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        receive after 300 -> gen_tcp:close(S) end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([{active, false}]), 2000),
    {ok, {PeerIp, PeerPort}} = inet:peername(C),
    {ok, {LocalIp, LocalPort}} = inet:sockname(C),
    gen_tcp:close(C),
    gen_tcp:close(L),
    {PeerIp, LocalIp, PeerPort =:= Port, is_integer(LocalPort), LocalPort =/= Port}.

udp() ->
    {ok, S} = gen_udp:open(0, [{udp_module, inet_udp}]),
    ok = gen_udp:close(S),
    ok.

sctp() ->
    gen_sctp:open([{sctp_module, inet_sctp}]).

inet6() ->
    {ok, L} = gen_tcp:listen(0, [inet6, {active, false}]),
    {ok, P} = inet:port(L),
    ok = gen_tcp:close(L),
    is_integer(P) andalso P > 0.
"#
}

#[test]
fn gen_tcp_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet_tcp differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_tcp_diff", source(), &[])
        .expect("compile inet_tcp_diff");
    reference
        .load("inet_tcp_diff", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    for case in [
        "listen",
        "echo",
        "active_once",
        "active_true",
        "packet4",
        "line",
        "closed_peer",
        "closed_local",
        "accept_timeout",
        "refused",
        "connect_timeout",
        "names",
        "inet6",
        "udp",
    ] {
        let input = OwnedTerm::Atom(case.into());
        let expected = reference.call("inet_tcp_diff", "run", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval_scheduled("inet_tcp_diff", "run", &[arg], 2, None)
            .unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{case}");
    }
    // sctp_inet is not a driver on macOS. prim_inet maps the open_port
    // badarg onto {error, eprotonosupport}, the same term erts returns.
    let input = OwnedTerm::Atom("sctp".into());
    let mut heap = VecHeap::new();
    let arg = from_owned(&input, &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("inet_tcp_diff", "run", &[arg], 2, None)
        .unwrap_or_else(|error| panic!("sctp: {error}"));
    assert_eq!(
        actual.term,
        OwnedTerm::Tuple(vec![
            OwnedTerm::Atom("error".into()),
            OwnedTerm::Atom("eprotonosupport".into()),
        ])
    );
}
