//! Differential `gen_udp` over the `udp_inet` port driver against OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;
use socket2::SockRef;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

fn multicast_probe() -> Result<(), String> {
    let group = Ipv4Addr::new(224, 0, 0, 1);
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("could not bind probe socket: {error}"))?;
    socket
        .join_multicast_v4(&group, &Ipv4Addr::LOCALHOST)
        .map_err(|error| format!("could not join 224.0.0.1: {error}"))?;
    SockRef::from(&socket)
        .set_multicast_if_v4(&Ipv4Addr::LOCALHOST)
        .map_err(|error| format!("could not select loopback multicast interface: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(800)))
        .map_err(|error| format!("could not set probe timeout: {error}"))?;

    let payload = b"arinsal multicast probe";
    let port = socket
        .local_addr()
        .map_err(|error| format!("could not read probe socket address: {error}"))?
        .port();
    socket
        .send_to(payload, (group, port))
        .map_err(|error| format!("could not send multicast probe: {error}"))?;
    let mut received = [0; 64];
    match socket.recv_from(&mut received) {
        Ok((length, _)) if &received[..length] == payload => Ok(()),
        Ok(_) => Err("received a different packet instead of the probe".into()),
        Err(error) => Err(format!("no multicast packet arrived: {error}")),
    }
}

fn source() -> &'static str {
    r#"
-module(inet_udp_diff).
-export([run/1]).

run(Case) ->
    catch ets:new(ac_tab, [named_table, public, set]),
    case Case of
        open -> open();
        passive -> passive();
        active -> active();
        once -> once();
        connected -> connected();
        broadcast -> broadcast();
        options -> options();
        options6 -> options6();
        stat -> stat();
        anc -> anc();
        header -> header();
        mcast -> mcast();
        mcast6 -> mcast6();
        local -> local();
        inet6 -> inet6();
        errors -> errors();
        ctl -> ctl();
        host -> host();
        sctp -> sctp();
        udp6drv -> udp6drv();
        subbin -> subbin();
        stress -> stress()
    end.

%% `inet` selects inet_udp without inet_db (same reason tcp tests pass tcp_module).
udp(Extra) ->
    [inet, {ip, {127,0,0,1}} | Extra].

subbin() ->
    Block = list_to_binary([<<N:32>> || N <- lists:seq(1, 65)]),
    <<_:100/binary, Tail/binary>> = Block,
    <<_:3, Unaligned/binary>> = <<0:3, Block/binary>>,
    <<_:8/binary, Mid:20/binary, _/binary>> = Block,
    Inputs = [Tail, [Tail], [<<"x">>, Tail, <<"y">>, [Mid]], Unaligned, [7, Unaligned], Mid],
    [subbin_send(Input) || Input <- Inputs].

subbin_send(Data) ->
    {ok, R} = gen_udp:open(0, udp([binary, {active, false}])),
    {ok, Port} = inet:port(R),
    {ok, S} = gen_udp:open(0, udp([binary])),
    Sent = gen_udp:send(S, {127,0,0,1}, Port, Data),
    Got = gen_udp:recv(R, 0, 2000),
    gen_udp:close(S),
    gen_udp:close(R),
    Packet = case Got of {ok, {_, _, Bin}} -> Bin; Other -> Other end,
    {iolist_size(Data), Sent, Packet =:= iolist_to_binary(Data)}.

open() ->
    {ok, S} = gen_udp:open(0, udp([binary, {active, false}])),
    {ok, P} = inet:port(S),
    {ok, {IP, P2}} = inet:sockname(S),
    ok = gen_udp:close(S),
    {is_integer(P) andalso P > 0, P =:= P2, IP =:= {0,0,0,0}}.

passive() ->
    exchange([{active, false}, binary], <<"ping">>).

active() ->
    {ok, A} = gen_udp:open(0, udp([binary, {active, true}, {ip, {127,0,0,1}}])),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, udp([binary, {active, false}])),
    ok = gen_udp:send(B, {127,0,0,1}, Port, <<"act">>),
    Got = receive
        {udp, A, IP, _P, Data} -> {IP, Data}
    after 1000 ->
        timeout
    end,
    gen_udp:close(A),
    gen_udp:close(B),
    Got.

once() ->
    {ok, A} = gen_udp:open(0, udp([binary, {active, once}, {ip, {127,0,0,1}}])),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, udp([binary, {active, false}])),
    ok = gen_udp:send(B, {127,0,0,1}, Port, <<"once">>),
    Got = receive
        {udp, A, _IP, _P, Data} -> Data
    after 1000 ->
        timeout
    end,
    {ok, [{active, Active}]} = inet:getopts(A, [active]),
    gen_udp:close(A),
    gen_udp:close(B),
    {Got, Active}.

exchange(Opts, Payload) ->
    {ok, A} = gen_udp:open(0, udp([{ip, {127,0,0,1}} | Opts])),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, udp([binary, {active, false}])),
    ok = gen_udp:send(B, {127,0,0,1}, Port, Payload),
    {ok, {IP, _P, Data}} = gen_udp:recv(A, 0, 1000),
    gen_udp:close(A),
    gen_udp:close(B),
    {IP, Data}.

connected() ->
    {ok, A} = gen_udp:open(0, udp([binary, {active, false}, {ip, {127,0,0,1}}])),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, udp([binary, {active, false}, {ip, {127,0,0,1}}])),
    ok = gen_udp:connect(B, {127,0,0,1}, Port),
    {ok, {{127,0,0,1}, Peer}} = inet:peername(B),
    ok = gen_udp:send(B, <<"con">>),
    {ok, {IP, _P, Data}} = gen_udp:recv(A, 0, 1000),
    gen_udp:close(A),
    gen_udp:close(B),
    {Peer =:= Port, IP, Data}.

broadcast() ->
    {ok, S} = gen_udp:open(0, udp([binary, {active, false}])),
    ok = inet:setopts(S, [{broadcast, true}]),
    {ok, [{broadcast, On}]} = inet:getopts(S, [broadcast]),
    ok = inet:setopts(S, [{broadcast, false}]),
    {ok, [{broadcast, Off}]} = inet:getopts(S, [broadcast]),
    gen_udp:close(S),
    {On, Off}.

options() ->
    {ok, S} = gen_udp:open(0, udp([binary, {active, false}])),
    Pairs = [
        {multicast_ttl, 2},
        {multicast_loop, false},
        {reuseaddr, true},
        {reuseport, true},
        {dontroute, true},
        {tos, 16},
        {ttl, 8},
        {recvtos, true},
        {recvttl, true},
        {buffer, 4096},
        {read_packets, 3},
        {header, 2},
        {mode, list},
        {deliver, port},
        {sndbuf, 16384},
        {recbuf, 32768}
    ],
    Set = [{K, inet:setopts(S, [{K, V}])} || {K, V} <- Pairs],
    {ok, Got} = inet:getopts(S, [K || {K, _} <- Pairs] ++ [active]),
    MifSet = inet:setopts(S, [{multicast_if, {127,0,0,1}}]),
    {ok, [{multicast_if, _}]} = inet:getopts(S, [multicast_if]),
    gen_udp:close(S),
    {Set, norm_mif(Got), MifSet}.

options6() ->
    {ok, S} = gen_udp:open(0, [inet6, {ip, {0,0,0,0,0,0,0,1}}, binary, {active, false}]),
    Set = inet:setopts(S, [{ipv6_v6only, true}, {buffer, 2048}, {read_packets, 4}]),
    {ok, Got} = inet:getopts(S, [ipv6_v6only, buffer, read_packets, mode]),
    Mif = inet:setopts(S, [{multicast_if, 1}]),
    GetMif = case inet:getopts(S, [multicast_if]) of
        {ok, [{multicast_if, _}]} -> got;
        Other -> Other
    end,
    gen_udp:close(S),
    {Set, Got, Mif, GetMif}.

norm_mif(Opts) ->
    [case Opt of
        {multicast_if, _} -> {multicast_if, got};
        Other -> Other
     end || Opt <- Opts].

stat() ->
    {ok, A} = gen_udp:open(0, udp([binary, {active, false}, {ip, {127,0,0,1}}])),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, udp([binary, {active, false}])),
    ok = gen_udp:send(B, {127,0,0,1}, Port, <<"stat">>),
    {ok, {_, _, <<"stat">>}} = gen_udp:recv(A, 0, 1000),
    {ok, Recv} = inet:getstat(A),
    {ok, Send} = inet:getstat(B),
    gen_udp:close(A),
    gen_udp:close(B),
    {Recv, Send}.

anc() ->
    {ok, A} = gen_udp:open(0, udp([binary, {active, false}, {recvtos, true}, {recvttl, true}, {ip, {127,0,0,1}}])),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, udp([binary, {active, false}])),
    Send = gen_udp:send(B, {127,0,0,1}, Port, [{tos, 16}, {ttl, 8}], <<"anc">>),
    Recv = gen_udp:recv(A, 0, 1000),
    gen_udp:close(A),
    gen_udp:close(B),
    case Recv of
        {ok, {IP, _, Anc, Data}} -> {Send, IP, lists:sort(Anc), Data};
        Other -> {Send, Other}
    end.

header() ->
    {ok, A} = gen_udp:open(0, udp([binary, {active, false}, {header, 2}, {ip, {127,0,0,1}}])),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, udp([binary, {active, false}])),
    ok = gen_udp:send(B, {127,0,0,1}, Port, <<1,2,3,4>>),
    {ok, {_IP, _P, Data}} = gen_udp:recv(A, 0, 1000),
    gen_udp:close(A),
    gen_udp:close(B),
    Data.

mcast() ->
    case gen_udp:open(0, [inet, {ip, {224,0,0,1}}, binary, {active, false}, {reuseaddr, true},
                          {add_membership, {{224,0,0,1}, {127,0,0,1}}}]) of
        {ok, M} ->
            {ok, Port} = inet:port(M),
            {ok, N} = gen_udp:open(0, udp([binary, {active, false}, {multicast_if, {127,0,0,1}}, {multicast_ttl, 1}, {multicast_loop, true}])),
            Send = gen_udp:send(N, {224,0,0,1}, Port, <<"mc">>),
            Recv = case gen_udp:recv(M, 0, 800) of
                {ok, {_IP, _P, Bin}} -> Bin;
                Other -> Other
            end,
            Drop = inet:setopts(M, [{drop_membership, {{224,0,0,1}, {127,0,0,1}}}]),
            gen_udp:close(M),
            gen_udp:close(N),
            {Send, Recv, Drop};
        Err ->
            Err
    end.

mcast6() ->
    %% Loopback only: lo0 (interface index 1 on macOS) for the membership and the sends.
    case gen_udp:open(0, [inet6, {ip, {0,0,0,0,0,0,0,1}}, binary, {active, false}, {ipv6_v6only, true},
                          {add_membership, {{16#ff02,0,0,0,0,0,0,1}, 1}}]) of
        {ok, M} ->
            {ok, Port} = inet:port(M),
            {ok, N} = gen_udp:open(0, [inet6, {ip, {0,0,0,0,0,0,0,1}}, binary, {active, false}, {multicast_if, 1}, {multicast_loop, true}]),
            Send = gen_udp:send(N, {16#ff02,0,0,0,0,0,0,1}, Port, <<"mc6">>),
            Recv = case gen_udp:recv(M, 0, 800) of
                {ok, {_IP, _P, Bin}} -> Bin;
                Other -> Other
            end,
            gen_udp:close(M),
            gen_udp:close(N),
            {joined, Send, Recv};
        Err ->
            Err
    end.

local() ->
    Name = "arinsal-udp-" ++ integer_to_list(erlang:unique_integer([positive])),
    Path = filename:join(["/tmp", Name]),
    _ = prim_file:delete(Path),
    {ok, A} = gen_udp:open(0, [local, binary, {active, false}, {ifaddr, {local, Path}}]),
    {ok, B} = gen_udp:open(0, [local, binary, {active, false}]),
    ok = gen_udp:send(B, {local, Path}, 0, <<"loc">>),
    {ok, {_Addr, _Port, Data}} = gen_udp:recv(A, 0, 1000),
    gen_udp:close(A),
    gen_udp:close(B),
    _ = prim_file:delete(Path),
    Data.

inet6() ->
    {ok, A} = gen_udp:open(0, [inet6, {ip, {0,0,0,0,0,0,0,1}}, binary, {active, false}, {ipv6_v6only, true}]),
    {ok, {_, Port}} = inet:sockname(A),
    {ok, B} = gen_udp:open(0, [inet6, {ip, {0,0,0,0,0,0,0,1}}, binary, {active, false}]),
    ok = gen_udp:send(B, {0,0,0,0,0,0,0,1}, Port, <<"v6">>),
    {ok, {IP, _P, Data}} = gen_udp:recv(A, 0, 1000),
    gen_udp:close(A),
    gen_udp:close(B),
    {IP, Data}.

errors() ->
    {ok, S} = gen_udp:open(0, udp([binary, {active, false}])),
    Timeout = gen_udp:recv(S, 0, 40),
    Active = inet:setopts(S, [{active, true}]),
    WhileActive = gen_udp:recv(S, 0, 40),
    BadPackets = inet:setopts(S, [{read_packets, 0}]),
    ok = gen_udp:close(S),
    Closed = gen_udp:send(S, {127,0,0,1}, 9, <<"z">>),
    {Timeout, Active, WhileActive, BadPackets, Closed}.

ctl() ->
    {ok, S} = gen_udp:open(0, udp([binary, {active, false}])),
    Parent = self(),
    Pid = spawn(fun() ->
        receive
            go -> Parent ! {ctl, gen_udp:controlling_process(S, self())}
        end
    end),
    First = gen_udp:controlling_process(S, Pid),
    Pid ! go,
    Second = receive
        {ctl, V} -> V
    after 1000 ->
        timeout
    end,
    gen_udp:close(S),
    {First, Second}.

host() ->
    {ok, S} = gen_udp:open(0, udp([binary, {active, false}])),
    Host = inet:gethostname(S),
    gen_udp:close(S),
    Host.

sctp() ->
    gen_sctp:open([{sctp_module, inet_sctp}]).

udp6drv() ->
    case catch open_port({spawn_driver, "udp_inet6"}, [binary]) of
        {'EXIT', {badarg, _}} -> badarg;
        Other -> {unexpected, Other}
    end.

stress() ->
    Workers = [spawn_monitor(fun() -> stress_worker(20) end) || _ <- lists:seq(1, 6)],
    wait_workers(Workers, 15000).

stress_worker(0) -> ok;
stress_worker(N) ->
    {ok, A} = gen_udp:open(0, [inet, binary, {active, true}, {ip, {127,0,0,1}}]),
    {ok, Port} = inet:port(A),
    {ok, B} = gen_udp:open(0, [inet, {ip, {127,0,0,1}}, binary, {active, false}]),
    {Sender, SenderRef} = spawn_monitor(fun() -> gen_udp:send(B, {127,0,0,1}, Port, <<N:32>>) end),
    ok = gen_udp:close(A),
    ok = gen_udp:close(B),
    receive {'DOWN', SenderRef, process, Sender, _} -> ok after 1000 -> exit(sender_timeout) end,
    stress_worker(N - 1).

wait_workers([], _) -> true;
wait_workers(Workers, Timeout) ->
    receive
        {'DOWN', Ref, process, _Pid, normal} -> wait_workers(lists:keydelete(Ref, 2, Workers), Timeout);
        {'DOWN', Ref, process, _Pid, Reason} -> {worker_failed, Reason}
    after Timeout -> timeout
    end.
"#
}

#[test]
fn gen_udp_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet_udp differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_udp_diff", source(), &[])
        .expect("compile inet_udp_diff");
    reference
        .load("inet_udp_diff", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    let multicast_available = match multicast_probe() {
        Ok(()) => true,
        Err(reason) => {
            eprintln!("skipping inet_udp mcast differential case: {reason}");
            false
        }
    };
    for case in [
        "open",
        "passive",
        "active",
        "once",
        "connected",
        "broadcast",
        "options",
        "options6",
        "stat",
        "anc",
        "header",
        "mcast",
        "mcast6",
        "local",
        "inet6",
        "errors",
        "ctl",
        "host",
        "sctp",
        "udp6drv",
        "subbin",
        "stress",
    ] {
        if case == "mcast" && !multicast_available {
            continue;
        }
        let input = OwnedTerm::Atom(case.into());
        let expected = reference.call("inet_udp_diff", "run", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval_scheduled("inet_udp_diff", "run", &[arg], 2, None)
            .unwrap_or_else(|error| panic!("{case}: {error}"));
        similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{case}");
    }
}
