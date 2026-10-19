//! Differential `gen_tcp` over the `tcp_inet` port driver against OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;
use std::sync::Mutex;

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
        subbin -> subbin();
        sctp -> sctp();
        inet6 -> inet6();
        sendfile -> sendfile();
        sendfile_large -> sendfile_large();
        sendfile_ranges -> sendfile_ranges();
        sendfile_queued -> sendfile_queued();
        sendfile_errors -> sendfile_errors();
        sendfile_raw -> sendfile_raw();
        sendfile_reset -> sendfile_reset();
        sendfile_active_true -> sendfile_active_true();
        sendfile_active_once -> sendfile_active_once();
        empty_out_q -> empty_out_q();
        close_empty_out_q -> close_empty_out_q()
    end.

tcp(Extra) ->
    [{tcp_module, inet_tcp}, {ip, {127,0,0,1}} | Extra].

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

subbin() ->
    Block = list_to_binary([<<N:32>> || N <- lists:seq(1, 65)]),
    <<_:100/binary, Tail/binary>> = Block,
    <<_:3, Unaligned/binary>> = <<0:3, Block/binary>>,
    <<_:8/binary, Mid:20/binary, _/binary>> = Block,
    Inputs = [Tail, [Tail], [<<"x">>, Tail, <<"y">>, [Mid]], Unaligned, [7, Unaligned], Mid],
    [subbin_send(Input) || Input <- Inputs].

subbin_send(Data) ->
    Size = iolist_size(Data),
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    {ok, Port} = inet:port(L),
    Parent = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        Parent ! {sent, gen_tcp:send(S, Data)},
        receive after 500 -> ok end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary, {active, false}]), 2000),
    Got = gen_tcp:recv(C, Size, 2000),
    Extra = gen_tcp:recv(C, 0, 100),
    Sent = receive {sent, R} -> R after 2000 -> timeout end,
    gen_tcp:close(C),
    gen_tcp:close(L),
    {Size, Sent, Got =:= {ok, iolist_to_binary(Data)}, Extra}.

udp() ->
    {ok, S} = gen_udp:open(0, [{udp_module, inet_udp}, {ip, {127,0,0,1}}]),
    ok = gen_udp:close(S),
    ok.

sctp() ->
    gen_sctp:open([{sctp_module, inet_sctp}]).

inet6() ->
    {ok, L} = gen_tcp:listen(0, [inet6, {ip, {0,0,0,0,0,0,0,1}}, {active, false}]),
    {ok, P} = inet:port(L),
    ok = gen_tcp:close(L),
    is_integer(P) andalso P > 0.

sendfile() ->
    Payload = list_to_binary([integer_to_list(N) || N <- lists:seq(1, 20000)]),
    Path = "/tmp/inet_tcp_diff_sendfile_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = prim_file:write_file(Path, Payload),
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    {ok, Port} = inet:port(L),
    Parent = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        {ok, Got} = gen_tcp:recv(S, byte_size(Payload), 2000),
        Parent ! {received, Got}
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary, {active, false}]), 2000),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    Sent = file:sendfile(Fd, C, 0, 0, []),
    Ranged = file:sendfile(Fd, C, 10, 5, []),
    ok = file:close(Fd),
    Received = receive {received, Bin} -> Bin =:= Payload after 2000 -> timeout end,
    gen_tcp:close(C),
    gen_tcp:close(L),
    ok = prim_file:delete(Path),
    {Sent, Ranged, Received}.

sf_file(Payload) ->
    Path = "/tmp/inet_tcp_diff_sendfile_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = prim_file:write_file(Path, Payload),
    Path.

sf_pair(Opts, Receiver) ->
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    {ok, Port} = inet:port(L),
    Parent = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        Parent ! {received, Receiver(S)}
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary | Opts]), 2000),
    {L, C}.

sf_received() ->
    receive {received, Got} -> Got after 10000 -> timeout end.

sf_recv_all(S, Acc) ->
    case gen_tcp:recv(S, 0, 2000) of
        {ok, Bin} -> sf_recv_all(S, [Acc, Bin]);
        {error, closed} -> iolist_to_binary(Acc);
        {error, Reason} -> {error, Reason, iolist_size(Acc)}
    end.

sf_slow_reader(S) ->
    timer:sleep(200),
    sf_recv_all(S, []).

sf_cleanup(L, C, Path) ->
    gen_tcp:close(C),
    gen_tcp:close(L),
    ok = prim_file:delete(Path).

sf_big() ->
    binary:copy(<<"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/">>, 128 * 1024).

sendfile_large() ->
    Payload = sf_big(),
    Path = sf_file(Payload),
    {L, C} = sf_pair([{active, false}], fun sf_slow_reader/1),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    Sent = file:sendfile(Fd, C, 0, 0, []),
    ok = file:close(Fd),
    ok = gen_tcp:close(C),
    Got = sf_received(),
    sf_cleanup(L, C, Path),
    {Sent, Got =:= Payload}.

sendfile_ranges() ->
    Payload = binary:part(sf_big(), 0, 1000000),
    Size = byte_size(Payload),
    Path = sf_file(Payload),
    {L, C} = sf_pair([{active, false}], fun sf_slow_reader/1),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    Ranges = [{0, 0}, {100, 1000}, {Size - 10, 0}, {Size - 10, 100},
              {12345, 600000}, {Size, 0}, {Size, 10}, {Size + 5, 10}],
    Results = [file:sendfile(Fd, C, Off, Len, []) || {Off, Len} <- Ranges],
    Expected = iolist_to_binary(
                 [case Len of
                      0 when Off >= Size -> <<>>;
                      0 -> binary:part(Payload, Off, Size - Off);
                      _ when Off >= Size -> <<>>;
                      _ -> binary:part(Payload, Off, min(Len, Size - Off))
                  end || {Off, Len} <- Ranges]),
    ok = file:close(Fd),
    ok = gen_tcp:close(C),
    Got = sf_received(),
    sf_cleanup(L, C, Path),
    {Results, Got =:= Expected}.

sendfile_queued() ->
    File = binary:copy(<<"file">>, 256 * 1024),
    Path = sf_file(File),
    Before = binary:copy(<<"before">>, 1024 * 1024),
    After = <<"after">>,
    {L, C} = sf_pair([{active, false}], fun sf_slow_reader/1),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    ok = gen_tcp:send(C, Before),
    {ok, [{send_pend, Pending}]} = inet:getstat(C, [send_pend]),
    Sent = file:sendfile(Fd, C, 0, 0, []),
    ok = gen_tcp:send(C, After),
    ok = file:close(Fd),
    ok = gen_tcp:close(C),
    Got = sf_received(),
    sf_cleanup(L, C, Path),
    {Pending > 0, Sent, Got =:= <<Before/binary, File/binary, After/binary>>}.

sendfile_errors() ->
    Path = sf_file(<<"abc">>),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    {ok, L} = gen_tcp:listen(0, tcp([binary, {active, false}])),
    Unconnected = file:sendfile(Fd, L, 0, 0, []),
    {ok, Port} = inet:port(L),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary, {active, false}]), 2000),
    ok = gen_tcp:close(C),
    Closed = file:sendfile(Fd, C, 0, 0, []),
    Parent = self(),
    {ok, C2} = gen_tcp:connect({127,0,0,1}, Port, tcp([binary, {active, false}]), 2000),
    spawn(fun() ->
        {ok, Fd2} = file:open(Path, [raw, read, binary]),
        Parent ! {not_owner, file:sendfile(Fd2, C2, 0, 0, [])}
    end),
    NotOwner = receive {not_owner, R} -> R after 2000 -> timeout end,
    Negative = file:sendfile(Fd, C2, -1, 0, []),
    ok = file:close(Fd),
    ok = gen_tcp:close(C2),
    ok = gen_tcp:close(L),
    ok = prim_file:delete(Path),
    {Unconnected, Closed, NotOwner, Negative}.

sendfile_raw() ->
    Payload = sf_big(),
    Size = byte_size(Payload),
    Path = sf_file(Payload),
    {L, C} = sf_pair([{active, false}], fun sf_slow_reader/1),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    Handle = prim_file:get_handle(Fd),
    Op = 16#03f1a300 + 45,
    BadLen = erlang:port_control(C, Op, <<1, 2, 3>>),
    BadFd = erlang:port_control(C, Op, [<<-1:32/native>>, <<0:64>>, <<10:64>>]),
    First = erlang:port_control(C, Op, [Handle, <<0:64>>, <<Size:64>>]),
    Again = erlang:port_control(C, Op, [Handle, <<0:64>>, <<Size:64>>]),
    Done = receive {sendfile, C, Res} -> Res after 10000 -> timeout end,
    Zero = erlang:port_control(C, Op, [Handle, <<0:64>>, <<0:64>>]),
    ZeroDone = receive {sendfile, C, Res2} -> Res2 after 10000 -> timeout end,
    ok = file:close(Fd),
    ok = gen_tcp:close(C),
    Got = sf_received(),
    sf_cleanup(L, C, Path),
    {BadLen, BadFd, First, Again, Done, Zero, ZeroDone, Got =:= Payload}.

sendfile_reset() ->
    Path = sf_file(sf_big()),
    Parent = self(),
    {L, C} = sf_pair([{active, false}],
                     fun(S) ->
                         %% The reset must not overtake the client's connect completion,
                         %% which is a port task on a scheduler like the accept.
                         timer:sleep(50),
                         ok = inet:setopts(S, [{linger, {true, 0}}]),
                         ok = gen_tcp:close(S),
                         Parent ! reset,
                         reset
                     end),
    receive reset -> ok after 2000 -> timeout end,
    timer:sleep(100),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    Sent = file:sendfile(Fd, C, 0, 0, []),
    After = gen_tcp:send(C, <<"x">>),
    ok = file:close(Fd),
    Got = sf_received(),
    sf_cleanup(L, C, Path),
    {Sent, After, Got}.

sf_active_reader(Mode, Size) ->
    fun(S) ->
        ok = inet:setopts(S, [{active, Mode}]),
        sf_active_loop(S, Mode, Size, [])
    end.

sf_active_loop(_S, _Mode, Left, Acc) when Left =< 0 ->
    iolist_to_binary(Acc);
sf_active_loop(S, Mode, Left, Acc) ->
    receive
        {tcp, S, Bin} ->
            Mode =:= once andalso inet:setopts(S, [{active, once}]),
            sf_active_loop(S, Mode, Left - byte_size(Bin), [Acc, Bin]);
        {tcp_closed, S} -> {closed, iolist_size(Acc)}
    after 5000 -> {timeout, iolist_size(Acc)}
    end.

sf_active(Mode, SenderOpts) ->
    Payload = sf_big(),
    Path = sf_file(Payload),
    {L, C} = sf_pair(SenderOpts, sf_active_reader(Mode, byte_size(Payload))),
    {ok, Fd} = file:open(Path, [raw, read, binary]),
    Sent = file:sendfile(Fd, C, 0, 0, []),
    ok = file:close(Fd),
    Got = sf_received(),
    sf_cleanup(L, C, Path),
    Stray = receive {sendfile, _, _} = M -> M after 100 -> none end,
    {Sent, Got =:= Payload, Stray}.

sendfile_active_true() -> sf_active(true, [{active, true}]).

sendfile_active_once() -> sf_active(once, [{active, once}]).

slow_reader_pair(Size) ->
    {ok, L} = gen_tcp:listen(0, tcp([{ip, {127,0,0,1}}, binary, {active, false}])),
    {ok, Port} = inet:port(L),
    Parent = self(),
    Reader = spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        receive go -> ok end,
        Got = slow_read(S, Size, 0),
        Eof = gen_tcp:recv(S, 0, 5000),
        Parent ! {reader, Got, Eof, erlang:monotonic_time(millisecond)},
        gen_tcp:close(S)
    end),
    %% Keep the driver queue observable regardless of the host's default TCP send buffer.
    Opts = tcp([binary, {active, false}, {sndbuf, 4096},
                {high_watermark, 16 * 1024 * 1024},
                {low_watermark, 8 * 1024 * 1024}]),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, Opts, 2000),
    {L, C, Reader}.

slow_read(_S, Size, Got) when Got >= Size -> Got;
slow_read(S, Size, Got) ->
    case gen_tcp:recv(S, 65536, 5000) of
        {ok, Bin} ->
            receive after 10 -> ok end,
            slow_read(S, Size, Got + byte_size(Bin));
        _ -> Got
    end.

subscribe_empty_out_q(C) ->
    case erlang:port_control(C, 16#03f1a300 + 24, <<1>>) of
        [1, 1, A, B, C2, D] -> {ok, (A bsl 24) bor (B bsl 16) bor (C2 bsl 8) bor D};
        Other -> Other
    end.

empty_out_q() ->
    Size = 2 * 1024 * 1024,
    {L, C, Reader} = slow_reader_pair(Size),
    ok = gen_tcp:send(C, binary:copy(<<"x">>, Size)),
    {ok, Queued} = subscribe_empty_out_q(C),
    Reader ! go,
    Msg = receive {empty_out_q, C} -> ok after 3000 -> timeout end,
    {ok, [{send_pend, Pending}]} = inet:getstat(C, [send_pend]),
    Again = subscribe_empty_out_q(C),
    Stray = receive {empty_out_q, _} = M -> M after 100 -> none end,
    ok = gen_tcp:close(C),
    receive {reader, _, _, _} -> ok after 5000 -> ok end,
    ok = gen_tcp:close(L),
    {Queued > 0, Msg, Pending, Again, Stray}.

close_empty_out_q() ->
    Size = 2 * 1024 * 1024,
    {L, C, Reader} = slow_reader_pair(Size),
    ok = gen_tcp:send(C, binary:copy(<<"x">>, Size)),
    {ok, [{send_pend, Queued}]} = inet:getstat(C, [send_pend]),
    Reader ! go,
    T0 = erlang:monotonic_time(millisecond),
    ok = gen_tcp:close(C),
    CloseMs = erlang:monotonic_time(millisecond) - T0,
    {Received, Eof, EofAt} = receive {reader, G, E, At} -> {G, E, At} after 10000 -> {timeout, timeout, T0} end,
    ok = gen_tcp:close(L),
    {Queued > 0, Received =:= Size, Eof, CloseMs < 3000, EofAt - T0 < 3000}.
"#
}

/// The inet driver keeps its port table per process, so tests that boot a `Vm` run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn run_cases(cases: &[&str]) {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
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
    for case in cases {
        let input = OwnedTerm::Atom((*case).into());
        let expected = reference.call("inet_tcp_diff", "run", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval_scheduled("inet_tcp_diff", "run", &[arg], 2, None)
            .unwrap_or_else(|error| panic!("{case}: {error}"));
        similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{case}");
    }
}

#[test]
fn empty_out_q_matches_erts() {
    run_cases(&["empty_out_q"]);
}

#[test]
fn close_with_queued_output_matches_erts() {
    run_cases(&["close_empty_out_q"]);
}

#[test]
fn gen_tcp_matches_erts() {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
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
        "subbin",
        "sendfile",
        "sendfile_large",
        "sendfile_ranges",
        "sendfile_queued",
        "sendfile_errors",
        "sendfile_raw",
        "sendfile_reset",
        "sendfile_active_true",
        "sendfile_active_once",
    ] {
        let input = OwnedTerm::Atom(case.into());
        let expected = reference.call("inet_tcp_diff", "run", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        let actual = vm
            .eval_scheduled("inet_tcp_diff", "run", &[arg], 2, None)
            .unwrap_or_else(|error| panic!("{case}: {error}"));
        similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{case}");
    }
    // sctp_inet is not a driver on macOS. prim_inet maps the open_port
    // badarg onto {error, eprotonosupport}, the same term erts returns.
    let input = OwnedTerm::Atom("sctp".into());
    let mut heap = VecHeap::new();
    let arg = from_owned(&input, &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("inet_tcp_diff", "run", &[arg], 2, None)
        .unwrap_or_else(|error| panic!("sctp: {error}"));
    similar_asserts::assert_eq!(
        actual.term,
        OwnedTerm::Tuple(vec![
            OwnedTerm::Atom("error".into()),
            OwnedTerm::Atom("eprotonosupport".into()),
        ])
    );
}
