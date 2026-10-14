//! `gen_tcp` over the `socket` backend (prim_socket) against OTP 29.1.1. Every socket
//! binds and connects on 127.0.0.1. The runtimes are started as programs because the
//! backend needs the kernel application (inet_db, socket registry).

use arinsal_difftest::RefErl;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SOURCE: &str = r#"
-module(gen_tcp_socket_compat).
-export([connect_accept_send_recv/0, connect_refused/0, accept_timeout/0,
         connect_after_listener_close/0, recv_partial_nowait/0, recv_partial_blocking/0,
         recv_timeouts/0, recv_nowait_select_message/0, two_readers/0,
         eof_aborts_queued_reader/0, gen_tcp_recv_n_partial/0,
         large_send_slow_reader/0,
         sendv_several_binaries/0, send_after_shutdown_write/0,
         shutdown_on_closed_socket/0, cancel_send/0, writer_queue_order/0,
         writer_abort_on_error/0, packet_send_sendv/0, sendto_sendmsg_stream/0,
         dirty_io_nifs_wait_for_dirty_schedulers/0]).

listen() ->
    {ok, Listen} = gen_tcp:listen(0, [{inet_backend, socket}, {ip, {127,0,0,1}},
                                      {active, false}]),
    {ok, Port} = inet:port(Listen),
    {Listen, Port}.

connect_accept_send_recv() ->
    {Listen, Port} = listen(),
    Parent = self(),
    spawn(fun() ->
        {ok, Accepted} = gen_tcp:accept(Listen, 2000),
        Parent ! {accepted, ok},
        Parent ! {received, gen_tcp:recv(Accepted, 2, 2000)},
        receive stop -> gen_tcp:close(Accepted) end
    end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{inet_backend, socket}, {active, false}], 2000),
    Accepted = receive {accepted, A} -> A after 3000 -> timeout end,
    Sent = gen_tcp:send(Client, <<"hi">>),
    Received = receive {received, R} -> R after 3000 -> timeout end,
    Peer = inet:peername(Client),
    ok = gen_tcp:close(Client),
    ok = gen_tcp:close(Listen),
    {Accepted, Sent, Received, element(1, Peer),
     element(1, element(2, Peer)) =:= {127,0,0,1}}.

connect_refused() ->
    {Listen, Port} = listen(),
    ok = gen_tcp:close(Listen),
    gen_tcp:connect({127,0,0,1}, Port, [{inet_backend, socket}, {active, false}], 2000).

accept_timeout() ->
    {Listen, _Port} = listen(),
    Result = gen_tcp:accept(Listen, 200),
    ok = gen_tcp:close(Listen),
    Result.

connect_after_listener_close() ->
    {Listen, Port} = listen(),
    Parent = self(),
    spawn(fun() -> Parent ! {accepted, gen_tcp:accept(Listen, 500)} end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{inet_backend, socket}, {active, false}], 2000),
    Accepted = receive {accepted, {ok, _}} -> ok; {accepted, Other} -> Other
               after 3000 -> timeout end,
    ok = gen_tcp:close(Client),
    ok = gen_tcp:close(Listen),
    Accepted.

norm(R) when is_reference(R) -> ref;
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm(L) when is_list(L) -> [norm(E) || E <- L];
norm(T) -> T.

sock_pair() ->
    Addr = #{family => inet, addr => {127,0,0,1}, port => 0},
    {ok, L} = socket:open(inet, stream),
    ok = socket:bind(L, Addr),
    ok = socket:listen(L),
    {ok, #{port := Port}} = socket:sockname(L),
    {ok, C} = socket:open(inet, stream),
    ok = socket:connect(C, Addr#{port := Port}),
    {ok, A} = socket:accept(L, 2000),
    ok = socket:close(L),
    {C, A}.

recv_partial_nowait() ->
    {C, A} = sock_pair(),
    ok = socket:send(C, <<1,2>>),
    timer:sleep(100),
    R1 = socket:recv(A, 4, [], nowait),
    {select, {{select_info, recv, H}, <<1,2>>}} = R1,
    ok = socket:send(C, <<3,4>>),
    Sel = receive {'$socket', _, select, H} -> select after 2000 -> timeout end,
    R2 = socket:recv(A, 2, [], nowait),
    ok = socket:close(C),
    ok = socket:close(A),
    norm({R1, Sel, R2}).

recv_partial_blocking() ->
    {C, A} = sock_pair(),
    spawn(fun() ->
        timer:sleep(100), ok = socket:send(C, <<1,2>>),
        timer:sleep(200), ok = socket:send(C, <<3,4>>),
        timer:sleep(200), ok = socket:send(C, <<5,6,7>>)
    end),
    R1 = socket:recv(A, 4, 3000),
    R2 = socket:recv(A, 0, 3000),
    ok = socket:close(C),
    ok = socket:close(A),
    {R1, R2}.

recv_timeouts() ->
    {C, A} = sock_pair(),
    R1 = socket:recv(A, 4, 100),
    R2 = socket:recv(A, 0, 0),
    ok = socket:send(C, <<1,2>>),
    timer:sleep(100),
    R3 = socket:recv(A, 4, 100),
    ok = socket:send(C, <<9,9>>),
    timer:sleep(100),
    R4 = socket:recv(A, 4, 0),
    R5 = socket:recv(A, 0, 0),
    ok = socket:close(C),
    ok = socket:close(A),
    {R1, R2, R3, R4, R5}.

recv_nowait_select_message() ->
    {C, A} = sock_pair(),
    R1 = socket:recv(A, 0, [], nowait),
    {select, {select_info, recv, H}} = R1,
    ok = socket:send(C, <<"abc">>),
    Sel = receive {'$socket', _, select, H} -> select after 2000 -> timeout end,
    R2 = socket:recv(A, 0, [], nowait),
    R3 = socket:recv(A, 0, [], nowait),
    {select, {select_info, recv, H3}} = R3,
    ok = socket:cancel(A, {select_info, recv, H3}),
    ok = socket:close(C),
    ok = socket:close(A),
    norm({R1, Sel, R2, R3}).

await(Name, Tag, Timeout) ->
    receive {Name, Tag, V} -> V after Timeout -> none end.

reader(A, Name, Parent) ->
    spawn(fun() ->
        R = socket:recv(A, 0, [], nowait),
        Parent ! {Name, first, norm(R)},
        {select, {select_info, recv, H}} = R,
        Sel = receive
                  {'$socket', _, select, H} -> select;
                  {'$socket', _, abort, {H, Reason}} -> {abort, Reason}
              after 3000 -> timeout end,
        Parent ! {Name, selected, Sel},
        receive go -> ok after 3000 -> ok end,
        Parent ! {Name, second, norm(socket:recv(A, 0, [], nowait))}
    end).

two_readers() ->
    {C, A} = sock_pair(),
    Me = self(),
    Ra = reader(A, a, Me),
    R1 = await(a, first, 2000),
    Rb = reader(A, b, Me),
    R2 = await(b, first, 2000),
    ok = socket:send(C, <<"x">>),
    S1 = await(a, selected, 2000),
    S2 = await(b, selected, 300),
    Ra ! go,
    R3 = await(a, second, 2000),
    timer:sleep(100),
    ok = socket:send(C, <<"y">>),
    S3 = await(b, selected, 2000),
    Rb ! go,
    R4 = await(b, second, 2000),
    ok = socket:close(C),
    ok = socket:close(A),
    {R1, R2, S1, S2, R3, S3, R4}.

eof_aborts_queued_reader() ->
    {C, A} = sock_pair(),
    Me = self(),
    Ra = reader(A, a, Me),
    R1 = await(a, first, 2000),
    Rb = reader(A, b, Me),
    R2 = await(b, first, 2000),
    ok = socket:close(C),
    S1 = await(a, selected, 2000),
    S2 = await(b, selected, 2000),
    Ra ! go,
    Rb ! go,
    R3 = await(a, second, 2000),
    ok = socket:close(A),
    {R1, R2, S1, S2, R3}.

gen_tcp_recv_n_partial() ->
    {Listen, Port} = listen(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(Listen, 2000),
        timer:sleep(100), ok = gen_tcp:send(S, <<1,2>>),
        timer:sleep(200), ok = gen_tcp:send(S, <<3,4,5>>),
        timer:sleep(500), gen_tcp:close(S)
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{inet_backend, socket}, {active, false}, binary], 2000),
    R1 = gen_tcp:recv(C, 4, 3000),
    R2 = gen_tcp:recv(C, 0, 3000),
    R3 = gen_tcp:recv(C, 2, 3000),
    ok = gen_tcp:close(C),
    ok = gen_tcp:close(Listen),
    {R1, R2, R3}.

cancelled(ok) -> cancelled_or_sent;
cancelled(select_sent) -> cancelled_or_sent;
cancelled(Other) -> Other.

raised(Fun) ->
    try Fun() catch Class:Reason -> {Class, Reason} end.

loopback() -> #{family => inet, addr => loopback, port => 0}.

pair() ->
    {ok, L} = socket:open(inet, stream, tcp),
    ok = socket:bind(L, loopback()),
    ok = socket:listen(L),
    {ok, #{port := Port}} = socket:sockname(L),
    {ok, C} = socket:open(inet, stream, tcp),
    ok = socket:connect(C, #{family => inet, addr => loopback, port => Port}),
    {ok, S} = socket:accept(L),
    {L, C, S}.

small_buffers(C, S) -> buffers(C, S, 8192).

buffers(C, S, Size) ->
    ok = socket:setopt(C, {socket, sndbuf}, Size),
    ok = socket:setopt(S, {socket, rcvbuf}, Size).

tag(Res) when is_tuple(Res) -> {element(1, Res), tuple_size(Res)};
tag(Res) -> Res.

await(Sock, SendRef) ->
    receive {'$socket', Sock, select, SendRef} -> ok
    after 5000 -> timeout end.

send_all({'$socket', Ref} = Sock, Data) ->
    send_all(Sock, Ref, Data, [], 0, first).

send_all(Sock, Ref, Data, Flags, Partials, First) ->
    SendRef = make_ref(),
    Res = prim_socket:send(Ref, Data, Flags, SendRef),
    First1 = case First of first -> tag(Res); _ -> First end,
    case Res of
        ok -> {First1, Partials > 0};
        {select, Rest, EFlags} ->
            await(Sock, SendRef),
            send_all(Sock, Ref, Rest, EFlags, Partials + 1, First1);
        {select, EFlags} ->
            await(Sock, SendRef),
            send_all(Sock, Ref, Data, EFlags, Partials, First1);
        Other -> {error, Other}
    end.

slow_read(_S, Total, Got, Ctx) when Got >= Total ->
    {Got, erlang:md5_final(Ctx)};
slow_read(S, Total, Got, Ctx) ->
    case socket:recv(S, 0, 5000) of
        {ok, Bin} ->
            timer:sleep(1),
            slow_read(S, Total, Got + byte_size(Bin), erlang:md5_update(Ctx, Bin));
        {error, Reason} -> {error, Reason, Got}
    end.

read_all(S, Acc) ->
    case socket:recv(S, 0, 2000) of
        {ok, Bin} -> read_all(S, [Acc, Bin]);
        {error, Reason} -> {iolist_to_binary(Acc), Reason}
    end.

large_send_slow_reader() ->
    {_L, C, S} = pair(),
    small_buffers(C, S),
    Total = 256 * 1024,
    Data = binary:copy(<<"0123456789abcdef">>, Total div 16),
    Parent = self(),
    spawn_link(fun() ->
        Parent ! {read, slow_read(S, Total, 0, erlang:md5_init())}
    end),
    {First, Partials} = send_all(C, Data),
    {Bytes, Md5} = receive {read, R} -> R after 30000 -> {timeout, timeout} end,
    {First, Partials, Bytes, Md5 =:= erlang:md5(Data)}.

sendv_several_binaries() ->
    {_L, C, S} = pair(),
    R1 = socket:sendv(C, [<<"a">>, <<"bc">>, <<>>, <<"def">>]),
    R2 = socket:sendv(C, [binary:part(<<"xxHELLOyy">>, 2, 5), <<"-">>, <<"w">>]),
    R3 = socket:sendv(C, lists:duplicate(2500, <<"z">>)),
    R4 = socket:sendv(C, []),
    R5 = socket:sendv(C, [<<>>, <<>>]),
    ok = socket:shutdown(C, write),
    {Received, End} = read_all(S, []),
    <<Head:14/binary, Zs/binary>> = Received,
    {R1, R2, R3, R4, R5, Head, byte_size(Zs), Zs =:= binary:copy(<<"z">>, 2500), End}.

send_after_shutdown_write() ->
    {_L, C, S} = pair(),
    Shutdown = socket:shutdown(C, write),
    R1 = socket:send(C, <<"x">>),
    R2 = socket:sendv(C, [<<"x">>, <<"y">>]),
    R3 = socket:sendto(C, <<"x">>, #{family => inet, addr => loopback, port => 1}),
    R4 = socket:sendmsg(C, #{iov => [<<"x">>]}),
    Eof = socket:recv(S, 0, 1000),
    ok = socket:send(S, <<"back">>),
    Back = socket:recv(C, 4, 1000),
    Gen = gen_tcp_shutdown_send(),
    {Shutdown, R1, R2, R3, R4, Eof, Back, Gen}.

gen_tcp_shutdown_send() ->
    {ok, Listen} = gen_tcp:listen(0, [{inet_backend, socket}, {ip, {127,0,0,1}},
                                      {active, false}]),
    {ok, Port} = inet:port(Listen),
    Parent = self(),
    spawn(fun() ->
        {ok, A} = gen_tcp:accept(Listen, 2000),
        Parent ! {accepted, gen_tcp:recv(A, 0, 2000)}
    end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{inet_backend, socket}, {active, false}], 2000),
    ok = gen_tcp:send(Client, <<"before">>),
    Shut = gen_tcp:shutdown(Client, write),
    Send = gen_tcp:send(Client, <<"after">>),
    Recv = receive {accepted, X} -> X after 3000 -> timeout end,
    {Shut, Send, Recv}.

shutdown_on_closed_socket() ->
    {_L, C, S} = pair(),
    {'$socket', Ref} = C,
    BadHowOpen = raised(fun() -> prim_socket:shutdown(Ref, bad) end),
    ok = socket:close(C),
    BadHowClosed = raised(fun() -> prim_socket:shutdown(Ref, bad) end),
    Closed = [socket:shutdown(C, How) || How <- [read, write, read_write]],
    {ok, U} = socket:open(inet, stream, tcp),
    Unconnected = [socket:shutdown(U, How) || How <- [read, write, read_write]],
    Twice = [socket:shutdown(S, write), socket:shutdown(S, write),
             socket:shutdown(S, read), socket:shutdown(S, read_write)],
    ok = socket:close(S),
    AfterClose = socket:shutdown(S, write),
    Gen = gen_tcp_shutdown_closed(),
    {BadHowOpen, BadHowClosed, Closed, Unconnected, Twice, AfterClose, Gen}.

gen_tcp_shutdown_closed() ->
    {ok, Listen} = gen_tcp:listen(0, [{inet_backend, socket}, {ip, {127,0,0,1}},
                                      {active, false}]),
    {ok, Port} = inet:port(Listen),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{inet_backend, socket}, {active, false}], 2000),
    ok = gen_tcp:close(Client),
    {gen_tcp:shutdown(Client, write), gen_tcp:send(Client, <<"x">>)}.

cancel_send() ->
    {_L, C, S} = pair(),
    small_buffers(C, S),
    {'$socket', Ref} = C,
    Big = binary:copy(<<0>>, 1 bsl 22),
    NoWriter = prim_socket:cancel(Ref, send, make_ref()),
    Ref1 = make_ref(),
    First = tag(prim_socket:send(Ref, Big, [], Ref1)),
    Parent = self(),
    RefB = make_ref(),
    B = spawn(fun() ->
        Parent ! {b_send, prim_socket:send(Ref, <<"x">>, [], RefB)},
        receive {'$socket', C, select, RefB} -> Parent ! b_selected
        after 3000 -> Parent ! b_timeout end,
        receive stop -> ok end
    end),
    BSend = receive {b_send, X} -> X after 2000 -> timeout end,
    WrongRef = prim_socket:cancel(Ref, send, make_ref()),
    WrongOp = [prim_socket:cancel(Ref, Op, make_ref()) || Op <- [sendto, sendmsg, sendv]],
    CancelA = cancelled(prim_socket:cancel(Ref, sendv, Ref1)),
    {Drained, _} = read_all(S, []),
    BResult = receive b_selected -> ok; b_timeout -> timeout after 5000 -> none end,
    CancelAgain = prim_socket:cancel(Ref, send, Ref1),
    B ! stop,
    {NoWriter, First, BSend, WrongRef, WrongOp, CancelA, byte_size(Drained) > 0,
     BResult, CancelAgain}.

writer_queue_order() ->
    {_L, C, S} = pair(),
    buffers(C, S, 65536),
    Parent = self(),
    {'$socket', Ref} = C,
    Big = binary:copy(<<"a">>, 1024 * 1024),
    Sender = fun(Tag, Payload) ->
        spawn(fun() ->
            SendRef = make_ref(),
            First = prim_socket:send(Ref, Payload, [], SendRef),
            Parent ! {Tag, first, tag(First)},
            Result = case First of
                {select, EFlags} ->
                    await(C, SendRef),
                    {_, _} = send_all(C, Ref, Payload, EFlags, 0, first),
                    sent;
                ok -> sent
            end,
            Parent ! {Tag, done, Result}
        end)
    end,
    A = spawn(fun() ->
        {_, _} = send_all(C, Big),
        Parent ! {a, done, sent}
    end),
    timer:sleep(200),
    _ = A,
    Sender(b, <<"B">>),
    BFirst = receive {b, first, F1} -> F1 after 2000 -> timeout end,
    Sender(c, <<"C">>),
    CFirst = receive {c, first, F2} -> F2 after 2000 -> timeout end,
    ABlocked = receive {a, done, _} = Early -> Early after 100 -> a_blocked end,
    {Received, _} = read_all_until(S, byte_size(Big) + 2),
    AResult = case ABlocked of
        a_blocked -> receive {a, done, AR} -> AR after 5000 -> timeout end;
        {a, done, Early1} -> Early1
    end,
    BDone = receive {b, done, BR} -> BR after 5000 -> timeout end,
    CDone = receive {c, done, CR} -> CR after 5000 -> timeout end,
    Tail = binary:part(Received, byte_size(Received) - 2, 2),
    {BFirst, CFirst, ABlocked, AResult, BDone, CDone, byte_size(Received), Tail}.

read_all_until(S, Total) -> read_all_until(S, Total, 0, []).
read_all_until(_S, Total, Got, Acc) when Got >= Total ->
    {iolist_to_binary(Acc), done};
read_all_until(S, Total, Got, Acc) ->
    case socket:recv(S, 0, 5000) of
        {ok, Bin} -> read_all_until(S, Total, Got + byte_size(Bin), [Acc, Bin]);
        {error, Reason} -> {iolist_to_binary(Acc), Reason}
    end.

writer_abort_on_error() ->
    {_L, C, S} = pair(),
    small_buffers(C, S),
    {'$socket', Ref} = C,
    Big = binary:copy(<<0>>, 1 bsl 22),
    Ref1 = make_ref(),
    First = tag(prim_socket:send(Ref, Big, [], Ref1)),
    Parent = self(),
    RefB = make_ref(),
    spawn(fun() ->
        Parent ! {b_send, prim_socket:send(Ref, <<"x">>, [], RefB)},
        receive Msg -> Parent ! {b_msg, Msg} after 5000 -> Parent ! {b_msg, timeout} end
    end),
    BSend = receive {b_send, X} -> X after 2000 -> timeout end,
    ok = socket:setopt(S, {socket, linger}, #{onoff => true, linger => 0}),
    ok = socket:close(S),
    ASelect = await(C, Ref1),
    AError = prim_socket:send(Ref, Big, [], make_ref()),
    BMsg = receive
        {b_msg, {'$socket', Sock, abort, {AbortRef, Reason}}} ->
            {abort, Sock =:= C, AbortRef =:= RefB, Reason};
        {b_msg, M} -> M
    after 5000 -> timeout end,
    {First, BSend, ASelect, AError, BMsg}.

packet_send_sendv() ->
    {ok, Listen} = gen_tcp:listen(0, [{inet_backend, socket}, {ip, {127,0,0,1}},
                                      {active, false}, {packet, 4}, binary]),
    {ok, Port} = inet:port(Listen),
    Parent = self(),
    N = 300,
    spawn(fun() ->
        {ok, A} = gen_tcp:accept(Listen, 2000),
        Parent ! {frames, [gen_tcp:recv(A, 0, 2000) || _ <- lists:seq(1, N)]}
    end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{inet_backend, socket}, {active, false},
                                    {packet, 4}, binary], 2000),
    Sent = [gen_tcp:send(Client, binary:copy(<<"p">>, I)) || I <- lists:seq(1, N)],
    Frames = receive {frames, Fs} -> Fs after 10000 -> timeout end,
    Ok = Frames =:= [{ok, binary:copy(<<"p">>, I)} || I <- lists:seq(1, N)],
    {lists:usort(Sent), Ok}.

sendto_sendmsg_stream() ->
    {_L, C, S} = pair(),
    Addr = #{family => inet, addr => loopback, port => 1},
    R1 = socket:sendto(C, <<"to">>, Addr),
    R2 = socket:sendmsg(C, #{iov => [<<"m">>, <<"sg">>]}),
    R3 = socket:sendmsg(C, #{iov => [<<"x">>], addr => #{family => inet, addr => nope}}),
    R4 = raised(fun() ->
        prim_socket:sendmsg(element(2, C), #{iov => []}, [], make_ref(), [<<"ok">>])
    end),
    R5 = socket:sendmsg(C, #{iov => [<<"y">>], ctrl => []}),
    ok = socket:shutdown(C, write),
    {Received, End} = read_all(S, []),
    {R1, R2, R3, R4, R5, Received, End}.

dirty_tag(R) when is_tuple(R) -> element(1, R);
dirty_tag(R) -> R.

dirty_io_nifs_wait_for_dirty_schedulers() ->
    Parent = self(),
    {_C, A} = sock_pair(),
    Count = erlang:system_info(dirty_io_schedulers),
    Calls = [
        {dirty_getifaddrs, fun() -> dirty_tag(prim_net:getifaddrs(#{})) end},
        {dirty_getservbyname, fun() -> dirty_tag(prim_net:getservbyname("http", "tcp")) end},
        {dirty_getservbyport, fun() -> dirty_tag(prim_net:getservbyport(80, "tcp")) end},
        {dirty_ioctl_nread, fun() -> dirty_tag(socket:ioctl(A, nread)) end},
        {dirty_ioctl_atmark, fun() -> dirty_tag(socket:ioctl(A, atmark)) end},
        {plain_gethostname, fun() -> dirty_tag(prim_net:gethostname()) end},
        {plain_if_names, fun() -> dirty_tag(prim_net:if_names()) end},
        {plain_getaddrinfo, fun() -> dirty_tag(net:getaddrinfo("localhost")) end},
        {plain_sockname, fun() -> dirty_tag(socket:sockname(A)) end}
    ],
    [Call() || {_, Call} <- Calls],
    erts_debug:dirty_io(wait, 1),
    timer:sleep(1),
    [spawn_link(fun() -> erts_debug:dirty_io(wait, 1500), Parent ! blocker_done end)
     || _ <- lists:seq(1, Count)],
    timer:sleep(300),
    Pids = [{Name, spawn_link(fun() -> Parent ! {self(), Call()} end)}
            || {Name, Call} <- Calls],
    timer:sleep(500),
    Early = lists:sort([Name || {Name, Pid} <- Pids, dirty_finished(Pid)]),
    Late = lists:sort([{Name, dirty_wait(Pid)} || {Name, Pid} <- Pids]),
    {Early, Late}.

dirty_finished(Pid) ->
    receive {Pid, _} = Done -> self() ! Done, true after 0 -> false end.

dirty_wait(Pid) ->
    receive {Pid, Result} -> Result after 10000 -> timeout end.
"#;

fn run(program: &Path, dir: &Path, module: &str, function: &str) -> (bool, String) {
    let eval = format!("io:format(\"~p~n\", [{module}:{function}()]), halt().");
    let root = arinsal_difftest::reference::otp_root();
    let mut command = if program == Path::new("erl") {
        match &root {
            Some(root) => Command::new(root.join("bin/erl")),
            None => Command::new("erl"),
        }
    } else {
        let mut command = Command::new(program);
        if let Some(root) = &root {
            command.env("ERL_ROOTDIR", root);
        }
        command
    };
    command
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &eval])
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().expect("output");
                return (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                );
            }
            Ok(None) if started.elapsed() > Duration::from_secs(60) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{} timed out in {function}", program.display());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("wait {}: {error}", program.display()),
        }
    }
}

fn compare(function: &str) {
    compare_in("gen_tcp_socket_compat", SOURCE, function);
}

fn compare_in(module: &str, source: &str, function: &str) {
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping gen_tcp_socket differential test");
        return;
    };
    let beam = reference
        .compile_named(module, source, &[])
        .unwrap_or_else(|error| panic!("compile {module}: {error:?}"));
    let dir = std::env::temp_dir().join(format!("{module}_{}_{function}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{module}.beam")), beam).unwrap();
    let (erl_ok, expected) = run(Path::new("erl"), &dir, module, function);
    let (ok, actual) = run(&arinsal, &dir, module, function);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(erl_ok, "erl failed in {function}: {expected}");
    assert!(ok, "arinsal failed in {function}: {actual}");
    similar_asserts::assert_eq!(expected, actual, "{function}");
}

#[test]
fn connect_accept_send_recv_matches_erts() {
    compare("connect_accept_send_recv");
}

#[test]
fn connect_refused_matches_erts() {
    compare("connect_refused");
}

#[test]
fn accept_timeout_matches_erts() {
    compare("accept_timeout");
}

#[test]
fn connect_with_acceptor_matches_erts() {
    compare("connect_after_listener_close");
}

#[test]
fn recv_partial_nowait_matches_erts() {
    compare("recv_partial_nowait");
}

#[test]
fn recv_partial_blocking_matches_erts() {
    compare("recv_partial_blocking");
}

#[test]
fn recv_timeouts_match_erts() {
    compare("recv_timeouts");
}

#[test]
fn recv_nowait_select_message_matches_erts() {
    compare("recv_nowait_select_message");
}

#[test]
fn two_concurrent_readers_match_erts() {
    compare("two_readers");
}

#[test]
fn eof_aborts_queued_reader_matches_erts() {
    compare("eof_aborts_queued_reader");
}

#[test]
fn gen_tcp_recv_n_partial_matches_erts() {
    compare("gen_tcp_recv_n_partial");
}

#[test]
fn large_send_with_slow_reader_matches_erts() {
    compare("large_send_slow_reader");
}

#[test]
fn sendv_with_several_binaries_matches_erts() {
    compare("sendv_several_binaries");
}

#[test]
fn send_after_shutdown_write_matches_erts() {
    compare("send_after_shutdown_write");
}

#[test]
fn shutdown_on_closed_socket_matches_erts() {
    compare("shutdown_on_closed_socket");
}

#[test]
fn cancel_send_matches_erts() {
    compare("cancel_send");
}

#[test]
fn writer_queue_order_matches_erts() {
    compare("writer_queue_order");
}

#[test]
fn writer_abort_on_error_matches_erts() {
    compare("writer_abort_on_error");
}

#[test]
fn packet_send_through_sendv_matches_erts() {
    compare("packet_send_sendv");
}

#[test]
fn sendto_and_sendmsg_on_stream_match_erts() {
    compare("sendto_sendmsg_stream");
}

const ACTIVE_SOURCE: &str = include_str!("fixtures/sock_active_compat.erl");

fn compare_active(function: &str) {
    compare_in("sock_active_compat", ACTIVE_SOURCE, function);
}

#[test]
fn passive_send_and_recv_match_erts() {
    compare_active("passive_send_recv");
}

#[test]
fn active_once_matches_erts() {
    compare_active("active_once");
}

#[test]
fn active_n_and_tcp_passive_match_erts() {
    compare_active("active_n");
}

#[test]
fn active_true_matches_erts() {
    compare_active("active_true");
}

#[test]
fn packet_modes_passive_match_erts() {
    compare_active("packet_passive");
}

#[test]
fn packet_wire_format_matches_erts() {
    compare_active("packet_wire_format");
}

#[test]
fn packet_modes_active_match_erts() {
    compare_active("packet_active");
}

#[test]
fn packet_split_over_segments_matches_erts() {
    compare_active("packet_split_segments");
}

#[test]
fn packet_too_long_on_receive_matches_erts() {
    compare_active("packet_too_long");
}

#[test]
fn packet_too_long_on_send_matches_erts() {
    compare_active("packet_send_too_long");
}

#[test]
fn gen_tcp_close_errors_passive_match_erts() {
    compare_active("close_errors_passive");
}

#[test]
fn gen_tcp_close_errors_active_match_erts() {
    compare_active("close_errors_active");
}

#[test]
fn gen_tcp_shutdown_errors_match_erts() {
    compare_active("shutdown_errors");
}

#[test]
fn gen_tcp_close_wakes_blocked_recv_like_erts() {
    compare_active("close_wakes_blocked_recv");
}

const CLOSE_SOURCE: &str = include_str!("fixtures/sock_close_compat.erl");

fn compare_close(function: &str) {
    compare_in("sock_close_compat", CLOSE_SOURCE, function);
}

#[test]
fn close_aborts_blocked_recv_matches_erts() {
    compare_close("close_aborts_blocked_recv");
}

#[test]
fn close_aborts_blocked_accept_matches_erts() {
    compare_close("close_aborts_blocked_accept");
}

#[test]
fn close_aborts_nowait_requestors_matches_erts() {
    compare_close("close_aborts_nowait_requestors");
}

#[test]
fn controlling_process_transfer_keeps_the_socket_open() {
    compare_close("controlling_process_transfer");
}

#[test]
fn controlling_process_to_a_dead_process_closes_the_socket() {
    compare_close("controlling_process_to_dead");
}

#[test]
fn owner_exit_closes_the_socket() {
    compare_close("owner_exit_closes");
}

#[test]
fn owner_exit_aborts_waiting_readers() {
    compare_close("owner_dies_with_waiting_reader");
}

#[test]
fn closer_exit_before_finalize_closes_the_socket() {
    compare_close("closer_dies_before_finalize");
}

#[test]
fn closing_from_a_process_that_is_not_the_owner() {
    compare_close("closer_not_owner");
}

#[test]
fn reader_exit_activates_the_next_reader() {
    compare_close("reader_death_activates_next");
}

#[test]
fn readers_are_served_in_queue_order() {
    compare_close("reader_queue_order");
}

#[test]
fn otp_options_round_trip_like_erts() {
    compare_close("otp_options");
}

#[test]
fn accepted_sockets_inherit_the_otp_options() {
    compare_close("accept_inherits");
}

#[test]
fn socket_options_round_trip_like_erts() {
    compare_close("socket_options");
}

#[test]
fn cancel_results_match_erts() {
    compare_close("cancel_ops");
}

#[test]
fn info_counters_and_registry_match_erts() {
    compare_close("info_and_registry");
}

#[test]
fn errno_atoms_match_erts() {
    compare_close("errnos");
}

#[test]
fn dirty_io_socket_and_net_nifs_wait_for_dirty_schedulers_like_erts() {
    compare("dirty_io_nifs_wait_for_dirty_schedulers");
}
