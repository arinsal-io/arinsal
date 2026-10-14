-module(sock_active_compat).
-export([passive_send_recv/0, active_once/0, active_n/0, active_true/0,
         packet_passive/0, packet_wire_format/0, packet_active/0, packet_split_segments/0,
         packet_too_long/0, packet_send_too_long/0, close_errors_passive/0,
         close_errors_active/0, shutdown_errors/0, close_wakes_blocked_recv/0]).

norm(T) when is_reference(T) -> ref;
norm(T) when is_pid(T) -> pid;
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm([H|T]) -> [norm(H)|norm(T)];
norm(T) -> T.

opts(Extra) ->
    [{active, false}, binary | Extra].

backend(Opts) -> [{inet_backend, socket} | Opts].

tcp_pair(Extra) ->
    {ok, L} = gen_tcp:listen(0, backend([{ip, {127,0,0,1}} | opts(Extra)])),
    {ok, Port} = inet:port(L),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, backend([{ip, {127,0,0,1}} | opts(Extra)]), 2000),
    {ok, S} = gen_tcp:accept(L, 2000),
    ok = gen_tcp:close(L),
    {C, S}.

tcp_pair(SenderExtra, ReceiverExtra) ->
    {ok, L} = gen_tcp:listen(0, backend([{ip, {127,0,0,1}} | opts(ReceiverExtra)])),
    {ok, Port} = inet:port(L),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, backend([{ip, {127,0,0,1}} | opts(SenderExtra)]), 2000),
    {ok, S} = gen_tcp:accept(L, 2000),
    ok = gen_tcp:close(L),
    {C, S}.

msg(S) -> msg(S, 5000).

msg(S, Timeout) ->
    receive
        {tcp, S, Data} when byte_size(Data) > 64 -> {tcp_big, byte_size(Data), erlang:md5(Data)};
        {tcp, S, Data} -> {tcp, Data};
        {tcp_closed, S} -> tcp_closed;
        {tcp_passive, S} -> tcp_passive;
        {tcp_error, S, Reason} -> {tcp_error, Reason}
    after Timeout -> timeout end.

quiet(S) ->
    case msg(S, 50) of
        timeout -> quiet;
        Other -> {unexpected, Other}
    end.

mailbox(S) ->
    case msg(S, 0) of
        timeout -> [];
        M -> [M | mailbox(S)]
    end.

shape({ok, Bin}) when byte_size(Bin) > 64 -> {ok_big, byte_size(Bin), erlang:md5(Bin)};
shape(Other) -> Other.

lockstep(C, S, Frames) ->
    [begin
         Sent = gen_tcp:send(C, Frame),
         {Sent, msg(S)}
     end || Frame <- Frames].

wait_until(_Fun, 0) -> timeout;
wait_until(Fun, N) ->
    case Fun() of
        true -> ok;
        false -> receive after 10 -> wait_until(Fun, N - 1) end
    end.

passive_send_recv() ->
    {C, S} = tcp_pair([]),
    Sent = [gen_tcp:send(C, <<"hello world">>), gen_tcp:send(C, <<>>),
            gen_tcp:send(C, []), gen_tcp:send(C, [<<"io">>, "list", [$!]])],
    R1 = [gen_tcp:recv(S, 5, 5000), gen_tcp:recv(S, 1, 5000), gen_tcp:recv(S, 5, 5000)],
    R2 = [gen_tcp:recv(S, 9, 50), gen_tcp:recv(S, 7, 5000)],
    NothingLeft = [gen_tcp:recv(S, 0, 0), gen_tcp:recv(S, 4, 50)],
    Back = [gen_tcp:send(S, <<"back">>), gen_tcp:recv(C, 4, 5000)],
    ok = inet:setopts(S, [list]),
    ok = gen_tcp:send(C, <<"abcdef">>),
    ListMode = [gen_tcp:recv(S, 3, 5000), gen_tcp:recv(S, 3, 5000)],
    ok = inet:setopts(S, [binary]),
    Size = 300000,
    Big = binary:copy(<<"0123456789abcdef">>, Size div 16),
    Parent = self(),
    spawn_link(fun() -> Parent ! {big_sent, gen_tcp:send(C, Big)} end),
    BigRecv = case gen_tcp:recv(S, Size, 20000) of
                  {ok, Got} -> {ok, byte_size(Got), Got =:= Big};
                  Error -> Error
              end,
    BigSent = receive {big_sent, BS} -> BS after 5000 -> timeout end,
    ok = gen_tcp:close(C),
    Eof = gen_tcp:recv(S, 0, 5000),
    ok = gen_tcp:close(S),
    {Sent, R1, R2, NothingLeft, Back, ListMode, BigRecv, BigSent, Eof}.

active_once() ->
    {C, S} = tcp_pair([]),
    ok = inet:setopts(S, [{active, once}]),
    Armed = inet:getopts(S, [active]),
    RecvWhileArmed = gen_tcp:recv(S, 0, 0),
    ok = gen_tcp:send(C, <<"A">>),
    M1 = msg(S),
    Disarmed = inet:getopts(S, [active]),
    ok = gen_tcp:send(C, <<"B">>),
    Q1 = quiet(S),
    ok = inet:setopts(S, [{active, once}]),
    M2 = msg(S),
    Q2 = quiet(S),
    ok = inet:setopts(S, [{active, once}]),
    Q3 = quiet(S),
    ok = gen_tcp:send(C, <<"C">>),
    M3 = msg(S),
    ok = gen_tcp:send(C, <<"D">>),
    Passive = gen_tcp:recv(S, 1, 5000),
    ok = inet:setopts(S, [{active, once}]),
    ok = gen_tcp:close(C),
    M4 = msg(S),
    Closed = gen_tcp:close(S),
    {Armed, RecvWhileArmed, M1, Disarmed, Q1, M2, Q2, Q3, M3, Passive, M4, Closed}.

active_n() ->
    {C, S} = tcp_pair([]),
    ok = inet:setopts(S, [{active, 3}]),
    Armed = inet:getopts(S, [active]),
    First = lockstep(C, S, [<<1>>, <<2>>, <<3>>]),
    Passive = msg(S),
    Disarmed = inet:getopts(S, [active]),
    ok = gen_tcp:send(C, <<4, 5>>),
    PassiveRecv = [gen_tcp:recv(S, 1, 5000), gen_tcp:recv(S, 1, 5000)],
    ok = inet:setopts(S, [{active, 2}]),
    Second = lockstep(C, S, [<<6>>, <<7>>]),
    Passive2 = msg(S),
    ok = inet:setopts(S, [{active, 2}]),
    ok = inet:setopts(S, [{active, 3}]),
    Added = inet:getopts(S, [active]),
    ok = inet:setopts(S, [{active, -4}]),
    Reduced = inet:getopts(S, [active]),
    ok = inet:setopts(S, [{active, -1}]),
    Zero = {msg(S), inet:getopts(S, [active])},
    ok = inet:setopts(S, [{active, 0}]),
    ZeroMsg = msg(S),
    Limits = [inet:setopts(S, [{active, 32768}]), inet:setopts(S, [{active, -32769}]),
              inet:setopts(S, [{active, 32767}]), inet:setopts(S, [{active, -32767}])],
    LimitPassive = msg(S),
    ok = inet:setopts(S, [{active, 1}]),
    ok = gen_tcp:send(C, <<8>>),
    M8 = msg(S),
    M8Passive = msg(S),
    ok = inet:setopts(S, [{active, 2}]),
    ok = gen_tcp:send(C, <<9>>),
    M9 = msg(S),
    ok = gen_tcp:close(C),
    Closed = msg(S),
    ok = gen_tcp:close(S),
    {Armed, First, Passive, Disarmed, PassiveRecv, Second, Passive2, Added, Reduced, Zero,
     ZeroMsg, Limits, LimitPassive, M8, M8Passive, M9, Closed}.

active_true() ->
    {C, S} = tcp_pair([]),
    ok = inet:setopts(S, [{active, true}]),
    Armed = inet:getopts(S, [active]),
    Frames = [<<I>> || I <- lists:seq(1, 6)] ++ [binary:copy(<<"x">>, 1000)],
    Stream = lockstep(C, S, Frames),
    Back = [gen_tcp:send(S, <<"back">>), gen_tcp:recv(C, 4, 5000)],
    RecvActive = gen_tcp:recv(S, 0, 0),
    ok = inet:setopts(S, [{active, false}]),
    ok = gen_tcp:send(C, <<"late">>),
    Late = gen_tcp:recv(S, 4, 5000),
    NoMsg = quiet(S),
    ok = inet:setopts(S, [{active, true}]),
    ok = gen_tcp:send(C, <<"last">>),
    Last = msg(S),
    ok = gen_tcp:close(C),
    Closed = msg(S),
    Mailbox = mailbox(S),
    ok = gen_tcp:close(S),
    {Armed, Stream, Back, RecvActive, Late, NoMsg, Last, Closed, Mailbox}.

packet_frames(raw) -> [<<"abc">>, <<"defgh">>, <<"i">>];
packet_frames(0) -> [<<"abc">>, <<"defgh">>, <<"i">>];
packet_frames(_) -> [<<>>, <<"a">>, <<"hello">>, binary:copy(<<"z">>, 250)].

packet_passive() ->
    [{P, packet_passive(P)} || P <- [raw, 0, 1, 2, 4]].

packet_passive(P) ->
    {C, S} = tcp_pair([{packet, P}]),
    Frames = packet_frames(P),
    Sent = [gen_tcp:send(C, F) || F <- Frames],
    Recv = case P of
               _ when P =:= raw; P =:= 0 ->
                   [shape(gen_tcp:recv(S, byte_size(F), 5000)) || F <- Frames];
               _ ->
                   [shape(gen_tcp:recv(S, 0, 5000)) || _ <- Frames]
           end,
    Sendv = gen_tcp:send(C, [<<"ab">>, [<<"c">>, "de"]]),
    SendvRecv = case P of
                    _ when P =:= raw; P =:= 0 -> gen_tcp:recv(S, 5, 5000);
                    _ -> gen_tcp:recv(S, 0, 5000)
                end,
    Back = [gen_tcp:send(S, <<"back">>), gen_tcp:recv(C, case P of
                                                            _ when P =:= raw; P =:= 0 -> 4;
                                                            _ -> 0
                                                        end, 5000)],
    ok = gen_tcp:send(C, <<"xyz">>),
    LenInPacketMode = case P of
                          _ when P =:= raw; P =:= 0 -> not_applicable;
                          _ -> gen_tcp:recv(S, 2, 5000)
                      end,
    ok = gen_tcp:close(C),
    Eof = gen_tcp:recv(S, 0, 5000),
    ok = gen_tcp:close(S),
    {Sent, Recv, Sendv, SendvRecv, Back, LenInPacketMode, Eof}.

packet_wire_format() ->
    [{P, packet_wire_format(P)} || P <- [1, 2, 4]].

packet_wire_format(P) ->
    {Sender, Receiver} = tcp_pair([{packet, P}], [{packet, raw}]),
    Frames = [<<>>, <<"a">>, <<"hello">>, binary:copy(<<"z">>, 250)],
    Sent = [gen_tcp:send(Sender, F) || F <- Frames],
    Total = lists:sum([P + byte_size(F) || F <- Frames]),
    Wire = shape(gen_tcp:recv(Receiver, Total, 5000)),
    {Back, Back2} = tcp_pair([{packet, raw}], [{packet, P}]),
    Raw = [<<0:(P * 8)>>, <<0:((P - 1) * 8), 3, "abc">>, <<0:((P - 1) * 8), 1, "d">>],
    RawSent = [gen_tcp:send(Back, B) || B <- Raw],
    Decoded = [gen_tcp:recv(Back2, 0, 5000) || _ <- [1, 2, 3]],
    {Sent, Wire, RawSent, Decoded}.

packet_active() ->
    [{P, packet_active(P)} || P <- [raw, 1, 2, 4]].

packet_active(P) ->
    Frames = packet_frames(P),
    {C, S} = tcp_pair([{packet, P}]),
    ok = inet:setopts(S, [{active, once}]),
    Once = [begin
                Sent = gen_tcp:send(C, F),
                M = msg(S),
                ok = inet:setopts(S, [{active, once}]),
                {Sent, M}
            end || F <- Frames],
    Q = quiet(S),
    ok = inet:setopts(S, [{active, true}]),
    True = lockstep(C, S, Frames),
    ok = inet:setopts(S, [{active, 2}]),
    N = lockstep(C, S, lists:sublist(Frames, 2)),
    NPassive = msg(S),
    ok = gen_tcp:send(C, hd(Frames)),
    ok = gen_tcp:close(C),
    ok = inet:setopts(S, [{active, once}]),
    Last = msg(S),
    ok = inet:setopts(S, [{active, once}]),
    Closed = msg(S),
    ok = gen_tcp:close(S),
    {Once, Q, True, N, NPassive, Last, Closed}.

split_frame(1, Body) -> {<<(byte_size(Body))>>, Body};
split_frame(2, Body) -> {<<(byte_size(Body)):16>>, Body};
split_frame(4, Body) -> {<<(byte_size(Body)):32>>, Body}.

pieces(P, Body) ->
    {Header, Body} = split_frame(P, Body),
    Half = byte_size(Body) div 2,
    case byte_size(Header) of
        1 -> [Header, binary:part(Body, 0, 3), binary:part(Body, 3, Half - 3),
              binary:part(Body, Half, byte_size(Body) - Half)];
        N -> [binary:part(Header, 0, 1), binary:part(Header, 1, N - 1),
              binary:part(Body, 0, 3), binary:part(Body, 3, Half - 3),
              binary:part(Body, Half, byte_size(Body) - Half)]
    end.

packet_split_segments() ->
    [{P, packet_split_passive(P), packet_split_active(P)} || P <- [1, 2, 4]].

packet_split_passive(P) ->
    {Sender, Receiver} = tcp_pair([{packet, raw}, {nodelay, true}], [{packet, P}]),
    Body = binary:copy(<<"abcdefghij">>, 20),
    Pieces = pieces(P, Body),
    Steps = [begin
                 Sent = gen_tcp:send(Sender, Piece),
                 {Sent, gen_tcp:recv(Receiver, 0, 50)}
             end || Piece <- lists:droplast(Pieces)],
    ok = gen_tcp:send(Sender, lists:last(Pieces)),
    Frame = gen_tcp:recv(Receiver, 0, 5000),
    Two = [gen_tcp:send(Sender, [element(1, split_frame(P, <<"one">>)), <<"one">>,
                                 element(1, split_frame(P, <<"two">>)), <<"two">>]),
           gen_tcp:recv(Receiver, 0, 5000), gen_tcp:recv(Receiver, 0, 5000)],
    ok = gen_tcp:close(Sender),
    Eof = gen_tcp:recv(Receiver, 0, 5000),
    ok = gen_tcp:close(Receiver),
    {Steps, Frame =:= {ok, Body}, Two, Eof}.

packet_split_active(P) ->
    {Sender, Receiver} = tcp_pair([{packet, raw}, {nodelay, true}], [{packet, P}]),
    ok = inet:setopts(Receiver, [{active, true}]),
    Body = binary:copy(<<"abcdefghij">>, 20),
    Pieces = pieces(P, Body),
    Steps = [begin
                 Sent = gen_tcp:send(Sender, Piece),
                 {Sent, quiet(Receiver)}
             end || Piece <- lists:droplast(Pieces)],
    ok = gen_tcp:send(Sender, lists:last(Pieces)),
    Frame = msg(Receiver),
    ok = inet:setopts(Receiver, [{active, once}]),
    Header = element(1, split_frame(P, <<"tail">>)),
    ok = gen_tcp:send(Sender, [Header, <<"ta">>]),
    Q = quiet(Receiver),
    ok = gen_tcp:send(Sender, <<"il">>),
    Tail = msg(Receiver),
    ok = gen_tcp:close(Sender),
    {Steps, Frame =:= {tcp_big, byte_size(Body), erlang:md5(Body)}, Q, Tail, quiet(Receiver)}.

too_long_header(1) -> <<32>>;
too_long_header(2) -> <<32:16>>;
too_long_header(4) -> <<32:32>>.

packet_too_long() ->
    [{P, packet_too_long_passive(P), packet_too_long_active(P)} || P <- [1, 2, 4]].

packet_too_long_passive(P) ->
    {Sender, Receiver} = tcp_pair([{packet, raw}], [{packet, P}, {packet_size, 16}]),
    Opt = inet:getopts(Receiver, [packet_size]),
    ok = gen_tcp:send(Sender, [too_long_header(P), binary:copy(<<"x">>, 32)]),
    First = gen_tcp:recv(Receiver, 0, 5000),
    Again = gen_tcp:recv(Receiver, 0, 100),
    Closed = gen_tcp:close(Receiver),
    Sender2 = gen_tcp:close(Sender),
    {Opt, First, Again, Closed, Sender2}.

packet_too_long_active(P) ->
    {Sender, Receiver} = tcp_pair([{packet, raw}], [{packet, P}, {packet_size, 16}]),
    ok = inet:setopts(Receiver, [{active, true}]),
    ok = gen_tcp:send(Sender, [too_long_header(P), binary:copy(<<"x">>, 32)]),
    First = msg(Receiver),
    Rest = mailbox(Receiver),
    Quiet = quiet(Receiver),
    Closed = gen_tcp:close(Receiver),
    Sender2 = gen_tcp:close(Sender),
    {First, Rest, Quiet, Closed, Sender2}.

packet_send_too_long() ->
    {C1, S1} = tcp_pair([{packet, 1}]),
    P1 = [gen_tcp:send(C1, binary:copy(<<"a">>, 255)), gen_tcp:send(C1, binary:copy(<<"a">>, 256))],
    P1Recv = case gen_tcp:recv(S1, 0, 5000) of
                 {ok, B1} -> {ok, byte_size(B1)};
                 E1 -> E1
             end,
    P1Quiet = gen_tcp:recv(S1, 0, 50),
    {C2, _S2} = tcp_pair([{packet, 2}]),
    P2 = gen_tcp:send(C2, binary:copy(<<"a">>, 65536)),
    {C3, _S3} = tcp_pair([{packet, 4}, {packet_size, 10}]),
    P4 = gen_tcp:send(C3, binary:copy(<<"a">>, 20)),
    {P1, P1Recv, P1Quiet, P2, P4}.

close_errors_passive() ->
    {C, S} = tcp_pair([]),
    ok = gen_tcp:send(C, <<"abc">>),
    ok = gen_tcp:close(C),
    Partial = [gen_tcp:recv(S, 2, 5000), gen_tcp:recv(S, 5, 5000)],
    SendToClosed = send_until_error(S),
    Local = gen_tcp:close(S),
    After = [gen_tcp:recv(S, 0, 100), gen_tcp:recv(S, 2, 100), gen_tcp:send(S, <<"x">>),
             gen_tcp:shutdown(S, read), gen_tcp:shutdown(S, write),
             gen_tcp:shutdown(S, read_write), gen_tcp:close(S), inet:peername(S),
             inet:sockname(S), inet:port(S), inet:getopts(S, [active]),
             inet:setopts(S, [{active, once}]), gen_tcp:controlling_process(S, self())],
    {C2, S2} = tcp_pair([]),
    ok = gen_tcp:send(C2, <<"pending">>),
    Local2 = gen_tcp:close(C2),
    Remote = gen_tcp:recv(S2, 7, 5000),
    Remote2 = gen_tcp:recv(S2, 0, 5000),
    ok = gen_tcp:close(S2),
    {Partial, SendToClosed, Local, After, Local2, Remote, Remote2}.

send_until_error(S) ->
    send_until_error(S, 100).

send_until_error(_S, 0) -> still_ok;
send_until_error(S, N) ->
    case gen_tcp:send(S, binary:copy(<<"x">>, 1000)) of
        ok -> send_until_error(S, N - 1);
        {error, Reason} -> {error, Reason}
    end.

close_errors_active() ->
    {C, S} = tcp_pair([]),
    ok = inet:setopts(S, [{active, true}]),
    ok = gen_tcp:send(C, <<"abc">>),
    Data = msg(S),
    ok = gen_tcp:close(C),
    Closed = msg(S),
    Mailbox = mailbox(S),
    SendToClosed = send_until_error(S),
    ok = gen_tcp:close(S),
    {Cr, Sr} = tcp_pair([]),
    ok = inet:setopts(Sr, [{active, true}]),
    ok = gen_tcp:send(Cr, <<"before">>),
    Before = msg(Sr),
    ok = inet:setopts(Cr, [{linger, {true, 0}}]),
    ok = gen_tcp:close(Cr),
    Reset = msg(Sr),
    ResetNext = msg(Sr),
    ResetRest = mailbox(Sr),
    ResetSend = gen_tcp:send(Sr, <<"x">>),
    ok = gen_tcp:close(Sr),
    {Cl, Sl} = tcp_pair([]),
    ok = inet:setopts(Sl, [{active, once}]),
    ok = gen_tcp:close(Sl),
    LocalClose = [msg(Cl, 50), mailbox(Sl)],
    ok = gen_tcp:close(Cl),
    {Data, Closed, Mailbox, SendToClosed, Before, Reset, ResetNext, ResetRest,
     ResetSend, LocalClose}.

shutdown_errors() ->
    {C, S} = tcp_pair([{exit_on_close, false}]),
    ok = inet:setopts(S, [{active, true}]),
    ok = gen_tcp:send(C, <<"one">>),
    One = msg(S),
    WriteShut = gen_tcp:shutdown(C, write),
    Eof = msg(S),
    Back = [gen_tcp:send(S, <<"back">>), gen_tcp:recv(C, 4, 5000)],
    SendAfter = gen_tcp:send(C, <<"two">>),
    WriteAgain = [gen_tcp:shutdown(C, write), gen_tcp:shutdown(C, write)],
    ok = gen_tcp:close(C),
    ok = gen_tcp:close(S),
    {C2, S2} = tcp_pair([]),
    ReadShut = gen_tcp:shutdown(C2, read),
    RecvAfterRead = gen_tcp:recv(C2, 0, 50),
    ok = gen_tcp:close(C2),
    ok = gen_tcp:close(S2),
    {C4, S4} = tcp_pair([]),
    Both = gen_tcp:shutdown(C4, read_write),
    SendAfterBoth = gen_tcp:send(C4, <<"x">>),
    PeerEof = gen_tcp:recv(S4, 0, 5000),
    ok = gen_tcp:close(C4),
    ok = gen_tcp:close(S4),
    {C3, S3} = tcp_pair([]),
    ok = inet:setopts(C3, [{active, once}]),
    ShutPeer = gen_tcp:shutdown(S3, write),
    PeerShutMsg = msg(C3),
    Replied = [gen_tcp:send(C3, <<"reply">>), gen_tcp:recv(S3, 5, 5000)],
    BadHow = try gen_tcp:shutdown(C3, bogus) catch Class:Reason -> {Class, element(1, Reason)} end,
    ok = gen_tcp:close(C3),
    ok = gen_tcp:close(S3),
    {One, WriteShut, Eof, SendAfter, Back, WriteAgain, ReadShut, RecvAfterRead, Both,
     SendAfterBoth, PeerEof, ShutPeer, PeerShutMsg, Replied, norm(BadHow)}.

close_wakes_blocked_recv() ->
    {C, S} = tcp_pair([]),
    {'$inet', gen_tcp_socket, {_, Sock}} = S,
    Parent = self(),
    Reader = spawn(fun() -> Parent ! {read, gen_tcp:recv(S, 0, infinity)} end),
    Waiting = wait_until(fun() -> maps:get(num_readers, socket:info(Sock), 0) >= 1 end, 500),
    Close = gen_tcp:close(S),
    Read = receive {read, R} -> R after 5000 -> timeout end,
    _ = Reader,
    Peer = gen_tcp:recv(C, 0, 5000),
    ok = gen_tcp:close(C),
    {C2, S2} = tcp_pair([]),
    {'$inet', gen_tcp_socket, {_, Sock2}} = S2,
    Reader2 = spawn(fun() -> Parent ! {read2, gen_tcp:recv(S2, 3, infinity)} end),
    Waiting2 = wait_until(fun() -> maps:get(num_readers, socket:info(Sock2), 0) >= 1 end, 500),
    Shut = gen_tcp:shutdown(C2, write),
    Read2 = receive {read2, R2} -> R2 after 5000 -> timeout end,
    _ = Reader2,
    ok = gen_tcp:close(C2),
    ok = gen_tcp:close(S2),
    {Waiting, Close, Read, Peer, Waiting2, Shut, Read2}.
