-module(sock_close_compat).
-export([close_aborts_blocked_recv/0, close_aborts_blocked_accept/0,
         close_aborts_nowait_requestors/0, controlling_process_transfer/0,
         owner_exit_closes/0, otp_options/0, cancel_ops/0, info_and_registry/0,
         closer_not_owner/0, errnos/0, socket_options/0,
         reader_death_activates_next/0, closer_dies_before_finalize/0, accept_inherits/0,
         controlling_process_to_dead/0, owner_dies_with_waiting_reader/0, reader_queue_order/0,
         unreferenced_socket_is_closed_by_gc/0, monitored_by_lists_the_socket/0]).

addr(Port) -> #{family => inet, addr => loopback, port => Port}.

norm(T) when is_reference(T) -> ref;
norm(T) when is_pid(T) -> pid;
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm([H|T]) -> [norm(H)|norm(T)];
norm(M) when is_map(M) -> maps:from_list([{norm(K), norm(V)} || {K,V} <- maps:to_list(M)]);
norm(T) -> T.

listener() ->
    {ok, L} = socket:open(inet, stream, tcp),
    ok = socket:bind(L, #{family => inet, addr => loopback, port => 0}),
    ok = socket:listen(L),
    {ok, #{port := Port}} = socket:sockname(L),
    {L, Port}.

pair() ->
    {L, Port} = listener(),
    {ok, C} = socket:open(inet, stream, tcp),
    ok = socket:connect(C, addr(Port)),
    {ok, A} = socket:accept(L, 2000),
    ok = socket:close(L),
    {C, A}.

close_aborts_blocked_recv() ->
    {C, A} = pair(),
    Parent = self(),
    Reader = spawn(fun() -> Parent ! {read, socket:recv(C, 0)} end),
    timer:sleep(200),
    Close = socket:close(C),
    Read = receive {read, R} -> R after 3000 -> timeout end,
    _ = Reader,
    Peer = socket:recv(A, 0, 1000),
    ok = socket:close(A),
    {Close, Read, Peer}.

close_aborts_blocked_accept() ->
    {L, _Port} = listener(),
    Parent = self(),
    spawn(fun() -> Parent ! {acc, socket:accept(L)} end),
    timer:sleep(200),
    Close = socket:close(L),
    Acc = receive {acc, R} -> R after 3000 -> timeout end,
    {Close, Acc}.

close_aborts_nowait_requestors() ->
    {C, A} = pair(),
    Parent = self(),
    {select, {select_info, recv, RRef}} = socket:recv(C, 0, nowait),
    Other = spawn(fun() ->
        Parent ! {other, socket:recv(C, 0, nowait)},
        receive {'$socket', _, abort, Info} -> Parent ! {other_abort, Info} after 3000 -> Parent ! other_timeout end
    end),
    Queued = receive {other, Q} -> norm(Q) after 3000 -> timeout end,
    Close = socket:close(C),
    Mine = receive {'$socket', _, abort, {RRef, Why}} -> {abort, Why} after 3000 -> timeout end,
    OtherAbort = receive {other_abort, {_, W2}} -> {abort, W2}; other_timeout -> timeout after 3000 -> timeout end,
    _ = Other,
    ok = socket:close(A),
    {Queued, Close, Mine, OtherAbort}.

controlling_process_transfer() ->
    Parent = self(),
    {L, Port} = listener(),
    Owner = spawn(fun() ->
        {ok, S} = socket:open(inet, stream, tcp),
        ok = socket:connect(S, addr(Port)),
        Parent ! {sock, S},
        receive {give, To} ->
            NotOwner = socket:setopt(S, {otp, controlling_process}, To),
            Parent ! {not_owner_result, norm(NotOwner)},
            Parent ! {gave, socket:setopt(S, {otp, controlling_process}, To)}
        end
    end),
    S = receive {sock, X} -> X after 3000 -> timeout end,
    {ok, Peer} = socket:accept(L, 2000),
    NonOwner = socket:setopt(S, {otp, controlling_process}, self()),
    Mon = erlang:monitor(process, Owner),
    Owner ! {give, self()},
    NotOwnerRes = receive {not_owner_result, N} -> N after 3000 -> timeout end,
    Gave = receive {gave, G} -> G after 3000 -> timeout end,
    receive {'DOWN', Mon, process, Owner, _} -> ok after 3000 -> timeout end,
    timer:sleep(100),
    Ctrl = socket:getopt(S, {otp, controlling_process}),
    Open = socket:send(S, <<"x">>),
    Got = socket:recv(Peer, 1, 2000),
    Same = Ctrl =:= {ok, self()},
    NewOwnerSetsMeta = socket:setopt(S, {otp, meta}, hello),
    Meta = socket:getopt(S, {otp, meta}),
    ok = socket:close(S),
    ok = socket:close(Peer),
    ok = socket:close(L),
    {norm(NonOwner), NotOwnerRes, Gave, Same, Open, Got, NewOwnerSetsMeta, Meta}.

owner_exit_closes() ->
    Parent = self(),
    {L, Port} = listener(),
    Owner = spawn(fun() ->
        {ok, S} = socket:open(inet, stream, tcp),
        ok = socket:connect(S, addr(Port)),
        Parent ! {sock, S}
    end),
    S = receive {sock, X} -> X after 3000 -> timeout end,
    {ok, Peer} = socket:accept(L, 2000),
    Mon = erlang:monitor(process, Owner),
    receive {'DOWN', Mon, process, Owner, _} -> ok after 3000 -> timeout end,
    Eof = socket:recv(Peer, 0, 2000),
    Fd = socket:getopt(S, {otp, fd}),
    Send = socket:send(S, <<"x">>),
    Close = socket:close(S),
    ok = socket:close(Peer),
    ok = socket:close(L),
    {Eof, Fd, Send, Close}.

otp_options() ->
    {ok, S} = socket:open(inet, stream, tcp),
    Get = fun(O) -> socket:getopt(S, {otp, O}) end,
    Set = fun(O, V) -> socket:setopt(S, {otp, O}, V) end,
    Defaults = [Get(O) || O <- [debug, iow, select_read, rcvbuf, rcvctrlbuf, sndctrlbuf, meta, use_registry, domain]],
    {ok, Fd} = Get(fd),
    Ctrl = Get(controlling_process) =:= {ok, self()},
    Sets = [{O, V, Set(O, V), Get(O)} ||
               {O, V} <- [{debug, false}, {iow, true}, {iow, false}, {select_read, true},
                          {rcvbuf, 4096}, {rcvbuf, default}, {rcvbuf, {3, 100}}, {rcvbuf, {3, default}},
                          {rcvbuf, 0}, {rcvbuf, {0, 10}}, {rcvbuf, foo}, {rcvbuf, -1},
                          {rcvctrlbuf, 77}, {rcvctrlbuf, default}, {rcvctrlbuf, 0},
                          {sndctrlbuf, 88}, {sndctrlbuf, default}, {sndctrlbuf, bad},
                          {meta, #{a => 1}}, {meta, undefined},
                          {use_registry, true}, {use_registry, false}, {debug, 1}, {iow, 'maybe'}]],
    NotOwner = begin
        Self = self(),
        spawn(fun() -> Self ! {no, norm({Set(meta, 1), Get(meta), Set(controlling_process, self())})} end),
        receive {no, R} -> R after 3000 -> timeout end
    end,
    Bad = ok,
    ok = socket:close(S),
    After = [Get(O) || O <- [debug, iow, select_read, rcvbuf, controlling_process, fd, meta, domain, use_registry]],
    AfterSet = [Set(O, true) || O <- [debug, iow, select_read, use_registry]],
    {Defaults, is_integer(Fd), Ctrl, Sets, NotOwner, norm(Bad), After, AfterSet}.

cancel_ops() ->
    {C, A} = pair(),
    {select, SI} = socket:recv(C, 0, nowait),
    C1 = socket:cancel(C, SI),
    C2 = socket:cancel(C, SI),
    {select, SI2} = socket:recv(C, 0, nowait),
    ok = socket:send(A, <<"d">>),
    receive {'$socket', _, select, _} -> ok after 2000 -> timeout end,
    C3 = socket:cancel(C, SI2),
    Rec = socket:recv(C, 0, nowait),
    {L, _Port} = listener(),
    {select, AI} = socket:accept(L, nowait),
    C4 = socket:cancel(L, AI),
    C5 = socket:cancel(L, AI),
    BadOp = try prim_socket:cancel(L, bogus, make_ref()) catch OC:OR -> {OC, OR} end,
    ok = socket:close(L),
    Closed = socket:cancel(L, AI),
    ok = socket:close(C),
    ok = socket:close(A),
    {C1, norm(C2), C3, Rec, C4, norm(C5), norm(BadOp), norm(Closed)}.

info_and_registry() ->
    Before = socket:which_sockets(),
    {ok, S} = socket:open(inet, stream, tcp),
    Reg = lists:member(S, socket:which_sockets()),
    Info0 = maps:with([domain, type, protocol, ctype, rstates, wstates, num_readers, num_writers, num_acceptors], socket:info(S)),
    ok = socket:bind(S, #{family => inet, addr => loopback, port => 0}),
    ok = socket:listen(S),
    Info1 = maps:with([rstates, wstates], socket:info(S)),
    {select, _} = socket:accept(S, nowait),
    Info2 = maps:with([rstates, num_acceptors], socket:info(S)),
    Counters = fun() -> maps:with([num_sockets, num_tstreams, num_ptcp, num_dinet], maps:get(counters, socket:info())) end,
    C1 = Counters(),
    Mon = socket:monitor(S),
    ok = socket:close(S),
    Down = receive {'DOWN', Mon, socket, S, Why} -> Why after 3000 -> timeout end,
    C2 = Counters(),
    Gone = not lists:member(S, socket:which_sockets()),
    Info3 = try maps:with([rstates, wstates], socket:info(S)) catch IC:IR -> {IC, IR} end,
    {Before =:= socket:which_sockets(), Reg, Info0, Info1, Info2, C1 =/= C2, norm(Down), Gone, Info3}.

closer_not_owner() ->
    Parent = self(),
    {ok, S} = socket:open(inet, stream, tcp),
    Closer = spawn(fun() -> Parent ! {closed, socket:close(S)} end),
    Res = receive {closed, R} -> R after 3000 -> timeout end,
    _ = Closer,
    Again = socket:close(S),
    Fd = socket:getopt(S, {otp, fd}),
    {Res, Again, Fd}.

errnos() ->
    {ok, S} = socket:open(inet, stream, tcp),
    R1 = socket:connect(S, #{family => inet, addr => loopback, port => 1}, 2000),
    ok = socket:close(S),
    {ok, S2} = socket:open(inet, stream, tcp),
    R2 = socket:bind(S2, #{family => inet, addr => {203,0,113,1}, port => 0}),
    R3 = socket:sockname(S2),
    R4 = socket:peername(S2),
    ok = socket:close(S2),
    {ok, SL} = socket:open(local, stream),
    R5 = socket:connect(SL, #{family => local, path => <<"/nonexistent/sock_close_compat">>}),
    ok = socket:close(SL),
    {ok, SD} = socket:open(inet, dgram, udp),
    R6 = socket:listen(SD),
    ok = socket:close(SD),
    {R1, R2, R3, norm(R4), R5, R6}.

socket_options() ->
    {ok, S} = socket:open(inet, stream, tcp),
    {ok, S6} = socket:open(inet6, stream, tcp),
    Try = fun(Sock, Opt, Val) ->
        Set = try socket:setopt(Sock, Opt, Val) catch SC:SR -> {SC, element(1, SR)} end,
        Get = try socket:getopt(Sock, Opt) catch GC:GR -> {GC, element(1, GR)} end,
        {Opt, Val, Set, Get}
    end,
    Cases = [{{socket,reuseaddr}, true}, {{socket,reuseaddr}, false}, {{socket,reuseaddr}, 1}, {{socket,reuseaddr}, foo},
             {{socket,keepalive}, true}, {{socket,keepalive}, 0},
             {{socket,reuseport}, true}, {{socket,dontroute}, true}, {{socket,oobinline}, true},
             {{socket,linger}, #{onoff => true, linger => 5}}, {{socket,linger}, #{onoff => false, linger => 0}},
             {{socket,linger}, abort}, {{socket,linger}, #{onoff => true, linger => -1}}, {{socket,linger}, foo},
             {{socket,rcvbuf}, 65536}, {{socket,rcvbuf}, foo}, {{socket,sndbuf}, 65536},
             {{socket,rcvlowat}, 2}, {{socket,sndlowat}, 2},
             {{socket,type}, stream}, {{socket,domain}, inet},
             {{tcp,nodelay}, true}, {{tcp,nodelay}, false}, {{tcp,nodelay}, 3},
             {{tcp,keepcnt}, 5}, {{tcp,keepintvl}, 7},
             {{ip,ttl}, 33}, {{ip,tos}, lowdelay}, {{ip,tos}, 16},
             {{ip,recvtos}, true}, {{ip,recvttl}, true}, {{ip,multicast_ttl}, 3}, {{ip,multicast_loop}, true},
             {{tcp,bogus}, true}, {{bogus,nodelay}, true}],
    R4 = [Try(S, O, V) || {O, V} <- Cases],
    R6 = [Try(S6, O, V) || {O, V} <- [{{ipv6,v6only}, true}, {{ipv6,v6only}, false}, {{ipv6,unicast_hops}, 10},
                                       {{ipv6,tclass}, 4}, {{ipv6,multicast_hops}, 2}, {{ipv6,multicast_loop}, true}]],
    Native = [begin
        SetN = try socket:setopt_native(S, {socket, reuseaddr}, V) catch NC:NR -> {NC, element(1, NR)} end,
        {V, SetN, socket:getopt_native(S, {socket, reuseaddr}, int)}
    end || V <- [<<1:32/native>>, 0, true]],
    ok = socket:close(S),
    ok = socket:close(S6),
    {R4, R6, Native}.

reader_death_activates_next() ->
    {C, A} = pair(),
    Parent = self(),
    P1 = spawn(fun() ->
        Parent ! {p1, socket:recv(C, 0, nowait)},
        receive stop -> ok end
    end),
    {p1, R1} = receive {p1, X1} -> {p1, norm(X1)} after 3000 -> timeout end,
    P2 = spawn(fun() ->
        Parent ! {p2, socket:recv(C, 0, nowait)},
        receive {'$socket', _, select, Ref} -> Parent ! {p2_select, Ref, socket:recv(C, 0, nowait)}
        after 3000 -> Parent ! p2_timeout end
    end),
    {p2, R2} = receive {p2, X2} -> {p2, norm(X2)} after 3000 -> timeout end,
    Mon = erlang:monitor(process, P1),
    exit(P1, kill),
    receive {'DOWN', Mon, process, P1, _} -> ok after 3000 -> timeout end,
    timer:sleep(100),
    ok = socket:send(A, <<"data">>),
    R3 = receive {p2_select, _, Rec} -> Rec; p2_timeout -> timeout after 4000 -> timeout end,
    _ = P2,
    ok = socket:close(C),
    ok = socket:close(A),
    {R1, R2, R3}.

closer_dies_before_finalize() ->
    {C, A} = pair(),
    Parent = self(),
    Closer = spawn(fun() ->
        Parent ! {closed, prim_socket:close(element(2, C))},
        receive never -> ok end
    end),
    {closed, Res} = receive {closed, X} -> {closed, X} after 3000 -> timeout end,
    Mon = erlang:monitor(process, Closer),
    exit(Closer, kill),
    receive {'DOWN', Mon, process, Closer, _} -> ok after 3000 -> timeout end,
    timer:sleep(100),
    Eof = socket:recv(A, 0, 2000),
    Fd = socket:getopt(C, {otp, fd}),
    Again = socket:close(C),
    ok = socket:close(A),
    {Res, Eof, Fd, Again}.

accept_inherits() ->
    {L, Port} = listener(),
    ok = socket:setopt(L, {otp, rcvbuf}, {2, 4096}),
    ok = socket:setopt(L, {otp, rcvctrlbuf}, 33),
    ok = socket:setopt(L, {otp, sndctrlbuf}, 44),
    ok = socket:setopt(L, {otp, iow}, true),
    ok = socket:setopt(L, {otp, select_read}, true),
    ok = socket:setopt(L, {otp, meta}, listener_meta),
    {ok, C} = socket:open(inet, stream, tcp),
    ok = socket:connect(C, addr(Port)),
    {ok, A} = socket:accept(L, 2000),
    Opts = [Opt || Opt <- [rcvbuf, rcvctrlbuf, sndctrlbuf, iow, select_read, meta, use_registry, debug, controlling_process]],
    Got = [{Opt, socket:getopt(A, {otp, Opt})} || Opt <- Opts],
    ok = socket:close(A), ok = socket:close(C), ok = socket:close(L),
    norm(Got).

controlling_process_to_dead() ->
    {ok, S} = socket:open(inet, stream, tcp),
    Dead = spawn(fun() -> ok end),
    Mon = erlang:monitor(process, Dead),
    receive {'DOWN', Mon, process, Dead, _} -> ok after 3000 -> timeout end,
    R = socket:setopt(S, {otp, controlling_process}, Dead),
    Fd = socket:getopt(S, {otp, fd}),
    Ctrl = norm(socket:getopt(S, {otp, controlling_process})),
    Close = socket:close(S),
    {R, Fd, Ctrl, Close}.

owner_dies_with_waiting_reader() ->
    Parent = self(),
    {L, Port} = listener(),
    Owner = spawn(fun() ->
        {ok, S} = socket:open(inet, stream, tcp),
        ok = socket:connect(S, addr(Port)),
        Parent ! {sock, S},
        receive stop -> ok end
    end),
    S = receive {sock, X} -> X after 3000 -> timeout end,
    {ok, Peer} = socket:accept(L, 2000),
    Reader = spawn(fun() ->
        Parent ! {sel, socket:recv(S, 0, nowait)},
        receive {'$socket', _, abort, {_, Why}} -> Parent ! {abort, Why}
        after 3000 -> Parent ! abort_timeout end
    end),
    Sel = receive {sel, V} -> norm(V) after 3000 -> timeout end,
    Mon = erlang:monitor(process, Owner),
    exit(Owner, kill),
    receive {'DOWN', Mon, process, Owner, _} -> ok after 3000 -> timeout end,
    Abort = receive {abort, W} -> W; abort_timeout -> timeout after 4000 -> timeout end,
    Eof = socket:recv(Peer, 0, 2000),
    _ = Reader,
    ok = socket:close(Peer), ok = socket:close(L),
    {Sel, Abort, Eof}.

reader_queue_order() ->
    {C, A} = pair(),
    Parent = self(),
    P1 = spawn(fun() ->
        Parent ! {p1, socket:recv(C, 0, nowait)},
        receive {'$socket', _, select, _} -> Parent ! p1_selected after 3000 -> Parent ! p1_timeout end,
        Parent ! {p1_data, socket:recv(C, 0, nowait)},
        receive stop -> ok end
    end),
    receive {p1, _} -> ok after 3000 -> timeout end,
    P2 = spawn(fun() ->
        Parent ! {p2, norm(socket:recv(C, 0, nowait))},
        receive {'$socket', _, select, _} -> Parent ! p2_selected after 3000 -> Parent ! p2_timeout end
    end),
    P2Queued = receive {p2, Q} -> Q after 3000 -> timeout end,
    ok = socket:send(A, <<"one">>),
    First = receive p1_selected -> p1; p1_timeout -> p1_timeout after 4000 -> timeout end,
    P1Data = receive {p1_data, D} -> D after 3000 -> timeout end,
    Second = receive p2_selected -> p2; p2_timeout -> p2_timeout after 500 -> none end,
    ok = socket:send(A, <<"two">>),
    Third = receive p2_selected -> p2; p2_timeout -> p2_timeout after 4000 -> timeout end,
    _ = {P1, P2},
    ok = socket:close(C), ok = socket:close(A),
    {P2Queued, First, P1Data, Second, Third}.

monitored_count() ->
    timer:sleep(50),
    {monitored_by, L} = process_info(self(), monitored_by),
    length(L).

open_bound_dropped() ->
    {ok, C} = socket:open(inet, stream, tcp, #{use_registry => false}),
    ok = socket:bind(C, addr(0)),
    {ok, #{port := Port}} = socket:sockname(C),
    {ok, Fd} = socket:getopt(C, {otp, fd}),
    {Fd, Port}.

open_registered_dropped() ->
    {ok, C} = socket:open(inet, stream, tcp),
    ok = socket:bind(C, addr(0)),
    ok.

unreferenced_socket_is_closed_by_gc() ->
    Mon0 = monitored_count(),
    {Fd, Port} = open_bound_dropped(),
    Mon1 = monitored_count(),
    erlang:garbage_collect(),
    Mon2 = monitored_count(),
    {ok, S2} = socket:open(inet, stream, tcp, #{use_registry => false}),
    {ok, Fd2} = socket:getopt(S2, {otp, fd}),
    Rebind = socket:bind(S2, addr(Port)),
    ok = socket:close(S2),
    Registered0 = socket:which_sockets(),
    ok = open_registered_dropped(),
    erlang:garbage_collect(),
    timer:sleep(100),
    Pinned = socket:which_sockets() -- Registered0,
    [ok = socket:close(S) || S <- Pinned],
    {Fd =:= Fd2, Rebind, Mon1 - Mon0, Mon2 - Mon0, length(Pinned)}.

monitored_by_lists_the_socket() ->
    {ok, S} = socket:open(inet, stream, tcp),
    {'$socket', Ref} = S,
    timer:sleep(50),
    {monitored_by, M0} = process_info(self(), monitored_by),
    Listed = lists:member(Ref, M0),
    Other = spawn(fun() -> receive stop -> ok end end),
    ok = socket:setopt(S, {otp, controlling_process}, Other),
    timer:sleep(100),
    {monitored_by, M1} = process_info(self(), monitored_by),
    {monitored_by, M2} = process_info(Other, monitored_by),
    Moved = {lists:member(Ref, M1), lists:member(Ref, M2)},
    Other ! stop,
    timer:sleep(100),
    {Listed, Moved, socket:getopt(S, {otp, fd}) =:= {error, closed}}.
