%% Reference endpoint for arinsal-difftest. Protocol values are ETF terms.
-module(difftest_server).
-export([main/0]).

-record(state, {port, active = #{}, queued = queue:new(), max = 32}).

main() ->
    ok = logger:set_primary_config(level, emergency),
    process_flag(trap_exit, true),
    Max = case os:getenv("DIFFTEST_MAX_CALLS") of
        false -> 32;
        Text -> case string:to_integer(Text) of
            {N, ""} when N > 0 -> N;
            _ -> 32
        end
    end,
    Port = open_port({fd, 0, 1}, [{packet, 4}, binary, eof]),
    start_parent_watchdog(),
    loop(#state{port = Port, max = Max}),
    %% Started with -s, so returning would leave the node running forever.
    erlang:halt(0).

%% Halt when the Rust test process that started us is gone, even if it was
%% killed before it could close our stdin (e.g. SIGKILL or a crashed runner).
start_parent_watchdog() ->
    case os:getenv("DIFFTEST_PARENT_PID") of
        false -> ok;
        Pid ->
            spawn(fun() -> watch_parent(Pid) end)
    end.

watch_parent(Pid) ->
    timer:sleep(1000),
    case string:trim(os:cmd("kill -0 " ++ Pid ++ " 2>/dev/null && echo alive")) of
        "alive" -> watch_parent(Pid);
        _ -> erlang:halt(0)
    end.

loop(State = #state{port = Port, active = Active}) ->
    receive
        {Port, {data, Bytes}} ->
            Next = try binary_to_term(Bytes) of
                Request -> dispatch(Request, State)
            catch _:Reason ->
                reply(Port, {protocol_error, Reason}), State
            end,
            loop(Next);
        {Port, {exit_status, _}} -> ok;
        {Port, eof} -> ok;
        {worker, Ref, Response} ->
            case maps:take(Ref, Active) of
                {{Id, _Pid, Timer}, Rest} ->
                    erlang:cancel_timer(Timer),
                    erlang:demonitor(Ref, [flush]),
                    reply(Port, {Id, Response}),
                    loop(drain(State#state{active = Rest}));
                error -> loop(State)
            end;
        {'DOWN', Ref, process, _Pid, Reason} ->
            case maps:take(Ref, Active) of
                {{Id, _Worker, Timer}, Rest} ->
                    erlang:cancel_timer(Timer),
                    reply(Port, {Id, {exception, exit, Reason, undefined}}),
                    loop(drain(State#state{active = Rest}));
                error -> loop(State)
            end;
        {call_timeout, Ref} ->
            case maps:take(Ref, Active) of
                {{Id, Pid, _Timer}, Rest} ->
                    exit(Pid, kill),
                    erlang:demonitor(Ref, [flush]),
                    reply(Port, {Id, timeout}),
                    loop(drain(State#state{active = Rest}));
                error -> loop(State)
            end;
        {'EXIT', Port, _} -> ok;
        _ -> loop(State)
    end.

dispatch(ping, State = #state{port = Port}) ->
    reply(Port, {pong, erlang:system_info(otp_release),
                 otp_version()}), State;
dispatch(stop, State = #state{port = Port}) ->
    reply(Port, stopped),
    erlang:halt(0), State;
dispatch({load, Id, Mod, Beam}, State = #state{port = Port}) ->
    Reply = try code:load_binary(Mod, atom_to_list(Mod) ++ ".beam", Beam)
            catch Class:Reason -> {error, {Class, Reason}} end,
    reply(Port, {Id, Reply}), State;
dispatch({compile, Id, Mod, Source, Opts}, State = #state{port = Port}) ->
    Reply = try compile_source(Mod, Source, Opts)
            catch Class:Reason:Stack -> {exception, Class, Reason, top(Stack)} end,
    reply(Port, {Id, Reply}), State;
dispatch({eval, Id, Expression}, State) ->
    submit(Id, fun() -> eval_expr(Expression) end, [], State);
dispatch({call, Id, M, F, Args}, State) ->
    case forbidden(M, F) of
        true -> reply(State#state.port, {Id, {exception, error, forbidden_call, undefined}}), State;
        false -> submit(Id, fun() -> apply(M, F, Args) end, [], State)
    end;
dispatch({call_opts, Id, M, F, Args, Opts}, State) ->
    case forbidden(M, F) of
        true -> reply(State#state.port, {Id, {exception, error, forbidden_call, undefined}}), State;
        false -> submit(Id, fun() -> apply(M, F, Args) end, Opts, State)
    end;
dispatch(Other, State = #state{port = Port}) ->
    reply(Port, {protocol_error, {bad_request, Other}}), State.

%% halt/stop terminate the whole node even when called in a monitored process.
forbidden(erlang, halt) -> true;
forbidden(erlang, display) -> true;
forbidden(erlang, display_string) -> true;
forbidden(init, stop) -> true;
forbidden(init, restart) -> true;
forbidden(_, _) -> false.

submit(Id, Fun, Opts, State = #state{active = Active, max = Max, queued = Queued}) ->
    case maps:size(Active) < Max of
        true -> start_worker(Id, Fun, Opts, State);
        false -> State#state{queued = queue:in({Id, Fun, Opts}, Queued)}
    end.

drain(State = #state{active = Active, max = Max, queued = Queued}) ->
    case maps:size(Active) < Max of
        false -> State;
        true -> case queue:out(Queued) of
            {{value, {Id, Fun, Opts}}, Rest} ->
                drain(start_worker(Id, Fun, Opts, State#state{queued = Rest}));
            {empty, _} -> State
        end
    end.

start_worker(Id, Fun, Opts, State = #state{active = Active}) ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        receive {request_ref, WorkerRef} ->
            Response = run(Fun, Opts),
            Parent ! {worker, WorkerRef, Response}
        end
    end),
    %% The worker needs its own monitor reference for the response. Send it
    %% explicitly after spawn; this also prevents completion before registration.
    Pid ! {request_ref, Ref},
    Timeout = proplists:get_value(timeout, Opts, 5000),
    Ms = case Timeout of N when is_integer(N), N >= 0 -> N; _ -> 5000 end,
    Timer = erlang:send_after(Ms, self(), {call_timeout, Ref}),
    State#state{active = Active#{Ref => {Id, Pid, Timer}}}.

run(Fun, Opts) ->
    Sink = spawn_link(fun() -> io_sink([]) end),
    group_leader(Sink, self()),
    Before = element(2, process_info(self(), reductions)),
    Result = try Fun() of
        Value ->
            case proplists:get_value(encode_opts, Opts) of
                undefined -> {ok, Value};
                EncodeOpts -> {ok, term_to_binary(Value, EncodeOpts)}
            end
    catch Class:Reason:Stack -> {exception, Class, Reason,
        top(Stack, proplists:get_value(strip_lines, Opts, false))} end,
    After = element(2, process_info(self(), reductions)),
    Heap = element(2, process_info(self(), total_heap_size)),
    Sink ! {output, self()},
    Output = receive {output, Chunks} -> unicode:characters_to_binary(lists:reverse(Chunks))
             after 1000 -> <<>> end,
    exit(Sink, normal),
    Meta = [Item || Item <- [
        case proplists:get_value(capture_io, Opts) of true -> {io, Output}; _ -> skip end,
        case proplists:get_value(reductions, Opts) of true -> {reductions, After - Before}; _ -> skip end,
        case proplists:get_value(heap, Opts) of true -> {heap, Heap}; _ -> skip end
    ], Item =/= skip],
    case Opts of [] -> Result; _ -> attach_meta(Result, Meta) end.

attach_meta({ok, Value}, Meta) -> {ok, Value, Meta};
attach_meta({exception, Class, Reason, Top}, Meta) ->
    {exception, Class, Reason, Top, Meta}.

io_sink(Chunks) ->
    receive
        {io_request, From, ReplyAs, Request} ->
            {Answer, Bytes} = io_request(Request),
            From ! {io_reply, ReplyAs, Answer},
            io_sink([Bytes | Chunks]);
        {output, From} -> From ! {output, Chunks}, io_sink(Chunks);
        _ -> io_sink(Chunks)
    end.

io_request({put_chars, Chars}) -> {ok, Chars};
io_request({put_chars, _Encoding, Chars}) -> {ok, Chars};
io_request({put_chars, Mod, Func, Args}) ->
    try {ok, apply(Mod, Func, Args)} catch _:_ -> {{error, put_chars}, <<>>} end;
io_request({put_chars, _Encoding, Mod, Func, Args}) ->
    io_request({put_chars, Mod, Func, Args});
io_request({requests, Requests}) ->
    Pairs = [io_request(Request) || Request <- Requests],
    {ok, [Bytes || {_, Bytes} <- Pairs]};
io_request(_) -> {{error, request}, <<>>}.

top(Stack) -> top(Stack, false).
top([{M, F, A, Location} | _], true) ->
    {M, F, A, proplists:delete(line, Location)};
top([Frame | _], false) -> Frame;
top(_, _) -> undefined.

compile_source(Mod, Source, Opts) ->
    Text = unicode:characters_to_list(Source),
    {ok, Tokens, _} = erl_scan:string(Text),
    Forms = parse_forms(Tokens, [], []),
    case compile:forms(Forms, [binary, return_errors, return_warnings | Opts]) of
        {ok, Mod, Beam} -> {ok, Beam};
        {ok, Mod, Beam, _Warnings} -> {ok, Beam};
        Error -> {error, Error}
    end.

parse_forms([], [], Acc) -> lists:reverse(Acc);
parse_forms([], _Pending, _Acc) -> erlang:error(incomplete_form);
parse_forms([{dot, _} = Dot | Rest], Pending, Acc) ->
    {ok, Form} = erl_parse:parse_form(lists:reverse([Dot | Pending])),
    parse_forms(Rest, [], [Form | Acc]);
parse_forms([Token | Rest], Pending, Acc) ->
    parse_forms(Rest, [Token | Pending], Acc).

eval_expr(Expression) ->
    Text = unicode:characters_to_list(Expression),
    {ok, Tokens, _} = erl_scan:string(Text ++ "."),
    {ok, Exprs} = erl_parse:parse_exprs(Tokens),
    {value, Value, _} = erl_eval:exprs(Exprs, []),
    Value.

reply(Port, Term) -> port_command(Port, term_to_binary(Term)).

otp_version() ->
    Path = filename:join([code:root_dir(), "releases",
                          erlang:system_info(otp_release), "OTP_VERSION"]),
    {ok, Binary} = file:read_file(Path),
    string:trim(binary_to_list(Binary)).
