%% Per-project log collector. It is the group leader of the project's processes: it speaks the
%% io protocol, keeps the last N lines in a ring buffer and appends everything to a file.
%% Raw output (for example the stdout of an OS process) goes through `write/2`.
-module(arinsal_cloud_log).
-behaviour(gen_server).

-export([start_link/1, write/2, lines/2, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(s, {
    file :: file:io_device() | undefined,
    max :: pos_integer(),
    seq = 0 :: non_neg_integer(),
    lines = queue:new() :: queue:queue({pos_integer(), binary()}),
    count = 0 :: non_neg_integer(),
    partial = <<>> :: binary()
}).

%% Opts: file => path of the log file (optional), max_lines => ring buffer size.
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

-spec write(pid(), iodata()) -> ok.
write(Pid, Data) ->
    gen_server:cast(Pid, {write, iolist_to_binary(Data)}).

%% The newest `N` complete lines after sequence number `Since` (0 for all) and the sequence
%% number to pass as `Since` next time.
-spec lines(pid(), #{n := non_neg_integer(), since => non_neg_integer()}) ->
    {[binary()], non_neg_integer()}.
lines(Pid, Opts) ->
    gen_server:call(Pid, {lines, Opts}).

stop(Pid) ->
    gen_server:stop(Pid).

init(Opts) ->
    process_flag(trap_exit, true),
    File = case maps:find(file, Opts) of
        {ok, Path} ->
            ok = filelib:ensure_dir(Path),
            {ok, Fd} = file:open(Path, [append, raw, binary]),
            Fd;
        error ->
            undefined
    end,
    {ok, #s{file = File, max = maps:get(max_lines, Opts, 1000)}}.

handle_call({lines, Opts}, _From, #s{lines = Q, seq = Seq} = S) ->
    N = maps:get(n, Opts, 100),
    Since = maps:get(since, Opts, 0),
    Fresh = [L || {I, L} <- queue:to_list(Q), I > Since],
    Take = case length(Fresh) - N of
        Drop when Drop > 0 -> lists:nthtail(Drop, Fresh);
        _ -> Fresh
    end,
    {reply, {Take, Seq}, S};
handle_call(_Request, _From, S) ->
    {reply, {error, badcall}, S}.

handle_cast({write, Bin}, S) ->
    {noreply, append(Bin, S)};
handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({io_request, From, ReplyAs, Request}, S) ->
    {Reply, S1} = io_request(Request, S),
    From ! {io_reply, ReplyAs, Reply},
    {noreply, S1};
handle_info(_Info, S) ->
    {noreply, S}.

terminate(_Reason, #s{file = Fd}) ->
    case Fd of
        undefined -> ok;
        _ -> file:close(Fd)
    end.

io_request({put_chars, Chars}, S) ->
    put_chars(unicode, Chars, S);
io_request({put_chars, Enc, Chars}, S) ->
    put_chars(Enc, Chars, S);
io_request({put_chars, M, F, A}, S) ->
    put_mfa(unicode, M, F, A, S);
io_request({put_chars, Enc, M, F, A}, S) ->
    put_mfa(Enc, M, F, A, S);
io_request({put_chars_sync, Enc, Chars, Reply}, S) ->
    {_, S1} = put_chars(Enc, Chars, S),
    {Reply, S1};
io_request({get_chars, _, _, _}, S) -> {eof, S};
io_request({get_chars, _, _, _, _}, S) -> {eof, S};
io_request({get_line, _, _}, S) -> {eof, S};
io_request({get_line, _}, S) -> {eof, S};
io_request({get_until, _, _, _, _, _}, S) -> {eof, S};
io_request({get_until, _, _, _, _}, S) -> {eof, S};
io_request({get_geometry, _}, S) -> {{error, enotsup}, S};
io_request({setopts, _}, S) -> {ok, S};
io_request(getopts, S) -> {[{binary, false}, {encoding, unicode}], S};
io_request({requests, Requests}, S) ->
    lists:foldl(fun
        (R, {ok, S0}) -> io_request(R, S0);
        (_, Failed) -> Failed
    end, {ok, S}, Requests);
io_request(_, S) ->
    {{error, request}, S}.

put_mfa(Enc, M, F, A, S) ->
    try apply(M, F, A) of
        Chars -> put_chars(Enc, Chars, S)
    catch
        _:_ -> {{error, F}, S}
    end.

put_chars(Enc, Chars, S) ->
    try convert(Enc, Chars) of
        Bin when is_binary(Bin) -> {ok, append(Bin, S)};
        _ -> {{error, badarg}, S}
    catch
        _:_ -> {{error, badarg}, S}
    end.

convert(latin1, Chars) -> unicode:characters_to_binary(Chars, latin1, unicode);
convert(_Unicode, Chars) -> unicode:characters_to_binary(Chars, unicode, unicode).

append(Bin, #s{file = Fd, partial = Partial} = S) ->
    case Fd of
        undefined -> ok;
        _ -> file:write(Fd, Bin)
    end,
    Parts = binary:split(<<Partial/binary, Bin/binary>>, <<"\n">>, [global]),
    {Complete, [Rest]} = lists:split(length(Parts) - 1, Parts),
    lists:foldl(fun push/2, S#s{partial = Rest}, Complete).

push(Line, #s{seq = Seq, lines = Q, count = Count, max = Max} = S) ->
    Q1 = queue:in({Seq + 1, Line}, Q),
    case Count + 1 > Max of
        true -> S#s{seq = Seq + 1, lines = queue:drop(Q1), count = Count};
        false -> S#s{seq = Seq + 1, lines = Q1, count = Count + 1}
    end.
