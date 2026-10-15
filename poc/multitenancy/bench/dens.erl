-module(dens).
-export([idle/1, suspend_resume/1, boot_ready/0]).
-export([start_tenant/2, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(WORKERS, 5).

state(Entries, Seed) ->
    #{data => [{Seed + N, integer_to_binary(Seed * N)} || N <- lists:seq(1, Entries)]}.

start_tenant(Id, Restored) ->
    supervisor:start_link(?MODULE, {sup, Id, Restored}).

init({sup, Id, Restored}) ->
    Children = [#{id => W,
                  start => {gen_server, start_link, [?MODULE, {worker, Id, W, worker_state(Restored, W)}, []]}}
                || W <- lists:seq(1, ?WORKERS)],
    {ok, {#{strategy => one_for_one}, Children}};
init({worker, _Id, W, {State, Ets}}) ->
    Tab = case W of
              1 -> T = ets:new(tenant, [set, public]), ets:insert(T, Ets), T;
              _ -> undefined
          end,
    {ok, State#{tab => Tab}}.

worker_state({fresh, Entries}, W) ->
    {state(Entries, W), [{N, N * W} || N <- lists:seq(1, Entries)]};
worker_state({restored, Saved}, W) ->
    maps:get(W, Saved).

handle_call(ping, _From, S) -> {reply, pong, S};
handle_call(dump, _From, S = #{tab := Tab}) ->
    Ets = case Tab of undefined -> []; _ -> ets:tab2list(Tab) end,
    {reply, {maps:remove(tab, S), Ets}, S}.
handle_cast(_, S) -> {noreply, S}.
handle_info(hibernate, S) -> {noreply, S, hibernate};
handle_info(_, S) -> {noreply, S}.

workers(Sup) -> [P || {_, P, _, _} <- supervisor:which_children(Sup)].

start_many(N, Entries) ->
    [begin {ok, S} = start_tenant(I, {fresh, Entries}), unlink(S), S end || I <- lists:seq(1, N)].

idle([NA, HA, EA]) -> idle(list_to_integer(atom_to_list(NA)), HA =:= true, list_to_integer(atom_to_list(EA))).
idle(N, Hibernate, Entries) ->
    Sups = start_many(N, Entries),
    Hibernate andalso [W ! hibernate || S <- Sups, W <- workers(S)],
    timer:sleep(500),
    [erlang:garbage_collect(P) || P <- processes()],
    io:format("READY ~p~n", [#{tenants => N, hibernate => Hibernate, procs => erlang:system_info(process_count),
                              mem => maps:from_list(erlang:memory())}]),
    receive after infinity -> ok end.

%% Suspend: dump state, write+fsync, kill tree. Resume: read, rebuild tree, first ping answered.
suspend_resume([TA, EA, DirA]) ->
    T = list_to_integer(atom_to_list(TA)), E = list_to_integer(atom_to_list(EA)), Dir = atom_to_list(DirA),
    Sups = start_many(T, E),
    [ [W ! hibernate || W <- workers(S)] || S <- Sups],
    timer:sleep(200),
    Wake = [timed(fun() -> [pong = gen_server:call(W, ping) || W <- workers(S)] end) || S <- Sups],
    Res = [cycle(I, S, Dir) || {I, S} <- lists:zip(lists:seq(1, T), Sups)],
    {Susp, Resu, Bytes} = lists:unzip3(Res),
    io:format("RESULT ~p~n", [#{tenants => T, entries => E, bytes_p50 => pct(Bytes, 50),
                               wake_hibernated_us => stats(Wake), suspend_us => stats(Susp), resume_us => stats(Resu)}]),
    halt().

cycle(I, Sup, Dir) ->
    File = filename:join(Dir, "t" ++ integer_to_list(I)),
    {Su, Bytes} = timed2(fun() ->
        Saved = maps:from_list(lists:zip(lists:seq(1, ?WORKERS), [gen_server:call(W, dump) || W <- lists:sort(workers(Sup))])),
        Bin = term_to_binary(Saved),
        {ok, F} = file:open(File, [raw, binary, write]),
        ok = file:write(F, Bin), ok = file:datasync(F), ok = file:close(F),
        Ref = monitor(process, Sup), exit(Sup, shutdown),
        receive {'DOWN', Ref, _, _, _} -> ok end,
        byte_size(Bin) end),
    {Re, _} = timed2(fun() ->
        {ok, Bin} = file:read_file(File),
        {ok, S} = start_tenant(I, {restored, binary_to_term(Bin)}), unlink(S),
        [pong = gen_server:call(W, ping) || W <- workers(S)] end),
    {Su, Re, Bytes}.

boot_ready() -> io:format("BOOTED~n"), halt().

timed(F) -> {T, _} = timer:tc(F), T.
timed2(F) -> timer:tc(F).
pct(L, P) -> S = lists:sort(L), lists:nth(max(1, round(length(S) * P / 100)), S).
stats(L) -> #{p50 => pct(L, 50), p99 => pct(L, 99), max => lists:max(L)}.
