%% Test-harness carrier of Vm::eval_scheduled / spawn_entry: the host evaluates
%% M:F(Args) in an ordinary process of the booted node and gets the result as
%% external term format over a {fd,R,W} port, as arinsal_difftest::RefErl talks
%% to a real erl node. Started by init's `-run arinsal_eval_carrier start R W`.
-module(arinsal_eval_carrier).
-export([start/1, eval/4]).

%% A request is `{Id, Module, Function, ArgsExt}`: the arguments are decoded on their own, so
%% arguments binary_to_term rejects (as erts' dec_term does, e.g. a non-finite float) are
%% reported as that badarg instead of taking the carrier down.

start([R, W]) ->
    Fds = {list_to_integer(R), list_to_integer(W)},
    _ = spawn(fun() -> init(Fds) end),
    ok.

init({R, W}) ->
    Port = open_port({fd, R, W}, [binary, {packet, 4}]),
    loop(Port, #{}).

loop(Port, Pending) ->
    receive
        {Port, {data, Request}} ->
            {Id, M, F, ArgsExt} = binary_to_term(Request),
            try binary_to_term(ArgsExt) of
                Args ->
                    {_, Ref} = spawn_monitor(?MODULE, eval, [self(), M, F, Args]),
                    loop(Port, Pending#{Ref => Id})
            catch
                error:badarg:Stack ->
                    true = port_command(Port, term_to_binary({Id, {error, badarg, Stack}})),
                    loop(Port, Pending)
            end;
        {'DOWN', Ref, process, Pid, Reason} when is_map_key(Ref, Pending) ->
            {Id, Rest} = maps:take(Ref, Pending),
            Result =
                receive
                    {eval_result, Pid, Done} -> Done
                after 0 -> {exit, Reason, []}
                end,
            true = port_command(Port, term_to_binary({Id, Result})),
            loop(Port, Rest)
    end.

eval(Carrier, M, F, Args) ->
    Result =
        try apply(M, F, Args) of
            Value ->
                [{total_heap_size, Heap}, {garbage_collection, Gc}] =
                    process_info(self(), [total_heap_size, garbage_collection]),
                {ok, Value, Heap, proplists:get_value(minor_gcs, Gc, 0)}
        catch
            Class:Reason:Stack -> {Class, Reason, own_frames(Stack)}
        end,
    Carrier ! {eval_result, self(), Result},
    ok.

%% The frames of the evaluated call, without this module's frame under them.
own_frames(Stack) ->
    lists:reverse(lists:dropwhile(fun({?MODULE, _, _, _}) -> true; (_) -> false end,
                                  lists:reverse(Stack))).
