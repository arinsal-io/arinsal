-module(beamasm_caught_bif_error).
-export([run/0, run/2]).

run() ->
    try run(left, right)
    catch error:badarg:Stack -> top(Stack)
    end.

run(Tab, Pat) ->
    _ = try ets:match_spec_compile(Pat)
        catch error:_ -> caught
        end,
    erlang:error(badarg, [Tab, Pat]).

top(Stack) ->
    {Module, Function, Args, _} = hd(Stack),
    Arity = if is_list(Args) -> length(Args); true -> Args end,
    Result = {Module, Function, Arity},
    io:format("~tp~n", [Result]),
    Result.
