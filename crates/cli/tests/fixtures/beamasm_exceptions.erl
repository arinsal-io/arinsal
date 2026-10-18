-module(beamasm_exceptions).
-export([run/0]).

run() ->
    Results = [
        normalize(catch bif_error()),
        normalize(catch throw_error()),
        normalize(catch error_two()),
        normalize(catch error_three())
    ],
    io:format("~w", [Results]).

bif_error() -> ets:lookup(exc_perf_missing_table, key).
throw_error() -> throw(caught_throw).
error_two() -> erlang:error(error_two, [error_two_arg]).
error_three() ->
    erlang:error(error_three, [error_three_arg],
                  [{error_info, #{cause => custom_cause}}]).

normalize({'EXIT', {Reason, Stack}}) ->
    Local = [Frame || Frame = {Module, _, _, _} <- Stack,
                      Module =:= ets orelse Module =:= beamasm_exceptions],
    {'EXIT', {Reason, Local}};
normalize(Value) -> Value.
