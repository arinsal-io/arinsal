-module(beamasm_exceptions).
-export([run/0]).

run() ->
    Results = [
        normalize(catch bif_error()),
        normalize(catch throw_error()),
        normalize(catch error_two()),
        normalize(catch error_three()),
        normalize_path(caught_arithmetic()),
        normalize_path(caught_list_to_integer())
    ],
    erlang:display(Results).

bif_error() -> ets:lookup(exc_perf_missing_table, key).
throw_error() -> throw(caught_throw).
error_two() -> erlang:error(error_two, [error_two_arg]).
error_three() ->
    erlang:error(error_three, [error_three_arg],
                  [{error_info, #{cause => custom_cause}}]).

caught_arithmetic() ->
    try 1 + a
    catch error:Reason:Stack -> {Reason, Stack}
    end.

caught_list_to_integer() ->
    try list_to_integer(<<"x">>)
    catch error:Reason:Stack -> {Reason, Stack}
    end.

normalize_path({Reason, Stack}) ->
    Local = [Frame || Frame = {Module, _, _, _} <- Stack,
                      Module =:= erlang orelse Module =:= beamasm_exceptions],
    {Reason, [normalize_path_frame(Frame) || Frame <- Local]}.

normalize_path_frame({erlang, Function, Args, Info}) ->
    ErrorInfo = [Entry || Entry = {error_info, _} <- Info],
    {erlang, Function, Args, ErrorInfo};
normalize_path_frame(Frame) -> Frame.

normalize({'EXIT', {Reason, Stack}}) ->
    Local = [Frame || Frame = {Module, _, _, _} <- Stack,
                      Module =:= ets orelse Module =:= beamasm_exceptions],
    {'EXIT', {Reason, Local}};
normalize(Value) -> Value.
