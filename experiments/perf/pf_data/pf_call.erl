-module(pf_call).
-export([plain/1, local/1, bif/1]).

plain(N) -> plain(N, 0).
plain(0, Acc) -> Acc;
plain(N, Acc) -> plain(N - 1, Acc + N).

local(N) -> local(N, 0).
local(0, Acc) -> Acc;
local(N, Acc) ->
    Value = id(N),
    local(N - 1, Acc + Value).

id(Value) -> Value.

bif(N) -> bif(N, 0).
bif(0, Acc) -> Acc;
bif(N, Acc) ->
    Value = lists:reverse([], N),
    bif(N - 1, Acc + Value).
