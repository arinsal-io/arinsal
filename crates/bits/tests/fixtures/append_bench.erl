-module(append_bench).
-export([run/1]).

run(N) -> run(N, <<>>).

run(0, Acc) -> Acc;
run(N, Acc) -> run(N - 1, <<Acc/binary, 42>>).
