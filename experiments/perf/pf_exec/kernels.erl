-module(kernels).
-export([tail/1, list/1, fib/1, tuple/1, binary/1]).

tail(N) -> tail_loop(N, 0).
tail_loop(0, Sum) -> Sum;
tail_loop(N, Sum) -> tail_loop(N - 1, Sum + 1).

list(N) ->
    lists:foldl(fun(X, Sum) -> X + Sum end,
                0,
                lists:map(fun(X) -> X + 1 end, lists:seq(1, N))).

fib(N) when N < 2 -> N;
fib(N) -> fib(N - 1) + fib(N - 2).

tuple(N) -> tuple_loop(N, {0, 0, 0}, 0).
tuple_loop(0, _Tuple, Sum) -> Sum;
tuple_loop(N, Tuple, Sum) ->
    Next = setelement(2, Tuple, N),
    tuple_loop(N - 1, Next, Sum + element(2, Next)).

binary(N) ->
    Data = binary:copy(<<1, 2, 3, 4>>, N),
    binary_loop(Data, 0).
binary_loop(<<>>, Sum) -> Sum;
binary_loop(<<2, Rest/binary>>, Sum) -> binary_loop(Rest, Sum + 1);
binary_loop(<<_, Rest/binary>>, Sum) -> binary_loop(Rest, Sum).
