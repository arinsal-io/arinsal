-module(beamasm_bits_b).
-export([run/0]).
a(<<"hello world", R/binary>>) -> R; a(_) -> none.
b(N, Bin) -> case Bin of <<_:N, R/binary>> -> R; _ -> none end.
c(N, Bin) -> case Bin of <<X:N/binary, R/binary>> -> {X, R}; _ -> none end.
d(N, Bin) -> case Bin of <<X:N, R/binary>> -> {X, R}; _ -> none end.
e(N, Bin) -> case Bin of <<X:N/signed-little, R/binary>> -> {X, R}; _ -> none end.
f(<<X:3, R/bitstring>>) -> {X, R}; f(_) -> none.
g(<<A, B>>) -> {A, B}; g(<<A>>) -> A; g(_) -> none.
h(<<>>) -> empty; h(<<_, R/binary>>) -> h(R).
i(<<X:100, R/binary>>) -> {X, R}; i(_) -> none.
j(<<X:32/signed, Y:16/little-signed, R/binary>>) -> {X, Y, R}; j(_) -> none.
k(<<X:8/unit:2, R/binary>>) -> {X, R}; k(_) -> none.
l(<<255, 254, R/binary>>) -> R; l(<<1:1, 0:1, R/bitstring>>) -> R; l(_) -> none.
run() ->
    B = <<"hello world!!">>,
    R = [a(B), a(<<"hello">>), b(8, B), b(200, B), c(5, B), c(50, B), d(16, B), d(100, B), d(0, B),
         e(24, <<255,255,255,9>>), e(70, <<1,2,3,4,5,6,7,8,9,10,11>>), f(<<255, 1>>), f(<<>>),
         g(<<1,2>>), g(<<1>>), g(<<1,2,3>>), h(<<1,2,3>>),
         i(<<1:100, 7>>), i(<<1,2>>), j(<<255,255,255,254,1,2,3>>), k(<<1,2,3>>),
         l(<<255,254,9>>), l(<<2#10:2, 5:6>>), l(<<0>>)],
    io:format("~p~n", [R]).
