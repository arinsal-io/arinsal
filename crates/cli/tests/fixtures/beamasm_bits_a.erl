-module(beamasm_bits_a).
-export([run/0]).
a(<<"abc", R/binary>>) -> R; a(_) -> none.
b(<<X:8, Y:16/little, R/binary>>) -> {X, Y, R}; b(_) -> none.
c(<<X:3, _:5, R/binary>>) -> {X, R}; c(_) -> none.
d(<<_/utf8, R/binary>>) -> R; d(_) -> none.
e(<<C/utf8, R/binary>>) -> {C, R}; e(_) -> none.
f(<<C/utf16, R/binary>>) -> {C, R}; f(_) -> none.
g(<<C:32/float, R/binary>>) -> {C, R}; g(_) -> none.
run() -> io:format("~p~n", [[a(<<"abcd">>), a(<<"abx">>), b(<<1,2,3,4>>), c(<<255,1>>), d(<<"é1"/utf8>>), e(<<"é1"/utf8>>), f(<<"é1"/utf16>>), g(<<1.5:32/float,9>>)]]).
