-module(beamasm_ops).
-export([run/0]).
-compile([nowarn_unused_function, nowarn_export_all]).
-define(V(E), v(fun() -> E end)).

%% Arithmetic in guards must fall through instead of raising.
g1(X) when X + 1 > 5 -> a; g1(_) -> b.
g2(X, Y) when X rem Y =:= 0 -> a; g2(_, _) -> b.
g3(X, Y) when X div Y =:= 2 -> a; g3(_, _) -> b.
g4(X, Y) when X band Y =:= 1 -> a; g4(_, _) -> b.
g5(X) when -X > 1 -> a; g5(_) -> b.
g6(X, Y) when X bsl Y > 1 -> a; g6(_, _) -> b.
g7(X) when bnot X > 1 -> a; g7(_) -> b.
g8(X, Y) when X * Y > 1 -> a; g8(_, _) -> b.
g9(X, Y) when X - Y > 1 -> a; g9(_, _) -> b.

%% Float conversion of integers, bignums included, and float errors.
f1(X, Y) when is_integer(X), is_integer(Y) -> X / Y.
f2(X, Y) -> X / Y.
f3(X, Y) -> X * Y * 1.0e300.

%% Fused div/rem.
r1(X, Y) -> R = X rem Y, Q = X div Y, {R, Q}.
r2(X, Y) -> Q = X div Y, R = X rem Y, {Q, R}.

%% Bit syntax.
b1(<<_/utf8, R/binary>>) -> R; b1(_) -> none.
b2(<<_/utf16, R/binary>>) -> R; b2(_) -> none.
b3(<<C/utf32, R/binary>>) -> {C, R}; b3(_) -> none.
b4(<<F:32/float, R/binary>>) -> {F, R}; b4(_) -> none.
b5(<<F:64/float-little, R/binary>>) -> {F, R}; b5(_) -> none.
b6(<<F:64/float-native, R/binary>>) -> {F, R}; b6(_) -> none.

%% Dense integer selection (jump table with a negative base) and record-like tuples.
s1(X) ->
    case X of
        -1 -> m1; 0 -> z; 1 -> p1; 2 -> p2; 3 -> p3; 4 -> p4;
        5 -> p5; 6 -> p6; 7 -> p7; 8 -> p8; 9 -> p9; _ -> other
    end.
t1({ok, V}) -> {ok, V};
t1({error, R}) -> {err, R};
t1(T) when is_tuple(T) -> tuple;
t1(_) -> other.
t2({a, B}) -> B; t2({a, B, C}) -> {B, C}; t2(_) -> none.

%% Funs with more than six arguments and free variables.
h1(A, B, C, D, E, F, G, H) ->
    Fun = fun(P, Q, R, S, T, U, V) -> {A, H, P + Q + R + S + T + U + V} end,
    Fun(B, C, D, E, F, G, 1).
h2(A, B, C, D, E, F, G, H) ->
    Get = fun() -> {A, B, C, D, E, F, G, H} end,
    Get().
h3(A, B, C, D, E, F, G, H, I) ->
    put(k, {A, B}),
    {get(k), erlang:node(), is_tuple(H) andalso I >= 1, length([A, B, C, D, E, F, G])}.

run() ->
    A = id(foo), Z = id(0), Big = id(1 bsl 70),
    out(g1, [g1(A), g1(9), g1(1)]),
    out(g2, [g2(A, 2), g2(4, Z), g2(4, 2)]),
    out(g3, [g3(A, 1), g3(4, Z), g3(4, 2)]),
    out(g4, [g4(A, 1), g4(3, A), g4(3, 1)]),
    out(g5, [g5(A), g5(-5)]),
    out(g6, [g6(A, 1), g6(1, A), g6(1, 5), g6(1, 100000000000000000000000000)]),
    out(g7, [g7(A), g7(-5)]),
    out(g8, [g8(A, 2), g8(2, A), g8(2, 3)]),
    out(g9, [g9(A, 1), g9(5, 1), g9(1.5, 1)]),
    out(f1, [?V(f1(5, 2)), ?V(f1(-7, 2)), ?V(f1(Big, 3)), ?V(f1(3, Big)), ?V(f1(-Big, 3)),
             ?V(f1(1 bsl 1030, 1)), ?V(f1(1, 0))]),
    out(f2, [?V(f2(A, 1)), ?V(f2(1, A)), ?V(f2(1.5, 0)), ?V(f2(1.0e300, 1.0e-300))]),
    out(f3, [?V(f3(1.0e10, 1.0e10)), ?V(f3(2, 3))]),
    [out(r, [?V(r1(X, Y)), ?V(r2(X, Y))]) || {X, Y} <- [{7, 2}, {-7, 2}, {7, -2}, {Big, 3}, {5, Z}, {A, 1}]],
    out(b1, [b1(<<"héé"/utf8, 1>>), b1(<<255, 1>>), b1(<<>>)]),
    out(b2, [b2(<<"hé"/utf16, 1>>), b2(<<0, 216>>), b2(<<>>)]),
    out(b3, [b3(<<"é"/utf32, 1>>), b3(<<16#110000:32>>), b3(<<16#D800:32>>), b3(<<>>)]),
    out(b4, [b4(<<1.5:32/float, 7>>), b4(<<1>>)]),
    out(b5, [b5(<<1.5:64/float-little, 7>>), b6(<<2.5:64/float-native>>)]),
    out(s1, [s1(X) || X <- [-2, -1, 0, 1, 5, 9, 10, foo]]),
    out(t, [t1({ok, 1}), t1({error, 2}), t1({x}), t1(a), t2({a, 1}), t2({a, 1, 2}), t2({b, 1})]),
    out(h, [h1(1, 2, 3, 4, 5, 6, 7, 8), h2(1, 2, 3, 4, 5, 6, 7, 8), h3(1, 2, 3, 4, 5, 6, 7, {}, 9)]),
    erlang:yield(),
    out(perf, [is_integer(os:perf_counter())]).

v(F) -> try F() catch C:R -> {C, R} end.
out(Tag, L) -> io:format("~p ~p~n", [Tag, L]).
id(X) -> X.
