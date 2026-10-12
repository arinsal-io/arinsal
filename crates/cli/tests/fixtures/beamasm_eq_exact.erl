%% Exact comparisons against literals that BeamAsm inlines (tuples and lists of immediates,
%% <<>>, #{}) and against literals it leaves to the general path (floats, bignums, nested tuples).
-module(beamasm_eq_exact).
-export([run/0]).

tuple_eq(X) -> X =:= {c, 3}.
tuple_ne(X) -> X =/= {c, 3}.
tuple_match(X) -> case X of {c, 3} -> yes; _ -> no end.
list_eq(X) -> X =:= [1, 2, 3].
list_ne(X) -> X =/= [1, 2, 3].
list_single(X) -> X =:= [c].
list_match(X) -> case X of [1, 2, 3] -> yes; _ -> no end.
bin_eq(X) -> X =:= <<>>.
bin_ne(X) -> X =/= <<>>.
map_eq(X) -> X =:= #{}.
map_ne(X) -> X =/= #{}.
int_eq(X) -> X =:= 1.
float_eq(X) -> X =:= 1.0.
big_eq(X) -> X =:= 1 bsl 70.
float_tuple_eq(X) -> X =:= {c, 1.0}.
nested_eq(X) -> X =:= {c, {d}}.
neg_zero_eq(X) -> X =:= 0.0.

run() ->
    Values = [{c, 3}, {c, 3.0}, {c, 4}, {d, 3}, {c, 3, c}, {}, {c, 3, x}, c, 3, 3.0, 1, 1.0,
              [1, 2, 3], [1, 2], [1, 2, 3, 4], [1, 2, 3.0], [c], [c, c], [], [c | d], [1 | [2, 3]],
              "\x01\x02\x03", <<>>, <<1>>, <<1:3>>, binary:part(<<1, 2>>, 0, 0), <<"ab">>,
              #{}, #{a => 1}, (1 bsl 70), -(1 bsl 70), {c, 1.0}, {c, {d}}, {c, {d}, 1}, 0.0, -0.0],
    Funs = [fun tuple_eq/1, fun tuple_ne/1, fun tuple_match/1, fun list_eq/1, fun list_ne/1,
            fun list_single/1, fun list_match/1, fun bin_eq/1, fun bin_ne/1, fun map_eq/1,
            fun map_ne/1, fun int_eq/1, fun float_eq/1, fun big_eq/1, fun float_tuple_eq/1,
            fun nested_eq/1, fun neg_zero_eq/1],
    [io:format("~w~n", [[F(V) || V <- Values]]) || F <- Funs],
    ok.
