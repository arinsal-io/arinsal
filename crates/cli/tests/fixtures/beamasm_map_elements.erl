-module(beamasm_map_elements).
-export([run/0, pattern1/1, pattern3/1, pattern8/1]).

run() ->
    M8 = #{a => 1, b => 2, c => 3, d => 4, e => 5, f => 6, g => 7, h => 8},
    M100 = maps:from_list(
        [{a, 1}, {b, 2}, {c, 3}, {d, 4}, {e, 5}, {f, 6}, {g, 7}, {h, 8} |
         [{I, I} || I <- lists:seq(1, 92)]]),
    M10000 = maps:from_list(
        [{a, 1}, {b, 2}, {c, 3}, {d, 4}, {e, 5}, {f, 6}, {g, 7}, {h, 8} |
         [{I, I} || I <- lists:seq(1, 9992)]]),
    CrossModule = beamasm_map_callee:pattern8(M100),
    io:format("~p~n", [{pattern1(M8), pattern1(M100), pattern1(M10000),
                       pattern3(M8), pattern3(M100), pattern3(M10000),
                       pattern8(M8), pattern8(M100), pattern8(M10000),
                       maps:get(a, M8#{a => 100}), maps:get(z, M8#{z => 100}),
                       maps:get(a, M100#{a => 100}), maps:get(z, M100#{z => 100}),
                       maps:get(a, M8#{a := 100}), maps:get(a, M100#{a := 100}),
                       try M8#{z := 100} catch error:{badkey, _} -> badkey end,
                       try M100#{z := 100} catch error:{badkey, _} -> badkey end,
                       is_map_key(a, M8), is_map_key(a, M100),
                       has_fields(M8), has_fields(M100),
                       map_size(M8), map_size(M100), map_size(M10000), CrossModule}]).

pattern1(#{a := A}) -> A.
pattern3(#{a := A, b := B, c := C}) -> {A, B, C}.
pattern8(#{a := A, b := B, c := C, d := D, e := E, f := F, g := G, h := H}) ->
    {A, B, C, D, E, F, G, H}.
has_fields(#{a := _, b := _, c := _}) -> true;
has_fields(_) -> false.
