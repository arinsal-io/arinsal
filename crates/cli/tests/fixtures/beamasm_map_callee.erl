-module(beamasm_map_callee).
-export([run/0, pattern8/1]).

run() ->
    Map = #{a => 1, b => 2, c => 3, d => 4, e => 5, f => 6, g => 7, h => 8},
    io:format("~p~n", [pattern8(Map)]).

pattern8(#{a := A, b := B, c := C, d := D, e := E, f := F, g := G, h := H}) ->
    {A, B, C, D, E, F, G, H}.
