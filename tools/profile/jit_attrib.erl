-module(jit_attrib).
-export([enum_n/1, map_n/1]).

%% Repeated demo calls for JIT time attribution. The tail loop is small next
%% to Enum.map/filter/reduce and Map.put; stats still include it.

enum_n(N) -> enum_n(N, 0).

enum_n(0, Acc) -> Acc;
enum_n(N, _Acc) ->
    enum_n(N - 1, 'Elixir.ArinsalDemo.Pure':enum_pipeline(1000)).

map_n(N) -> map_n(N, 0).

map_n(0, Acc) -> Acc;
map_n(N, _Acc) ->
    map_n(N - 1, 'Elixir.ArinsalDemo.Maps':put_n(1000)).
