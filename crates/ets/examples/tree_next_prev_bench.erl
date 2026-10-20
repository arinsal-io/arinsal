-module(tree_next_prev_bench).
-export([run/0]).

-define(SAMPLES, 5).
-define(TARGET_CALLS, 1000000).

run() ->
    lists:foreach(
      fun(Size) ->
          lists:foreach(
            fun({Name, WriteConcurrency}) ->
                Table = ets:new(tree_next_prev_bench,
                                [ordered_set, {write_concurrency, WriteConcurrency}]),
                true = ets:insert(Table, [{I, I} || I <- lists:seq(0, Size - 1)]),
                Repetitions = max(1, ?TARGET_CALLS div Size),
                lists:foreach(
                  fun({DirectionName, Direction}) ->
                      Samples = [measure(Table, Size, Repetitions, Direction)
                                 || _ <- lists:seq(1, ?SAMPLES)],
                      Sorted = lists:sort(Samples),
                      Median = lists:nth((?SAMPLES + 1) div 2, Sorted),
                      io:format("~s ~s ~B keys: ~.2f ns/call (min ~.2f, max ~.2f)~n",
                                [Name, DirectionName, Size, Median,
                                 hd(Sorted), lists:last(Sorted)])
                  end,
                  [{"next", next}, {"prev", prev}]),
                true = ets:delete(Table)
            end,
            [{"plain", false}, {"write_concurrency", true}])
      end,
      [1000, 100000]).

measure(Table, Size, Repetitions, Walk) ->
    Started = erlang:monotonic_time(nanosecond),
    Calls = lists:sum([walk(Table, edge(Table, Walk), Walk, 0)
                       || _ <- lists:seq(1, Repetitions)]),
    Elapsed = erlang:monotonic_time(nanosecond) - Started,
    true = (Calls =:= Size * Repetitions),
    Elapsed / Calls - empty_loop_time(Calls).

empty_loop_time(Calls) ->
    Started = erlang:monotonic_time(nanosecond),
    empty_loop(Calls),
    Elapsed = erlang:monotonic_time(nanosecond) - Started,
    Elapsed / Calls.

empty_loop(0) -> ok;
empty_loop(Calls) -> empty_loop(Calls - 1).

edge(Table, next) -> ets:first(Table);
edge(Table, prev) -> ets:last(Table).

walk(_Table, '$end_of_table', _Direction, Calls) -> Calls;
walk(Table, Key, next, Calls) -> walk(Table, ets:next(Table, Key), next, Calls + 1);
walk(Table, Key, prev, Calls) -> walk(Table, ets:prev(Table, Key), prev, Calls + 1).
