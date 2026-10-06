-module(sort_kernel).
-export([run/0, run/1, run/2, time/2, make_list/1, bench/1, bench/2]).

make_list(reversed) ->
    lists:seq(1000, 1, -1);
make_list(sorted) ->
    lists:seq(1, 1000);
make_list(random) ->
    random_list(1000, 12345, []).

random_list(0, _, Acc) ->
    lists:reverse(Acc);
random_list(N, Seed, Acc) ->
    Next = (Seed * 1664525 + 1013904223) band 16#7fffffff,
    random_list(N - 1, Next, [Next rem 10000 | Acc]).

loop(0, _List, Acc) ->
    Acc;
loop(N, List, Acc) ->
    Sorted = lists:sort(List),
    loop(N - 1, List, erlang:phash2(Sorted) + Acc).

time(Shape, N) ->
    List = make_list(Shape),
    _ = lists:sort(List),
    T0 = erlang:monotonic_time(nanosecond),
    Sum = loop(N, List, 0),
    T1 = erlang:monotonic_time(nanosecond),
    TotalNs = T1 - T0,
    NsPerOp = TotalNs / N,
    io:format("~s: N=~p, total=~p ms, ns_per_sort=~.2f, checksum=~p~n",
              [Shape, N, TotalNs div 1000000, NsPerOp, Sum]),
    {NsPerOp, Sum}.

run() ->
    run(1000).

run(N) ->
    run(N, N).

run(NFast, NSlow) ->
    io:format("=== sort_kernel (1000 integers) ===~n", []),
    time(reversed, NFast),
    time(sorted, NFast),
    time(random, NSlow),
    ok.

bench(Shape) ->
    bench(Shape, 1).

bench(Shape, N) when is_atom(Shape) ->
    List = make_list(Shape),
    _ = lists:sort(List),
    loop(N, List, 0);
bench(ShapeStr, N) when is_list(ShapeStr) ->
    bench(list_to_existing_atom(ShapeStr), N).
