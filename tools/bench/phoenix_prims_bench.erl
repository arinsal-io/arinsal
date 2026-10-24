%% Focused per-operation benchmark for the Phoenix usage report.
-module(phoenix_prims_bench).
-export([run/2, run_fast/2, run_one/3, run_profile/3, sample_n/4]).

-define(N, 1000000).

run(Runtime, Round) ->
    setup(),
    Rows = [sample(Runtime, Round, Op) || Op <- operations()],
    ets:delete(phoenix_prims_bench_table),
    persistent_term:erase(phoenix_prims_bench_key),
    Rows.

run_fast(Runtime, Round) ->
    setup(),
    Rows = [sample_n(Runtime, Round, Op, 10000000)
            || Op <- [lists_member, persistent_get, atom_to_binary, integer_to_binary]],
    ets:delete(phoenix_prims_bench_table),
    persistent_term:erase(phoenix_prims_bench_key),
    Rows.

run_one(Runtime, Round, Op) ->
    setup(),
    sample(Runtime, Round, Op),
    ets:delete(phoenix_prims_bench_table),
    persistent_term:erase(phoenix_prims_bench_key),
    ok.

run_profile(Runtime, Round, Op) ->
    setup(),
    Row = sample_n(Runtime, Round, Op, 100000000),
    receive after 5000 -> ok end,
    ets:delete(phoenix_prims_bench_table),
    persistent_term:erase(phoenix_prims_bench_key),
    Row.

operations() ->
    [append, maps_remove, maps_merge, lists_keyfind, lists_reverse,
     tuple_to_list, maps_from_list, maps_from_keys, maps_keys, maps_take,
     list_to_tuple, lists_member, lists_keymember, maps_put, ets_lookup,
     persistent_get, phash2, atom_to_binary, iolist_to_binary,
     integer_to_binary, monotonic_time, universaltime_to_localtime,
     binary_match, binary_split, unicode_characters_to_binary, send_receive,
     string_downcase, enum_map, enum_reduce, keyword_get].

sample(Runtime, Round, Op) ->
    sample_n(Runtime, Round, Op, ?N).

sample_n(Runtime, Round, Op, N) ->
    Input = input(Op),
    warmup(Op, erlang:min(N, 1000), Input),
    {Empty, Work} = case (op_index(Op) + Round) rem 2 of
        0 ->
            E = timed(fun() -> empty(N) end),
            W = timed(fun() -> work(Op, N, Input) end),
            {E, W};
        1 ->
            W = timed(fun() -> work(Op, N, Input) end),
            E = timed(fun() -> empty(N) end),
            {E, W}
    end,
    {Runtime, Round, Op, N, Empty, Work}.

timed(F) ->
    Start = erlang:monotonic_time(nanosecond),
    F(),
    erlang:monotonic_time(nanosecond) - Start.

warmup(Op, N, Input) ->
    empty(N),
    work(Op, N, Input).

empty(0) -> ok;
empty(N) -> empty(N - 1).

work(_Op, 0, _Input) -> ok;
work(Op, N, Input) ->
    _ = operation(Op, Input),
    work(Op, N - 1, Input).

input(append) -> {[a, b, c, d, e], [f, g, h]};
input(maps_remove) -> map20();
input(maps_merge) -> {map20(), map_right()};
input(lists_keyfind) -> keywords();
input(lists_reverse) -> {keywords(), [{tail, true}]};
input(tuple_to_list) -> tuple10();
input(maps_from_list) -> keywords();
input(maps_from_keys) -> atom_keys();
input(maps_keys) -> map20();
input(maps_take) -> map20();
input(list_to_tuple) -> keywords();
input(lists_member) -> atom_keys();
input(lists_keymember) -> keywords();
input(maps_put) -> map20();
input(ets_lookup) -> undefined;
input(persistent_get) -> undefined;
input(phash2) -> map20();
input(atom_to_binary) -> undefined;
input(iolist_to_binary) -> [<<"content-">>, [<<"type">>, $:, <<" application/json">>]];
input(integer_to_binary) -> undefined;
input(monotonic_time) -> undefined;
input(universaltime_to_localtime) -> {{2026, 10, 23}, {12, 34, 56}};
input(binary_match) -> header();
input(binary_split) -> header();
input(unicode_characters_to_binary) -> header();
input(send_receive) -> undefined;
input(string_downcase) -> header();
input(enum_map) -> {list10(), fun(X) -> X + 1 end};
input(enum_reduce) -> {list10(), fun(X, Acc) -> X + Acc end};
input(keyword_get) -> keywords().

operation(append, {Left, Right}) -> Left ++ Right;
operation(maps_remove, Map) -> maps:remove(content_type, Map);
operation(maps_merge, {Left, Right}) -> maps:merge(Left, Right);
operation(lists_keyfind, Keywords) -> lists:keyfind(content_type, 1, Keywords);
operation(lists_reverse, {Keywords, Tail}) -> lists:reverse(Keywords, Tail);
operation(tuple_to_list, Tuple) -> erlang:tuple_to_list(Tuple);
operation(maps_from_list, Keywords) -> maps:from_list(Keywords);
operation(maps_from_keys, Keys) -> maps:from_keys(Keys, <<>>);
operation(maps_keys, Map) -> maps:keys(Map);
operation(maps_take, Map) -> maps:take(content_type, Map);
operation(list_to_tuple, Keywords) -> erlang:list_to_tuple(Keywords);
operation(lists_member, Keys) -> lists:member(content_type, Keys);
operation(lists_keymember, Keywords) -> lists:keymember(content_type, 1, Keywords);
operation(maps_put, Map) -> maps:put(content_type, <<"application/json">>, Map);
operation(ets_lookup, _Input) -> ets:lookup(phoenix_prims_bench_table, content_type);
operation(persistent_get, _Input) -> persistent_term:get(phoenix_prims_bench_key, undefined);
operation(phash2, Map) -> erlang:phash2(Map);
operation(atom_to_binary, _Input) -> erlang:atom_to_binary(content_type, utf8);
operation(iolist_to_binary, Iolist) -> erlang:iolist_to_binary(Iolist);
operation(integer_to_binary, _Input) -> erlang:integer_to_binary(123456789);
operation(monotonic_time, _Input) -> erlang:monotonic_time();
operation(universaltime_to_localtime, Time) -> erlang:universaltime_to_localtime(Time);
operation(binary_match, Binary) -> binary:match(Binary, <<"request-id">>);
operation(binary_split, Binary) -> binary:split(Binary, <<": ">>, [global]);
operation(unicode_characters_to_binary, Binary) -> unicode:characters_to_binary(Binary, utf8);
operation(send_receive, _Input) ->
    self() ! {phoenix_bench, ok},
    receive {phoenix_bench, Value} -> Value end;
operation(string_downcase, Binary) -> apply('Elixir.String', downcase, [Binary]);
operation(enum_map, {List, Fun}) -> apply('Elixir.Enum', map, [List, Fun]);
operation(enum_reduce, {List, Fun}) -> apply('Elixir.Enum', reduce, [List, 0, Fun]);
operation(keyword_get, Keywords) -> apply('Elixir.Keyword', get, [Keywords, content_type, undefined]).

setup() ->
    Tab = ets:new(phoenix_prims_bench_table,
                  [named_table, set, public, {read_concurrency, true}]),
    true = ets:insert(Tab, {content_type, <<"application/json">>}),
    persistent_term:put(phoenix_prims_bench_key, {ok, <<"application/json">>}),
    ok.

map20() -> maps:from_list([{K, V} || {K, V} <- keywords()] ++
                           [{content_length, 42}, {accept, <<"*/*">>},
                            {x_request_id, <<"abc123">>}, {host, <<"localhost">>},
                            {connection, keep_alive}, {cache_control, no_cache},
                            {user_agent, <<"phoenix-test">>}, {origin, <<"localhost">>},
                            {referer, <<"/">>}, {x_forwarded_for, <<"127.0.0.1">>}]).
map_right() -> #{content_type => <<"text/html">>, x_request_id => <<"xyz789">>}.
keywords() -> [{method, get}, {path, <<"/api">>}, {host, <<"localhost">>},
               {content_type, <<"application/json">>}, {accept, <<"*/*">>},
               {content_length, 42}, {connection, keep_alive},
               {user_agent, <<"phoenix-test">>}, {x_request_id, <<"abc123">>},
               {x_forwarded_for, <<"127.0.0.1">>}].
atom_keys() -> [method, path, host, content_type, accept, content_length,
                connection, user_agent, x_request_id, x_forwarded_for].
tuple10() -> {method, path, host, content_type, accept, content_length,
              connection, user_agent, x_request_id, x_forwarded_for}.
list10() -> [1,2,3,4,5,6,7,8,9,10].
header() -> <<"X-Request-Id: abc123          ">>.

op_index(append) -> 1;
op_index(maps_remove) -> 2;
op_index(maps_merge) -> 3;
op_index(lists_keyfind) -> 4;
op_index(lists_reverse) -> 5;
op_index(tuple_to_list) -> 6;
op_index(maps_from_list) -> 7;
op_index(maps_from_keys) -> 8;
op_index(maps_keys) -> 9;
op_index(maps_take) -> 10;
op_index(list_to_tuple) -> 11;
op_index(lists_member) -> 12;
op_index(lists_keymember) -> 13;
op_index(maps_put) -> 14;
op_index(ets_lookup) -> 15;
op_index(persistent_get) -> 16;
op_index(phash2) -> 17;
op_index(atom_to_binary) -> 18;
op_index(iolist_to_binary) -> 19;
op_index(integer_to_binary) -> 20;
op_index(monotonic_time) -> 21;
op_index(universaltime_to_localtime) -> 22;
op_index(binary_match) -> 23;
op_index(binary_split) -> 24;
op_index(unicode_characters_to_binary) -> 25;
op_index(send_receive) -> 26;
op_index(string_downcase) -> 27;
op_index(enum_map) -> 28;
op_index(enum_reduce) -> 29;
op_index(keyword_get) -> 30.
