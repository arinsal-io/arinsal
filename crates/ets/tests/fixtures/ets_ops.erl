-module(ets_ops).
-export([run/2, run_ordered/2, run_sequences/2, run_select/1, run_slots/1, run_counters/1, run_big_counters/0, run_big_counter_operands/0, run_element_default/0, run_lookup_element/1, run_count_delete/0, run_count_simple/1, run_continuation_slot/0, run_map_specs/2, run_replace/0, run_match/0, run_hash_traversal/2, run_hash_history/2, run_shrink/0, run_info/1, run_fixed_info/0, run_mutating_chunks/2, run_fixed/0, run_specs/1]).

run_map_specs(Object, Spec) ->
    ets:match_spec_run([Object], ets:match_spec_compile(Spec)).

run_continuation_slot() ->
    Table = ets:new(continuation_slot, [bag]),
    ets:insert(Table, [{1, I} || I <- lists:seq(1, 5)]),
    {_, Continuation} = ets:select(Table, [{{'$1', '$2'}, [], ['$_']}], 2),
    element(2, Continuation).

run_count_simple(Type) ->
    Table = ets:new(count_simple, [Type]),
    ets:insert(Table, [{I, I} || I <- lists:seq(1, 100)]),
    ets:select_count(Table, [{{'$1', '_'}, [{'>', '$1', 50}], [true]}]).

run_big_counter_operands() ->
    Table = ets:new(big_operands, [set]),
    Big = 1 bsl 80,
    First = ets:update_counter(Table, wanted, {2, Big}, {other, 0}),
    Second = ets:update_counter(Table, wanted, {2, -Big}),
    {First, Second, ets:lookup(Table, wanted), ets:lookup(Table, other)}.

run_mutating_chunks(Type, Fixed) ->
    Table = ets:new(mutating_chunks, [Type]),
    ets:insert(Table, [{I, I} || I <- lists:seq(1, 50)]),
    ets:safe_fixtable(Table, Fixed),
    Spec = [{{'$1', '$2'}, [], ['$_']}],
    First = ets:select(Table, Spec, 5),
    ets:delete(Table, 10),
    ets:insert(Table, {100, 100}),
    Pages = collect_chunks(First, []),
    ets:safe_fixtable(Table, false),
    Pages.

run_element_default() ->
    Table = ets:new(element_default, [set]),
    A = ets:update_element(Table, wanted, {2, 9}, {other, 0}),
    B = ets:update_element(Table, wanted, [{2, 11}], {other, 0}),
    {A, B, ets:lookup(Table, wanted), ets:lookup(Table, other)}.

run_lookup_element(Type) ->
    Table = ets:new(lookup_element, [Type]),
    ets:insert(Table, [{key, first}, {key, second}]),
    ets:lookup_element(Table, key, 2).

run_info(Type) ->
    Table = ets:new(info_probe, [Type]),
    [{Key, ets:info(Table, Key)} || Key <-
        [name, type, keypos, protection, heir, size, node, named_table,
         read_concurrency, write_concurrency, decentralized_counters,
         compressed, fixed, safe_fixed, safe_fixed_monotonic_time, stats]].

run_fixed_info() ->
    Table = ets:new(info_fixed, [set]),
    ets:safe_fixtable(Table, true),
    A = ets:info(Table, safe_fixed),
    M = ets:info(Table, safe_fixed_monotonic_time),
    ets:safe_fixtable(Table, true),
    B = ets:info(Table, safe_fixed),
    ets:safe_fixtable(Table, false),
    C = ets:info(Table, safe_fixed),
    ets:safe_fixtable(Table, false),
    {A, M, B, C, ets:info(Table, safe_fixed)}.

run_shrink() ->
    Table = ets:new(shrink, [set]),
    ets:insert(Table, [{I, I} || I <- lists:seq(1, 5000)]),
    lists:foreach(fun(I) -> ets:delete(Table, I) end, lists:seq(1, 4500)),
    {slots(Table, 0, []), ets:tab2list(Table)}.

run_big_counters() ->
    Table = ets:new(big_counters, [set]),
    ets:insert(Table, {k, 1 bsl 80}),
    First = ets:update_counter(Table, k, {2, 5}),
    Second = ets:update_counter(Table, k, [{2, -10}, {2, 1, 0, 7}]),
    {First, Second, ets:lookup(Table, k)}.

run_sequences(Type, Sequences) -> [run(Type, Operations) || Operations <- Sequences].

run_hash_history(Type, Objects) ->
    Table = ets:new(ets_hash_history, [Type]),
    lists:foreach(fun(Object) -> ets:insert(Table, Object) end, Objects),
    {walk_hash(Table, ets:first(Table), []), slots(Table, 0, []),
     ets:tab2list(Table), [ets:lookup(Table, K) || K <- lists:seq(1, 20)]}.

run_specs(Specs) ->
    [case catch ets:match_spec_compile(Spec) of
        Program when is_reference(Program) -> ets:match_spec_run([{1}], Program);
        _ -> badarg
    end || Spec <- Specs].

run_fixed() ->
    Table = ets:new(ets_fixed, [set]),
    ets:insert(Table, [{I, I} || I <- lists:seq(1, 255)]),
    ets:safe_fixtable(Table, true),
    First = ets:first(Table),
    ets:delete(Table, First),
    Next = ets:next(Table, First),
    Slot = ets:slot(Table, 0),
    ets:safe_fixtable(Table, false),
    {First, Next, Slot}.

run_hash_traversal(Type, Count) ->
    Table = ets:new(ets_hash_traversal, [Type]),
    ets:insert(Table, [{I, I} || I <- lists:seq(1, Count)]),
    First = ets:first(Table),
    Walk = walk_hash(Table, First, []),
    {First, Walk, slots(Table, 0, []), ets:tab2list(Table)}.

slots(Table, Index, Acc) ->
    case ets:slot(Table, Index) of
        '$end_of_table' -> lists:reverse(['$end_of_table' | Acc]);
        Objects -> slots(Table, Index + 1, [Objects | Acc])
    end.

walk_hash(_Table, '$end_of_table', Acc) -> lists:reverse(Acc);
walk_hash(Table, Key, Acc) -> walk_hash(Table, ets:next(Table, Key), [Key | Acc]).

run(Type, Ops) ->
    run_with_options([Type], Ops).

run_ordered(WriteConcurrency, Ops) ->
    run_with_options([ordered_set, {write_concurrency, WriteConcurrency}], Ops).

run_with_options(Options, Ops) ->
    Table = ets:new(ets_ops, Options),
    lists:map(fun(Op) -> Result = apply_op(Table, Op),
                         {Result, ets:info(Table, size)} end, Ops).

apply_op(Table, {insert, Object}) -> ets:insert(Table, Object);
apply_op(Table, {insert_new, Object}) -> ets:insert_new(Table, Object);
apply_op(Table, {insert_new_list, Objects}) -> ets:insert_new(Table, Objects);
apply_op(Table, {lookup, Key}) -> ets:lookup(Table, Key);
apply_op(Table, {member, Key}) -> ets:member(Table, Key);
apply_op(Table, {delete, Key}) -> ets:delete(Table, Key);
apply_op(Table, {first, _}) -> ets:first(Table);
apply_op(Table, {delete_object, Object}) -> ets:delete_object(Table, Object);
apply_op(Table, {take, Key}) -> ets:take(Table, Key);
apply_op(Table, {slot, Index}) -> safe(fun() -> ets:slot(Table, Index) end);
apply_op(Table, {info_size, _}) -> ets:info(Table, size);
apply_op(Table, {first, _}) -> ets:first(Table);
apply_op(Table, {next, Key}) -> safe(fun() -> ets:next(Table, Key) end);
apply_op(Table, {prev, Key}) -> safe(fun() -> ets:prev(Table, Key) end);
apply_op(Table, {info_size, _}) -> ets:info(Table, size);
apply_op(Table, {info_fixed, _}) -> ets:info(Table, fixed);
apply_op(Table, {match, Pattern}) -> ets:match(Table, Pattern);
apply_op(Table, {select_chunks, Spec}) ->
    collect_chunks(ets:select(Table, Spec, 2), []);
apply_op(Table, {select, Spec}) -> safe(fun() -> ets:select(Table, Spec) end);
apply_op(Table, {counter, Key}) ->
    safe(fun() -> ets:update_counter(Table, Key, 1, {Key, 0}) end);
apply_op(Table, {counter_threshold, Key}) ->
    safe(fun() -> ets:update_counter(Table, Key, {2, -1, -10, 0}, {Key, 0}) end);
apply_op(Table, {counter_list, Key}) ->
    safe(fun() -> ets:update_counter(Table, Key, [{2, 2}, {2, -1, -10, 0}], {Key, 0}) end);
apply_op(Table, {update_element, Key}) ->
    safe(fun() -> ets:update_element(Table, Key, {2, 7}) end);
apply_op(Table, {fix, _}) -> ets:safe_fixtable(Table, true);
apply_op(Table, {unfix, _}) -> ets:safe_fixtable(Table, false).

safe(Fun) -> try Fun() catch error:badarg -> badarg end.

collect_chunks('$end_of_table', Acc) -> lists:reverse(Acc);
collect_chunks({Rows, '$end_of_table'}, Acc) -> lists:reverse([Rows | Acc]);
collect_chunks({Rows, Continuation}, Acc) ->
    collect_chunks(ets:select(Continuation), [Rows | Acc]).

run_select(Queries) ->
    Table = ets:new(ets_select, [ordered_set]),
    ets:insert(Table, [{I, I * 2} || I <- lists:seq(1, 1000)]),
    lists:map(fun({Op, Bound, Limit}) ->
        Spec = [{{'$1', '$2'}, [{Op, '$1', Bound}], ['$1']}],
        case ets:select(Table, Spec, Limit) of
            '$end_of_table' -> [];
            {Rows, _Continuation} -> Rows
        end
    end, Queries).

run_slots(Indexes) ->
    Table = ets:new(ets_slots, [ordered_set]),
    ets:insert(Table, [{I, I * 2} || I <- lists:seq(1, 1000)]),
    [ets:slot(Table, Index) || Index <- Indexes].

run_counters(Queries) ->
    Table = ets:new(ets_counters, [set]),
    [ets:update_counter(Table, Key, Update, {Key, 0}) || {Key, Update} <- Queries].

run_count_delete() ->
    Table = ets:new(ets_count_delete, [ordered_set]),
    ets:insert(Table, [{I, I * 2} || I <- lists:seq(1, 10)]),
    Head = {'$1', '_'},
    Guard = [{'>', '$1', 5}],
    Yes = [{Head, Guard, [true]}],
    No = [{Head, Guard, [false]}],
    A = ets:select_count(Table, Yes),
    B = ets:select_count(Table, No),
    C = ets:select_delete(Table, No),
    D = ets:select_delete(Table, Yes),
    {A, B, C, D, ets:tab2list(Table)}.

run_replace() ->
    Table = ets:new(ets_replace, [ordered_set]),
    ets:insert(Table, [{I, old} || I <- lists:seq(1, 10)]),
    Spec = [{{'$1', '$2'}, [{'>', '$1', 5}], [{{'$1', changed}}]}],
    Count = ets:select_replace(Table, Spec),
    {Count, ets:tab2list(Table)}.

run_match() ->
    Table = ets:new(ets_match, [ordered_set]),
    ets:insert(Table, [{I, I rem 3} || I <- lists:seq(1, 10)]),
    {ets:match(Table, {'$1', 2}), ets:match_object(Table, {'_', 2})}.
