-module(ets_hash_port_fixture).
-export([bag/0, duplicate_bag/0, iteration_set/0, iteration_bag/0,
         iteration_duplicate_bag/0]).

bag() ->
    T = ets:new(bag, [bag]),
    true = ets:insert(T, [{1, 10}, {1, 10}, {1, 20}]),
    ets:lookup(T, 1).

duplicate_bag() ->
    T = ets:new(duplicate_bag, [duplicate_bag]),
    true = ets:insert(T, [{1, 10}, {1, 10}, {1, 20}]),
    ets:lookup(T, 1).

iteration_set() -> iteration_order(set).
iteration_bag() -> iteration_order(bag).
iteration_duplicate_bag() -> iteration_order(duplicate_bag).

iteration_order(Type) ->
    T = ets:new(iteration, [Type]),
    Objects = [{mixed_key(I), I} || I <- lists:seq(1, 1000)],
    true = ets:insert(T, Objects),
    ets:tab2list(T).

mixed_key(I) ->
    case I rem 4 of
        0 -> I;
        1 -> {-I, I};
        2 -> list_to_atom("hash_key_" ++ integer_to_list(I));
        3 -> I + 0.5
    end.
