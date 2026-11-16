-module(unique_maps).
-export([run/0]).

%% Differential fixture for the ARINSAL_UNIQUE_MAPS experiment: loops that the analysis marks
%% (frameless, tail recursive, map carried in an argument) are called in situations where the
%% old map is still referenced; every printed result must equal what erl prints.

%% Marked shapes ---------------------------------------------------------------------------

%% Type-checked update (is_map + put_map_assoc), result carried back into the loop.
fill(N, N, M) -> M;
fill(I, N, M) -> fill(I + 1, N, M#{I rem 4 => I}).

%% Keys beyond the flatmap limit: grows into a HAMT.
grow(N, N, M) -> M;
grow(I, N, M) -> grow(I + 1, N, M#{I => I * 2}).

%% Non-immediate keys (binaries, floats, tuples) and nested maps as values.
fill_keys(N, N, M) -> M;
fill_keys(I, N, M) ->
    K = case I rem 4 of
            0 -> <<I:8>>;
            1 -> float(I rem 3);
            2 -> {k, I rem 3};
            3 -> I rem 3
        end,
    fill_keys(I + 1, N, M#{K => #{I => I}}).

%% Bignum arithmetic in the loop: a collection can run in the middle of the chain.
churn(N, N, _, M) -> M;
churn(I, N, B, M) ->
    B2 = (B * 1000003 + I) rem (1 bsl 200),
    churn(I + 1, N, B2, M#{I rem 8 => B2}).

%% Fails with badarith after in-place updates.
boom(N, N, M) -> M;
boom(I, N, M) when I < 5 -> boom(I + 1, N, M#{I rem 2 => I});
boom(I, N, M) -> boom(I + 1, N, M#{I rem 2 => I + a}).

%% Two maps, only one can be the unique one.
two(N, N, A, B) -> {A, B};
two(I, N, A, B) -> two(I + 1, N, A#{I rem 3 => I}, B#{I rem 5 => -I}).

%% Overwrites with the same value.
same(N, N, M) -> M;
same(I, N, M) -> same(I + 1, N, M#{x => 1}).

%% The previous value is read before the update.
bump(N, N, M) -> M;
bump(I, N, #{c := C} = M) -> bump(I + 1, N, M#{c := C + 1, I rem 3 => I}).

%% Driver ----------------------------------------------------------------------------------

run() ->
    M0 = #{0 => zero, 1 => one, 2 => two, 3 => three},
    %% 1. the argument map must stay unchanged
    R1 = fill(0, 10, M0),
    show(arg_unchanged, {M0, R1}),
    %% 2. calling twice with the same argument
    R2 = fill(0, 7, M0),
    R3 = fill(0, 10, M0),
    show(twice, {M0, R2, R3}),
    %% 3. a returned map passed to the same loop again, with the first result kept
    R4 = fill(100, 105, R1),
    show(result_reuse, {R1, R4}),
    R5 = fill(200, 203, R4),
    show(result_reuse2, {R1, R4, R5}),
    %% 4. result kept in different places before the next call
    Self = self(),
    Pid = spawn(fun() -> receive {m, M} -> Self ! {echo, M, fill(300, 304, M)} end end),
    R6 = fill(0, 6, M0),
    Pid ! {m, R6},
    Echo = receive {echo, E, F} -> {E, F} end,
    show(sent, {R6, Echo, fill(400, 404, R6), R6}),
    T = ets:new(t, [set]),
    R7 = fill(0, 9, M0),
    ets:insert(T, {key, R7}),
    R7b = fill(500, 510, R7),
    show(ets, {R7, R7b, ets:lookup(T, key)}),
    R8 = fill(0, 5, M0),
    Fun = fun() -> R8 end,
    R8b = fill(600, 605, R8),
    show(closure, {Fun(), R8b, R8}),
    R9 = fill(0, 3, M0),
    L = [R9, R9],
    R9b = fill(700, 703, R9),
    show(list, {L, R9b}),
    Tup = {R9, R9b},
    R9c = fill(800, 802, R9b),
    show(tuple, {Tup, R9c}),
    put(pd, R9c),
    R9d = fill(900, 901, R9c),
    show(pdict, {get(pd), R9d}),
    %% 5. collection between the calls
    R10 = fill(0, 6, M0),
    erlang:garbage_collect(),
    R10b = fill(1000, 1006, R10),
    show(gc_between, {R10, R10b}),
    R11 = churn(0, 2000, 1, M0),
    show(churn, R11),
    R11b = churn(0, 50, 7, R11),
    show(churn2, {R11, R11b}),
    %% 6. flatmap to HAMT and back-and-forth
    G = grow(0, 100, #{}),
    G2 = grow(100, 140, G),
    show(grow, {maps:size(G), maps:size(G2), maps:get(99, G), maps:get(139, G2),
                maps:is_key(139, G)}),
    G3 = grow(0, 40, G2),
    show(grow2, {maps:size(G2), maps:get(5, G2), maps:get(5, G3), G3 =:= G2}),
    %% 7. non-immediate keys and nested values
    K = fill_keys(0, 20, #{}),
    show(keys, lists:sort(maps:to_list(K))),
    K2 = fill_keys(20, 31, K),
    show(keys2, {lists:sort(maps:to_list(K)), lists:sort(maps:to_list(K2))}),
    %% 8. exceptions in the middle of the chain
    X = (catch boom(0, 10, M0)),
    show(boom, {element(1, X), M0}),
    Y = (catch boom(0, 4, M0)),
    show(boom_ok, {Y, M0}),
    Z = fill(0, 4, M0),
    X2 = (catch boom(0, 10, Z)),
    show(boom_arg, {element(1, X2), Z, fill(10, 12, Z)}),
    %% 9. not a map
    show(badmap, catch fill(0, 3, not_a_map)),
    show(badmap0, catch fill(3, 3, not_a_map)),
    %% 10. two maps, same value, bump
    show(two, two(0, 20, #{}, #{a => 1})),
    show(same, {same(0, 5, M0), same(0, 5, #{x => 1}), same(0, 5, #{x => 2}), M0}),
    B = bump(0, 9, #{c => 0}),
    show(bump, {B, bump(0, 3, B), B}),
    %% 11. repeated calls with growing result chains
    Chain = lists:foldl(fun(I, Acc) -> [fill(I, I + 5, hd_or(Acc)) | Acc] end, [M0], lists:seq(1, 6)),
    show(chain, Chain),
    ok.

hd_or([H | _]) -> H.

show(Tag, Term) -> io:format("~p: ~p~n", [Tag, Term]).
