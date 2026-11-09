//! Differential tests for the native fast paths of `ets:lookup/2`, `ets:member/2` and
//! `ets:insert/2` and for the compressed-object decoder, against OTP 29.1.1.
use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_direct_diff).
-export([compressed_roundtrip/0, access_and_deleted/0, concurrent_inserts/0, native_loop/0,
         tail_delete/0, tail_delete_in_fun/0, catree_update_counter/0,
         insert_list_trap_cursor/0, overwrite_memory/0, overwrite_binary_refc/0,
         overwrite_readers/0]).

sample_terms() ->
    [{"abc", abc, 42, -7, 1.5, <<1,2,3>>, [a|b], {nested, {deep, [1,2,3]}}},
     {make_ref(), self(), [make_ref(), self()]},
     {123456789012345678901234567890, -123456789012345678901234567890},
     {#{a => 1, b => #{c => 2}}, fun erlang:length/1},
     {<<1:3>>, <<"binary data here that is longer than sixty four bytes, to be a refc binary....">>},
     {[], {}, "", [[]], [[], []], 16#7fffffff, -16#80000000, 16#80000000},
     {lists:seq(1, 300), lists:duplicate(70, {x, y})}].

compressed_roundtrip() ->
    T = ets:new(t, [set, compressed]),
    Objs = [{I, X} || {I, X} <- lists:zip(lists:seq(1, 7), sample_terms())],
    true = ets:insert(T, Objs),
    Back = [ets:lookup(T, I) || I <- lists:seq(1, 7)],
    Same = lists:all(fun({{I, X}, [{I2, Y}]}) -> I =:= I2 andalso norm(X) =:= norm(Y) end,
                     lists:zip(Objs, Back)),
    ElemBack = [ets:lookup_element(T, I, 2) =:= element(2, lists:keyfind(I, 1, Objs)) orelse
                    norm(ets:lookup_element(T, I, 2)) =:= norm(element(2, lists:keyfind(I, 1, Objs)))
                || I <- lists:seq(1, 7)],
    {Same, ElemBack}.

%% Refs and pids differ by identity only through =:=; replace nothing, compare as is.
norm(X) -> X.

access_and_deleted() ->
    Pub = ets:new(pub, [public, set]),
    Prot = ets:new(prot, [protected, set]),
    Priv = ets:new(priv, [private, set]),
    Named = ets:new(named, [public, named_table, set]),
    [true = ets:insert(T, {k, 1}) || T <- [Pub, Prot, Priv, Named]],
    Self = self(),
    Other = spawn_link(fun() ->
        R = [c(fun() -> ets:lookup(T, k) end) || T <- [Pub, Prot, Priv, Named]]
            ++ [c(fun() -> ets:insert(T, {k, 2}) end) || T <- [Pub, Prot, Priv, Named]]
            ++ [c(fun() -> ets:member(T, k) end) || T <- [Pub, Prot, Priv]],
        Self ! {self(), R}
    end),
    Remote = receive {Other, R} -> R end,
    %% Warm the handle caches, then delete and use the stale handle.
    [ets:lookup(Pub, k) || _ <- lists:seq(1, 10)],
    true = ets:delete(Pub),
    After = [c(fun() -> ets:lookup(Pub, k) end), c(fun() -> ets:member(Pub, k) end),
             c(fun() -> ets:insert(Pub, {k, 3}) end)],
    Bad = [c(fun() -> ets:insert(Prot, bad) end), c(fun() -> ets:insert(Prot, {}) end),
           c(fun() -> ets:insert(Prot, [{k, 9}, bad]) end), c(fun() -> ets:lookup(Prot, k) end),
           c(fun() -> ets:insert(not_a_table, {a}) end), c(fun() -> ets:lookup(12345, k) end)],
    {Remote, After, Bad}.

c(F) ->
    try F() of V -> {ok, V}
    catch Class:Reason -> {Class, Reason}
    end.

concurrent_inserts() ->
    Self = self(),
    Result = [begin
        T = ets:new(t, Opts ++ [public, {keypos, 2}]),
        [ets:insert(T, {x, K}) || K <- lists:seq(1, 1000)],
        Ps = [spawn_link(fun() ->
                  [begin ets:insert(T, {{P, K}, 1000 + P * 1000 + K}), ets:lookup(T, K), ets:member(T, K) end
                   || K <- lists:seq(1, 200)],
                  Self ! {done, self()}
              end) || P <- lists:seq(1, 8)],
        [receive {done, Pid} -> ok end || Pid <- Ps],
        Size = ets:info(T, size),
        Sum = lists:sum([V || {_, V} <- ets:tab2list(T), is_integer(V)]),
        true = ets:delete(T),
        {Opts, Size, Sum}
    end || Opts <- [[set], [ordered_set], [set, {write_concurrency, true}],
                    [ordered_set, {write_concurrency, true}], [bag], [duplicate_bag],
                    [set, compressed], [ordered_set, {write_concurrency, true}, compressed]]],
    Result.

%% `ets:delete/1` of a big table yields several times. As the last call of a function with
%% a stack frame, the interpreter used to release that frame again when it resumed.
tail_delete() ->
    T = ets:new(t, [public]),
    [ets:insert(T, {K, K}) || K <- lists:seq(1, 60000)],
    {ets_gone(), c(fun() -> ets:info(T, size) end), finish_delete(T), ets:info(T)}.

tail_delete_in_fun() ->
    T = ets:new(t, [public, {write_concurrency, true}]),
    [ets:insert(T, {{self(), K}, K}) || K <- lists:seq(1, 60000)],
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() -> Parent ! {self(), finish_delete(T)} end),
    receive {Pid, Res} -> receive {'DOWN', Ref, _, _, Why} -> {Res, Why} end end.

ets_gone() -> ok.

finish_delete(T) ->
    Size = ets:info(T, size),
    true = is_integer(Size),
    ets:delete(T).

native_loop() ->
    T = ets:new(t, [public, {keypos, 2}]),
    [ets:insert(T, {k, K}) || K <- lists:seq(1, 50)],
    loop(T, 20000, 0).

loop(_T, 0, Acc) -> Acc;
loop(T, N, Acc) ->
    K = N rem 100,
    Hits = length(ets:lookup(T, K)),
    M = case ets:member(T, K) of true -> 1; false -> 0 end,
    ets:insert(T, {tag, 1000 + (N rem 7)}),
    loop(T, N - 1, Acc + Hits + M).

%% `ets:update_counter/3,4` on an ordered_set with write_concurrency (a CA tree) whose
%% objects keep boxed terms: the update must read the stored object, not a copy freed
%% before the replacement is built (smolquery's telemetry counters, keyed by
%% `{Name, Labels}`, aborted the VM there).
catree_update_counter() ->
    Self = self(),
    T = ets:new(t, [ordered_set, public, {write_concurrency, true}]),
    Keys = [{<<"series_", (integer_to_binary(I))/binary>>, [{kind, I}, {node, <<"n">>}]}
            || I <- lists:seq(1, 40)],
    Ps = [spawn_link(fun() ->
              R = [begin
                       K = lists:nth(1 + (N * P) rem 40, Keys),
                       _ = ets:update_counter(T, K, {2, 1}, {K, 0, 0}),
                       Big = ets:update_counter(T, K, [{3, 1 bsl 62}, {2, 0}], {K, 0, 0}),
                       ets:insert(T, {{junk, P, N}, lists:seq(1, 20), <<N:64>>}),
                       ets:delete(T, {junk, P, N - 1}),
                       length(Big)
                   end || N <- lists:seq(1, 3000)],
              Self ! {done, self(), lists:sum(R)}
          end) || P <- lists:seq(1, 4)],
    Sums = [receive {done, Pid, S} -> S end || Pid <- Ps],
    Rows = [Row || {{B, _}, _, _} = Row <- ets:tab2list(T), is_binary(B)],
    {Sums, Rows, lists:sum([C || {_, C, _} <- Rows]),
     ets:update_counter(T, hd(Keys), {2, -1}, {hd(Keys), 0, 0}),
     ets:update_counter(T, {absent, [x]}, {2, 5}, {{absent, [x]}, 1, 0}),
     ets:lookup(T, {absent, [x]})}.

insert_list_trap_cursor() ->
    T = ets:new(t, [public, set]),
    First = [{I, I * 2} || I <- lists:seq(1, 4096)],
    true = ets:insert(T, First),
    false = ets:insert_new(T, First),
    Second = [{I, I * 3} || I <- lists:seq(4097, 8192)],
    true = ets:insert_new(T, Second),
    {ets:info(T, size), ets:lookup(T, 1), ets:lookup(T, 4096),
     ets:lookup(T, 4097), ets:lookup(T, 8192), ets:insert_new(T, Second)}.

overwrite_memory() ->
    [overwrite_memory_case(set, []),
     overwrite_memory_case(set, [compressed]),
     overwrite_memory_case(set, [{write_concurrency, true}]),
     overwrite_memory_case(bag, []),
     overwrite_memory_case(duplicate_bag, [])].

overwrite_memory_case(Type, Extra) ->
    T = ets:new(t, [Type | Extra]),
    Empty = ets:info(T, memory),
    true = ets:insert(T, {key, [aa, bb]}),
    First = ets:info(T, memory),
    true = ets:insert(T, {key, [cc, dd]}),
    EqualSizeOverwrite = ets:info(T, memory),
    false = ets:insert_new(T, {key, [ee, ff]}),
    FailedInsertNew = ets:info(T, memory),
    true = ets:insert(T, {key, lists:seq(1, 20)}),
    DifferentSize = ets:info(T, memory),
    {Type, Extra, [Empty, First, EqualSizeOverwrite, FailedInsertNew, DifferentSize],
     ets:info(T, size), ets:lookup(T, key)}.

overwrite_binary_refc() ->
    [overwrite_binary_refc_case([]),
     overwrite_binary_refc_case([compressed])].

overwrite_binary_refc_case(Extra) ->
    T = ets:new(t, [set | Extra]),
    First = insert_and_measure_binary(T, 1, 100),
    EqualSize = insert_and_measure_binary(T, 2, 100),
    DifferentSize = insert_and_measure_binary(T, 3, 180),
    {Extra, First, EqualSize, DifferentSize, ets:info(T, memory)}.

insert_and_measure_binary(T, Byte, Size) ->
    true = ets:insert(T, {key, binary:copy(<<Byte>>, Size)}),
    garbage_collect(),
    lists:sort([{Bytes, Refc} || {_, Bytes, Refc} <-
                                  erts_internal:ets_lookup_binary_info(T, key)]).

overwrite_readers() ->
    T = ets:new(t, [set, public, {read_concurrency, true}, {write_concurrency, true}]),
    A = {key, a, lists:seq(1, 20), binary:copy(<<1>>, 100)},
    B = {key, b, lists:seq(1, 20), binary:copy(<<2>>, 100)},
    true = ets:insert(T, A),
    Parent = self(),
    Readers = [spawn_link(fun() ->
                  Parent ! {ready, self()},
                  receive go -> Parent ! {done, self(), read_consistent(T, A, B, 10000)} end
              end) || _ <- lists:seq(1, 4)],
    [receive {ready, Reader} -> ok end || Reader <- Readers],
    [Reader ! go || Reader <- Readers],
    [begin
         true = ets:insert(T, B),
         true = ets:insert(T, A)
     end || _ <- lists:seq(1, 2000)],
    Results = [receive {done, Reader, Result} -> Result end || Reader <- Readers],
    {lists:all(fun(X) -> X end, Results), ets:lookup(T, key)}.

read_consistent(_T, _A, _B, 0) -> true;
read_consistent(T, A, B, Left) ->
    case ets:lookup(T, key) of
        [A] -> read_consistent(T, A, B, Left - 1);
        [B] -> read_consistent(T, A, B, Left - 1);
        _ -> false
    end.
"#;

#[test]
fn compressed_objects_round_trip_like_otp_29() {
    assert_same("compressed_roundtrip");
}

#[test]
fn access_checks_and_deleted_tables_match_otp_29() {
    assert_same("access_and_deleted");
}

#[test]
fn concurrent_inserts_match_otp_29() {
    assert_same("concurrent_inserts");
}

#[test]
fn tail_call_of_yielding_delete_matches_otp_29() {
    assert_same("tail_delete");
    assert_same("tail_delete_in_fun");
}

#[test]
fn native_loop_matches_otp_29() {
    assert_same("native_loop");
}

#[test]
fn catree_update_counter_matches_otp_29() {
    assert_same("catree_update_counter");
}

#[test]
fn trapped_insert_lists_match_otp_29() {
    assert_same("insert_list_trap_cursor");
}

#[test]
fn same_size_and_resized_overwrites_match_otp_29() {
    assert_same_with_four_schedulers("overwrite_memory");
    assert_same_with_four_schedulers("overwrite_binary_refc");
    assert_same_with_four_schedulers("overwrite_readers");
}

fn assert_same(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ETS direct-path differential {function}");
        return;
    };
    assert_same_with_reference(function, &reference);
}

fn assert_same_with_four_schedulers(function: &str) {
    let Ok(reference) = RefErl::start_with_erl_args(&["+S", "4"]) else {
        eprintln!("erl unavailable; skipping ETS direct-path differential {function}");
        return;
    };
    assert_same_with_reference(function, &reference);
}

fn assert_same_with_reference(function: &str, reference: &RefErl) {
    let beam = reference
        .compile_named("ets_direct_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_direct_diff", &beam).unwrap();
    let expected = reference.call("ets_direct_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_direct_diff", function, &[], 4, Some(81))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}
