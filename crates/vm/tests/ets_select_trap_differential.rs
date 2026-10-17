//! `ets:select/2`, `match/2`, `match_object/2`, `tab2list/1`, `select_count/2` and
//! `select_reverse/2` on hash tables charge reductions per visited object and trap through
//! `ets:select_trap/1` (`ets:count_trap/1` for `select_count/2`) like erts. Differential against
//! OTP: reductions, schedule-ins and result at 1, 1k and 100k rows, and a writer that runs while a
//! select is trapped.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "ets_select_trap_test";

/// The interpreter counts a few more instructions around the call than BEAMASM and erts do.
const SLACK: i64 = 16;

const SIZES: [(&str, usize); 3] = [("1", 1), ("1k", 1_000), ("100k", 100_000)];

const SELECT_ALL: &str = "[{{'$1', '_'}, [], ['$1']}]";
const COUNT_ALL: &str = "[{{'$1', '_'}, [], [true]}]";

/// Table kind, the call and how the result is reduced to the value compared with OTP.
const CALLS: &[(&str, &str, &str)] = &[
    ("match", "ets:match(In, {'$1', '_'})", "length"),
    ("select", "ets:select(In, SELECT_ALL)", "length"),
    (
        "select_reverse",
        "ets:select_reverse(In, SELECT_ALL)",
        "length",
    ),
    ("tab2list", "ets:tab2list(In)", "length"),
    ("match_object", "ets:match_object(In, {'$1', 7})", "length"),
    ("match_object_all", "ets:match_object(In, '_')", "length"),
    ("select_count", "ets:select_count(In, COUNT_ALL)", "id"),
    (
        "select_count_some",
        "ets:select_count(In, [{{'$1', '_'}, [{'<', '$1', 77}], [true]}])",
        "id",
    ),
    (
        "select_key",
        "ets:select(In, [{{1, '_'}, [], ['$_']}])",
        "length",
    ),
    (
        "select_two_keys",
        "ets:select(In, [{{1, '_'}, [], ['$_']}, {{2, '_'}, [], ['$_']}, {{3, '_'}, [], ['$_']}])",
        "length",
    ),
    ("match_key", "ets:match(In, {1, '$1'})", "length"),
    (
        "select_range",
        "ets:select(In, [{{{3, '_'}, '_'}, [], ['$_']}])",
        "length",
    ),
    (
        "select_range_reverse",
        "ets:select_reverse(In, [{{{3, '_'}, '_'}, [], ['$_']}])",
        "length",
    ),
    (
        "select_count_range",
        "ets:select_count(In, [{{{3, '_'}, '_'}, [], [true]}])",
        "id",
    ),
    ("match_range", "ets:match(In, {{3, '$1'}, '_'})", "length"),
    (
        "match_object_key",
        "ets:match_object(In, {1, '_'})",
        "length",
    ),
    (
        "select_count_key",
        "ets:select_count(In, [{{1, '_'}, [], [true]}])",
        "id",
    ),
    (
        "select_missing_key",
        "ets:select(In, [{{-5, '_'}, [], ['$_']}])",
        "length",
    ),
];

/// Calls that run on ordered_set tables of both kinds.
const ORDERED_CALLS: &[&str] = &[
    "select",
    "select_reverse",
    "match",
    "match_object",
    "match_object_all",
    "tab2list",
    "select_count",
    "select_count_some",
    "select_key",
    "select_missing_key",
    "match_key",
    "select_range",
    "select_range_reverse",
    "select_count_range",
    "match_range",
];

/// Chunked calls (`select/3`, `match/3`, `match_object/3` and the continuations) on every table
/// kind: the call, the limit and how the chunks are folded.
const CHUNK_CALLS: &[(&str, &str)] = &[
    (
        "select3_1",
        "chunks(fun() -> ets:select(In, SELECT_ALL, 1) end, 0)",
    ),
    (
        "select3_100",
        "chunks(fun() -> ets:select(In, SELECT_ALL, 100) end, 0)",
    ),
    (
        "select3_1000",
        "chunks(fun() -> ets:select(In, SELECT_ALL, 1000) end, 0)",
    ),
    (
        "select3_big",
        "chunks(fun() -> ets:select(In, SELECT_ALL, 1000000) end, 0)",
    ),
    (
        "select3_rev_100",
        "chunks(fun() -> ets:select_reverse(In, SELECT_ALL, 100) end, 0)",
    ),
    (
        "select3_some_100",
        "chunks(fun() -> ets:select(In, [{{'$1', '_'}, [{'<', '$1', 77}], ['$1']}], 100) end, 0)",
    ),
    (
        "match3_100",
        "chunks(fun() -> ets:match(In, {'$1', '_'}, 100) end, 0)",
    ),
    (
        "match_object3_1000",
        "chunks(fun() -> ets:match_object(In, '_', 1000) end, 0)",
    ),
    (
        "select3_range_100",
        "chunks(fun() -> ets:select(In, [{{{3, '_'}, '_'}, [], ['$_']}], 100) end, 0)",
    ),
];

const TABLES: &[(&str, &str)] = &[
    (
        "set",
        "ets_fill(ets:new(t, [set, public]), N, fun(I) -> {I, I} end)",
    ),
    (
        "bag",
        "ets_fill(ets:new(t, [bag, public]), N, fun(I) -> {I rem 500, I} end)",
    ),
    (
        "dbag",
        "ets_fill(ets:new(t, [duplicate_bag, public]), N, fun(I) -> {I rem 500, I rem 3} end)",
    ),
    (
        "set_wc",
        "ets_fill(ets:new(t, [set, public, {write_concurrency, true}]), N, fun(I) -> {I, I} end)",
    ),
    (
        "ordered",
        "ets_fill(ets:new(t, [ordered_set, public]), N, fun(I) -> {I, I} end)",
    ),
    (
        "ordered_wc",
        "ets_fill(ets:new(t, [ordered_set, public, {write_concurrency, true}]), N, fun(I) -> {I, I} end)",
    ),
    (
        "tuples",
        "ets_fill(ets:new(t, [ordered_set, public]), N, fun(I) -> {{I rem 10, I}, I} end)",
    ),
    (
        "tuples_wc",
        "ets_fill(ets:new(t, [ordered_set, public, {write_concurrency, true}]), N, fun(I) -> {{I rem 10, I}, I} end)",
    ),
];

fn is_ordered(table: &str) -> bool {
    matches!(table, "ordered" | "ordered_wc" | "tuples" | "tuples_wc")
}

fn functions(chunked: bool) -> Vec<(String, String, String, String)> {
    let mut all = Vec::new();
    for (table, build) in TABLES {
        let ordered = is_ordered(table);
        for (call_name, call, post) in CALLS.iter().filter(|_| !chunked) {
            for (label, size) in SIZES {
                let hash_ok = matches!(
                    *call_name,
                    "select" | "match_object_all" | "select_count" | "select_key"
                );
                if ordered {
                    let tuple_keys = matches!(*table, "tuples" | "tuples_wc");
                    if !ORDERED_CALLS.contains(call_name)
                        || tuple_keys != call_name.contains("range")
                    {
                        continue;
                    }
                } else if call_name.contains("range") || (*table != "set" && !hash_ok) {
                    continue;
                }
                if *table == "set_wc" && size > 1000 {
                    continue;
                }
                let name = format!("{table}_{call_name}_{label}");
                let call = call
                    .replace("SELECT_ALL", SELECT_ALL)
                    .replace("COUNT_ALL", COUNT_ALL);
                let body = format!(
                    "{name}() ->\n    measure({size}, fun(N) -> {build} end, fun(In) -> {call} end, fun post_{post}/1).\n\n"
                );
                all.push((name, body, String::new(), String::new()));
            }
        }
        for (call_name, call) in CHUNK_CALLS.iter().filter(|_| chunked) {
            if call_name.contains("range") != matches!(*table, "tuples" | "tuples_wc") {
                continue;
            }
            for (label, size) in SIZES {
                if *call_name == "select3_1" && size > 1000 {
                    continue;
                }
                if matches!(*table, "set_wc") && size > 1000 {
                    continue;
                }
                let name = format!("{table}_{call_name}_{label}");
                let call = call.replace("SELECT_ALL", SELECT_ALL);
                let body = format!(
                    "{name}() ->\n    measure({size}, fun(N) -> {build} end, fun(In) -> {call} end, fun post_id/1).\n\n"
                );
                all.push((name, body, String::new(), String::new()));
            }
        }
    }
    all
}

const COMMON: &str = r#"
ets_fill(T, N, F) ->
    true = ets:insert(T, [F(I) || I <- lists:seq(1, N)]),
    T.


%% Every page of select/3, select_reverse/3, match/3 and match_object/3 and of the select/1
%% continuations, with the parts of each continuation that do not name a reference or a table.
chunk_pages() ->
    Tables = [{set, [set, public], fun(I) -> {I, I} end},
              {bag, [bag, public], fun(I) -> {I rem 7, I} end},
              {dbag, [duplicate_bag, public], fun(I) -> {I rem 7, I rem 3} end},
              {wc_bag, [bag, public, {write_concurrency, true}], fun(I) -> {I rem 50, I} end},
              {ord, [ordered_set, public], fun(I) -> {I, I} end},
              {ord_wc, [ordered_set, public, {write_concurrency, true}], fun(I) -> {I, I} end},
              {tup, [ordered_set, public], fun(I) -> {{I rem 5, I}, I} end}],
    Calls = [fun(T, N) -> ets:select(T, [{{'$1', '_'}, [], ['$1']}], N) end,
             fun(T, N) -> ets:select_reverse(T, [{{'$1', '_'}, [], ['$1']}], N) end,
             fun(T, N) -> ets:select(T, [{{'$1', '_'}, [{'<', '$1', 40}], ['$_']}], N) end,
             fun(T, N) -> ets:match(T, {'$1', '_'}, N) end,
             fun(T, N) -> ets:match_object(T, '_', N) end,
             fun(T, N) -> ets:select(T, [{{{3, '_'}, '_'}, [], ['$_']}], N) end,
             fun(T, N) -> ets:select_reverse(T, [{{{3, '_'}, '_'}, [], ['$_']}], N) end,
             fun(T, N) -> ets:select(T, [{{1, '_'}, [], ['$_']}], N) end],
    [begin
         T = ets:new(t, Opts),
         ets_fill(T, 300, F),
         [[chunk_pages(T, Call, N) || N <- [1, 2, 3, 7, 50, 400]] || Call <- Calls]
     end || {_, Opts, F} <- Tables].

chunk_pages(T, Call, N) ->
    try page_list(Call(T, N), []) catch error:E -> {error, E} end.

page_list('$end_of_table', Acc) -> lists:reverse(Acc);
page_list({L, '$end_of_table'}, Acc) -> lists:reverse([{L, eot} | Acc]);
page_list({L, C}, Acc) -> page_list(ets:select(C), [{L, cont_shape(C)} | Acc]).

cont_shape(C) when tuple_size(C) =:= 6 ->
    {element(2, C), element(3, C), element(5, C), element(6, C)};
cont_shape(C) when tuple_size(C) =:= 8 ->
    {element(2, C), element(3, C), element(4, C), element(6, C), element(7, C), element(8, C)}.

%% Errors, empty results and the end markers of the chunked calls.
chunk_edges() ->
    [begin
         T = ets:new(t, Opts),
         Empty = [ets:select(T, [{'_', [], ['$_']}], 5), ets:match(T, '_', 5), ets:match_object(T, '_', 5)],
         ets_fill(T, 20, fun(I) -> {I, I} end),
         Ms = [{{'$1', '_'}, [], ['$1']}],
         Errors = [catch_error(fun() -> ets:select(T, Ms, 0) end), catch_error(fun() -> ets:select(T, Ms, -3) end),
                   catch_error(fun() -> ets:select(T, Ms, a) end), catch_error(fun() -> ets:select(T, Ms, 1.0) end),
                   catch_error(fun() -> ets:select(T, bad, 5) end), catch_error(fun() -> ets:match(T, '_', 0) end),
                   catch_error(fun() -> ets:select(nope, Ms, 5) end), catch_error(fun() -> ets:select(foo) end),
                   catch_error(fun() -> ets:select({}) end), catch_error(fun() -> ets:select({1, 2, 3}) end),
                   catch_error(fun() -> ets:select({T, 1, 2, 3, 4, 5}) end)],
         Ends = [ets:select('$end_of_table'), ets:match('$end_of_table'), ets:match_object('$end_of_table'),
                 ets:select(T, [], 5), ets:select(T, [{{-1, '_'}, [], ['$_']}], 5),
                 ets:match(T, {-1, '_'}, 5), ets:select(T, [{{25, '_'}, [], ['$_']}], 5)],
         {Empty, Errors, Ends, ets:select(T, Ms, 100)}
     end || Opts <- [[set, public], [bag, public], [ordered_set, public],
                     [ordered_set, public, {write_concurrency, true}]]].

catch_error(F) -> try F() catch error:E -> E end.

post_length(R) -> length(R).

chunks(First, Acc) -> chunk(First(), Acc).

chunk('$end_of_table', Acc) -> Acc;
chunk({L, '$end_of_table'}, Acc) -> Acc + length(L);
chunk({L, C}, Acc) -> chunk(ets:select(C), Acc + length(L)).
post_id(R) -> R.

measure(N, Build, Run, Post) ->
    Parent = self(),
    Words = 40 * N + 100000,
    Pid = spawn_opt(fun() ->
        In = Build(N),
        Parent ! ready,
        receive go -> ok end,
        erlang:yield(),
        {reductions, R0} = process_info(self(), reductions),
        Result = Run(In),
        {reductions, R1} = process_info(self(), reductions),
        {garbage_collection, GC} = process_info(self(), garbage_collection),
        Parent ! {measured, R1 - R0, true, proplists:get_value(minor_gcs, GC)},
        Parent ! {post, Post(Result)},
        erlang:yield()
    end, [{min_heap_size, Words}, {min_bin_vheap_size, Words}]),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    receive ready -> ok after 20000 -> exit(no_ready) end,
    drain(Pid),
    Pid ! go,
    {Reds, Ins, Gcs} = schedule_ins(Pid, 0),
    receive {post, Value} -> {Reds, Ins, Gcs, Value} after 20000 -> timeout end.

drain(Pid) ->
    receive
        {trace, Pid, _, _} -> drain(Pid)
    after 300 -> ok
    end.

schedule_ins(Pid, Count) ->
    receive
        {trace, Pid, in, _} -> schedule_ins(Pid, Count + 1);
        {trace, Pid, _, _} -> schedule_ins(Pid, Count);
        {measured, Reds, true, Gcs} -> {Reds, Count, Gcs}
    after 20000 -> exit(no_measure)
    end.

%% Result order of the select family follows the bucket order (a fine-locked table visits the
%% buckets of one lock after the other).
orders() ->
    [begin
         T = ets:new(t, Opts),
         ets_fill(T, 600, fun(I) -> {I, I} end),
         [lists:sublist([K || {K, _} <- ets:tab2list(T)], 6), lists:sublist(ets:select(T, [{{'$1', '_'}, [], ['$1']}]), 6),
          lists:sublist([K || [K] <- ets:match(T, {'$1', '_'})], 6)]
     end || Opts <- [[set, public], [set, public, {write_concurrency, true}],
                     [bag, public, {write_concurrency, true}]]].

%% Ordered tables return the objects in key order and a trapped traversal resumes from its
%% last key, also where the clause heads name a range, several ranges or no key at all.
ordered_results() ->
    [begin
         T = ets:new(t, Opts),
         ets_fill(T, 2500, fun(I) -> {{I rem 7, I}, I} end),
         Spec = fun(Head) -> [{Head, [], ['$_']}] end,
         All = [{{'$1', '$2'}, '$3'}],
         Count = [{{'$1', '_'}, [], [true]}],
         [ets:select(T, Spec({{3, '_'}, '_'})), ets:select_reverse(T, Spec({{3, '_'}, '_'})),
          ets:select(T, [{{{2, '_'}, '_'}, [], ['$_']}, {{{5, '_'}, '_'}, [], ['$_']}]),
          ets:select(T, [{{{2, '_'}, '_'}, [], ['$_']}, {'_', [], [1]}]),
          ets:select(T, [{{{3, 4}, '_'}, [], ['$_']}, {{{4, 5}, '_'}, [], ['$_']}]),
          ets:select(T, [{{{'_', 3}, '_'}, [], ['$_']}]),
          ets:match(T, {{4, '$1'}, '_'}), ets:match_object(T, {{4, '_'}, '_'}), ets:match_object(T, '_'),
          ets:select_count(T, Count), ets:select_count(T, [{{{3, '_'}, '_'}, [], [true]}]),
          ets:select(T, [{{'_', '_'}, [], ['$_']}]), ets:select(T, [{All, [], ['$_']}]),
          ets:select(T, [{{{3, '_'}, '_'}, [], ['$_']}, {{{3, 5}, '_'}, [], [x]}]), ets:tab2list(T)]
     end || Opts <- [[ordered_set, public], [ordered_set, public, {write_concurrency, true}]]].

%% A writer inserts and deletes while an ordered select is trapped; the reader never sees a key twice.
ordered_writers() ->
    N = 30000,
    T = ets:new(t, [ordered_set, public]),
    ets_fill(T, N, fun(I) -> {I, I} end),
    Me = self(),
    Reader = spawn(fun() ->
        receive go -> ok end,
        R1 = ets:select(T, [{{'$1', '_'}, [], ['$1']}]),
        R2 = ets:select_reverse(T, [{{'$1', '_'}, [], ['$1']}]),
        R3 = ets:select_count(T, [{{'$1', '_'}, [], [true]}]),
        Me ! {reader, R1, R2, R3}
    end),
    Reader ! go,
    spawn(fun() ->
        [ets:delete(T, K) || K <- lists:seq(2, N, 2)],
        [ets:insert(T, {K, K}) || K <- lists:seq(N + 1, N + 5000)],
        Me ! modded
    end),
    receive modded -> ok after 60000 -> exit(no_modded) end,
    {R1, R2, R3} = receive {reader, A, B, C} -> {A, B, C} after 60000 -> exit(no_reader) end,
    Odd = lists:seq(1, N, 2),
    {R1 =:= lists:sort(R1), R2 =:= lists:reverse(lists:sort(R2)), unique(R1), unique(R2),
     Odd -- R1 =:= [], Odd -- R2 =:= [], R3 >= N div 2, R3 =< N + 5000, ets:info(T, safe_fixed)}.

%% Slot counts decide where a traversal traps.
shapes() ->
    [begin
         T = ets:new(t, Opts),
         ets_fill(T, N, fun(I) -> {I, I} end),
         slots(T)
     end || Opts <- [[set, public], [set, public, {write_concurrency, true}],
                     [bag, public], [set, public, {read_concurrency, true}],
                     [duplicate_bag, public, {write_concurrency, true}]],
            N <- [1, 100, 1000, 1500, 5000, 100000]].

slots(T) ->
    slots(T, 0, 1 bsl 22).

slots(T, Lo, Hi) when Hi - Lo =< 1 ->
    case ets:slot(T, Lo) of '$end_of_table' -> Lo; _ -> Hi end;
slots(T, Lo, Hi) ->
    Mid = (Lo + Hi) div 2,
    try ets:slot(T, Mid) of
        '$end_of_table' -> slots(T, Lo, Mid);
        _ -> slots(T, Mid, Hi)
    catch error:badarg -> slots(T, Lo, Mid)
    end.

%% A collection after a yielded slice moves the call's arguments; boxed results survive it.
gc_after_trap() ->
    T = ets:new(t, [set, public]),
    ets_fill(T, 60000, fun(I) -> {I, I} end),
    [length(ets:match_object(T, '_')), ets:select_count(T, [{{'$1', '_'}, [], [true]}]),
     length(ets:match(T, {'$1', '$2'})), erlang:garbage_collect(), length(ets:tab2list(T))].

%% The trapped call runs as ets:select_trap/1 (ets:count_trap/1 for select_count/2).
trap_mfa() ->
    T = ets:new(t, [set, public]),
    ets_fill(T, 20000, fun(I) -> {I, I} end),
    C = ets:new(c, [set, public]),
    ets_fill(C, 20000, fun(I) -> {I, I} end),
    Me = self(),
    Tracer = spawn(fun() -> tracer(Me, []) end),
    erlang:trace(self(), true, [running, {tracer, Tracer}]),
    _ = ets:select(T, [{{'$1', '_'}, [], ['$1']}]),
    _ = ets:select_count(C, [{{'$1', '_'}, [], [true]}]),
    erlang:trace(self(), false, [running]),
    Tracer ! done,
    Msgs = receive {Tracer, M} -> M end,
    Outs = [MFA || {trace, _, out, MFA} <- Msgs],
    {length([x || {ets, select_trap, 1} <- Outs]) >= 5, length([x || {ets, count_trap, 1} <- Outs]) >= 5}.

tracer(Parent, Acc) ->
    receive done -> Parent ! {self(), lists:reverse(Acc)};
            M -> tracer(Parent, [M | Acc])
    end.

%% A writer deletes and inserts while a select is trapped; the table is fixed for the reader.
writers(Type, Access) ->
    N = 60000,
    T = ets:new(t, [Type, Access, public]),
    ets_fill(T, N, fun(I) -> {I, I} end),
    Me = self(),
    Reader = spawn_opt(fun() ->
        receive go -> ok end,
        R1 = ets:select(T, [{{'$1', '_'}, [], ['$1']}]),
        R2 = ets:match_object(T, '_'),
        R3 = ets:select_count(T, [{{'$1', '_'}, [], [true]}]),
        Me ! {reader, R1, R2, R3}
    end, [link]),
    Watcher = spawn(fun() -> watch(T, Reader, false, Me) end),
    Reader ! go,
    Mod = spawn(fun() ->
        [ets:delete(T, K) || K <- lists:seq(2, N, 2)],
        [ets:insert(T, {K, K}) || K <- lists:seq(N + 1, N + 20000)],
        Me ! modded
    end),
    receive modded -> ok after 60000 -> exit(no_modded) end,
    {R1, R2, R3} = receive {reader, A, B, C} -> {A, B, C} after 60000 -> exit(no_reader) end,
    Watcher ! stop,
    Fixed = receive {watched, F} -> F after 5000 -> no_watch end,
    _ = Mod,
    Odd = lists:seq(1, N, 2),
    Keys2 = [K || {K, _} <- R2],
    {Fixed,
     [unique(R1), unique(Keys2)],
     [lists:all(fun(K) -> lists:member(K, R1) end, [1, 3, 59999]), Odd -- R1 =:= [], Odd -- Keys2 =:= []],
     R3 >= N div 2 andalso R3 =< N + 20000,
     ets:info(T, safe_fixed),
     ets:info(T, size)}.

watch(T, Reader, Seen, Parent) ->
    receive stop -> Parent ! {watched, Seen}
    after 0 ->
        Now = case ets:info(T, safe_fixed) of
                  {_, Fixers} -> Seen orelse lists:keymember(Reader, 1, Fixers);
                  _ -> Seen
              end,
        watch(T, Reader, Now, Parent)
    end.

unique(L) -> length(L) =:= length(lists:usort(L)).

%% The owner of a private/protected table fixes nothing when it traps (ITER_SAFE).
owner_unfixed() ->
    N = 40000,
    T = ets:new(t, [set, protected]),
    ets_fill(T, N, fun(I) -> {I, I} end),
    Me = self(),
    Watcher = spawn(fun() -> watch_any(T, false, Me) end),
    Len = length(ets:select(T, [{{'$1', '_'}, [], ['$1']}])),
    Watcher ! stop,
    Fixed = receive {watched, F} -> F end,
    {Len, Fixed, ets:info(T, safe_fixed)}.

watch_any(T, Seen, Parent) ->
    receive stop -> Parent ! {watched, Seen}
    after 0 ->
        watch_any(T, Seen orelse (ets:info(T, safe_fixed) =/= false), Parent)
    end.

%% A table deleted while its select is trapped ends the call with badarg.
deleted_while_trapped() ->
    N = 300000,
    T = ets:new(t, [set, public]),
    ets_fill(T, N, fun(I) -> {I, I} end),
    Me = self(),
    Reader = spawn(fun() ->
        receive go -> ok end,
        R = try length(ets:select(T, [{{'$1', '_'}, [], ['$1']}])) of
                L -> {ok, L >= 0}
            catch error:E -> {error, E}
            end,
        Me ! {reader, R}
    end),
    Reader ! go,
    receive after 3 -> ok end,
    ets:delete(T),
    receive {reader, R} -> element(1, R) end.
"#;

fn source() -> String {
    let mut all = functions(false);
    all.extend(functions(true));
    let exports = all
        .iter()
        .map(|(name, ..)| format!("{name}/0"))
        .collect::<Vec<_>>()
        .join(", ");
    let bodies = all
        .iter()
        .map(|(_, body, ..)| body.as_str())
        .collect::<String>();
    format!(
        "-module({MODULE}).\n-export([{exports}, trap_mfa/0, ordered_results/0, ordered_writers/0, gc_after_trap/0, chunk_pages/0, chunk_edges/0, shapes/0, orders/0, writers_set/0, writers_bag/0, owner_unfixed/0, deleted_while_trapped/0]).\n\nwriters_set() -> writers(set, public).\nwriters_bag() -> writers(bag, public).\n\n{bodies}{COMMON}"
    )
}

fn measured(term: &OwnedTerm) -> (i64, i64, i64, &OwnedTerm) {
    let OwnedTerm::Tuple(elems) = term else {
        panic!("probe did not return a tuple: {term:?}");
    };
    let (OwnedTerm::Int(reds), OwnedTerm::Int(ins), OwnedTerm::Int(gcs)) =
        (&elems[0], &elems[1], &elems[2])
    else {
        panic!("probe returned {term:?}");
    };
    (*reds, *ins, *gcs, &elems[3])
}

#[test]
fn select_family_charges_and_traps_like_otp() {
    family(false);
}

/// select/3, match/3, match_object/3 and the continuations charge per visited object and trap
/// like OTP: a hash table traps as `ets:select_trap/1`, an ordered table always traps to
/// `ets:reverse/3` once a page has results.
#[test]
fn chunked_selects_charge_and_trap_like_otp() {
    family(true);
}

fn family(chunked: bool) {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = source();
    let beam = reference.compile_named(MODULE, &source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let mut failures = Vec::new();
    let filter = std::env::var("REDS_FILTER").unwrap_or_default();
    let names: Vec<String> = functions(false)
        .into_iter()
        .chain(functions(true))
        .map(|(name, ..)| name)
        .collect();
    for (index, function) in names.iter().enumerate() {
        if functions(chunked).iter().all(|(name, ..)| name != function) {
            continue;
        }
        if !function.contains(&filter) {
            continue;
        }
        let CallResult::Ok(expected) = reference.call(MODULE, function, &[]) else {
            panic!("OTP {function} failed");
        };
        let actual = vm
            .eval_scheduled_reductions(MODULE, function, &[], 1, Some(0xE700 + index as u64), 4_000)
            .unwrap();
        let (expected_reds, expected_ins, expected_gcs, expected_value) = measured(&expected);
        let (actual_reds, actual_ins, actual_gcs, actual_value) = measured(&actual.term);
        eprintln!(
            "{function}: erl reds {expected_reds} ins {expected_ins} gcs {expected_gcs}; \
             arinsal reds {actual_reds} ins {actual_ins} gcs {actual_gcs}"
        );
        // OTP's own count of a call that traps a thousand times drifts upward under load, by up
        // to one reduction per schedule-in; the value measured here is the floor.
        let drift = if expected_ins > 500 { expected_ins } else { 0 };
        let tolerance = SLACK + 4 * expected_ins.min(10) + drift;
        if expected_value != actual_value {
            failures.push(format!("{function}: the result differs from OTP"));
        }
        // OTP itself varies by one schedule-in between runs of a call that traps a hundred times.
        let ins_slack = i64::from(expected_ins > 10);
        if (expected_ins - actual_ins).abs() > ins_slack
            || !(expected_reds - tolerance..=expected_reds + tolerance).contains(&actual_reds)
        {
            failures.push(format!(
                "{function}: erl reds {expected_reds} ins {expected_ins}, arinsal reds {actual_reds} ins {actual_ins}"
            ));
        }
    }
    assert_eq!(Vec::<String>::new(), failures);
}

fn both(function: &str, workers: usize, seed: Option<u64>) -> (OwnedTerm, OwnedTerm) {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = source();
    let beam = reference.compile_named(MODULE, &source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let CallResult::Ok(expected) = reference.call(MODULE, function, &[]) else {
        panic!("OTP {function} failed");
    };
    let actual = vm
        .eval_scheduled_reductions(MODULE, function, &[], workers, seed, 4_000)
        .unwrap();
    (expected, actual.term)
}

#[test]
fn result_order_matches_otp() {
    let (expected, actual) = both("orders", 1, Some(0xE7F4));
    if std::env::var("SHOW").is_ok() {
        eprintln!("erl: {expected:?}\narinsal: {actual:?}");
    }
    assert_eq!(expected, actual);
}

#[test]
fn ordered_results_match_otp() {
    let (expected, actual) = both("ordered_results", 1, Some(0xE7F6));
    assert_eq!(expected, actual);
}

#[test]
fn writers_during_a_trapped_ordered_select_behave_like_otp() {
    let (expected, actual) = both("ordered_writers", 2, None);
    assert_eq!(expected, actual);
}

#[test]
fn chunk_pages_match_otp() {
    let (expected, actual) = both("chunk_pages", 1, Some(0xE7F7));
    assert_eq!(expected, actual);
}

#[test]
fn chunk_errors_and_end_markers_match_otp() {
    let (expected, actual) = both("chunk_edges", 1, Some(0xE7F8));
    assert_eq!(expected, actual);
}

#[test]
fn table_shapes_match_otp() {
    let (expected, actual) = both("shapes", 1, Some(0xE7F3));
    assert_eq!(expected, actual);
}

#[test]
fn results_survive_a_collection_after_a_trap() {
    let (expected, actual) = both("gc_after_trap", 1, Some(0xE7F5));
    assert_eq!(expected, actual);
}

#[test]
fn trapped_calls_run_as_the_trap_exports() {
    let (expected, actual) = both("trap_mfa", 1, Some(0xE7F0));
    assert_eq!(expected, actual);
}

#[test]
fn writers_during_a_trapped_select_behave_like_otp() {
    for function in ["writers_set", "writers_bag"] {
        let (expected, actual) = both(function, 2, None);
        assert_eq!(expected, actual, "{function}");
    }
}

#[test]
fn owner_of_a_protected_table_does_not_fix_it_and_a_deleted_table_ends_the_call() {
    for function in ["owner_unfixed", "deleted_while_trapped"] {
        let (expected, actual) = both(function, 2, None);
        assert_eq!(expected, actual, "{function}");
    }
}
