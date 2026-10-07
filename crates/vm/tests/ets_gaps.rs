use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_gaps_diff).
-export([all_tables/0, run_r/0, stats/0, errors/0, select_delete_large/0]).

all_tables() ->
    Named = ets:new(gap_named, [named_table, public, set]),
    Unnamed = ets:new(gap_unnamed, [bag, public]),
    true = ets:insert(Named, {k, 1}),
    true = ets:insert(Unnamed, [{k, 1}, {k, 2}]),
    Temp = ets:new(gap_temp, [named_table]),
    true = ets:delete(Temp),
    Live = ours(ets:all()),
    Ref = ets:internal_request_all(),
    N = erlang:system_info(schedulers),
    Proto = ours(recv_all(Ref, N)),
    {lists:sort(Live), lists:sort(Proto)}.

recv_all(_Ref, 0) ->
    [];
recv_all(Ref, N) ->
    receive
        {Ref, Part} ->
            Part ++ recv_all(Ref, N - 1)
    end.

ours(Tables) ->
    [describe(T) || T <- Tables, mine(T)].

mine(T) ->
    Name = name_of(T),
    Name =:= gap_named orelse Name =:= gap_unnamed orelse Name =:= gap_temp.

name_of(T) when is_atom(T) ->
    T;
name_of(T) ->
    ets:info(T, name).

describe(T) ->
    {name_of(T), form(T), ets:info(T, type), ets:info(T, size), ets:info(T, named_table)}.

form(T) when is_atom(T) ->
    atom;
form(_T) ->
    reference.

run_r() ->
    MS = [{{'$1', '$2'}, [], ['$_']}],
    C = ets:match_spec_compile(MS),
    Hit = ets:match_spec_run_r([{a, 1}, {b, 2}, c], C, [tail]),
    Empty = ets:match_spec_run_r([], C, not_a_list),
    ImproperAcc = ets:match_spec_run_r([{a, 1}], C, not_a_list),
    BadList = try ets:match_spec_run_r(1, C, []) catch error:R1 -> R1 end,
    BadMs = try ets:match_spec_run_r([{a, 1}], not_ms, []) catch error:R2 -> R2 end,
    BadTail = try ets:match_spec_run_r([1 | 2], C, []) catch error:R3 -> R3 end,
    Run = ets:match_spec_run([{a, 1}, {b, 2}, c], C),
    {Hit, Empty, ImproperAcc, BadList, BadMs, BadTail, Run, ets:is_compiled_ms(C), ets:is_compiled_ms(MS)}.

stats() ->
    Set = ets:new(gap_stats_set, [set]),
    ets:insert(Set, [{I, I} || I <- lists:seq(1, 10)]),
    Empty = ets:new(gap_stats_empty, [set]),
    Ordered = ets:new(gap_stats_ord, [ordered_set]),
    Write = ets:new(gap_stats_ordw, [ordered_set, {write_concurrency, true}]),
    ets:insert(Write, [{I, I} || I <- lists:seq(1, 20)]),
    Auto = ets:new(gap_stats_auto, [set, {write_concurrency, auto}]),
    Bag = ets:new(gap_stats_bag, [bag, {write_concurrency, true}]),
    {ets:info(Set, stats), ets:info(Empty, stats), ets:info(Ordered, stats),
     ets:info(Write, stats), ets:info(Auto, stats), ets:info(Bag, stats)}.

errors() ->
    Pub = ets:new(gap_err, [set, public]),
    ets:insert(Pub, {a, 1}),
    Prot = ets:new(gap_prot, [protected]),
    Priv = ets:new(gap_priv, [private]),
    Dead = ets:new(gap_dead, [set, public]),
    ets:delete(Dead),
    Named = ets:new(gap_named_err, [named_table, protected]),
    ets:delete(gap_named_err),
    Unnamed = ets:new(gap_unnamed_err, [set]),
    Renamed = ets:rename(Unnamed, gap_renamed_err),
    Parent = self(),
    spawn(fun() -> Parent ! {priv_ins, caught(fun() -> ets:insert(Priv, {a, 1}) end)} end),
    spawn(fun() -> Parent ! {priv_look, caught(fun() -> ets:lookup(Priv, a) end)} end),
    spawn(fun() -> Parent ! {prot_look, caught(fun() -> ets:lookup(Prot, a) end)} end),
    spawn(fun() -> Parent ! {prot_ins, caught(fun() -> ets:insert(Prot, {a, 1}) end)} end),
    spawn(fun() -> Parent ! {prot_del, caught(fun() -> ets:delete(Prot) end)} end),
    spawn(fun() ->
        receive
            go -> Parent ! {not_owner, caught(fun() -> ets:give_away(Pub, Parent, data) end)}
        end
    end) ! go,
    Spec = [{{'$1', '$2'}, [], ['$_']}],
    Cases = [
        caught(fun() -> ets:info(1) end),
        caught(fun() -> ets:info(1, size) end),
        caught(fun() -> ets:info({a, b}) end),
        caught(fun() -> ets:info(Pub, not_a_key) end),
        caught(fun() -> ets:info(self(), size) end),
        caught(fun() -> ets:info(make_ref(), size) end),
        ets:info(no_such_gap_table, size),
        ets:info(no_such_gap_table),
        caught(fun() -> ets:lookup(Dead, a) end),
        ets:info(Dead),
        ets:info(Dead, size),
        caught(fun() -> ets:insert(Dead, {a, 1}) end),
        caught(fun() -> ets:lookup(gap_named_err, a) end),
        ets:info(gap_named_err, size),
        caught(fun() -> ets:member(Dead, a) end),
        caught(fun() -> ets:delete(Dead, a) end),
        caught(fun() -> ets:new(1, []) end),
        caught(fun() -> ets:new(gap_bad_opt, [not_opt]) end),
        caught(fun() -> ets:new(gap_keypos, [{keypos, 0}]) end),
        caught(fun() -> ets:new(gap_keypos_neg, [{keypos, -1}]) end),
        caught(fun() -> ets:insert(Pub, 1) end),
        caught(fun() -> ets:insert(Pub, [1 | {a, 1}]) end),
        caught(fun() -> ets:insert(1, {a, 1}) end),
        caught(fun() -> ets:slot(Pub, -1) end),
        caught(fun() -> ets:slot(Pub, a) end),
        caught(fun() -> ets:slot(Pub, 100000) end),
        caught(fun() -> ets:select(Pub, Spec, 0) end),
        caught(fun() -> ets:select(Pub, Spec, -1) end),
        ets:select(Pub, [], 2),
        ets:select_reverse(Pub, [], 2),
        caught(fun() -> ets:member(1, a) end),
        caught(fun() -> ets:delete(1, a) end),
        caught(fun() -> ets:delete(1) end),
        caught(fun() -> ets:whereis(1) end),
        ets:whereis(no_such_gap_name),
        {Renamed =:= Unnamed, ets:info(Unnamed, name), ets:info(Unnamed, named_table), ets:whereis(gap_renamed_err)},
        caught(fun() -> ets:safe_fixtable(Pub, 'maybe') end),
        caught(fun() -> ets:give_away(Pub, self(), x) end),
        caught(fun() -> ets:lookup_element(Pub, missing, 1) end),
        caught(fun() -> ets:lookup_element(Pub, a, 0) end),
        caught(fun() -> ets:update_counter(Pub, missing, 1) end),
        caught(fun() -> ets:update_element(Pub, a, 1) end),
        caught(fun() -> ets:first(123) end),
        caught(fun() -> ets:last(make_ref()) end),
        caught(fun() -> ets:next(Pub, missing) end),
        caught(fun() -> ets:prev(no_such_gap_table, a) end),
        caught(fun() -> ets:tab2list(ok) end),
        caught(fun() -> ets:take(1, a) end),
        caught(fun() -> ets:delete_object(Pub, 1) end),
        caught(fun() -> ets:insert_new(Pub, [1]) end),
        ets:match(Pub, 1),
        caught(fun() -> ets:match_object(1, {a}) end),
        caught(fun() -> ets:select(Pub, not_ms) end),
        caught(fun() -> ets:select_reverse(Pub, bad) end),
        caught(fun() -> ets:select_count(1, []) end),
        ets:select_delete(Pub, []),
        ets:select_replace(Pub, []),
        ets:select_count(Pub, []),
        ets:select(Pub, []),
        caught(fun() -> ets:repair_continuation(1, []) end),
        caught(fun() -> ets:match_spec_compile([]) end),
        recv(priv_ins),
        recv(priv_look),
        recv(prot_look),
        recv(prot_ins),
        recv(prot_del),
        recv(not_owner)
    ],
    {length(Cases), Cases}.

caught(Fun) ->
    try Fun() catch error:Reason -> Reason end.

recv(Tag) ->
    receive
        {Tag, Value} -> Value
    after 2000 -> timeout
    end.

select_delete_large() ->
    Table = ets:new(gap_select_delete, [set]),
    true = ets:insert(Table, [{I, I rem 7} || I <- lists:seq(1, 2048)]),
    Spec = [{{'$1', '$2'}, [{'>', '$1', 1000}], [true]}],
    Before = ets:select_count(Table, Spec),
    Deleted = ets:select_delete(Table, Spec),
    {Before, Deleted, lists:sort(ets:tab2list(Table))}.
"#;

#[test]
fn ets_all_matches_otp_29() {
    assert_same("all_tables");
}

#[test]
fn match_spec_run_r_matches_otp_29() {
    assert_same("run_r");
}

#[test]
fn ets_stats_match_otp_29() {
    assert_same("stats");
}

#[test]
fn ets_error_cases_match_otp_29() {
    let actual = assert_same("errors");
    let CallResult::Ok(term) = &actual else {
        return;
    };
    let text = format!("{term}");
    assert!(
        text.starts_with("{6") || text.starts_with("{7"),
        "expected at least 40 error cases, got {text}"
    );
}

#[test]
fn select_delete_large_hash_table_matches_otp_29() {
    assert_same("select_delete_large");
}

fn assert_same(function: &str) -> CallResult {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ETS gap differential {function}");
        return CallResult::Timeout;
    };
    let beam = reference
        .compile_named("ets_gaps_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_gaps_diff", &beam).unwrap();
    let expected = reference.call("ets_gaps_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_gaps_diff", function, &[], 2, Some(81))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    expected
}
