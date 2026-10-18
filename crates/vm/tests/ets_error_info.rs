//! ETS BIF failures name the BIF as the top frame with erts `error_info` causes, and the
//! update/select/rename edge cases they guard behave like OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_error_info_diff).
-export([causes/0, updates/0, selects/0, fixations/0]).

top(F) ->
    try F() of
        V -> {ok, V}
    catch
        error:R:S ->
            [{M, Fn, Args, Info} | _] = S,
            {R, M, Fn, length(Args), Info}
    end.

causes() ->
    T = ets:new(t, [set]),
    O = ets:new(o, [ordered_set]),
    B = ets:new(b, [bag]),
    D = ets:new(d, []),
    ets:delete(D),
    Parent = self(),
    Owner = spawn(fun() ->
        Prot = ets:new(q, [protected]),
        Priv = ets:new(p, [private]),
        NamedPriv = ets:new(named_private, [named_table, private]),
        Parent ! {tabs, Prot, Priv, NamedPriv},
        receive stop -> ok end
    end),
    {Prot, Priv, _NamedPriv} = receive {tabs, A1, A2, A3} -> {A1, A2, A3} end,
    ets:insert(T, {k, 1}),
    Cases = [
        fun() -> ets:lookup(1, a) end,
        fun() -> ets:lookup(nonexist, a) end,
        fun() -> ets:lookup(named_missing, a) end,
        fun() -> ets:lookup(named_private, a) end,
        fun() -> ets:lookup(D, a) end,
        fun() -> ets:lookup(Priv, a) end,
        fun() -> ets:insert(Prot, {a}) end,
        fun() -> ets:insert(T, a) end,
        fun() -> ets:info(1) end,
        fun() -> ets:give_away(T, self(), x) end,
        fun() -> ets:give_away(Prot, self(), x) end,
        fun() -> ets:new(T, [bad]) end,
        fun() -> ets:new(dup_name, [named_table]), ets:new(dup_name, [named_table]) end,
        fun() -> ets:rename(dup_name, dup_name) end,
        fun() -> ets:rename(Prot, other_name) end,
        fun() -> ets:update_counter(B, a, 1) end,
        fun() -> ets:update_element(B, a, {2, 1}) end,
        fun() -> ets:lookup_element(T, nokey, 2) end,
        fun() -> ets:lookup_element(T, k, 5) end,
        fun() -> ets:update_counter(T, x, 1, {}) end,
        fun() -> ets:update_counter(T, x, 1, {x, a}) end,
        fun() -> ets:update_counter(T, nokey, foo) end,
        fun() -> ets:update_counter(T, k, {1, 1}) end,
        fun() -> ets:update_counter(T, k, {5, 1}) end,
        fun() -> ets:update_counter(T, k, [{1, 1} | foo]) end,
        fun() -> ets:update_counter(T, k, {2, 1, a, 0}) end,
        fun() -> ets:update_element(T, k, {1, 2}) end,
        fun() -> ets:update_element(T, k, {3, 2}) end,
        fun() -> ets:update_element(T, nokey, {2, 2}, {}) end,
        fun() -> ets:slot(O, -1) end,
        fun() -> ets:select(T, bad) end,
        fun() -> ets:select({T, 1}) end,
        fun() -> ets:first(Priv) end,
        fun() -> ets:take(Prot, a) end,
        fun() -> ets:select_replace(B, []) end,
        fun() -> ets:select_replace(T, [{'$1', [], [{{a, b}}]}]) end,
        fun() -> ets:match_spec_compile(bad) end,
        fun() -> ets:safe_fixtable(T, foo) end,
        fun() -> ets:delete_object(Prot, {a}) end
    ],
    Result = [top(F) || F <- Cases],
    Owner ! stop,
    Result.

updates() ->
    T = ets:new(t, [set, {keypos, 2}]),
    ets:insert(T, {x, a, 1, 2}),
    [ets:update_counter(T, a, 5),
     ets:update_counter(T, a, []),
     ets:update_counter(T, a, [{3, 1}]),
     ets:update_counter(T, a, {4, 10, 5, -1}),
     ets:update_counter(T, n, [], {y, z, 0}),
     ets:update_element(T, missing, garbage),
     ets:update_element(T, a, [{1, q}, {4, r}]),
     lists:sort(ets:tab2list(T))].

selects() ->
    T = ets:new(t, [set]),
    ets:insert(T, [{I, I} || I <- lists:seq(1, 10)]),
    {Rows, Cont} = ets:select(T, [{'_', [], ['$_']}], 100),
    Dup = ets:new(d, [duplicate_bag]),
    ets:insert(Dup, [{a, 1}, {a, 1}, {b, 2}]),
    Replaced = ets:select_replace(Dup, [{{a, 1}, [], [{{a, 2}}]}]),
    K = ets:new(k, []),
    ets:insert(K, {{[{a, a}]}, 1, 2}),
    Swapped = ets:select_replace(K, [{{{[{a, a}]}, '$2', '$3'}, [],
                                      [{{{{{const, [{a, a}]}}}, '$3', '$2'}}]}]),
    Ord = ets:new(o, [ordered_set, {write_concurrency, true}]),
    ets:insert(Ord, [{I} || I <- lists:seq(1, 300)]),
    Walk = walk(Ord, ets:first(Ord), []),
    {length(Rows), Cont, ets:select(Cont), ets:select('$end_of_table'),
     Replaced, lists:sort(ets:tab2list(Dup)), Swapped, ets:tab2list(K),
     Walk =:= lists:seq(1, 300)}.

walk(_T, '$end_of_table', Acc) -> lists:reverse(Acc);
walk(T, K, Acc) -> walk(T, ets:next(T, K), [K | Acc]).

fixations() ->
    T = ets:new(t, [public]),
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        true = ets:safe_fixtable(T, true),
        true = ets:safe_fixtable(T, true),
        Parent ! fixed
    end),
    receive fixed -> ok end,
    receive {'DOWN', Ref, process, Pid, _} -> ok end,
    ets:info(T, fixed).
"#;

#[test]
fn ets_error_info_causes_match_otp_29() {
    assert_same("causes");
}

#[test]
fn ets_update_shapes_match_otp_29() {
    assert_same("updates");
}

#[test]
fn ets_select_edges_match_otp_29() {
    assert_same("selects");
}

#[test]
fn ets_exit_releases_fixations_like_otp_29() {
    assert_same("fixations");
}

fn assert_same(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ETS error_info differential {function}");
        return;
    };
    let beam = reference
        .compile_named("ets_error_info_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_error_info_diff", &beam).unwrap();
    let expected = reference.call("ets_error_info_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_error_info_diff", function, &[], 2, Some(81))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}
