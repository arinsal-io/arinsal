//! Regressions for VM crashes found by the erts suite run: a handler installed after a failing
//! BIF that exhausted the slice, and a stack trace whose arguments are a deeply nested term.

use arinsal_difftest::{CallResult, RefErl};

const SOURCE: &str = r#"
-module(crash_reg).
-export([limit_catch/0, limit_try/0, limit_class/0, deep_args/0, bad_terms/0, bad_node_terms/0]).

%% A negative maximum bignum minus one fails with system_limit after a huge reduction
%% charge; the handler must still see x0-x3 and keep the saved stack trace alive.
limit_catch() ->
    M = -erlang:system_info(max_integer),
    {'EXIT', {Reason, Stack}} = (catch M - 1),
    {Reason, is_list(Stack)}.
limit_try() ->
    M = -erlang:system_info(max_integer),
    try M - 1 catch C:E:S -> {C, E, is_list(S), length(S) > 0} end.
limit_class() ->
    M = -erlang:system_info(max_integer),
    try M - 1 catch C:E -> {C, E} end.

nest(0, Acc) -> Acc;
nest(N, Acc) -> nest(N - 1, [Acc, $a]).

%% Rebuilding the stack trace used to deep-clone the 300000-level argument and overflow the
%% native stack.
deep_args() ->
    A = [[nest(300000, []), oops]],
    erlang:yield(),
    try erlang:list_to_binary(A) catch error:E:S -> [{M, F, _, _} | _] = S, {E, M, F} end.

%% binary_SUITE:bad_terms/1: a truncated or bit-flipped external term must fail without leaving
%% the partial term in a heap fragment that the collection after the BIF treats as live. The
%% deterministic option keeps both runtimes' map encodings byte-identical. The [safe] result is
%% exercised but not tallied because it depends on each VM's atom table.
bad_terms() ->
    Terms = [{a, b, [1, 2, 3], "abc", <<1, 2, 3>>, 1.5, #{a => 1, b => [x]}},
             lists:seq(1, 100), <<1:3>>, 1 bsl 100, [<<"x">> | y],
             binary:copy(<<"0123456789">>, 20)],
    lists:foldl(fun(T, Acc) -> corrupt(T, Acc) end, {0, 0}, Terms).

%% Pids, references and funs encode differently on each node, so only the absence of a crash
%% is compared.
bad_node_terms() ->
    Terms = [{self(), make_ref()}, [make_ref() || _ <- lists:seq(1, 20)], {fun() -> ok end, self()}],
    _ = lists:foldl(fun(T, Acc) -> corrupt(T, Acc) end, {0, 0}, Terms),
    ok.
corrupt(Term, Acc0) ->
    Bin = term_to_binary(Term, [deterministic]),
    Acc = corrupter(Bin, size(Bin) - 1, Acc0),
    CBin = term_to_binary(Term, [compressed, deterministic]),
    corrupter(CBin, size(CBin) - 1, Acc).
corrupter(Bin, Pos, Acc0) when Pos >= 0 ->
    {Short, Rest} = split_binary(Bin, Pos),
    Acc1 = tally(Short, tally(list_to_binary([Short]), Acc0)),
    <<Byte, Tail/binary>> = Rest,
    Acc = lists:foldl(fun(M, A) -> tally(<<Short/binary, (Byte bxor M), Tail/binary>>, A) end,
                      Acc1, [1, 2, 4, 8, 16, 32, 64, 128, 255]),
    corrupter(Bin, Pos - 1, Acc);
corrupter(_, _, Acc) -> Acc.
tally(Bin, {Ok, Bad}) ->
    Default = try binary_to_term(Bin), true catch error:_ -> false end,
    _ = try binary_to_term(Bin, [safe]) catch error:_ -> error end,
    case Default of
        true -> {Ok + 1, Bad};
        false -> {Ok, Bad + 1}
    end.
"#;

#[test]
fn crashes_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping crash regression test");
        return;
    };
    let beam = reference.compile_named("crash_reg", SOURCE, &[]).unwrap();
    reference.load("crash_reg", &beam).unwrap();
    for function in [
        "limit_catch",
        "limit_try",
        "limit_class",
        "deep_args",
        "bad_terms",
        "bad_node_terms",
    ] {
        let expected = reference.call("crash_reg", function, &[]);
        let mut vm = crate::common::node();
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("crash_reg", function, &[], 1)
            .map(|result| result.term)
            .unwrap_or_else(|error| panic!("{function}: VM error {error:?}"));
        similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "{function}");
    }
}
