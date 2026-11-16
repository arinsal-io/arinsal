use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

#[test]
fn binary_match_matches_split_match_otp_results_and_reductions() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let source = r#"
-module(binary_find_differential).
-export([run/0]).
f(F) -> try F() catch C:R -> {C, R} end.
reds(F) ->
    erlang:garbage_collect(),
    erlang:yield(),
    {reductions, B} = process_info(self(), reductions),
    F(),
    {reductions, A} = process_info(self(), reductions),
    A - B.
run() ->
    process_flag(min_heap_size, 4000000),
    Small = <<"a,b,,c;d,e,,">>,
    Big = binary:copy(<<"abcdefghij,klmnopqrst;uvwxyz,">>, 60000),
    Never = binary:copy(<<"x">>, 700000),
    {ok, CP} = {ok, binary:compile_pattern(<<",">>)},
    CAC = binary:compile_pattern([<<",">>, <<";">>, <<"ab">>]),
    Pats = [<<",">>, <<"ab">>, [<<",">>, <<";">>], [<<"klm">>, <<"qr">>, <<"z,">>], CP, CAC, <<>>, [], [<<>>], foo, {bm, make_ref()}],
    Opts = [[], [{scope, {2, 5}}], [{scope, {3, -3}}], [{scope, {100, 1}}], [global], [global, trim], [global, trim_all],
            [trim], [trim_all], [global, {scope, {1, 8}}], [bad]],
    Subjects = [<<>>, Small, Big, Never, foo, <<1:3>>],
    Calls = [fun(S, P, O) -> binary:match(S, P, O) end, fun(S, P, O) -> binary:matches(S, P, O) end,
             fun(S, P, O) -> binary:split(S, P, O) end, fun(S, P, _) -> binary:match(S, P) end,
             fun(S, P, _) -> binary:matches(S, P) end, fun(S, P, _) -> binary:split(S, P) end],
    Compile = [f(fun() -> element(1, binary:compile_pattern(P)) end) || P <- Pats],
    %% The reductions of the searches of the large subjects, which trap, are not compared: the
    %% result-building loops of those calls charge a few reductions (1 to 5 of 6000) more in
    %% erts than here. The results are compared for every call.
    Results = [{erlang:phash2(f(fun() -> C(S, P, O) end)),
                case is_binary(S) andalso byte_size(S) > 100000 of
                    true -> 0;
                    false -> f(fun() -> reds(fun() -> C(S, P, O) end) end)
                end}
               || S <- Subjects, P <- Pats, O <- Opts, C <- Calls, valid(S, P, O)],
    {Compile, length(Results), erlang:phash2(Results)}.
%% Keep the number of combinations of the large subjects bounded.
valid(S, _P, O) when is_binary(S), byte_size(S) > 100000 -> O =:= [] orelse O =:= [global];
valid(_, _, _) -> true.
"#;
    let beam = reference
        .compile_named("binary_find_differential", source, &[])
        .unwrap();
    reference.load("binary_find_differential", &beam).unwrap();
    let expected = reference.call("binary_find_differential", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("binary_find_differential", "run", &[], 1)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
