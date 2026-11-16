use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

#[test]
fn characters_to_binary_matches_otp_results_and_reductions() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let source = r#"
-module(unicode_to_binary_differential).
-export([run/0]).
f(A, E) ->
    try unicode:characters_to_binary(A, E) of
        R when is_binary(R) -> {bin, erlang:phash2(R), byte_size(R)};
        {T, B, Rest} -> {T, erlang:phash2(B), byte_size(B), erlang:phash2(Rest)}
    catch C:_ -> C end.
run() ->
    process_flag(min_heap_size, 2000000),
    Big = lists:duplicate(60000, $a) ++ [16#1F600, 16#e9] ++ lists:duplicate(30000, 16#4e2d),
    Bin = unicode:characters_to_binary(Big),
    Cases = [
      {<<>>, utf8}, {[], utf8}, {"abc", utf8}, {<<"héllo"/utf8>>, utf8},
      {<<"héllo"/utf8>>, latin1}, {[<<"a">>, "bc", [<<"é"/utf8>>, 16#10FFFF]], utf8},
      {[<<195>>, <<169>>], utf8}, {[<<195>>], utf8}, {[<<255>>], utf8}, {[16#D800], utf8},
      {[16#110000], utf8}, {[-1], utf8}, {"abc" ++ foo, utf8}, {foo, utf8}, {[a], utf8},
      {[<<"é"/utf8>>, 300], latin1}, {[233, <<233>>], latin1}, {<<233>>, latin1},
      {[<<226,130>>, <<172>>], utf8}, {[<<226,130>>], unicode}, {[<<240,159,152>>, 65], utf8},
      {<<1:3>>, utf8}, {[<<1:3>>], utf8}, {<<"abc">>, bad},
      {lists:duplicate(200, <<"é"/utf8>>), utf8},
      {[[[[<<"a">>]]], <<"b">>|<<"c">>], utf8}, {"a" ++ <<"b">>, latin1},
      {Big, utf8}, {[Big, <<"x">>], utf8}, {[Bin, Bin, Big], utf8},
      {[Bin, [<<226,130>>, <<172>>], Bin], utf8}, {Big ++ [16#D800|Big], utf8},
      {[Bin, <<255>>, Bin], utf8}, {[Bin|<<226,130>>], utf8}, {binary:copy(Bin, 3), latin1},
      {Big, latin1}],
    % Calls that finish within a few reductions, and the trapping calls whose result and
    % input stay below the binary virtual heap limit, must match exactly. The calls with
    % the 450000 byte binaries are compared by result only: erts collects garbage after
    % them at a point that depends on its virtual binary heap, which varies from run to run
    % (the reference itself differs by up to 1700 reductions between runs).
    {Exact, ResultOnly} = lists:split(28, Cases),
    [{f(A, E), reds(A, E)} || {A, E} <- Exact] ++ [{f(A, E), 0} || {A, E} <- ResultOnly].
reds(A, E) ->
    erlang:garbage_collect(),
    erlang:yield(),
    {reductions, Before} = process_info(self(), reductions),
    f(A, E),
    {reductions, After} = process_info(self(), reductions),
    After - Before.
"#;
    let beam = reference
        .compile_named("unicode_to_binary_differential", source, &[])
        .unwrap();
    reference
        .load("unicode_to_binary_differential", &beam)
        .unwrap();
    let expected = reference.call("unicode_to_binary_differential", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("unicode_to_binary_differential", "run", &[], 1)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
