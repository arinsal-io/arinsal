use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

#[test]
fn binary_first_last_at_copy_unsigned_match_otp_results_and_reductions() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let source = r#"
-module(binary_misc_differential).
-export([run/0]).
f(F) -> try F() catch C:R -> {C, R} end.
reds(F) ->
    erlang:garbage_collect(),
    erlang:yield(),
    {reductions, B} = process_info(self(), reductions),
    F(),
    {reductions, A} = process_info(self(), reductions),
    A - B.
both(F) -> {erlang:phash2(f(F)), f(fun() -> reds(F) end)}.
run() ->
    process_flag(min_heap_size, 8000000),
    Sub = binary:part(<<"0123456789abcdef">>, 3, 7),
    Bins = [<<>>, <<1>>, <<"abc">>, Sub, <<1:3>>, <<1, 2:5>>, <<"x", 7:3>>, foo, 7,
            binary:copy(<<"0123456789">>, 500),
            binary:part(binary:copy(<<7>>, 1000), 100, 100)],
    Lists = [[], [<<>>], [<<"abc">>], [<<"abcd">>, <<"abxy">>, <<"ab">>], [<<"xabc">>, <<"yabc">>],
             [Sub, <<"345xx">>], [<<"a">>, foo], foo, [<<1:3>>, <<"a">>],
             [binary:copy(<<"a">>, 100000), binary:copy(<<"a">>, 99999), <<"ab">>]],
    Ints = [0, 1, 255, 256, 65535, 1 bsl 64, (1 bsl 200) + 12345, -1, a, 1.5],
    Orders = [big, little, foo, 1],
    Counts = [0, 1, 2, 7, 100, -1, a, 70000, 100000, 1 bsl 62],
    [{N, both(fun() -> F(B) end)} || B <- Bins, {N, F} <- [{first, fun binary:first/1}, {last, fun binary:last/1},
        {rbs, fun binary:referenced_byte_size/1}, {bsz, fun erlang:byte_size/1}, {bitsz, fun erlang:bit_size/1}, {dec1, fun binary:decode_unsigned/1},
        {decl, fun(X) -> binary:decode_unsigned(X, little) end}, {decb, fun(X) -> binary:decode_unsigned(X, big) end},
        {copy1, fun binary:copy/1}]] ++
    [{part, erlang:phash2(P), both(fun() -> binary:part(B, P) end), both(fun() -> erlang:binary_part(B, element(1, P), element(2, P)) end)}
     || B <- Bins, P <- [{0, 0}, {0, 3}, {2, 5}, {3, -3}, {100, 1}, {1, -2}, {a, 1}, {-1, 1}, {1 bsl 62, 1}, {0, -1}]] ++
    [{at, I, both(fun() -> binary:at(B, I) end)} || B <- Bins, I <- [0, 1, 2, 6, 100, -1, a]] ++
    [{lcp, both(fun() -> binary:longest_common_prefix(L) end), both(fun() -> binary:longest_common_suffix(L) end)}
     || L <- Lists] ++
    [{enc, I, O, both(fun() -> binary:encode_unsigned(I, O) end)} || I <- Ints, O <- Orders] ++
    [{enc1, I, both(fun() -> binary:encode_unsigned(I) end)} || I <- Ints] ++
    [{copy, N, erlang:phash2(C), both(fun() -> binary:copy(B, C) end)} || {N, B} <- [{1, <<"abc">>}, {2, Sub}, {3, <<>>}, {4, <<1:3>>},
        {5, binary:copy(<<"0123456789">>, 500)}], C <- Counts].
"#;
    let beam = reference
        .compile_named("binary_misc_differential", source, &[])
        .unwrap();
    reference.load("binary_misc_differential", &beam).unwrap();
    let expected = reference.call("binary_misc_differential", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("binary_misc_differential", "run", &[], 1)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
