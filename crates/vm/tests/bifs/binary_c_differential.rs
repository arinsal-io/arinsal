use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

#[test]
fn bitstring_to_list_split_binary_and_binary_to_list_match_otp() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let source = r#"
-module(binary_c_differential).
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
    process_flag(min_heap_size, 2000000),
    Sub = binary:part(<<"0123456789abcdef">>, 3, 7),
    Bits = [<<>>, <<1:1>>, <<5:3>>, <<"abc">>, <<"abc", 5:3>>, <<255, 7:7>>, <<1:3, "xyz">>,
            <<1:5, "0123456789abcdef", 3:2>>, Sub, <<0:(8 * 70000 + 5)>>, <<1:2, (binary:copy(<<7>>, 5000))/binary>>],
    Calls = [fun(B) -> bitstring_to_list(B) end, fun(B) -> binary_to_list(B) end,
             fun(B) -> split_binary(B, 0) end, fun(B) -> split_binary(B, 1) end,
             fun(B) -> split_binary(B, bit_size(B) div 8) end,
             fun(B) -> split_binary(B, bit_size(B) div 8 + 1) end,
             fun(B) -> binary_to_list(B, 1, 1) end, fun(B) -> binary_to_list(B, 2, 3) end],
    [{f(fun() -> erlang:phash2(Fun(B)) end), f(fun() -> reds(fun() -> Fun(B) end) end)}
     || B <- Bits, Fun <- Calls] ++
    [f(fun() -> split_binary(foo, 1) end), f(fun() -> split_binary(<<1,2>>, -1) end),
     f(fun() -> split_binary(<<1,2>>, a) end), f(fun() -> bitstring_to_list(foo) end)].
"#;
    let beam = reference
        .compile_named("binary_c_differential", source, &[])
        .unwrap();
    reference.load("binary_c_differential", &beam).unwrap();
    let expected = reference.call("binary_c_differential", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("binary_c_differential", "run", &[], 1)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
