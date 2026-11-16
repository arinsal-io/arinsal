//! Arithmetic BIF exports and edge cases compared with OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_term::ProcessHeap;

const MODULE: &str = "arith_moved_differential";
const SOURCE: &str = r#"
-module(arith_moved_differential).
-export([run/0, large_integer_text/0, overflow/0, special_mul/2, static_div/2]).

top([{M, F, Args, Location} | _]) ->
    {M, F, frame_arity(Args), proplists:get_value(error_info, Location)};
top([]) -> [];
top(_) -> other.

frame_arity(Args) when is_list(Args) -> length(Args);
frame_arity(Arity) -> Arity.

attempt(M, F, Args) ->
    try apply(M, F, Args) of
        Value -> {ok, Value}
    catch
        Class:Reason:Stack -> {exception, Class, Reason, top(Stack)}
    end.

static_attempt(Fun) ->
    try Fun() of
        Value -> {ok, Value}
    catch
        Class:Reason:Stack -> {exception, Class, Reason, top(Stack)}
    end.

run() ->
    Big = 1 bsl 120,
    [attempt(erlang, '+', [4, 5]),
     attempt(erlang, '+', [Big, 17]),
     attempt(erlang, '+', [1.25, 2]),
     attempt(erlang, '+', [bad, 2]),
     attempt(erlang, '+', [1]),
     attempt(erlang, '-', [-0.0]),
     attempt(erlang, '-', [Big, 1]),
     attempt(erlang, '*', [Big, Big + 3]),
     attempt(erlang, '*', [1.0e308, 1.0e308]),
     attempt(erlang, '/', [9, 2]),
     attempt(erlang, '/', [1, 0]),
     attempt(erlang, 'div', [-17, 5]),
     attempt(erlang, 'rem', [-17, 5]),
     attempt(erlang, 'rem', [4, 0]),
     attempt(erlang, 'band', [Big, 16#ff]),
     attempt(erlang, 'bor', [Big, 3]),
     attempt(erlang, 'bxor', [Big, 7]),
     attempt(erlang, 'bsl', [-3, 70]),
     attempt(erlang, 'bsr', [Big, 65]),
     attempt(erlang, 'bnot', [Big]),
     attempt(erlang, 'bsl', [bad, 2]),
     static_attempt(fun() -> Big + 17 end),
     static_attempt(fun() -> Big * (Big + 3) end),
     static_div(1, 0)].

overflow() -> attempt(erlang, '*', [1.0e308, 1.0e308]).

special_mul(A, B) -> attempt(erlang, '*', [A, B]).

static_div(A, B) -> static_attempt(fun() -> A / B end).

large_integer_text() ->
    Big = (1 bsl 511) + 16#deadbeef,
    [[attempt(erlang, integer_to_list, [Big]),
      attempt(erlang, integer_to_binary, [Big]),
      attempt(erlang, integer_to_list, [Big, Base]),
      attempt(erlang, integer_to_binary, [Big, Base])]
     || Base <- [2, 8, 10, 16, 36]] ++
    [attempt(erts_internal, list_to_integer, ["-0012x", 10]),
     attempt(erts_internal, list_to_integer, ["x", 10]),
     attempt(erts_internal, list_to_integer, [<<>>, 10]),
     attempt(erts_internal, binary_to_integer, [<<"-0012">>, 10]),
     attempt(erts_internal, binary_to_integer, [<<"x">>, 10])].
"#;

fn compare(function: &str) {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile arithmetic fixture");
    reference
        .load(MODULE, &beam)
        .expect("load reference fixture");
    let expected = reference.call(MODULE, function, &[]);

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM fixture");
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 1)
        .expect("run VM arithmetic fixture");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn arithmetic_exports_match_otp_values_and_error_info() {
    compare("run");
}

#[test]
fn bignum_integer_text_matches_otp_for_each_base() {
    compare("large_integer_text");
}

#[test]
fn nonfinite_float_operands_raise_badarith() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile arithmetic fixture");
    reference
        .load(MODULE, &beam)
        .expect("load reference fixture");

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM fixture");
    for value in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
        let expected = reference.call(MODULE, "overflow", &[]);
        let mut heap = ProcessHeap::default();
        let operands = {
            let mut builder = arinsal_term::TermBuilder::new(&mut heap);
            [
                builder.float(value).expect("box nonfinite operand"),
                builder.float(1.0).expect("box finite operand"),
            ]
        };
        let actual = vm
            .eval_scheduled(MODULE, "special_mul", &operands, 1)
            .expect("run special float arithmetic");
        similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
    }
}
