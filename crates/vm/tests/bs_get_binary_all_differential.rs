//! Differential check for `bs_get_binary2` with the size atom `all`, which the
//! compiler emits when SSA optimization is disabled (as Elixir does for
//! module-body code).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
use arinsal_vm::Vm;

const MODULE: &str = "bs_get_binary_all_differential";
const SOURCE: &str = r#"
-module(bs_get_binary_all_differential).
-compile([export_all, nowarn_export_all]).

run(Name) -> [{B, [apply(bs_get_binary_all_differential, Name, [V]) || V <- variants(B)]} || B <- inputs()].

variants(B) ->
    [B, binary:part(<<0, B/binary, 0>>, 1, byte_size(B))]
    ++ [shifted(B, N) || N <- lists:seq(1, 7)]
    ++ [<<B/bitstring, 5:3>>, <<B/bitstring, 1:1>>].

shifted(B, N) ->
    <<_:N, S/bitstring>> = <<(1 bsl N - 1):N, B/binary>>,
    S.

inputs() ->
    [<<>>, <<0>>, <<255>>, <<"a">>, <<"abc">>, <<"abcdef">>,
     <<16#0123456789ABCDEF:64, 7>>, binary:copy(<<"xyz">>, 40)].

head_binary(B) -> case B of <<X:8, R/binary>> -> {m, X, R}; _ -> other end.
head_bitstring(B) -> case B of <<X:8, R/bitstring>> -> {m, X, R}; _ -> other end.
head_char(B) -> case B of <<$a, R/binary>> -> {m, R}; _ -> other end.
two_fields(B) -> case B of <<X:3, Y:7, R/binary>> -> {m, X, Y, R}; _ -> other end.
only_tail(B) -> case B of <<R/binary>> -> {m, R}; _ -> other end.
only_tail_bits(B) -> case B of <<R/bitstring>> -> {m, R}; _ -> other end.
literal() -> case <<"abc">> of <<$a, R/binary>> -> {m, R}; _ -> other end.
"#;

fn compile_opts() -> Vec<OwnedTerm> {
    ["no_ssa_opt", "no_bool_opt"]
        .iter()
        .map(|name| OwnedTerm::Atom((*name).to_owned()))
        .collect()
}

fn check(reference: &RefErl, vm: &mut Vm, function: &str, args: &[OwnedTerm]) {
    let expected = reference.call(MODULE, function, args);
    let mut heap = arinsal_term::VecHeap::new();
    let terms: Vec<_> = args
        .iter()
        .map(|arg| arinsal_term::from_owned(arg, &mut heap).expect("convert argument"))
        .collect();
    let actual = vm
        .eval_scheduled(MODULE, function, &terms, 1, None)
        .unwrap_or_else(|error| panic!("{function}: VM raised unexpectedly: {error:?}"));
    let actual = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    similar_asserts::assert_eq!(CallResult::Ok(actual), expected, "{function}");
}

#[test]
fn bs_get_binary_all_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference runtime");
    let beam = reference
        .compile_named(MODULE, SOURCE, &compile_opts())
        .expect("compile differential module");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM module");
    for name in [
        "head_binary",
        "head_bitstring",
        "head_char",
        "two_fields",
        "only_tail",
        "only_tail_bits",
    ] {
        check(
            &reference,
            &mut vm,
            "run",
            &[OwnedTerm::Atom(name.to_owned())],
        );
    }
    check(&reference, &mut vm, "literal", &[]);
}
