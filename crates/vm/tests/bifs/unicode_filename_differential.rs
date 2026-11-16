use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

#[test]
fn filename_conversion_bifs_match_otp() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let source = r#"
-module(unicode_filename_differential).
-export([run/0]).
f(F) -> try F() catch C:R -> {C, R} end.
run() ->
    Names = [[], "abc", "héllo", [16#1F600], [$a, [$b, [$c]]], <<"abc">>, <<"a", 0, "b">>,
             "a\0b", [0], [16#D800], [16#110000], [-1], foo, [foo], <<"héllo"/utf8>>,
             <<255>>, [255, 256]],
    Bins = [<<>>, <<"abc">>, <<"héllo"/utf8>>, <<255>>, <<226,130>>, <<"e", 16#CC, 16#81>>,
            <<"A", 16#CC, 16#8A>>, <<1:3>>],
    [{f(fun() -> prim_file:internal_name2native(N) end)} || N <- Names] ++
    [{f(fun() -> prim_file:internal_native2name(B) end),
      f(fun() -> prim_file:internal_normalize_utf8(B) end),
      f(fun() -> prim_file:is_translatable(B) end)} || B <- Bins] ++
    [file:native_name_encoding(), io:printable_range()].
"#;
    let beam = reference
        .compile_named("unicode_filename_differential", source, &[])
        .unwrap();
    reference
        .load("unicode_filename_differential", &beam)
        .unwrap();
    let expected = reference.call("unicode_filename_differential", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("unicode_filename_differential", "run", &[], 1)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
