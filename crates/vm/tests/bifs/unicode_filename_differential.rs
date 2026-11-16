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
    Sweep = [begin
                 D = unicode:characters_to_binary(unicode:characters_to_nfd_list([CP])),
                 {CP, prim_file:internal_normalize_utf8(D)}
             end || CP <- lists:seq(16#C0, 16#3100) ++ [16#1D15E, 16#1F600],
                    %% Lone combining marks and these four decompositions read
                    %% uninitialized saved points in erts; they have no defined result.
                    length(unicode:characters_to_nfd_list([CP])) > 1,
                    not lists:member(CP, [836, 3955, 3957, 3969])],
    Runs = [begin
                D = unicode:characters_to_binary(unicode:characters_to_nfd_list(S)),
                {prim_file:internal_normalize_utf8(D), prim_file:internal_native2name(D)}
            end || S <- ["e\u0301a\u030a", [16#1100, 16#1161, 16#11A8], "\u0041\u0300\u0301\u0302",
                         "x\u0328\u0301", [16#1D157, 16#1D165, 16#1D16E], "\u3046\u3099\u30a6\u3099"]],
    [{erlang:phash2(Sweep), erlang:phash2(Runs)}] ++
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
