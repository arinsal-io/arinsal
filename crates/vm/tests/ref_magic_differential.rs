use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ref_magic_differential).
-export([run/0]).

check(Ref, Use) ->
    Text = erlang:ref_to_list(Ref),
    Printed = lists:flatten(io_lib:format("~p", [Ref])),
    Restored = erlang:list_to_ref(Text),
    {length(string:tokens(Text, ".")),
     Printed =:= Text,
     erlang:is_reference(Restored),
     erlang:phash2(Ref) =:= erlang:phash2(Restored),
     Ref =:= Restored,
     Ref < Restored,
     Restored < Ref,
     Use(Restored)}.

run() ->
    Atomic = atomics:new(1, []),
    Match = ets:match_spec_compile([{{'$1'}, [], [true]}]),
    {bm, Binary} = binary:compile_pattern(<<"needle">>),
    [check(Atomic, fun(Ref) -> atomics:get(Ref, 1) =:= 0 end),
     check(Match, fun(Ref) -> ets:match_spec_run([{value}], Ref) =:= [true] end),
     check(Binary, fun(Ref) -> binary:match(<<"a needle">>, {bm, Ref}) =:= {2, 6} end)].
"#;

#[test]
fn magic_reference_text_roundtrips_and_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping magic reference differential test");
        return;
    };
    let beam = reference
        .compile_named("ref_magic_differential", SOURCE, &[])
        .expect("compile ref_magic_differential");
    reference
        .load("ref_magic_differential", &beam)
        .expect("load into erl");
    let expected = reference.call("ref_magic_differential", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled("ref_magic_differential", "run", &[], 1, Some(79))
        .expect("run in arinsal");

    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}
