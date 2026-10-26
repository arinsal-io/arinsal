use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

#[test]
fn small_iolist_reductions_match_both_otp_passes() {
    let reference = RefErl::start().expect("OTP 29 reference");
    let source = r#"
-module(iolist_reductions).
-export([run/0]).
run() ->
    process_flag(min_heap_size, 100000),
    erlang:garbage_collect(),
    Inputs = [[], [<<>>], [<<1,2,3>>], [1], [1,2,3],
              [[1], [2,3], <<4,5>>], lists:duplicate(31, 97),
              lists:duplicate(63, 97), lists:duplicate(64, 97),
              lists:duplicate(65, 97), [lists:duplicate(16, <<1,2,3,4>>)]],
    [measure(F, X) || F <- [fun erlang:iolist_to_binary/1,
                           fun erlang:list_to_binary/1,
                           fun binary:list_to_bin/1], X <- Inputs]
        ++ [measure(fun erlang:iolist_to_binary/1, <<1,2,3>>)].
measure(F, X) ->
    {reductions, Before} = process_info(self(), reductions),
    loop(F, X, 20),
    {reductions, After} = process_info(self(), reductions),
    After - Before.
loop(_, _, 0) -> ok;
loop(F, X, N) -> F(X), loop(F, X, N - 1).
"#;
    let beam = reference
        .compile_named("iolist_reductions", source, &[])
        .unwrap();
    reference.load("iolist_reductions", &beam).unwrap();
    let expected = reference.call("iolist_reductions", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("iolist_reductions", "run", &[], 1, None)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
