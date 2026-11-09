//! ETS chunk continuations keep their match program alive while the caller retains the token.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "ets_continuation_reuse";
const SOURCE: &str = r#"
-module(ets_continuation_reuse).
-export([whitebox/0]).

whitebox() ->
    [bag_reuse() || _ <- lists:seq(1, 3)] ++
    [ordered_reuse() || _ <- lists:seq(1, 3)].

bag_reuse() ->
    T = ets:new(x, [bag]),
    true = ets:insert(T, [{du,glade},{ta,en},{hej,hopp2},{du,glade2},{ta,en2}]),
    {_, C} = ets:match(T, {ta,'$1'}, 1),
    _ = ets:select(C),
    _ = ets:match(C),
    true = ets:delete(T),
    ok.

ordered_reuse() ->
    T = ets:new(x, [ordered_set]),
    true = ets:insert(T, [{{ta,1},en},{{ta,2},en2}]),
    {_, C} = ets:match(T, {{ta,'$1'},'$2'}, 1),
    _ = ets:select(C),
    _ = ets:match(C),
    true = ets:delete(T),
    ok.
"#;

#[test]
fn ets_match_continuations_remain_reusable() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ETS continuation differential test");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "whitebox", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "whitebox", &[], 2, Some(81))
        .unwrap_or_else(|error| panic!("whitebox: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
