use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

/// A select that traps keeps the results it already has as terms of the caller's heap. Another
/// process collects the caller between the traps, and the results must survive it.
const SOURCE: &str = r#"
-module(ets_select_gc_diff).
-export([run/0]).

run() ->
    [one(Type) || Type <- [set, ordered_set]].

one(Type) ->
    T = ets:new(t, [Type, public]),
    ets:insert(T, [{K, lists:seq(1, 12), {K, [K]}} || K <- lists:seq(1, 6000)]),
    Self = self(),
    Collector = spawn(fun() -> collect(Self, 400) end),
    Rows = [ets:select(T, [{'$1', [], ['$1']}]),
            ets:match_object(T, '_'),
            ets:tab2list(T),
            ets:select(T, [{{'$1', '_', '_'}, [], ['$1']}])],
    Collector ! stop,
    [{length(R), erlang:phash2(lists:sort(R))} || R <- Rows].

collect(Pid, 0) -> Pid ! done;
collect(Pid, N) ->
    receive stop -> ok after 0 -> erlang:garbage_collect(Pid), collect(Pid, N - 1) end.
"#;

#[test]
fn trapped_select_results_survive_collections() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let beam = reference
        .compile_named("ets_select_gc_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_select_gc_diff", &beam).unwrap();
    let expected = reference.call("ets_select_gc_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("ets_select_gc_diff", "run", &[], 2, Some(81))
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}
