//! `integer_to_list` places its whole result in one allocation, so the GC
//! events of a process that calls it under a live frame match OTP.
//!
//! A non-tail recursion keeps a frame per element and calls `integer_to_list`
//! in each. When the heap is nearly full, OTP puts all digit cells on the heap
//! or all in one fragment. Building them one cell at a time split the run
//! between the two and moved the heap top, the fragment size and with them the
//! collection point.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "list_halloc_differential";
const SOURCE: &str = r#"
-module(list_halloc_differential).
-export([probe/0, run/1, r/2]).

probe() ->
    [one(S, N) || S <- [il, cons, app], N <- [45, 50, 55, 60, 65, 70, 80]].

one(S, N) ->
    Me = self(),
    Tr = spawn(fun() -> col([]) end),
    P = spawn(list_halloc_differential, run, [{S, N}]),
    erlang:trace(P, true, [garbage_collection, {tracer, Tr}]),
    P ! {go, Me},
    receive {done, Info} -> ok end,
    Tr ! {dump, self()},
    receive {ev, L} ->
        {S, N, [heap_stack(E) || {trace, _, gc_minor_start, _} = E <- L], Info}
    end.

heap_stack({trace, _, _, I}) ->
    [proplists:get_value(K, I) || K <- [heap_size, stack_size]].

col(Acc) ->
    receive
        {dump, From} -> From ! {ev, lists:reverse(Acc)};
        E -> col([E | Acc])
    end.

run({S, N}) ->
    receive {go, Me} -> ok end,
    L = lists:seq(1, N),
    r(S, L),
    {garbage_collection, G} = process_info(self(), garbage_collection),
    Me ! {done, proplists:get_value(minor_gcs, G)}.

r(_, []) -> 0;
r(K, [H | T]) -> X = b(K, H), Y = r(K, T), length(X) + Y.

b(il, H) -> integer_to_list(H);
b(cons, H) -> [H, H, H];
b(app, H) -> [H] ++ [H, H].
"#;

fn render(term: &OwnedTerm) -> String {
    format!("{term:?}")
}

#[test]
fn integer_to_list_gc_events_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping list allocation differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile probe");
    reference.load(MODULE, &beam).expect("load probe");
    let expected = match reference.call(MODULE, "probe", &[]) {
        CallResult::Ok(term) => term,
        other => panic!("reference probe failed: {other:?}"),
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load probe into Arinsal");
    let actual = vm
        .eval_scheduled(MODULE, "probe", &[], 1, None)
        .unwrap_or_else(|error| panic!("Arinsal probe failed: {error:?}"))
        .term;
    assert_eq!(render(&actual), render(&expected));
}
