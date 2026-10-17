//! `process_info` builds its whole result with one up-front sizing and one allocation per
//! part, so the heap placement and the GC events of the calling process match OTP.
//!
//! A process holds `K` words of live data, calls `process_info` on itself and then collects.
//! When the free heap is smaller than the result, OTP puts each part (the 55 words of the
//! `garbage_collection_info` rows, a 2-tuple, a cons cell) on the heap or whole in a heap
//! fragment. Building the rows cell by cell split a part between the two and moved the heap
//! top and the fragment size, and with them the first collection point and the stack size at
//! it.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "process_info_halloc_differential";
const SOURCE: &str = r#"
-module(process_info_halloc_differential).
-export([probe/0, run/3]).

probe() ->
    [{Mode, K, one(Mode, K)}
     || Mode <- [list, one, gci, gc, all],
        K <- lists:seq(150, 216, 6)].

one(Mode, K) ->
    Me = self(),
    Tr = spawn(fun() -> col([]) end),
    P = spawn(process_info_halloc_differential, run, [Me, Mode, K]),
    erlang:trace(P, true, [garbage_collection, {tracer, Tr}]),
    P ! go,
    receive {P, done, Info} -> ok end,
    Tr ! {dump, self()},
    receive {ev, L} ->
        {[f(E) || {trace, _, gc_minor_start, _} = E <- L],
         length([E || {trace, _, T, _} = E <- L, T =:= gc_minor_start orelse T =:= gc_major_start]),
         Info}
    end.

f({trace, _, _, I}) ->
    [proplists:get_value(K, I) || K <- [heap_size, heap_block_size, mbuf_size, stack_size]].

col(Acc) ->
    receive
        {dump, From} -> From ! {ev, lists:reverse(Acc)};
        E -> col([E | Acc])
    end.

run(Parent, Mode, K) ->
    receive go -> ok end,
    erlang:garbage_collect(),
    L = lists:duplicate(K div 2, a),
    R = case Mode of
        list -> process_info(self(), [heap_size, total_heap_size, min_heap_size, garbage_collection]);
        one -> process_info(self(), heap_size);
        gci -> process_info(self(), garbage_collection_info);
        gc -> process_info(self(), garbage_collection);
        all -> process_info(self())
    end,
    erlang:garbage_collect(self(), [{type, minor}]),
    Parent ! {self(), done, is_list(R) orelse is_tuple(R)},
    keep(L, R).

keep(L, R) ->
    case erlang:phash2({L, R}) of
        -1 -> ok;
        _ -> ok
    end.
"#;

fn render(term: &OwnedTerm) -> String {
    format!("{term:?}")
}

#[test]
fn process_info_result_placement_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process_info allocation differential test");
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
    let (
        OwnedTerm::List { elems: actual, .. },
        OwnedTerm::List {
            elems: expected, ..
        },
    ) = (&actual, &expected)
    else {
        panic!("probe did not return lists");
    };
    assert_eq!(actual.len(), expected.len());
    let differing: Vec<String> = actual
        .iter()
        .zip(expected)
        .filter(|(left, right)| render(left) != render(right))
        .map(|(left, right)| format!("arinsal {}\n   erl     {}", render(left), render(right)))
        .collect();
    assert!(
        differing.is_empty(),
        "{} of {} cases differ:\n{}",
        differing.len(),
        expected.len(),
        differing.join("\n")
    );
}
