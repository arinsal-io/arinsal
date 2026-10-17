//! GC timing around `erlang:prepare_loading/2` against erl 29.1.1: the magic ref is allocated
//! with HAlloc (a heap fragment when the young heap is full, never a collection inside the
//! BIF) and the magic binary charges the size of erts' loader state to the virtual binary
//! heap.
//!
//! Event sizes are `heap_size + mbuf_size`: whether the 3-word ref lands on the heap or in a
//! fragment right at the free-word boundary also depends on the Erlang frame words at the BIF
//! call, which this change does not touch.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

const MODULE: &str = "prepare_loading_gc_differential";
const TARGET: &str = "prepare_loading_gc_target";

const SOURCE: &str = r##"
-module(prepare_loading_gc_differential).
-export([run/2, vheap/1]).

run(Beam, Step) ->
    [one(Beam, Step, K) || K <- lists:seq(0, 300, 4)].

one(Beam, Step, K) ->
    Me = self(),
    Tracer = spawn(fun() -> collect([]) end),
    P = spawn_opt(fun() -> body(Me, Beam, Step, K) end, [{min_heap_size, 233}]),
    1 = erlang:trace(P, true, [garbage_collection, {tracer, Tracer}]),
    P ! go,
    receive {P, done} -> ok end,
    Tracer ! {dump, self()},
    Events = receive {events, L} -> L end,
    {K, [fmt(E) || E <- Events]}.

body(Parent, Beam, Step, K) ->
    receive go -> ok end,
    erlang:garbage_collect(),
    Live = lists:duplicate(K div 2, a),
    R = step(Step, Beam),
    erlang:garbage_collect(),
    Parent ! {self(), done},
    keep(Live, R).

keep(Live, R) -> case erlang:phash2({Live, R}) of -1 -> ok; _ -> ok end.

step(prepare, Beam) -> erlang:prepare_loading(prepare_loading_gc_target, Beam);
step(prepare_twice, Beam) ->
    A = erlang:prepare_loading(prepare_loading_gc_target, Beam),
    B = erlang:prepare_loading(prepare_loading_gc_target, Beam),
    {A, B};
step(badfile, Beam) ->
    erlang:prepare_loading(prepare_loading_gc_target, <<"FOR1", (binary:part(Beam, 4, 8))/binary>>).

vheap(Beam) ->
    Me = self(),
    Tracer = spawn(fun() -> collect([]) end),
    P = spawn_opt(fun() ->
        receive go -> ok end,
        erlang:garbage_collect(),
        R = erlang:prepare_loading(prepare_loading_gc_target, Beam),
        erlang:garbage_collect(),
        Me ! {self(), done},
        keep([], R)
    end, [{min_heap_size, 233}]),
    1 = erlang:trace(P, true, [garbage_collection, {tracer, Tracer}]),
    P ! go,
    receive {P, done} -> ok end,
    Tracer ! {dump, self()},
    receive {events, L} -> [fmt(E) || E <- L] end.

fmt({trace, _, Tag, I}) ->
    [Heap, Block, Old, Stack, Vheap, Mbuf] =
        [proplists:get_value(X, I) || X <- [heap_size, heap_block_size, old_heap_size, stack_size, bin_vheap_size, mbuf_size]],
    {Tag, [Heap + Mbuf, Block, Old, Stack, Vheap]}.

collect(Acc) ->
    receive
        {dump, From} -> From ! {events, lists:reverse(Acc)};
        {trace, _, Tag, _} = E when Tag =:= gc_minor_start; Tag =:= gc_major_start;
                                    Tag =:= gc_minor_end; Tag =:= gc_major_end ->
            collect([E | Acc]);
        _ -> collect(Acc)
    end.
"##;

const TARGET_SOURCE: &str =
    "-module(prepare_loading_gc_target). -export([f/0]). f() -> {ok, [1,2,3]}.";

fn compare(function: &str, step: Option<&str>) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping prepare_loading GC differential");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile");
    reference.load(MODULE, &beam).expect("load into erl");
    let target = reference
        .compile_named(TARGET, TARGET_SOURCE, &[])
        .expect("compile target");
    let mut owned_args = vec![OwnedTerm::Binary(target)];
    if let Some(step) = step {
        owned_args.push(OwnedTerm::Atom(step.into()));
    }
    let expected = reference.call(MODULE, function, &owned_args);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let mut heap = VecHeap::new();
    let args: Vec<_> = owned_args
        .iter()
        .map(|term| from_owned(term, &mut heap).unwrap())
        .collect();
    let actual = vm
        .eval_scheduled(MODULE, function, &args, 2, None)
        .unwrap_or_else(|error| panic!("{function} {step:?}: {error}"));
    let actual = CallResult::Ok(actual.term);
    if expected != actual {
        let (
            CallResult::Ok(OwnedTerm::List { elems: want, .. }),
            CallResult::Ok(OwnedTerm::List { elems: got, .. }),
        ) = (&expected, &actual)
        else {
            panic!("{function} {step:?}\nexpected {expected:?}\nactual {actual:?}");
        };
        for (want, got) in want.iter().zip(got) {
            assert_eq!(want, got, "{function} {step:?}");
        }
        assert_eq!(want.len(), got.len(), "{function} {step:?}");
    }
}

#[test]
fn prepare_loading_gc_events_match_otp_across_heap_fill_levels() {
    compare("run", Some("prepare"));
}

#[test]
fn two_prepares_in_one_slice_match_otp() {
    compare("run", Some("prepare_twice"));
}

#[test]
fn prepare_loading_badfile_tuple_matches_otp() {
    compare("run", Some("badfile"));
}

#[test]
fn prepared_magic_ref_charges_the_loader_state_to_bin_vheap() {
    compare("vheap", None);
}
