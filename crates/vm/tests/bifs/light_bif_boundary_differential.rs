//! Where a BIF result lands at the free-word boundary, against erl 29.1.1.
//!
//! A BIF allocates with HAlloc against `E - S_REDZONE` and the epilogue of the light BIF call
//! collects when `E - HTOP` is below the heap fragment words. A BIF that the scheduler runs for
//! native code (`erts_internal:prepare_loading/2` here) must see the same `E`: the return
//! address the executor pushes for the call is not on erts' stack while the BIF body runs. One
//! word too low moved the 3-word magic ref into a heap fragment at the boundary where erts keeps
//! it on the heap, and with it every later free-word test of the process.
//!
//! The probe sweeps the number of live words `K` so the BIF is entered with every free-word
//! count around the boundary, then reads `minor_gcs`, `heap_size`, `mbuf_size` and `stack_size`
//! of the idle process from outside. Nothing in the probed process is traced: the default
//! tracer builds its messages on the tracee's heap in erl, which would move the boundary.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

const MODULE: &str = "light_bif_boundary_differential";
const TARGET: &str = "light_bif_boundary_target";

const SOURCE: &str = r##"
-module(light_bif_boundary_differential).
-export([run/2, body/4]).

run(Beam, Step) ->
    persistent_term:put({light_bif_boundary_differential, beam}, Beam),
    [one(Step, K) || K <- lists:seq(170, 250)].

one(Step, K) ->
    Me = self(),
    P = spawn_opt(light_bif_boundary_differential, body, [Me, Step, K, persistent_term:get({light_bif_boundary_differential, beam})],
                  [{min_heap_size, 233}]),
    P ! go,
    receive ready -> ok end,
    {garbage_collection_info, I} = process_info(P, garbage_collection_info),
    {garbage_collection, G} = process_info(P, garbage_collection),
    P ! stop,
    {K, proplists:get_value(minor_gcs, G),
     [proplists:get_value(X, I) || X <- [heap_size, mbuf_size, stack_size]]}.

body(Parent, Step, K, _Beam) ->
    receive go -> ok end,
    erlang:garbage_collect(),
    Live = lists:duplicate(K div 2, a),
    R = step(Step, K),
    Parent ! ready,
    receive stop -> ok end,
    case erlang:phash2({Live, R}) of -1 -> ok; _ -> ok end.

step(nop, _) -> ok;
step(int_to_list, K) -> integer_to_list(K);
step(list_to_atom, _) -> list_to_atom(id("m212"));
step(prepare_tail, _) ->
    erts_internal:prepare_loading(light_bif_boundary_target, persistent_term:get({light_bif_boundary_differential, beam}));
step(prepare_frame, _) ->
    frame(persistent_term:get({light_bif_boundary_differential, beam}));
step(prepare_erlang, _) ->
    erlang:prepare_loading(light_bif_boundary_target, persistent_term:get({light_bif_boundary_differential, beam})).

frame(Beam) ->
    R = erts_internal:prepare_loading(light_bif_boundary_target, Beam),
    {R}.

id(X) -> X.
"##;

const TARGET_SOURCE: &str =
    "-module(light_bif_boundary_target). -export([f/0]). f() -> {ok, [1,2,3]}.";

fn compare(step: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping light BIF boundary differential");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile");
    reference.load(MODULE, &beam).expect("load into erl");
    let target = reference
        .compile_named(TARGET, TARGET_SOURCE, &[])
        .expect("compile target");
    let owned_args = vec![OwnedTerm::Binary(target), OwnedTerm::Atom(step.into())];
    let expected = reference.call(MODULE, "run", &owned_args);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let mut heap = VecHeap::new();
    let args: Vec<_> = owned_args
        .iter()
        .map(|term| from_owned(term, &mut heap).unwrap())
        .collect();
    let actual = vm
        .eval_scheduled(MODULE, "run", &args, 2, None)
        .unwrap_or_else(|error| panic!("{step}: {error}"));
    let actual = CallResult::Ok(actual.term);
    if expected != actual {
        let (
            CallResult::Ok(OwnedTerm::List { elems: want, .. }),
            CallResult::Ok(OwnedTerm::List { elems: got, .. }),
        ) = (&expected, &actual)
        else {
            panic!("{step}\nexpected {expected:?}\nactual {actual:?}");
        };
        for (want, got) in want.iter().zip(got) {
            assert_eq!(want, got, "{step}");
        }
        assert_eq!(want.len(), got.len(), "{step}");
    }
}

#[test]
fn bif_free_after_nothing_matches_otp() {
    compare("nop");
}

#[test]
fn integer_to_list_boundary_matches_otp() {
    compare("int_to_list");
}

#[test]
fn list_to_atom_boundary_matches_otp() {
    compare("list_to_atom");
}

#[test]
fn prepare_loading_tail_call_boundary_matches_otp() {
    compare("prepare_tail");
}

#[test]
fn prepare_loading_with_caller_frame_boundary_matches_otp() {
    compare("prepare_frame");
}

#[test]
fn prepare_loading_wrapper_boundary_matches_otp() {
    compare("prepare_erlang");
}
