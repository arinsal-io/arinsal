//! Garbage collection after a dirty NIF call against erl 29.1.1: the words a dirty job leaves
//! in the process count towards the next GC test by the words used, not by the capacity of the
//! shadow heap block the job ran on, and the result of the job lies on the process heap (the
//! heap top moves past it) whenever it fits, as erts_flush_dirty_shadow_proc leaves it.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;

const SOURCE: &str = r##"
-module(dirty_shadow_gc_differential).
-export([run/1]).

run(MinHeap) ->
    Base = case os:getenv("TMPDIR") of false -> "/tmp"; T -> T end,
    File = filename:join(Base, "dirty_shadow_gc_" ++ os:getpid() ++ "_" ++ integer_to_list(MinHeap)),
    ok = prim_file:write_file(File, binary:copy(<<"abcdefgh">>, 3500)),
    Parent = self(),
    Tracer = spawn(fun() -> collect([]) end),
    Worker = spawn_opt(fun() ->
        receive go -> ok end,
        {ok, Bin} = prim_file:read_file(File),
        Parent ! {done, self(), byte_size(Bin)}
    end, [{min_heap_size, MinHeap}]),
    1 = erlang:trace(Worker, true, [garbage_collection, {tracer, Tracer}]),
    Worker ! go,
    Size = receive {done, Worker, S} -> S end,
    Tracer ! {dump, self()},
    Events = receive {events, L} -> L end,
    prim_file:delete(File),
    {Size, [event(E) || E <- Events]}.

event({trace, _, Tag, Info}) ->
    {Tag, [proplists:get_value(K, Info) || K <- [heap_size, heap_block_size, old_heap_size, old_heap_block_size, stack_size, recent_size, bin_vheap_size]]}.

collect(Acc) ->
    receive
        {dump, From} -> From ! {events, lists:reverse(Acc)};
        {trace, _, Tag, _} = E when Tag =:= gc_minor_start; Tag =:= gc_major_start;
                                    Tag =:= gc_minor_end; Tag =:= gc_major_end ->
            collect([E | Acc]);
        _ -> collect(Acc)
    end.
"##;

fn reference() -> Option<RefErl> {
    match RefErl::start() {
        Ok(reference) => Some(reference),
        Err(_) => {
            eprintln!("erl unavailable; skipping dirty shadow GC differential");
            None
        }
    }
}

fn assert_matches_otp(min_heap: i64, expected_events: Option<usize>) {
    let Some(reference) = reference() else {
        return;
    };
    let beam = reference
        .compile_named("dirty_shadow_gc_differential", SOURCE, &[])
        .expect("compile dirty_shadow_gc_differential");
    reference
        .load("dirty_shadow_gc_differential", &beam)
        .expect("load into erl");
    let expected = reference.call(
        "dirty_shadow_gc_differential",
        "run",
        &[OwnedTerm::Int(min_heap)],
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled(
            "dirty_shadow_gc_differential",
            "run",
            &[Term::small(min_heap).unwrap()],
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("min_heap_size {min_heap}: {error}"));
    if let Some(count) = expected_events {
        let OwnedTerm::Tuple(fields) = &actual.term else {
            panic!("result {:?}", actual.term)
        };
        let OwnedTerm::List { elems, .. } = &fields[1] else {
            assert_eq!(count, 0, "no events expected: {:?}", fields[1]);
            return;
        };
        assert_eq!(elems.len(), count, "GC events: {:?}", fields[1]);
    }
    assert_eq!(
        expected,
        CallResult::Ok(actual.term.clone()),
        "min_heap_size {min_heap}"
    );
}

#[test]
fn small_dirty_nif_result_does_not_trigger_gc_as_otp() {
    assert_matches_otp(100, Some(0));
}

#[test]
fn small_dirty_nif_result_with_default_heap_matches_otp() {
    assert_matches_otp(233, Some(0));
}

#[test]
fn small_dirty_nif_result_with_larger_heap_matches_otp() {
    assert_matches_otp(376, Some(0));
}

const PLACEMENT_SOURCE: &str = r##"
-module(dirty_result_placement_differential).
-export([run/3]).

run(MinHeap, Op, N) ->
    Base = case os:getenv("TMPDIR") of false -> "/tmp"; T -> T end,
    File = filename:join(Base, "dirty_place_" ++ os:getpid() ++ "_" ++ integer_to_list(MinHeap) ++ atom_to_list(Op) ++ integer_to_list(N)),
    ok = prim_file:write_file(File, binary:copy(<<"abcdefgh">>, 300)),
    Parent = self(),
    Tracer = spawn(fun() -> collect([]) end),
    Worker = spawn_opt(fun() ->
        receive go -> ok end,
        Samples = loop(Op, N, File, []),
        Parent ! {done, self(), Samples}
    end, [{min_heap_size, MinHeap}]),
    1 = erlang:trace(Worker, true, [garbage_collection, {tracer, Tracer}]),
    Worker ! go,
    Samples = receive {done, Worker, S} -> S end,
    Tracer ! {dump, self()},
    Events = receive {events, L} -> L end,
    prim_file:delete(File),
    {Samples, [event(E) || E <- Events]}.

loop(_Op, 0, _File, Acc) -> lists:reverse(Acc);
loop(Op, N, File, Acc) ->
    R = call(Op, File),
    {heap_size, HeapSize} = process_info(self(), heap_size),
    {total_heap_size, Total} = process_info(self(), total_heap_size),
    Sample = {HeapSize, Total, element(1, R)},
    loop(Op, N - 1, File, [Sample | Acc]).

call(none, _File) -> {ok, none};
call(read, File) -> prim_file:read_file(File);
call(info, File) -> prim_file:read_file_info(File);
call(both, File) ->
    {ok, _} = prim_file:read_file_info(File),
    prim_file:read_file(File).

event({trace, _, Tag, Info}) ->
    {Tag, [proplists:get_value(K, Info) || K <- [heap_block_size, old_heap_block_size]]}.

collect(Acc) ->
    receive
        {dump, From} -> From ! {events, lists:reverse(Acc)};
        {trace, _, Tag, _} = E when Tag =:= gc_minor_start; Tag =:= gc_major_start;
                                    Tag =:= gc_minor_end; Tag =:= gc_major_end ->
            collect([E | Acc]);
        _ -> collect(Acc)
    end.
"##;

static PLACEMENT_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn assert_placement_matches_otp(min_heap: i64, op: &str, calls: i64) {
    let _serial = PLACEMENT_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(reference) = reference() else {
        return;
    };
    let beam = reference
        .compile_named("dirty_result_placement_differential", PLACEMENT_SOURCE, &[])
        .expect("compile dirty_result_placement_differential");
    reference
        .load("dirty_result_placement_differential", &beam)
        .expect("load into erl");
    let op_atom = || Term::atom(global_atoms().intern(op).expect("atom"));
    let expected = reference.call(
        "dirty_result_placement_differential",
        "run",
        &[
            OwnedTerm::Int(min_heap),
            OwnedTerm::Atom(op.to_string()),
            OwnedTerm::Int(calls),
        ],
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled(
            "dirty_result_placement_differential",
            "run",
            &[
                Term::small(min_heap).unwrap(),
                op_atom(),
                Term::small(calls).unwrap(),
            ],
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("{op} x{calls} min_heap_size {min_heap}: {error}"));
    if let (CallResult::Ok(OwnedTerm::Tuple(want)), OwnedTerm::Tuple(got)) =
        (&expected, &actual.term)
    {
        for (part, (want, got)) in ["samples", "gc events"].iter().zip(want.iter().zip(got)) {
            let (OwnedTerm::List { elems: want, .. }, OwnedTerm::List { elems: got, .. }) =
                (want, got)
            else {
                continue;
            };
            let first = want.iter().zip(got).position(|(want, got)| want != got);
            assert!(
                first.is_none() && want.len() == got.len(),
                "{op} x{calls} min_heap_size {min_heap}: {part} differ at {first:?}\nerl:     {:?}\narinsal: {:?}",
                first.map(|at| &want[at]),
                first.map(|at| &got[at]),
            );
        }
    }
    assert_eq!(
        expected,
        CallResult::Ok(actual.term.clone()),
        "{op} x{calls} min_heap_size {min_heap}"
    );
}

macro_rules! placement_tests {
    ($($name:ident: $heap:expr, $op:expr, $calls:expr;)*) => {
        $(
            #[test]
            fn $name() {
                assert_placement_matches_otp($heap, $op, $calls);
            }
        )*
    };
}

placement_tests! {
    read_file_result_placement_min_heap_100_matches_otp: 100, "read", 12;
    read_file_result_placement_min_heap_233_matches_otp: 233, "read", 12;
    read_file_result_placement_min_heap_376_matches_otp: 376, "read", 12;
    read_file_info_result_placement_min_heap_100_matches_otp: 100, "info", 12;
    read_file_info_result_placement_min_heap_233_matches_otp: 233, "info", 12;
    read_file_info_result_placement_min_heap_376_matches_otp: 376, "info", 12;
    mixed_dirty_results_min_heap_100_matches_otp: 100, "both", 10;
    mixed_dirty_results_min_heap_233_matches_otp: 233, "both", 10;
    process_info_sampling_without_dirty_calls_min_heap_100_matches_otp: 100, "none", 12;
    process_info_sampling_without_dirty_calls_min_heap_233_matches_otp: 233, "none", 12;
}
