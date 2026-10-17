//! Garbage collection after a dirty NIF call against erl 29.1.1: the words a dirty job leaves
//! in the process count towards the next GC test by the words used, not by the capacity of the
//! shadow heap block the job ran on.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
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
