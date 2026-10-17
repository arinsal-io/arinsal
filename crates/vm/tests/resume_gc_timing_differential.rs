//! Garbage collection timing of a process resumed after a call-return yield, against erl 29.1.1.
//!
//! erts does no collection when a process is swapped in: it restores registers and jumps, and
//! collects later at an instruction that needs heap, with the callee's continuation word already on
//! the stack. The process below runs `process_info` and `register/2` probes at a sweep of heap fill
//! levels while a tracer records every minor collection; `stack_size`, `heap_size` and
//! `total_heap_size` must equal erl's.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const MODULE: &str = "resume_gc_timing_differential";

const SOURCE: &str = r##"
-module(resume_gc_timing_differential).
-export([run_pi/1, run_reg/1, probe/2, body/3, rbody/2]).

run_pi(K) ->
    [{Mode, K, probe(Mode, K)} || Mode <- [list, one, gci, gc, all]].

probe(Mode, K) ->
    Me = self(),
    Tr = spawn(fun() -> col([]) end),
    P = spawn(resume_gc_timing_differential, body, [Me, Mode, K]),
    erlang:trace(P, true, [garbage_collection, {tracer, Tr}]),
    P ! go,
    receive {P, done} -> ok end,
    Tr ! {dump, self()},
    receive {ev, L} ->
        [f(E) || {trace, _, gc_minor_start, _} = E <- L]
    end.

f({trace, _, _, I}) ->
    [proplists:get_value(K, I) || K <- [heap_size, heap_block_size, mbuf_size, stack_size]].

col(Acc) ->
    receive
        {dump, From} -> From ! {ev, lists:reverse(Acc)};
        E -> col([E | Acc])
    end.

body(Parent, Mode, K) ->
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
    Parent ! {self(), done},
    keep(L, R).

keep(L, R) ->
    case erlang:phash2({L, R}) of
        -1 -> ok;
        _ -> ok
    end.

run_reg(K) ->
    Me = self(),
    P = spawn(resume_gc_timing_differential, rbody, [Me, K]),
    P ! go,
    receive {P, R} -> R end.

rbody(Parent, K) ->
    receive go -> ok end,
    erlang:garbage_collect(),
    L = lists:duplicate(K div 2, a),
    register(rgname, self()),
    rgname ! hi,
    {stack_size, S} = process_info(self(), stack_size),
    {heap_size, H} = process_info(self(), heap_size),
    {total_heap_size, T} = process_info(self(), total_heap_size),
    Parent ! {self(), {S, H, T, length(L)}},
    receive hi -> ok end.
"##;

fn assert_matches_otp(function: &str, ks: impl Iterator<Item = i64> + Clone) {
    let reference = match RefErl::start() {
        Ok(reference) => reference,
        Err(_) => {
            eprintln!("erl unavailable; skipping resume GC timing differential");
            return;
        }
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile resume_gc_timing_differential");
    reference.load(MODULE, &beam).expect("load into erl");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    for k in ks {
        let expected = reference.call(MODULE, function, &[OwnedTerm::Int(k)]);
        let actual = vm
            .eval_scheduled(MODULE, function, &[Term::small(k).unwrap()], 2, None)
            .unwrap_or_else(|error| panic!("{function} K {k}: {error}"));
        assert_eq!(
            expected,
            CallResult::Ok(actual.term.clone()),
            "{function} K {k}"
        );
    }
}

#[test]
fn process_info_probe_list_170() {
    assert_matches_otp("run_pi", std::iter::once(170));
}

#[test]
fn process_info_probe_one_222() {
    assert_matches_otp("run_pi", std::iter::once(222));
}

#[test]
fn process_info_probe_gc_188() {
    assert_matches_otp("run_pi", std::iter::once(188));
}

#[test]
fn process_info_probe_sweep() {
    assert_matches_otp("run_pi", (150..=232).step_by(2));
}

#[test]
fn register_send_total_heap_size_218() {
    assert_matches_otp("run_reg", std::iter::once(218));
}

#[test]
fn register_send_total_heap_size_sweep() {
    assert_matches_otp("run_reg", (130..=236).step_by(2));
}
