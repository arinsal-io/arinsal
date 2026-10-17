//! Garbage collection after the `send` instruction against erl 29.1.1: erts runs `send` through
//! the light-BIF path, so a send that returns with heap fragments larger than the free heap
//! collects at once. The process builds a tuple that does not fit its heap, returns to a shallow
//! stack and sends; the heap and stack sizes of every collection must equal erl's.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r##"
-module(send_gc_after_bif_differential).
-export([run/1, body/3, deep/3, t/3]).

run(K) ->
    [one(Kind, K) || Kind <- [send, send_name, bif]].

one(Kind, K) ->
    Me = self(),
    catch unregister(send_gc_target),
    true = register(send_gc_target, Me),
    Tracer = spawn(fun() -> collect([]) end),
    P = spawn(send_gc_after_bif_differential, body, [Kind, 10, K]),
    1 = erlang:trace(P, true, [garbage_collection, {tracer, Tracer}]),
    P ! {go, Me},
    receive done -> ok end,
    Tracer ! {dump, self()},
    receive {events, L} -> {Kind, [event(E) || {trace, _, gc_minor_start, _} = E <- L]} end.

body(Kind, D, K) ->
    code:ensure_loaded(send_gc_after_bif_differential),
    receive {go, Me} -> ok end,
    send_gc_after_bif_differential:deep(Kind, D, K),
    case Kind of
        send -> Me ! done;
        send_name -> send_gc_target ! done;
        bif -> erlang:phash2(K), Me ! done
    end.

deep(Kind, 0, K) -> t(Kind, K, x);
deep(Kind, D, K) -> {deep(Kind, D - 1, K), D}.

t(_Kind, K, _) ->
    P = erlang:make_tuple(K, 0),
    X = integer_to_list(5555),
    {P, X, length(X)}.

event({trace, _, _, Info}) ->
    [proplists:get_value(K, Info) || K <- [heap_size, stack_size]].

collect(Acc) ->
    receive
        {dump, From} -> From ! {events, lists:reverse(Acc)};
        {trace, _, _, _} = E -> collect([E | Acc]);
        _ -> collect(Acc)
    end.
"##;

fn assert_matches_otp(k: i64) {
    let reference = match RefErl::start() {
        Ok(reference) => reference,
        Err(_) => {
            eprintln!("erl unavailable; skipping send GC differential");
            return;
        }
    };
    let beam = reference
        .compile_named("send_gc_after_bif_differential", SOURCE, &[])
        .expect("compile send_gc_after_bif_differential");
    reference
        .load("send_gc_after_bif_differential", &beam)
        .expect("load into erl");
    let expected = reference.call(
        "send_gc_after_bif_differential",
        "run",
        &[OwnedTerm::Int(k)],
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled(
            "send_gc_after_bif_differential",
            "run",
            &[Term::small(k).unwrap()],
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("K {k}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term.clone()), "K {k}");
}

#[test]
fn send_after_fragment_matches_otp_192() {
    assert_matches_otp(192);
}

#[test]
fn send_after_fragment_matches_otp_193() {
    assert_matches_otp(193);
}

#[test]
fn send_after_fragment_matches_otp_194() {
    assert_matches_otp(194);
}

#[test]
fn send_after_fragment_matches_otp_range() {
    for k in 185..=200 {
        assert_matches_otp(k);
    }
}
