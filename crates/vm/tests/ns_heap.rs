//! Heap accounting of a namespace and the `max_bytes` cap.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(ns_heap_t).
-compile([export_all, nowarn_export_all]).

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_heap_t, wrapper, [Fun]),
    Ref = erlang:monitor(process, P),
    {P, Ref}.

go({P, _Ref} = H) -> P ! go, H.

await({P, Ref}) ->
    receive
        {'DOWN', Ref, process, P, {r, R}} -> R;
        {'DOWN', Ref, process, P, Other} -> {crashed, Other}
    after 5000 -> timeout
    end.

in_ns(Ns, Fun) -> await(go(start_in(Ns, Fun))).

settle() -> receive after 150 -> ok end.

check({P, _} = H) -> P ! check, H.

holder(Ns, Setup, Fun) ->
    go(start_in(Ns, fun() ->
        S = Setup(),
        receive check -> ok end,
        Fun(S)
    end)).

mk(Name, Opts) ->
    {ok, Ns} = arinsal_ns:create(Name, <<"shop">>, Opts),
    Ns.

heap_words(Ns) -> maps:get(heap_words, arinsal_ns:info(Ns)).

wait_until(Fun, Tries) ->
    case Fun() of
        true -> true;
        _ when Tries =< 0 -> false;
        _ -> receive after 50 -> ok end, wait_until(Fun, Tries - 1)
    end.

ns_heap_accounting_grows_and_shrinks() ->
    Ns = mk(<<"acme">>, #{}),
    Other = mk(<<"globex">>, #{}),
    Idle = heap_words(Ns),
    H = holder(Ns, fun() ->
        L = lists:seq(1, 300000),
        erlang:garbage_collect(),
        L
    end, fun(L) -> length(L) end),
    Grew = wait_until(fun() -> heap_words(Ns) >= 300000 end, 60),
    During = heap_words(Ns),
    OtherDuring = heap_words(Other),
    EtsWords = maps:get(ets_words, arinsal_ns:info(Ns)),
    check(H),
    Len = await(H),
    Shrunk = wait_until(fun() -> heap_words(Ns) =< Idle + 100 end, 60),
    case {Grew, Len, Shrunk, OtherDuring, is_integer(EtsWords)} of
        {true, 300000, true, 0, true} when During >= 300000 -> ok;
        Other -> {bad, Other, Idle, During, heap_words(Ns)}
    end.

ns_max_bytes_destroys_ns_only() ->
    Capped = mk(<<"acme">>, #{max_bytes => 1000000}),
    Other = mk(<<"globex">>, #{}),
    Survivor = holder(Other, fun() ->
        L = lists:seq(1, 1000),
        erlang:garbage_collect(),
        L
    end, fun(L) -> length(L) end),
    Victim = go(start_in(Capped, fun() ->
        L = lists:seq(1, 500000),
        erlang:garbage_collect(),
        receive never -> L end
    end)),
    Gone = wait_until(fun() -> not lists:member(Capped, arinsal_ns:list()) end, 60),
    Reason = await(Victim),
    Drained = wait_until(fun() -> maps:get(processes, arinsal_ns:info(Capped)) =:= 0 end, 60),
    Spawn = (catch arinsal_ns:spawn(Capped, erlang, self, [])),
    InOther = lists:member(Other, arinsal_ns:list()),
    check(Survivor),
    Alive = await(Survivor),
    Again = in_ns(Other, fun() -> alive end),
    case {Gone, Reason, Drained, Spawn, InOther, Alive, Again} of
        {true, {crashed, killed}, true, {'EXIT', {badarg, _}}, true, 1000, alive} -> ok;
        Other2 -> {bad, Other2}
    end.
"#;

fn run(entry: &str) {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {entry}");
        return;
    };
    let beam = reference
        .compile_named("ns_heap_t", SOURCE, &[])
        .expect("compile ns_heap_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_heap_t");
    let actual = vm
        .eval_scheduled("ns_heap_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

#[test]
fn ns_heap_accounting_grows_and_shrinks() {
    run("ns_heap_accounting_grows_and_shrinks");
}

#[test]
fn ns_max_bytes_destroys_ns_only() {
    run("ns_max_bytes_destroys_ns_only");
}
