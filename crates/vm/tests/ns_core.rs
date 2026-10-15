//! Namespace word, spawn inheritance and the delivery check.
//!
//! A namespace process cannot message root (root is not shared), so each test runs its probe
//! in a namespace process and reads the result from the exit reason that the root monitor sees.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(ns_core_t).
-compile([export_all, nowarn_export_all]).

mk(Name) ->
    {ok, Ns} = arinsal_ns:create(Name, <<"shop">>, #{}),
    Ns.

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_core_t, wrapper, [Fun]),
    Ref = erlang:monitor(process, P),
    {P, Ref}.

result({P, Ref}) ->
    P ! go,
    await(P, Ref).

await(P, Ref) ->
    receive
        {'DOWN', Ref, process, P, {r, R}} -> R;
        {'DOWN', Ref, process, P, Other} -> {crashed, Other}
    after 5000 -> timeout
    end.

in_ns(Ns, Fun) -> result(start_in(Ns, Fun)).

%% A process of Ns that returns the first message it receives.
receiver(Ns) ->
    start_in(Ns, fun() -> receive M -> {got, M} end end).

ns_spawn_inherits_ns() ->
    Ns = mk(<<"acme">>),
    {Own, Child, ChildOfChild} =
        in_ns(Ns, fun() ->
            Me = self(),
            C = spawn(fun() ->
                receive {From, q} -> From ! {ns, arinsal_ns:'of'(self()), arinsal_ns:'of'(From)} end
            end),
            C ! {Me, q},
            receive {ns, N, Parent} -> {arinsal_ns:'of'(Me), N, Parent} after 2000 -> timeout end
        end),
    case {Own, Child, ChildOfChild, arinsal_ns:'of'(self())} of
        {Ns, Ns, Ns, 0} when Ns > 0 -> ok;
        Other -> {bad, Ns, Other}
    end.

ns_delivery_same_ns_ok() ->
    Ns = mk(<<"acme">>),
    case in_ns(Ns, fun() ->
            Me = self(),
            B = spawn(fun() -> receive {From, ping} -> From ! pong end end),
            B ! {Me, ping},
            receive pong -> same_ns_ok after 2000 -> timeout end
        end) of
        same_ns_ok -> ok;
        Other -> {bad, Other}
    end.

ns_delivery_cross_ns_dropped() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    {PB, RefB} = receiver(N2),
    PB ! go,
    Sent = in_ns(N1, fun() -> PB ! hello end),
    PB ! release,
    Got = await(PB, RefB),
    case {Sent, Got} of
        {hello, {got, release}} -> ok;
        Other -> {bad, Other}
    end.

ns_root_can_send_into_ns() ->
    Ns = mk(<<"acme">>),
    {PB, RefB} = receiver(Ns),
    PB ! go,
    PB ! ping,
    case await(PB, RefB) of
        {got, ping} -> ok;
        Other -> {bad, Other}
    end.

ns_link_cross_ns_noproc() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    {PB, RefB} = start_in(N2, fun() -> receive stop -> stopped end end),
    PB ! go,
    Reason = in_ns(N1, fun() ->
        process_flag(trap_exit, true),
        link(PB),
        receive {'EXIT', PB, R} -> R after 2000 -> timeout end
    end),
    PB ! stop,
    Stopped = await(PB, RefB),
    case {Reason, Stopped} of
        {noproc, stopped} -> ok;
        Other -> {bad, Other}
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
        .compile_named("ns_core_t", SOURCE, &[])
        .expect("compile ns_core_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_core_t");
    let actual = vm
        .eval_scheduled("ns_core_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

#[test]
fn ns_spawn_inherits_ns() {
    run("ns_spawn_inherits_ns");
}

#[test]
fn ns_delivery_same_ns_ok() {
    run("ns_delivery_same_ns_ok");
}

#[test]
fn ns_delivery_cross_ns_dropped() {
    run("ns_delivery_cross_ns_dropped");
}

#[test]
fn ns_root_can_send_into_ns() {
    run("ns_root_can_send_into_ns");
}

#[test]
fn ns_link_cross_ns_noproc() {
    run("ns_link_cross_ns_noproc");
}
