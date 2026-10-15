//! Per-namespace registered names: register, whereis, send to a name, registered/0.
//!
//! Namespace processes cannot message root (root is not shared), so a namespace probe returns
//! its result through the exit reason that the root monitor sees. Root waits a short time
//! after `go` so that a registration has happened before the next step; names live as long as
//! their process, which waits for a second message.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(ns_names_t).
-compile([export_all, nowarn_export_all]).

mk(Name) ->
    {ok, Ns} = arinsal_ns:create(Name, <<"shop">>, #{}),
    Ns.

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_names_t, wrapper, [Fun]),
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

%% A namespace process that registers Name for itself, then waits for `check`, then runs Fun.
holder(Ns, Name, Fun) ->
    go(start_in(Ns, fun() ->
        true = register(Name, self()),
        receive check -> ok end,
        Fun()
    end)).

check({P, _} = H) -> P ! check, H.

%% A root process registered as Name that returns the first message it gets.
root_named(Name) ->
    Me = self(),
    P = spawn(fun() ->
        receive M -> Me ! {root_got, self(), M} end
    end),
    true = register(Name, P),
    P.

root_probe(P) ->
    receive {root_got, P, M} -> M after 3000 -> timeout end.

ns_register_same_name_two_ns() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    H1 = holder(N1, svc, fun() -> {self(), whereis(svc)} end),
    H2 = holder(N2, svc, fun() -> {self(), whereis(svc)} end),
    settle(),
    check(H1),
    check(H2),
    {P1, W1} = await(H1),
    {P2, W2} = await(H2),
    case {P1 =:= W1, P2 =:= W2, P1 =/= P2, whereis(svc)} of
        {true, true, true, undefined} -> ok;
        Other -> {bad, Other}
    end.

ns_whereis_isolated() ->
    NA = mk(<<"acme">>),
    NB = mk(<<"globex">>),
    R = root_named(root_only),
    HB = holder(NB, b_name, fun() -> ok end),
    settle(),
    Res = in_ns(NA, fun() ->
        [whereis(b_name),
         whereis(root_only),
         catch unregister(b_name),
         catch unregister(root_only),
         lists:member(b_name, registered()),
         lists:member(root_only, registered())]
    end),
    R ! release,
    root_probe(R),
    check(HB),
    ok = await(HB),
    case Res of
        [undefined, undefined, {'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, false, false] -> ok;
        Other -> {bad, Other}
    end.

ns_whereis_shared_root_fallback() ->
    Ns = mk(<<"acme">>),
    Shared = root_named(shared_svc),
    Hidden = root_named(hidden_svc),
    ok = arinsal_ns:expose(Shared),
    Res = in_ns(Ns, fun() ->
        Seen = whereis(shared_svc),
        Unseen = whereis(hidden_svc),
        InList = lists:member(shared_svc, registered()),
        Sent = (catch (shared_svc ! hello)),
        Own = register(shared_svc, self()),
        Shadow = whereis(shared_svc) =:= self(),
        {Seen, Unseen, InList, Sent, Own, Shadow}
    end),
    Got = root_probe(Shared),
    Hidden ! release,
    root_probe(Hidden),
    case Res of
        {Shared, undefined, false, hello, true, true} when Got =:= hello -> ok;
        Other -> {bad, Other, Got}
    end.

collect(N) -> collect(N, []).
collect(0, Acc) -> lists:sort(Acc);
collect(N, Acc) ->
    receive M -> collect(N - 1, [M | Acc]) after 2000 -> {missing, lists:sort(Acc)} end.

ns_send_to_name_resolves_in_own_ns() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    N3 = mk(<<"initech">>),
    H1 = holder(N1, svc, fun() -> collect(3) end),
    H2 = holder(N2, svc, fun() -> collect(3) end),
    settle(),
    Sender = fun(Tag) ->
        fun() ->
            svc ! {Tag, direct},
            {svc, node()} ! {Tag, node_tuple},
            _ = erlang:send_after(10, svc, {Tag, timer}),
            ok
        end
    end,
    ok = in_ns(N1, Sender(n1)),
    ok = in_ns(N2, Sender(n2)),
    Missing = in_ns(N3, fun() -> catch (svc ! x) end),
    check(H1),
    check(H2),
    G1 = await(H1),
    G2 = await(H2),
    case {G1, G2, Missing} of
        {[{n1, direct}, {n1, node_tuple}, {n1, timer}],
         [{n2, direct}, {n2, node_tuple}, {n2, timer}],
         {'EXIT', {badarg, _}}} -> ok;
        Other -> {bad, Other}
    end.

ns_registered_filtered() ->
    NA = mk(<<"acme">>),
    NB = mk(<<"globex">>),
    R = root_named(root_listed),
    HA = go(start_in(NA, fun() ->
        true = register(a1, self()),
        Other = spawn(fun() -> receive stop -> ok end end),
        true = register(a2, Other),
        receive check -> ok end,
        lists:sort(registered())
    end)),
    HB = holder(NB, b1, fun() -> lists:sort(registered()) end),
    settle(),
    RootNames = registered(),
    check(HA),
    check(HB),
    A = await(HA),
    B = await(HB),
    R ! release,
    root_probe(R),
    Leaked = [N || N <- [a1, a2, b1], lists:member(N, RootNames)],
    case {A, B, Leaked, lists:member(root_listed, RootNames)} of
        {[a1, a2], [b1], [], true} -> ok;
        Other -> {bad, Other}
    end.

ns_root_names_unchanged() ->
    Ns = mk(<<"acme">>),
    R = root_named(dup),
    Res = in_ns(Ns, fun() ->
        true = register(dup, self()),
        Mine = whereis(dup) =:= self(),
        true = unregister(dup),
        true = register(dup, self()),
        Mine
    end),
    Same = whereis(dup) =:= R,
    Listed = lists:member(dup, registered()),
    R2 = (catch register(dup, self())),
    dup ! hello,
    Got = root_probe(R),
    true = (catch unregister(dup)) =:= true orelse is_unregistered(dup),
    Gone = whereis(dup),
    case {Res, Same, Listed, R2, Got, Gone} of
        {true, true, true, {'EXIT', {badarg, _}}, hello, undefined} -> ok;
        Other -> {bad, Other}
    end.

is_unregistered(Name) -> whereis(Name) =:= undefined.

ns_register_cleared_on_exit() ->
    Ns = mk(<<"acme">>),
    ok = in_ns(Ns, fun() -> true = register(tmp, self()), ok end),
    Res = in_ns(Ns, fun() ->
        {whereis(tmp), register(tmp, self()), whereis(tmp) =:= self()}
    end),
    case Res of
        {undefined, true, true} -> ok;
        Other -> {bad, Other}
    end.

ns_register_foreign_pid_badarg() ->
    Ns = mk(<<"acme">>),
    R = spawn(fun() -> receive stop -> ok end end),
    Res = in_ns(Ns, fun() -> catch register(x, R) end),
    R ! stop,
    case {Res, whereis(x)} of
        {{'EXIT', {badarg, _}}, undefined} -> ok;
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
        .compile_named("ns_names_t", SOURCE, &[])
        .expect("compile ns_names_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_names_t");
    let actual = vm
        .eval_scheduled("ns_names_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

#[test]
fn ns_register_same_name_two_ns() {
    run("ns_register_same_name_two_ns");
}

#[test]
fn ns_whereis_isolated() {
    run("ns_whereis_isolated");
}

#[test]
fn ns_whereis_shared_root_fallback() {
    run("ns_whereis_shared_root_fallback");
}

#[test]
fn ns_send_to_name_resolves_in_own_ns() {
    run("ns_send_to_name_resolves_in_own_ns");
}

#[test]
fn ns_registered_filtered() {
    run("ns_registered_filtered");
}

#[test]
fn ns_root_names_unchanged() {
    run("ns_root_names_unchanged");
}

#[test]
fn ns_register_cleared_on_exit() {
    run("ns_register_cleared_on_exit");
}

#[test]
fn ns_register_foreign_pid_badarg() {
    run("ns_register_foreign_pid_badarg");
}
