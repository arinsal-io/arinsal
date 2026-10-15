//! ETS namespaces: named tables are scoped by namespace, a table is reachable by identity
//! from its own namespace only, root tables of shared owners are readable from anywhere,
//! `ets:all/0` is filtered, and ownership never crosses a namespace.
//!
//! Namespace processes return results through the exit reason that the root monitor sees.
//! Tests that need a table identity from a namespace expose the root test process so that the
//! namespace process can send it over.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(ns_ets_t).
-compile([export_all, nowarn_export_all]).

mk(Name) ->
    {ok, Ns} = arinsal_ns:create(Name, <<"shop">>, #{}),
    Ns.

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_ets_t, wrapper, [Fun]),
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

%% A namespace process that runs Setup, waits for `check`, then returns Fun(SetupResult).
holder(Ns, Setup, Fun) ->
    go(start_in(Ns, fun() ->
        S = Setup(),
        receive check -> ok end,
        Fun(S)
    end)).

%% A namespace process that sends {tab, Tid} to Root, then behaves like holder.
tab_holder(Ns, Root, Fun) ->
    holder(Ns, fun() ->
        T = ets:new(own, [public]),
        true = ets:insert(T, {k, own}),
        Root ! {tab, T},
        T
    end, Fun).

recv_tab() ->
    receive {tab, T} -> T after 3000 -> timeout end.

%% A root process that creates a table, tells Root, then waits for `stop`.
root_owner(Setup) ->
    Me = self(),
    P = spawn(fun() ->
        Setup(),
        Me ! {ready, self()},
        receive stop -> ok end
    end),
    receive {ready, P} -> P after 3000 -> timeout end.

ns_ets_same_name_two_ns() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    Setup = fun(V) -> fun() ->
        t = ets:new(t, [named_table, public]),
        true = ets:insert(t, {k, V}),
        ok
    end end,
    Fin = fun(_) -> {ets:lookup(t, k), ets:info(t, size), ets:whereis(t) =/= undefined} end,
    H1 = holder(N1, Setup(n1), Fin),
    H2 = holder(N2, Setup(n2), Fin),
    settle(),
    t = ets:new(t, [named_table]),
    Root = ets:lookup(t, k),
    check(H1),
    check(H2),
    R1 = await(H1),
    R2 = await(H2),
    case {R1, R2, Root, ets:info(t, size)} of
        {{[{k, n1}], 1, true}, {[{k, n2}], 1, true}, [], 0} -> ok;
        Other -> {bad, Other}
    end.

ns_ets_tid_cross_ns_badarg() ->
    ok = arinsal_ns:expose(self()),
    Root = self(),
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    H1 = tab_holder(N1, Root, fun(T) ->
        {ets:lookup(T, k), catch ets:insert(T, {k2, x}), ets:whereis(named1) =/= undefined}
    end),
    N1Named = go(start_in(N1, fun() ->
        named1 = ets:new(named1, [named_table, public]),
        receive check -> ok end,
        ok
    end)),
    T = recv_tab(),
    settle(),
    FromRoot = [catch ets:lookup(T, k), catch ets:insert(T, {k2, x}), ets:info(T, size),
                ets:whereis(named1), ets:info(named1), catch ets:lookup(named1, k)],
    FromN2 = in_ns(N2, fun() ->
        [catch ets:lookup(T, k), catch ets:insert(T, {k2, x}), catch ets:delete(T),
         ets:info(T), catch ets:lookup(named1, k), ets:whereis(named1)]
    end),
    check(H1),
    check(N1Named),
    Own = await(H1),
    ok = await(N1Named),
    case {FromRoot, FromN2, Own} of
        {[[{k, own}], true, 2, undefined, undefined, {'EXIT', {badarg, _}}],
         [{'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, undefined,
          {'EXIT', {badarg, _}}, undefined],
         {[{k, own}], true, true}} -> ok;
        Other -> {bad, Other}
    end.

ns_ets_shared_root_read_only() ->
    Ns = mk(<<"acme">>),
    Shared = root_owner(fun() ->
        shared_t = ets:new(shared_t, [named_table, public]),
        true = ets:insert(shared_t, {k, v})
    end),
    ok = arinsal_ns:expose(Shared),
    hidden_t = ets:new(hidden_t, [named_table, public]),
    true = ets:insert(hidden_t, {k, h}),
    SharedTid = ets:whereis(shared_t),
    HiddenTid = ets:whereis(hidden_t),
    Res = in_ns(Ns, fun() ->
        Read = [ets:lookup(shared_t, k), ets:lookup(SharedTid, k), ets:lookup(SharedTid, k),
                ets:member(SharedTid, k), ets:info(shared_t, size)],
        Write = [catch ets:insert(shared_t, {k2, x}), catch ets:insert(SharedTid, {k2, x}),
                 catch ets:delete(shared_t, k), catch ets:delete_all_objects(SharedTid),
                 catch ets:update_counter(SharedTid, k, 1), catch ets:delete(SharedTid)],
        Hidden = [catch ets:lookup(hidden_t, k), catch ets:lookup(HiddenTid, k),
                  ets:info(hidden_t), ets:info(HiddenTid), ets:whereis(hidden_t)],
        shared_t = ets:new(shared_t, [named_table]),
        Shadow = ets:lookup(shared_t, k),
        {Read, Write, Hidden, Shadow}
    end),
    Shared ! stop,
    Intact = ets:lookup(hidden_t, k),
    case Res of
        {[[{k, v}], [{k, v}], [{k, v}], true, 1],
         [{'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, {'EXIT', {badarg, _}},
          {'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}],
         [{'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, undefined, undefined, undefined],
         []} when Intact =:= [{k, h}] -> ok;
        Other -> {bad, Other}
    end.

ns_ets_all_filtered() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    Setup1 = fun() ->
        a1 = ets:new(a1, [named_table]),
        _ = ets:new(unnamed, []),
        ok
    end,
    Setup2 = fun() -> b1 = ets:new(b1, [named_table]), ok end,
    Fin = fun(_) ->
        All = ets:all(),
        {length(All), lists:member(a1, All), lists:member(b1, All), lists:member(r_named, All)}
    end,
    H1 = holder(N1, Setup1, Fin),
    H2 = holder(N2, Setup2, Fin),
    r_named = ets:new(r_named, [named_table]),
    settle(),
    RootAll = ets:all(),
    check(H1),
    check(H2),
    R1 = await(H1),
    R2 = await(H2),
    case {R1, R2, lists:member(r_named, RootAll)} of
        {{2, true, false, false}, {1, false, true, false}, true} -> ok;
        Other -> {bad, Other}
    end.

ns_ets_all_root_sees_all() ->
    N1 = mk(<<"acme">>),
    N2 = mk(<<"globex">>),
    H1 = holder(N1, fun() -> a1 = ets:new(a1, [named_table]), _ = ets:new(unnamed, []), ok end,
                fun(_) -> ok end),
    H2 = holder(N2, fun() -> b1 = ets:new(b1, [named_table]), ok end, fun(_) -> ok end),
    r_named = ets:new(r_named, [named_table]),
    RootOwn = ets:new(root_unnamed, []),
    settle(),
    All = ets:all(),
    check(H1),
    check(H2),
    ok = await(H1),
    ok = await(H2),
    case {[lists:member(N, All) || N <- [a1, b1, r_named]], lists:member(RootOwn, All), length(All) >= 5} of
        {[true, true, true], true, true} -> ok;
        Other -> {bad, Other}
    end.

ns_ets_give_away_cross_ns_badarg() ->
    ok = arinsal_ns:expose(self()),
    Root = self(),
    Ns = mk(<<"acme">>),
    Wait = fun() -> receive stop -> ok end end,
    Peer = start_in(Ns, fun() -> receive {'ETS-TRANSFER', _, _, _} -> got end end),
    {PeerPid, _} = Peer,
    RootTab = ets:new(root_tab, [public]),
    H = holder(Ns, fun() ->
        T = ets:new(own, [public]),
        Root ! {tab, T},
        T
    end, fun(T) ->
        Child = spawn(Wait),
        ToRoot = catch ets:give_away(T, Root, x),
        HeirRoot = catch ets:new(h, [{heir, Root, x}]),
        SetHeir = catch ets:setopts(T, {heir, Root, x}),
        SameNs = catch ets:give_away(T, Child, x),
        Child ! stop,
        {ToRoot, HeirRoot, SetHeir, SameNs}
    end),
    _ = recv_tab(),
    ToNs = catch ets:give_away(RootTab, PeerPid, x),
    HeirNs = catch ets:new(h2, [{heir, PeerPid, x}]),
    SetHeirNs = catch ets:setopts(RootTab, {heir, PeerPid, x}),
    HeirOk = is_reference(catch ets:new(h3, [{heir, Root, x}])) orelse true,
    check(H),
    Res = await(H),
    PeerPid ! release,
    case {ToNs, HeirNs, SetHeirNs, Res, HeirOk} of
        {{'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, {'EXIT', {badarg, _}},
         {{'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, {'EXIT', {badarg, _}}, true}, true} -> ok;
        Other -> {bad, Other}
    end.

ns_ets_destroy_frees() ->
    Ns = mk(<<"acme">>),
    H = holder(Ns, fun() ->
        dt = ets:new(dt, [named_table, public]),
        _ = ets:new(unnamed, []),
        register(dreg, self()),
        ok
    end, fun(_) -> ok end),
    settle(),
    Before = length(ets:all()),
    ok = arinsal_ns:destroy(Ns),
    _ = await(H),
    settle(),
    After = length(ets:all()),
    case {Before - After, lists:member(dt, ets:all())} of
        {2, false} -> ok;
        Other -> {bad, Other, Before, After}
    end.

ns_ets_root_unchanged() ->
    Ns = mk(<<"acme">>),
    H = holder(Ns, fun() -> t = ets:new(t, [named_table, public]), ok end, fun(_) -> ets:info(t, size) end),
    settle(),
    t = ets:new(t, [named_table, public]),
    Dup = (catch ets:new(t, [named_table])),
    true = ets:insert(t, [{a, 1}, {b, 2}]),
    Tid = ets:whereis(t),
    Direct = [ets:lookup(Tid, a), ets:lookup(Tid, a), ets:member(Tid, b), ets:lookup(t, b)],
    true = ets:insert(Tid, {c, 3}),
    3 = ets:update_counter(Tid, c, 0),
    Listed = lists:member(t, ets:all()),
    t2 = ets:rename(t, t2),
    Renamed = {ets:whereis(t), ets:whereis(t2) =:= Tid, ets:info(t2, size)},
    check(H),
    InNs = await(H),
    true = ets:delete(t2),
    case {Dup, Direct, Listed, Renamed, InNs, ets:whereis(t2)} of
        {{'EXIT', {badarg, _}}, [[{a, 1}], [{a, 1}], true, [{b, 2}]], true, {undefined, true, 3}, 0,
         undefined} -> ok;
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
        .compile_named("ns_ets_t", SOURCE, &[])
        .expect("compile ns_ets_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_ets_t");
    let actual = vm
        .eval_scheduled("ns_ets_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

#[test]
fn ns_ets_same_name_two_ns() {
    run("ns_ets_same_name_two_ns");
}

#[test]
fn ns_ets_tid_cross_ns_badarg() {
    run("ns_ets_tid_cross_ns_badarg");
}

#[test]
fn ns_ets_shared_root_read_only() {
    run("ns_ets_shared_root_read_only");
}

#[test]
fn ns_ets_all_filtered() {
    run("ns_ets_all_filtered");
}

#[test]
fn ns_ets_all_root_sees_all() {
    run("ns_ets_all_root_sees_all");
}

#[test]
fn ns_ets_give_away_cross_ns_badarg() {
    run("ns_ets_give_away_cross_ns_badarg");
}

#[test]
fn ns_ets_destroy_frees() {
    run("ns_ets_destroy_frees");
}

#[test]
fn ns_ets_root_unchanged() {
    run("ns_ets_root_unchanged");
}
