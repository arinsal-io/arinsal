//! Persistent terms of a namespace live in a store of their own.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(ns_pterm_t).
-compile([export_all, nowarn_export_all]).

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_pterm_t, wrapper, [Fun]),
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

mk(Name) ->
    {ok, Ns} = arinsal_ns:create(Name, <<"shop">>, #{}),
    Ns.

ns_pterm_isolated() ->
    Ns1 = mk(<<"acme">>),
    Ns2 = mk(<<"globex">>),
    ok = persistent_term:put(shared_key, root),
    ok = persistent_term:put(root_only, r),
    Setup = fun(V) -> fun() ->
        Before = [persistent_term:get(shared_key, none), persistent_term:get(root_only, none)],
        ok = persistent_term:put(shared_key, V),
        ok = persistent_term:put({priv, V}, V),
        Before
    end end,
    Fin = fun(Before) ->
        {Before, persistent_term:get(shared_key), lists:sort(persistent_term:get()),
         catch persistent_term:get(root_only), persistent_term:erase(root_only)}
    end,
    H1 = holder(Ns1, Setup(n1), Fin),
    H2 = holder(Ns2, Setup(n2), Fin),
    settle(),
    RootDuring = [persistent_term:get(shared_key), persistent_term:get({priv, n1}, none)],
    check(H1),
    check(H2),
    R1 = await(H1),
    R2 = await(H2),
    RootKeys = [K || {K, _} <- persistent_term:get(), K =:= shared_key orelse K =:= root_only],
    case {R1, R2, RootDuring, lists:sort(RootKeys), persistent_term:get(root_only)} of
        {{[none, none], n1, [{shared_key, n1}, {{priv, n1}, n1}], {'EXIT', {badarg, _}}, false},
         {[none, none], n2, [{shared_key, n2}, {{priv, n2}, n2}], {'EXIT', {badarg, _}}, false},
         [root, none], [root_only, shared_key], r} -> ok;
        Other -> {bad, Other}
    end.

ns_pterm_system_key_fallback() ->
    Ns = mk(<<"acme">>),
    ok = persistent_term:put(erl_prim_loader, root_loader),
    ok = persistent_term:put({prim_socket, protocols}, root_protocols),
    ok = persistent_term:put({erl_features, enabled_features}, root_features),
    Res = in_ns(Ns, fun() ->
        Read = [persistent_term:get(erl_prim_loader), persistent_term:get({prim_socket, protocols}),
                persistent_term:get({erl_features, enabled_features}, none),
                persistent_term:get({prim_socket, missing}, dflt)],
        ErasedRoot = persistent_term:erase(erl_prim_loader),
        StillRead = persistent_term:get(erl_prim_loader),
        ok = persistent_term:put({prim_socket, protocols}, own),
        Shadow = persistent_term:get({prim_socket, protocols}),
        Keys = lists:sort([K || {K, _} <- persistent_term:get()]),
        {Read, ErasedRoot, StillRead, Shadow, Keys}
    end),
    ok = persistent_term:put(erl_prim_loader, root_loader2),
    Again = in_ns(Ns, fun() -> persistent_term:get(erl_prim_loader) end),
    case {Res, persistent_term:get({prim_socket, protocols}), Again} of
        {{[root_loader, root_protocols, root_features, dflt], false, root_loader, own,
          [{prim_socket, protocols}]}, root_protocols, root_loader2} -> ok;
        Other -> {bad, Other}
    end.

ns_pterm_root_secret_invisible() ->
    Ns = mk(<<"acme">>),
    Secrets = [root_secret, {my_app, secret}, {logger_config, x}, {socketx, 1}, {code_server_clone, 1},
               {1, root}, [code_server], {{code_server}, 1}, {code_server}],
    [ok = persistent_term:put(K, root) || K <- Secrets],
    Res = in_ns(Ns, fun() ->
        Leaks = [K || K <- Secrets,
                      persistent_term:get(K, none) =/= none orelse
                          not is_exit(catch persistent_term:get(K))],
        {Leaks, [K || {K, _} <- persistent_term:get(), lists:member(K, Secrets)]}
    end),
    [true = persistent_term:erase(K) || K <- Secrets],
    case Res of
        {[], []} -> ok;
        Other -> {bad, Other}
    end.

is_exit({'EXIT', _}) -> true;
is_exit(_) -> false.
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
        .compile_named("ns_pterm_t", SOURCE, &[])
        .expect("compile ns_pterm_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_pterm_t");
    let actual = vm
        .eval_scheduled("ns_pterm_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

#[test]
fn ns_pterm_isolated() {
    run("ns_pterm_isolated");
}

#[test]
fn ns_pterm_system_key_fallback() {
    run("ns_pterm_system_key_fallback");
}

#[test]
fn ns_pterm_root_secret_invisible() {
    run("ns_pterm_root_secret_invisible");
}
