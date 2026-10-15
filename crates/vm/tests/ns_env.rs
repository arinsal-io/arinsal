//! OS environment of a namespace: overlay, seed from `os_env`, allowlist of node variables.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(ns_env_t).
-compile([export_all, nowarn_export_all]).

wrapper(Fun) ->
    receive go -> ok end,
    exit({r, Fun()}).

start_in(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_env_t, wrapper, [Fun]),
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

ns_env_overlay() ->
    true = os:putenv("ARL_ROOT_VAR", "root"),
    N1 = mk(<<"acme">>, #{os_env => [{"ARL_FOO", "bar"}, {<<"ARL_BIN">>, <<"qux">>}]}),
    N2 = mk(<<"globex">>, #{}),
    Res1 = in_ns(N1, fun() ->
        Seeded = [os:getenv("ARL_FOO"), os:getenv("ARL_BIN"), os:getenv("ARL_ROOT_VAR")],
        true = os:putenv("ARL_NEW", "1"),
        true = os:putenv("ARL_FOO", "changed"),
        Put = [os:getenv("ARL_NEW"), os:getenv("ARL_FOO")],
        true = os:unsetenv("ARL_BIN"),
        All = os:env(),
        {Seeded, Put, os:getenv("ARL_BIN"), lists:keyfind("ARL_NEW", 1, All),
         lists:keyfind("ARL_BIN", 1, All), lists:keyfind("ARL_ROOT_VAR", 1, All)}
    end),
    Res2 = in_ns(N2, fun() ->
        [os:getenv("ARL_FOO"), os:getenv("ARL_NEW"), os:getenv("ARL_ROOT_VAR")]
    end),
    RootAfter = [os:getenv("ARL_FOO"), os:getenv("ARL_NEW"), os:getenv("ARL_ROOT_VAR")],
    case {Res1, Res2, RootAfter} of
        {{["bar", "qux", false], ["1", "changed"], false, {"ARL_NEW", "1"}, false, false},
         [false, false, false], [false, false, "root"]} -> ok;
        Other -> {bad, Other}
    end.

ns_env_no_root_leak() ->
    true = os:putenv("ARL_SECRET_TOKEN", "s3cret"),
    true = os:putenv("PATH", "/arl/bin"),
    true = os:putenv("HOME", "/arl/home"),
    N = mk(<<"acme">>, #{os_env => [{"MINE", "1"}]}),
    Allowed = ["PATH", "HOME", "LANG", "TZ", "MINE"],
    Res = in_ns(N, fun() ->
        Before = [os:getenv("ARL_SECRET_TOKEN"), os:getenv("PATH"), os:getenv("HOME")],
        Keys = [K || {K, _} <- os:env()],
        true = os:putenv("PATH", "/tenant"),
        true = os:unsetenv("HOME"),
        {Before, [K || K <- Keys, not lists:member(K, Allowed)],
         lists:member("ARL_SECRET_TOKEN", Keys), os:getenv("PATH"), os:getenv("HOME"),
         lists:keyfind("PATH", 1, os:env())}
    end),
    RootAfter = [os:getenv("PATH"), os:getenv("HOME")],
    case {Res, RootAfter} of
        {{[false, "/arl/bin", "/arl/home"], [], false, "/tenant", false, {"PATH", "/tenant"}},
         ["/arl/bin", "/arl/home"]} -> ok;
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
        .compile_named("ns_env_t", SOURCE, &[])
        .expect("compile ns_env_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_env_t");
    let actual = vm
        .eval_scheduled("ns_env_t", entry, &[], 2, None)
        .unwrap_or_else(|error| panic!("{entry}: {error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()), "{entry}");
}

#[test]
fn ns_env_overlay() {
    run("ns_env_overlay");
}

#[test]
fn ns_env_no_root_leak() {
    run("ns_env_no_root_leak");
}
