//! Virtual scheduler count of a namespace: `system_info(schedulers | schedulers_online)`.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ns_si_t).
-compile([export_all, nowarn_export_all]).

wrapper(Fun) ->
    exit({r, Fun()}).

in_ns(Ns, Fun) ->
    P = arinsal_ns:spawn(Ns, ns_si_t, wrapper, [Fun]),
    Ref = erlang:monitor(process, P),
    receive
        {'DOWN', Ref, process, P, {r, R}} -> R;
        {'DOWN', Ref, process, P, Other} -> {crashed, Other}
    after 5000 -> timeout
    end.

counts() ->
    {erlang:system_info(schedulers), erlang:system_info(schedulers_online)}.

ns_system_info_virtual_schedulers() ->
    Root = counts(),
    {ok, N1} = arinsal_ns:create(<<"acme">>, <<"shop">>, #{}),
    {ok, N4} = arinsal_ns:create(<<"globex">>, <<"shop">>, #{schedulers => 4}),
    Default = in_ns(N1, fun counts/0),
    Four = in_ns(N4, fun counts/0),
    Info = maps:get(schedulers, arinsal_ns:info(N4)),
    Bad = try arinsal_ns:create(<<"x">>, <<"y">>, #{schedulers => 0}) catch error:badarg -> badarg end,
    RootAfter = counts(),
    case {Default, Four, Info, Bad, RootAfter =:= Root, element(1, Root) >= 1} of
        {{1, 1}, {4, 4}, 4, badarg, true, true} -> ok;
        Other -> {bad, Other, Root}
    end.
"#;

#[test]
fn ns_system_info_virtual_schedulers() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let beam = reference
        .compile_named("ns_si_t", SOURCE, &[])
        .expect("compile ns_si_t");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load ns_si_t");
    let actual = vm
        .eval_scheduled("ns_si_t", "ns_system_info_virtual_schedulers", &[], 4, None)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(actual.term, OwnedTerm::Atom("ok".into()));
}
