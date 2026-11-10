//! `demonitor(Ref, [flush])` traps to `erts_internal:flush_monitor_messages/3`: the flush is an
//! Erlang receive, so selective receive order of the other messages must match erl. The `apply_*` and `eval_*` cases reach the BIF the way
//! `erl_eval` does (`apply/3` with a runtime argument list, and `erl_eval:exprs/2` itself).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;

const MODULE: &str = "demonitor_flush_trap";
const CASES: &[&str] = &[
    "queued",
    "queued_info",
    "transit",
    "transit_info",
    "tail_queued",
    "gc_queued",
    "apply_queued",
    "apply_queued_info",
    "apply_missing",
    "apply_missing_info",
    "apply_active",
    "apply_badarg",
    "eval_queued",
    "eval_missing",
];

const SOURCE: &str = r#"-module(demonitor_flush_trap).
-export([run/1]).

run(Case) ->
    Self = self(),
    Self ! first,
    P = spawn(fun() -> receive stop -> ok end end),
    M = monitor(process, P),
    Keep = {keep, is_pid(Self), is_reference(M)},
    Self ! middle,
    R = case Case of
        queued ->
            P ! stop,
            wait_down(M),
            Self ! last,
            erlang:demonitor(M, [flush]);
        queued_info ->
            P ! stop,
            wait_down(M),
            Self ! last,
            erlang:demonitor(M, [flush, info]);
        transit ->
            P ! stop,
            erlang:demonitor(M, [flush]);
        transit_info ->
            P ! stop,
            erlang:demonitor(M, [flush, info]);
        tail_queued ->
            P ! stop,
            wait_down(M),
            Self ! last,
            tail_demonitor(M);
        gc_queued ->
            P ! stop,
            wait_down(M),
            %% Many queued messages and a large live heap: collections run while the flush
            %% is trapped and while it receives, so the trapped arguments must be roots.
            [Self ! {filler, N} || N <- lists:seq(1, 3000)],
            Live = [{live, N, lists:seq(1, 40)} || N <- lists:seq(1, 4000)],
            Last = length(Live),
            R2 = erlang:demonitor(M, [flush]),
            {R2, Last};
        apply_queued ->
            P ! stop,
            wait_down(M),
            Self ! last,
            apply(id(erlang), id(demonitor), id([M, [flush]]));
        apply_queued_info ->
            P ! stop,
            wait_down(M),
            Self ! last,
            apply(id(erlang), id(demonitor), id([M, [flush, info]]));
        apply_missing ->
            P ! stop,
            wait_down(M),
            drop_down(M, apply(id(erlang), id(demonitor), id([make_ref(), [flush]])));
        apply_missing_info ->
            P ! stop,
            wait_down(M),
            drop_down(M, apply(id(erlang), id(demonitor), id([make_ref(), [flush, info]])));
        apply_active ->
            R3 = apply(id(erlang), id(demonitor), id([M, [flush, info]])),
            P ! stop,
            R3;
        apply_badarg ->
            P ! stop,
            wait_down(M),
            drop_down(M, try apply(id(erlang), id(demonitor), id([M, [bad]])) of
                Unexpected -> {unexpected, Unexpected}
            catch
                Class:Reason:Stack ->
                    [{Mod, Fun, Args, _} | _] = Stack,
                    {Class, Reason, Mod, Fun, length(Args)}
            end);
        eval_queued ->
            P ! stop,
            wait_down(M),
            Self ! last,
            eval("erlang:demonitor(M, [flush]).", M);
        eval_missing ->
            P ! stop,
            wait_down(M),
            drop_down(M, eval("demonitor(make_ref(), [flush, info]).", M))
    end,
    {R, messages(), Keep}.

id(X) -> X.

%% The DOWN of `M` names a pid and a ref that differ between the runtimes.
drop_down(M, Result) ->
    true = erlang:demonitor(M, [flush]),
    Result.

%% The expression runs in erl_eval, as `erl -eval` and the shell run it.
eval(String, M) ->
    {ok, Tokens, _} = erl_scan:string(String),
    {ok, Exprs} = erl_parse:parse_exprs(Tokens),
    {value, Value, _} = erl_eval:exprs(Exprs, erl_eval:add_binding('M', M, erl_eval:new_bindings())),
    Value.

%% The demonitor is the last call of this function: a tail call from Erlang.
tail_demonitor(M) -> erlang:demonitor(M, [flush]).

wait_down(M) ->
    case lists:any(fun({'DOWN', Ref, _, _, _}) -> Ref =:= M; (_) -> false end,
                   messages()) of
        true -> ok;
        false -> wait_down(M)
    end.

messages() ->
    {messages, Messages} = process_info(self(), messages),
    Messages.
"#;

#[test]
fn demonitor_flush_traps_to_erts_internal_and_matches_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping demonitor flush trap test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile demonitor_flush_trap");
    reference.load(MODULE, &beam).expect("load into erl");
    let expected: Vec<(String, OwnedTerm)> = CASES
        .iter()
        .map(
            |case| match reference.call(MODULE, "run", &[OwnedTerm::Atom((*case).into())]) {
                CallResult::Ok(term) => (case.to_string(), term),
                other => panic!("{MODULE}:run({case}) on erl: {other:?}"),
            },
        )
        .collect();

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    for (case, want) in &expected {
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2, None)
            .expect("scheduled run");
        assert_eq!(actual.term, *want, "{MODULE}:run({case})");
    }
}
