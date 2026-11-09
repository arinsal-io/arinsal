//! `alias/1`, `unalias/1`, `monitor/3` with `{alias, Mode}` and `iolist_size/1` run as light BIFs
//! under the JIT; their results must match erl, including the iolist walk that yields.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "alias_light_differential";
const CASES: &[&str] = &[
    "alias_receive",
    "unalias_drops",
    "unalias_twice",
    "reply_alias_once",
    "bad_alias_option",
    "bad_alias_list",
    "monitor_alias_reply",
    "demonitor_drops_alias",
    "monitor_alias_down",
    "monitor_alias_tag",
    "monitor_alias_noproc",
    "monitor_bad_alias_mode",
    "alias_default_lifecycle",
    "alias_explicit_lifecycle",
    "alias_reply_lifecycle",
    "alias_reply_then_explicit",
    "alias_explicit_then_reply",
    "monitor_demonitor_explicit",
    "monitor_demonitor_demonitor",
    "monitor_demonitor_reply_demonitor",
    "monitor_down_explicit",
    "monitor_down_demonitor",
    "monitor_down_reply_demonitor",
    "monitor_reply_demonitor_once",
    "monitor_alias_last_mode",
    "spawn_opt_alias_explicit",
    "spawn_opt_alias_demonitor",
    "spawn_opt_alias_reply_demonitor",
    "iolist_size_small",
    "iolist_size_nested",
    "iolist_size_long",
    "iolist_size_huge_yields",
    "iolist_size_badarg",
    "iolist_size_improper",
];

const SOURCE: &str = r#"-module(alias_light_differential).
-export([run/1]).

recv(Msg) -> receive Msg -> got after 100 -> missed end.

send_status(Alias, Msg) ->
    Alias ! Msg,
    receive Msg -> delivered after 0 -> dropped end.

alias_lifecycle(Alias) ->
    First = send_status(Alias, alias_first),
    U1 = unalias(Alias),
    Second = send_status(Alias, alias_second),
    {First, U1, Second, unalias(Alias)}.

monitor_demonitor(Mode) ->
    P = spawn(fun() -> receive stop -> ok end end),
    M = erlang:monitor(process, P, [{alias, Mode}]),
    D = erlang:demonitor(M),
    First = send_status(M, after_demonitor),
    U = erlang:unalias(M),
    Second = send_status(M, after_unalias),
    P ! stop,
    {D, First, U, Second}.

monitor_down(Mode) ->
    P = spawn(fun() -> ok end),
    M = erlang:monitor(process, P, [{alias, Mode}]),
    receive {'DOWN', M, process, P, _} -> ok after 1000 -> timeout end,
    First = send_status(M, after_down),
    U = erlang:unalias(M),
    Second = send_status(M, after_unalias),
    {First, U, Second}.

spawn_opt_alias(Mode) ->
    Parent = self(),
    {P, M} = spawn_opt(fun() ->
        receive {Alias, ParentPid} ->
            Alias ! spawn_first,
            Alias ! spawn_second,
            ParentPid ! spawn_done
        end
    end, [{monitor, [{alias, Mode}]}]),
    P ! {M, Parent},
    receive spawn_done -> ok after 1000 -> timeout end,
    First = receive spawn_first -> delivered after 0 -> dropped end,
    Second = receive spawn_second -> delivered after 0 -> dropped end,
    {First, Second, unalias(M)}.

echo() -> receive {From, X} -> From ! {X, ok}, echo(); stop -> ok end.

run(alias_receive) ->
    A = alias(), A ! m1, {is_reference(A), recv(m1)};
run(unalias_drops) ->
    A = alias(), U = unalias(A), A ! m2, {U, recv(m2)};
run(unalias_twice) ->
    A = alias(), {unalias(A), unalias(A), unalias(make_ref())};
run(reply_alias_once) ->
    A = alias([reply]), A ! m3, R1 = recv(m3), A ! m4, {R1, recv(m4)};
run(bad_alias_option) ->
    try alias([bogus]) catch error:E -> E end;
run(bad_alias_list) ->
    try alias(foo) catch error:E -> E end;
run(monitor_alias_reply) ->
    P = spawn(fun echo/0),
    M = erlang:monitor(process, P, [{alias, demonitor}]),
    P ! {M, hi},
    R = receive {hi, ok} -> reply after 100 -> none end,
    erlang:demonitor(M, [flush]), P ! stop, R;
run(demonitor_drops_alias) ->
    P = spawn(fun echo/0),
    M = erlang:monitor(process, P, [{alias, demonitor}]),
    D = erlang:demonitor(M, [flush]),
    M ! late, P ! stop, {D, recv(late)};
run(monitor_alias_down) ->
    P = spawn(fun() -> receive stop -> ok end end),
    M = erlang:monitor(process, P, [{alias, reply_demonitor}]),
    P ! stop,
    receive {'DOWN', M, process, P, Why} -> Why after 200 -> none end;
run(monitor_alias_tag) ->
    P = spawn(fun() -> receive stop -> ok end end),
    M = erlang:monitor(process, P, [{alias, demonitor}, {tag, mytag}]),
    P ! stop,
    receive {mytag, M, process, P, Why} -> Why after 200 -> none end;
run(monitor_alias_noproc) ->
    D = spawn(fun() -> ok end),
    Ref = erlang:monitor(process, D),
    receive {'DOWN', Ref, process, D, _} -> ok end,
    M = erlang:monitor(process, D, [{alias, demonitor}]),
    receive {'DOWN', M, process, D, Why} -> Why after 200 -> none end;
run(monitor_bad_alias_mode) ->
    P = self(),
    try erlang:monitor(process, spawn(fun() -> ok end), [{alias, bogus}]) catch error:E -> {E, P =:= P} end;
run(alias_default_lifecycle) -> alias_lifecycle(alias());
run(alias_explicit_lifecycle) -> alias_lifecycle(alias([explicit_unalias]));
run(alias_reply_lifecycle) -> alias_lifecycle(alias([reply]));
run(alias_reply_then_explicit) -> alias_lifecycle(alias([reply, explicit_unalias]));
run(alias_explicit_then_reply) -> alias_lifecycle(alias([explicit_unalias, reply]));
run(monitor_demonitor_explicit) -> monitor_demonitor(explicit_unalias);
run(monitor_demonitor_demonitor) -> monitor_demonitor(demonitor);
run(monitor_demonitor_reply_demonitor) -> monitor_demonitor(reply_demonitor);
run(monitor_down_explicit) -> monitor_down(explicit_unalias);
run(monitor_down_demonitor) -> monitor_down(demonitor);
run(monitor_down_reply_demonitor) -> monitor_down(reply_demonitor);
run(monitor_reply_demonitor_once) ->
    P = spawn(fun() -> receive stop -> ok end end),
    M = erlang:monitor(process, P, [{alias, reply_demonitor}]),
    First = send_status(M, first_reply),
    D = erlang:demonitor(M),
    Second = send_status(M, second_reply),
    U = erlang:unalias(M),
    P ! stop,
    {First, D, Second, U};
run(monitor_alias_last_mode) ->
    P = spawn(fun() -> receive stop -> ok end end),
    M = erlang:monitor(process, P, [
        {alias, reply_demonitor}, {alias, explicit_unalias}
    ]),
    D = erlang:demonitor(M),
    First = send_status(M, last_mode),
    U = erlang:unalias(M),
    P ! stop,
    {D, First, U};
run(spawn_opt_alias_explicit) -> spawn_opt_alias(explicit_unalias);
run(spawn_opt_alias_demonitor) -> spawn_opt_alias(demonitor);
run(spawn_opt_alias_reply_demonitor) -> spawn_opt_alias(reply_demonitor);
run(iolist_size_small) ->
    {iolist_size([]), iolist_size(<<"abc">>), iolist_size([1, 2, <<3, 4>>, [5]]), iolist_size("hello")};
run(iolist_size_nested) ->
    iolist_size([[<<1>>, [2, [3, <<4, 5>>]]], [], <<>>, [[[6]]]]);
run(iolist_size_long) ->
    iolist_size([<<N:8>> || N <- lists:seq(1, 5000)]);
run(iolist_size_huge_yields) ->
    L = lists:duplicate(300000, [<<"ab">>, 3, [4]]),
    {iolist_size(L), iolist_size([L, L])};
run(iolist_size_badarg) ->
    try iolist_size([1, 256]) catch error:E -> E end;
run(iolist_size_improper) ->
    {iolist_size([1 | <<2, 3>>]), try iolist_size([1 | 2]) catch error:E -> E end}.
"#;

#[test]
fn alias_and_iolist_size_light_bifs_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping alias light differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile alias_light_differential");
    reference.load(MODULE, &beam).expect("load into erl");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    for case in CASES {
        let want: OwnedTerm =
            match reference.call(MODULE, "run", &[OwnedTerm::Atom((*case).into())]) {
                CallResult::Ok(term) => term,
                other => panic!("{MODULE}:run({case}) on erl: {other:?}"),
            };
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2, None)
            .unwrap_or_else(|error| panic!("{MODULE}:run({case}): {error}"));
        assert_eq!(actual.term, want, "{MODULE}:run({case})");
    }
}
