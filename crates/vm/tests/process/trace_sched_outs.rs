//! A process traced with the `running` flag reports the same `in` and `out` events, with the same
//! function in each, as in erts: one `out`/`in` pair per slice that is really used up, per
//! trapped BIF slice and per receive wait, and none for anything else. Compared with erl.
//!
//! Regression: the first `in` of a spawned process carried `0` instead of its initial function.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;

const MODULE: &str = "trace_sched_outs";
const CASES: &[&str] = &[
    "empty",
    "loop",
    "loop_y",
    "member_y",
    "recv_wait",
    "send",
    "mixed",
    "ext_loop",
    "spawned_reverse",
];

const SOURCE: &str = r#"-module(trace_sched_outs).
-export([run/1]).

%% The `in`/`out` events of a traced child doing a fixed workload, as text.
%%   loop, member, ...  the child traces itself; a `_y` suffix starts the slice afresh first
%%   ext_...            the parent traces the child before it starts the work
%%   spawned_reverse    a list copied into a child by spawn, reversed by a trapping BIF
run(spawned_reverse) ->
    Me = self(),
    L = lists:seq(1, 800000),
    Fun = fun() -> lists:reverse(L, []) end,
    {Pid, Mon} = spawn_opt(fun() -> receive go -> Fun(), ok end end,
                           [monitor, {min_heap_size, 4000000}]),
    erlang:trace(Pid, true, [running, {tracer, Me}]),
    Pid ! go,
    events(Pid, Mon);
run(Case) ->
    Me = self(),
    {Pid, Mon} = spawn_monitor(fun() -> child(Me, Case) end),
    case parse(Case) of
        {_, ext} ->
            receive {ready, Pid} -> ok end,
            erlang:trace(Pid, true, [running, {tracer, Me}]),
            Pid ! go;
        _ -> ok
    end,
    events(Pid, Mon).

events(Pid, Mon) ->
    iolist_to_binary(lists:join(" ", [fmt(E) || E <- collect(Pid, Mon, [])])).

collect(Pid, Mon, Acc) ->
    receive
        {trace, Pid, in, MFA} -> collect(Pid, Mon, [{in, MFA} | Acc]);
        {trace, Pid, out, MFA} -> collect(Pid, Mon, [{out, MFA} | Acc]);
        {trace, Pid, _, _} -> collect(Pid, Mon, Acc);
        {'DOWN', Mon, process, Pid, normal} -> lists:reverse(Acc)
    end.

fmt({Dir, {M, F, A}}) -> io_lib:format("~s:~s:~s/~w", [Dir, M, F, A]);
fmt({Dir, Other}) -> io_lib:format("~s:~w", [Dir, Other]).

child(Tracer, Case) ->
    {Kind, Mode} = parse(Case),
    Data = data(Kind),
    case Mode of
        ext ->
            Tracer ! {ready, self()},
            receive go -> ok end,
            work(Kind, Data);
        yield ->
            erlang:yield(),
            self_traced(Tracer, Kind, Data);
        plain ->
            self_traced(Tracer, Kind, Data)
    end.

self_traced(Tracer, Kind, Data) ->
    erlang:trace(self(), true, [running, {tracer, Tracer}]),
    work(Kind, Data),
    erlang:trace(self(), false, [running]),
    TD = erlang:trace_delivered(self()),
    receive {trace_delivered, _, TD} -> ok end,
    ok.

parse(Case) ->
    case atom_to_list(Case) of
        "ext_" ++ Rest -> {list_to_atom(Rest), ext};
        Name ->
            case lists:reverse(Name) of
                "y_" ++ Base -> {list_to_atom(lists:reverse(Base)), yield};
                _ -> {Case, plain}
            end
    end.

data(member) -> lists:seq(1, 1000000);
data(_) -> [].

work(empty, _) -> ok;
work(loop, _) -> loop(200000);
work(member, L) -> false = lists:member(x, L), ok;
work(recv_wait, _) ->
    Me = self(),
    spawn(fun() -> timer:sleep(30), Me ! go end),
    receive go -> ok after 2000 -> timeout end,
    ok;
work(send, _) ->
    Me = self(),
    Me ! a, Me ! b,
    P = spawn(fun() -> receive _ -> ok end end),
    P ! hello,
    receive a -> ok end,
    receive b -> ok end,
    ok;
work(mixed, _) ->
    loop(100000),
    Me = self(),
    spawn(fun() -> timer:sleep(30), Me ! go end),
    receive go -> ok after 2000 -> timeout end,
    Me ! x,
    loop(100000),
    ok.

loop(0) -> ok;
loop(N) -> loop(N - 1).
"#;

/// The text of a debug-printed binary, or the debug text itself.
fn text(debug: &str) -> String {
    let Some(inner) = debug
        .strip_prefix("Binary([")
        .and_then(|rest| rest.strip_suffix("])"))
    else {
        return debug.to_string();
    };
    let bytes: Vec<u8> = inner
        .split(", ")
        .filter_map(|byte| byte.parse().ok())
        .collect();
    String::from_utf8_lossy(&bytes).replace("trace_sched_outs:", "")
}

/// `outs=<n> <first events>`: enough to see how a mismatch differs.
fn summary(debug: &str) -> String {
    let text = text(debug);
    let outs = text.matches("out:").count();
    let head: Vec<&str> = text.split(' ').take(6).collect();
    format!("outs={outs} {head:?}")
}

#[test]
fn running_trace_reports_the_erts_in_and_out_events() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping trace_sched_outs differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile trace_sched_outs");
    reference.load(MODULE, &beam).expect("load into erl");
    let expected: Vec<(&str, OwnedTerm)> = CASES
        .iter()
        .map(
            |case| match reference.call(MODULE, "run", &[OwnedTerm::Atom((*case).into())]) {
                CallResult::Ok(term) => (*case, term),
                other => panic!("{MODULE}:run({case}) on erl: {other:?}"),
            },
        )
        .collect();

    let mut failures = Vec::new();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    for (case, want) in &expected {
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2, None)
            .expect("scheduled run");
        if actual.term != *want {
            failures.push(format!(
                "JIT {case}: erl {} / arinsal {}",
                summary(&format!("{want:?}")),
                summary(&format!("{:?}", actual.term))
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "differs from erl:\n{}",
        failures.join("\n")
    );
}
