//! `demonitor(Ref, [flush])` traps to `erts_internal:flush_monitor_messages/3`: the flush is an
//! Erlang receive, so selective receive order of the other messages must match erl, under the
//! JIT and under `ARINSAL_INTERP=1`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_DEMONITOR_FLUSH_CHILD";
const MODULE: &str = "demonitor_flush_trap";
const CASES: &[&str] = &[
    "queued",
    "queued_info",
    "transit",
    "transit_info",
    "tail_queued",
    "gc_queued",
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
            {R2, Last}
    end,
    {R, messages(), Keep}.

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

fn child() -> bool {
    let Some(beam_path) = std::env::var_os(CHILD) else {
        return false;
    };
    for case in CASES {
        let mut vm = Vm::new([]);
        vm.load_bytes(&std::fs::read(&beam_path).unwrap()).unwrap();
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm.eval_scheduled(MODULE, "run", &[arg], 2, None).unwrap();
        println!("RESULT:{case}:{:?}", actual.term);
    }
    true
}

#[test]
fn demonitor_flush_traps_to_erts_internal_and_matches_erl() {
    if child() {
        return;
    }
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

    // The JIT is the default: run the cases in this process.
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    for (case, want) in &expected {
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2, None)
            .expect("scheduled run");
        assert_eq!(actual.term, *want, "JIT {MODULE}:run({case})");
    }

    // The interpreter: the flavour is fixed per process, so the cases run in a child.
    let dir = std::env::temp_dir().join(format!("arinsal-demonitor-flush-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, &beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "demonitor_flush_traps_to_erts_internal_and_matches_erl",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &path)
        .env("ARINSAL_INTERP", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "interpreter child failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    for (case, want) in &expected {
        // The result follows the harness's `test ... ` text on the same line, so search for it.
        let marker = format!("RESULT:{case}:");
        let start = stdout
            .find(&marker)
            .unwrap_or_else(|| panic!("no interpreter result for {case}: {stdout}"))
            + marker.len();
        let line = stdout[start..].lines().next().unwrap_or_default();
        assert_eq!(
            line,
            format!("{want:?}"),
            "interpreter {MODULE}:run({case})"
        );
    }
}
