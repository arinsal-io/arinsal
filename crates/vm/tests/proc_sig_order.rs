//! Signal order per sender and receiver pair, for the process BIFs that send signals
//! (monitor, demonitor, link, exit): a later message from the same sender is handled after the
//! earlier signal, as erts orders them. Compared with erl, under the JIT and `ARINSAL_INTERP=1`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_PROC_SIG_ORDER_CHILD";
const MODULE: &str = "proc_sig_order";
const CASES: &[&str] = &["monitor_then_send", "demonitor_then_send", "link_then_exit"];

const SOURCE: &str = r#"-module(proc_sig_order).
-export([run/1]).

run(monitor_then_send) ->
    Self = self(),
    P = spawn(fun target/0),
    M = erlang:monitor(process, P),
    P ! {probe, Self},
    Seen = receive {P, Found} -> Found after 5000 -> timeout end,
    P ! stop,
    erlang:demonitor(M, [flush]),
    Seen;
run(demonitor_then_send) ->
    Self = self(),
    P = spawn(fun target/0),
    M = erlang:monitor(process, P),
    erlang:demonitor(M, [flush]),
    P ! {probe, Self},
    Seen = receive {P, Found} -> Found after 5000 -> timeout end,
    P ! stop,
    Seen;
run(link_then_exit) ->
    Self = self(),
    P = spawn(fun() -> trapping_target(Self) end),
    receive {P, ready} -> ok end,
    link(P),
    exit(P, boom),
    Seen = receive {P, Found} -> Found after 5000 -> timeout end,
    P ! stop,
    unlink(P),
    Seen.

%% Replies with whether the probing parent is among the monitors it has when the probe is handled.
target() ->
    receive
        {probe, Parent} ->
            {monitored_by, Mons} = process_info(self(), monitored_by),
            Parent ! {self(), lists:member(Parent, Mons)},
            target();
        stop -> ok
    end.

%% Replies with whether the parent is among its links when the exit signal is handled.
trapping_target(Parent) ->
    process_flag(trap_exit, true),
    Parent ! {self(), ready},
    trapping_loop(Parent).

trapping_loop(Parent) ->
    receive
        {'EXIT', Parent, _} ->
            {links, Links} = process_info(self(), links),
            Parent ! {self(), lists:member(Parent, Links)},
            trapping_loop(Parent);
        stop -> ok
    end.
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
fn process_signal_order_matches_erl() {
    if child() {
        return;
    }
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping signal order test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile proc_sig_order");
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
        assert_eq!(actual.term, *want, "JIT {MODULE}:run({case})");
    }

    let dir = std::env::temp_dir().join(format!("arinsal-proc-sig-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, &beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_signal_order_matches_erl",
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
