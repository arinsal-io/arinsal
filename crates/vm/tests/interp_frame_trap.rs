//! An interpreted frame keeps its Y registers when a BIF it calls traps.
//!
//! Runs under the interpreter flavor (`-emu_flavor emu`, here its `ARINSAL_INTERP` alias).
//! `walk/4`'s `erlang:iolist_size/1` call traps when the slice is out of reductions; the trap
//! must keep the frame's Y registers (`Count` once read as `[]`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::global_atoms;
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_INTERP_FRAME_TRAP_CHILD";
const MODULE: &str = "interp_frame_trap";

const SOURCE: &str = r#"-module(interp_frame_trap).
-export([run/1, walk/4]).

run(N) ->
    Result = interp_frame_trap:walk(N, 0, [], lists:duplicate(2000, $a)),
    {ok, Result}.

%% Interpreted: every call keeps N, Count, Seen and Big in Y registers across the BIF calls. The
%% first BIF charges enough reductions to empty the slice, so the second one traps at entry.
walk(0, Count, [Last | _] = Seen, _Big) ->
    {done, Count, Last, Seen == lists:duplicate(Count, Last)};
walk(N, Count, Seen, Big) ->
    Burn = erlang:iolist_size(Big),
    Size = erlang:iolist_size([<<"ab">>, "cd", [$e]]),
    Next = Count + Size - 4 + Burn - 2000,
    walk(N - 1, Next, [Size | Seen], Big).
"#;

fn child() -> bool {
    let Some(beam_path) = std::env::var_os(CHILD) else {
        return false;
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&std::fs::read(&beam_path).unwrap()).unwrap();
    let arg = arinsal_term::Term::small(20_000).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[arg], 2, None).unwrap();
    println!("RESULT:{:?}", actual.term);
    let _ = global_atoms();
    true
}

#[test]
fn trap_in_interpreted_frame_keeps_y_registers() {
    if child() {
        return;
    }
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping interpreted frame trap test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile interp_frame_trap");
    reference.load(MODULE, &beam).expect("load into erl");
    let want = match reference.call(MODULE, "run", &[OwnedTerm::Int(20_000)]) {
        CallResult::Ok(term) => term,
        other => panic!("{MODULE}:run on erl: {other:?}"),
    };
    let dir = std::env::temp_dir().join(format!("arinsal-frame-trap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, &beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "trap_in_interpreted_frame_keeps_y_registers",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &path)
        .env("ARINSAL_INTERP", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        output.status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let start = stdout.find("RESULT:").expect("child result") + "RESULT:".len();
    let line = stdout[start..].lines().next().unwrap_or_default();
    assert_eq!(line, format!("{want:?}"));
}
