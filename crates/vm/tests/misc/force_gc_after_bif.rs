//! `erts_debug:set_internal_state(force_gc, Pid)` sets `F_FORCE_GC` (`ERTS_FORCE_GC`); the
//! collection is the BIF epilogue's (`erts_gc_after_bif_call_lhf`), rooting the BIF result,
//! never an immediate collection of whatever the saved register file holds. Live data in the
//! stack and the argument registers must survive repeated forced collections from native code.

use arinsal_difftest::RefErl;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MODULE: &str = "force_gc_after_bif";
const SOURCE: &str = r#"
-module(force_gc_after_bif).
-export([run/0, loop/6]).

run() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Big = lists:seq(1, 200),
    Before = gcs(),
    {A, B, C, D} = loop(Big, {x, Big}, #{k => Big}, [Big | Big], self(), 2000),
    After = gcs(),
    case {A =:= Big, B =:= {x, Big}, C =:= #{k => Big}, D =:= [Big | Big], After > Before} of
        {true, true, true, true, true} -> ok;
        Other -> {error, Other}
    end.

gcs() ->
    {garbage_collection, Info} = process_info(self(), garbage_collection),
    proplists:get_value(minor_gcs, Info).

loop(A, B, C, D, _Self, 0) ->
    {A, B, C, D};
loop(A, B, C, D, Self, N) ->
    true = erts_debug:set_internal_state(force_gc, Self),
    loop(A, B, C, D, Self, N - 1).
"#;

fn run_arinsal(directory: &Path) -> std::process::Output {
    let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(executable.is_file(), "build target/release/arinsal first");
    let mut child = Command::new(&executable)
        .args(["-noshell", "-pa"])
        .arg(directory)
        .args([
            "-eval",
            &format!("io:format(\"RESULT=~p~n\", [{MODULE}:run()]), halt()."),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn arinsal");
    let started = Instant::now();
    loop {
        if child.try_wait().expect("wait for child").is_some() {
            return child.wait_with_output().expect("read child output");
        }
        if started.elapsed() >= Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("arinsal did not finish within 120 seconds");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn forced_collections_from_native_code_keep_live_registers_and_stack() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile fixture");
    let directory = std::env::temp_dir().join(format!("arinsal-force-gc-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create temporary code path");
    std::fs::write(directory.join(format!("{MODULE}.beam")), beam).expect("write fixture BEAM");
    let output = run_arinsal(&directory);
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        output.status.success(),
        "arinsal failed ({:?}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().any(|line| line == "RESULT=ok"), "{stdout}");
}
